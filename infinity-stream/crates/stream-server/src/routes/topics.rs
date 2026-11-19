use std::borrow::Cow;
use std::time::{Duration, Instant};

use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::Json;
use rand::Rng;
use serde::Deserialize;
use serde_json::json;
use stream_core::commit_log::MAX_READ_RECORDS;
use stream_core::model::NewRecord;
use stream_core::security::{validate_group_name, validate_resource_name};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::OwnedSemaphorePermit;

use crate::auth::{Principal, PrincipalKind};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

const MAX_WS_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_WS_FRAME_BYTES: usize = 16 * 1024;
const MAX_WS_INBOUND_DATA_BYTES: usize = 4096;
const MAX_CONSECUTIVE_WS_LAGS: u32 = 3;
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(10);
const WS_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const MAX_PRODUCED_TIMES_WINDOW: usize = 200_000;

#[derive(Debug, Deserialize)]
pub struct CreateTopic {
    pub name: String,
    pub partitions: u32,
}

#[derive(Debug, Deserialize)]
pub struct ProduceInput {
    #[serde(default)]
    pub key: Option<String>,
    pub value: serde_json::Value,
    #[serde(default)]
    pub partition: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ProduceRequest {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    #[serde(default)]
    pub partition: Option<u32>,
    #[serde(default)]
    pub records: Option<Vec<ProduceInput>>,
}

#[derive(Debug, Deserialize)]
pub struct ConsumeQuery {
    pub partition: u32,
    pub offset: u64,
    #[serde(default = "default_max")]
    pub max: usize,
}

fn default_max() -> usize {
    100
}

#[derive(Debug, Deserialize)]
pub struct CommitRequest {
    pub group: String,
    pub partition: u32,
    pub offset: u64,
}

#[derive(Debug, Deserialize)]
pub struct OffsetQuery {
    pub group: String,
    pub partition: u32,
}

fn topic_partition_count(partitions: i64) -> ApiResult<u32> {
    u32::try_from(partitions)
        .ok()
        .filter(|&n| n > 0)
        .ok_or_else(|| ApiError::Internal("corrupt topic partition count".into()))
}

pub async fn create(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<CreateTopic>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("topics:create")?;
    validate_resource_name(&req.name)?;
    if req.partitions == 0 || req.partitions > 1024 {
        return Err(ApiError::BadRequest("partitions must be 1..=1024".into()));
    }
    store::create_topic(&st.db, &req.name, req.partitions as i64)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
                ApiError::Conflict("topic already exists".into())
            }
            other => other.into(),
        })?;
    let mut log = st.log.lock().await;
    for part in 0..req.partitions {
        log.create_partition(&req.name, part)?;
    }
    st.topic_sender(&req.name).await;
    Ok(Json(json!({"name":req.name,"partitions":req.partitions})))
}

pub async fn list(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("topics:read")?;
    Ok(Json(json!({"topics": store::list_topics(&st.db).await?})))
}

pub async fn delete_topic(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("topics:delete")?;
    validate_resource_name(&name)?;
    if !store::delete_topic(&st.db, &name).await? {
        return Err(ApiError::NotFound("topic not found".into()));
    }
    st.log.lock().await.delete_topic(&name)?;
    st.broadcasts.write().await.remove(&name);
    Ok(Json(json!({"ok":true})))
}

pub async fn produce(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
    Json(req): Json<ProduceRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("topics:produce")?;
    validate_resource_name(&name)?;
    let topic = store::get_topic(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("topic not found".into()))?;
    let num_partitions = topic_partition_count(topic.partitions)?;

    let inputs = if let Some(records) = req.records {
        records
    } else {
        vec![ProduceInput {
            key: req.key,
            value: req
                .value
                .ok_or_else(|| ApiError::BadRequest("value required".into()))?,
            partition: req.partition,
        }]
    };
    if inputs.is_empty() || inputs.len() > st.config.max_batch_records {
        return Err(ApiError::BadRequest(format!(
            "records must contain 1..={} entries",
            st.config.max_batch_records
        )));
    }

    // Pre-validate every record in the batch before mutating the commit log
    // or broadcasting to subscribers. `append_partitioned` atomically prepares
    // full `StoredRecord` frames across the entire batch before writing to disk.
    let mut validated: Vec<(u32, NewRecord)> = Vec::with_capacity(inputs.len());
    for input in inputs {
        if input.key.as_ref().is_some_and(|k| k.len() > 1024) {
            return Err(ApiError::BadRequest("record key too large".into()));
        }
        let part = input
            .partition
            .unwrap_or_else(|| rand::thread_rng().gen_range(0..num_partitions));
        if part >= num_partitions {
            return Err(ApiError::BadRequest("partition out of range".into()));
        }
        validated.push((
            part,
            NewRecord {
                key: input.key,
                value: input.value,
            },
        ));
    }

    let assigned = {
        let mut log = st.log.lock().await;
        log.append_partitioned(&name, validated)?
    };
    let sender = st.topic_sender(&name).await;
    for rec in &assigned {
        let _ = sender.send(rec.clone());
    }

    let mut times = st.produced_times.lock().await;
    let now = Instant::now();
    for _ in 0..assigned.len() {
        if times.len() >= MAX_PRODUCED_TIMES_WINDOW {
            times.pop_front();
        }
        times.push_back(now);
    }
    while times
        .front()
        .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
    {
        times.pop_front();
    }

    let first = assigned.first().cloned();
    Ok(Json(json!({
        "partition": first.as_ref().map(|r| r.partition),
        "offset": first.as_ref().map(|r| r.offset),
        "records": assigned
    })))
}

pub async fn consume(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
    Query(q): Query<ConsumeQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("topics:consume")?;
    validate_resource_name(&name)?;
    let topic = store::get_topic(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("topic not found".into()))?;
    let num_partitions = topic_partition_count(topic.partitions)?;
    if q.partition >= num_partitions {
        return Err(ApiError::BadRequest("partition out of range".into()));
    }
    if q.max == 0 || q.max > MAX_READ_RECORDS {
        return Err(ApiError::BadRequest(format!(
            "max must be 1..={MAX_READ_RECORDS}"
        )));
    }
    let records = st
        .log
        .lock()
        .await
        .read_from(&name, q.partition, q.offset, q.max)?;
    let next = records
        .last()
        .map(|r| r.offset.saturating_add(1))
        .unwrap_or(q.offset);
    Ok(Json(json!({"records": records, "nextOffset": next})))
}

pub async fn commit(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
    Json(req): Json<CommitRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("topics:commit")?;
    validate_resource_name(&name)?;
    validate_group_name(&req.group)?;
    let topic = store::get_topic(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("topic not found".into()))?;
    let num_partitions = topic_partition_count(topic.partitions)?;
    if req.partition >= num_partitions {
        return Err(ApiError::BadRequest("partition out of range".into()));
    }
    let offset = i64::try_from(req.offset)
        .map_err(|_| ApiError::BadRequest("offset out of range".into()))?;
    store::commit_offset(&st.db, &name, &req.group, req.partition as i64, offset).await?;
    Ok(Json(json!({"ok":true})))
}

pub async fn offset(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
    Query(q): Query<OffsetQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("topics:consume")?;
    validate_resource_name(&name)?;
    validate_group_name(&q.group)?;
    let topic = store::get_topic(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("topic not found".into()))?;
    let num_partitions = topic_partition_count(topic.partitions)?;
    if q.partition >= num_partitions {
        return Err(ApiError::BadRequest("partition out of range".into()));
    }
    let offset = store::get_offset(&st.db, &name, &q.group, q.partition as i64)
        .await?
        .unwrap_or(0);
    Ok(Json(
        json!({"topic":name,"group":q.group,"partition":q.partition,"offset":offset}),
    ))
}

pub async fn consumers(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require("topics:consume")?;
    Ok(Json(json!({"offsets": store::list_offsets(&st.db).await?})))
}

/// Validates Cross-Site WebSocket Hijacking (CSWSH) origin constraints.
/// - Whenever an `Origin` header is present, it must strictly match an allowed origin.
/// - Cookie-authenticated browser upgrades MUST include a valid `Origin` header.
/// - Non-browser API key clients may omit `Origin`, but are rejected if an
///   untrusted `Origin` is supplied.
fn validate_ws_origin(st: &SharedState, p: &Principal, headers: &HeaderMap) -> ApiResult<()> {
    match headers.get(header::ORIGIN) {
        Some(raw) => {
            let origin = raw
                .to_str()
                .map_err(|_| ApiError::Forbidden("invalid Origin header".into()))?;
            if !st.config.is_allowed_origin(origin) {
                return Err(ApiError::Forbidden("WebSocket origin not allowed".into()));
            }
            Ok(())
        }
        None => {
            if matches!(p.kind, PrincipalKind::User) {
                Err(ApiError::Forbidden(
                    "Origin header required for session-authenticated WebSocket".into(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

pub async fn subscribe(
    State(st): State<SharedState>,
    p: Principal,
    Path(name): Path<String>,
    headers: HeaderMap,
    ws_res: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> ApiResult<impl axum::response::IntoResponse> {
    p.require("topics:subscribe")?;
    validate_resource_name(&name)?;
    validate_ws_origin(&st, &p, &headers)?;
    store::get_topic(&st.db, &name)
        .await?
        .ok_or_else(|| ApiError::NotFound("topic not found".into()))?;
    let permit =
        st.ws_semaphore.clone().try_acquire_owned().map_err(|_| {
            ApiError::TooManyRequests("too many active WebSocket subscribers".into())
        })?;
    let ws = ws_res.map_err(|_| ApiError::BadRequest("WebSocket upgrade required".into()))?;
    let rx = st.topic_sender(&name).await.subscribe();
    Ok(ws
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_FRAME_BYTES)
        .on_upgrade(move |socket| ws_loop(socket, rx, permit)))
}

async fn send_ws_text(socket: &mut WebSocket, text: String) -> bool {
    matches!(
        tokio::time::timeout(WS_SEND_TIMEOUT, socket.send(Message::Text(text))).await,
        Ok(Ok(()))
    )
}

async fn ws_loop(
    mut socket: WebSocket,
    mut rx: tokio::sync::broadcast::Receiver<stream_core::model::LogRecord>,
    _permit: OwnedSemaphorePermit,
) {
    let mut consecutive_lags: u32 = 0;
    let mut keepalive = tokio::time::interval(WS_KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick so ping waits a full interval.
    keepalive.tick().await;

    loop {
        tokio::select! {
            recv = rx.recv() => {
                match recv {
                    Ok(record) => {
                        consecutive_lags = 0;
                        let Ok(text) = serde_json::to_string(&record) else {
                            break;
                        };
                        if !send_ws_text(&mut socket, text).await {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(missed)) => {
                        consecutive_lags = consecutive_lags.saturating_add(1);
                        let notice = json!({"type": "lagged", "missed": missed}).to_string();
                        if !send_ws_text(&mut socket, notice).await {
                            break;
                        }
                        if consecutive_lags >= MAX_CONSECUTIVE_WS_LAGS {
                            let _ = socket
                                .send(Message::Close(Some(CloseFrame {
                                    code: 1008,
                                    reason: Cow::Borrowed("subscriber lagged behind stream"),
                                })))
                                .await;
                            break;
                        }
                    }
                    Err(RecvError::Closed) => {
                        let _ = socket
                            .send(Message::Close(Some(CloseFrame {
                                code: 1001,
                                reason: Cow::Borrowed("topic closed"),
                            })))
                            .await;
                        break;
                    }
                }
            }
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(Message::Text(t))) if t.len() > MAX_WS_INBOUND_DATA_BYTES => {
                        let _ = socket
                            .send(Message::Close(Some(CloseFrame {
                                code: 1009,
                                reason: Cow::Borrowed("inbound frame too large"),
                            })))
                            .await;
                        break;
                    }
                    Some(Ok(Message::Binary(b))) if b.len() > MAX_WS_INBOUND_DATA_BYTES => {
                        let _ = socket
                            .send(Message::Close(Some(CloseFrame {
                                code: 1009,
                                reason: Cow::Borrowed("inbound frame too large"),
                            })))
                            .await;
                        break;
                    }
                    Some(Ok(_)) => {}
                }
            }
            _ = keepalive.tick() => {
                if !matches!(
                    tokio::time::timeout(WS_SEND_TIMEOUT, socket.send(Message::Ping(Vec::new()))).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
        }
    }
}
