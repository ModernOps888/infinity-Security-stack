use axum::extract::State;
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::auth::IngestAuth;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store::{self, OwnedLog, OwnedMetric, OwnedSpan};
use crate::util::{has_control_or_bidi, normalize_utc_rfc3339, sanitize_log_text};

const MAX_LOG_BATCH: usize = 5_000;
const MAX_METRIC_BATCH: usize = 10_000;
const MAX_SPAN_BATCH: usize = 5_000;
const MAX_SERVICE_LEN: usize = 160;
const MAX_NAME_LEN: usize = 240;
const MAX_MESSAGE_LEN: usize = 16 * 1024;
const MAX_JSON_LEN: usize = 64 * 1024;
const MAX_ATTR_KEYS: usize = 32;
const MAX_ATTR_KEY_LEN: usize = 128;
const MAX_ATTR_STR_LEN: usize = 2_048;
const MAX_ATTR_DEPTH: usize = 4;
const MAX_ATTR_ARRAY_LEN: usize = 64;
const MAX_ATTR_NODES: usize = 256;
const MAX_SPAN_DURATION_MS: f64 = 365.0 * 24.0 * 3600.0 * 1000.0;

#[derive(Debug, Deserialize)]
pub struct LogIn {
    pub timestamp: Option<String>,
    pub level: String,
    pub service: String,
    pub message: String,
    pub attributes: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct MetricIn {
    pub timestamp: Option<String>,
    pub name: String,
    pub value: f64,
    pub tags: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct SpanIn {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub service: String,
    pub start: String,
    pub end: Option<String>,
    pub duration_ms: Option<f64>,
    pub status: Option<String>,
    pub attributes: Option<Value>,
}

fn ensure_text(name: &str, value: &str, max: usize) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max || has_control_or_bidi(trimmed) {
        return Err(ApiError::BadRequest(format!(
            "{name} must be 1-{max} bytes without control characters"
        )));
    }
    Ok(trimmed.to_string())
}

fn ensure_id(name: &str, value: &str, max: usize) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > max
        || trimmed.chars().any(char::is_whitespace)
        || has_control_or_bidi(trimmed)
    {
        return Err(ApiError::BadRequest(format!(
            "{name} must be a valid identifier (1-{max} bytes)"
        )));
    }
    Ok(trimmed.to_string())
}

fn ensure_level(level: &str) -> ApiResult<String> {
    let norm = level.trim().to_ascii_uppercase();
    if matches!(
        norm.as_str(),
        "TRACE" | "DEBUG" | "INFO" | "NOTICE" | "WARN" | "WARNING" | "ERROR" | "FATAL" | "CRITICAL"
    ) {
        Ok(norm)
    } else {
        Err(ApiError::BadRequest("unsupported log level".into()))
    }
}

fn ensure_timestamp(name: &str, raw: Option<&str>) -> ApiResult<String> {
    match raw {
        Some(ts) => {
            normalize_utc_rfc3339(ts).map_err(|msg| ApiError::BadRequest(format!("{name} {msg}")))
        }
        None => Ok(store::now()),
    }
}

fn sanitize_json_val(val: Value, depth: usize, nodes: &mut usize) -> ApiResult<Value> {
    *nodes += 1;
    if *nodes > MAX_ATTR_NODES {
        return Err(ApiError::BadRequest(
            "attributes/tags exceed maximum node count".into(),
        ));
    }
    if depth > MAX_ATTR_DEPTH {
        return Err(ApiError::BadRequest(
            "attributes/tags exceed maximum nesting depth".into(),
        ));
    }
    match val {
        Value::Null | Value::Bool(_) => Ok(val),
        Value::Number(n) => {
            if n.as_f64().map(|f| f.is_finite()).unwrap_or(false) {
                Ok(Value::Number(n))
            } else {
                Err(ApiError::BadRequest(
                    "attributes/tags numeric value must be finite".into(),
                ))
            }
        }
        Value::String(s) => {
            if s.len() > MAX_ATTR_STR_LEN {
                return Err(ApiError::BadRequest(format!(
                    "attribute string exceeds {MAX_ATTR_STR_LEN} bytes"
                )));
            }
            Ok(Value::String(sanitize_log_text(&s)))
        }
        Value::Array(arr) => {
            if arr.len() > MAX_ATTR_ARRAY_LEN {
                return Err(ApiError::BadRequest(
                    "attributes/tags array exceeds max length".into(),
                ));
            }
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(sanitize_json_val(item, depth + 1, nodes)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            if map.len() > MAX_ATTR_KEYS {
                return Err(ApiError::BadRequest(format!(
                    "attributes/tags exceed {MAX_ATTR_KEYS} keys"
                )));
            }
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                if k.trim().is_empty() || k.len() > MAX_ATTR_KEY_LEN || has_control_or_bidi(&k) {
                    return Err(ApiError::BadRequest(
                        "attribute/tag key is invalid or too long".into(),
                    ));
                }
                out.insert(k, sanitize_json_val(v, depth + 1, nodes)?);
            }
            Ok(Value::Object(out))
        }
    }
}

fn validate_attributes(name: &str, value: Option<Value>) -> ApiResult<Option<Value>> {
    let Some(val) = value else {
        return Ok(None);
    };
    let Value::Object(_) = val else {
        return Err(ApiError::BadRequest(format!(
            "{name} must be a JSON object"
        )));
    };
    let mut nodes = 0usize;
    let sanitized = sanitize_json_val(val, 1, &mut nodes)?;
    if sanitized.to_string().len() > MAX_JSON_LEN {
        return Err(ApiError::BadRequest(format!("{name} is too large")));
    }
    Ok(Some(sanitized))
}

pub async fn logs(
    State(st): State<SharedState>,
    auth: IngestAuth,
    Json(items): Json<Vec<LogIn>>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = &auth.key_id;
    if items.len() > MAX_LOG_BATCH {
        return Err(ApiError::BadRequest("too many log records".into()));
    }
    let mut validated = Vec::with_capacity(items.len());
    for l in items {
        let level = ensure_level(&l.level)?;
        let service = ensure_text("service", &l.service, MAX_SERVICE_LEN)?;
        let msg_clean = sanitize_log_text(&l.message);
        if msg_clean.trim().is_empty() || msg_clean.len() > MAX_MESSAGE_LEN {
            return Err(ApiError::BadRequest(format!(
                "message is required and must be <= {MAX_MESSAGE_LEN} bytes"
            )));
        }
        let attributes = validate_attributes("attributes", l.attributes)?;
        let timestamp = ensure_timestamp("timestamp", l.timestamp.as_deref())?;
        validated.push(OwnedLog {
            timestamp,
            level,
            service,
            message: msg_clean,
            attributes,
        });
    }
    let accepted = validated.len();
    store::insert_logs_batch(&st.db, &validated).await?;
    store::evaluate_alerts(&st.db, &st.config).await?;
    Ok(Json(json!({ "accepted": accepted })))
}

pub async fn metrics(
    State(st): State<SharedState>,
    auth: IngestAuth,
    Json(items): Json<Vec<MetricIn>>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = &auth.key_id;
    if items.len() > MAX_METRIC_BATCH {
        return Err(ApiError::BadRequest("too many metric records".into()));
    }
    let mut validated = Vec::with_capacity(items.len());
    for m in items {
        let name = ensure_text("name", &m.name, MAX_NAME_LEN)?;
        let tags = validate_attributes("tags", m.tags)?;
        if !m.value.is_finite() {
            return Err(ApiError::BadRequest("metric value must be finite".into()));
        }
        let timestamp = ensure_timestamp("timestamp", m.timestamp.as_deref())?;
        validated.push(OwnedMetric {
            timestamp,
            name,
            value: m.value,
            tags,
        });
    }
    let accepted = validated.len();
    store::insert_metrics_batch(&st.db, &validated).await?;
    store::evaluate_alerts(&st.db, &st.config).await?;
    Ok(Json(json!({ "accepted": accepted })))
}

pub async fn traces(
    State(st): State<SharedState>,
    auth: IngestAuth,
    Json(items): Json<Vec<SpanIn>>,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = &auth.key_id;
    if items.len() > MAX_SPAN_BATCH {
        return Err(ApiError::BadRequest("too many spans".into()));
    }
    let mut validated = Vec::with_capacity(items.len());
    for s in items {
        let trace_id = ensure_id("trace_id", &s.trace_id, 128)?;
        let span_id = ensure_id("span_id", &s.span_id, 128)?;
        let parent_span_id = match s.parent_span_id {
            Some(p) if !p.trim().is_empty() => Some(ensure_id("parent_span_id", &p, 128)?),
            _ => None,
        };
        let name = ensure_text("name", &s.name, MAX_NAME_LEN)?;
        let service = ensure_text("service", &s.service, MAX_SERVICE_LEN)?;
        let status = match s.status {
            Some(st_val) if !st_val.trim().is_empty() => Some(ensure_text("status", &st_val, 32)?),
            _ => None,
        };
        let attributes = validate_attributes("attributes", s.attributes)?;
        let start_utc = ensure_timestamp("start", Some(&s.start))?;
        let (end_utc, duration_ms) =
            normalize_span_time(&start_utc, s.end.as_deref(), s.duration_ms)?;
        validated.push(OwnedSpan {
            trace_id,
            span_id,
            parent_span_id,
            name,
            service,
            start_time: start_utc,
            end_time: end_utc,
            duration_ms,
            status,
            attributes,
        });
    }
    let accepted = validated.len();
    store::insert_spans_batch(&st.db, &validated).await?;
    Ok(Json(json!({ "accepted": accepted })))
}

fn normalize_span_time(
    start_utc: &str,
    end: Option<&str>,
    duration_ms: Option<f64>,
) -> ApiResult<(String, f64)> {
    let sdt = chrono::DateTime::parse_from_rfc3339(start_utc)
        .map_err(|_| ApiError::BadRequest("start must be RFC3339".into()))?
        .with_timezone(&Utc);

    if let Some(d) = duration_ms {
        if !d.is_finite() || !(0.0..=MAX_SPAN_DURATION_MS).contains(&d) {
            return Err(ApiError::BadRequest(
                "duration_ms must be finite and between 0 and 1 year".into(),
            ));
        }
        if let Some(e) = end {
            let end_utc = normalize_utc_rfc3339(e)
                .map_err(|msg| ApiError::BadRequest(format!("end {msg}")))?;
            let edt = chrono::DateTime::parse_from_rfc3339(&end_utc)
                .map_err(|_| ApiError::BadRequest("end must be RFC3339".into()))?
                .with_timezone(&Utc);
            if edt < sdt {
                return Err(ApiError::BadRequest(
                    "span end time must not precede start time".into(),
                ));
            }
            return Ok((end_utc, d));
        }
        let delta = Duration::milliseconds(d.round() as i64);
        let end_dt = sdt
            .checked_add_signed(delta)
            .ok_or_else(|| ApiError::BadRequest("span end timestamp overflow".into()))?;
        return Ok((end_dt.to_rfc3339(), d));
    }

    let e = end.ok_or_else(|| ApiError::BadRequest("end or duration_ms is required".into()))?;
    let end_utc =
        normalize_utc_rfc3339(e).map_err(|msg| ApiError::BadRequest(format!("end {msg}")))?;
    let edt = chrono::DateTime::parse_from_rfc3339(&end_utc)
        .map_err(|_| ApiError::BadRequest("end must be RFC3339".into()))?
        .with_timezone(&Utc);
    if edt < sdt {
        return Err(ApiError::BadRequest(
            "span end time must not precede start time".into(),
        ));
    }
    let d = (edt - sdt).num_milliseconds() as f64;
    Ok((end_utc, d))
}
