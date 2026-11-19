use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::ssrf::validate_webhook_on_create;
use crate::state::SharedState;
use crate::store;
use crate::util::has_control_or_bidi;

const MAX_ALERT_RULES: i64 = 500;

#[derive(Debug, Deserialize)]
pub struct CreateRule {
    pub name: String,
    pub kind: String,
    pub target: String,
    pub threshold: f64,
    pub window_secs: Option<i64>,
    #[serde(default)]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AlertParams {
    pub limit: Option<i64>,
}

pub async fn rules(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("alerts:read")?;
    let rules = store::list_alert_rules(&st.db).await?;
    Ok(Json(json!({ "rules": rules })))
}

pub async fn create_rule(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateRule>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("alerts:create")?;
    if !matches!(req.kind.as_str(), "error_log_count" | "metric_p99") {
        return Err(ApiError::BadRequest(
            "kind must be error_log_count or metric_p99".into(),
        ));
    }
    let name = req.name.trim();
    let target = req.target.trim();
    if name.is_empty()
        || name.len() > 120
        || target.len() > 160
        || has_control_or_bidi(name)
        || has_control_or_bidi(target)
        || !req.threshold.is_finite()
        || (req.kind == "error_log_count" && req.threshold < 0.0)
    {
        return Err(ApiError::BadRequest(
            "valid name, target and finite threshold are required".into(),
        ));
    }
    let window_secs = req.window_secs.unwrap_or(300);
    if !(60..=86_400).contains(&window_secs) {
        return Err(ApiError::BadRequest(
            "window_secs must be between 60 and 86400".into(),
        ));
    }
    if store::count_alert_rules(&st.db).await? >= MAX_ALERT_RULES {
        return Err(ApiError::BadRequest(
            "maximum number of alert rules reached".into(),
        ));
    }
    let webhook_url = match req
        .webhook_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(
            validate_webhook_on_create(
                raw,
                st.config.allow_insecure_webhooks,
                st.config.allow_private_webhooks,
            )
            .await
            .map_err(ApiError::BadRequest)?,
        ),
        None => None,
    };
    let rule = store::create_alert_rule(
        &st.db,
        name,
        &req.kind,
        target,
        req.threshold,
        window_secs,
        webhook_url.as_deref(),
    )
    .await?;
    Ok(Json(json!({ "rule": rule })))
}

pub async fn delete_rule(
    State(st): State<SharedState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("alerts:delete")?;
    if id.trim().is_empty() || id.len() > 128 || has_control_or_bidi(&id) {
        return Err(ApiError::BadRequest("invalid alert rule id".into()));
    }
    store::delete_alert_rule(&st.db, &id).await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn list_alerts(
    State(st): State<SharedState>,
    principal: Principal,
    Query(params): Query<AlertParams>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("alerts:read")?;
    let alerts = store::list_alerts(&st.db, params.limit.unwrap_or(100)).await?;
    Ok(Json(json!({ "alerts": alerts })))
}
