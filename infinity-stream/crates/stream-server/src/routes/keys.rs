use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{Principal, PrincipalKind};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;

#[derive(Debug, Deserialize)]
pub struct CreateKey {
    pub name: String,
}

/// Defense in depth: even if API-key scopes are ever widened, keys must never
/// be able to list, mint, or revoke other keys.
fn deny_api_keys(p: &Principal) -> Result<(), ApiError> {
    if matches!(p.kind, PrincipalKind::ApiKey) {
        return Err(ApiError::Forbidden(
            "API keys cannot manage API keys".into(),
        ));
    }
    Ok(())
}

fn with_no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

pub async fn list(State(st): State<SharedState>, p: Principal) -> ApiResult<Response> {
    deny_api_keys(&p)?;
    p.require("keys:read")?;
    Ok(with_no_store(
        Json(json!({"keys": store::list_api_keys(&st.db).await?})).into_response(),
    ))
}

pub async fn create(
    State(st): State<SharedState>,
    p: Principal,
    Json(req): Json<CreateKey>,
) -> ApiResult<Response> {
    deny_api_keys(&p)?;
    p.require("keys:create")?;
    let trimmed = req.name.trim();
    if trimmed.is_empty() || trimmed.len() > 128 || trimmed.chars().any(|c| c.is_control()) {
        return Err(ApiError::BadRequest("key name must be 1-128 chars".into()));
    }
    let (id, token) = store::create_api_key(&st.db, trimmed).await?;
    Ok(with_no_store(
        Json(json!({
            "id": id,
            "key": token,
            "note": "store this key now; only its SHA-256 hash is persisted"
        }))
        .into_response(),
    ))
}

pub async fn delete_key(
    State(st): State<SharedState>,
    p: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    deny_api_keys(&p)?;
    p.require("keys:delete")?;
    if id.is_empty()
        || id.len() > 128
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::BadRequest("invalid key id".into()));
    }
    if !store::revoke_api_key(&st.db, &id).await? {
        return Err(ApiError::NotFound(
            "api key not found or already revoked".into(),
        ));
    }
    Ok(Json(json!({"ok": true})))
}
