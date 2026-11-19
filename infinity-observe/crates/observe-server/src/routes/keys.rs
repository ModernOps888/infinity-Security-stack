use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::Principal;
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;
use crate::util::has_control_or_bidi;

const MAX_INGEST_KEYS: i64 = 500;

#[derive(Debug, Deserialize)]
pub struct CreateKey {
    pub name: Option<String>,
}

pub async fn list(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("keys:read")?;
    let keys = store::list_ingest_keys(&st.db).await?;
    Ok(Json(json!({ "keys": keys })))
}

pub async fn create(
    State(st): State<SharedState>,
    principal: Principal,
    Json(req): Json<CreateKey>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("keys:create")?;
    let name = req.name.unwrap_or_else(|| "dashboard".into());
    let name = name.trim();
    if name.is_empty() || name.len() > 80 || has_control_or_bidi(name) {
        return Err(ApiError::BadRequest(
            "name must be 1-80 characters without control characters".into(),
        ));
    }
    if store::count_ingest_keys(&st.db).await? >= MAX_INGEST_KEYS {
        return Err(ApiError::BadRequest(
            "maximum number of ingest keys reached".into(),
        ));
    }
    let (key, token) = store::create_ingest_key(&st.db, name)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.message().contains("UNIQUE") => {
                ApiError::Conflict("key collision".into())
            }
            other => other.into(),
        })?;
    Ok(Json(
        json!({ "key": key, "token": token, "note": "copy now; only the SHA-256 hash is stored" }),
    ))
}

pub async fn revoke(
    State(st): State<SharedState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require("keys:delete")?;
    if id.trim().is_empty() || id.len() > 128 || has_control_or_bidi(&id) {
        return Err(ApiError::BadRequest("invalid ingest key id".into()));
    }
    store::revoke_ingest_key(&st.db, &id).await?;
    Ok(Json(json!({ "ok": true })))
}
