use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::state::SharedState;
use crate::store;
use crate::util::sha256_hex;

pub const SESSION_COOKIE: &str = "infinity_observe_session";
const MIN_TOKEN_LEN: usize = 16;
const MAX_TOKEN_LEN: usize = 512;

#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub permissions: Vec<String>,
}

impl Principal {
    pub fn require(&self, required: &str) -> Result<(), ApiError> {
        if observe_core::rbac::any_permission(&self.permissions, required) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!(
                "missing permission: {required}"
            )))
        }
    }
}

#[derive(Debug, Clone)]
pub struct IngestAuth {
    pub key_id: String,
}

fn valid_token_shape(tok: &str) -> bool {
    (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&tok.len())
        && !tok.chars().any(|c| c.is_whitespace() || c.is_control())
}

pub(crate) fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    let header = parts
        .headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;
    header.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        let val = v.trim();
        (k == name && valid_token_shape(val)).then(|| val.to_string())
    })
}

pub(crate) fn bearer(parts: &Parts) -> Option<String> {
    let mut all = parts
        .headers
        .get_all(axum::http::header::AUTHORIZATION)
        .iter();
    let first = all.next()?;
    if all.next().is_some() {
        return None;
    }
    let raw = first.to_str().ok()?.strip_prefix("Bearer ")?.trim();
    valid_token_shape(raw).then(|| raw.to_string())
}

#[axum::async_trait]
impl FromRequestParts<SharedState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let tok = if parts
            .headers
            .contains_key(axum::http::header::AUTHORIZATION)
        {
            bearer(parts)
        } else {
            cookie_value(parts, SESSION_COOKIE)
        };
        if let Some(tok) = tok {
            let hash = sha256_hex(&tok);
            if let Some(uid) = store::get_session_user(&state.db, &hash).await? {
                return resolve(state, &uid).await;
            }
        }
        Err(ApiError::Unauthorized("authentication required".into()))
    }
}

#[axum::async_trait]
impl FromRequestParts<SharedState> for IngestAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let Some(tok) = bearer(parts) else {
            return Err(ApiError::Unauthorized("missing bearer ingest key".into()));
        };
        if !tok.starts_with("io_") {
            return Err(ApiError::Unauthorized("invalid ingest key".into()));
        }
        let hash = sha256_hex(&tok);
        match store::validate_ingest_key(&state.db, &hash).await? {
            Some(id) => Ok(IngestAuth { key_id: id }),
            None => Err(ApiError::Unauthorized("invalid ingest key".into())),
        }
    }
}

async fn resolve(state: &SharedState, user_id: &str) -> Result<Principal, ApiError> {
    let user = store::get_user(&state.db, user_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("unknown subject".into()))?;
    if user.disabled != 0 {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    let permissions = observe_core::rbac::permissions_for_role(&user.role);
    Ok(Principal {
        user_id: user.id,
        email: user.email,
        role: user.role,
        permissions,
    })
}
