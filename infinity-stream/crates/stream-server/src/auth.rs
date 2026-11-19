use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;

use crate::error::ApiError;
use crate::state::SharedState;
use crate::store;
use crate::util::sha256_hex;

pub const SESSION_COOKIE: &str = "infinity_session";
const MAX_BEARER_LEN: usize = 256;
const MAX_COOKIE_LEN: usize = 256;

/// Least-privilege permission set granted to API keys. Data-plane only —
/// keys can produce/consume/search and create topics/indexes, but CANNOT
/// delete topics/indexes or manage API keys / admin. A leaked key therefore
/// cannot escalate to full administration (dashboard sessions remain admin).
const API_KEY_SCOPE: &[&str] = &[
    "topics:read",
    "topics:produce",
    "topics:consume",
    "topics:commit",
    "topics:subscribe",
    "topics:create",
    "search:read",
    "search:query",
    "search:write",
    "search:create",
];

#[derive(Debug, Clone)]
pub enum PrincipalKind {
    User,
    ApiKey,
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub subject: String,
    pub kind: PrincipalKind,
    pub permissions: Vec<String>,
}

impl Principal {
    pub fn require(&self, required: &str) -> Result<(), ApiError> {
        if stream_core::rbac::any_permission(&self.permissions, required) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!(
                "missing permission: {required}"
            )))
        }
    }
}

pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    header.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        let val = v.trim();
        (k.trim() == name && !val.is_empty() && val.len() <= MAX_COOKIE_LEN)
            .then(|| val.to_string())
    })
}

#[axum::async_trait]
impl FromRequestParts<SharedState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // If an Authorization header is explicitly supplied, never silently
        // fall back to an ambient session cookie if the Bearer token is invalid.
        if let Some(auth_val) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            let auth = auth_val
                .to_str()
                .map_err(|_| ApiError::Unauthorized("invalid authorization header".into()))?;
            let token = auth
                .strip_prefix("Bearer ")
                .map(str::trim)
                .filter(|t| {
                    !t.is_empty()
                        && t.len() <= MAX_BEARER_LEN
                        && !t.chars().any(|c| c.is_control() || c.is_whitespace())
                })
                .ok_or_else(|| ApiError::Unauthorized("invalid bearer token".into()))?;
            if let Some(id) = store::api_key_subject(&state.db, &sha256_hex(token)).await? {
                return Ok(Principal {
                    subject: id,
                    kind: PrincipalKind::ApiKey,
                    permissions: API_KEY_SCOPE.iter().map(|s| s.to_string()).collect(),
                });
            }
            return Err(ApiError::Unauthorized("invalid or revoked API key".into()));
        }

        if let Some(raw) = extract_cookie(&parts.headers, SESSION_COOKIE) {
            if let Some(uid) = store::session_user(&state.db, &sha256_hex(&raw)).await? {
                return Ok(Principal {
                    subject: uid,
                    kind: PrincipalKind::User,
                    permissions: vec!["*:*".into()],
                });
            }
        }
        Err(ApiError::Unauthorized("authentication required".into()))
    }
}
