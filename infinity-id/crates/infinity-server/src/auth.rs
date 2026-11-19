//! Request authentication: resolves a [`Principal`] from either a Bearer JWT
//! (machine/API clients) or the dashboard session cookie, then enforces RBAC.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, Method};
use infinity_core::{rbac, token};

use crate::config::Config;
use crate::error::ApiError;
use crate::state::SharedState;
use crate::store;
use crate::util::sha256_hex;

pub const SESSION_COOKIE: &str = "infinity_session";
pub const CSRF_COOKIE: &str = "infinity_csrf";

/// An authenticated caller with resolved roles and effective permissions.
#[derive(Debug, Clone)]
pub struct Principal {
    pub user_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    /// True for the dashboard session cookie or a first-party access token
    /// (audience == issuer). Third-party access tokens (audience == some client
    /// id) are NOT first-party and must not reach privileged/self-service APIs.
    pub first_party: bool,
}

impl Principal {
    /// Enforce that the principal holds a permission satisfying `required`.
    ///
    /// Also requires a first-party context — this prevents a token minted for
    /// an unrelated relying party from being replayed against the management
    /// API (confused-deputy / audience-confusion).
    pub fn require(&self, required: &str) -> Result<(), ApiError> {
        self.require_first_party()?;
        if rbac::any_permission(&self.permissions, required) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!(
                "missing permission: {required}"
            )))
        }
    }

    /// Require that the caller is first-party (dashboard session or issuer-
    /// audience token). Used to gate self-service account mutations too.
    pub fn require_first_party(&self) -> Result<(), ApiError> {
        if self.first_party {
            Ok(())
        } else {
            Err(ApiError::Forbidden(
                "this endpoint requires a first-party token (audience must be the issuer)".into(),
            ))
        }
    }
}

pub fn cookie_value_from_headers(headers: &HeaderMap, name: &str) -> Option<String> {
    let header = headers.get(header::COOKIE)?.to_str().ok()?;
    header.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

fn canonical_origin(raw: &str) -> Option<String> {
    let u = url::Url::parse(raw.trim()).ok()?;
    let host = u.host_str()?;
    let scheme = u.scheme();
    match u.port() {
        Some(p) => Some(format!("{scheme}://{host}:{p}")),
        None => Some(format!("{scheme}://{host}")),
    }
}

/// Verify browser CSRF defenses for cookie-authenticated or login requests:
/// - `Sec-Fetch-Site` (when present) must be `same-origin` or `none`
/// - `Origin` (when present) must match `issuer` or configured `cors_origins`
/// - `Referer` (fallback when `Origin` is absent) must match allowed origins
/// - When `infinity_csrf` cookie is present, `X-CSRF-Token` must match it
pub fn verify_browser_csrf(headers: &HeaderMap, config: &Config) -> Result<(), ApiError> {
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if !matches!(sfs, "same-origin" | "none") {
            return Err(ApiError::Forbidden("cross-site request blocked".into()));
        }
    }

    let mut allowed: Vec<String> = Vec::new();
    if let Some(orig) = config.issuer_origin() {
        allowed.push(orig);
    }
    for o in &config.cors_origins {
        if let Some(orig) = canonical_origin(o) {
            if !allowed.contains(&orig) {
                allowed.push(orig);
            }
        }
    }

    if let Some(origin_hdr) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let Some(orig) = canonical_origin(origin_hdr) else {
            return Err(ApiError::Forbidden("invalid origin".into()));
        };
        if !allowed.iter().any(|a| a == &orig) {
            return Err(ApiError::Forbidden("cross-origin request blocked".into()));
        }
    } else if let Some(referer_hdr) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) {
        let Some(orig) = canonical_origin(referer_hdr) else {
            return Err(ApiError::Forbidden("invalid referer".into()));
        };
        if !allowed.iter().any(|a| a == &orig) {
            return Err(ApiError::Forbidden("cross-origin referer blocked".into()));
        }
    }

    if let Some(csrf_cookie) = cookie_value_from_headers(headers, CSRF_COOKIE) {
        if csrf_cookie.is_empty() {
            return Err(ApiError::Forbidden("invalid csrf cookie".into()));
        }
        let csrf_hdr = headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::Forbidden("missing x-csrf-token".into()))?;
        if !infinity_core::password::constant_time_eq(csrf_cookie.as_bytes(), csrf_hdr.as_bytes()) {
            return Err(ApiError::Forbidden("csrf token mismatch".into()));
        }
    }

    Ok(())
}

#[axum::async_trait]
impl FromRequestParts<SharedState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // 1) Bearer JWT (validated with our own public key components + kid match).
        // When an Authorization header is present, never fall back to session cookie.
        if let Some(auth) = parts.headers.get(header::AUTHORIZATION) {
            let val = auth
                .to_str()
                .map_err(|_| ApiError::Unauthorized("invalid authorization header".into()))?;
            let tok = val
                .strip_prefix("Bearer ")
                .ok_or_else(|| ApiError::Unauthorized("expected Bearer token".into()))?;
            let hdr = token::inspect_header(tok)
                .map_err(|_| ApiError::Unauthorized("invalid or expired token".into()))?;
            let kid = hdr
                .kid
                .ok_or_else(|| ApiError::Unauthorized("token missing kid".into()))?;

            let jwks: Vec<_> = {
                let ring = state.key.read().unwrap_or_else(|e| e.into_inner());
                ring.verification_keys()
                    .filter(|j| j.kid == kid)
                    .cloned()
                    .collect()
            };
            let claims = jwks
                .iter()
                .find_map(|jwk| {
                    token::validate_with_components(tok, &jwk.n, &jwk.e, &state.config.issuer, None)
                        .ok()
                })
                .ok_or_else(|| ApiError::Unauthorized("invalid or expired token".into()))?;
            // Only access tokens may authorize API calls.
            if claims.typ != "access" {
                return Err(ApiError::Unauthorized(
                    "only access tokens are accepted here".into(),
                ));
            }
            // First-party iff the token audience is the issuer itself.
            let first_party = claims.aud == state.config.issuer;
            return resolve(state, &claims.sub, first_party).await;
        }

        // 2) Dashboard session cookie (opaque, stored hashed) — always first-party.
        if let Some(raw) = cookie_value_from_headers(&parts.headers, SESSION_COOKIE) {
            if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
                verify_browser_csrf(&parts.headers, &state.config)?;
            }
            let hash = sha256_hex(&raw);
            if let Some(uid) = store::get_session_user(&state.db, &hash).await? {
                return resolve(state, &uid, true).await;
            }
        }

        Err(ApiError::Unauthorized("authentication required".into()))
    }
}

async fn resolve(
    state: &SharedState,
    user_id: &str,
    first_party: bool,
) -> Result<Principal, ApiError> {
    let row = store::get_user_row(&state.db, user_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("unknown subject".into()))?;
    if row.disabled != 0 {
        return Err(ApiError::Forbidden("account disabled".into()));
    }
    let roles = store::user_roles(&state.db, user_id).await?;
    let permissions = store::user_permissions(&state.db, user_id).await?;
    Ok(Principal {
        user_id: user_id.to_string(),
        roles,
        permissions,
        first_party,
    })
}
