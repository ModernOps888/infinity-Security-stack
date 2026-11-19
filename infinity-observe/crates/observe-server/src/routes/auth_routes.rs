use axum::extract::{FromRequestParts, State};
use axum::http::header::{CACHE_CONTROL, PRAGMA, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use url::{Host, Url};

use crate::auth::{bearer, cookie_value, Principal, SESSION_COOKIE};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;
use crate::util::{random_token, sha256_hex};

#[derive(Debug, Clone)]
pub struct ClientIp(pub String);

#[axum::async_trait]
impl FromRequestParts<SharedState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ClientIp>()
            .map(|c| c.0.clone())
            .unwrap_or_else(|| "unknown".into());
        Ok(ClientIp(ip))
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

fn session_cookie(token: &str, ttl: i64, secure: bool) -> String {
    let base =
        format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}");
    if secure {
        format!("{base}; Secure")
    } else {
        base
    }
}

fn clear_session_cookie(secure: bool) -> String {
    let base = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    if secure {
        format!("{base}; Secure")
    } else {
        base
    }
}

/// Only omit `Secure` for explicit local loopback HTTP (`http://localhost`,
/// `http://127.0.0.0/8`, `http://[::1]`). Any other host or `https://` sets `Secure`.
fn use_secure_cookie(st: &SharedState) -> bool {
    let Ok(url) = Url::parse(&st.config.public_url) else {
        return true;
    };
    if url.scheme() != "http" {
        return true;
    }
    let is_loopback = match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    !is_loopback
}

fn cookie_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == SESSION_COOKIE).then(|| v.trim().to_string())
        })
}

fn attach_no_store(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
}

pub struct AuthExtract(pub Option<String>);

#[axum::async_trait]
impl FromRequestParts<SharedState> for AuthExtract {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        let tok = if parts
            .headers
            .contains_key(axum::http::header::AUTHORIZATION)
        {
            bearer(parts)
        } else {
            cookie_value(parts, SESSION_COOKIE)
        };
        Ok(AuthExtract(tok))
    }
}

pub async fn login(
    State(st): State<SharedState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    if let Err(retry) = st.login_throttle.check_ip(&client_ip) {
        return Err(ApiError::TooManyRequests(format!(
            "too many attempts; retry in {retry}s"
        )));
    }

    let email = req.email.trim().to_lowercase();
    if email.is_empty() || email.len() > 254 || req.password.len() > 1024 {
        let safe_pw = if req.password.len() <= 1024 {
            &req.password
        } else {
            ""
        };
        observe_core::password::dummy_verify(safe_pw);
        st.login_throttle.record_ip_failure(&client_ip);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    if let Err(retry) = st.login_throttle.check(&email) {
        return Err(ApiError::TooManyRequests(format!(
            "too many attempts; retry in {retry}s"
        )));
    }

    let user = match store::get_user_by_email(&st.db, &email).await? {
        Some(u) => u,
        None => {
            observe_core::password::dummy_verify(&req.password);
            st.login_throttle.record_failure(&email);
            st.login_throttle.record_ip_failure(&client_ip);
            return Err(ApiError::Unauthorized("invalid credentials".into()));
        }
    };
    if !observe_core::password::verify_password(&req.password, &user.password_hash)? {
        st.login_throttle.record_failure(&email);
        st.login_throttle.record_ip_failure(&client_ip);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    if user.disabled != 0 {
        st.login_throttle.record_failure(&email);
        st.login_throttle.record_ip_failure(&client_ip);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    st.login_throttle.record_success(&email);
    st.login_throttle.record_ip_success(&client_ip);

    // Session fixation defense: invalidate any pre-existing session cookie on re-auth.
    if let Some(old_session) = cookie_from_headers(&headers) {
        if !old_session.is_empty() {
            let _ = store::delete_session(&st.db, &sha256_hex(&old_session)).await;
        }
    }

    let session = random_token();
    store::create_session(
        &st.db,
        &sha256_hex(&session),
        &user.id,
        st.config.session_ttl_secs,
    )
    .await?;
    let permissions = observe_core::rbac::permissions_for_role(&user.role);
    let mut resp = Json(json!({
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "display_name": user.display_name,
            "role": user.role,
            "permissions": permissions
        }
    }))
    .into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(
            &session,
            st.config.session_ttl_secs,
            use_secure_cookie(&st),
        ))
        .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    attach_no_store(resp.headers_mut());
    Ok(resp)
}

pub async fn logout(
    State(st): State<SharedState>,
    AuthExtract(tok): AuthExtract,
    principal: Principal,
) -> ApiResult<Response> {
    if let Some(raw) = tok {
        store::delete_session(&st.db, &sha256_hex(&raw)).await?;
    }
    let mut resp = Json(json!({ "ok": true, "user_id": principal.user_id })).into_response();
    let cleared = clear_session_cookie(use_secure_cookie(&st));
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&cleared).map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    attach_no_store(resp.headers_mut());
    Ok(resp)
}

pub async fn me(principal: Principal) -> ApiResult<Response> {
    let mut resp = Json(json!({
        "id": principal.user_id,
        "email": principal.email,
        "role": principal.role,
        "permissions": principal.permissions,
    }))
    .into_response();
    attach_no_store(resp.headers_mut());
    Ok(resp)
}
