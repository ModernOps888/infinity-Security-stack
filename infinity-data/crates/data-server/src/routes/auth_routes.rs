use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{cookie_value, Principal, SESSION_COOKIE};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;
use crate::util::{self, random_token, sha256_hex};

const MAX_IP_LOGIN_FAILS: u32 = 30;

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

fn clear_cookie(secure: bool) -> String {
    let base = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    if secure {
        format!("{base}; Secure")
    } else {
        base
    }
}

fn header_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    header.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

pub async fn login(
    State(st): State<SharedState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let email = req.email.trim().to_ascii_lowercase();
    let proxies = util::parse_trusted_proxies(&st.config.trusted_proxies);
    let client_ip = util::extract_client_ip(&headers, peer.map(|c| c.0), &proxies);
    let ua = util::sanitize_user_agent(&headers);
    let acct_key = format!("acct:{email}");
    let ip_key = format!("ip:{client_ip}");

    if email.is_empty() || email.len() > 254 || req.password.len() > 1024 {
        data_core::password::dummy_verify(&req.password);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    if let Err(retry) = st.login_throttle.check(&acct_key) {
        return Err(ApiError::TooManyRequests(format!(
            "too many attempts; retry in {retry}s"
        )));
    }
    if let Err(retry) = st.login_throttle.check(&ip_key) {
        return Err(ApiError::TooManyRequests(format!(
            "too many attempts; retry in {retry}s"
        )));
    }

    let Some(user) = store::get_user_by_email(&st.db, &email).await? else {
        data_core::password::dummy_verify(&req.password);
        st.login_throttle.record_failure(&acct_key);
        st.login_throttle
            .record_failure_with_limit(&ip_key, MAX_IP_LOGIN_FAILS);
        store::audit(
            &st.db,
            None,
            "login.fail",
            Some("unknown"),
            None,
            Some(&client_ip),
            ua.as_deref(),
        )
        .await;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    };
    if !data_core::password::verify_password(&req.password, &user.password_hash)? {
        st.login_throttle.record_failure(&acct_key);
        st.login_throttle
            .record_failure_with_limit(&ip_key, MAX_IP_LOGIN_FAILS);
        store::audit(
            &st.db,
            Some(&user.id),
            "login.fail",
            Some("user"),
            None,
            Some(&client_ip),
            ua.as_deref(),
        )
        .await;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    if user.disabled != 0 {
        st.login_throttle.record_failure(&acct_key);
        st.login_throttle
            .record_failure_with_limit(&ip_key, MAX_IP_LOGIN_FAILS);
        store::audit(
            &st.db,
            Some(&user.id),
            "login.fail",
            Some("user"),
            None,
            Some(&client_ip),
            ua.as_deref(),
        )
        .await;
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    st.login_throttle.record_success(&acct_key);
    st.login_throttle.record_success(&ip_key);

    // Session fixation defense: revoke any pre-existing session cookie on the login request
    // and always bind a fresh CSPRNG session identifier.
    if let Some(old_raw) = header_cookie_value(&headers, SESSION_COOKIE) {
        let _ = store::delete_session(&st.db, &sha256_hex(&old_raw)).await;
    }

    let session = random_token();
    store::create_session(
        &st.db,
        &sha256_hex(&session),
        &user.id,
        st.config.session_ttl_secs,
    )
    .await?;
    store::audit(
        &st.db,
        Some(&user.id),
        "login.success",
        Some("user"),
        None,
        Some(&client_ip),
        ua.as_deref(),
    )
    .await;
    let roles = store::user_roles(&st.db, &user.id).await?;
    let permissions = store::user_permissions(&st.db, &user.id).await?;
    let body = json!({"user":{"id":user.id,"email":user.email,"username":user.username,"display_name":user.display_name,"roles":roles,"permissions":permissions}});
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(
            &session,
            st.config.session_ttl_secs,
            st.config.secure_cookies(),
        ))
        .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    Ok(resp)
}

pub async fn logout(
    State(st): State<SharedState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    principal: Principal,
) -> ApiResult<Response> {
    if principal.user_id.starts_with("api_key:") {
        return Err(ApiError::Forbidden("user session required".into()));
    }
    let proxies = util::parse_trusted_proxies(&st.config.trusted_proxies);
    let client_ip = util::extract_client_ip(&headers, peer.map(|c| c.0), &proxies);
    let ua = util::sanitize_user_agent(&headers);
    if let Some(raw) = header_cookie_value(&headers, SESSION_COOKIE) {
        store::delete_session(&st.db, &sha256_hex(&raw)).await?;
    }
    let _ = cookie_value;
    store::audit(
        &st.db,
        Some(&principal.user_id),
        "logout",
        Some("session"),
        None,
        Some(&client_ip),
        ua.as_deref(),
    )
    .await;
    let mut resp = Json(json!({"ok": true})).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&clear_cookie(st.config.secure_cookies()))
            .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    Ok(resp)
}

pub async fn me(
    State(st): State<SharedState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    if principal.user_id.starts_with("api_key:") {
        return Err(ApiError::Forbidden("user session required".into()));
    }
    let user = store::get_user(&st.db, &principal.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    Ok(Json(json!({
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "display_name": user.display_name,
        "roles": principal.roles,
        "permissions": principal.permissions
    })))
}
