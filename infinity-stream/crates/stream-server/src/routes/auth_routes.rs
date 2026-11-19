use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, PRAGMA, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{extract_cookie, Principal, PrincipalKind, SESSION_COOKIE};
use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;
use crate::store;
use crate::util::{random_token, sha256_hex};

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

fn set_no_store(resp: &mut Response) {
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
}

pub async fn login(
    State(st): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Response> {
    let throttle_key = req.email.trim().to_lowercase();
    if throttle_key.is_empty()
        || throttle_key.len() > 320
        || req.password.is_empty()
        || req.password.len() > 1024
    {
        stream_core::password::dummy_verify(&req.password);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    if let Err(retry) = st.login_throttle.check(&throttle_key) {
        return Err(ApiError::TooManyRequests(format!(
            "too many attempts; retry in {retry}s"
        )));
    }

    let Some((id, email, username, hash)) = store::get_user_by_email(&st.db, &throttle_key).await?
    else {
        stream_core::password::dummy_verify(&req.password);
        st.login_throttle.record_failure(&throttle_key);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    };
    if !stream_core::password::verify_password(&req.password, &hash)? {
        st.login_throttle.record_failure(&throttle_key);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }
    st.login_throttle.record_success(&throttle_key);

    // Session fixation prevention: invalidate any pre-existing session cookie
    // before issuing a freshly minted CSPRNG session token.
    if let Some(old_raw) = extract_cookie(&headers, SESSION_COOKIE) {
        let _ = store::delete_session(&st.db, &sha256_hex(&old_raw)).await;
    }

    let session = random_token();
    store::create_session(
        &st.db,
        &sha256_hex(&session),
        &id,
        st.config.session_ttl_secs,
    )
    .await?;
    let mut resp = Json(json!({
        "user": {
            "id": id,
            "email": email,
            "username": username,
            "roles": ["superadmin"],
            "permissions": ["*:*"]
        }
    }))
    .into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(
            &session,
            st.config.session_ttl_secs,
            st.config.cookie_secure(),
        ))
        .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    set_no_store(&mut resp);
    Ok(resp)
}

pub async fn logout(
    State(st): State<SharedState>,
    headers: HeaderMap,
    principal: Principal,
) -> ApiResult<Response> {
    if matches!(principal.kind, PrincipalKind::ApiKey) {
        return Err(ApiError::Forbidden(
            "API keys cannot manage user sessions".into(),
        ));
    }
    if let Some(raw) = extract_cookie(&headers, SESSION_COOKIE) {
        store::delete_session(&st.db, &sha256_hex(&raw)).await?;
    }
    let mut resp = Json(json!({"ok":true,"subject":principal.subject})).into_response();
    resp.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie("", 0, st.config.cookie_secure()))
            .map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    set_no_store(&mut resp);
    Ok(resp)
}

pub async fn me(State(st): State<SharedState>, principal: Principal) -> ApiResult<Response> {
    let ((email, username), roles) = match principal.kind {
        PrincipalKind::User => (
            store::get_user_by_id(&st.db, &principal.subject)
                .await?
                .unwrap_or_else(|| ("unknown".into(), "unknown".into())),
            vec!["superadmin"],
        ),
        PrincipalKind::ApiKey => (("api-key".into(), "api-key".into()), Vec::new()),
    };
    let mut resp = Json(json!({
        "id": principal.subject,
        "kind": format!("{:?}", principal.kind),
        "username": username,
        "email": email,
        "roles": roles,
        "permissions": principal.permissions
    }))
    .into_response();
    set_no_store(&mut resp);
    Ok(resp)
}
