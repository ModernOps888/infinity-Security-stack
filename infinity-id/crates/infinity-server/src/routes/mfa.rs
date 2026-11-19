//! MFA enrolment and lifecycle for the currently authenticated user.

use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::{cookie_value_from_headers, Principal, SESSION_COOKIE};
use crate::error::{ApiError, ApiResult};
use crate::routes::{auth_routes, oidc};
use crate::state::SharedState;
use crate::store;
use crate::util::{random_token, sha256_hex};

#[derive(Deserialize)]
pub struct ActivateRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct DisableRequest {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

/// Rotate the caller's dashboard session cookie on MFA security-level change
/// (prevents session fixation across privilege/MFA transitions) and purge
/// any other open sessions belonging to that user.
async fn rotate_session_if_cookie(
    st: &SharedState,
    headers: &HeaderMap,
    user_id: &str,
    resp: &mut Response,
) -> ApiResult<()> {
    if let Some(old_raw) = cookie_value_from_headers(headers, SESSION_COOKIE) {
        let old_hash = sha256_hex(&old_raw);
        let new_session = random_token();
        let new_hash = sha256_hex(&new_session);
        let new_csrf = random_token();
        store::create_session(&st.db, &new_hash, user_id, st.config.session_ttl_secs).await?;
        let _ = store::delete_session(&st.db, &old_hash).await;
        let _ = store::delete_other_user_sessions(&st.db, user_id, &new_hash).await;

        let secure = st.config.cookie_secure();
        resp.headers_mut().insert(
            SET_COOKIE,
            HeaderValue::from_str(&auth_routes::session_cookie(
                &new_session,
                st.config.session_ttl_secs,
                secure,
            ))
            .map_err(|e| ApiError::Internal(e.to_string()))?,
        );
        resp.headers_mut().append(
            SET_COOKIE,
            HeaderValue::from_str(&auth_routes::csrf_cookie(
                &new_csrf,
                st.config.session_ttl_secs,
                secure,
            ))
            .map_err(|e| ApiError::Internal(e.to_string()))?,
        );
    }
    Ok(())
}

/// POST /mfa/enroll — generate a TOTP secret + recovery codes (not yet active).
pub async fn enroll(
    State(st): State<SharedState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require_first_party()?;
    let user = store::get_user_row(&st.db, &p.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    if user.mfa_enabled != 0 {
        return Err(ApiError::Conflict(
            "MFA is already enabled; disable it before re-enrolling".into(),
        ));
    }

    let secret = infinity_core::mfa::generate_secret();
    let uri = infinity_core::mfa::provisioning_uri(&secret, &st.config.mfa_issuer, &user.email)?;
    store::set_mfa_secret(&st.db, &p.user_id, &secret).await?;

    let codes = infinity_core::mfa::generate_recovery_codes(10);
    let hashes: Vec<String> = codes.iter().map(|c| c.hash.clone()).collect();
    let plaintext: Vec<String> = codes.iter().map(|c| c.plaintext.clone()).collect();
    store::store_recovery_codes(&st.db, &p.user_id, &hashes).await?;

    Ok(Json(json!({
        "secret": secret,
        "otpauth_uri": uri,
        "recovery_codes": plaintext,
        "next": "Scan the QR / enter the secret in your authenticator, then POST the current code to /mfa/activate",
    })))
}

/// POST /mfa/activate — confirm enrolment by verifying the first TOTP code.
pub async fn activate(
    State(st): State<SharedState>,
    headers: HeaderMap,
    p: Principal,
    Json(req): Json<ActivateRequest>,
) -> ApiResult<Response> {
    p.require_first_party()?;
    let mfa_key = format!("mfa:{}", p.user_id);
    if let Err(retry) = st.login_throttle.check(&mfa_key) {
        return Err(ApiError::TooManyRequests(format!(
            "too many MFA attempts; retry in {retry}s"
        )));
    }

    let user = store::get_user_row(&st.db, &p.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    if user.mfa_enabled != 0 {
        return Err(ApiError::Conflict("MFA is already enabled".into()));
    }
    let secret = user.mfa_secret.as_deref().ok_or_else(|| {
        ApiError::BadRequest("no pending MFA enrolment; call /mfa/enroll first".into())
    })?;
    let ok = infinity_core::mfa::verify_totp(secret, &req.code, &st.config.mfa_issuer, &user.email)
        .unwrap_or(false);
    if !ok {
        st.login_throttle.record_failure_with_threshold(&mfa_key, 5);
        return Err(ApiError::BadRequest("invalid code".into()));
    }
    st.login_throttle.record_success(&mfa_key);
    store::enable_mfa(&st.db, &p.user_id).await?;
    store::audit(&st.db, &p.user_id, "mfa.enabled", None, None, None).await;

    let mut resp = Json(json!({ "mfa_enabled": true })).into_response();
    rotate_session_if_cookie(&st, &headers, &p.user_id, &mut resp).await?;
    Ok(resp)
}

/// POST /mfa/disable — turn MFA off for the current user (requires step-up
/// password or valid TOTP/recovery code verification).
pub async fn disable(
    State(st): State<SharedState>,
    headers: HeaderMap,
    p: Principal,
    body: Option<Json<DisableRequest>>,
) -> ApiResult<Response> {
    p.require_first_party()?;
    let mfa_key = format!("mfa:{}", p.user_id);
    if let Err(retry) = st.login_throttle.check(&mfa_key) {
        return Err(ApiError::TooManyRequests(format!(
            "too many MFA attempts; retry in {retry}s"
        )));
    }

    let req = body.map(|b| b.0).unwrap_or(DisableRequest {
        password: None,
        code: None,
    });
    let user = store::get_user_row(&st.db, &p.user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    let verified = if let Some(pw) = req.password.as_deref().filter(|s| !s.is_empty()) {
        infinity_core::password::verify_password(pw, &user.password_hash)?
    } else if let Some(code) = req.code.as_deref().filter(|s| !s.trim().is_empty()) {
        if user.mfa_enabled != 0 {
            oidc::verify_second_factor(&st, &user, Some(code))
                .await
                .is_ok()
        } else {
            false
        }
    } else {
        return Err(ApiError::BadRequest(
            "password or current MFA code required to disable MFA".into(),
        ));
    };

    if !verified {
        st.login_throttle.record_failure_with_threshold(&mfa_key, 5);
        return Err(ApiError::Unauthorized("invalid credentials".into()));
    }

    st.login_throttle.record_success(&mfa_key);
    store::disable_mfa(&st.db, &p.user_id).await?;
    store::audit(&st.db, &p.user_id, "mfa.disabled", None, None, None).await;

    let mut resp = Json(json!({ "mfa_enabled": false })).into_response();
    rotate_session_if_cookie(&st, &headers, &p.user_id, &mut resp).await?;
    Ok(resp)
}
