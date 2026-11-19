//! Integration tests for security-critical HTTP surface that had never been
//! exercised by an automated test: the OAuth2 authorization-code + PKCE
//! flow, refresh-token rotation/reuse detection, and TOTP MFA replay
//! protection.
//!
//! Each test drives the *real* axum `Router` (`infinity_server::routes::router`)
//! in-process via `tower::ServiceExt::oneshot` against a fresh temp-file
//! SQLite database with the same migrations `main.rs` applies at startup —
//! no mocks, no live TCP port.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::BodyExt;
use rand::Rng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use totp_rs::{Algorithm, Secret, TOTP};
use tower::ServiceExt;

use infinity_core::keys::KeyRing;
use infinity_server::config::Config;
use infinity_server::ratelimit::IpRateLimiter;
use infinity_server::routes;
use infinity_server::state::{AppState, SharedState};
use infinity_server::store::{self, NewClient, NewUser};
use infinity_server::throttle::LoginThrottle;

// ---------------------------------------------------------------------------
// Test fixtures / helpers
// ---------------------------------------------------------------------------

/// Build a fresh `AppState` backed by a unique temp-file SQLite database with
/// migrations applied, mirroring exactly what `main.rs` does at startup.
async fn test_state() -> SharedState {
    let db_path = std::env::temp_dir().join(format!(
        "infinity-id-security-test-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))
        .expect("parse sqlite url")
        .create_if_missing(true)
        .busy_timeout(std::time::Duration::from_secs(5));
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("connect sqlite");
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("run migrations");

    let key_dir = std::env::temp_dir().join(format!(
        "infinity-id-security-test-key-{}",
        uuid::Uuid::new_v4()
    ));
    let key_path = key_dir.join("signing_key.pem");
    let key = KeyRing::load_or_generate(&key_path, 3600).expect("generate signing key");

    // Disable the global per-IP limiter so it can't interfere with tests that
    // fire several requests back-to-back.
    let config = Config {
        global_rate_limit_per_min: 0,
        ..Config::default()
    };

    Arc::new(AppState {
        db,
        key: RwLock::new(key),
        key_path,
        config,
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(0),
    })
}

async fn await_safe_window(period_secs: u64) {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let secs_left = period_secs - (now_secs % period_secs);
    if secs_left <= 3 {
        tokio::time::sleep(std::time::Duration::from_millis((secs_left * 1000) + 50)).await;
    }
}

async fn await_safe_minute_window() {
    await_safe_window(60).await;
}

async fn await_safe_totp_window() {
    await_safe_window(30).await;
}

/// Send a request through the real router. Manually inserts a `ConnectInfo`
/// extension (normally supplied by `into_make_service_with_connect_info` in
/// `main.rs`) because the per-IP rate-limit middleware extracts it.
async fn send(app: &Router, mut req: Request<Body>) -> Response {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    app.clone().oneshot(req).await.expect("router call")
}

async fn json_body(resp: Response) -> Value {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("invalid json body: {e}: {bytes:?}"))
    }
}

async fn create_user(db: &sqlx::SqlitePool, email: &str, username: &str, password: &str) -> String {
    let hash = infinity_core::password::hash_password(password).expect("hash password");
    store::create_user(
        db,
        NewUser {
            email,
            username,
            display_name: None,
            password_hash: &hash,
            roles: &[],
        },
    )
    .await
    .expect("create user")
}

/// Register a public (PKCE-only, no client secret) OAuth client.
async fn create_public_client(db: &sqlx::SqlitePool, redirect_uri: &str) -> String {
    store::create_client(
        db,
        NewClient {
            name: "test-client",
            secret_hash: None,
            redirect_uris: &[redirect_uri.to_string()],
            grant_types: &["authorization_code".into(), "refresh_token".into()],
            scopes: &["openid".into(), "profile".into(), "offline_access".into()],
            public: true,
        },
    )
    .await
    .expect("create client")
}

/// POST /auth/login. Returns (status, session cookie value if any, json body).
async fn login(
    app: &Router,
    email: &str,
    password: &str,
    otp: Option<&str>,
) -> (StatusCode, Option<String>, Value) {
    let mut body = json!({ "email": email, "password": password });
    if let Some(otp) = otp {
        body["otp"] = json!(otp);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = send(app, req).await;
    let status = resp.status();
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap().to_string());
    let json = json_body(resp).await;
    (status, cookie, json)
}

/// A PKCE `code_verifier` / S256 `code_challenge` pair.
struct Pkce {
    verifier: String,
    challenge: String,
}

fn random_pkce() -> Pkce {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    let verifier: String = (0..64)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
    Pkce {
        verifier,
        challenge,
    }
}

/// Drive GET /oauth/authorize with a valid session cookie and PKCE challenge;
/// returns the `code` extracted from the redirect's `Location` header.
async fn authorize(
    app: &Router,
    cookie: &str,
    client_id: &str,
    redirect_uri: &str,
    pkce: &Pkce,
) -> String {
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope=openid&state=xyz123&code_challenge={}&code_challenge_method=S256",
        pkce.challenge
    );
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    let resp = send(app, req).await;
    assert!(
        resp.status().is_redirection(),
        "expected a redirect from /oauth/authorize, got {}: {:?}",
        resp.status(),
        json_body(resp).await
    );
    let location = resp
        .headers()
        .get(header::LOCATION)
        .expect("Location header on authorize redirect")
        .to_str()
        .unwrap()
        .to_string();
    let query = location
        .split_once('?')
        .expect("redirect has query string")
        .1;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix("code=").map(|c| c.to_string()))
        .expect("redirect contains code=")
}

/// POST /oauth/token with an arbitrary form body, returning (status, json).
async fn token_request(app: &Router, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let body = form
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let resp = send(app, req).await;
    let status = resp.status();
    (status, json_body(resp).await)
}

const REDIRECT_URI: &str = "https://client.example/callback";

/// Full setup used by both the PKCE and refresh-rotation tests: a user, a
/// public PKCE client, a logged-in session cookie, and the router.
async fn setup_authorize_flow() -> (Router, SharedState, String, String, String) {
    let state = test_state().await;
    create_user(
        &state.db,
        "alice@example.com",
        "alice",
        "correct horse battery staple",
    )
    .await;
    let client_id = create_public_client(&state.db, REDIRECT_URI).await;
    let app = routes::router(state.clone());
    let (status, cookie, _) = login(
        &app,
        "alice@example.com",
        "correct horse battery staple",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "setup login must succeed");
    let cookie = cookie.expect("login must set a session cookie");
    (app, state, client_id, cookie, REDIRECT_URI.to_string())
}

// ---------------------------------------------------------------------------
// 1. OAuth2 authorization-code + PKCE flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oauth_authorize_and_token_pkce_success() {
    let (app, _state, client_id, cookie, redirect_uri) = setup_authorize_flow().await;
    let pkce = random_pkce();

    let code = authorize(&app, &cookie, &client_id, &redirect_uri, &pkce).await;

    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "valid PKCE exchange must succeed: {body:?}"
    );
    assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(body["refresh_token"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
    assert!(
        body["id_token"].as_str().is_some_and(|s| !s.is_empty()),
        "openid scope must yield an id_token"
    );
}

#[tokio::test]
async fn oauth_token_rejects_wrong_code_verifier() {
    let (app, _state, client_id, cookie, redirect_uri) = setup_authorize_flow().await;
    let pkce = random_pkce();
    let code = authorize(&app, &cookie, &client_id, &redirect_uri, &pkce).await;

    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", "totally-wrong-verifier-value-xyz"),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "wrong code_verifier must be rejected: {body:?}"
    );
    assert!(body["access_token"].is_null());
}

#[tokio::test]
async fn oauth_token_rejects_missing_code_verifier() {
    let (app, _state, client_id, cookie, redirect_uri) = setup_authorize_flow().await;
    let pkce = random_pkce();
    let code = authorize(&app, &cookie, &client_id, &redirect_uri, &pkce).await;

    // No code_verifier at all — must be rejected the same as a wrong one.
    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
        ],
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing code_verifier must be rejected: {body:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. Refresh-token rotation + reuse detection
// ---------------------------------------------------------------------------

/// Real behavior confirmed by reading `crates/infinity-server/src/routes/oidc.rs`
/// (`grant_refresh`) and `crates/infinity-server/src/store/mod.rs`
/// (`revoke_refresh_family`): replaying an already-rotated refresh token does
/// **not** just invalidate that one token — it revokes every refresh token for
/// that user+client pair (the whole "family"/session for that client), per the
/// `oauth.refresh_reuse` audit event and the explicit
/// `revoke_refresh_family(user_id, client_id)` call. This test asserts that
/// full-family revocation, not single-token revocation.
#[tokio::test]
async fn refresh_token_reuse_revokes_whole_family() {
    let (app, _state, client_id, cookie, redirect_uri) = setup_authorize_flow().await;
    let pkce = random_pkce();
    let code = authorize(&app, &cookie, &client_id, &redirect_uri, &pkce).await;
    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "initial code exchange must succeed: {body:?}"
    );
    let refresh1 = body["refresh_token"].as_str().unwrap().to_string();

    // Rotate: exchanging refresh1 must succeed and mint a *different* refresh2,
    // and must invalidate refresh1.
    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh1),
            ("client_id", &client_id),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "first refresh must succeed: {body:?}"
    );
    let refresh2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(
        refresh1, refresh2,
        "rotation must issue a brand new refresh token"
    );

    // Replay the rotated-away refresh1 — must be rejected.
    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh1),
            ("client_id", &client_id),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "replaying an already-rotated refresh token must be rejected: {body:?}"
    );

    // The just-issued refresh2 must ALSO now be dead: reuse of refresh1 is a
    // compromise signal that revokes the whole user+client refresh-token
    // family, not just the replayed token.
    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh2),
            ("client_id", &client_id),
        ],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "reuse detection must revoke the WHOLE refresh-token family, so the \
         still-fresh refresh2 must also be rejected afterwards: {body:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. TOTP MFA replay-window rejection
// ---------------------------------------------------------------------------

fn current_totp_code(secret_b32: &str, issuer: &str, account: &str) -> String {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .expect("decode base32 secret");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some(issuer.to_string()),
        account.to_string(),
    )
    .expect("build TOTP");
    totp.generate_current().expect("generate current TOTP code")
}

#[tokio::test]
async fn totp_code_cannot_be_replayed_within_its_validity_window() {
    let state = test_state().await;
    let email = "bob@example.com";
    let password = "correct horse battery staple";
    create_user(&state.db, email, "bob", password).await;
    let app = routes::router(state.clone());

    // Log in once (no MFA yet) to get a session for the self-service MFA API.
    let (status, cookie, _) = login(&app, email, password, None).await;
    assert_eq!(status, StatusCode::OK);
    let cookie = cookie.unwrap();

    // Enroll: get the TOTP secret.
    let req = Request::builder()
        .method("POST")
        .uri("/mfa/enroll")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let secret = body["secret"]
        .as_str()
        .expect("enroll returns a secret")
        .to_string();

    await_safe_totp_window().await;
    let code = current_totp_code(&secret, &state.config.mfa_issuer, email);

    // Activate using the current code.
    let req = Request::builder()
        .method("POST")
        .uri("/mfa/activate")
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "code": code }).to_string()))
        .unwrap();
    let resp = send(&app, req).await;
    let status = resp.status();
    let activate_body = json_body(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "activation with a fresh code must succeed: {activate_body:?}"
    );

    // First login with this TOTP code as the second factor: must succeed, and
    // it should record this step as consumed (one-time-use high-water mark).
    let (status, _cookie2, body) = login(&app, email, password, Some(&code)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "first use of the TOTP code at login must succeed: {body:?}"
    );

    // Replay: logging in again with the exact same TOTP code (still within its
    // ±1 step / 30s validity window) must now be rejected.
    let (status, _cookie3, body) = login(&app, email, password, Some(&code)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "reusing the same TOTP code a second time must be rejected as a replay: {body:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. PKCE S256 enforcement, required redirect_uri, single-use auth codes,
//    and grant_types enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pkce_enforces_s256_only_and_requires_redirect_uri_on_token() {
    let state = test_state().await;
    create_user(
        &state.db,
        "pkce@example.com",
        "pkceuser",
        "correct horse battery staple",
    )
    .await;
    let secret = "super-secret-client-credential-value";
    let conf_id = store::create_client(
        &state.db,
        NewClient {
            name: "conf-app",
            secret_hash: Some(&infinity_server::util::sha256_hex(secret)),
            redirect_uris: &[REDIRECT_URI.to_string()],
            grant_types: &["authorization_code".into(), "refresh_token".into()],
            scopes: &["openid".into(), "profile".into()],
            public: false,
        },
    )
    .await
    .unwrap();
    let app = routes::router(state.clone());
    let (st, cookie, _) = login(
        &app,
        "pkce@example.com",
        "correct horse battery staple",
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let cookie = cookie.unwrap();

    // Missing code_challenge even on confidential client is rejected.
    let req = Request::builder()
        .uri(format!("/oauth/authorize?response_type=code&client_id={conf_id}&redirect_uri={REDIRECT_URI}&scope=openid"))
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.status(), StatusCode::BAD_REQUEST);

    // `plain` PKCE method is refused.
    let pkce = random_pkce();
    let req = Request::builder()
        .uri(format!(
            "/oauth/authorize?response_type=code&client_id={conf_id}&redirect_uri={REDIRECT_URI}&scope=openid&code_challenge={}&code_challenge_method=plain",
            pkce.verifier
        ))
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.status(), StatusCode::BAD_REQUEST);

    // Valid S256 authorize works; omitting redirect_uri on /oauth/token is rejected (RFC 6749 §4.1.3).
    let code = authorize(&app, &cookie, &conf_id, REDIRECT_URI, &pkce).await;
    let (status, _) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("client_id", &conf_id),
            ("client_secret", secret),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Single-use: the consumed auth code cannot be redeemed again even with valid params.
    let (status2, _) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &conf_id),
            ("client_secret", secret),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await;
    assert_eq!(status2, StatusCode::BAD_REQUEST);

    // Valid exchange with redirect_uri + client_secret + S256 code_verifier succeeds.
    let pkce2 = random_pkce();
    let code2 = authorize(&app, &cookie, &conf_id, REDIRECT_URI, &pkce2).await;
    let (status3, body3) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code2),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &conf_id),
            ("client_secret", secret),
            ("code_verifier", &pkce2.verifier),
        ],
    )
    .await;
    assert_eq!(status3, StatusCode::OK, "{body3:?}");
}

#[tokio::test]
async fn redirect_uri_and_state_injection_defenses() {
    let state = test_state().await;
    let mut seed_cfg = state.config.clone();
    seed_cfg.admin_password = "StrongTestAdminPassword!987".into();
    store::seed(&state.db, &seed_cfg).await.unwrap();

    let app = routes::router(state.clone());
    let (st, cookie, _) = login(&app, &seed_cfg.admin_email, &seed_cfg.admin_password, None).await;
    assert_eq!(st, StatusCode::OK);
    let cookie = cookie.unwrap();

    for bad_uri in [
        "javascript:alert(1)",
        "https://client.example/cb#frag",
        "https://*.client.example/cb",
        "https://client.example/cb\r\nX-Inject: 1",
        "http://evil.example/cb",
    ] {
        let req = Request::builder()
            .method("POST")
            .uri("/admin/clients")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "name": "bad-client",
                    "redirect_uris": [bad_uri],
                    "public": true
                })
                .to_string(),
            ))
            .unwrap();
        let resp = send(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "must reject {bad_uri}"
        );
    }

    // Valid loopback redirect_uri is accepted.
    let req = Request::builder()
        .method("POST")
        .uri("/admin/clients")
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "name": "good-client",
                "redirect_uris": ["http://127.0.0.1:4000/cb"],
                "public": true
            })
            .to_string(),
        ))
        .unwrap();
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cid = json_body(resp).await["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Control characters in `state` return 400 rather than panicking Redirect::to.
    let pkce = random_pkce();
    let req = Request::builder()
        .uri(format!(
            "/oauth/authorize?response_type=code&client_id={cid}&redirect_uri=http://127.0.0.1:4000/cb&state=bad%0d%0a&code_challenge={}&code_challenge_method=S256",
            pkce.challenge
        ))
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.status(), StatusCode::BAD_REQUEST);

    // Special query characters in `state` are URL-encoded safely.
    let req = Request::builder()
        .uri(format!(
            "/oauth/authorize?response_type=code&client_id={cid}&redirect_uri=http://127.0.0.1:4000/cb&state=a%26admin%3D1&code_challenge={}&code_challenge_method=S256",
            pkce.challenge
        ))
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc.contains("state=a%26admin%3D1"),
        "state must be URL-encoded: {loc}"
    );
}

#[tokio::test]
async fn grant_types_enforced_per_client() {
    let state = test_state().await;
    create_user(
        &state.db,
        "gt@example.com",
        "gtuser",
        "correct horse battery staple",
    )
    .await;
    let secret = "secret-gt-value-12345";
    let cc_only = store::create_client(
        &state.db,
        NewClient {
            name: "m2m-only",
            secret_hash: Some(&infinity_server::util::sha256_hex(secret)),
            redirect_uris: &[REDIRECT_URI.to_string()],
            grant_types: &["client_credentials".into()],
            scopes: &["api:read".into()],
            public: false,
        },
    )
    .await
    .unwrap();
    let app = routes::router(state.clone());
    let (_, cookie, _) = login(&app, "gt@example.com", "correct horse battery staple", None).await;
    let cookie = cookie.unwrap();
    let pkce = random_pkce();

    // client_credentials-only client cannot initiate /oauth/authorize.
    let req = Request::builder()
        .uri(format!(
            "/oauth/authorize?response_type=code&client_id={cc_only}&redirect_uri={REDIRECT_URI}&code_challenge={}&code_challenge_method=S256",
            pkce.challenge
        ))
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.status(), StatusCode::BAD_REQUEST);

    // But client_credentials grant succeeds for it.
    let (st, body) = token_request(
        &app,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &cc_only),
            ("client_secret", secret),
        ],
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body:?}");
}

#[tokio::test]
async fn refresh_token_concurrent_rotation_prevents_double_mint() {
    let (app, _state, client_id, cookie, redirect_uri) = setup_authorize_flow().await;
    let pkce = random_pkce();
    let code = authorize(&app, &cookie, &client_id, &redirect_uri, &pkce).await;
    let (status, body) = token_request(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", &pkce.verifier),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let refresh1 = body["refresh_token"].as_str().unwrap().to_string();

    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh1.as_str()),
        ("client_id", client_id.as_str()),
    ];
    let (r1, r2) = tokio::join!(token_request(&app, &form), token_request(&app, &form),);
    let ok_count = [r1.0, r2.0]
        .into_iter()
        .filter(|s| *s == StatusCode::OK)
        .count();
    assert!(
        ok_count <= 1,
        "concurrent refresh must never mint two valid successor tokens: {r1:?} vs {r2:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. Session fixation, CSRF protection, cookie flags, and MFA step-up/lockout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_fixation_csrf_and_cookie_flags_hardened() {
    let mut state = test_state().await;
    if let Some(cfg) = Arc::get_mut(&mut state) {
        cfg.config.issuer = "https://id.example.com".into();
        cfg.config.cors_origins = vec!["https://id.example.com".into()];
    }
    create_user(
        &state.db,
        "csrf@example.com",
        "csrfuser",
        "correct horse battery staple",
    )
    .await;
    let app = routes::router(state.clone());

    // Initial login gets session1 + csrf1, both with Secure; SameSite=Strict.
    let (st1, cookie1, _) = login(
        &app,
        "csrf@example.com",
        "correct horse battery staple",
        None,
    )
    .await;
    assert_eq!(st1, StatusCode::OK);
    let cookie1 = cookie1.unwrap();

    // Login again while presenting cookie1 -> old session1 MUST be revoked (fixation guard).
    let req = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &cookie1)
        .body(Body::from(
            json!({ "email": "csrf@example.com", "password": "correct horse battery staple" })
                .to_string(),
        ))
        .unwrap();
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookies: Vec<String> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert_eq!(set_cookies.len(), 2);
    assert!(
        set_cookies[0].contains("HttpOnly")
            && set_cookies[0].contains("SameSite=Strict")
            && set_cookies[0].contains("Secure")
    );
    assert!(
        set_cookies[1].starts_with("infinity_csrf=")
            && set_cookies[1].contains("SameSite=Strict")
            && set_cookies[1].contains("Secure")
    );
    let cookie2 = set_cookies[0].split(';').next().unwrap().to_string();
    let csrf2 = set_cookies[1].split(';').next().unwrap().to_string();
    let csrf2_val = csrf2.strip_prefix("infinity_csrf=").unwrap();

    // Old session1 is now rejected.
    let req_old = Request::builder()
        .uri("/auth/me")
        .header(header::COOKIE, &cookie1)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req_old).await.status(), StatusCode::UNAUTHORIZED);

    // Cross-origin / Sec-Fetch-Site / missing X-CSRF-Token blocked with 403.
    let req_bad_origin = Request::builder()
        .method("POST")
        .uri("/mfa/enroll")
        .header(header::COOKIE, format!("{cookie2}; {csrf2}"))
        .header("x-csrf-token", csrf2_val)
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(&app, req_bad_origin).await.status(),
        StatusCode::FORBIDDEN
    );

    let req_bad_sfs = Request::builder()
        .method("POST")
        .uri("/mfa/enroll")
        .header(header::COOKIE, format!("{cookie2}; {csrf2}"))
        .header("x-csrf-token", csrf2_val)
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(&app, req_bad_sfs).await.status(),
        StatusCode::FORBIDDEN
    );

    let req_no_csrf_hdr = Request::builder()
        .method("POST")
        .uri("/mfa/enroll")
        .header(header::COOKIE, format!("{cookie2}; {csrf2}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(&app, req_no_csrf_hdr).await.status(),
        StatusCode::FORBIDDEN
    );

    // Valid same-origin + matching X-CSRF-Token succeeds.
    let req_ok = Request::builder()
        .method("POST")
        .uri("/mfa/enroll")
        .header(header::COOKIE, format!("{cookie2}; {csrf2}"))
        .header("x-csrf-token", csrf2_val)
        .header(header::ORIGIN, "https://id.example.com")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req_ok).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn mfa_activation_rotates_session_disable_requires_step_up_and_lockout_enforced() {
    let state = test_state().await;
    let email = "mfastep@example.com";
    let pw = "correct horse battery staple";
    create_user(&state.db, email, "mfastep", pw).await;
    let app = routes::router(state.clone());

    let (_, cookie1, _) = login(&app, email, pw, None).await;
    let cookie1 = cookie1.unwrap();

    let enroll_resp = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/mfa/enroll")
            .header(header::COOKIE, &cookie1)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let secret = json_body(enroll_resp).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    await_safe_totp_window().await;
    let code = current_totp_code(&secret, &state.config.mfa_issuer, email);

    let act_resp = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/mfa/activate")
            .header(header::COOKIE, &cookie1)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "code": code }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(act_resp.status(), StatusCode::OK);
    let cookie2 = act_resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert_ne!(
        cookie1, cookie2,
        "MFA activation must rotate session cookie"
    );

    // Old pre-MFA session must be invalidated.
    assert_eq!(
        send(
            &app,
            Request::builder()
                .uri("/auth/me")
                .header(header::COOKIE, &cookie1)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    // Disabling MFA without step-up auth is rejected.
    assert_eq!(
        send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/mfa/disable")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap()
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    // 5 wrong attempts on /mfa/disable trigger 429 lockout.
    for _ in 0..5 {
        let r = send(
            &app,
            Request::builder()
                .method("POST")
                .uri("/mfa/disable")
                .header(header::COOKIE, &cookie2)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "password": "wrong-password-123" }).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
    let locked = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/mfa/disable")
            .header(header::COOKIE, &cookie2)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "password": pw }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ---------------------------------------------------------------------------
// 6. RBAC privilege escalation guards, seed placeholder rejection,
//    JWKS rotation, security headers, and XFF rate-limit trust boundary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rbac_blocks_admin_from_disabling_or_deleting_superadmin_and_role_escalation() {
    let state = test_state().await;
    let mut seed_cfg = state.config.clone();
    seed_cfg.admin_password = "StrongSeedPassword!2026".into();
    store::seed(&state.db, &seed_cfg).await.unwrap();

    let superadmin = store::get_user_row_by_email(&state.db, &seed_cfg.admin_email)
        .await
        .unwrap()
        .unwrap();

    // Create a plain `admin` user (holds users:* and clients:*, NOT *:*).
    let hash = infinity_core::password::hash_password("AdminPass!12345").unwrap();
    store::create_user(
        &state.db,
        NewUser {
            email: "plainadmin@example.com",
            username: "plainadmin",
            display_name: None,
            password_hash: &hash,
            roles: &["admin".into()],
        },
    )
    .await
    .unwrap();

    // Create a custom role with `roles:write` + `users:read` and assign to a user.
    store::upsert_role(
        &state.db,
        &infinity_core::model::Role {
            name: "role_editor".into(),
            description: "limited".into(),
            permissions: vec!["roles:write".into(), "users:read".into()],
        },
    )
    .await
    .unwrap();
    let hash2 = infinity_core::password::hash_password("EditorPass!12345").unwrap();
    store::create_user(
        &state.db,
        NewUser {
            email: "editor@example.com",
            username: "editor",
            display_name: None,
            password_hash: &hash2,
            roles: &["role_editor".into()],
        },
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let (_, admin_cookie, _) = login(&app, "plainadmin@example.com", "AdminPass!12345", None).await;
    let admin_cookie = admin_cookie.unwrap();

    // Plain admin cannot disable, demote, or delete superadmin.
    let patch_disable = send(
        &app,
        Request::builder()
            .method("PATCH")
            .uri(format!("/admin/users/{}", superadmin.id))
            .header(header::COOKIE, &admin_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "disabled": true }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(patch_disable.status(), StatusCode::FORBIDDEN);

    let del_super = send(
        &app,
        Request::builder()
            .method("DELETE")
            .uri(format!("/admin/users/{}", superadmin.id))
            .header(header::COOKIE, &admin_cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(del_super.status(), StatusCode::FORBIDDEN);

    // Non-superadmin role editor cannot grant `*:*` via PUT /admin/roles.
    let (_, editor_cookie, _) = login(&app, "editor@example.com", "EditorPass!12345", None).await;
    let editor_cookie = editor_cookie.unwrap();
    let escalate_role = send(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/admin/roles")
            .header(header::COOKIE, &editor_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "name": "backdoor",
                    "description": "escalate",
                    "permissions": ["*:*"]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(escalate_role.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn seed_rejects_placeholders_and_autogenerates_when_empty() {
    for bad in [
        "ChangeMe_Infinity#2025",
        "change-me-to-a-long-random-value",
        "shortpass",
    ] {
        let state = test_state().await;
        let mut cfg = state.config.clone();
        cfg.admin_password = bad.into();
        assert!(
            store::seed(&state.db, &cfg).await.is_err(),
            "seed must reject placeholder/weak password '{bad}'"
        );
    }

    let state = test_state().await;
    let mut cfg = state.config.clone();
    cfg.admin_password = String::new();
    store::seed(&state.db, &cfg)
        .await
        .expect("empty admin_password auto-generates strong password");
    let admin = store::get_user_row_by_email(&state.db, &cfg.admin_email)
        .await
        .unwrap()
        .unwrap();
    assert!(!admin.password_hash.is_empty());
}

#[tokio::test]
async fn jwks_kid_rotation_preserves_live_tokens_and_rejects_bad_jwts() {
    let state = test_state().await;
    let mut seed_cfg = state.config.clone();
    seed_cfg.admin_password = "StrongRotationTestPass!99".into();
    store::seed(&state.db, &seed_cfg).await.unwrap();

    let app = routes::router(state.clone());
    let (st, admin_cookie, _) =
        login(&app, &seed_cfg.admin_email, &seed_cfg.admin_password, None).await;
    assert_eq!(st, StatusCode::OK);
    let admin_cookie = admin_cookie.unwrap();

    let (st, tok_body) = token_request(
        &app,
        &[
            ("grant_type", "password"),
            ("username", &seed_cfg.admin_email),
            ("password", &seed_cfg.admin_password),
            ("scope", "openid profile"),
        ],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let access1 = tok_body["access_token"].as_str().unwrap().to_string();
    let id_tok = tok_body["id_token"].as_str().unwrap().to_string();

    // Rotate signing keys via Admin API.
    let rot_resp = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/admin/keys/rotate")
            .header(header::COOKIE, &admin_cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rot_resp.status(), StatusCode::OK);
    let new_kid = json_body(rot_resp).await["active_kid"]
        .as_str()
        .unwrap()
        .to_string();

    let jwks_resp = send(
        &app,
        Request::builder()
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let jwks_json = json_body(jwks_resp).await;
    let keys = jwks_json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["kid"], new_kid);

    // Previously issued access1 still validates against retired key in JWKS.
    let ui1 = send(
        &app,
        Request::builder()
            .uri("/userinfo")
            .header(header::AUTHORIZATION, format!("Bearer {access1}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(ui1.status(), StatusCode::OK);

    // id_token is rejected at /userinfo.
    let ui_id = send(
        &app,
        Request::builder()
            .uri("/userinfo")
            .header(header::AUTHORIZATION, format!("Bearer {id_tok}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(ui_id.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn security_headers_csp_no_store_and_xff_rate_limit_boundary() {
    let mut state = test_state().await;
    if let Some(cfg) = Arc::get_mut(&mut state) {
        cfg.ip_limiter = IpRateLimiter::new(2);
    }
    let app = routes::router(state.clone());
    await_safe_minute_window().await;

    // Static root serves strict CSP without 'unsafe-inline'.
    let root_resp = send(
        &app,
        Request::builder().uri("/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(root_resp.status(), StatusCode::OK);
    let csp = root_resp
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        !csp.contains("unsafe-inline"),
        "CSP must not allow unsafe-inline: {csp}"
    );
    assert_eq!(
        root_resp.headers().get(header::X_FRAME_OPTIONS).unwrap(),
        "DENY"
    );
    assert_eq!(
        root_resp
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );

    // /auth/login returns Cache-Control: no-store + Pragma: no-cache even on error.
    let login_resp = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", "1.1.1.1")
            .body(Body::from(
                json!({ "email": "nobody@example.com", "password": "wrongpassword1" }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(
        login_resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        login_resp.headers().get(header::PRAGMA).unwrap(),
        "no-cache"
    );

    // Spoofed rotating X-Forwarded-For headers from untrusted peer 127.0.0.1 hit the 2/min limit.
    let third = send(
        &app,
        Request::builder()
            .uri("/health")
            .header("x-forwarded-for", "9.9.9.9")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn bearer_header_never_falls_back_to_cookie_and_unknown_api_returns_json_404() {
    let state = test_state().await;
    let mut seed_cfg = state.config.clone();
    seed_cfg.admin_password = "StrongBearerFallbackTest!123".into();
    store::seed(&state.db, &seed_cfg).await.unwrap();
    let app = routes::router(state.clone());

    let (st, cookie, _) = login(&app, &seed_cfg.admin_email, &seed_cfg.admin_password, None).await;
    assert_eq!(st, StatusCode::OK);
    let cookie = cookie.unwrap();

    // Malformed Authorization header with valid session cookie MUST NOT fall back to cookie.
    let bad_auth = send(
        &app,
        Request::builder()
            .uri("/auth/me")
            .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(bad_auth.status(), StatusCode::UNAUTHORIZED);

    // Invalid single-segment permission rejected by PUT /admin/roles.
    let bad_role = send(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/admin/roles")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "name": "badperm",
                    "description": "bad",
                    "permissions": ["users"]
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(bad_role.status(), StatusCode::BAD_REQUEST);

    // Unknown /admin/* path returns 404 JSON instead of SPA index.html.
    let not_found_api = send(
        &app,
        Request::builder()
            .uri("/admin/does-not-exist")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(not_found_api.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(not_found_api).await["error"], "not_found");
}

#[tokio::test]
async fn disabled_account_records_login_throttle_across_login_and_password_grant() {
    let st = test_state().await;
    let uid = create_user(&st.db, "dis-login@example.com", "dislogin", "ValidPass!123").await;
    sqlx::query("UPDATE users SET disabled = 1 WHERE id = ?")
        .bind(&uid)
        .execute(&st.db)
        .await
        .expect("disable user");
    let app = routes::router(st);

    for _ in 0..10 {
        let (status, _, _) = login(&app, "dis-login@example.com", "ValidPass!123", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (locked_status, _, _) = login(&app, "dis-login@example.com", "ValidPass!123", None).await;
    assert_eq!(locked_status, StatusCode::TOO_MANY_REQUESTS);

    let st2 = test_state().await;
    let uid2 = create_user(&st2.db, "dis-oidc@example.com", "disoidc", "ValidPass!123").await;
    sqlx::query("UPDATE users SET disabled = 1 WHERE id = ?")
        .bind(&uid2)
        .execute(&st2.db)
        .await
        .expect("disable oidc user");
    let app2 = routes::router(st2);

    for _ in 0..10 {
        let resp = send(
            &app2,
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=password&username=dis-oidc%40example.com&password=ValidPass%21123",
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
    let locked_resp = send(
        &app2,
        Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "grant_type=password&username=dis-oidc%40example.com&password=ValidPass%21123",
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(locked_resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn router_xff_multi_header_and_ipv4_mapped_proxy_trust() {
    let base = test_state().await;
    let key = KeyRing::load_or_generate(&base.key_path, 3600).expect("reload signing key");
    let st = Arc::new(AppState {
        db: base.db.clone(),
        key: RwLock::new(key),
        key_path: base.key_path.clone(),
        config: Config {
            trusted_proxies: vec!["10.0.0.0/8".into()],
            global_rate_limit_per_min: 1,
            ..Config::default()
        },
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(1),
    });
    let app = routes::router(st);
    await_safe_minute_window().await;
    let peer = SocketAddr::new("::ffff:10.0.0.5".parse().unwrap(), 4444);

    let mut req1 = Request::builder()
        .uri("/.well-known/openid-configuration")
        .header("x-forwarded-for", "1.2.3.4")
        .header("x-forwarded-for", "203.0.113.10, ::ffff:10.0.0.9")
        .body(Body::empty())
        .unwrap();
    req1.extensions_mut().insert(ConnectInfo(peer));
    assert_eq!(
        app.clone().oneshot(req1).await.expect("req1").status(),
        StatusCode::OK
    );

    // Changing only the attacker-injected first XFF header must NOT bypass the rate limit.
    let mut req2 = Request::builder()
        .uri("/.well-known/openid-configuration")
        .header("x-forwarded-for", "9.8.7.6")
        .header("x-forwarded-for", "203.0.113.10, ::ffff:10.0.0.9")
        .body(Body::empty())
        .unwrap();
    req2.extensions_mut().insert(ConnectInfo(peer));
    assert_eq!(
        app.clone().oneshot(req2).await.expect("req2").status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // Different real client IP in rightmost trusted proxy header gets its own bucket.
    let mut req3 = Request::builder()
        .uri("/.well-known/openid-configuration")
        .header("x-forwarded-for", "9.8.7.6")
        .header("x-forwarded-for", "203.0.113.11")
        .body(Body::empty())
        .unwrap();
    req3.extensions_mut().insert(ConnectInfo(peer));
    assert_eq!(
        app.clone().oneshot(req3).await.expect("req3").status(),
        StatusCode::OK
    );
}
