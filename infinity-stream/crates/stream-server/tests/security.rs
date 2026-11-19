//! Comprehensive integration security tests for `stream-server`:
//! - Auth, password policy, login lockout, session fixation, cookie flags & Bearer precedence
//! - Least-privilege API key RBAC vs admin session boundaries
//! - Path traversal, Windows reserved device names, CommitLog bounds & atomic produce validation
//! - BM25 query/token/k/offset/depth DoS bounds
//! - WebSocket CSWSH (`Origin` header), auth, topic existence, connection cap, and live fan-out
//! - X-Forwarded-For trust boundary, CSRF Origin/Sec-Fetch-Site guard, and CSP/security headers
//!
//! All tests drive the real `stream_server::app(state)` Axum router against a real
//! temp-file SQLite database with migrations applied and a real temp `CommitLog` directory.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use stream_core::commit_log::CommitLog;
use stream_server::config::Config;
use stream_server::ratelimit::IpRateLimiter;
use stream_server::state::{AppState, SharedState};
use stream_server::store;
use stream_server::throttle::LoginThrottle;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http as ws_http;
use tower::ServiceExt;

const ADMIN_PASSWORD: &str = "Sup3r-Secret-Stream-Admin!";

struct TestApp {
    state: SharedState,
    router: Router,
    temp_root: PathBuf,
    admin_email: String,
    api_token: String,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp_root);
    }
}

async fn spawn_app() -> TestApp {
    spawn_app_with(Config::default(), LoginThrottle::new(3, 60, 60)).await
}

async fn spawn_app_with(mut config: Config, login_throttle: LoginThrottle) -> TestApp {
    let temp_root = std::env::temp_dir().join(format!("stream-sec-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_root).expect("create temp root");
    let db_path = temp_root.join("stream.sqlite");
    let data_dir = temp_root.join("data");
    std::fs::create_dir_all(&data_dir).expect("create temp data dir");

    config.admin_email = "admin@infinity.local".into();
    config.admin_password = ADMIN_PASSWORD.into();
    config.data_dir = data_dir.to_string_lossy().into_owned();
    config.database_url = format!("sqlite://{}", db_path.to_string_lossy());
    if config.global_rate_limit_per_min == 600 {
        config.global_rate_limit_per_min = 1_000_000;
    }

    let opts = SqliteConnectOptions::from_str(&config.database_url)
        .expect("parse sqlite url")
        .create_if_missing(true)
        .foreign_keys(true);
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("connect temp sqlite");
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("run migrations");

    let api_token = store::seed(&db, &config)
        .await
        .expect("seed db")
        .expect("seeded initial API key");
    let log = CommitLog::open(&config.data_dir, config.segment_max_bytes).expect("open commit log");

    let ip_limiter = IpRateLimiter::new(config.global_rate_limit_per_min);
    let ws_semaphore = Arc::new(Semaphore::new(config.ws_max_connections));
    let state = Arc::new(AppState {
        db,
        config,
        log: tokio::sync::Mutex::new(log),
        indexes: tokio::sync::RwLock::new(HashMap::new()),
        broadcasts: tokio::sync::RwLock::new(HashMap::new()),
        produced_times: tokio::sync::Mutex::new(VecDeque::new()),
        login_throttle,
        ip_limiter,
        ws_semaphore,
    });
    let router = stream_server::app(state.clone());

    TestApp {
        state,
        router,
        temp_root,
        admin_email: "admin@infinity.local".into(),
        api_token,
    }
}

fn req_with_ip(builder: axum::http::request::Builder, body: Body, ip: [u8; 4]) -> Request<Body> {
    let mut req = builder.body(body).expect("build request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ip, 44444))));
    req
}

fn req(builder: axum::http::request::Builder, body: Body) -> Request<Body> {
    req_with_ip(builder, body, [127, 0, 0, 1])
}

async fn send(router: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Value) {
    let resp = router.clone().oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, headers, json)
}

async fn send_raw(
    router: &Router,
    req: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = router.clone().oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

async fn login_with_headers(
    router: &Router,
    email: &str,
    password: &str,
    extra_cookie: Option<&str>,
) -> (
    StatusCode,
    Option<String>,
    Option<String>,
    axum::http::HeaderMap,
    Value,
) {
    let mut b = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(c) = extra_cookie {
        b = b.header(header::COOKIE, c);
    }
    let r = req(
        b,
        Body::from(json!({"email": email, "password": password}).to_string()),
    );
    let (status, headers, body) = send(router, r).await;
    let raw_set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let cookie_pair = raw_set_cookie
        .as_deref()
        .and_then(|s| s.split(';').next())
        .map(ToOwned::to_owned);
    (status, cookie_pair, raw_set_cookie, headers, body)
}

async fn login_admin(app: &TestApp) -> String {
    let (status, cookie, _, _, body) =
        login_with_headers(&app.router, &app.admin_email, ADMIN_PASSWORD, None).await;
    assert_eq!(status, StatusCode::OK, "admin login failed: {body}");
    cookie.expect("session cookie")
}

/// Ensures fixed 60-second `IpRateLimiter` test bursts never straddle a UTC `:00`
/// minute boundary, avoiding clock-edge window resets during CI/test execution.
async fn await_safe_minute_window() {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs_left = 60 - (now_secs % 60);
    if secs_left <= 3 {
        tokio::time::sleep(std::time::Duration::from_millis((secs_left * 1000) + 50)).await;
    }
}

// ---------------------------------------------------------------------------
// 1. Auth, Password Policy, Lockout, Session Fixation & Bearer Precedence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_rejects_weak_and_placeholder_admin_passwords() {
    for bad in [
        "ChangeMe_Infinity#2025",
        "ChangeMe_Infinity#2026",
        "ChooseAStrongOne#2026",
        "password123456",
        "short",
    ] {
        let cfg = Config {
            admin_password: bad.into(),
            ..Config::default()
        };
        assert!(
            cfg.validate().is_err(),
            "weak password {bad:?} must be rejected"
        );
    }

    // Empty admin_password triggers random CSPRNG password generation on seed.
    let temp_root = std::env::temp_dir().join(format!("stream-seed-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_root).unwrap();
    let db_path = temp_root.join("seed.sqlite");
    let cfg = Config {
        admin_password: String::new(),
        database_url: format!("sqlite://{}", db_path.to_string_lossy()),
        ..Config::default()
    };
    let opts = SqliteConnectOptions::from_str(&cfg.database_url)
        .unwrap()
        .create_if_missing(true);
    let db = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let seeded_key = store::seed(&db, &cfg).await.unwrap();
    assert!(seeded_key.is_some());
    db.close().await;
    let _ = std::fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn login_lockout_blocks_even_correct_password_and_is_scoped_per_account() {
    let app = spawn_app().await;

    for _ in 0..3 {
        let (st, _, _, _, _) =
            login_with_headers(&app.router, &app.admin_email, "wrong-password", None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    // Correct password must still fail with 429 while locked out.
    let (st, cookie, _, _, _) =
        login_with_headers(&app.router, &app.admin_email, ADMIN_PASSWORD, None).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert!(cookie.is_none());

    // Unrelated account remains unaffected (still returns 401 rather than 429).
    let (st_other, _, _, _, _) =
        login_with_headers(&app.router, "other@infinity.local", "wrong-password", None).await;
    assert_eq!(st_other, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_prevents_session_fixation_and_enforces_cookie_flags_and_no_store() {
    let mut cfg = Config {
        public_url: "https://stream.example.com".into(),
        cors_origins: vec!["https://stream.example.com".into()],
        ..Config::default()
    };
    cfg.global_rate_limit_per_min = 1_000_000;
    let app = spawn_app_with(cfg, LoginThrottle::default()).await;

    let (st1, cookie1, set1, h1, _) =
        login_with_headers(&app.router, &app.admin_email, ADMIN_PASSWORD, None).await;
    assert_eq!(st1, StatusCode::OK);
    let cookie1 = cookie1.unwrap();
    let set1 = set1.unwrap();
    assert!(set1.contains("HttpOnly"));
    assert!(set1.contains("SameSite=Strict"));
    assert!(set1.contains("Secure"));
    assert_eq!(h1.get(header::CACHE_CONTROL).unwrap(), "no-store");

    // Re-authenticating with an existing session cookie must rotate AND revoke the old token.
    let (st2, cookie2, _, _, _) = login_with_headers(
        &app.router,
        &app.admin_email,
        ADMIN_PASSWORD,
        Some(&cookie1),
    )
    .await;
    assert_eq!(st2, StatusCode::OK);
    let cookie2 = cookie2.unwrap();
    assert_ne!(cookie1, cookie2);

    let (old_me, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/auth/me")
                .header(header::COOKIE, &cookie1),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(old_me, StatusCode::UNAUTHORIZED);

    let (new_me, h_me, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/auth/me")
                .header(header::COOKIE, &cookie2),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(new_me, StatusCode::OK);
    assert_eq!(h_me.get(header::CACHE_CONTROL).unwrap(), "no-store");

    // Logout must preserve Secure flag when clearing cookie and revoke the session.
    let (lo_st, lo_h, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header(header::COOKIE, &cookie2),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(lo_st, StatusCode::OK);
    let cleared = lo_h.get(header::SET_COOKIE).unwrap().to_str().unwrap();
    assert!(cleared.contains("Max-Age=0"));
    assert!(cleared.contains("Secure"));

    let (after_lo, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/auth/me")
                .header(header::COOKIE, &cookie2),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(after_lo, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_bearer_token_never_falls_back_to_session_cookie() {
    let app = spawn_app().await;
    let cookie = login_admin(&app).await;

    let (status, _, body) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/topics")
                .header(header::AUTHORIZATION, "Bearer invalid_key_token")
                .header(header::COOKIE, &cookie),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");
}

// ---------------------------------------------------------------------------
// 2. API Key Least-Privilege RBAC & Key Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_key_data_plane_allowed_but_admin_deletes_keys_and_stats_forbidden() {
    let app = spawn_app().await;
    let auth = format!("Bearer {}", app.api_token);

    // Data plane: create topic, produce, consume, commit, create index, upsert, search.
    let (st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "events", "partitions": 2}).to_string()),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // /auth/me must NOT report superadmin role for API key.
    let (st_me, _, me_body) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/auth/me")
                .header(header::AUTHORIZATION, &auth),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(st_me, StatusCode::OK);
    assert_eq!(me_body["roles"], json!([]));

    // Privileged control-plane endpoints must reject API keys with 403 Forbidden.
    for (method, uri, body) in [
        ("DELETE", "/v1/topics/events", Body::empty()),
        (
            "POST",
            "/v1/indexes",
            Body::from(json!({"name":"idx1"}).to_string()),
        ),
        ("GET", "/v1/keys", Body::empty()),
        (
            "POST",
            "/v1/keys",
            Body::from(json!({"name":"escalate"}).to_string()),
        ),
        ("DELETE", "/v1/keys/nonexistent", Body::empty()),
        ("GET", "/v1/stats", Body::empty()),
        ("POST", "/auth/logout", Body::empty()),
    ] {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, &auth);
        if method == "POST" && uri == "/v1/indexes" {
            // Confirm index creation works for API key, then test DELETE /v1/indexes/idx1 is 403.
            b = b.header(header::CONTENT_TYPE, "application/json");
            let (idx_st, _, _) = send(&app.router, req(b, body)).await;
            assert_eq!(idx_st, StatusCode::OK);
            let (del_st, _, _) = send(
                &app.router,
                req(
                    Request::builder()
                        .method("DELETE")
                        .uri("/v1/indexes/idx1")
                        .header(header::AUTHORIZATION, &auth),
                    Body::empty(),
                ),
            )
            .await;
            assert_eq!(del_st, StatusCode::FORBIDDEN);
            continue;
        }
        if method == "POST" {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        let (f_st, _, f_body) = send(&app.router, req(b, body)).await;
        assert_eq!(
            f_st,
            StatusCode::FORBIDDEN,
            "{method} {uri} should forbid API key, got {f_body}"
        );
    }

    // Admin creates and revokes a key; revoked key fails immediately; double revoke returns 404.
    let cookie = login_admin(&app).await;
    let (ck_st, ck_h, ck_body) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "temp-producer"}).to_string()),
        ),
    )
    .await;
    assert_eq!(ck_st, StatusCode::OK);
    assert_eq!(ck_h.get(header::CACHE_CONTROL).unwrap(), "no-store");
    let key_id = ck_body["id"].as_str().unwrap().to_string();
    let key_tok = ck_body["key"].as_str().unwrap().to_string();

    let (ok_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/topics")
                .header(header::AUTHORIZATION, format!("Bearer {key_tok}")),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(ok_st, StatusCode::OK);

    let (rev_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/keys/{key_id}"))
                .header(header::COOKIE, &cookie),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(rev_st, StatusCode::OK);

    let (rev2_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("DELETE")
                .uri(format!("/v1/keys/{key_id}"))
                .header(header::COOKIE, &cookie),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(rev2_st, StatusCode::NOT_FOUND);

    let (after_rev, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/topics")
                .header(header::AUTHORIZATION, format!("Bearer {key_tok}")),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(after_rev, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// 3. Path Traversal, Windows Reserved Names, Overflows & Atomic Batches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_traversal_reserved_names_overflow_and_partial_batches() {
    let app = spawn_app().await;
    let auth = format!("Bearer {}", app.api_token);

    for bad_name in ["..", "CON", "nul", "COM1", "LPT9"] {
        let (st, _, _) = send(
            &app.router,
            req(
                Request::builder()
                    .method("POST")
                    .uri("/v1/topics")
                    .header(header::AUTHORIZATION, &auth)
                    .header(header::CONTENT_TYPE, "application/json"),
                Body::from(json!({"name": bad_name, "partitions": 1}).to_string()),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "topic {bad_name} must fail");

        let (st_idx, _, _) = send(
            &app.router,
            req(
                Request::builder()
                    .method("POST")
                    .uri("/v1/indexes")
                    .header(header::AUTHORIZATION, &auth)
                    .header(header::CONTENT_TYPE, "application/json"),
                Body::from(json!({"name": bad_name}).to_string()),
            ),
        )
        .await;
        assert_eq!(
            st_idx,
            StatusCode::BAD_REQUEST,
            "index {bad_name} must fail"
        );
    }

    // Create valid topic for produce/consume/commit checks.
    let (st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "orders", "partitions": 1}).to_string()),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Atomic batch pre-validation: record #1 valid, record #2 bad partition -> entire batch fails, 0 written.
    let (bat_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics/orders/produce")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(
                json!({
                    "records": [
                        {"partition": 0, "value": {"ok": 1}},
                        {"partition": 99, "value": {"bad": 2}}
                    ]
                })
                .to_string(),
            ),
        ),
    )
    .await;
    assert_eq!(bat_st, StatusCode::BAD_REQUEST);
    let (con_st, _, con_body) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/topics/orders/consume?partition=0&offset=0&max=10")
                .header(header::AUTHORIZATION, &auth),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(con_st, StatusCode::OK);
    assert_eq!(con_body["records"].as_array().unwrap().len(), 0);

    // Reject u64::MAX offset in commit (prevents wrapping to -1 in SQLite).
    let (ov_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics/orders/commit")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"group": "workers", "partition": 0, "offset": u64::MAX}).to_string()),
        ),
    )
    .await;
    assert_eq!(ov_st, StatusCode::BAD_REQUEST);

    // Reject traversal/reserved consumer group names.
    for bad_group in ["..", ".", "a..b", "NUL.grp", "trail."] {
        let (gr_st, _, _) = send(
            &app.router,
            req(
                Request::builder()
                    .method("POST")
                    .uri("/v1/topics/orders/commit")
                    .header(header::AUTHORIZATION, &auth)
                    .header(header::CONTENT_TYPE, "application/json"),
                Body::from(json!({"group": bad_group, "partition": 0, "offset": 0}).to_string()),
            ),
        )
        .await;
        assert_eq!(
            gr_st,
            StatusCode::BAD_REQUEST,
            "group {bad_group} must fail"
        );
    }

    // Reject oversized consume `max` and out-of-range partition.
    let (bad_max, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/topics/orders/consume?partition=0&offset=0&max=1001")
                .header(header::AUTHORIZATION, &auth),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(bad_max, StatusCode::BAD_REQUEST);

    let (bad_part, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/topics/orders/consume?partition=5&offset=0&max=10")
                .header(header::AUTHORIZATION, &auth),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(bad_part, StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// 4. BM25 Query/Token/K/Offset/Depth Bounds & Body Limit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_enforces_query_bounds_and_depth_limit() {
    let app = spawn_app().await;
    let auth = format!("Bearer {}", app.api_token);

    let (c_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/indexes")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "docs"}).to_string()),
        ),
    )
    .await;
    assert_eq!(c_st, StatusCode::OK);

    // Reject deeply nested JSON (> 32 depth) without persisting partial doc to SQLite.
    let mut nested = json!("leaf");
    for _ in 0..35 {
        nested = json!({"x": nested});
    }
    let (deep_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/indexes/docs/docs")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!([{"id": "deep1", "payload": nested}]).to_string()),
        ),
    )
    .await;
    assert_eq!(deep_st, StatusCode::BAD_REQUEST);
    assert!(store::doc_fields(&app.state.db, "docs", "deep1")
        .await
        .unwrap()
        .is_none());

    // Valid docs + query bounds.
    let (up_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/indexes/docs/docs")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(
                json!([
                    {"id": "d1", "text": "rust streaming engine"},
                    {"id": "d2", "text": "rust search engine"}
                ])
                .to_string(),
            ),
        ),
    )
    .await;
    assert_eq!(up_st, StatusCode::OK);

    let many_tokens = (0..65)
        .map(|i| format!("w{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    for bad_qs in [
        format!("q={}&k=10", "a".repeat(513)),
        format!("q={}&k=10", many_tokens.replace(' ', "%20")),
        "q=rust&k=0".into(),
        "q=rust&k=101".into(),
        "q=rust&k=10&offset=1001".into(),
    ] {
        let (st, _, _) = send(
            &app.router,
            req(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/indexes/docs/search?{bad_qs}"))
                    .header(header::AUTHORIZATION, &auth),
                Body::empty(),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "expected 400 for {bad_qs}");
    }

    let (ok_st, _, ok_body) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/indexes/docs/search?q=rust&k=1&offset=1")
                .header(header::AUTHORIZATION, &auth),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(ok_st, StatusCode::OK);
    assert_eq!(ok_body["hits"].as_array().unwrap().len(), 1);

    // Oversized body > max_json_body_bytes (1 MiB) rejected with 413.
    let big_body = vec![b' '; 1024 * 1024 + 128];
    let (big_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(big_body),
        ),
    )
    .await;
    assert_eq!(big_st, StatusCode::PAYLOAD_TOO_LARGE);
}

// ---------------------------------------------------------------------------
// 5. WebSocket Security (CSWSH, Auth, Origin, Fan-out & Connection Cap)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn websocket_cswsh_origin_auth_cap_and_live_fanout() {
    let cfg = Config {
        ws_max_connections: 1,
        global_rate_limit_per_min: 1_000_000,
        ..Config::default()
    };
    let app = spawn_app_with(cfg, LoginThrottle::default()).await;
    let cookie = login_admin(&app).await;
    let auth = format!("Bearer {}", app.api_token);

    // Nonexistent topic returns 404 without polluting broadcast map.
    let (nf_ws, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/topics/missing_topic/subscribe")
                .header(header::AUTHORIZATION, &auth),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(nf_ws, StatusCode::NOT_FOUND);
    assert!(!app
        .state
        .broadcasts
        .read()
        .await
        .contains_key("missing_topic"));

    // Create topic "live".
    let (c_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "live", "partitions": 1}).to_string()),
        ),
    )
    .await;
    assert_eq!(c_st, StatusCode::OK);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_app = app.router.clone();
    let srv_handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            server_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let ws_url = format!("ws://{addr}/v1/topics/live/subscribe");

    // 1) Unauthenticated upgrade -> 401.
    let mut unauth_req = ws_url.as_str().into_client_request().unwrap();
    unauth_req.headers_mut().insert(
        ws_http::header::ORIGIN,
        "http://localhost:8092".parse().unwrap(),
    );
    let err = tokio_tungstenite::connect_async(unauth_req)
        .await
        .unwrap_err();
    match err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), ws_http::StatusCode::UNAUTHORIZED);
        }
        other => panic!("unexpected ws error: {other:?}"),
    }

    // 2) CSWSH: cookie auth with evil Origin, prefix-trick Origin, null Origin, or missing Origin -> 403.
    for bad_origin in [
        Some("https://evil.example"),
        Some("http://localhost:8092.evil.com"),
        Some("null"),
        None,
    ] {
        let mut r = ws_url.as_str().into_client_request().unwrap();
        r.headers_mut()
            .insert(ws_http::header::COOKIE, cookie.parse().unwrap());
        if let Some(orig) = bad_origin {
            r.headers_mut()
                .insert(ws_http::header::ORIGIN, orig.parse().unwrap());
        }
        let err = tokio_tungstenite::connect_async(r).await.unwrap_err();
        match err {
            tokio_tungstenite::tungstenite::Error::Http(resp) => {
                assert_eq!(
                    resp.status(),
                    ws_http::StatusCode::FORBIDDEN,
                    "expected 403 for origin {bad_origin:?}"
                );
            }
            other => panic!("unexpected ws error for {bad_origin:?}: {other:?}"),
        }
    }

    // 3) API key WITH evil Origin -> 403.
    let mut bad_key_ws = ws_url.as_str().into_client_request().unwrap();
    bad_key_ws
        .headers_mut()
        .insert(ws_http::header::AUTHORIZATION, auth.parse().unwrap());
    bad_key_ws.headers_mut().insert(
        ws_http::header::ORIGIN,
        "https://evil.example".parse().unwrap(),
    );
    let err = tokio_tungstenite::connect_async(bad_key_ws)
        .await
        .unwrap_err();
    match err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), ws_http::StatusCode::FORBIDDEN);
        }
        other => panic!("unexpected ws error: {other:?}"),
    }

    // 4) Cookie auth WITH allowed Origin -> connects (101) and receives live record;
    //    concurrent second subscriber exceeds ws_max_connections=1 -> 429.
    let mut ok_ws = ws_url.as_str().into_client_request().unwrap();
    ok_ws
        .headers_mut()
        .insert(ws_http::header::COOKIE, cookie.parse().unwrap());
    ok_ws.headers_mut().insert(
        ws_http::header::ORIGIN,
        "http://localhost:8092".parse().unwrap(),
    );
    let (mut ws_stream, resp) = tokio_tungstenite::connect_async(ok_ws).await.unwrap();
    assert_eq!(resp.status(), ws_http::StatusCode::SWITCHING_PROTOCOLS);

    let mut second_ws = ws_url.as_str().into_client_request().unwrap();
    second_ws
        .headers_mut()
        .insert(ws_http::header::AUTHORIZATION, auth.parse().unwrap());
    let err2 = tokio_tungstenite::connect_async(second_ws)
        .await
        .unwrap_err();
    match err2 {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(resp.status(), ws_http::StatusCode::TOO_MANY_REQUESTS);
        }
        other => panic!("unexpected ws error: {other:?}"),
    }

    // Produce a record and confirm subscriber receives it over WebSocket.
    let (p_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics/live/produce")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"partition": 0, "value": {"msg": "hello-ws"}}).to_string()),
        ),
    )
    .await;
    assert_eq!(p_st, StatusCode::OK);

    let msg = tokio::time::timeout(std::time::Duration::from_secs(3), ws_stream.next())
        .await
        .expect("ws recv timeout")
        .expect("ws frame")
        .expect("valid ws message");
    assert!(msg.to_text().unwrap().contains("hello-ws"));

    drop(ws_stream);

    // 5) API key without Origin header succeeds once the connection slot is released.
    let mut key_ws = ws_url.as_str().into_client_request().unwrap();
    key_ws
        .headers_mut()
        .insert(ws_http::header::AUTHORIZATION, auth.parse().unwrap());
    let (key_stream, key_resp) = tokio_tungstenite::connect_async(key_ws).await.unwrap();
    assert_eq!(key_resp.status(), ws_http::StatusCode::SWITCHING_PROTOCOLS);
    drop(key_stream);

    srv_handle.abort();
}

#[tokio::test]
async fn unauthenticated_rejected_and_admin_delete_works() {
    let app = spawn_app().await;

    for (method, uri) in [
        ("GET", "/auth/me"),
        ("POST", "/auth/logout"),
        ("GET", "/v1/topics"),
        ("POST", "/v1/topics"),
        ("DELETE", "/v1/topics/orders"),
        ("GET", "/v1/indexes"),
        ("GET", "/v1/keys"),
        ("GET", "/v1/stats"),
        ("GET", "/v1/consumers"),
    ] {
        let (st, _, _) = send(
            &app.router,
            req(Request::builder().method(method).uri(uri), Body::empty()),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::UNAUTHORIZED,
            "{method} {uri} must require auth"
        );
    }

    let cookie = login_admin(&app).await;
    let (ct, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "temp_topic", "partitions": 1}).to_string()),
        ),
    )
    .await;
    assert_eq!(ct, StatusCode::OK);
    let (dt, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("DELETE")
                .uri("/v1/topics/temp_topic")
                .header(header::COOKIE, &cookie),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(dt, StatusCode::OK);
    let (dt2, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("DELETE")
                .uri("/v1/topics/temp_topic")
                .header(header::COOKIE, &cookie),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(dt2, StatusCode::NOT_FOUND);

    let (ci, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/indexes")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "temp_idx"}).to_string()),
        ),
    )
    .await;
    assert_eq!(ci, StatusCode::OK);
    let (di, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("DELETE")
                .uri("/v1/indexes/temp_idx")
                .header(header::COOKIE, &cookie),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(di, StatusCode::OK);
    let (di2, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("DELETE")
                .uri("/v1/indexes/temp_idx")
                .header(header::COOKIE, &cookie),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(di2, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// 6. XFF Trust Boundary, CSRF Guard & Hardened Security Headers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn xff_spoofing_ignored_unless_trusted_proxy_and_csrf_blocked() {
    // Untrusted peer 198.51.100.10 sending rotating X-Forwarded-For must still hit rate limit 2/min.
    let cfg = Config {
        global_rate_limit_per_min: 2,
        trusted_proxies: vec![],
        ..Config::default()
    };
    let app = spawn_app_with(cfg, LoginThrottle::default()).await;

    await_safe_minute_window().await;
    for i in 1..=3 {
        let r = req_with_ip(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("x-forwarded-for", format!("203.0.113.{i}")),
            Body::empty(),
            [198, 51, 100, 10],
        );
        let (st, _, _) = send(&app.router, r).await;
        if i <= 2 {
            assert_eq!(st, StatusCode::OK);
        } else {
            assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // Trusted proxy 10.0.0.5 forwarding distinct client IPs gets separate buckets.
    let cfg_proxy = Config {
        global_rate_limit_per_min: 1,
        trusted_proxies: vec!["10.0.0.0/8".into()],
        ..Config::default()
    };
    let app_proxy = spawn_app_with(cfg_proxy, LoginThrottle::default()).await;
    await_safe_minute_window().await;
    for (xff, expected) in [
        ("203.0.113.1", StatusCode::OK),
        ("203.0.113.2", StatusCode::OK),
        ("203.0.113.1", StatusCode::TOO_MANY_REQUESTS),
    ] {
        let r = req_with_ip(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("x-forwarded-for", xff),
            Body::empty(),
            [10, 0, 0, 5],
        );
        let (st, _, _) = send(&app_proxy.router, r).await;
        assert_eq!(st, expected);
    }
}

#[tokio::test]
async fn csrf_guard_and_security_headers_enforced() {
    let app = spawn_app().await;
    let cookie = login_admin(&app).await;

    // Cross-origin & same-site different-port cookie POST rejected with 403 Forbidden.
    for bad_origin in ["https://evil.example", "http://127.0.0.1:9999"] {
        let (st, _, _) = send(
            &app.router,
            req(
                Request::builder()
                    .method("POST")
                    .uri("/v1/topics")
                    .header(header::COOKIE, &cookie)
                    .header(header::ORIGIN, bad_origin)
                    .header(header::CONTENT_TYPE, "application/json"),
                Body::from(json!({"name": "csrf", "partitions": 1}).to_string()),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "expected 403 for {bad_origin}");
    }

    // Cross-site Sec-Fetch-Site without Origin also rejected.
    let (sfs_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics")
                .header(header::COOKIE, &cookie)
                .header("sec-fetch-site", "cross-site")
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "csrf2", "partitions": 1}).to_string()),
        ),
    )
    .await;
    assert_eq!(sfs_st, StatusCode::FORBIDDEN);

    // Login CSRF with untrusted Origin rejected.
    let (lcsrf_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"email": app.admin_email, "password": ADMIN_PASSWORD}).to_string()),
        ),
    )
    .await;
    assert_eq!(lcsrf_st, StatusCode::FORBIDDEN);

    // Hardened CSP (no unsafe-inline in style-src) and security headers on root UI.
    let (root_st, root_h, _) = send_raw(
        &app.router,
        req(Request::builder().method("GET").uri("/"), Body::empty()),
    )
    .await;
    assert_eq!(root_st, StatusCode::OK);
    let csp = root_h
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!csp.contains("unsafe-inline"));
    assert!(csp.contains("object-src 'none'"));
    assert_eq!(
        root_h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(root_h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(root_h.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
    assert_eq!(root_h.get(header::CACHE_CONTROL).unwrap(), "no-store");

    // Unknown /v1/ route returns 404 JSON rather than index.html SPA fallback.
    let (nf_st, _, nf_body) = send(
        &app.router,
        req(
            Request::builder().method("GET").uri("/v1/does-not-exist"),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(nf_st, StatusCode::NOT_FOUND);
    assert_eq!(nf_body["error"], "not_found");
}

// ---------------------------------------------------------------------------
// 7. Regression tests for sec-verifier audit findings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_password_login_is_uniform_and_argon2_variant_is_pinned() {
    let app = spawn_app().await;
    for email in [&app.admin_email, "nonexistent@infinity.local"] {
        let (st, cookie, _, _, _) = login_with_headers(&app.router, email, "", None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert!(cookie.is_none());
    }
    let h = stream_core::password::hash_password("V3ry$tr0ng-Str3am-Pass!").unwrap();
    let downgraded = h.replacen("$argon2id$", "$argon2i$", 1);
    assert!(
        stream_core::password::verify_password("V3ry$tr0ng-Str3am-Pass!", &downgraded).is_err()
    );
}

#[tokio::test]
async fn xff_mapped_ipv6_and_malformed_hop_handled_safely() {
    let cfg = Config {
        global_rate_limit_per_min: 1,
        trusted_proxies: vec!["10.0.0.0/8".into()],
        ..Config::default()
    };
    let app = spawn_app_with(cfg, LoginThrottle::default()).await;

    await_safe_minute_window().await;
    let mapped_peer = std::net::IpAddr::V6("::ffff:10.0.0.5".parse().unwrap());
    let mut r1 = Request::builder()
        .method("GET")
        .uri("/health")
        .header("x-forwarded-for", "198.51.100.77, bad_hop, 10.0.0.9")
        .body(Body::empty())
        .unwrap();
    r1.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(mapped_peer, 44444)));
    let (st1, _, _) = send(&app.router, r1).await;
    assert_eq!(st1, StatusCode::OK);

    // Same trusted mapped peer with a different leftmost spoofed IP behind a malformed hop
    // still resolves to peer 10.0.0.5 and gets rate-limited (429).
    let mut r2 = Request::builder()
        .method("GET")
        .uri("/health")
        .header("x-forwarded-for", "198.51.100.88, bad_hop, 10.0.0.9")
        .body(Body::empty())
        .unwrap();
    r2.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(mapped_peer, 44444)));
    let (st2, _, _) = send(&app.router, r2).await;
    assert_eq!(st2, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn upsert_docs_batch_is_atomic_on_partial_failure() {
    let app = spawn_app().await;
    let auth = format!("Bearer {}", app.api_token);

    let (c_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/indexes")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "atomic_idx"}).to_string()),
        ),
    )
    .await;
    assert_eq!(c_st, StatusCode::OK);

    let mut deep = json!("leaf");
    for _ in 0..35 {
        deep = json!({"k": deep});
    }
    let (up_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/indexes/atomic_idx/docs")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(
                json!([
                    {"id": "good_1", "text": "uniqueatomicterm"},
                    {"id": "bad_2", "nested": deep}
                ])
                .to_string(),
            ),
        ),
    )
    .await;
    assert_eq!(up_st, StatusCode::BAD_REQUEST);

    // Neither SQLite nor Bm25Index may retain good_1 from the failed batch.
    assert!(store::doc_fields(&app.state.db, "atomic_idx", "good_1")
        .await
        .unwrap()
        .is_none());
    let (s_st, _, s_body) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/indexes/atomic_idx/search?q=uniqueatomicterm&k=10")
                .header(header::AUTHORIZATION, &auth),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(s_st, StatusCode::OK);
    assert_eq!(s_body["hits"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn produce_batch_is_atomic_on_stored_record_size_overflow() {
    let cfg = Config {
        max_json_body_bytes: 2 * 1024 * 1024,
        global_rate_limit_per_min: 1_000_000,
        ..Config::default()
    };
    let app = spawn_app_with(cfg, LoginThrottle::default()).await;
    let auth = format!("Bearer {}", app.api_token);

    let (c_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(json!({"name": "atomic_topic", "partitions": 1}).to_string()),
        ),
    )
    .await;
    assert_eq!(c_st, StatusCode::OK);

    // Value alone is under 1 MiB, but combined with StoredRecord envelope + key it exceeds MAX_RECORD_BYTES (1 MiB).
    let near_limit = "x".repeat(stream_core::commit_log::MAX_RECORD_BYTES - 30);
    let (p_st, _, _) = send(
        &app.router,
        req(
            Request::builder()
                .method("POST")
                .uri("/v1/topics/atomic_topic/produce")
                .header(header::AUTHORIZATION, &auth)
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(
                json!({
                    "records": [
                        {"partition": 0, "value": {"first": "should_not_persist"}},
                        {"partition": 0, "key": "k".repeat(200), "value": near_limit}
                    ]
                })
                .to_string(),
            ),
        ),
    )
    .await;
    assert_eq!(p_st, StatusCode::BAD_REQUEST);

    let (con_st, _, con_body) = send(
        &app.router,
        req(
            Request::builder()
                .method("GET")
                .uri("/v1/topics/atomic_topic/consume?partition=0&offset=0&max=10")
                .header(header::AUTHORIZATION, &auth),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(con_st, StatusCode::OK);
    assert_eq!(con_body["records"].as_array().unwrap().len(), 0);
}
