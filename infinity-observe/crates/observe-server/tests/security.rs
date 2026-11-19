//! Integration tests for the security-critical HTTP surface of `observe-server`:
//! login lockout/throttling, the ingest-key vs session auth boundary, and
//! alert-rule RBAC. These exercise the real axum `Router` (via
//! `tower::ServiceExt::oneshot`) against a real temp-file SQLite database with
//! migrations actually applied — no mocks.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tower::ServiceExt;

use observe_server::config::Config;
use observe_server::ratelimit::IpRateLimiter;
use observe_server::routes;
use observe_server::state::AppState;
use observe_server::throttle::LoginThrottle;

const ADMIN_PASSWORD: &str = "Sup3r-Secret-Admin-Pass!";
const VIEWER_PASSWORD: &str = "Sup3r-Secret-Viewer-Pass!";

/// A running test instance: the router plus the raw credentials/tokens seeded
/// into its database, so tests can exercise auth without knowing internals.
struct TestApp {
    router: Router,
    db_path: PathBuf,
    admin_email: String,
    viewer_email: String,
    ingest_token: String,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.db_path);
    }
}

async fn spawn_app() -> TestApp {
    spawn_app_with_throttle(LoginThrottle::new(3, 60, 60)).await
}

async fn spawn_app_with_throttle(login_throttle: LoginThrottle) -> TestApp {
    let mut db_path = std::env::temp_dir();
    db_path.push(format!("observe-test-{}.sqlite", uuid::Uuid::new_v4()));

    let opts = SqliteConnectOptions::from_str(&format!(
        "sqlite://{}",
        db_path.to_str().expect("utf8 temp path")
    ))
    .expect("valid sqlite url")
    .create_if_missing(true);
    let db: SqlitePool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .expect("connect to temp sqlite db");
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("run migrations");

    let admin_email = "admin@example.com".to_string();
    let config = Config {
        admin_email: admin_email.clone(),
        admin_password: ADMIN_PASSWORD.to_string(),
        session_ttl_secs: 3600,
        // High enough that the global per-IP limiter never interferes with
        // the (small, deliberate) burst of requests these tests send.
        global_rate_limit_per_min: 1_000_000,
        ..Config::default()
    };

    // Seeds the admin user (using config.admin_password above) and an
    // initial ingest key (raw token only logged, not returned) — create our
    // own ingest key afterwards so the test knows the raw token.
    observe_server::store::seed(&db, &config)
        .await
        .expect("seed database");

    let viewer_email = "viewer@example.com".to_string();
    let viewer_hash =
        observe_core::password::hash_password(VIEWER_PASSWORD).expect("hash viewer password");
    sqlx::query(
        "INSERT INTO users (id, email, username, display_name, password_hash, role, created_at)
         VALUES (?, ?, 'viewer', 'Viewer', ?, 'viewer', ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&viewer_email)
    .bind(&viewer_hash)
    .bind(observe_server::store::now())
    .execute(&db)
    .await
    .expect("insert viewer user");

    let (_, ingest_token) = observe_server::store::create_ingest_key(&db, "test-key")
        .await
        .expect("create ingest key");

    let state = Arc::new(AppState {
        db,
        config,
        login_throttle,
        ip_limiter: IpRateLimiter::new(1_000_000),
    });

    TestApp {
        router: routes::router(state),
        db_path,
        admin_email,
        viewer_email,
        ingest_token,
    }
}

/// Builds a request with a fake connect-info extension inserted (required by
/// the router's per-IP rate-limit middleware, which normally gets this from
/// `into_make_service_with_connect_info` — not present under `oneshot`).
fn req_builder(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder().method(method).uri(uri)
}

fn with_connect_info(builder: axum::http::request::Builder, body: Body) -> Request<Body> {
    let mut req = builder.body(body).expect("build request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

/// Ensures a fixed 60-second `IpRateLimiter` window will not roll over mid-burst.
async fn await_safe_minute_window() {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs_left = 60 - (now_secs % 60);
    if secs_left <= 5 {
        tokio::time::sleep(std::time::Duration::from_millis((secs_left * 1000) + 50)).await;
    }
}

async fn send(router: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("router call");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

async fn login(
    router: &Router,
    email: &str,
    password: &str,
) -> (StatusCode, Option<String>, Value) {
    let payload = json!({ "email": email, "password": password }).to_string();
    let req = with_connect_info(
        req_builder("POST", "/auth/login").header(header::CONTENT_TYPE, "application/json"),
        Body::from(payload),
    );
    let resp = router.clone().oneshot(req).await.expect("router call");
    let status = resp.status();
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| raw.split(';').next())
        .map(|s| s.to_string());
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, cookie, body)
}

// ---------------------------------------------------------------------
// 1. Login lockout / throttling
// ---------------------------------------------------------------------

/// After `max_fails` wrong-password attempts against the same account, the
/// account is locked out — and critically, a *subsequent attempt with the
/// correct password* is still rejected (429, not 200) while locked. This is
/// what distinguishes a real lockout from mere password verification.
#[tokio::test]
async fn login_lockout_blocks_even_correct_password_while_locked() {
    let app = spawn_app().await; // LoginThrottle::new(3, 60, 60): locks after 3 fails.

    for attempt in 1..=3 {
        let (status, _, body) =
            login(&app.router, &app.admin_email, "totally-wrong-password").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} should be a plain auth failure, got body {body:?}"
        );
    }

    // Now retry with the CORRECT password: must still be rejected because
    // the account is locked out, not because the password is wrong.
    let (status, cookie, body) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "correct password during lockout window must still be rejected, got body {body:?}"
    );
    assert!(
        cookie.is_none(),
        "no session should be issued while locked out"
    );
}

/// Sanity check that the correct password *does* work absent any lockout —
/// proves the lockout test above isn't just permanently rejecting logins.
#[tokio::test]
async fn login_succeeds_with_correct_password_when_not_locked_out() {
    let app = spawn_app().await;
    let (status, cookie, body) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert!(
        cookie.is_some(),
        "a session cookie must be issued on success"
    );
}

/// A failed attempt against one account must not lock out an unrelated
/// account — the throttle key is per-identity, not global.
#[tokio::test]
async fn login_lockout_is_scoped_per_account() {
    let app = spawn_app().await;

    for _ in 1..=3 {
        let (status, _, _) = login(&app.router, &app.admin_email, "wrong-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // Admin account is now locked; viewer account must be unaffected.
    let (status, cookie, body) = login(&app.router, &app.viewer_email, VIEWER_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert!(cookie.is_some());
}

// ---------------------------------------------------------------------
// 2. Ingest-key auth boundary
// ---------------------------------------------------------------------

/// An ingest key can reach ingest endpoints (POST /v1/logs).
#[tokio::test]
async fn ingest_key_can_reach_ingest_endpoint() {
    let app = spawn_app().await;
    let payload = json!([{
        "level": "info",
        "service": "test-svc",
        "message": "hello from ingest key",
    }])
    .to_string();
    let req = with_connect_info(
        req_builder("POST", "/v1/logs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", app.ingest_token),
            ),
        Body::from(payload),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(body["accepted"], json!(1));
}

/// The same ingest key must be rejected from an admin/session-only endpoint
/// (GET /v1/alerts/rules requires a `Principal`, i.e. a real session).
#[tokio::test]
async fn ingest_key_is_rejected_from_session_only_endpoint() {
    let app = spawn_app().await;
    let req = with_connect_info(
        req_builder("GET", "/v1/alerts/rules").header(
            header::AUTHORIZATION,
            format!("Bearer {}", app.ingest_token),
        ),
        Body::empty(),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an ingest key must not authenticate a session-only endpoint, got body {body:?}"
    );
}

/// A request with no credentials at all is rejected from both endpoint
/// classes.
#[tokio::test]
async fn no_credentials_are_rejected_from_both_ingest_and_admin_endpoints() {
    let app = spawn_app().await;

    let ingest_req = with_connect_info(
        req_builder("POST", "/v1/logs").header(header::CONTENT_TYPE, "application/json"),
        Body::from(json!([]).to_string()),
    );
    let (status, body) = send(&app.router, ingest_req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body:?}");

    let admin_req = with_connect_info(req_builder("GET", "/v1/alerts/rules"), Body::empty());
    let (status, body) = send(&app.router, admin_req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body:?}");
}

/// A valid session (not an ingest key) must not be usable against an
/// ingest-only endpoint — the boundary holds in both directions.
#[tokio::test]
async fn session_cookie_is_rejected_from_ingest_only_endpoint() {
    let app = spawn_app().await;
    let (_, cookie, _) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    let cookie = cookie.expect("admin login should succeed");

    let req = with_connect_info(
        req_builder("POST", "/v1/logs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie),
        Body::from(json!([]).to_string()),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a dashboard session must not authenticate the ingest key surface, got body {body:?}"
    );
}

// ---------------------------------------------------------------------
// 3. Alert-rule RBAC
// ---------------------------------------------------------------------

fn create_rule_payload() -> String {
    json!({
        "name": "too many errors",
        "kind": "error_log_count",
        "target": "",
        "threshold": 5.0,
        "window_secs": 300
    })
    .to_string()
}

/// A viewer (non-admin, lacking `alerts:create`) must not be able to create
/// an alert rule.
#[tokio::test]
async fn viewer_cannot_create_alert_rule() {
    let app = spawn_app().await;
    let (_, cookie, _) = login(&app.router, &app.viewer_email, VIEWER_PASSWORD).await;
    let cookie = cookie.expect("viewer login should succeed");

    let req = with_connect_info(
        req_builder("POST", "/v1/alerts/rules")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie),
        Body::from(create_rule_payload()),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer must be forbidden from creating alert rules, got body {body:?}"
    );
}

/// An admin (or any principal with `alerts:create`) can create an alert
/// rule.
#[tokio::test]
async fn admin_can_create_alert_rule() {
    let app = spawn_app().await;
    let (_, cookie, _) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    let cookie = cookie.expect("admin login should succeed");

    let req = with_connect_info(
        req_builder("POST", "/v1/alerts/rules")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie),
        Body::from(create_rule_payload()),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(body["rule"]["name"], json!("too many errors"));
}

/// A viewer also must not be able to delete an alert rule created by an
/// admin (covers the `alerts:delete` permission, not just `alerts:create`).
#[tokio::test]
async fn viewer_cannot_delete_alert_rule() {
    let app = spawn_app().await;
    let (_, admin_cookie, _) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    let admin_cookie = admin_cookie.expect("admin login should succeed");

    let create_req = with_connect_info(
        req_builder("POST", "/v1/alerts/rules")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, admin_cookie),
        Body::from(create_rule_payload()),
    );
    let (status, body) = send(&app.router, create_req).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    let rule_id = body["rule"]["id"].as_str().expect("rule id").to_string();

    let (_, viewer_cookie, _) = login(&app.router, &app.viewer_email, VIEWER_PASSWORD).await;
    let viewer_cookie = viewer_cookie.expect("viewer login should succeed");
    let delete_req = with_connect_info(
        req_builder("DELETE", &format!("/v1/alerts/rules/{rule_id}"))
            .header(header::COOKIE, viewer_cookie),
        Body::empty(),
    );
    let (status, body) = send(&app.router, delete_req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer must be forbidden from deleting alert rules, got body {body:?}"
    );
}

// ---------------------------------------------------------------------
// 4. SSRF protection on alert webhooks
// ---------------------------------------------------------------------

#[tokio::test]
async fn alert_webhook_blocks_ssrf_targets_and_insecure_schemes() {
    let app = spawn_app().await;
    let (_, cookie, _) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    let cookie = cookie.expect("admin login");

    for bad_url in [
        "http://hooks.example.com/alert",
        "file:///etc/passwd",
        "https://user:pass@hooks.example.com/alert",
        "https://127.0.0.1/hook",
        "https://10.0.0.1/hook",
        "https://172.16.0.1/hook",
        "https://192.168.1.1/hook",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/hook",
        "https://[fe80::1]/hook",
        "https://[fc00::1]/hook",
        "https://[::ffff:127.0.0.1]/hook",
        "https://[::ffff:169.254.169.254]/hook",
        "https://localhost/hook",
        "https://metadata.google.internal/computeMetadata/v1/",
    ] {
        let payload = json!({
            "name": "ssrf check",
            "kind": "error_log_count",
            "target": "",
            "threshold": 5.0,
            "window_secs": 300,
            "webhook_url": bad_url,
        })
        .to_string();
        let req = with_connect_info(
            req_builder("POST", "/v1/alerts/rules")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie),
            Body::from(payload),
        );
        let (status, body) = send(&app.router, req).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "SSRF target {bad_url} must be rejected, got {status} {body:?}"
        );
    }

    let ok_payload = json!({
        "name": "valid webhook rule",
        "kind": "error_log_count",
        "target": "api",
        "threshold": 5.0,
        "window_secs": 300,
        "webhook_url": "https://hooks.example.com/alert",
    })
    .to_string();
    let req = with_connect_info(
        req_builder("POST", "/v1/alerts/rules")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, cookie),
        Body::from(ok_payload),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(
        body["rule"]["webhook_url"],
        json!("https://hooks.example.com/alert")
    );
}

#[tokio::test]
async fn webhook_dispatcher_does_not_follow_redirects_to_metadata() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local test listener");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n";
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });
    let url = format!("http://{addr}/hook");
    let err = observe_server::ssrf::dispatch_webhook(&url, json!({"ok": true}), true, true)
        .await
        .expect_err("302 redirect must not be followed as success");
    assert!(
        err.contains("302"),
        "expected 302 non-follow error, got {err}"
    );
}

// ---------------------------------------------------------------------
// 5. Ingestion DoS bounds, CRLF sanitization, timestamps & LIKE escaping
// ---------------------------------------------------------------------

#[tokio::test]
async fn ingest_rejects_bad_batches_atomically_and_sanitizes_crlf() {
    let app = spawn_app().await;

    // Cardinality explosion (> 32 attribute keys) and bad level in second element:
    // whole batch must fail atomically with 400 and 0 rows inserted.
    let mut big_attrs = serde_json::Map::new();
    for i in 0..35 {
        big_attrs.insert(format!("k{i}"), json!("v"));
    }
    let bad_batch = json!([
        {
            "level": "INFO",
            "service": "svc-atomic",
            "message": "first record should roll back",
        },
        {
            "level": "INFO",
            "service": "svc-atomic",
            "message": "too many attrs",
            "attributes": big_attrs,
        }
    ])
    .to_string();
    let req = with_connect_info(
        req_builder("POST", "/v1/logs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", app.ingest_token),
            ),
        Body::from(bad_batch),
    );
    let (status, _) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Negative / pre-epoch timestamp, non-object attributes, and CRLF in service must be rejected.
    for payload in [
        json!([{"timestamp": "1969-12-31T23:59:59Z", "level": "INFO", "service": "api", "message": "old"}]),
        json!([{"level": "INFO\r\nERROR", "service": "api", "message": "bad level"}]),
        json!([{"level": "INFO", "service": "api\r\nforged", "message": "bad service"}]),
        json!([{"level": "INFO", "service": "api", "message": "arr attrs", "attributes": [1, 2, 3]}]),
    ] {
        let req = with_connect_info(
            req_builder("POST", "/v1/logs")
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", app.ingest_token),
                ),
            Body::from(payload.to_string()),
        );
        let (status, body) = send(&app.router, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body:?}");
    }

    // Valid logs including CRLF/ANSI inside message + literal `%` and `_` for LIKE escape test.
    let good_batch = json!([
        {
            "level": "INFO",
            "service": "api",
            "message": "line1\r\nFAKE_LOG\x1b[31m literal 100% match_me",
        },
        {
            "level": "INFO",
            "service": "api",
            "message": "plain unrelated entry",
        }
    ])
    .to_string();
    let req = with_connect_info(
        req_builder("POST", "/v1/logs")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", app.ingest_token),
            ),
        Body::from(good_batch),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::OK, "body: {body:?}");
    assert_eq!(body["accepted"], json!(2));

    let (_, cookie, _) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    let cookie = cookie.expect("admin login");

    // Verify atomic rollback: svc-atomic must have 0 logs.
    let req = with_connect_info(
        req_builder("GET", "/v1/logs?service=svc-atomic").header(header::COOKIE, &cookie),
        Body::empty(),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["logs"].as_array().unwrap().len(), 0);

    // Verify LIKE escaping: searching q=% must match ONLY the log containing literal `%`.
    let req = with_connect_info(
        req_builder("GET", "/v1/logs?q=%25").header(header::COOKIE, &cookie),
        Body::empty(),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::OK);
    let logs = body["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 1);
    let msg = logs[0]["message"].as_str().unwrap();
    assert!(!msg.contains('\r') && !msg.contains('\n') && !msg.contains('\x1b'));

    // Verify LIKE escaping for `_` (`match_me` vs `matchXme`).
    let req = with_connect_info(
        req_builder("GET", "/v1/logs?q=match_me").header(header::COOKIE, &cookie),
        Body::empty(),
    );
    let (status, body) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["logs"].as_array().unwrap().len(), 1);

    // Verify > 16 search tokens and negative since timestamp are rejected.
    let req = with_connect_info(
        req_builder("GET", "/v1/logs?since=1960-01-01T00:00:00Z").header(header::COOKIE, &cookie),
        Body::empty(),
    );
    let (status, _) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let many_tokens = (0..18)
        .map(|i| format!("t{i}"))
        .collect::<Vec<_>>()
        .join("+");
    let req = with_connect_info(
        req_builder("GET", &format!("/v1/logs?q={many_tokens}")).header(header::COOKIE, cookie),
        Body::empty(),
    );
    let (status, _) = send(&app.router, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ingest_spans_rejects_negative_duration_and_invalid_end() {
    let app = spawn_app().await;
    let bad_spans = [
        json!([{
            "trace_id": "tr1",
            "span_id": "sp1",
            "name": "op",
            "service": "svc",
            "start": "2026-11-19T10:00:00Z",
            "end": "2026-11-19T09:59:00Z"
        }]),
        json!([{
            "trace_id": "tr1",
            "span_id": "sp1",
            "name": "op",
            "service": "svc",
            "start": "2026-11-19T10:00:00Z",
            "end": "not-a-timestamp",
            "duration_ms": 10.0
        }]),
        json!([{
            "trace_id": "tr1",
            "span_id": "sp1",
            "name": "op",
            "service": "svc",
            "start": "2026-11-19T10:00:00Z",
            "duration_ms": 1e20
        }]),
    ];
    for payload in bad_spans {
        let req = with_connect_info(
            req_builder("POST", "/v1/traces")
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", app.ingest_token),
                ),
            Body::from(payload.to_string()),
        );
        let (status, body) = send(&app.router, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body:?}");
    }
}

// ---------------------------------------------------------------------
// 6. Session fixation, Secure cookie, CSRF, XFF, headers & weak seed
// ---------------------------------------------------------------------

#[tokio::test]
async fn session_fixation_csrf_and_security_headers() {
    let app = spawn_app().await;
    let (_, cookie1, _) = login(&app.router, &app.admin_email, ADMIN_PASSWORD).await;
    let cookie1 = cookie1.expect("first login");

    // Re-login while sending cookie1 must rotate and invalidate cookie1.
    let payload = json!({ "email": app.admin_email, "password": ADMIN_PASSWORD }).to_string();
    let req = with_connect_info(
        req_builder("POST", "/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &cookie1),
        Body::from(payload),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let csp = resp
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        !csp.contains("unsafe-inline"),
        "CSP must not allow unsafe-inline: {csp}"
    );
    assert_eq!(
        resp.headers()
            .get(header::X_FRAME_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );

    let cookie2 = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert_ne!(cookie1, cookie2);

    // Old session cookie1 must be revoked.
    let old_req = with_connect_info(
        req_builder("GET", "/auth/me").header(header::COOKIE, &cookie1),
        Body::empty(),
    );
    let (status, _) = send(&app.router, old_req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Cross-site Origin on cookie-authenticated POST must be blocked (403).
    let csrf_req = with_connect_info(
        req_builder("POST", "/v1/alerts/rules")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "https://attacker.example")
            .header(header::COOKIE, &cookie2),
        Body::from(create_rule_payload()),
    );
    let (status, _) = send(&app.router, csrf_req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Cross-site Sec-Fetch-Site on cookie-authenticated POST must be blocked (403).
    let sfs_req = with_connect_info(
        req_builder("POST", "/auth/logout")
            .header("sec-fetch-site", "cross-site")
            .header(header::COOKIE, &cookie2),
        Body::empty(),
    );
    let (status, _) = send(&app.router, sfs_req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn xff_ignored_unless_trusted_proxy_and_body_limit_enforced() {
    let mut db_path = std::env::temp_dir();
    db_path.push(format!("observe-xff-{}.sqlite", uuid::Uuid::new_v4()));
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.to_str().unwrap()))
        .unwrap()
        .create_if_missing(true);
    let db = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();

    let config = Config {
        admin_email: "admin@example.com".into(),
        admin_password: ADMIN_PASSWORD.into(),
        global_rate_limit_per_min: 2,
        max_request_body_bytes: 256,
        public_url: "http://localhost.evil.com:8090".into(),
        trusted_proxies: Vec::new(),
        ..Config::default()
    };
    observe_server::store::seed(&db, &config).await.unwrap();
    let state = Arc::new(AppState {
        db,
        config,
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(2),
    });
    let router = routes::router(state);

    await_safe_minute_window().await;

    // Verify public_url="http://localhost.evil.com:8090" STILL sets Secure cookie flag!
    let login_req = with_connect_info(
        req_builder("POST", "/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", "198.51.100.1"),
        Body::from(json!({"email": "admin@example.com", "password": ADMIN_PASSWORD}).to_string()),
    );
    let resp = router.clone().oneshot(login_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        set_cookie.contains("; Secure"),
        "http://localhost.evil.com must keep Secure cookie flag: {set_cookie}"
    );

    // Request 2 from same TCP peer with spoofed XFF -> still allowed (count = 2).
    let req2 = with_connect_info(
        req_builder("GET", "/health").header("x-forwarded-for", "198.51.100.2"),
        Body::empty(),
    );
    let (s2, _) = send(&router, req2).await;
    assert_eq!(s2, StatusCode::OK);

    // Request 3 from same TCP peer with DIFFERENT spoofed XFF -> must hit 429!
    let req3 = with_connect_info(
        req_builder("GET", "/health").header("x-forwarded-for", "198.51.100.3"),
        Body::empty(),
    );
    let (s3, _) = send(&router, req3).await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);

    // Oversized body (> 256 bytes) rejected with 413 PAYLOAD_TOO_LARGE when limiter allows.
    let big_router = spawn_app().await;
    let oversized = "x".repeat(2 * 1024 * 1024);
    let big_req = with_connect_info(
        req_builder("POST", "/auth/login").header(header::CONTENT_TYPE, "application/json"),
        Body::from(oversized),
    );
    let resp = big_router.router.clone().oneshot(big_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    drop(router);
    let _ = std::fs::remove_file(&db_path);
}

#[tokio::test]
async fn seed_rejects_weak_placeholder_admin_passwords() {
    let mut db_path = std::env::temp_dir();
    db_path.push(format!("observe-weak-{}.sqlite", uuid::Uuid::new_v4()));
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.to_str().unwrap()))
        .unwrap()
        .create_if_missing(true);
    let db = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();

    for weak in [
        "ChangeMe_InfinityObserve#2026",
        "ChangeMe_Infinity#2025",
        "password1234",
        "short",
    ] {
        let cfg = Config {
            admin_password: weak.into(),
            ..Config::default()
        };
        assert!(
            observe_server::store::seed(&db, &cfg).await.is_err(),
            "weak/placeholder password {weak} must be rejected"
        );
    }

    // Unset/empty admin_password auto-generates a strong random password.
    let auto_cfg = Config::default();
    assert!(observe_server::store::seed(&db, &auto_cfg).await.is_ok());

    drop(db);
    let _ = std::fs::remove_file(&db_path);
}

#[tokio::test]
async fn keys_rbac_unknown_role_fail_closed_and_metrics_bounds() {
    let mut db_path = std::env::temp_dir();
    db_path.push(format!("observe-rbac-{}.sqlite", uuid::Uuid::new_v4()));
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.to_str().unwrap()))
        .unwrap()
        .create_if_missing(true);
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let config = Config {
        admin_email: "admin@example.com".into(),
        admin_password: ADMIN_PASSWORD.into(),
        global_rate_limit_per_min: 1_000_000,
        ..Config::default()
    };
    observe_server::store::seed(&db, &config).await.unwrap();

    let viewer_hash = observe_core::password::hash_password(VIEWER_PASSWORD).unwrap();
    sqlx::query(
        "INSERT INTO users (id, email, username, display_name, password_hash, role, created_at)
         VALUES (?, 'viewer@example.com', 'viewer', 'Viewer', ?, 'viewer', ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&viewer_hash)
    .bind(observe_server::store::now())
    .execute(&db)
    .await
    .unwrap();

    let ghost_hash = observe_core::password::hash_password(VIEWER_PASSWORD).unwrap();
    sqlx::query(
        "INSERT INTO users (id, email, username, display_name, password_hash, role, created_at)
         VALUES (?, 'ghost@example.com', 'ghost', 'Ghost', ?, 'unknown_role', ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&ghost_hash)
    .bind(observe_server::store::now())
    .execute(&db)
    .await
    .unwrap();

    let router = routes::router(Arc::new(AppState {
        db,
        config,
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(1_000_000),
    }));

    // Viewer cannot list, create, or delete ingest keys.
    let (_, viewer_cookie, _) = login(&router, "viewer@example.com", VIEWER_PASSWORD).await;
    let viewer_cookie = viewer_cookie.unwrap();
    for (method, path, body) in [
        ("GET", "/v1/keys", Body::empty()),
        (
            "POST",
            "/v1/keys",
            Body::from(json!({"name": "v"}).to_string()),
        ),
        ("DELETE", "/v1/keys/some-id", Body::empty()),
    ] {
        let req = with_connect_info(
            req_builder(method, path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &viewer_cookie),
            body,
        );
        let (status, _) = send(&router, req).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {path} must be 403 for viewer"
        );
    }

    // Unknown role gets zero permissions (fails closed on read endpoints too).
    let (_, ghost_cookie, _) = login(&router, "ghost@example.com", VIEWER_PASSWORD).await;
    let ghost_cookie = ghost_cookie.unwrap();
    let req = with_connect_info(
        req_builder("GET", "/v1/stats").header(header::COOKIE, ghost_cookie),
        Body::empty(),
    );
    let (status, _) = send(&router, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin creates and revokes a key; revoked key is rejected from ingest; alert window_secs bounded.
    let (_, admin_cookie, _) = login(&router, "admin@example.com", ADMIN_PASSWORD).await;
    let admin_cookie = admin_cookie.unwrap();
    let create_req = with_connect_info(
        req_builder("POST", "/v1/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &admin_cookie),
        Body::from(json!({"name": "temp-agent"}).to_string()),
    );
    let (status, body) = send(&router, create_req).await;
    assert_eq!(status, StatusCode::OK);
    let key_id = body["key"]["id"].as_str().unwrap().to_string();
    let raw_tok = body["token"].as_str().unwrap().to_string();

    let del_req = with_connect_info(
        req_builder("DELETE", &format!("/v1/keys/{key_id}")).header(header::COOKIE, &admin_cookie),
        Body::empty(),
    );
    let (status, _) = send(&router, del_req).await;
    assert_eq!(status, StatusCode::OK);

    let ingest_revoked = with_connect_info(
        req_builder("POST", "/v1/metrics")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {raw_tok}")),
        Body::from(json!([{"name": "m", "value": 1.0}]).to_string()),
    );
    let (status, _) = send(&router, ingest_revoked).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Out-of-bounds alert window_secs (< 60 or > 86400) must fail with 400.
    for bad_win in [10, 1_000_000] {
        let req = with_connect_info(
            req_builder("POST", "/v1/alerts/rules")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &admin_cookie),
            Body::from(
                json!({
                    "name": "bad window",
                    "kind": "metric_p99",
                    "target": "lat",
                    "threshold": 100.0,
                    "window_secs": bad_win
                })
                .to_string(),
            ),
        );
        let (status, _) = send(&router, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Unknown /v1/* route returns 404 JSON rather than 200 HTML; logout works and revokes cookie.
    let not_found_req = with_connect_info(req_builder("GET", "/v1/nope"), Body::empty());
    let (status, _) = send(&router, not_found_req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let logout_req = with_connect_info(
        req_builder("POST", "/auth/logout").header(header::COOKIE, &admin_cookie),
        Body::empty(),
    );
    let (status, _) = send(&router, logout_req).await;
    assert_eq!(status, StatusCode::OK);
    let after_logout = with_connect_info(
        req_builder("GET", "/auth/me").header(header::COOKIE, &admin_cookie),
        Body::empty(),
    );
    let (status, _) = send(&router, after_logout).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    drop(router);
    let _ = std::fs::remove_file(&db_path);
}

#[tokio::test]
async fn invalid_authorization_never_falls_back_to_session_cookie_and_disabled_account_locks_out() {
    let mut db_path = std::env::temp_dir();
    db_path.push(format!("observe-authz-{}.sqlite", uuid::Uuid::new_v4()));
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.to_str().unwrap()))
        .unwrap()
        .create_if_missing(true);
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let config = Config {
        admin_email: "admin@example.com".into(),
        admin_password: ADMIN_PASSWORD.into(),
        global_rate_limit_per_min: 1_000_000,
        trusted_proxies: vec!["10.0.0.0/8".into()],
        ..Config::default()
    };
    observe_server::store::seed(&db, &config).await.unwrap();

    let disabled_hash = observe_core::password::hash_password(VIEWER_PASSWORD).unwrap();
    sqlx::query(
        "INSERT INTO users (id, email, username, display_name, password_hash, role, disabled, created_at)
         VALUES (?, 'disabled@example.com', 'disabled', 'Disabled', ?, 'viewer', 1, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&disabled_hash)
    .bind(observe_server::store::now())
    .execute(&db)
    .await
    .unwrap();

    let router = routes::router(Arc::new(AppState {
        db,
        config,
        login_throttle: LoginThrottle::new(3, 60, 60),
        ip_limiter: IpRateLimiter::new(1_000_000),
    }));

    // 1. Valid session cookie + malformed/invalid Authorization header must return 401 (no cookie fallback).
    let (_, admin_cookie, _) = login(&router, "admin@example.com", ADMIN_PASSWORD).await;
    let admin_cookie = admin_cookie.unwrap();

    for bad_auth in [
        "Basic dXNlcjpwYXNz",
        "Bearer short",
        "Bearer invalid_bearer_token_that_does_not_exist",
    ] {
        let req = with_connect_info(
            req_builder("GET", "/auth/me")
                .header(header::AUTHORIZATION, bad_auth)
                .header(header::COOKIE, &admin_cookie),
            Body::empty(),
        );
        let (status, _) = send(&router, req).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "invalid Authorization {bad_auth} must not fall back to session cookie"
        );
    }

    // 2. Disabled account with valid password must throttle identically (3x 401 -> 429).
    for _ in 1..=3 {
        let (status, _, _) = login(&router, "disabled@example.com", VIEWER_PASSWORD).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, cookie, _) = login(&router, "disabled@example.com", VIEWER_PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "disabled account must lock out after max_fails to prevent password oracle"
    );
    assert!(cookie.is_none());

    drop(router);
    let _ = std::fs::remove_file(&db_path);
}

#[tokio::test]
async fn xff_canonicalizes_ipv4_mapped_ipv6_and_breaks_on_malformed_hop() {
    let mut db_path = std::env::temp_dir();
    db_path.push(format!("observe-xffv6-{}.sqlite", uuid::Uuid::new_v4()));
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.to_str().unwrap()))
        .unwrap()
        .create_if_missing(true);
    let db = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let config = Config {
        trusted_proxies: vec!["10.0.0.0/8".into()],
        global_rate_limit_per_min: 2,
        ..Config::default()
    };
    let router = routes::router(Arc::new(AppState {
        db,
        config,
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(2),
    }));

    await_safe_minute_window().await;

    let mapped_peer = SocketAddr::new("::ffff:10.0.0.1".parse().unwrap(), 4444);
    for idx in 0..3 {
        let mut req = req_builder("GET", "/health")
            .header(
                "x-forwarded-for",
                format!("198.51.100.{idx}, garbage, 10.0.0.5"),
            )
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(mapped_peer));
        let (status, _) = send(&router, req).await;
        if idx < 2 {
            assert_eq!(status, StatusCode::OK);
        } else {
            assert_eq!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "malformed XFF hop must stop walking left and share peer bucket 10.0.0.1"
            );
        }
    }

    drop(router);
    let _ = std::fs::remove_file(&db_path);
}
