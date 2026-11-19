//! Integration tests for the privilege-escalation guard documented in the
//! top-level README's Security table:
//!
//! > Privilege escalation | Callers may only assign roles / grant permissions
//! > they already hold; the built-in `superadmin` role is protected from
//! > non-superadmins.
//!
//! These tests drive the real axum `Router` returned by `data_server::routes::router`
//! (via `tower::ServiceExt::oneshot`) against a real, freshly-migrated SQLite
//! database. Nothing about the RBAC logic or the admin route handlers is mocked.
//!
//! ## The real protection boundary (read from source, not assumed)
//!
//! `crates/data-server/src/routes/admin.rs` defines the guard as:
//!
//! - `caller_is_superadmin(p)`: true if the caller holds the `superadmin`
//!   *role*, OR the caller holds the literal wildcard permission `*:*`
//!   (see `rbac::any_permission(&p.permissions, "*:*")`). These two are
//!   treated as fully equivalent privilege levels *by design* — a caller
//!   with `*:*` already has every permission, so letting them also assign
//!   the `superadmin` role is not an escalation.
//! - `permission_grant_allowed(p, perms)`: a non-superadmin-equivalent caller
//!   may only grant a permission set that is a subset of permissions they
//!   already hold (checked with the same `granted:action` wildcard matching
//!   used everywhere else in RBAC, `data_core::rbac::any_permission`).
//! - `role_change_allowed` / `assigned_roles_allowed`: a non-superadmin-equivalent
//!   caller may not assign a role literally named `superadmin`, and may not
//!   assign any role whose *expanded* permission set they don't already
//!   fully hold.
//!
//! Critically, holding broad-but-partial wildcards short of `*:*` (e.g.
//! `users:*` + `roles:*`) does **not** make a caller superadmin-equivalent —
//! `any_permission(["users:*", "roles:*"], "*:*")` is `false`, because the
//! resource segment `users`/`roles` does not match the required resource
//! segment `*`. Only the literal `*:*` permission (or the `superadmin` role)
//! crosses the line. Test `wildcard_permission_holder_is_superadmin_equivalent`
//! below confirms that nuance explicitly, since it is easy to assume (as a
//! first guess) that the boundary is purely role-based.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use data_server::config::Config;
use data_server::ratelimit::IpRateLimiter;
use data_server::routes;
use data_server::state::AppState;
use data_server::store;
use data_server::throttle::LoginThrottle;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tower::ServiceExt;

/// Spins up a fresh in-memory SQLite database, runs the real migrations, and
/// seeds the built-in roles (`superadmin` / `admin` / `user`) plus the
/// bootstrap admin account exactly as the production binary does at startup.
async fn test_state() -> Arc<AppState> {
    let opts: SqliteConnectOptions = "sqlite::memory:".parse().expect("parse sqlite url");
    let db = SqlitePoolOptions::new()
        .max_connections(1) // single connection so the in-memory DB persists across calls
        .connect_with(opts)
        .await
        .expect("connect in-memory sqlite");
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("run migrations");

    let config = Config {
        admin_email: "admin@infinity.local".into(),
        admin_password: "Sup3rStrongAdminPass!1".into(),
        ..Config::default()
    };
    store::seed(&db, &config).await.expect("seed database");

    Arc::new(AppState {
        db,
        config,
        indexes: tokio::sync::RwLock::new(HashMap::new()),
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(0), // unlimited, so it never interferes with these tests
    })
}

/// Creates a role directly via the store (test fixture setup only — this does
/// NOT exercise the HTTP guard; it just seeds data the guard will later be
/// checked against).
async fn seed_role(state: &Arc<AppState>, name: &str, perms: &[&str]) {
    let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
    store::upsert_role(&state.db, name, "fixture role", &perms)
        .await
        .expect("seed role");
}

/// Creates a real user, assigns real roles to them, and opens a real session
/// row in the database, returning a `Cookie` header value. This goes through
/// the exact same `Principal::from_request_parts` session-lookup path that
/// production requests use — nothing about authentication is mocked.
async fn login_as(state: &Arc<AppState>, email: &str, username: &str, roles: &[&str]) -> String {
    let user = store::create_user(&state.db, email, username, None, "irrelevant-password-1")
        .await
        .expect("create fixture user");
    let roles: Vec<String> = roles.iter().map(|r| r.to_string()).collect();
    store::set_user_roles(&state.db, &user.id, &roles)
        .await
        .expect("assign fixture roles");

    let raw_token = format!("test-session-{}", user.id);
    let hash = data_server::util::sha256_hex(&raw_token);
    store::create_session(&state.db, &hash, &user.id, 3600)
        .await
        .expect("create fixture session");
    format!("{}={}", data_server::auth::SESSION_COOKIE, raw_token)
}

/// Issues a request against the real router and returns (status, json body).
async fn call(
    state: &Arc<AppState>,
    method: &str,
    path: &str,
    cookie: &str,
    body: Value,
) -> (StatusCode, Value) {
    let app = routes::router(state.clone());
    // The real binary serves via `into_make_service_with_connect_info`, which
    // populates a `ConnectInfo<SocketAddr>` extension consumed by the global
    // IP rate-limit middleware. `oneshot` bypasses that layer, so the fixture
    // inserts the same extension a real TCP connection would provide.
    let peer: std::net::SocketAddr = ([127, 0, 0, 1], 12345).into();
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .extension(axum::extract::ConnectInfo(peer))
        .body(Body::from(body.to_string()))
        .expect("build request");
    let response = app.oneshot(request).await.expect("router call");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn new_user_payload(email: &str, username: &str, roles: &[&str]) -> Value {
    json!({
        "email": email,
        "username": username,
        "password": "TargetUserPassword1!",
        "roles": roles,
    })
}

/// 1. Baseline: a non-superadmin caller who holds permission `widgets:write`
///    (via a custom role) CAN grant a role that carries only that permission
///    to another user. Proves legitimate, non-escalating grants still work.
#[tokio::test]
async fn non_superadmin_can_grant_permission_they_hold() {
    let state = test_state().await;
    seed_role(&state, "widget_editor", &["widgets:write"]).await;
    seed_role(&state, "user_admin", &["users:write"]).await;
    let cookie = login_as(
        &state,
        "granter1@infinity.local",
        "granter1",
        &["widget_editor", "user_admin"],
    )
    .await;

    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload("target1@infinity.local", "target1", &["widget_editor"]),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "granting a held permission should succeed, got body: {body}"
    );
    let roles = body["user"]["roles"]
        .as_array()
        .expect("roles array in response");
    assert!(
        roles.iter().any(|r| r == "widget_editor"),
        "target user should have received the widget_editor role: {body}"
    );
}

/// 2. A non-superadmin caller who holds `widgets:write` and `users:write`
///    CANNOT grant a role that carries `secrets:read`, a permission they do
///    not hold themselves. This is the core self-escalation guard.
#[tokio::test]
async fn non_superadmin_cannot_grant_permission_they_do_not_hold() {
    let state = test_state().await;
    seed_role(&state, "widget_editor", &["widgets:write"]).await;
    seed_role(&state, "user_admin", &["users:write"]).await;
    seed_role(&state, "secret_reader", &["secrets:read"]).await;
    let cookie = login_as(
        &state,
        "granter2@infinity.local",
        "granter2",
        &["widget_editor", "user_admin"],
    )
    .await;

    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload("target2@infinity.local", "target2", &["secret_reader"]),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "granting a permission the caller lacks must be rejected, got body: {body}"
    );
    assert_eq!(body["error"], "access_denied");
}

/// 3. A non-superadmin caller who holds broad-but-partial wildcards
///    (`users:*` and `roles:*`, short of the full `*:*`) CANNOT assign the
///    built-in `superadmin` role to anyone. Confirms the real boundary is not
///    "any wildcard permission" but specifically full (`*:*`) or the
///    `superadmin` role itself.
#[tokio::test]
async fn non_superadmin_with_broad_wildcards_cannot_assign_superadmin() {
    let state = test_state().await;
    seed_role(&state, "power_user", &["users:*", "roles:*"]).await;
    let cookie = login_as(
        &state,
        "poweruser@infinity.local",
        "poweruser",
        &["power_user"],
    )
    .await;

    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload("target3@infinity.local", "target3", &["superadmin"]),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a broad-but-partial wildcard holder must not be able to assign superadmin, got body: {body}"
    );
    assert_eq!(body["error"], "access_denied");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("superadmin"),
        "error should explain the superadmin restriction: {body}"
    );
}

/// 4. Positive control: the actual seeded `superadmin` user CAN grant a
///    permission it did not previously hold as an explicit string (via its
///    `*:*` wildcard) and CAN assign the `superadmin` role to another user.
///    Proves the guard is a real allow/deny check, not a blanket rejection.
#[tokio::test]
async fn superadmin_can_grant_permissions_and_assign_superadmin() {
    let state = test_state().await;
    let cookie = login_as(
        &state,
        "sa@infinity.local",
        "sa_user",
        &[data_core::rbac::ROLE_SUPERADMIN],
    )
    .await;

    // Can create a brand new role carrying an arbitrary permission.
    let (status, body) = call(
        &state,
        "PUT",
        "/admin/roles",
        &cookie,
        json!({
            "name": "arbitrary_role",
            "description": "granted by superadmin",
            "permissions": ["anything:goes", "totally:unheld-elsewhere"],
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "superadmin should be able to grant any permission, got body: {body}"
    );

    // Can assign the superadmin role to another user.
    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload(
            "target4@infinity.local",
            "target4",
            &[data_core::rbac::ROLE_SUPERADMIN],
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "superadmin should be able to assign superadmin, got body: {body}"
    );
    let roles = body["user"]["roles"].as_array().expect("roles array");
    assert!(roles.iter().any(|r| r == "superadmin"));
}

/// 5. Boundary confirmation: a caller who does NOT hold the `superadmin`
///    *role* but does hold the literal wildcard permission `*:*` (via a
///    differently-named custom role) IS treated as superadmin-equivalent by
///    `caller_is_superadmin` and CAN assign the `superadmin` role. This is
///    the precise, code-confirmed boundary — not "any broad permission",
///    but "role == superadmin OR permission == *:*" exactly.
#[tokio::test]
async fn wildcard_permission_holder_is_superadmin_equivalent() {
    let state = test_state().await;
    seed_role(&state, "godmode", &["*:*"]).await;
    let cookie = login_as(
        &state,
        "godmode@infinity.local",
        "godmode_user",
        &["godmode"],
    )
    .await;

    let (status, body) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        new_user_payload(
            "target5@infinity.local",
            "target5",
            &[data_core::rbac::ROLE_SUPERADMIN],
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a literal *:* permission holder is superadmin-equivalent by design, got body: {body}"
    );
}

async fn call_raw(
    state: &Arc<AppState>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
    peer_ip: [u8; 4],
) -> (StatusCode, axum::http::HeaderMap, Value, String) {
    let app = routes::router(state.clone());
    let peer: std::net::SocketAddr = (peer_ip, 12345).into();
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .extension(axum::extract::ConnectInfo(peer));
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = builder
        .body(Body::from(body.to_string()))
        .expect("build raw request");
    let response = app.oneshot(request).await.expect("router call");
    let status = response.status();
    let resp_headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read body");
    let text = String::from_utf8_lossy(&bytes).to_string();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, resp_headers, json, text)
}

#[tokio::test]
async fn admin_cannot_disable_delete_superadmin_or_overwrite_roles() {
    let state = test_state().await;
    let sa = store::get_user_by_email(&state.db, "admin@infinity.local")
        .await
        .unwrap()
        .unwrap();
    seed_role(
        &state,
        "role_writer",
        &["users:write", "users:read", "roles:write", "roles:read"],
    )
    .await;
    let admin_cookie = login_as(
        &state,
        "sec_admin@infinity.local",
        "sec_admin",
        &["admin", "role_writer"],
    )
    .await;

    let (status, _) = call(
        &state,
        "PATCH",
        &format!("/admin/users/{}", sa.id),
        &admin_cookie,
        json!({"disabled": true}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = call(
        &state,
        "DELETE",
        &format!("/admin/users/{}", sa.id),
        &admin_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = call(
        &state,
        "PUT",
        "/admin/roles",
        &admin_cookie,
        json!({"name": "superadmin", "description": "wiped", "permissions": []}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let role_writer_cookie = login_as(
        &state,
        "role_writer@infinity.local",
        "role_writer",
        &["role_writer"],
    )
    .await;

    let (status, _) = call(
        &state,
        "PUT",
        "/admin/roles",
        &role_writer_cookie,
        json!({"name": "admin", "description": "wiped", "permissions": ["users:read"]}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Unknown role and duplicate email return 400 / 409 rather than 500.
    let (status, _) = call(
        &state,
        "POST",
        "/admin/users",
        &admin_cookie,
        new_user_payload("u1@infinity.local", "u1", &["nonexistent_role"]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &state,
        "POST",
        "/admin/users",
        &admin_cookie,
        new_user_payload("sec_admin@infinity.local", "dup", &["user"]),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn disabling_user_immediately_revokes_session() {
    let state = test_state().await;
    let admin_cookie = login_as(
        &state,
        "disabler@infinity.local",
        "disabler",
        &[data_core::rbac::ROLE_ADMIN],
    )
    .await;
    let victim_cookie = login_as(
        &state,
        "victim@infinity.local",
        "victim",
        &[data_core::rbac::ROLE_USER],
    )
    .await;
    let victim = store::get_user_by_email(&state.db, "victim@infinity.local")
        .await
        .unwrap()
        .unwrap();

    let (status, _) = call(&state, "GET", "/auth/me", &victim_cookie, Value::Null).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &state,
        "PATCH",
        &format!("/admin/users/{}", victim.id),
        &admin_cookie,
        json!({"disabled": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(&state, "GET", "/auth/me", &victim_cookie, Value::Null).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_cookie_flags_session_fixation_and_enumeration_resistance() {
    let mut cfg = Config {
        admin_email: "admin@infinity.local".into(),
        admin_password: "Sup3rStrongAdminPass!1".into(),
        public_url: "https://data.infinity.local".into(),
        ..Config::default()
    };
    assert!(cfg.secure_cookies());
    cfg.public_url = "http://localhost.evil.com:8094".into();
    assert!(cfg.secure_cookies());
    cfg.public_url = "http://localhost:8094".into();
    assert!(!cfg.secure_cookies());

    let state = test_state().await;
    let pre_cookie = login_as(
        &state,
        "fixation@infinity.local",
        "fixation_user",
        &[data_core::rbac::ROLE_USER],
    )
    .await;

    // Login while sending an old session cookie must revoke the old session and issue a new one.
    let body =
        json!({"email": "admin@infinity.local", "password": "Sup3rStrongAdminPass!1"}).to_string();
    let (status, headers, _, _) = call_raw(
        &state,
        "POST",
        "/auth/login",
        &[("cookie", &pre_cookie)],
        &body,
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let set_cookie = headers
        .get("set-cookie")
        .expect("set-cookie header")
        .to_str()
        .unwrap();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Max-Age=7200"));
    assert_ne!(set_cookie.split(';').next().unwrap(), pre_cookie);

    // Pre-existing session sent during login must be invalidated.
    let (old_status, _) = call(&state, "GET", "/auth/me", &pre_cookie, Value::Null).await;
    assert_eq!(old_status, StatusCode::UNAUTHORIZED);

    // Wrong password vs unknown user return identical uniform 401 message.
    let bad_pw =
        json!({"email": "admin@infinity.local", "password": "WrongPassword!123"}).to_string();
    let (s1, _, b1, _) = call_raw(&state, "POST", "/auth/login", &[], &bad_pw, [10, 0, 0, 1]).await;
    let unknown =
        json!({"email": "nobody@infinity.local", "password": "WrongPassword!123"}).to_string();
    let (s2, _, b2, _) =
        call_raw(&state, "POST", "/auth/login", &[], &unknown, [10, 0, 0, 2]).await;
    assert_eq!(s1, StatusCode::UNAUTHORIZED);
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    assert_eq!(b1, b2);
}

#[tokio::test]
async fn api_key_constant_time_auth_isolation_and_no_cookie_fallback() {
    let state = test_state().await;
    let sa_cookie = login_as(
        &state,
        "keyowner@infinity.local",
        "keyowner",
        &[data_core::rbac::ROLE_SUPERADMIN],
    )
    .await;
    let (status, created) = call(
        &state,
        "POST",
        "/admin/api-keys",
        &sa_cookie,
        json!({"name": "ci-ingest"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let raw_key = created["token"].as_str().unwrap().to_string();
    let key_id = created["api_key"]["id"].as_str().unwrap().to_string();
    assert!(raw_key.starts_with("idat_"));

    let bearer = format!("Bearer {raw_key}");
    let (status, _, _, _) = call_raw(
        &state,
        "GET",
        "/api/collections",
        &[("authorization", &bearer)],
        "",
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // API key cannot reach admin or session endpoints.
    let (status, _, _, _) = call_raw(
        &state,
        "GET",
        "/admin/users",
        &[("authorization", &bearer)],
        "",
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, _, _) = call_raw(
        &state,
        "GET",
        "/auth/me",
        &[("authorization", &bearer)],
        "",
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Invalid Bearer must NOT silently fall back to ambient session cookie.
    let (status, _, _, _) = call_raw(
        &state,
        "GET",
        "/admin/users",
        &[
            ("authorization", "Bearer idat_invalidtoken0000"),
            ("cookie", &sa_cookie),
        ],
        "",
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(
        &state,
        "DELETE",
        &format!("/admin/api-keys/{key_id}"),
        &sa_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &state,
        "DELETE",
        &format!("/admin/api-keys/{key_id}"),
        &sa_cookie,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

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

#[tokio::test]
async fn xff_spoofing_cannot_bypass_rate_limit_or_throttle() {
    // Build fresh state with tight per-IP limit (2 req/min) and empty trusted_proxies.
    let opts: SqliteConnectOptions = "sqlite::memory:".parse().unwrap();
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let config = Config {
        admin_email: "admin@infinity.local".into(),
        admin_password: "Sup3rStrongAdminPass!1".into(),
        global_rate_limit_per_min: 2,
        ..Config::default()
    };
    store::seed(&db, &config).await.unwrap();
    let state = Arc::new(AppState {
        db,
        config,
        indexes: tokio::sync::RwLock::new(HashMap::new()),
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(2),
    });

    await_safe_minute_window().await;
    for spoof in ["1.1.1.1", "2.2.2.2"] {
        let (status, _, _, _) = call_raw(
            &state,
            "GET",
            "/health",
            &[("x-forwarded-for", spoof)],
            "",
            [203, 0, 113, 10],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    // 3rd request from same peer with spoofed XFF must still be rate-limited.
    let (status, _, _, _) = call_raw(
        &state,
        "GET",
        "/health",
        &[("x-forwarded-for", "3.3.3.3")],
        "",
        [203, 0, 113, 10],
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn vector_table_bounds_sqli_allowlists_headers_and_csrf_enforced() {
    let state = test_state().await;
    let cookie = login_as(
        &state,
        "datauser@infinity.local",
        "datauser",
        &[data_core::rbac::ROLE_ADMIN],
    )
    .await;

    // Security headers + Cache-Control + CSRF Origin guard.
    let (status, headers, _, _) = call_raw(
        &state,
        "GET",
        "/api/collections",
        &[("cookie", &cookie)],
        "",
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!csp.contains("unsafe-inline"));
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert!(headers
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("no-store"));

    // Cross-site Origin denied on state-changing requests.
    let (status, _, _, _) = call_raw(
        &state,
        "POST",
        "/api/collections",
        &[("cookie", &cookie), ("origin", "https://attacker.example")],
        &json!({"name": "vecs", "dim": 3, "metric": "cosine"}).to_string(),
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Unknown API path returns JSON 404 rather than SPA index.html.
    let (status, _, body, _) = call_raw(
        &state,
        "GET",
        "/api/does-not-exist",
        &[("cookie", &cookie)],
        "",
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not_found");

    // Collection dim & name bounds.
    let (status, _) = call(
        &state,
        "POST",
        "/api/collections",
        &cookie,
        json!({"name": "vecs", "dim": 4097, "metric": "cosine"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &state,
        "POST",
        "/api/collections",
        &cookie,
        json!({"name": "vecs", "dim": 3, "metric": "cosine"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &state,
        "POST",
        "/api/collections/vecs/vectors",
        &cookie,
        json!({"points": [{"id": "p1", "vector": [1.0, 0.0, 0.0]}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Search bounds (k == 0, k > 100, ef > MAX_EF_SEARCH).
    let (status, _) = call(
        &state,
        "POST",
        "/api/collections/vecs/search",
        &cookie,
        json!({"vector": [1.0, 0.0, 0.0], "k": 0}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &state,
        "POST",
        "/api/collections/vecs/search",
        &cookie,
        json!({"vector": [1.0, 0.0, 0.0], "k": 101}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &state,
        "POST",
        "/api/collections/vecs/search",
        &cookie,
        json!({"vector": [1.0, 0.0, 0.0], "k": 5, "ef": 99999}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Table column allowlist & SQLi identifier rejection.
    let (status, _) = call(
        &state,
        "POST",
        "/api/tables",
        &cookie,
        json!({"name": "events", "columns": [{"name": "bad;col", "type": "string"}]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &state,
        "POST",
        "/api/tables",
        &cookie,
        json!({"name": "events", "columns": [{"name": "region", "type": "string"}, {"name": "amount", "type": "number"}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &state,
        "POST",
        "/api/tables/events/rows",
        &cookie,
        json!({"rows": [{"region": "eu", "amount": 42}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Query against undeclared column or injection string fails with 400.
    let (status, _) = call(
        &state,
        "POST",
        "/api/tables/events/query",
        &cookie,
        json!({"where": [{"column": "undeclared", "op": "eq", "value": "x"}]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &state,
        "POST",
        "/api/tables/events/query",
        &cookie,
        json!({"where": [{"column": "region; DROP TABLE users;--", "op": "eq", "value": "eu"}]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Oversized request body (> 1 MiB) hits DefaultBodyLimit (413 Payload Too Large).
    let oversized = format!(r#"{{"rows":[{{"region":"{}"}}]}}"#, "a".repeat(1_200_000));
    let (status, _, _, _) = call_raw(
        &state,
        "POST",
        "/api/tables/events/rows",
        &[("cookie", &cookie)],
        &oversized,
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // 1e39 deserializes into f32::INFINITY in JSON; both upsert and search must reject it.
    let (status, _, _, _) = call_raw(
        &state,
        "POST",
        "/api/collections/vecs/vectors",
        &[("cookie", &cookie)],
        r#"{"points":[{"id":"inf","vector":[1e39,0.0,0.0]}]}"#,
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _, _, _) = call_raw(
        &state,
        "POST",
        "/api/collections/vecs/search",
        &[("cookie", &cookie)],
        r#"{"vector":[1e39,0.0,0.0],"k":1}"#,
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Weak password on user creation returns 400 Bad Request.
    let (status, _) = call(
        &state,
        "POST",
        "/admin/users",
        &cookie,
        json!({"email": "weak@infinity.local", "username": "weakuser", "password": "password1234", "roles": ["user"]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn collection_vector_and_table_row_caps_enforced() {
    let opts: SqliteConnectOptions = "sqlite::memory:".parse().unwrap();
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let config = Config {
        admin_email: "admin@infinity.local".into(),
        admin_password: "Sup3rStrongAdminPass!1".into(),
        max_vectors_per_collection: 2,
        max_rows_per_table: 2,
        ..Config::default()
    };
    store::seed(&db, &config).await.unwrap();
    let state = Arc::new(AppState {
        db,
        config,
        indexes: tokio::sync::RwLock::new(HashMap::new()),
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(0),
    });
    let cookie = login_as(
        &state,
        "cap@infinity.local",
        "capuser",
        &[data_core::rbac::ROLE_ADMIN],
    )
    .await;

    let (status, _) = call(
        &state,
        "POST",
        "/api/collections",
        &cookie,
        json!({"name": "capped", "dim": 2, "metric": "l2"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &state,
        "POST",
        "/api/collections/capped/vectors",
        &cookie,
        json!({"points": [{"id": "v1", "vector": [1.0, 0.0]}, {"id": "v2", "vector": [0.0, 1.0]}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Updating existing point ID stays within cap (2).
    let (status, _) = call(
        &state,
        "POST",
        "/api/collections/capped/vectors",
        &cookie,
        json!({"points": [{"id": "v1", "vector": [0.5, 0.5]}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Adding a 3rd distinct point exceeds cap (2).
    let (status, _) = call(
        &state,
        "POST",
        "/api/collections/capped/vectors",
        &cookie,
        json!({"points": [{"id": "v3", "vector": [0.0, 0.0]}]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = call(
        &state,
        "POST",
        "/api/tables",
        &cookie,
        json!({"name": "capped_tbl", "columns": []}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &state,
        "POST",
        "/api/tables/capped_tbl/rows",
        &cookie,
        json!({"rows": [{"k": 1}, {"k": 2}]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(
        &state,
        "POST",
        "/api/tables/capped_tbl/rows",
        &cookie,
        json!({"rows": [{"k": 3}]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn trusted_proxy_extracts_rightmost_untrusted_xff() {
    let opts: SqliteConnectOptions = "sqlite::memory:".parse().unwrap();
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let config = Config {
        admin_email: "admin@infinity.local".into(),
        admin_password: "Sup3rStrongAdminPass!1".into(),
        global_rate_limit_per_min: 1,
        trusted_proxies: vec!["10.0.0.0/8".into()],
        ..Config::default()
    };
    store::seed(&db, &config).await.unwrap();
    let state = Arc::new(AppState {
        db,
        config,
        indexes: tokio::sync::RwLock::new(HashMap::new()),
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(1),
    });

    await_safe_minute_window().await;
    // Trusted proxy forwards real client IP 198.51.100.5 even when attacker prepends 9.9.9.9.
    let (s1, _, _, _) = call_raw(
        &state,
        "GET",
        "/health",
        &[("x-forwarded-for", "9.9.9.9, 198.51.100.5, 10.1.2.3")],
        "",
        [10, 0, 0, 1],
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    // Changing spoofed leftmost entry to 8.8.8.8 still maps to 198.51.100.5 and hits limit=1.
    let (s2, _, _, _) = call_raw(
        &state,
        "GET",
        "/health",
        &[("x-forwarded-for", "8.8.8.8, 198.51.100.5, 10.1.2.4")],
        "",
        [10, 0, 0, 1],
    )
    .await;
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn csrf_origin_rejects_http_downgrade_when_secure_cookies_enabled() {
    let opts: SqliteConnectOptions = "sqlite::memory:".parse().unwrap();
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let config = Config {
        admin_email: "admin@infinity.local".into(),
        admin_password: "Sup3rStrongAdminPass!1".into(),
        public_url: "https://data.infinity.local".into(),
        ..Config::default()
    };
    assert!(config.secure_cookies());
    store::seed(&db, &config).await.unwrap();
    let state = Arc::new(AppState {
        db,
        config,
        indexes: tokio::sync::RwLock::new(HashMap::new()),
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(0),
    });
    let cookie = login_as(
        &state,
        "tls@infinity.local",
        "tlsuser",
        &[data_core::rbac::ROLE_ADMIN],
    )
    .await;

    // HTTP Origin matching Host must be rejected when secure_cookies() is true.
    let (status, _, _, _) = call_raw(
        &state,
        "POST",
        "/api/collections",
        &[
            ("cookie", &cookie),
            ("host", "proxy.infinity.local"),
            ("origin", "http://proxy.infinity.local"),
        ],
        &json!({"name": "downgraded", "dim": 2, "metric": "cosine"}).to_string(),
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // HTTPS Origin matching Host succeeds.
    let (status, _, _, _) = call_raw(
        &state,
        "POST",
        "/api/collections",
        &[
            ("cookie", &cookie),
            ("host", "proxy.infinity.local"),
            ("origin", "https://proxy.infinity.local"),
        ],
        &json!({"name": "upgraded", "dim": 2, "metric": "cosine"}).to_string(),
        [127, 0, 0, 1],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn concurrent_table_row_inserts_cannot_exceed_max_rows_per_table() {
    let db_path = std::env::temp_dir().join(format!(
        "infinity_data_concurrent_{}.db",
        uuid::Uuid::new_v4()
    ));
    let opts = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));
    let db = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();
    let config = Config {
        admin_email: "admin@infinity.local".into(),
        admin_password: "Sup3rStrongAdminPass!1".into(),
        max_rows_per_table: 3,
        ..Config::default()
    };
    store::seed(&db, &config).await.unwrap();
    let state = Arc::new(AppState {
        db,
        config,
        indexes: tokio::sync::RwLock::new(HashMap::new()),
        login_throttle: LoginThrottle::default(),
        ip_limiter: IpRateLimiter::new(0),
    });
    let cookie = login_as(
        &state,
        "race@infinity.local",
        "raceuser",
        &[data_core::rbac::ROLE_ADMIN],
    )
    .await;

    let (status, _) = call(
        &state,
        "POST",
        "/api/tables",
        &cookie,
        json!({"name": "concurrent_tbl", "columns": []}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mut handles = Vec::new();
    for i in 0..5 {
        let st = state.clone();
        let ck = cookie.clone();
        handles.push(tokio::spawn(async move {
            call(
                &st,
                "POST",
                "/api/tables/concurrent_tbl/rows",
                &ck,
                json!({"rows": [{"seq": i}]}),
            )
            .await
            .0
        }));
    }

    let mut ok_count = 0usize;
    let mut rejected_count = 0usize;
    for h in handles {
        match h.await.unwrap() {
            StatusCode::OK => ok_count += 1,
            StatusCode::BAD_REQUEST => rejected_count += 1,
            other => panic!("unexpected concurrent status: {other}"),
        }
    }
    assert_eq!(ok_count, 3);
    assert_eq!(rejected_count, 2);
    assert_eq!(
        store::table_count(&state.db, "concurrent_tbl")
            .await
            .unwrap(),
        3
    );

    state.db.close().await;
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
    let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
}
