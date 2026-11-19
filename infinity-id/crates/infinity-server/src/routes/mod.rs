//! HTTP route table assembly.

pub mod audit;
pub mod auth_routes;
pub mod clients;
pub mod keys;
pub mod mfa;
pub mod oidc;
pub mod roles;
pub mod users;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::config::Config;
use crate::state::SharedState;
use crate::util::{parse_trusted_proxies, resolve_client_ip};

/// Per-IP rate-limiting middleware applied to all routes, respecting the
/// configured trusted-proxy boundary when resolving `X-Forwarded-For`.
async fn rate_limit(
    axum::extract::State(st): axum::extract::State<SharedState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(peer) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip())
    {
        let trusted = parse_trusted_proxies(&st.config.trusted_proxies);
        let client_ip = resolve_client_ip(peer, req.headers(), &trusted);
        if !st.ip_limiter.allow(&client_ip.to_string()) {
            return crate::error::ApiError::TooManyRequests("global rate limit exceeded".into())
                .into_response();
        }
    }
    next.run(req).await
}

/// Enforce `Cache-Control: no-store` and `Pragma: no-cache` on sensitive
/// token/session/admin endpoints (RFC 6749 §5.1), including error responses.
async fn cache_no_store(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

pub fn build_cors(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .cors_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("x-csrf-token"),
        ])
        .allow_credentials(true)
}

/// Build the full application router with complete security middleware stack.
pub fn router(state: SharedState) -> Router {
    let sensitive_api = Router::new()
        .route("/oauth/authorize", get(oidc::authorize))
        .route("/oauth/token", post(oidc::token))
        .route("/userinfo", get(oidc::userinfo))
        // Dashboard session auth
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/me", get(auth_routes::me))
        // MFA (self-service)
        .route("/mfa/enroll", post(mfa::enroll))
        .route("/mfa/activate", post(mfa::activate))
        .route("/mfa/disable", post(mfa::disable))
        // Admin: users
        .route("/admin/users", get(users::list).post(users::create))
        .route(
            "/admin/users/:id",
            patch(users::update).delete(users::delete),
        )
        // Admin: clients
        .route("/admin/clients", get(clients::list).post(clients::create))
        .route("/admin/clients/:client_id", delete(clients::delete))
        // Admin: roles
        .route("/admin/roles", get(roles::list))
        .route("/admin/roles", put(roles::upsert))
        // Admin: signing-key rotation
        .route("/admin/keys/rotate", post(keys::rotate))
        // Admin: audit
        .route("/admin/audit", get(audit::list))
        .layer(axum::middleware::from_fn(cache_no_store));

    let public_api = Router::new()
        .route("/health", get(health))
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/.well-known/jwks.json", get(oidc::jwks));

    let cors = build_cors(&state.config);

    Router::new()
        .merge(public_api)
        .merge(sensitive_api)
        .fallback(crate::assets::handler)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit,
        ))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; style-src 'self'; \
                 img-src 'self'; connect-src 'self'; frame-ancestors 'none'; \
                 base-uri 'self'; form-action 'self'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .with_state(state)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok", "service": "infinity-id" }))
}
