//! Infinity Stream — streaming commit log + BM25 search + WebSocket fan-out.
//!
//! Exposed as a library (in addition to the `infinity-stream` binary in
//! `main.rs`) so integration tests in `tests/` can drive the real axum
//! `Router` and `AppState` in-process instead of mocking route handlers.

pub mod assets;
pub mod auth;
pub mod config;
pub mod error;
pub mod ratelimit;
pub mod routes;
pub mod state;
pub mod store;
pub mod throttle;
pub mod util;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::state::SharedState;

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
            HeaderName::from_static("x-requested-with"),
        ])
        .allow_credentials(true)
}

/// Builds the full production Axum `Router` with body-size limits, CORS,
/// hardened security response headers, CSRF/Origin validation, rate limiting,
/// and tracing attached.
pub fn app(state: SharedState) -> Router {
    let cors = build_cors(&state.config);
    let body_limit = state.config.max_json_body_bytes;
    routes::router(state)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; \
                 img-src 'self' data:; connect-src 'self' ws: wss:; \
                 object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
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
        .layer(TraceLayer::new_for_http())
}
