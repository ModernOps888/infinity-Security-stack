pub mod alerts;
pub mod auth_routes;
pub mod ingest;
pub mod keys;
pub mod query;

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use url::Url;

use crate::auth::SESSION_COOKIE;
use crate::config::Config;
use crate::error::ApiError;
use crate::routes::auth_routes::ClientIp;
use crate::state::SharedState;
use crate::util::extract_client_ip;

async fn rate_limit(State(st): State<SharedState>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let client_ip = extract_client_ip(req.headers(), peer, &st.config.trusted_proxies);
    if !st.ip_limiter.allow(&client_ip) {
        return ApiError::TooManyRequests("global rate limit exceeded".into()).into_response();
    }
    req.extensions_mut().insert(ClientIp(client_ip));
    next.run(req).await
}

fn has_session_cookie(req: &Request) -> bool {
    let Some(raw) = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    raw.split(';').any(|kv| {
        kv.trim()
            .split_once('=')
            .map(|(k, _)| k == SESSION_COOKIE)
            .unwrap_or(false)
    })
}

fn origin_matches_url(origin: &str, allowed: &str) -> bool {
    let (Ok(o), Ok(a)) = (Url::parse(origin), Url::parse(allowed)) else {
        return false;
    };
    o.scheme().eq_ignore_ascii_case(a.scheme())
        && o.host_str()
            .zip(a.host_str())
            .map(|(oh, ah)| oh.eq_ignore_ascii_case(ah))
            .unwrap_or(false)
        && o.port_or_known_default() == a.port_or_known_default()
}

fn is_allowed_origin(origin: &str, cfg: &Config) -> bool {
    origin_matches_url(origin, &cfg.public_url)
        || cfg
            .cors_origins
            .iter()
            .any(|c| origin_matches_url(origin, c))
}

async fn security_guard(State(st): State<SharedState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let is_state_changing = matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    let is_ingest_path = matches!(path.as_str(), "/v1/logs" | "/v1/metrics" | "/v1/traces");

    if is_state_changing && !is_ingest_path && has_session_cookie(&req) {
        if let Some(sec_fetch) = req
            .headers()
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
        {
            if !sec_fetch.eq_ignore_ascii_case("same-origin")
                && !sec_fetch.eq_ignore_ascii_case("none")
            {
                return ApiError::Forbidden("cross-site request blocked".into()).into_response();
            }
        }
        if let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            if !is_allowed_origin(origin, &st.config) {
                return ApiError::Forbidden("origin not permitted".into()).into_response();
            }
        }
    }

    let mut resp = next.run(req).await;
    if path.starts_with("/auth/") || path.starts_with("/v1/") {
        resp.headers_mut()
            .entry(header::CACHE_CONTROL)
            .or_insert_with(|| HeaderValue::from_static("no-store"));
    }
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
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("x-requested-with"),
        ])
        .allow_credentials(true)
}

pub fn router(state: SharedState) -> Router {
    let cors = build_cors(&state.config);
    let max_body = state.config.max_request_body_bytes;
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/me", get(auth_routes::me))
        .route("/v1/logs", post(ingest::logs).get(query::logs))
        .route("/v1/metrics", post(ingest::metrics))
        .route("/v1/metrics/names", get(query::metric_names))
        .route("/v1/metrics/series", get(query::metric_series))
        .route("/v1/metrics/summary", get(query::metric_summary))
        .route("/v1/traces", post(ingest::traces).get(query::traces))
        .route("/v1/traces/:trace_id", get(query::trace_by_id))
        .route(
            "/v1/alerts/rules",
            get(alerts::rules).post(alerts::create_rule),
        )
        .route("/v1/alerts/rules/:id", delete(alerts::delete_rule))
        .route("/v1/alerts", get(alerts::list_alerts))
        .route("/v1/keys", get(keys::list).post(keys::create))
        .route("/v1/keys/:id", delete(keys::revoke))
        .route("/v1/stats", get(query::stats))
        .fallback(crate::assets::handler)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_guard,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(cors)
        .layer(DefaultBodyLimit::max(max_body))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; \
                 img-src 'self' data:; connect-src 'self'; object-src 'none'; \
                 frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
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
    axum::Json(serde_json::json!({ "status": "ok", "service": "infinity-observe" }))
}
