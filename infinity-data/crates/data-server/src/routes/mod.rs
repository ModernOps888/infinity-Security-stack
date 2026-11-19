pub mod admin;
pub mod audit;
pub mod auth_routes;
pub mod collections;
pub mod tables;

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;

pub use data_core::security::valid_name;

use crate::config::Config;
use crate::error::ApiError;
use crate::state::SharedState;
use crate::util;

async fn rate_limit(
    State(st): State<SharedState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let proxies = util::parse_trusted_proxies(&st.config.trusted_proxies);
    let client_ip = util::extract_client_ip(req.headers(), peer.map(|c| c.0), &proxies);
    if !st.ip_limiter.allow(&client_ip) {
        return ApiError::TooManyRequests("global rate limit exceeded".into()).into_response();
    }
    next.run(req).await
}

fn origin_matches_allowed(origin: &str, config: &Config, host_header: Option<&str>) -> bool {
    if origin.eq_ignore_ascii_case("null") {
        return false;
    }
    let normalized = origin.trim_end_matches('/');
    if normalized == config.public_url.trim_end_matches('/') {
        return true;
    }
    if config
        .cors_origins
        .iter()
        .any(|allowed| allowed.trim_end_matches('/') == normalized)
    {
        return true;
    }
    if let Some(host) = host_header {
        let rest = if config.secure_cookies() {
            normalized.strip_prefix("https://")
        } else {
            normalized
                .strip_prefix("https://")
                .or_else(|| normalized.strip_prefix("http://"))
        };
        if let Some(rest) = rest {
            return rest.eq_ignore_ascii_case(host);
        }
    }
    false
}

async fn csrf_origin_guard(
    State(st): State<SharedState>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let method = req.method();
    let is_safe = matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS);
    if !is_safe {
        if let Some(origin_hdr) = req.headers().get(header::ORIGIN) {
            let Ok(origin) = origin_hdr.to_str() else {
                return ApiError::Forbidden("invalid origin header".into()).into_response();
            };
            let host = req
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok());
            if !origin_matches_allowed(origin, &st.config, host) {
                return ApiError::Forbidden("cross-origin request denied".into()).into_response();
            }
        }
    }
    next.run(req).await
}

async fn cache_control_api(
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();
    let mut resp = next.run(req).await;
    if path.starts_with("/auth") || path.starts_with("/api") || path.starts_with("/admin") {
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        );
        resp.headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
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
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true)
}

pub fn router(state: SharedState) -> Router {
    let cors = build_cors(&state.config);
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/me", get(auth_routes::me))
        .route("/api/stats", get(collections::stats))
        .route(
            "/api/collections",
            get(collections::list).post(collections::create),
        )
        .route(
            "/api/collections/:name",
            get(collections::get_one).delete(collections::delete_one),
        )
        .route(
            "/api/collections/:name/vectors",
            post(collections::upsert_vectors),
        )
        .route("/api/collections/:name/search", post(collections::search))
        .route("/api/tables", get(tables::list).post(tables::create))
        .route(
            "/api/tables/:name",
            get(tables::get_one).delete(tables::delete_one),
        )
        .route("/api/tables/:name/rows", post(tables::insert_rows))
        .route("/api/tables/:name/query", post(tables::query))
        .route(
            "/admin/users",
            get(admin::list_users).post(admin::create_user),
        )
        .route(
            "/admin/users/:id",
            patch(admin::update_user).delete(admin::delete_user),
        )
        .route(
            "/admin/roles",
            get(admin::list_roles).put(admin::upsert_role),
        )
        .route(
            "/admin/api-keys",
            get(admin::list_api_keys).post(admin::create_api_key),
        )
        .route("/admin/api-keys/:id", delete(admin::delete_api_key))
        .route("/admin/audit", get(audit::list))
        .fallback(crate::assets::handler)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(cache_control_api))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            csrf_origin_guard,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(cors)
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
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

async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "service": "infinity-data" })),
    )
}
