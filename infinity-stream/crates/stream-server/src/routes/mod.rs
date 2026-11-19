pub mod auth_routes;
pub mod keys;
pub mod search;
pub mod stats;
pub mod topics;

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, Method};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;

use crate::auth::{extract_cookie, SESSION_COOKIE};
use crate::config::{canonical_ip, CidrRule};
use crate::error::ApiError;
use crate::state::SharedState;

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/me", get(auth_routes::me))
        .route("/v1/topics", get(topics::list).post(topics::create))
        .route("/v1/topics/:name", delete(topics::delete_topic))
        .route("/v1/topics/:name/produce", post(topics::produce))
        .route("/v1/topics/:name/consume", get(topics::consume))
        .route("/v1/topics/:name/commit", post(topics::commit))
        .route("/v1/topics/:name/offset", get(topics::offset))
        .route("/v1/topics/:name/subscribe", get(topics::subscribe))
        .route("/v1/consumers", get(topics::consumers))
        .route("/v1/indexes", get(search::list).post(search::create))
        .route("/v1/indexes/:name", delete(search::delete_index))
        .route("/v1/indexes/:name/docs", post(search::upsert_docs))
        .route("/v1/indexes/:name/search", get(search::query))
        .route("/v1/keys", get(keys::list).post(keys::create))
        .route("/v1/keys/:id", delete(keys::delete_key))
        .route("/v1/stats", get(stats::stats))
        .fallback(crate::assets::handler)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            csrf_and_origin_guard,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit,
        ))
        .with_state(state)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"status":"ok","service":"infinity-stream"}))
}

/// Resolves client IP respecting a strict proxy trust boundary:
/// `X-Forwarded-For` is IGNORED unless the direct TCP peer matches `trusted_proxies`.
/// Walks right-to-left across hops, stopping immediately on any unparseable hop.
pub fn resolve_client_ip(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted: &[CidrRule],
) -> String {
    let Some(raw_peer) = peer else {
        return "unknown".into();
    };
    let peer_ip = canonical_ip(raw_peer);
    if !trusted.iter().any(|r| r.matches(peer_ip)) {
        return peer_ip.to_string();
    }
    let xff_headers: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    for header_val in xff_headers.into_iter().rev() {
        for hop in header_val.split(',').rev().map(str::trim) {
            let Ok(parsed) = hop.parse::<IpAddr>() else {
                // Stop immediately on malformed hops instead of trusting anything further left.
                return peer_ip.to_string();
            };
            let ip = canonical_ip(parsed);
            if !trusted.iter().any(|r| r.matches(ip)) {
                return ip.to_string();
            }
        }
    }
    peer_ip.to_string()
}

async fn rate_limit(
    axum::extract::State(st): axum::extract::State<SharedState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    let trusted = st.config.parsed_trusted_proxies();
    let client_ip = resolve_client_ip(peer, req.headers(), &trusted);
    if !st.ip_limiter.allow(&client_ip) {
        return ApiError::TooManyRequests("global rate limit exceeded".into()).into_response();
    }
    next.run(req).await
}

async fn csrf_and_origin_guard(
    axum::extract::State(st): axum::extract::State<SharedState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_mutation = matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    if is_mutation {
        let headers = req.headers();
        let has_bearer = headers.contains_key(header::AUTHORIZATION);
        let has_cookie = extract_cookie(headers, SESSION_COOKIE).is_some();

        // Check explicit Origin on any state-changing browser request (also defends /auth/login against Login CSRF).
        if let Some(origin_hdr) = headers.get(header::ORIGIN) {
            let allowed = origin_hdr
                .to_str()
                .ok()
                .is_some_and(|o| st.config.is_allowed_origin(o));
            if !allowed {
                return ApiError::Forbidden("origin not allowed".into()).into_response();
            }
        } else if !has_bearer && has_cookie {
            if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
                if sfs != "same-origin" && sfs != "none" {
                    return ApiError::Forbidden("cross-site cookie request rejected".into())
                        .into_response();
                }
            }
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn resolve_client_ip_canonicalizes_mapped_v6_and_stops_on_malformed_hop() {
        let trusted = vec![CidrRule::parse("10.0.0.0/8").unwrap()];
        let mapped_peer: IpAddr = "::ffff:10.0.0.5".parse().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.7, not_an_ip, 10.0.0.9"),
        );
        // Stops at malformed hop and falls back to canonicalized trusted peer IP, never trusting 198.51.100.7.
        assert_eq!(
            resolve_client_ip(Some(mapped_peer), &headers, &trusted),
            "10.0.0.5"
        );

        // Valid mapped IPv4 hop canonicalizes cleanly.
        let mut clean_headers = HeaderMap::new();
        clean_headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("::ffff:203.0.113.42, ::ffff:10.0.0.9"),
        );
        assert_eq!(
            resolve_client_ip(Some(mapped_peer), &clean_headers, &trusted),
            "203.0.113.42"
        );
    }
}
