//! Infinity Edge — an auth-aware reverse proxy / API gateway.
//!
//! Validates Infinity ID access tokens (via JWKS), enforces per-route scopes,
//! applies per-IP rate limiting, then forwards to configured upstreams.

mod config;
mod jwks;
mod ratelimit;

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::{is_blocked_ssrf_ip, EdgeConfig, RouteConfig};
use crate::jwks::JwksCache;
use crate::ratelimit::RateLimiter;

struct EdgeState {
    config: EdgeConfig,
    jwks: JwksCache,
    limiter: RateLimiter,
    http: reqwest::Client,
    trusted_proxies: Vec<IpNet>,
}

type Shared = Arc<EdgeState>;

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn canonical_ip_net(net: IpNet) -> IpNet {
    match net {
        IpNet::V6(v6net) if v6net.prefix_len() >= 96 => {
            if let Some(v4) = v6net.network().to_ipv4_mapped() {
                if let Ok(v4net) = ipnet::Ipv4Net::new(v4, v6net.prefix_len() - 96) {
                    return IpNet::V4(v4net.trunc());
                }
            }
            IpNet::V6(v6net)
        }
        other => other,
    }
}

fn is_trusted_proxy(ip: IpAddr, trusted: &[IpNet]) -> bool {
    let canon = canonical_ip(ip);
    trusted
        .iter()
        .any(|net| net.contains(&canon) || net.contains(&ip))
}

fn parse_trusted_proxies(entries: &[String]) -> Vec<IpNet> {
    entries
        .iter()
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            trimmed
                .parse::<IpNet>()
                .ok()
                .map(canonical_ip_net)
                .or_else(|| {
                    trimmed
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| IpNet::from(canonical_ip(ip)))
                })
        })
        .collect()
}

fn resolve_client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer = canonical_ip(peer);
    if trusted.is_empty() || !is_trusted_proxy(peer, trusted) {
        return peer;
    }
    for hv in headers.get_all("x-forwarded-for").iter().rev() {
        let Ok(xff) = hv.to_str() else {
            return peer;
        };
        for part in xff.rsplit(',') {
            let candidate = part.trim();
            let Ok(parsed) = candidate.parse::<IpAddr>() else {
                return peer;
            };
            let ip = canonical_ip(parsed);
            if !is_trusted_proxy(ip, trusted) {
                return ip;
            }
        }
    }
    peer
}

fn healthcheck_target(bind: &str) -> String {
    if let Ok(addr) = bind.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() {
            return format!("127.0.0.1:{}", addr.port());
        }
        return addr.to_string();
    }
    bind.to_string()
}

fn run_healthcheck(bind: &str) -> bool {
    let target = healthcheck_target(bind);
    let Ok(addr) = target.parse::<SocketAddr>() else {
        return TcpStream::connect(&target).is_ok();
    };
    TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
}

fn build_http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()?)
}

fn edge_router(state: Shared) -> Router {
    let max_body = state.config.max_body_bytes;
    Router::new()
        .fallback(proxy)
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = EdgeConfig::load().context("loading edge config")?;
    if std::env::args().nth(1).as_deref() == Some("--healthcheck") {
        std::process::exit(if run_healthcheck(&config.bind) { 0 } else { 1 });
    }

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!(jwks = %config.jwks_url, "fetching signing keys");
    let jwks = JwksCache::fetch(&config.jwks_url, &config.issuer)
        .await
        .context("fetching JWKS — is Infinity ID running?")?;

    let limiter = RateLimiter::new(config.rate_limit_per_min);
    let trusted_proxies = parse_trusted_proxies(&config.trusted_proxies);
    let bind = config.bind.clone();
    let state = Arc::new(EdgeState {
        config,
        jwks,
        limiter,
        http: build_http_client()?,
        trusted_proxies,
    });

    let app = edge_router(state);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(%bind, "Infinity Edge listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Normalize and validate an incoming request path to prevent path-traversal
/// bypasses (`/api/public/../private`, `%2e%2e`, backslashes, or `//` confusion).
fn normalize_request_path(raw_path: &str) -> Option<String> {
    if !raw_path.starts_with('/') || raw_path.starts_with("//") {
        return None;
    }
    if raw_path.contains('\\') || raw_path.chars().any(|c| c.is_control()) {
        return None;
    }
    let decoded = percent_decode_str(raw_path).decode_utf8().ok()?;
    if decoded.contains('\\') || decoded.contains('\0') || decoded.chars().any(|c| c.is_control()) {
        return None;
    }
    // Reject encoded path separators (%2f / %2F) that create proxy/upstream split.
    let lower = raw_path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return None;
    }
    let mut segments = Vec::new();
    for seg in decoded.split('/') {
        if seg == "." || seg == ".." {
            return None;
        }
        if !seg.is_empty() {
            segments.push(seg);
        }
    }
    // Also reject raw percent-encoded dots if any segment resolved from them.
    if segments.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", segments.join("/")))
    }
}

/// Match longest route prefix on segment boundaries (e.g. `/api/public` matches
/// `/api/public` and `/api/public/foo`, NEVER `/api/public_admin`).
fn match_route<'a>(cfg: &'a EdgeConfig, norm_path: &str) -> Option<&'a RouteConfig> {
    cfg.routes
        .iter()
        .filter(|r| {
            let p = r.prefix.trim_end_matches('/');
            if p.is_empty() {
                true
            } else {
                norm_path == p
                    || norm_path
                        .strip_prefix(p)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
        })
        .max_by_key(|r| r.prefix.len())
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
}

async fn proxy(State(st): State<Shared>, req: Request) -> Response {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));
    let client_ip = resolve_client_ip(peer_ip, req.headers(), &st.trusted_proxies);
    if !st.limiter.allow(&client_ip.to_string()) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }

    let raw_path = req.uri().path().to_string();
    let Some(norm_path) = normalize_request_path(&raw_path) else {
        return err(StatusCode::BAD_REQUEST, "invalid request path");
    };
    let route = match match_route(&st.config, &norm_path) {
        Some(r) => r.clone(),
        None => return err(StatusCode::NOT_FOUND, "no route configured for this path"),
    };

    // Authentication / authorization.
    let mut subject: Option<String> = None;
    if route.require_auth {
        let token = bearer(req.headers());
        let claims = match token {
            Some(t) => st.jwks.validate(&t, route.audience.as_deref()).await,
            None => None,
        };
        let Some(claims) = claims else {
            return err(StatusCode::UNAUTHORIZED, "missing or invalid access token");
        };
        // Scopes and roles are checked against separate requirements so a
        // user's roles can never satisfy a scope-gated route.
        if let Some(required) = &route.required_scope {
            if !claims.scope.split_whitespace().any(|s| s == required) {
                return err(StatusCode::FORBIDDEN, "token lacks required scope");
            }
        }
        if let Some(required) = &route.required_role {
            if !claims.roles.iter().any(|r| r == required) {
                return err(StatusCode::FORBIDDEN, "token lacks required role");
            }
        }
        subject = Some(claims.sub);
    }

    forward(&st, &route, req, &norm_path, client_ip, subject).await
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
];

fn is_forged_identity_or_proxy_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("x-infinity-")
        || lower.starts_with("x-auth-")
        || lower.starts_with("x-remote-")
        || lower.starts_with("x-forwarded-")
        || matches!(
            lower.as_str(),
            "x-real-ip"
                | "forwarded"
                | "forwarded-user"
                | "remote-user"
                | "remote-groups"
                | "remote-email"
                | "x-user"
                | "x-user-id"
                | "x-user-roles"
                | "x-email"
        )
}

fn strip_hop_by_hop_and_forged(headers: &mut HeaderMap) {
    // Collect any header names listed inside `Connection` / `Proxy-Connection`.
    let mut dynamic_hop: Vec<HeaderName> = Vec::new();
    for hdr_name in ["connection", "proxy-connection"] {
        for val in headers.get_all(hdr_name) {
            if let Ok(s) = val.to_str() {
                for tok in s.split(',') {
                    if let Ok(name) = HeaderName::from_bytes(tok.trim().as_bytes()) {
                        dynamic_hop.push(name);
                    }
                }
            }
        }
    }
    for name in dynamic_hop {
        headers.remove(&name);
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
    let to_remove: Vec<HeaderName> = headers
        .keys()
        .filter(|k| is_forged_identity_or_proxy_header(k.as_str()))
        .cloned()
        .collect();
    for k in to_remove {
        headers.remove(&k);
    }
}

fn strip_response_hop_by_hop(headers: &mut HeaderMap) {
    let mut dynamic_hop: Vec<HeaderName> = Vec::new();
    for val in headers.get_all(header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for tok in s.split(',') {
                if let Ok(name) = HeaderName::from_bytes(tok.trim().as_bytes()) {
                    dynamic_hop.push(name);
                }
            }
        }
    }
    for name in dynamic_hop {
        headers.remove(&name);
    }
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
    headers.remove(header::CONTENT_LENGTH);
}

fn build_upstream_url(
    upstream: &str,
    req_path: &str,
    query: Option<&str>,
) -> anyhow::Result<url::Url> {
    let base = crate::config::validate_http_target_url(upstream, true)?;
    let mut target = base.clone();
    let base_path = base.path().trim_end_matches('/');
    let joined_path = if base_path.is_empty() || base_path == "/" {
        req_path.to_string()
    } else {
        format!("{base_path}{req_path}")
    };
    target.set_path(&joined_path);
    target.set_query(query);
    if target.scheme() != base.scheme()
        || target.host_str() != base.host_str()
        || target.port_or_known_default() != base.port_or_known_default()
        || !target.username().is_empty()
        || target.password().is_some()
    {
        anyhow::bail!("upstream URL authority mismatch");
    }
    if let Some(host) = target.host_str() {
        let host_clean = host.trim_matches(['[', ']']);
        if let Ok(ip) = host_clean.parse::<IpAddr>() {
            if is_blocked_ssrf_ip(ip) {
                anyhow::bail!("blocked SSRF destination");
            }
        }
    }
    Ok(target)
}

async fn forward(
    st: &Shared,
    route: &RouteConfig,
    req: Request,
    norm_path: &str,
    client_ip: IpAddr,
    subject: Option<String>,
) -> Response {
    let method = req.method().clone();
    let query = req.uri().query().map(str::to_string);
    if query
        .as_deref()
        .is_some_and(|q| q.chars().any(|c| c.is_control()))
    {
        return err(StatusCode::BAD_REQUEST, "invalid query string");
    }

    let mut headers = req.headers().clone();
    headers.remove(header::HOST);
    strip_hop_by_hop_and_forged(&mut headers);
    if let Ok(ip_val) = HeaderValue::from_str(&client_ip.to_string()) {
        headers.insert("x-forwarded-for", ip_val.clone());
        headers.insert("x-real-ip", ip_val);
    }
    if let Some(sub) = subject {
        if let Ok(v) = HeaderValue::from_str(&sub) {
            headers.insert("x-infinity-sub", v);
        }
    }

    let max_body = st.config.max_body_bytes;
    let body_bytes = match axum::body::to_bytes(req.into_body(), max_body).await {
        Ok(b) => b,
        Err(_) => {
            return err(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds size limit",
            )
        }
    };

    let target = match build_upstream_url(&route.upstream, norm_path, query.as_deref()) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "blocked invalid upstream URL");
            return err(StatusCode::BAD_GATEWAY, "invalid upstream configuration");
        }
    };

    let mut builder = st.http.request(method, target).headers(headers);
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes);
    }
    let upstream = match builder.send().await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "upstream error");
            return err(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    if upstream
        .content_length()
        .is_some_and(|len| len > max_body as u64)
    {
        return err(
            StatusCode::BAD_GATEWAY,
            "upstream response exceeds size limit",
        );
    }

    let status = upstream.status();
    let mut resp_headers = upstream.headers().clone();
    strip_response_hop_by_hop(&mut resp_headers);
    let bytes = match upstream.bytes().await {
        Ok(b) if b.len() <= max_body => b,
        Ok(_) => {
            return err(
                StatusCode::BAD_GATEWAY,
                "upstream response exceeds size limit",
            )
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream body read error");
            return err(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = resp_headers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwks::JwkEntry;
    use axum::routing::any;
    use http_body_util::BodyExt;
    use infinity_core::keys::KeyRing;
    use infinity_core::token::{issue, Claims};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    async fn spawn_echo_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(any(|req: Request| async move {
            let mut hdrs = serde_json::Map::new();
            for (k, v) in req.headers() {
                hdrs.insert(
                    k.as_str().to_string(),
                    serde_json::Value::String(v.to_str().unwrap_or("").to_string()),
                );
            }
            let body = serde_json::json!({
                "path": req.uri().path_and_query().map(|p| p.as_str()).unwrap_or(""),
                "headers": hdrs,
            });
            axum::Json(body)
        }));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, handle)
    }

    fn make_edge_state(
        upstream: String,
        keys: Vec<JwkEntry>,
        trusted_proxies: Vec<String>,
        max_body_bytes: usize,
    ) -> Shared {
        let config = EdgeConfig {
            bind: "127.0.0.1:0".into(),
            issuer: "https://id.example.com".into(),
            jwks_url: "https://id.example.com/.well-known/jwks.json".into(),
            rate_limit_per_min: 0,
            max_body_bytes,
            trusted_proxies: trusted_proxies.clone(),
            routes: vec![
                RouteConfig {
                    prefix: "/api/public".into(),
                    upstream: upstream.clone(),
                    require_auth: false,
                    required_scope: None,
                    required_role: None,
                    audience: None,
                },
                RouteConfig {
                    prefix: "/api".into(),
                    upstream,
                    require_auth: true,
                    required_scope: Some("api:read".into()),
                    required_role: None,
                    audience: Some("api.example.com".into()),
                },
            ],
        };
        config.validate().unwrap();
        Arc::new(EdgeState {
            config,
            jwks: JwksCache::from_entries_for_test(keys, "https://id.example.com"),
            limiter: RateLimiter::new(0),
            http: build_http_client().unwrap(),
            trusted_proxies: parse_trusted_proxies(&trusted_proxies),
        })
    }

    fn sign_test_token(
        ring: &KeyRing,
        typ: &str,
        aud: &str,
        scope: &str,
        roles: Vec<String>,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = Claims {
            sub: "user-42".into(),
            iss: "https://id.example.com".into(),
            aud: aud.into(),
            exp: now + 300,
            iat: now,
            nbf: now,
            scope: scope.into(),
            roles,
            preferred_username: Some("alice".into()),
            typ: typ.into(),
        };
        issue(&ring.active, &claims).unwrap()
    }

    #[test]
    fn rejects_ssrf_urls_and_path_traversals() {
        assert!(crate::config::validate_http_target_url(
            "http://169.254.169.254/latest/meta-data",
            false
        )
        .is_err());
        assert!(
            crate::config::validate_http_target_url("http://metadata.google.internal/", false)
                .is_err()
        );
        assert!(crate::config::validate_http_target_url("file:///etc/passwd", false).is_err());
        assert!(
            crate::config::validate_http_target_url("https://user:pass@127.0.0.1:8080", true)
                .is_err()
        );
        assert!(crate::config::validate_http_target_url("http://127.0.0.1:8081", true).is_ok());

        assert_eq!(normalize_request_path("/api/public/../admin"), None);
        assert_eq!(normalize_request_path("/api/public/%2e%2e/admin"), None);
        assert_eq!(normalize_request_path("/api/public/%2fadmin"), None);
        assert_eq!(normalize_request_path("//evil.com/api"), None);
        assert_eq!(normalize_request_path("/api/public\\..\\admin"), None);
        assert_eq!(
            normalize_request_path("/api/public/items"),
            Some("/api/public/items".into())
        );
        assert!(crate::config::validate_http_target_url(
            "http://[::ffff:169.254.169.254]/latest/meta-data",
            false,
        )
        .is_err());
        assert!(
            crate::config::validate_http_target_url("http://[::ffff:0.0.0.0]/", false).is_err()
        );
        assert!(
            crate::config::validate_http_target_url("http://[::169.254.169.254]/", false).is_err()
        );
        assert!(
            crate::config::validate_http_target_url("http://[::ffff:224.0.0.1]/", false).is_err()
        );
        assert!(
            crate::config::validate_http_target_url("http://[::ffff:127.0.0.1]:8080", false)
                .is_ok()
        );
        assert!(crate::config::validate_http_target_url("http://[::1]:8080", false).is_ok());
    }

    #[tokio::test]
    async fn edge_strips_forged_headers_enforces_xff_prefix_auth_rotation_and_body_cap() {
        let (upstream_addr, _handle) = spawn_echo_upstream().await;
        let upstream = format!("http://{upstream_addr}");

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key_dir = std::env::temp_dir().join(format!(
            "infinity-edge-test-{}-{}",
            std::process::id(),
            nanos
        ));
        let key_path = key_dir.join("signing_key.pem");
        let mut ring = KeyRing::load_or_generate(&key_path, 3600).unwrap();
        let tok_old = sign_test_token(
            &ring,
            "access",
            "api.example.com",
            "api:read",
            vec!["user".into()],
        );
        ring.rotate(&key_path, 3600).unwrap();
        let tok_new = sign_test_token(
            &ring,
            "access",
            "api.example.com",
            "api:read",
            vec!["user".into()],
        );
        let id_tok = sign_test_token(
            &ring,
            "id",
            "api.example.com",
            "api:read",
            vec!["user".into()],
        );

        let entries = ring
            .jwks()
            .keys
            .into_iter()
            .map(|k| JwkEntry {
                kid: k.kid,
                n: k.n,
                e: k.e,
            })
            .collect();

        let state = make_edge_state(upstream, entries, vec!["10.0.0.0/8".into()], 4096);
        let app = edge_router(state);

        // 1) Prefix boundary: `/api/public_secret` MUST NOT match `/api/public` unauthenticated!
        let mut req = Request::builder()
            .uri("/api/public_secret")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 1234))));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 2) Path traversal attempt rejected with 400.
        let mut req = Request::builder()
            .uri("/api/public/../secret")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 1234))));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 3) ID token rejected even with valid signature.
        let mut req = Request::builder()
            .uri("/api/orders")
            .header(header::AUTHORIZATION, format!("Bearer {id_tok}"))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 1234))));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // 4) Forged identity headers + spoofed XFF stripped; verified X-Infinity-Sub set;
        // both retired `tok_old` and active `tok_new` succeed across JWKS rotation.
        for tok in [&tok_old, &tok_new] {
            let mut req = Request::builder()
                .uri("/api/orders")
                .header(header::AUTHORIZATION, format!("Bearer {tok}"))
                .header("x-infinity-sub", "spoofed-admin")
                .header("x-infinity-roles", "superadmin")
                .header("x-forwarded-user", "spoofed")
                .header("x-auth-user", "spoofed")
                .header("x-forwarded-for", "1.2.3.4")
                .header("connection", "x-smuggled")
                .header("x-smuggled", "bad")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 1234))));
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let hdrs = json["headers"].as_object().unwrap();
            assert_eq!(hdrs["x-infinity-sub"], "user-42");
            assert!(!hdrs.contains_key("x-infinity-roles"));
            assert!(!hdrs.contains_key("x-forwarded-user"));
            assert!(!hdrs.contains_key("x-auth-user"));
            assert!(!hdrs.contains_key("x-smuggled"));
            // Untrusted peer IP 203.0.113.9 overrides spoofed X-Forwarded-For: 1.2.3.4.
            assert_eq!(hdrs["x-forwarded-for"], "203.0.113.9");
        }

        // 5) Trusted proxy IP honors XFF.
        let mut req = Request::builder()
            .uri("/api/public/ping")
            .header("x-forwarded-for", "198.51.100.42")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, 5], 1234))));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["headers"]["x-forwarded-for"], "198.51.100.42");

        // 6) Oversized request body returns 413 Payload Too Large.
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/public/upload")
            .body(Body::from(vec![b'a'; 5000]))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 1234))));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        std::fs::remove_dir_all(key_dir).ok();
    }

    #[test]
    fn resolve_client_ip_handles_multi_header_xff_and_ipv4_mapped_ipv6() {
        let trusted = parse_trusted_proxies(&["10.0.0.0/8".into(), "::ffff:192.168.1.1".into()]);
        let dual_stack_peer: IpAddr = "::ffff:10.0.0.5".parse().unwrap();

        // Client injected Header 1; trusted proxy appended Header 2 with real client + mapped proxy.
        let mut headers = HeaderMap::new();
        headers.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("1.2.3.4"),
        );
        headers.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("203.0.113.9, ::ffff:192.168.1.1"),
        );
        assert_eq!(
            resolve_client_ip(dual_stack_peer, &headers, &trusted),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );

        // Rightmost malformed header must fail safe to canonical peer, never fall back to Header 1.
        let mut bad = HeaderMap::new();
        bad.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("1.2.3.4"),
        );
        bad.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("not-an-ip"),
        );
        assert_eq!(
            resolve_client_ip(dual_stack_peer, &bad, &trusted),
            "10.0.0.5".parse::<IpAddr>().unwrap()
        );
    }
}
