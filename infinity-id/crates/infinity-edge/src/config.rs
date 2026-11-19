use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

/// Edge gateway configuration, loaded from `Edge.toml` + `EDGE_*` env vars.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    /// Address to bind, e.g. `0.0.0.0:9000`.
    pub bind: String,
    /// Issuer expected in JWTs (must match Infinity ID's issuer).
    pub issuer: String,
    /// URL of Infinity ID's JWKS document.
    pub jwks_url: String,
    /// Max requests per client IP per 60s window (0 = unlimited).
    #[serde(default)]
    pub rate_limit_per_min: u32,
    /// Maximum request and upstream response body size in bytes.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Optional trusted reverse-proxy IPs/CIDRs permitted to supply `X-Forwarded-For`.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Reverse-proxy routes, matched by longest segment-bounded path prefix.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Path prefix to match, e.g. `/api`.
    pub prefix: String,
    /// Upstream base URL, e.g. `http://127.0.0.1:8081`.
    pub upstream: String,
    /// Require a valid Infinity ID access token.
    #[serde(default)]
    pub require_auth: bool,
    /// Optional OAuth2 scope the token must carry (e.g. `orders:read`).
    /// Matched only against token scopes — never against roles.
    #[serde(default)]
    pub required_scope: Option<String>,
    /// Optional RBAC role the token must carry (e.g. `admin`). Kept separate
    /// from `required_scope` so a user's roles cannot satisfy a scope check.
    #[serde(default)]
    pub required_role: Option<String>,
    /// Optional expected audience (`aud`). When set, the token must have been
    /// minted for this resource, preventing a token issued to another client
    /// from being replayed against this upstream (confused-deputy).
    #[serde(default)]
    pub audience: Option<String>,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:9000".into(),
            issuer: "http://localhost:8080".into(),
            jwks_url: "http://localhost:8080/.well-known/jwks.json".into(),
            rate_limit_per_min: 600,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            trusted_proxies: Vec::new(),
            routes: vec![],
        }
    }
}

/// Returns true if an IP address is a link-local, metadata, unspecified, or
/// multicast destination that must never be targeted by gateway SSRF.
pub fn is_blocked_ssrf_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified() || v4.is_multicast(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ssrf_ip(IpAddr::V4(v4));
            }
            let segs = v6.segments();
            // Also unwrap deprecated IPv4-compatible IPv6 (::a.b.c.d, excluding :: and ::1).
            if segs[0..6] == [0; 6] && segs[6] != 0 {
                let v4 = std::net::Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    (segs[6] & 0xff) as u8,
                    (segs[7] >> 8) as u8,
                    (segs[7] & 0xff) as u8,
                );
                return is_blocked_ssrf_ip(IpAddr::V4(v4));
            }
            v6.is_unspecified() || v6.is_multicast() || (segs[0] & 0xffc0) == 0xfe80
            // fe80::/10 link-local
        }
    }
}

/// Validate a configured URL (`jwks_url` or route `upstream`) against SSRF hazards.
pub fn validate_http_target_url(raw: &str, reject_query: bool) -> anyhow::Result<url::Url> {
    let parsed = url::Url::parse(raw).map_err(|e| anyhow::anyhow!("invalid URL '{raw}': {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("disallowed URL scheme '{}' in '{raw}'", parsed.scheme());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("URL must not contain userinfo: '{raw}'");
    }
    if parsed.fragment().is_some() {
        anyhow::bail!("URL must not contain a fragment: '{raw}'");
    }
    if reject_query && parsed.query().is_some() {
        anyhow::bail!("upstream base URL must not contain a query string: '{raw}'");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL missing host: '{raw}'"))?;
    let host_lower = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if host_lower == "metadata.google.internal"
        || host_lower.ends_with(".internal") && host_lower.contains("metadata")
    {
        anyhow::bail!("disallowed metadata hostname in '{raw}'");
    }
    if let Ok(ip) = host_lower.parse::<IpAddr>() {
        if is_blocked_ssrf_ip(ip) {
            anyhow::bail!("disallowed link-local/unspecified/multicast IP '{ip}' in '{raw}'");
        }
    }
    Ok(parsed)
}

impl EdgeConfig {
    pub fn load() -> anyhow::Result<Self> {
        use figment::providers::{Env, Format, Serialized, Toml};
        use figment::Figment;
        let cfg: Self = Figment::from(Serialized::defaults(EdgeConfig::default()))
            .merge(Toml::file("Edge.toml"))
            .merge(Env::prefixed("EDGE_").split("__"))
            .extract()?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        validate_http_target_url(&self.jwks_url, false)?;
        if self.max_body_bytes == 0 {
            anyhow::bail!("max_body_bytes must be greater than 0");
        }
        for route in &self.routes {
            if !route.prefix.starts_with('/')
                || route.prefix.contains("..")
                || route.prefix.contains('\\')
                || route.prefix.contains('?')
                || route.prefix.contains('#')
                || route.prefix.chars().any(|c| c.is_control())
            {
                anyhow::bail!("invalid route prefix '{}'", route.prefix);
            }
            validate_http_target_url(&route.upstream, true)?;
        }
        Ok(())
    }
}
