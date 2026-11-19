use std::net::IpAddr;

use anyhow::bail;
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use stream_core::password::is_weak_or_default_password;
use url::Url;

fn default_ws_max_connections() -> usize {
    1024
}

/// Runtime configuration, loaded from defaults -> `Config.toml` -> `INFINITY_*` -> `STREAM_*` env.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub bind: String,
    pub public_url: String,
    pub database_url: String,
    pub data_dir: String,
    pub session_ttl_secs: i64,
    pub global_rate_limit_per_min: u32,
    pub max_json_body_bytes: usize,
    pub max_batch_records: usize,
    pub max_search_docs_per_batch: usize,
    pub admin_email: String,
    pub admin_password: String,
    pub cors_origins: Vec<String>,
    pub segment_max_bytes: u64,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default = "default_ws_max_connections")]
    pub ws_max_connections: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8092".into(),
            public_url: "http://localhost:8092".into(),
            database_url: "sqlite://data/stream.db".into(),
            data_dir: "data".into(),
            session_ttl_secs: 60 * 60 * 2,
            global_rate_limit_per_min: 600,
            max_json_body_bytes: 1024 * 1024,
            max_batch_records: 1_000,
            max_search_docs_per_batch: 1_000,
            admin_email: "admin@infinity.local".into(),
            admin_password: String::new(),
            cors_origins: vec![
                "http://localhost:8092".into(),
                "http://127.0.0.1:8092".into(),
            ],
            segment_max_bytes: 1 << 20,
            trusted_proxies: Vec::new(),
            ws_max_connections: default_ws_max_connections(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedOrigin {
    scheme: String,
    host: String,
    port: u16,
}

fn normalize_origin(raw: &str) -> Option<NormalizedOrigin> {
    let url = Url::parse(raw.trim()).ok()?;
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    if url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    if url.path() != "/" && !url.path().is_empty() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some(NormalizedOrigin { scheme, host, port })
}

fn is_loopback_url(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw.trim()) else {
        return false;
    };
    if !url.scheme().eq_ignore_ascii_case("http") {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

#[derive(Debug, Clone)]
pub struct CidrRule {
    addr: IpAddr,
    prefix: u8,
}

impl CidrRule {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let s = raw.trim();
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let raw_addr: IpAddr = ip_str
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid trusted proxy IP: {s}"))?;
            let raw_prefix: u8 = prefix_str
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid trusted proxy CIDR prefix: {s}"))?;
            let max = if raw_addr.is_ipv4() { 32 } else { 128 };
            if raw_prefix > max {
                bail!("trusted proxy prefix out of range: {s}");
            }
            let addr = canonical_ip(raw_addr);
            let prefix = match (raw_addr, addr) {
                (IpAddr::V6(_), IpAddr::V4(_)) => raw_prefix.saturating_sub(96),
                _ => raw_prefix,
            };
            Ok(Self { addr, prefix })
        } else {
            let raw_addr: IpAddr = s
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid trusted proxy IP: {s}"))?;
            let addr = canonical_ip(raw_addr);
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            Ok(Self { addr, prefix })
        }
    }

    pub fn matches(&self, candidate: IpAddr) -> bool {
        let candidate = canonical_ip(candidate);
        match (self.addr, candidate) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix);
                (u32::from(a) & mask) == (u32::from(b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix);
                (u128::from(a) & mask) == (u128::from(b) & mask)
            }
            _ => false,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Env::prefixed("INFINITY_").split("__"))
            .merge(Env::prefixed("STREAM_").split("__"))
            .extract()?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let pub_url =
            Url::parse(&self.public_url).map_err(|e| anyhow::anyhow!("invalid public_url: {e}"))?;
        if (pub_url.scheme() != "http" && pub_url.scheme() != "https")
            || pub_url.host_str().is_none()
        {
            bail!("public_url must be an http(s) URL with a host");
        }
        if !(1..=604_800).contains(&self.session_ttl_secs) {
            bail!("session_ttl_secs must be between 1 and 604800");
        }
        if !(1024..=32 * 1024 * 1024).contains(&self.max_json_body_bytes) {
            bail!("max_json_body_bytes must be between 1024 and 33554432");
        }
        if !(1..=10_000).contains(&self.max_batch_records) {
            bail!("max_batch_records must be between 1 and 10000");
        }
        if !(1..=10_000).contains(&self.max_search_docs_per_batch) {
            bail!("max_search_docs_per_batch must be between 1 and 10000");
        }
        if self.segment_max_bytes < 256 {
            bail!("segment_max_bytes must be at least 256");
        }
        if !(1..=100_000).contains(&self.ws_max_connections) {
            bail!("ws_max_connections must be between 1 and 100000");
        }
        if !self.admin_password.is_empty() && is_weak_or_default_password(&self.admin_password) {
            bail!("admin_password is weak or a known default placeholder; configure a strong >=12-char password or leave unset to auto-generate");
        }
        for proxy in &self.trusted_proxies {
            CidrRule::parse(proxy)?;
        }
        Ok(())
    }

    /// Cookies get the `Secure` flag by default. It is only omitted for local
    /// development over plain HTTP on loopback (`localhost` / `127.0.0.0/8` / `::1`).
    pub fn cookie_secure(&self) -> bool {
        !is_loopback_url(&self.public_url)
    }

    /// Strict origin validation for CSWSH & cookie CSRF defenses.
    pub fn is_allowed_origin(&self, origin: &str) -> bool {
        let Some(candidate) = normalize_origin(origin) else {
            return false;
        };
        if let Some(pub_origin) = normalize_origin(&self.public_url) {
            if candidate == pub_origin {
                return true;
            }
        }
        self.cors_origins
            .iter()
            .filter_map(|o| normalize_origin(o))
            .any(|allowed| allowed == candidate)
    }

    pub fn parsed_trusted_proxies(&self) -> Vec<CidrRule> {
        self.trusted_proxies
            .iter()
            .filter_map(|p| CidrRule::parse(p).ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_secure_cannot_be_bypassed_by_subdomain_prefix() {
        let mut cfg = Config::default();
        assert!(!cfg.cookie_secure());
        cfg.public_url = "http://localhost.evil.com:8092".into();
        assert!(cfg.cookie_secure());
        cfg.public_url = "http://127.evil.com:8092".into();
        assert!(cfg.cookie_secure());
        cfg.public_url = "https://localhost:8092".into();
        assert!(cfg.cookie_secure());
        cfg.public_url = "http://127.0.0.1:8092".into();
        assert!(!cfg.cookie_secure());
    }

    #[test]
    fn origin_allowlist_is_exact() {
        let cfg = Config::default();
        assert!(cfg.is_allowed_origin("http://localhost:8092"));
        assert!(cfg.is_allowed_origin("http://127.0.0.1:8092"));
        assert!(!cfg.is_allowed_origin("http://localhost:8092.evil.com"));
        assert!(!cfg.is_allowed_origin("http://localhost:3000"));
        assert!(!cfg.is_allowed_origin("null"));
        assert!(!cfg.is_allowed_origin("javascript:alert(1)"));
    }

    #[test]
    fn reject_weak_explicit_admin_password() {
        let mut cfg = Config::default();
        assert!(cfg.validate().is_ok()); // empty -> auto-generate
        cfg.admin_password = "ChangeMe_Infinity#2025".into();
        assert!(cfg.validate().is_err());
        cfg.admin_password = "Sup3r-Secret-Admin-Pass!".into();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn cidr_matches_ipv4_mapped_ipv6() {
        let rule = CidrRule::parse("10.0.0.0/8").unwrap();
        assert!(rule.matches("::ffff:10.0.0.5".parse().unwrap()));
        let mapped_rule = CidrRule::parse("::ffff:10.0.0.0/104").unwrap();
        assert!(mapped_rule.matches("10.0.0.5".parse().unwrap()));
    }
}
