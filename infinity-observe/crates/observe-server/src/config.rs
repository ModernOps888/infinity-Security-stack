use std::net::IpAddr;

use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use url::Url;

/// Runtime configuration, loaded from defaults -> `Config.toml` -> `OBSERVE_*` env.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Socket address to bind, e.g. `0.0.0.0:8090`.
    pub bind: String,
    /// Public URL used to decide whether dashboard cookies may omit `Secure` for local development.
    pub public_url: String,
    pub database_url: String,
    pub data_dir: String,
    pub session_ttl_secs: i64,
    /// Global per-IP request cap per 60s window (0 = unlimited).
    pub global_rate_limit_per_min: u32,
    /// Maximum accepted request body size in bytes.
    pub max_request_body_bytes: usize,
    pub admin_email: String,
    pub admin_password: String,
    pub cors_origins: Vec<String>,
    /// Allow plaintext `http://` alert webhook targets (default false: `https://` only).
    #[serde(default)]
    pub allow_insecure_webhooks: bool,
    /// Allow private/loopback/link-local IP ranges for alert webhooks (default false: SSRF-blocked).
    #[serde(default)]
    pub allow_private_webhooks: bool,
    /// Trusted reverse-proxy IPs or CIDRs whose `X-Forwarded-For` / `X-Real-IP` headers are honored.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8090".into(),
            public_url: "http://localhost:8090".into(),
            database_url: "sqlite://data/observe.db".into(),
            data_dir: "data".into(),
            session_ttl_secs: 60 * 60 * 2,
            global_rate_limit_per_min: 600,
            max_request_body_bytes: 1024 * 1024,
            admin_email: "admin@infinity.local".into(),
            admin_password: String::new(),
            cors_origins: vec![
                "http://localhost:8090".into(),
                "http://127.0.0.1:8090".into(),
            ],
            allow_insecure_webhooks: false,
            allow_private_webhooks: false,
            trusted_proxies: Vec::new(),
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Env::prefixed("OBSERVE_").split("__"))
            .extract()?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !(60..=604_800).contains(&self.session_ttl_secs) {
            anyhow::bail!("session_ttl_secs must be between 60 and 604800");
        }
        if !(1024..=(64 * 1024 * 1024)).contains(&self.max_request_body_bytes) {
            anyhow::bail!("max_request_body_bytes must be between 1024 and 67108864");
        }
        let url =
            Url::parse(&self.public_url).map_err(|e| anyhow::anyhow!("invalid public_url: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            anyhow::bail!("public_url must be an http(s) URL with a host");
        }
        for cidr in &self.trusted_proxies {
            validate_cidr_entry(cidr)?;
        }
        Ok(())
    }
}

fn validate_cidr_entry(entry: &str) -> anyhow::Result<()> {
    let trimmed = entry.trim();
    if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid trusted_proxies IP: {trimmed}"))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid trusted_proxies prefix: {trimmed}"))?;
        let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            anyhow::bail!("trusted_proxies prefix out of range: {trimmed}");
        }
    } else {
        let _: IpAddr = trimmed
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid trusted_proxies IP: {trimmed}"))?;
    }
    Ok(())
}
