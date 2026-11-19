use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Runtime configuration, loaded from defaults -> `Config.toml` -> `INFINITY_*` env.
#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    /// Socket address to bind, e.g. `0.0.0.0:8080`.
    pub bind: String,
    /// Public issuer URL used in tokens and discovery, e.g. `http://localhost:8080`.
    pub issuer: String,
    /// SQLite/Postgres connection string.
    pub database_url: String,
    /// Directory for persisted signing keys and data.
    pub data_dir: String,
    /// Access-token lifetime in seconds.
    pub access_token_ttl_secs: i64,
    /// Refresh-token lifetime in seconds.
    pub refresh_token_ttl_secs: i64,
    /// Authorization-code lifetime in seconds.
    pub code_ttl_secs: i64,
    /// Dashboard session lifetime in seconds.
    pub session_ttl_secs: i64,
    /// Global per-IP request cap per 60s window (0 = unlimited).
    pub global_rate_limit_per_min: u32,
    /// Display name shown in authenticator apps (must not contain a colon).
    pub mfa_issuer: String,
    /// Seed admin email (created on first run if no users exist).
    pub admin_email: String,
    /// Seed admin password (leave empty to auto-generate a strong password on first run).
    pub admin_password: String,
    /// Allowed CORS origins for the dashboard / SPA clients.
    pub cors_origins: Vec<String>,
    /// Optional trusted reverse-proxy IPs/CIDRs permitted to assert client IP
    /// via `X-Forwarded-For`. Empty = never trust `X-Forwarded-For`.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("issuer", &self.issuer)
            .field("database_url", &self.database_url)
            .field("data_dir", &self.data_dir)
            .field("access_token_ttl_secs", &self.access_token_ttl_secs)
            .field("refresh_token_ttl_secs", &self.refresh_token_ttl_secs)
            .field("code_ttl_secs", &self.code_ttl_secs)
            .field("session_ttl_secs", &self.session_ttl_secs)
            .field("global_rate_limit_per_min", &self.global_rate_limit_per_min)
            .field("mfa_issuer", &self.mfa_issuer)
            .field("admin_email", &self.admin_email)
            .field("admin_password", &"[REDACTED]")
            .field("cors_origins", &self.cors_origins)
            .field("trusted_proxies", &self.trusted_proxies)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".into(),
            issuer: "http://localhost:8080".into(),
            database_url: "sqlite://data/infinity.db".into(),
            data_dir: "data".into(),
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 60 * 60 * 24 * 30,
            code_ttl_secs: 300,
            session_ttl_secs: 60 * 60 * 2,
            global_rate_limit_per_min: 600,
            mfa_issuer: "Infinity ID".into(),
            admin_email: "admin@infinity.local".into(),
            admin_password: String::new(),
            cors_origins: vec!["http://localhost:8080".into()],
            trusted_proxies: Vec::new(),
        }
    }
}

/// Returns true if an explicitly supplied admin password is a known default or
/// placeholder value that must be refused.
pub fn is_placeholder_admin_password(pw: &str) -> bool {
    let norm = pw.trim().to_ascii_lowercase();
    if norm.is_empty() {
        return false;
    }
    const EXACT: &[&str] = &[
        "changeme_infinity#2025",
        "changeme_infinity#2026",
        "chooseastrongone#2025",
        "chooseastrongone#2026",
        "password",
        "password123",
        "admin",
        "admin123",
        "12345678",
        "changeme",
    ];
    EXACT.contains(&norm.as_str())
        || norm.starts_with("change-me")
        || norm.starts_with("changeme")
        || norm.starts_with("change_me")
        || norm.starts_with("placeholder")
}

impl Config {
    /// Load configuration, layering optional `Config.toml` and `INFINITY_` env vars.
    pub fn load() -> anyhow::Result<Self> {
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Env::prefixed("INFINITY_").split("__"))
            .extract()?;
        Ok(cfg)
    }

    /// Canonical `scheme://host[:port]` origin of `self.issuer`, if parseable.
    pub fn issuer_origin(&self) -> Option<String> {
        let u = url::Url::parse(&self.issuer).ok()?;
        let host = u.host_str()?;
        let scheme = u.scheme();
        match u.port() {
            Some(p) => Some(format!("{scheme}://{host}:{p}")),
            None => Some(format!("{scheme}://{host}")),
        }
    }

    /// True when cookies should carry the `Secure` attribute (HTTPS or non-loopback).
    pub fn cookie_secure(&self) -> bool {
        if self.issuer.starts_with("https://") {
            return true;
        }
        let Ok(u) = url::Url::parse(&self.issuer) else {
            return true;
        };
        !matches!(
            u.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        )
    }
}
