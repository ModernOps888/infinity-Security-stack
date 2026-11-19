use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::util::{is_loopback_http_origin, IpCidr};

pub const MAX_SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub bind: String,
    pub public_url: String,
    pub database_url: String,
    pub data_dir: String,
    pub session_ttl_secs: i64,
    pub global_rate_limit_per_min: u32,
    pub admin_email: String,
    pub admin_password: String,
    pub cors_origins: Vec<String>,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default = "default_max_vectors_per_collection")]
    pub max_vectors_per_collection: usize,
    #[serde(default = "default_max_rows_per_table")]
    pub max_rows_per_table: usize,
    #[serde(default, skip_serializing)]
    pub generated_admin_password: bool,
}

fn default_max_vectors_per_collection() -> usize {
    50_000
}

fn default_max_rows_per_table() -> usize {
    100_000
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8094".into(),
            public_url: "http://localhost:8094".into(),
            database_url: "sqlite://data/infinity_data.db".into(),
            data_dir: "data".into(),
            session_ttl_secs: 60 * 60 * 2,
            global_rate_limit_per_min: 600,
            admin_email: "admin@infinity.local".into(),
            admin_password: String::new(),
            cors_origins: vec![
                "http://localhost:8094".into(),
                "http://127.0.0.1:8094".into(),
            ],
            trusted_proxies: Vec::new(),
            max_vectors_per_collection: default_max_vectors_per_collection(),
            max_rows_per_table: default_max_rows_per_table(),
            generated_admin_password: false,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let mut cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("Config.toml"))
            .merge(Env::prefixed("INFINITY_").split("__"))
            .merge(Env::prefixed("DATA_").split("__"))
            .extract()?;
        if cfg.session_ttl_secs <= 0 || cfg.session_ttl_secs > MAX_SESSION_TTL_SECS {
            anyhow::bail!("session_ttl_secs must be between 1 and {MAX_SESSION_TTL_SECS}");
        }
        if cfg.max_vectors_per_collection == 0 {
            anyhow::bail!("max_vectors_per_collection must be > 0");
        }
        if cfg.max_rows_per_table == 0 {
            anyhow::bail!("max_rows_per_table must be > 0");
        }
        for p in &cfg.trusted_proxies {
            if IpCidr::parse(p).is_none() {
                anyhow::bail!("invalid trusted_proxies entry: {p}");
            }
        }
        if cfg.admin_password.trim().is_empty() {
            cfg.admin_password = strong_password();
            cfg.generated_admin_password = true;
            tracing::warn!(email = %cfg.admin_email, password = %cfg.admin_password, "generated initial Infinity Data admin password; shown once");
        } else {
            data_core::password::validate_admin_password(&cfg.admin_password)
                .map_err(|e| anyhow::anyhow!("insecure admin_password configured: {e}"))?;
        }
        Ok(cfg)
    }

    pub fn secure_cookies(&self) -> bool {
        !is_loopback_http_origin(&self.public_url)
    }
}

fn strong_password() -> String {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%*-_=+";
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    let body: String = bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    format!("Idat-{body}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_cookies_rejects_loopback_prefix_spoofing() {
        let mut cfg = Config::default();
        assert!(!cfg.secure_cookies());
        cfg.public_url = "http://127.0.0.1:8094".into();
        assert!(!cfg.secure_cookies());
        cfg.public_url = "http://[::1]:8094".into();
        assert!(!cfg.secure_cookies());

        for url in [
            "https://data.example.com",
            "http://localhost.attacker.com:8094",
            "http://127.evil.com",
            "http://localhost@evil.com",
            "http://10.0.0.5:8094",
        ] {
            cfg.public_url = url.into();
            assert!(cfg.secure_cookies(), "expected Secure cookie for {url}");
        }
    }
}
