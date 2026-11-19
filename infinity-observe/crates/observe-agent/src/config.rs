use std::fmt;
use std::net::IpAddr;

use anyhow::bail;
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

#[derive(Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub ingest_key: String,
    pub service: String,
    pub file: Option<String>,
    pub interval_secs: u64,
    pub once: bool,
    #[serde(default)]
    pub allow_insecure_http: bool,
}

impl fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentConfig")
            .field("server_url", &self.server_url)
            .field("ingest_key", &"[REDACTED]")
            .field("service", &self.service)
            .field("file", &self.file)
            .field("interval_secs", &self.interval_secs)
            .field("once", &self.once)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish()
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:9100".into(),
            ingest_key: "".into(),
            service: "sample-service".into(),
            file: None,
            interval_secs: 5,
            once: false,
            allow_insecure_http: false,
        }
    }
}

pub fn validate_server_url(raw: &str, allow_insecure_http: bool) -> anyhow::Result<Url> {
    let url = Url::parse(raw.trim()).map_err(|e| anyhow::anyhow!("invalid server_url: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("server_url must not contain embedded credentials");
    }
    if url.fragment().is_some() {
        bail!("server_url must not contain a fragment");
    }
    let is_loopback = match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => {
            ip.is_loopback()
                || ip
                    .to_ipv4_mapped()
                    .map(|v4| IpAddr::V4(v4).is_loopback())
                    .unwrap_or(false)
        }
        None => bail!("server_url must include a host"),
    };
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback || allow_insecure_http => Ok(url),
        "http" => bail!(
            "refusing cleartext http:// for non-loopback server_url (use https:// or pass --allow-insecure-http)"
        ),
        other => bail!("unsupported server_url scheme: {other}"),
    }
}

impl AgentConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.ingest_key.trim().is_empty() {
            bail!("ingest key required: pass --key or set INFINITY_AGENT_INGEST_KEY");
        }
        if self.service.trim().is_empty() || self.service.chars().any(char::is_control) {
            bail!("invalid service name");
        }
        validate_server_url(&self.server_url, self.allow_insecure_http)?;
        Ok(())
    }

    pub fn load() -> anyhow::Result<Self> {
        let mut cfg: AgentConfig = Figment::from(Serialized::defaults(AgentConfig::default()))
            .merge(Toml::file("Agent.toml"))
            .merge(Env::prefixed("INFINITY_AGENT_").split("__"))
            .extract()?;
        let args: Vec<String> = std::env::args().collect();
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--server" => {
                    i += 1;
                    let val = args
                        .get(i)
                        .ok_or_else(|| anyhow::anyhow!("--server requires a value"))?;
                    cfg.server_url = val.clone();
                }
                "--key" => {
                    i += 1;
                    let val = args
                        .get(i)
                        .ok_or_else(|| anyhow::anyhow!("--key requires a value"))?;
                    cfg.ingest_key = val.clone();
                }
                "--service" => {
                    i += 1;
                    let val = args
                        .get(i)
                        .ok_or_else(|| anyhow::anyhow!("--service requires a value"))?;
                    cfg.service = val.clone();
                }
                "--file" => {
                    i += 1;
                    let val = args
                        .get(i)
                        .ok_or_else(|| anyhow::anyhow!("--file requires a value"))?;
                    cfg.file = Some(val.clone());
                }
                "--interval" => {
                    i += 1;
                    let val = args
                        .get(i)
                        .ok_or_else(|| anyhow::anyhow!("--interval requires a value"))?;
                    cfg.interval_secs = val
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid --interval value"))?;
                }
                "--once" => cfg.once = true,
                "--allow-insecure-http" => cfg.allow_insecure_http = true,
                "--help" | "-h" => {
                    println!("infinity-observe-agent --key <ingest-key> [--server http://127.0.0.1:9100] [--service name] [--file path] [--once] [--allow-insecure-http]");
                    std::process::exit(0);
                }
                _ => {}
            }
            i += 1;
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_ingest_key() {
        let cfg = AgentConfig {
            ingest_key: "io_super_secret_key_value".into(),
            ..AgentConfig::default()
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("io_super_secret_key_value"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn validates_server_url_tls_policy() {
        assert!(validate_server_url("https://observe.example.com:8090", false).is_ok());
        assert!(validate_server_url("http://127.0.0.1:8090", false).is_ok());
        assert!(validate_server_url("http://localhost:8090", false).is_ok());
        assert!(validate_server_url("http://[::1]:8090", false).is_ok());
        assert!(validate_server_url("http://observe.example.com:8090", false).is_err());
        assert!(validate_server_url("http://observe.example.com:8090", true).is_ok());
        assert!(validate_server_url("https://user:pass@observe.example.com", false).is_err());
        assert!(validate_server_url("file:///etc/passwd", true).is_err());
    }
}
