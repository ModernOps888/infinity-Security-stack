//! Infinity Observe Agent — tails a file or emits sample telemetry to the server.

mod config;

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::time::Duration;

use anyhow::{bail, Context};
use chrono::Utc;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::redirect::Policy;
use serde_json::json;
use tokio::time::sleep;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;

use crate::config::AgentConfig;

const MAX_LOG_BATCH: usize = 500;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_ERR_BODY_CHARS: usize = 256;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = AgentConfig::load().context("loading agent config")?;
    cfg.validate()?;
    let client = client(&cfg.ingest_key)?;
    if let Some(path) = &cfg.file {
        tail_file(&client, &cfg, path).await?;
    } else {
        generate_samples(&client, &cfg).await?;
    }
    Ok(())
}

fn client(key: &str) -> anyhow::Result<reqwest::Client> {
    let trimmed = key.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        bail!("invalid ingest key format");
    }
    let mut headers = HeaderMap::new();
    let mut auth_val = HeaderValue::from_str(&format!("Bearer {trimmed}"))
        .map_err(|_| anyhow::anyhow!("ingest key contains invalid header bytes"))?;
    auth_val.set_sensitive(true);
    headers.insert(AUTHORIZATION, auth_val);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?)
}

fn sanitize_text(s: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_bytes));
    for ch in s.chars() {
        let mapped = if ch == '\r' || ch == '\n' || ch == '\t' {
            ' '
        } else if ch.is_control() {
            continue;
        } else {
            ch
        };
        if out.len() + mapped.len_utf8() > max_bytes {
            break;
        }
        out.push(mapped);
    }
    out
}

async fn tail_file(client: &reqwest::Client, cfg: &AgentConfig, path: &str) -> anyhow::Result<()> {
    let mut pos = 0u64;
    let source_name = sanitize_text(
        std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("log-file"),
        128,
    );
    loop {
        let mut file = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if file_len < pos {
            pos = 0;
        }
        file.seek(SeekFrom::Start(pos))?;
        let mut reader = BufReader::new(file);
        let mut lines = Vec::new();
        let mut buf = String::new();
        while reader.read_line(&mut buf)? > 0 {
            let line = sanitize_text(buf.trim_end(), MAX_LINE_BYTES);
            if !line.trim().is_empty() {
                lines.push(json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "level": infer_level(&line),
                    "service": cfg.service,
                    "message": line,
                    "attributes": { "source": source_name }
                }));
            }
            buf.clear();
            if lines.len() >= MAX_LOG_BATCH {
                post(
                    client,
                    &cfg.server_url,
                    "/v1/logs",
                    std::mem::take(&mut lines),
                )
                .await?;
            }
        }
        pos = reader.stream_position()?;
        if !lines.is_empty() {
            post(client, &cfg.server_url, "/v1/logs", lines).await?;
        }
        if cfg.once {
            break;
        }
        sleep(Duration::from_secs(cfg.interval_secs.max(1))).await;
    }
    Ok(())
}

async fn generate_samples(client: &reqwest::Client, cfg: &AgentConfig) -> anyhow::Result<()> {
    loop {
        let (latency, error) = {
            let mut rng = rand::thread_rng();
            (rng.gen_range(20.0..450.0), rng.gen_bool(0.08))
        };
        let now = Utc::now().to_rfc3339();
        post(client, &cfg.server_url, "/v1/logs", vec![json!({
            "timestamp": now,
            "level": if error { "ERROR" } else { "INFO" },
            "service": cfg.service,
            "message": if error { "request failed with upstream timeout" } else { "request completed" },
            "attributes": { "agent": "infinity-observe-agent" }
        })]).await?;
        post(
            client,
            &cfg.server_url,
            "/v1/metrics",
            vec![json!({
                "timestamp": Utc::now().to_rfc3339(),
                "name": "http.server.duration_ms",
                "value": latency,
                "tags": { "service": cfg.service }
            })],
        )
        .await?;
        let trace_id = Uuid::new_v4().simple().to_string();
        let root_span = Uuid::new_v4().simple().to_string();
        post(
            client,
            &cfg.server_url,
            "/v1/traces",
            vec![json!({
                "trace_id": trace_id,
                "span_id": root_span,
                "name": "GET /api/demo",
                "service": cfg.service,
                "start": Utc::now().to_rfc3339(),
                "duration_ms": latency,
                "status": if error { "ERROR" } else { "OK" }
            })],
        )
        .await?;
        tracing::info!(latency_ms = latency, error, "shipped sample telemetry");
        if cfg.once {
            break;
        }
        sleep(Duration::from_secs(cfg.interval_secs.max(1))).await;
    }
    Ok(())
}

async fn post(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: Vec<serde_json::Value>,
) -> anyhow::Result<()> {
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let res = client.post(&url).json(&body).send().await?;
    if !res.status().is_success() {
        let status = res.status();
        let text = sanitize_text(&res.text().await.unwrap_or_default(), MAX_ERR_BODY_CHARS);
        bail!("server rejected {path}: {status} {text}");
    }
    Ok(())
}

fn infer_level(line: &str) -> &'static str {
    let upper = line.to_ascii_uppercase();
    if upper.contains("ERROR") || upper.contains("FATAL") {
        "ERROR"
    } else if upper.contains("WARN") {
        "WARN"
    } else if upper.contains("DEBUG") {
        "DEBUG"
    } else {
        "INFO"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_rejects_control_chars_in_key() {
        assert!(client("io_bad\r\nkey").is_err());
        assert!(client("   ").is_err());
        assert!(client("io_valid_test_key_123456").is_ok());
    }

    #[test]
    fn sanitize_text_strips_crlf_and_bounds_len() {
        let cleaned = sanitize_text("hello\r\nworld\x1b[31m!", 12);
        assert!(!cleaned.contains('\r'));
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\x1b'));
        assert!(cleaned.len() <= 12);
    }
}
