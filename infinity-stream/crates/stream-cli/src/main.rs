use std::net::IpAddr;
use std::time::Duration;

use anyhow::{bail, Context};
use serde_json::json;
use stream_core::security::validate_resource_name;
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        usage();
        return Ok(());
    }
    let allow_insecure_http = take_flag(&mut args, "--allow-insecure-http")
        || std::env::var("STREAM_ALLOW_INSECURE_HTTP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    let server_raw =
        take_opt(&mut args, "--server")?.unwrap_or_else(|| "http://127.0.0.1:8092".into());
    let server = validate_server_url(&server_raw, allow_insecure_http)?;
    let key = take_opt(&mut args, "--key")?
        .or_else(|| std::env::var("STREAM_API_KEY").ok())
        .or_else(|| std::env::var("INFINITY_STREAM_KEY").ok())
        .context("--key, STREAM_API_KEY or INFINITY_STREAM_KEY required")?;
    if key.trim().is_empty() || key.len() > 256 || key.chars().any(|c| c.is_control()) {
        bail!("invalid API key format");
    }
    let cmd = args.first().cloned().context("command required")?;
    args.remove(0);

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .context("building HTTP client")?;

    match cmd.as_str() {
        "produce" => {
            let topic = pop(&mut args, "topic")?;
            validate_resource_name(&topic).context("invalid topic name")?;
            let count: usize = take_opt(&mut args, "--count")?
                .unwrap_or_else(|| "1".into())
                .parse()?;
            if count == 0 || count > 10_000 {
                bail!("--count must be 1..=10000");
            }
            let partition = take_opt(&mut args, "--partition")?
                .map(|v| v.parse::<u32>())
                .transpose()?;
            let value = take_opt(&mut args, "--value")?
                .unwrap_or_else(|| "hello from infinity-stream-cli".into());
            let endpoint = server.join(&format!("v1/topics/{topic}/produce"))?;
            for i in 0..count {
                let body = json!({
                    "partition": partition,
                    "key": format!("cli-{i}"),
                    "value": {"message": value, "n": i}
                });
                let res = http
                    .post(endpoint.clone())
                    .bearer_auth(&key)
                    .json(&body)
                    .send()
                    .await?;
                print_response(res).await?;
            }
        }
        "consume" => {
            let topic = pop(&mut args, "topic")?;
            validate_resource_name(&topic).context("invalid topic name")?;
            let partition: u32 = take_opt(&mut args, "--partition")?
                .unwrap_or_else(|| "0".into())
                .parse()?;
            let offset: u64 = take_opt(&mut args, "--offset")?
                .unwrap_or_else(|| "0".into())
                .parse()?;
            let max: usize = take_opt(&mut args, "--max")?
                .unwrap_or_else(|| "10".into())
                .parse()?;
            if max == 0 || max > 1_000 {
                bail!("--max must be 1..=1000");
            }
            let endpoint = server.join(&format!("v1/topics/{topic}/consume"))?;
            let res = http
                .get(endpoint)
                .bearer_auth(&key)
                .query(&[
                    ("partition", partition.to_string()),
                    ("offset", offset.to_string()),
                    ("max", max.to_string()),
                ])
                .send()
                .await?;
            print_response(res).await?;
        }
        "search" => {
            let index = pop(&mut args, "index")?;
            validate_resource_name(&index).context("invalid index name")?;
            let query = match take_opt(&mut args, "--query")? {
                Some(q) => q,
                None => take_opt(&mut args, "-q")?.context("--query required")?,
            };
            let k: usize = take_opt(&mut args, "--k")?
                .unwrap_or_else(|| "10".into())
                .parse()?;
            if k == 0 || k > 100 {
                bail!("--k must be 1..=100");
            }
            let endpoint = server.join(&format!("v1/indexes/{index}/search"))?;
            let res = http
                .get(endpoint)
                .bearer_auth(&key)
                .query(&[("q", query), ("k", k.to_string())])
                .send()
                .await?;
            print_response(res).await?;
        }
        _ => bail!("unknown command: {cmd}"),
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn validate_server_url(raw: &str, allow_insecure_http: bool) -> anyhow::Result<Url> {
    let mut url = Url::parse(raw).context("invalid --server URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("--server URL must not embed credentials");
    }
    let host = url.host_str().context("--server URL must contain a host")?;
    match url.scheme() {
        "https" => {}
        "http" => {
            if !is_loopback_host(host) && !allow_insecure_http {
                bail!(
                    "refusing to send API key over cleartext http:// to non-loopback host {host}; use https:// or pass --allow-insecure-http"
                );
            }
        }
        other => bail!("unsupported --server URL scheme: {other}"),
    }
    if !url.path().ends_with('/') {
        let p = format!("{}/", url.path().trim_end_matches('/'));
        url.set_path(&p);
    }
    Ok(url)
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == name) {
        args.remove(i);
        true
    } else {
        false
    }
}

fn take_opt(args: &mut Vec<String>, name: &str) -> anyhow::Result<Option<String>> {
    let Some(i) = args.iter().position(|a| a == name) else {
        return Ok(None);
    };
    args.remove(i);
    if i < args.len() {
        Ok(Some(args.remove(i)))
    } else {
        bail!("option {name} requires a value")
    }
}

fn pop(args: &mut Vec<String>, what: &str) -> anyhow::Result<String> {
    if args.is_empty() {
        bail!("{what} required")
    } else {
        Ok(args.remove(0))
    }
}

async fn print_response(res: reqwest::Response) -> anyhow::Result<()> {
    let status = res.status();
    let text = res.text().await?;
    if !status.is_success() {
        bail!("HTTP {status}: {text}");
    }
    let value: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}));
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn usage() {
    eprintln!(
        "Usage:\n  \
         infinity-stream-cli [--server URL] [--allow-insecure-http] [--key KEY] produce TOPIC [--count N] [--partition P] [--value TEXT]\n  \
         infinity-stream-cli [--server URL] [--allow-insecure-http] [--key KEY] consume TOPIC [--partition P] [--offset O] [--max M]\n  \
         infinity-stream-cli [--server URL] [--allow-insecure-http] [--key KEY] search INDEX --query TEXT [--k N]\n\n\
         Defaults: --server http://127.0.0.1:8092, key from STREAM_API_KEY (preferred over --key)."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_enforces_tls_off_loopback() {
        assert!(validate_server_url("http://127.0.0.1:8092", false).is_ok());
        assert!(validate_server_url("http://localhost:8092", false).is_ok());
        assert!(validate_server_url("http://[::1]:8092", false).is_ok());
        assert!(validate_server_url("https://stream.example.com", false).is_ok());
        assert!(validate_server_url("http://stream.example.com:8092", false).is_err());
        assert!(validate_server_url("http://stream.example.com:8092", true).is_ok());
        assert!(validate_server_url("https://user:pass@stream.example.com", false).is_err());
        assert!(validate_server_url("ftp://stream.example.com", false).is_err());
    }

    #[test]
    fn take_opt_rejects_dangling_flag() {
        let mut args = vec!["--server".to_string()];
        assert!(take_opt(&mut args, "--server").is_err());
    }
}
