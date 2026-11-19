use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{bail, Context};
use reqwest::header::AUTHORIZATION;
use serde_json::{json, Value};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "help" || args[0] == "--help" {
        print_help();
        return Ok(());
    }
    let allow_insecure_http = take_flag(&mut args, "--allow-insecure-http")
        || std::env::var("DATA_ALLOW_INSECURE_HTTP")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    let raw_server = take_opt(&mut args, "--server")?
        .or_else(|| std::env::var("DATA_SERVER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8094".into());
    let server = validate_server_url(&raw_server, allow_insecure_http)?;
    let token = take_opt(&mut args, "--token")?.or_else(|| std::env::var("DATA_API_TOKEN").ok());
    if args.is_empty() {
        print_help();
        bail!("missing command");
    }
    let cmd = args.remove(0);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    match cmd.as_str() {
        "health" => {
            let v: Value = client
                .get(format!("{server}/health"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        "login" => {
            let (email, password) = if args.len() == 2 {
                (args[0].clone(), args[1].clone())
            } else if args.len() == 1 {
                let pw = std::env::var("DATA_PASSWORD").or_else(|_| {
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf)?;
                    Ok::<String, std::io::Error>(
                        buf.trim_end_matches(&['\r', '\n'][..]).to_string(),
                    )
                })?;
                if pw.is_empty() {
                    bail!("password required via DATA_PASSWORD or stdin");
                }
                (args[0].clone(), pw)
            } else {
                bail!(
                    "usage: infinity-data-cli login <email> [password] [--server URL] (or pass DATA_PASSWORD / stdin)"
                );
            };
            let resp = client
                .post(format!("{server}/auth/login"))
                .json(&json!({"email": email, "password": password}))
                .send()
                .await?
                .error_for_status()?;
            let has_cookie = resp.headers().contains_key("set-cookie");
            let body: Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            if has_cookie {
                eprintln!("Session cookie received (HttpOnly, value redacted)");
            }
        }
        "create-collection" => {
            if args.len() < 2 || args.len() > 3 {
                bail!("usage: infinity-data-cli create-collection <name> <dim> [metric] --token TOKEN");
            }
            validate_segment(&args[0])?;
            let dim: usize = args[1].parse().context("dim must be a positive integer")?;
            let metric = args.get(2).cloned().unwrap_or_else(|| "cosine".into());
            let v = authed(
                client.post(format!("{server}/api/collections")),
                token.as_deref(),
            )
            .json(&json!({"name": args[0], "dim": dim, "metric": metric}))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        "insert" => {
            if args.len() < 3 || args.len() > 4 {
                bail!("usage: infinity-data-cli insert <collection> <id> <vector-json> [metadata-json] --token TOKEN");
            }
            validate_segment(&args[0])?;
            let vector: Vec<f32> =
                serde_json::from_str(&args[2]).context("vector must be a JSON number array")?;
            if vector.iter().any(|v| !v.is_finite()) {
                bail!("vector must contain only finite numbers");
            }
            let metadata: Option<Value> = if args.len() == 4 {
                Some(serde_json::from_str(&args[3]).context("metadata must be JSON")?)
            } else {
                None
            };
            let point = json!({"id": args[1], "vector": vector, "metadata": metadata});
            let v = authed(
                client.post(format!("{server}/api/collections/{}/vectors", args[0])),
                token.as_deref(),
            )
            .json(&json!({"points": [point]}))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        "search" => {
            if args.len() < 2 || args.len() > 3 {
                bail!(
                    "usage: infinity-data-cli search <collection> <vector-json> [k] --token TOKEN"
                );
            }
            validate_segment(&args[0])?;
            let vector: Vec<f32> =
                serde_json::from_str(&args[1]).context("vector must be a JSON number array")?;
            if vector.iter().any(|v| !v.is_finite()) {
                bail!("vector must contain only finite numbers");
            }
            let k: usize = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(10);
            let v = authed(
                client.post(format!("{server}/api/collections/{}/search", args[0])),
                token.as_deref(),
            )
            .json(&json!({"vector": vector, "k": k}))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        _ => {
            print_help();
            bail!("unknown command: {cmd}");
        }
    }
    Ok(())
}

fn authed(req: reqwest::RequestBuilder, token: Option<&str>) -> reqwest::RequestBuilder {
    match token {
        Some(t) => req.header(AUTHORIZATION, format!("Bearer {t}")),
        None => req,
    }
}

fn validate_segment(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("collection name must be 1-64 ASCII alphanumeric, '_' or '-' characters");
    }
    Ok(())
}

fn parse_authority_host(authority: &str) -> anyhow::Result<&str> {
    if authority.is_empty()
        || authority.contains('@')
        || authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("server URL authority must be a valid host[:port] without userinfo");
    }
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let Some((inner, tail)) = after_bracket.split_once(']') else {
            bail!("malformed IPv6 host in server URL");
        };
        if inner.is_empty() || inner.parse::<IpAddr>().is_err() {
            bail!("invalid IPv6 literal in server URL");
        }
        if let Some(port) = tail.strip_prefix(':') {
            let port_num: u16 = port.parse().context("invalid port in server URL")?;
            if port_num == 0 {
                bail!("port must be >= 1");
            }
        } else if !tail.is_empty() {
            bail!("malformed host/port in server URL");
        }
        return Ok(inner);
    }
    if let Some((host, port)) = authority.split_once(':') {
        if host.is_empty() || host.contains(':') {
            bail!("invalid host in server URL");
        }
        let port_num: u16 = port.parse().context("invalid port in server URL")?;
        if port_num == 0 {
            bail!("port must be >= 1");
        }
        Ok(host)
    } else {
        Ok(authority)
    }
}

fn validate_server_url(raw: &str, allow_insecure_http: bool) -> anyhow::Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.contains(['?', '#']) || trimmed.chars().any(char::is_control) {
        bail!("server URL must not contain query, fragment, or control characters");
    }
    if let Some(rest) = trimmed.strip_prefix("https://") {
        let authority = rest.split('/').next().unwrap_or("");
        parse_authority_host(authority)?;
        return Ok(trimmed.to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or("");
        let host_part = parse_authority_host(authority)?;
        let is_loopback = host_part.eq_ignore_ascii_case("localhost")
            || host_part
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if is_loopback || allow_insecure_http {
            return Ok(trimmed.to_string());
        }
        bail!(
            "refusing plain HTTP for non-loopback server {trimmed}; use https:// or pass --allow-insecure-http"
        );
    }
    bail!("server URL must use https:// or http://")
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    if let Some(pos) = args.iter().position(|a| a == name) {
        args.remove(pos);
        true
    } else {
        false
    }
}

fn take_opt(args: &mut Vec<String>, name: &str) -> anyhow::Result<Option<String>> {
    if let Some(pos) = args.iter().position(|a| a == name) {
        args.remove(pos);
        if pos < args.len() {
            Ok(Some(args.remove(pos)))
        } else {
            bail!("{name} requires a value");
        }
    } else {
        Ok(None)
    }
}

fn print_help() {
    eprintln!("Infinity Data CLI");
    eprintln!("  health [--server URL]");
    eprintln!(
        "  login <email> [password] [--server URL]   (reads DATA_PASSWORD or stdin if omitted)"
    );
    eprintln!("  create-collection <name> <dim> [metric] --token TOKEN");
    eprintln!("  insert <collection> <id> <vector-json> [metadata-json] --token TOKEN");
    eprintln!("  search <collection> <vector-json> [k] --token TOKEN");
    eprintln!("Options: --allow-insecure-http (non-loopback HTTP only when explicitly intended)");
    eprintln!("Env: DATA_SERVER_URL, DATA_API_TOKEN, DATA_PASSWORD, DATA_ALLOW_INSECURE_HTTP");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_enforces_https_off_loopback() {
        assert!(validate_server_url("http://localhost:8094/", false).is_ok());
        assert!(validate_server_url("http://127.0.0.1:8094", false).is_ok());
        assert!(validate_server_url("http://[::1]:8094", false).is_ok());
        assert!(validate_server_url("https://data.example.com", false).is_ok());
        assert!(validate_server_url("http://data.example.com:8094", false).is_err());
        assert!(validate_server_url("http://localhost.evil.com:8094", false).is_err());
        assert!(validate_server_url("http://localhost:pass@evil.com:8094", false).is_err());
        assert!(validate_server_url("http://[::1]@evil.com:8094", false).is_err());
        assert!(validate_server_url("https://", false).is_err());
        assert!(validate_server_url("https://user:pass@data.example.com", false).is_err());
        assert!(validate_server_url("http://localhost:notaport", false).is_err());
        assert!(validate_server_url("http://data.example.com:8094", true).is_ok());
    }

    #[test]
    fn validate_segment_blocks_traversal() {
        assert!(validate_segment("products_v1-a").is_ok());
        assert!(validate_segment("../admin").is_err());
        assert!(validate_segment("col?foo=bar").is_err());
    }
}
