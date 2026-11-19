//! SSRF protection and IP-pinned outbound dispatch for alert webhooks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use reqwest::redirect::Policy;
use serde_json::Value;
use url::{Host, Url};

const MAX_WEBHOOK_URL_LEN: usize = 2048;

#[derive(Debug, Clone)]
pub struct ParsedWebhook {
    pub url: Url,
    pub host: String,
    pub port: u16,
    pub is_ip_literal: bool,
}

/// Returns `true` if `ip` is loopback, private (RFC1918 / ULA), link-local
/// (including cloud metadata `169.254.169.254`), CGNAT, unspecified, multicast,
/// reserved, or embeds a forbidden IPv4 address via IPv6 tunneling/mapping.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4),
        IpAddr::V6(v6) => is_forbidden_ipv6(v6),
    }
}

fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || a == 0 // 0.0.0.0/8 ("this network")
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 CGNAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24 IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // 192.0.2.0/24 TEST-NET-1
        || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 benchmarking
        || (a == 198 && b == 51 && c == 100) // 198.51.100.0/24 TEST-NET-2
        || (a == 203 && b == 0 && c == 113) // 203.0.113.0/24 TEST-NET-3
        || a >= 224 // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
}

fn is_forbidden_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_forbidden_ipv4(v4);
    }
    if let Some(v4) = ip.to_ipv4() {
        // Handles deprecated IPv4-compatible `::/96` as well.
        return is_forbidden_ipv4(v4);
    }
    let segs = ip.segments();
    // NAT64: 64:ff9b::/96 or 64:ff9b:1::/48
    if segs[0] == 0x0064 && segs[1] == 0xff9b {
        if segs[2] == 0 && segs[3] == 0 && segs[4] == 0 && segs[5] == 0 {
            let v4 = Ipv4Addr::new(
                (segs[6] >> 8) as u8,
                (segs[6] & 0xff) as u8,
                (segs[7] >> 8) as u8,
                (segs[7] & 0xff) as u8,
            );
            return is_forbidden_ipv4(v4);
        }
        return true;
    }
    // 6to4: 2002::/16 (embeds IPv4 in segments 1..2)
    if segs[0] == 0x2002 {
        let v4 = Ipv4Addr::new(
            (segs[1] >> 8) as u8,
            (segs[1] & 0xff) as u8,
            (segs[2] >> 8) as u8,
            (segs[2] & 0xff) as u8,
        );
        return is_forbidden_ipv4(v4);
    }
    // Teredo (2001::/32), Documentation (2001:db8::/32), Discard (100::/64)
    if (segs[0] == 0x2001 && (segs[1] == 0 || segs[1] == 0x0db8))
        || (segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0)
    {
        return true;
    }
    // ULA fc00::/7
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local fe80::/10 and deprecated site-local fec0::/10
    if (segs[0] & 0xffc0) == 0xfe80 || (segs[0] & 0xffc0) == 0xfec0 {
        return true;
    }
    false
}

fn is_forbidden_hostname(domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.contains("..") {
        return true;
    }
    if d == "localhost"
        || d.ends_with(".localhost")
        || d.ends_with(".local")
        || d.ends_with(".internal")
        || d.ends_with(".localdomain")
        || d.ends_with(".arpa")
        || d == "metadata.google.internal"
        || !d.contains('.')
    {
        return true;
    }
    false
}

pub fn validate_webhook_url_syntax(
    raw: &str,
    allow_insecure_http: bool,
    allow_private_targets: bool,
) -> Result<ParsedWebhook, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_WEBHOOK_URL_LEN {
        return Err(format!("webhook_url must be 1-{MAX_WEBHOOK_URL_LEN} bytes"));
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("webhook_url must not contain whitespace or control characters".into());
    }
    let url = Url::parse(trimmed).map_err(|_| "webhook_url is not a valid URL".to_string())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("webhook_url must not contain embedded credentials".into());
    }
    if url.fragment().is_some() {
        return Err("webhook_url must not contain a URL fragment".into());
    }
    match url.scheme() {
        "https" => {}
        "http" if allow_insecure_http => {}
        "http" => {
            return Err(
                "webhook_url must use https:// unless allow_insecure_webhooks is enabled".into(),
            )
        }
        _ => return Err("webhook_url scheme must be https (or http when enabled)".into()),
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "webhook_url must have a valid port".to_string())?;
    let (host, is_ip_literal) = match url.host() {
        Some(Host::Ipv4(ip)) => {
            if !allow_private_targets && is_forbidden_ip(IpAddr::V4(ip)) {
                return Err("webhook_url points to a blocked IPv4 network".into());
            }
            (ip.to_string(), true)
        }
        Some(Host::Ipv6(ip)) => {
            if !allow_private_targets && is_forbidden_ip(IpAddr::V6(ip)) {
                return Err("webhook_url points to a blocked IPv6 network".into());
            }
            (ip.to_string(), true)
        }
        Some(Host::Domain(domain)) => {
            if !allow_private_targets && is_forbidden_hostname(domain) {
                return Err("webhook_url hostname is not permitted".into());
            }
            (domain.to_string(), false)
        }
        None => return Err("webhook_url must include a host".into()),
    };
    Ok(ParsedWebhook {
        url,
        host,
        port,
        is_ip_literal,
    })
}

/// Validates webhook syntax on rule creation and blocks domains that currently
/// resolve to forbidden/private/metadata IP ranges.
pub async fn validate_webhook_on_create(
    raw: &str,
    allow_insecure_http: bool,
    allow_private_targets: bool,
) -> Result<String, String> {
    let parsed = validate_webhook_url_syntax(raw, allow_insecure_http, allow_private_targets)?;
    if !parsed.is_ip_literal && !allow_private_targets {
        if let Ok(Ok(addrs)) = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::lookup_host((parsed.host.as_str(), parsed.port)),
        )
        .await
        {
            for addr in addrs {
                if is_forbidden_ip(addr.ip()) {
                    return Err("webhook_url resolved to a blocked private/internal IP".into());
                }
            }
        }
    }
    Ok(parsed.url.to_string())
}

/// Re-validates the webhook target right before dispatch and pins a single
/// verified IP address so DNS rebinding cannot occur between lookup and TCP connect.
pub async fn resolve_and_pin_webhook(
    raw: &str,
    allow_insecure_http: bool,
    allow_private_targets: bool,
) -> Result<(Url, Option<(String, SocketAddr)>), String> {
    let parsed = validate_webhook_url_syntax(raw, allow_insecure_http, allow_private_targets)?;
    if parsed.is_ip_literal {
        return Ok((parsed.url, None));
    }
    let addrs: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((parsed.host.as_str(), parsed.port)),
    )
    .await
    .map_err(|_| "webhook DNS resolution timed out".to_string())?
    .map_err(|_| "webhook DNS resolution failed".to_string())?
    .collect();
    if addrs.is_empty() {
        return Err("webhook hostname resolved to no addresses".into());
    }
    if !allow_private_targets {
        for addr in &addrs {
            if is_forbidden_ip(addr.ip()) {
                return Err("webhook resolved to a blocked IP address".into());
            }
        }
    }
    Ok((parsed.url, Some((parsed.host, addrs[0]))))
}

pub async fn dispatch_webhook(
    raw: &str,
    payload: Value,
    allow_insecure_http: bool,
    allow_private_targets: bool,
) -> Result<(), String> {
    let (url, pin) =
        resolve_and_pin_webhook(raw, allow_insecure_http, allow_private_targets).await?;
    let mut builder = reqwest::Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5));
    if let Some((host, addr)) = pin {
        builder = builder.resolve(&host, addr);
    }
    let client = builder
        .build()
        .map_err(|_| "failed to construct webhook HTTP client".to_string())?;
    let resp = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|_| "webhook request failed".to_string())?;
    if !resp.status().is_success() {
        return Err(format!("webhook returned status {}", resp.status()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_ssrf_schemes_and_private_ranges() {
        assert!(
            validate_webhook_url_syntax("https://hooks.example.com/alert", false, false).is_ok()
        );
        assert!(
            validate_webhook_url_syntax("http://hooks.example.com/alert", false, false).is_err()
        );
        assert!(validate_webhook_url_syntax("http://hooks.example.com/alert", true, false).is_ok());
        assert!(validate_webhook_url_syntax("file:///etc/passwd", true, true).is_err());
        assert!(
            validate_webhook_url_syntax("https://user:pass@hooks.example.com/a", false, false)
                .is_err()
        );

        for blocked in [
            "https://127.0.0.1/hook",
            "https://10.0.0.5/hook",
            "https://172.16.0.1/hook",
            "https://192.168.1.1/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://100.64.0.1/hook",
            "https://0.0.0.0/hook",
            "https://[::1]/hook",
            "https://[fe80::1]/hook",
            "https://[fc00::1]/hook",
            "https://[fd12:3456::1]/hook",
            "https://[::ffff:127.0.0.1]/hook",
            "https://[::ffff:169.254.169.254]/hook",
            "https://localhost/hook",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://redis/hook",
        ] {
            assert!(
                validate_webhook_url_syntax(blocked, false, false).is_err(),
                "should block {blocked}"
            );
        }
        assert!(validate_webhook_url_syntax("https://127.0.0.1/hook", false, true).is_ok());
    }

    #[tokio::test]
    async fn resolve_and_pin_rejects_loopback_domain() {
        assert!(
            resolve_and_pin_webhook("https://localhost/hook", false, false)
                .await
                .is_err()
        );
        assert!(
            resolve_and_pin_webhook("http://localhost:8080/hook", true, true)
                .await
                .is_ok()
        );
    }
}
