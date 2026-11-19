use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ipnet::IpNet;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Generate a cryptographically-random opaque token (32 bytes, base64url).
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hex digest — used to store opaque tokens/sessions at rest.
pub fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn is_pkce_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn is_base64url_nopad(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

/// Validate a PKCE challenge + method at `/oauth/authorize` (S256 only).
pub fn validate_pkce_challenge(challenge: &str, method: Option<&str>) -> bool {
    if method != Some("S256") {
        return false;
    }
    // SHA-256 raw digest (32 bytes) base64url-encoded without padding is 43 chars.
    challenge.len() == 43 && challenge.bytes().all(is_base64url_nopad)
}

/// Verify a PKCE `code_verifier` against a stored challenge.
///
/// Strictly enforces `S256` only (RFC 7636 / RFC 9700) — `plain` is refused.
/// Also validates `verifier` length (43..=128) and unreserved charset, and uses
/// constant-time comparison.
pub fn verify_pkce(verifier: &str, challenge: &str, method: Option<&str>) -> bool {
    if method != Some("S256") {
        return false;
    }
    if !(43..=128).contains(&verifier.len()) || !verifier.bytes().all(is_pkce_unreserved) {
        return false;
    }
    if challenge.len() != 43 || !challenge.bytes().all(is_base64url_nopad) {
        return false;
    }
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(h.finalize());
    infinity_core::password::constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

/// Validate an OAuth 2.0 `redirect_uri` strictly (RFC 6749 / RFC 9700).
///
/// Rejects fragments (`#`), control characters/CRLF, wildcards (`*`),
/// userinfo (`user@host`), dangerous schemes (`javascript:`, `data:`, `file:`,
/// etc.), and non-loopback plaintext `http://` URIs.
pub fn validate_redirect_uri(uri: &str) -> Result<String, &'static str> {
    if uri.is_empty() || uri != uri.trim() {
        return Err("redirect_uri must be non-empty without leading/trailing whitespace");
    }
    if uri.chars().any(|c| c.is_control()) {
        return Err("redirect_uri must not contain control characters");
    }
    if uri.contains('#') {
        return Err("redirect_uri must not contain a fragment");
    }
    let parsed = url::Url::parse(uri).map_err(|_| "redirect_uri must be an absolute URL")?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("redirect_uri must not contain userinfo");
    }
    if parsed.fragment().is_some() {
        return Err("redirect_uri must not contain a fragment");
    }
    let host = parsed.host_str().ok_or("redirect_uri must have a host")?;
    if host.is_empty() || host.contains('*') {
        return Err("redirect_uri host must not contain wildcards");
    }
    match parsed.scheme() {
        "https" => {}
        "http" => {
            if !matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1") {
                return Err("plaintext http redirect_uri is permitted only for loopback hosts");
            }
        }
        _ => return Err("redirect_uri scheme must be https (or loopback http)"),
    }
    Ok(uri.to_string())
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn canonical_ip_net(net: IpNet) -> IpNet {
    match net {
        IpNet::V6(v6net) if v6net.prefix_len() >= 96 => {
            if let Some(v4) = v6net.network().to_ipv4_mapped() {
                if let Ok(v4net) = ipnet::Ipv4Net::new(v4, v6net.prefix_len() - 96) {
                    return IpNet::V4(v4net.trunc());
                }
            }
            IpNet::V6(v6net)
        }
        other => other,
    }
}

fn is_trusted_proxy(ip: IpAddr, trusted: &[IpNet]) -> bool {
    let canon = canonical_ip(ip);
    trusted
        .iter()
        .any(|net| net.contains(&canon) || net.contains(&ip))
}

/// Parse configured `trusted_proxies` entries (CIDRs or single IPs).
pub fn parse_trusted_proxies(entries: &[String]) -> Vec<IpNet> {
    entries
        .iter()
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            trimmed
                .parse::<IpNet>()
                .ok()
                .map(canonical_ip_net)
                .or_else(|| {
                    trimmed
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| IpNet::from(canonical_ip(ip)))
                })
        })
        .collect()
}

/// Resolve the effective client IP with an explicit trusted-proxy boundary.
///
/// `X-Forwarded-For` is ignored unless the direct TCP peer (`peer_ip`) falls
/// within `trusted_proxies`. When trusted, walks all `X-Forwarded-For` header
/// instances right-to-left and returns the first non-trusted IP.
pub fn resolve_client_ip(peer_ip: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let peer_ip = canonical_ip(peer_ip);
    if trusted.is_empty() || !is_trusted_proxy(peer_ip, trusted) {
        return peer_ip;
    }
    for hv in headers.get_all("x-forwarded-for").iter().rev() {
        let Ok(xff) = hv.to_str() else {
            return peer_ip;
        };
        for part in xff.rsplit(',') {
            let candidate = part.trim();
            let Ok(parsed) = candidate.parse::<IpAddr>() else {
                return peer_ip;
            };
            let ip = canonical_ip(parsed);
            if !is_trusted_proxy(ip, trusted) {
                return ip;
            }
        }
    }
    peer_ip
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_enforces_s256_only_and_charset() {
        let verifier = "a".repeat(43);
        let mut h = Sha256::new();
        h.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(h.finalize());

        assert!(verify_pkce(&verifier, &challenge, Some("S256")));
        assert!(!verify_pkce(&verifier, &verifier, Some("plain")));
        assert!(!verify_pkce(&verifier, &verifier, None));
        assert!(!verify_pkce("short", &challenge, Some("S256")));
        assert!(!verify_pkce(
            &format!("{verifier}!"),
            &challenge,
            Some("S256")
        ));
    }

    #[test]
    fn redirect_uri_validation_blocks_dangerous_uris() {
        assert!(validate_redirect_uri("https://client.example/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:3000/cb?foo=1").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1:8080/cb").is_ok());

        assert!(validate_redirect_uri("javascript:alert(1)").is_err());
        assert!(validate_redirect_uri("data:text/html,<script>alert(1)</script>").is_err());
        assert!(validate_redirect_uri("https://client.example/cb#frag").is_err());
        assert!(validate_redirect_uri("https://client.example/cb\r\nLocation: evil").is_err());
        assert!(validate_redirect_uri("https://*.client.example/cb").is_err());
        assert!(validate_redirect_uri("https://good@evil.example/cb").is_err());
        assert!(validate_redirect_uri("http://evil.example/cb").is_err());
        assert!(validate_redirect_uri("/relative/cb").is_err());
    }

    #[test]
    fn client_ip_ignores_spoofed_xff_unless_trusted_proxy() {
        let peer: IpAddr = "203.0.113.5".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.77".parse().unwrap());

        assert_eq!(resolve_client_ip(peer, &headers, &[]), peer);

        let trusted = parse_trusted_proxies(&["10.0.0.0/8".into()]);
        assert_eq!(resolve_client_ip(peer, &headers, &trusted), peer);

        let proxy_peer: IpAddr = "10.0.0.4".parse().unwrap();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.77, 10.0.0.2".parse().unwrap(),
        );
        assert_eq!(
            resolve_client_ip(proxy_peer, &headers, &trusted),
            "198.51.100.77".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_client_ip_handles_multi_header_xff_and_ipv4_mapped_ipv6() {
        let trusted =
            parse_trusted_proxies(&["10.0.0.0/8".into(), "::ffff:192.168.1.0/120".into()]);
        let dual_stack_peer: IpAddr = "::ffff:10.0.0.2".parse().unwrap();

        let mut headers = HeaderMap::new();
        headers.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("1.2.3.4"),
        );
        headers.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("203.0.113.55, ::ffff:192.168.1.9"),
        );
        assert_eq!(
            resolve_client_ip(dual_stack_peer, &headers, &trusted),
            "203.0.113.55".parse::<IpAddr>().unwrap()
        );

        let mut bad = HeaderMap::new();
        bad.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("1.2.3.4"),
        );
        bad.append(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("bad-hop"),
        );
        assert_eq!(
            resolve_client_ip(dual_stack_peer, &bad, &trusted),
            "10.0.0.2".parse::<IpAddr>().unwrap()
        );
    }
}
