use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Datelike, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

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

pub fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

pub fn has_control_or_bidi(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || is_bidi_control(c))
}

/// Replaces CR/LF/tabs with spaces and strips NUL, ANSI/C0/C1 control characters,
/// and Unicode bidirectional overrides to defeat log/CRLF injection.
pub fn sanitize_log_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\r' || c == '\n' || c == '\t' {
            out.push(' ');
        } else if c.is_control() || is_bidi_control(c) {
            continue;
        } else {
            out.push(c);
        }
    }
    out
}

/// Escapes SQL LIKE wildcards (`\`, `%`, `_`) for use with `LIKE ? ESCAPE '\'`.
pub fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Parses an RFC3339 timestamp, rejects pre-epoch (negative Unix timestamps)
/// or far-future years (> 2100), and normalizes to canonical UTC RFC3339.
pub fn normalize_utc_rfc3339(raw: &str) -> Result<String, &'static str> {
    let dt = chrono::DateTime::parse_from_rfc3339(raw.trim()).map_err(|_| "must be RFC3339")?;
    let utc = dt.with_timezone(&Utc);
    if utc.timestamp() < 0 {
        return Err("timestamp must not be negative (pre-1970)");
    }
    if utc.year() > 2100 {
        return Err("timestamp year out of range");
    }
    Ok(utc.to_rfc3339())
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

fn ip_in_cidr(ip: IpAddr, entry: &str) -> bool {
    let ip = canonical_ip(ip);
    let trimmed = entry.trim();
    let Some((net_str, prefix_str)) = trimmed.split_once('/') else {
        return trimmed
            .parse::<IpAddr>()
            .map(|a| canonical_ip(a) == ip)
            .unwrap_or(false);
    };
    let Ok(net_ip) = net_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    let (net_ip, prefix) = match net_ip {
        IpAddr::V6(v6) if prefix >= 96 => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                (IpAddr::V4(v4), prefix - 96)
            } else {
                (IpAddr::V6(v6), prefix)
            }
        }
        other => (other, prefix),
    };
    match (ip, net_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

pub fn is_trusted_proxy(ip: IpAddr, trusted_proxies: &[String]) -> bool {
    let ip = canonical_ip(ip);
    trusted_proxies.iter().any(|entry| ip_in_cidr(ip, entry))
}

/// Extracts client IP enforcing the XFF trust boundary: `X-Forwarded-For` and
/// `X-Real-IP` are ignored unless the direct TCP peer belongs to `trusted_proxies`.
pub fn extract_client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted_proxies: &[String],
) -> String {
    let Some(peer_addr) = peer else {
        return "unknown".into();
    };
    let peer_ip = canonical_ip(peer_addr.ip());
    if !is_trusted_proxy(peer_ip, trusted_proxies) {
        return peer_ip.to_string();
    }
    if headers.contains_key("x-forwarded-for") {
        let mut xff_vals = Vec::new();
        for hv in headers.get_all("x-forwarded-for") {
            let Ok(s) = hv.to_str() else {
                return peer_ip.to_string();
            };
            xff_vals.push(s);
        }
        'xff_walk: for val in xff_vals.into_iter().rev() {
            for raw_hop in val.split(',').rev() {
                let Ok(parsed) = raw_hop.trim().parse::<IpAddr>() else {
                    break 'xff_walk;
                };
                let hop_ip = canonical_ip(parsed);
                if !is_trusted_proxy(hop_ip, trusted_proxies) {
                    return hop_ip.to_string();
                }
            }
        }
        return peer_ip.to_string();
    }
    if let Some(xri) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        let xri = canonical_ip(xri);
        if !is_trusted_proxy(xri, trusted_proxies) {
            return xri.to_string();
        }
    }
    peer_ip.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn xff_ignored_when_peer_untrusted_and_honored_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.7, 10.0.0.5"),
        );
        let untrusted_peer = Some(SocketAddr::from(([203, 0, 113, 9], 1234)));
        assert_eq!(
            extract_client_ip(&headers, untrusted_peer, &["10.0.0.0/8".into()]),
            "203.0.113.9"
        );
        let trusted_peer = Some(SocketAddr::from(([10, 0, 0, 1], 1234)));
        assert_eq!(
            extract_client_ip(&headers, trusted_peer, &["10.0.0.0/8".into()]),
            "198.51.100.7"
        );
    }

    #[test]
    fn xff_canonicalizes_ipv4_mapped_ipv6_and_breaks_on_malformed_hop() {
        let mapped_peer = Some(SocketAddr::new("::ffff:10.0.0.1".parse().unwrap(), 1234));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.9, ::ffff:10.0.0.5"),
        );
        assert_eq!(
            extract_client_ip(&headers, mapped_peer, &["10.0.0.0/8".into()]),
            "198.51.100.9"
        );

        let mut malformed = HeaderMap::new();
        malformed.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.9, not-an-ip, 10.0.0.5"),
        );
        assert_eq!(
            extract_client_ip(&malformed, mapped_peer, &["10.0.0.0/8".into()]),
            "10.0.0.1"
        );
    }

    #[test]
    fn normalizes_utc_and_rejects_negative_timestamps() {
        assert!(normalize_utc_rfc3339("1969-12-31T23:59:59Z").is_err());
        assert!(normalize_utc_rfc3339("2026-11-19T22:00:00+02:00")
            .unwrap()
            .starts_with("2026-11-19T20:00:00"));
    }

    #[test]
    fn escapes_like_and_sanitizes_crlf() {
        assert_eq!(escape_like(r"a%b_c\d"), r"a\%b\_c\\d");
        assert_eq!(sanitize_log_text("a\r\nb\x1b[31mc"), "a  b[31mc");
    }
}
