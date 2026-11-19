use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::http::HeaderMap;

pub fn random_token() -> String {
    data_core::security::random_token()
}

pub fn sha256_hex(input: &str) -> String {
    data_core::security::sha256_hex(input)
}

#[derive(Debug, Clone, Copy)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let addr = canonical_ip(ip_str.parse().ok()?);
            let prefix: u8 = prefix_str.parse().ok()?;
            let max = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return None;
            }
            Some(Self { addr, prefix })
        } else {
            let addr = canonical_ip(s.parse().ok()?);
            let prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Some(Self { addr, prefix })
        }
    }

    pub fn contains(&self, candidate: IpAddr) -> bool {
        let candidate = canonical_ip(candidate);
        match (self.addr, candidate) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix);
                (u32::from(a) & mask) == (u32::from(b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix);
                (u128::from(a) & mask) == (u128::from(b) & mask)
            }
            _ => false,
        }
    }
}

pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

pub fn parse_trusted_proxies(raw: &[String]) -> Vec<IpCidr> {
    raw.iter().filter_map(|s| IpCidr::parse(s)).collect()
}

/// Extracts the client IP without trusting spoofed `X-Forwarded-For` headers.
/// `X-Forwarded-For` is ONLY consulted when the direct TCP peer (`ConnectInfo`)
/// is an explicitly configured trusted proxy, and is walked right-to-left
/// skipping trusted proxy hops.
pub fn extract_client_ip(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted_proxies: &[IpCidr],
) -> String {
    let Some(peer_addr) = peer else {
        return "unknown".into();
    };
    let peer_ip = canonical_ip(peer_addr.ip());
    if trusted_proxies.is_empty() || !trusted_proxies.iter().any(|p| p.contains(peer_ip)) {
        return peer_ip.to_string();
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for part in xff.rsplit(',') {
            let trimmed = part.trim();
            if let Ok(parsed) = trimmed.parse::<IpAddr>() {
                let ip = canonical_ip(parsed);
                if !trusted_proxies.iter().any(|p| p.contains(ip)) {
                    return ip.to_string();
                }
            } else {
                // Stop on malformed XFF entry rather than walking into attacker-controlled prefix.
                break;
            }
        }
    }
    peer_ip.to_string()
}

pub fn sanitize_user_agent(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())?;
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).take(256).collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub fn is_loopback_http_origin(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let host = if let Some(after_bracket) = authority.strip_prefix('[') {
        let Some((inner, tail)) = after_bracket.split_once(']') else {
            return false;
        };
        if !tail.is_empty() && !tail.starts_with(':') {
            return false;
        }
        if let Some(port) = tail.strip_prefix(':') {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
        }
        inner
    } else if let Some((h, port)) = authority.split_once(':') {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        h
    } else {
        authority
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback() || v4 == Ipv4Addr::LOCALHOST,
        Ok(IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}
