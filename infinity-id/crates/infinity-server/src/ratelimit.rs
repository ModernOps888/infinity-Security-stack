//! Global per-IP request rate limiting (fixed 60s windows).
//!
//! Shields the identity server from unauthenticated request floods — important
//! because Argon2id verification is deliberately CPU/memory intensive. Login
//! attempts are additionally throttled per-account (see `throttle`).
//!
//! In-process only; front with a distributed limiter for multi-node clusters.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TRACKED_IPS: usize = 100_000;

pub struct IpRateLimiter {
    limit: u32,
    max_entries: usize,
    state: Mutex<HashMap<String, (u64, u32)>>,
}

impl IpRateLimiter {
    pub fn new(limit_per_min: u32) -> Self {
        Self {
            limit: limit_per_min,
            max_entries: MAX_TRACKED_IPS,
            state: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn with_max_entries(limit_per_min: u32, max_entries: usize) -> Self {
        Self {
            limit: limit_per_min,
            max_entries,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the request from `ip` is allowed this window.
    pub fn allow(&self, ip: &str) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window = now / 60;
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(ip) && map.len() >= self.max_entries {
            // Opportunistic cleanup to bound memory under IP churn.
            map.retain(|_, (w, _)| *w == window);
            // Fail closed inside the active window once the cap is reached.
            if map.len() >= self.max_entries {
                return false;
            }
        }
        let entry = map.entry(ip.to_string()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_limit_and_allows_zero_disabled() {
        let lim = IpRateLimiter::new(2);
        assert!(lim.allow("1.2.3.4"));
        assert!(lim.allow("1.2.3.4"));
        assert!(!lim.allow("1.2.3.4"));
        assert!(lim.allow("5.6.7.8"));

        let off = IpRateLimiter::new(0);
        for _ in 0..10 {
            assert!(off.allow("1.2.3.4"));
        }
    }

    #[test]
    fn caps_unseen_ips_within_single_window() {
        let lim = IpRateLimiter::with_max_entries(2, 2);
        assert!(lim.allow("10.0.0.1"));
        assert!(lim.allow("10.0.0.2"));
        // Unseen IP inside the same window fails closed without growing map.
        assert!(!lim.allow("10.0.0.3"));
        assert_eq!(lim.state.lock().unwrap().len(), 2);
        // Existing tracked IPs still retain their per-window budget.
        assert!(lim.allow("10.0.0.1"));
        assert!(!lim.allow("10.0.0.1"));
    }
}
