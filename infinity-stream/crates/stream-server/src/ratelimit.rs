//! Global per-IP fixed-window rate limiting with strict memory cap.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_MAX_ENTRIES: usize = 100_000;

pub struct IpRateLimiter {
    limit: u32,
    max_entries: usize,
    state: Mutex<HashMap<String, (u64, u32)>>,
}

impl IpRateLimiter {
    pub fn new(limit_per_min: u32) -> Self {
        Self::with_capacity(limit_per_min, DEFAULT_MAX_ENTRIES)
    }

    pub fn with_capacity(limit_per_min: u32, max_entries: usize) -> Self {
        Self {
            limit: limit_per_min,
            max_entries: max_entries.max(1),
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: &str) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window = now / 60;
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_entries && !map.contains_key(ip) {
            map.retain(|_, (w, _)| *w == window);
            if map.len() >= self.max_entries {
                // Table saturated within the active 60s window: fail closed
                // for unseen IPs rather than growing memory unboundedly.
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

    pub fn tracked_entries(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_memory_under_same_window_ip_flood() {
        let limiter = IpRateLimiter::with_capacity(10, 4);
        for i in 0..20 {
            let allowed = limiter.allow(&format!("192.0.2.{i}"));
            if i < 4 {
                assert!(allowed);
            } else {
                assert!(!allowed);
            }
        }
        assert_eq!(limiter.tracked_entries(), 4);
    }
}
