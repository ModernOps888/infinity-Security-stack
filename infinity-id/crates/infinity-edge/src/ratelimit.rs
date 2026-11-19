//! Simple per-IP fixed-window rate limiter (60s windows).
//!
//! Deliberately dependency-free and lock-light: a single mutex guarding a map
//! of `ip -> (window_start, count)`. Good enough to shield upstreams from
//! abusive spikes; swap for a distributed limiter (Redis/GCRA) at scale.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TRACKED_IPS: usize = 100_000;

pub struct RateLimiter {
    limit: u32,
    max_entries: usize,
    state: Mutex<HashMap<String, (u64, u32)>>,
}

impl RateLimiter {
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

    /// Returns true if the request is allowed, false if the limit is exceeded.
    pub fn allow(&self, key: &str) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window = now / 60;
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Bound memory under IP churn by pruning stale windows first.
        if !map.contains_key(key) && map.len() >= self.max_entries {
            map.retain(|_, (w, _)| *w == window);
            // Fail closed inside the active window once the cap is reached.
            if map.len() >= self.max_entries {
                return false;
            }
        }
        let entry = map.entry(key.to_string()).or_insert((window, 0));
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
    fn rate_limiter_enforces_cap_and_zero_disables() {
        let lim = RateLimiter::new(2);
        assert!(lim.allow("10.0.0.1"));
        assert!(lim.allow("10.0.0.1"));
        assert!(!lim.allow("10.0.0.1"));
        assert!(lim.allow("10.0.0.2"));

        let unlimited = RateLimiter::new(0);
        for _ in 0..10 {
            assert!(unlimited.allow("10.0.0.1"));
        }
    }

    #[test]
    fn caps_unseen_keys_within_single_window() {
        let lim = RateLimiter::with_max_entries(2, 2);
        assert!(lim.allow("10.0.0.1"));
        assert!(lim.allow("10.0.0.2"));
        assert!(!lim.allow("10.0.0.3"));
        assert_eq!(lim.state.lock().unwrap().len(), 2);
        assert!(lim.allow("10.0.0.1"));
        assert!(!lim.allow("10.0.0.1"));
    }
}
