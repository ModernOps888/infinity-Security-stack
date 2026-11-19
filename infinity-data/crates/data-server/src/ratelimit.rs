use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_TRACKED_IPS: usize = 100_000;

pub struct IpRateLimiter {
    limit: u32,
    max_entries: usize,
    state: Mutex<HashMap<String, (u64, u32)>>,
}

impl IpRateLimiter {
    pub fn new(limit_per_min: u32) -> Self {
        Self::with_capacity(limit_per_min, MAX_TRACKED_IPS)
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
        if !map.contains_key(ip) && map.len() >= self.max_entries {
            map.retain(|_, (w, _)| *w == window);
            if map.len() >= self.max_entries {
                // Fail closed when the active-window IP table is saturated by a cardinality flood.
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

    pub fn tracked_len(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_cardinality_within_single_window() {
        let limiter = IpRateLimiter::with_capacity(5, 3);
        assert!(limiter.allow("10.0.0.1"));
        assert!(limiter.allow("10.0.0.2"));
        assert!(limiter.allow("10.0.0.3"));
        assert!(!limiter.allow("10.0.0.4"));
        assert_eq!(limiter.tracked_len(), 3);
    }
}
