//! Global per-IP request rate limiting (fixed 60s windows).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TRACKED_IPS: usize = 100_000;

pub struct IpRateLimiter {
    limit: u32,
    state: Mutex<HashMap<String, (u64, u32)>>,
}

impl IpRateLimiter {
    pub fn new(limit_per_min: u32) -> Self {
        Self {
            limit: limit_per_min,
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
        if map.len() >= MAX_TRACKED_IPS {
            map.retain(|_, (w, _)| *w == window);
            if map.len() >= MAX_TRACKED_IPS && !map.contains_key(ip) {
                // Fail closed for untracked new keys during active flood instead of OOM.
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
