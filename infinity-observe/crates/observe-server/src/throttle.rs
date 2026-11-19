//! In-memory login throttling with temporary account lockout.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_THROTTLE_ENTRIES: usize = 100_000;

struct Entry {
    window_start: u64,
    fails: u32,
    locked_until: u64,
}

pub struct LoginThrottle {
    max_fails: u32,
    ip_max_fails: u32,
    window_secs: u64,
    lockout_secs: u64,
    state: Mutex<HashMap<String, Entry>>,
    ip_state: Mutex<HashMap<String, Entry>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl LoginThrottle {
    pub fn new(max_fails: u32, window_secs: u64, lockout_secs: u64) -> Self {
        let ip_max_fails = max_fails.saturating_mul(10).max(20);
        Self {
            max_fails,
            ip_max_fails,
            window_secs,
            lockout_secs,
            state: Mutex::new(HashMap::new()),
            ip_state: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, key: &str) -> Result<(), u64> {
        let now = now();
        let map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = map.get(key) {
            if e.locked_until > now {
                return Err(e.locked_until - now);
            }
        }
        Ok(())
    }

    pub fn check_ip(&self, ip: &str) -> Result<(), u64> {
        let now = now();
        let map = self.ip_state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = map.get(ip) {
            if e.locked_until > now {
                return Err(e.locked_until - now);
            }
        }
        Ok(())
    }

    pub fn record_failure(&self, key: &str) {
        self.record_in_map(&self.state, key, self.max_fails);
    }

    pub fn record_ip_failure(&self, ip: &str) {
        self.record_in_map(&self.ip_state, ip, self.ip_max_fails);
    }

    fn record_in_map(&self, lock: &Mutex<HashMap<String, Entry>>, key: &str, max_fails: u32) {
        let now = now();
        let mut map = lock.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_THROTTLE_ENTRIES {
            map.retain(|_, e| {
                e.locked_until > now || now.saturating_sub(e.window_start) <= self.window_secs
            });
            if map.len() >= MAX_THROTTLE_ENTRIES && !map.contains_key(key) {
                // Evict oldest unlocked entries to strictly cap memory usage.
                let drop_keys: Vec<String> = map
                    .iter()
                    .filter(|(_, e)| e.locked_until <= now)
                    .take(1_024)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in drop_keys {
                    map.remove(&k);
                }
                if map.len() >= MAX_THROTTLE_ENTRIES {
                    return;
                }
            }
        }
        let e = map.entry(key.to_string()).or_insert(Entry {
            window_start: now,
            fails: 0,
            locked_until: 0,
        });
        if now.saturating_sub(e.window_start) > self.window_secs {
            e.window_start = now;
            e.fails = 0;
        }
        e.fails = e.fails.saturating_add(1);
        if e.fails >= max_fails {
            e.locked_until = now.saturating_add(self.lockout_secs);
            e.fails = 0;
            e.window_start = now;
        }
    }

    pub fn record_success(&self, key: &str) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    pub fn record_ip_success(&self, ip: &str) {
        self.ip_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(ip);
    }
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new(10, 15 * 60, 15 * 60)
    }
}
