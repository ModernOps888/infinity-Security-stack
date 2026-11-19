//! In-memory login throttling with temporary account lockout and bounded memory.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_MAX_ENTRIES: usize = 100_000;

struct Entry {
    window_start: u64,
    fails: u32,
    locked_until: u64,
}

pub struct LoginThrottle {
    max_fails: u32,
    window_secs: u64,
    lockout_secs: u64,
    max_entries: usize,
    state: Mutex<HashMap<String, Entry>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl LoginThrottle {
    pub fn new(max_fails: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self::with_capacity(max_fails, window_secs, lockout_secs, DEFAULT_MAX_ENTRIES)
    }

    pub fn with_capacity(
        max_fails: u32,
        window_secs: u64,
        lockout_secs: u64,
        max_entries: usize,
    ) -> Self {
        Self {
            max_fails,
            window_secs,
            lockout_secs,
            max_entries: max_entries.max(1),
            state: Mutex::new(HashMap::new()),
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

    pub fn record_failure(&self, key: &str) {
        let now = now();
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_entries && !map.contains_key(key) {
            map.retain(|_, e| {
                e.locked_until > now || now.saturating_sub(e.window_start) <= self.window_secs
            });
            if map.len() >= self.max_entries {
                // Evict oldest non-locked entries (or oldest overall) to stay
                // strictly bounded even under identifier-spraying attacks.
                let evict_target = (self.max_entries / 10).max(1);
                let mut candidates: Vec<(String, u64, bool)> = map
                    .iter()
                    .map(|(k, e)| (k.clone(), e.window_start, e.locked_until > now))
                    .collect();
                candidates.sort_by_key(|(_, ws, locked)| (*locked, *ws));
                for (old_key, _, _) in candidates.into_iter().take(evict_target) {
                    map.remove(&old_key);
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
        if e.fails >= self.max_fails {
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

    pub fn tracked_entries(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new(10, 15 * 60, 15 * 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_bounds_memory_under_identifier_spray() {
        let t = LoginThrottle::with_capacity(5, 900, 900, 10);
        for i in 0..50 {
            t.record_failure(&format!("user{i}@example.com"));
        }
        assert!(t.tracked_entries() <= 10);
    }
}
