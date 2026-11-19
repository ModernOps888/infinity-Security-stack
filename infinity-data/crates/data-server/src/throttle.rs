use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_THROTTLE_ENTRIES: usize = 100_000;

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
        Self::with_capacity(max_fails, window_secs, lockout_secs, MAX_THROTTLE_ENTRIES)
    }

    pub fn with_capacity(
        max_fails: u32,
        window_secs: u64,
        lockout_secs: u64,
        max_entries: usize,
    ) -> Self {
        Self {
            max_fails: max_fails.max(1),
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
        self.record_failure_with_limit(key, self.max_fails);
    }

    pub fn record_failure_with_limit(&self, key: &str, max_fails: u32) {
        let now = now();
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(key) && map.len() >= self.max_entries {
            map.retain(|_, e| {
                e.locked_until > now || now.saturating_sub(e.window_start) <= self.window_secs
            });
            // If all entries are still within the active window, evict the oldest unlocked entry
            // first (preserving active lockouts) so memory remains strictly bounded.
            if map.len() >= self.max_entries {
                let victim = map
                    .iter()
                    .filter(|(_, e)| e.locked_until <= now)
                    .min_by_key(|(_, e)| e.window_start)
                    .map(|(k, _)| k.clone())
                    .or_else(|| {
                        map.iter()
                            .min_by_key(|(_, e)| e.window_start)
                            .map(|(k, _)| k.clone())
                    });
                if let Some(k) = victim {
                    map.remove(&k);
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
        if e.fails >= max_fails.max(1) {
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

    pub fn tracked_len(&self) -> usize {
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
    fn throttle_eviction_preserves_memory_bound_and_lockouts() {
        let t = LoginThrottle::with_capacity(2, 900, 900, 3);
        t.record_failure("locked@infinity.local");
        t.record_failure("locked@infinity.local");
        assert!(t.check("locked@infinity.local").is_err());

        t.record_failure("u1@infinity.local");
        t.record_failure("u2@infinity.local");
        t.record_failure("u3@infinity.local");
        assert_eq!(t.tracked_len(), 3);
        assert!(t.check("locked@infinity.local").is_err());
    }
}
