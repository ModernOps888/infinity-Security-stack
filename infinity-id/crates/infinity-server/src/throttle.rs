//! In-memory login throttling with temporary account lockout.
//!
//! Protects `/auth/login` and the password grant against online brute-force
//! attacks. Keyed by a caller-supplied identifier (email). Failures within a
//! rolling window accumulate; exceeding the threshold locks the key for a
//! cool-off period. Successful auth resets the counter.
//!
//! This is intentionally simple/in-process. For multi-node deployments back it
//! with a shared store (e.g. Redis) — see the deployment docs.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

struct Entry {
    window_start: u64,
    fails: u32,
    locked_until: u64,
}

const MAX_THROTTLE_KEYS: usize = 100_000;

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
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl LoginThrottle {
    pub fn new(max_fails: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self {
            max_fails,
            window_secs,
            lockout_secs,
            max_entries: MAX_THROTTLE_KEYS,
            state: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn with_max_entries(
        max_fails: u32,
        window_secs: u64,
        lockout_secs: u64,
        max_entries: usize,
    ) -> Self {
        Self {
            max_fails,
            window_secs,
            lockout_secs,
            max_entries,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `Err(retry_after_secs)` if the key is currently locked out.
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

    /// Record a failed attempt; locks the key if the threshold is reached.
    pub fn record_failure(&self, key: &str) {
        self.record_failure_with_threshold(key, self.max_fails);
    }

    /// Record a failed attempt with an explicit per-key failure threshold
    /// (e.g. a stricter cap for MFA/OTP attempts).
    pub fn record_failure_with_threshold(&self, key: &str, max_fails: u32) {
        let now = now();
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Bound memory: prune stale/idle entries first, then evict unlocked
        // low-failure entries inside the active window so the ceiling holds.
        if !map.contains_key(key) && map.len() >= self.max_entries {
            if self.max_entries == 0 {
                return;
            }
            map.retain(|_, e| {
                e.locked_until > now
                    || (e.fails > 0 && now.saturating_sub(e.window_start) <= self.window_secs)
            });
            if map.len() >= self.max_entries {
                let target_len = self
                    .max_entries
                    .saturating_sub((self.max_entries / 10).max(1));
                let need_remove = map.len().saturating_sub(target_len);
                let victims: Vec<String> = map
                    .iter()
                    .filter(|(_, e)| e.locked_until <= now && e.fails <= 1)
                    .take(need_remove)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in &victims {
                    map.remove(k);
                }
                let remaining = need_remove.saturating_sub(victims.len());
                if remaining > 0 {
                    let mut ranked: Vec<((bool, u32, u64, u64), String)> = map
                        .iter()
                        .map(|(k, e)| {
                            (
                                (
                                    e.locked_until > now,
                                    e.fails,
                                    e.locked_until,
                                    e.window_start,
                                ),
                                k.clone(),
                            )
                        })
                        .collect();
                    ranked.sort_by(|a, b| a.0.cmp(&b.0));
                    for (_, k) in ranked.into_iter().take(remaining) {
                        map.remove(&k);
                    }
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
            e.locked_until = now + self.lockout_secs;
            e.fails = 0;
            e.window_start = now;
        }
    }

    /// Clear counters for a key after a successful authentication.
    pub fn record_success(&self, key: &str) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }
}

impl Default for LoginThrottle {
    fn default() -> Self {
        // 10 failures within 15 minutes -> 15 minute lockout.
        Self::new(10, 15 * 60, 15 * 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_threshold_and_resets_on_success() {
        let t = LoginThrottle::new(3, 60, 120);
        assert!(t.check("u@example.com").is_ok());
        t.record_failure("u@example.com");
        t.record_failure("u@example.com");
        assert!(t.check("u@example.com").is_ok());
        t.record_failure("u@example.com");
        assert!(t.check("u@example.com").is_err());

        t.record_success("u@example.com");
        assert!(t.check("u@example.com").is_ok());
    }

    #[test]
    fn caps_entries_within_single_window_and_preserves_lockouts() {
        let t = LoginThrottle::with_max_entries(2, 60, 120, 3);
        t.record_failure("locked@example.com");
        t.record_failure("locked@example.com");
        assert!(t.check("locked@example.com").is_err());

        t.record_failure("noise1@example.com");
        t.record_failure("noise2@example.com");
        assert_eq!(t.state.lock().unwrap().len(), 3);

        // Fourth distinct key in same window must evict unlocked noise, keeping total <= 3
        // and keeping `locked@example.com` locked.
        t.record_failure("noise3@example.com");
        assert!(t.state.lock().unwrap().len() <= 3);
        assert!(t.check("locked@example.com").is_err());
    }
}
