//! Multi-factor authentication: TOTP (RFC 6238) + single-use recovery codes.
//!
//! TOTP interoperates with Google Authenticator, Authy, 1Password, etc.
//! Recovery codes are shown once and stored only as SHA-256 hashes.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use rand::{rngs::OsRng, Rng, RngCore};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Generate a fresh base32-encoded 160-bit TOTP secret using OS CSPRNG.
pub fn generate_secret() -> String {
    let mut raw = Zeroizing::new([0u8; 20]);
    OsRng.fill_bytes(&mut *raw);
    match Secret::Raw(raw.to_vec()).to_encoded() {
        Secret::Encoded(s) => s,
        // `to_encoded` always yields the Encoded variant; this arm is unreachable.
        Secret::Raw(_) => unreachable!("to_encoded always returns Encoded"),
    }
}

fn totp(secret_b32: &str, issuer: &str, account: &str) -> Result<TOTP> {
    if issuer.contains(':') {
        return Err(CoreError::Invalid("mfa_issuer must not contain ':'".into()));
    }
    let bytes = Zeroizing::new(
        Secret::Encoded(secret_b32.to_string())
            .to_bytes()
            .map_err(|e| CoreError::Mfa(format!("decode secret: {e:?}")))?,
    );
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes.to_vec(),
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|e| CoreError::Mfa(e.to_string()))
}

/// Build the `otpauth://` provisioning URI for QR-code enrolment.
pub fn provisioning_uri(secret_b32: &str, issuer: &str, account: &str) -> Result<String> {
    Ok(totp(secret_b32, issuer, account)?.get_url())
}

/// Verify a 6-digit TOTP code (±1 step of clock skew tolerance) in constant time.
pub fn verify_totp(secret_b32: &str, code: &str, issuer: &str, account: &str) -> Result<bool> {
    Ok(verify_totp_step(secret_b32, code, issuer, account, 0)?.is_some())
}

/// Verify a TOTP code and, on success, return the matched time-step.
///
/// Only steps strictly newer than the caller's high-water mark are accepted
/// (pass `last_step + 1` as `min_step`), so a single code cannot be replayed
/// within its ±1-step skew window once it has been consumed. Returns `None`
/// when the code does not match an allowed step.
pub fn verify_totp_step(
    secret_b32: &str,
    code: &str,
    issuer: &str,
    account: &str,
    min_step: u64,
) -> Result<Option<u64>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CoreError::Mfa(e.to_string()))?
        .as_secs();
    verify_totp_step_at(secret_b32, code, issuer, account, min_step, now)
}

/// Deterministic helper for verifying a TOTP code at an explicit UNIX timestamp.
pub fn verify_totp_step_at(
    secret_b32: &str,
    code: &str,
    issuer: &str,
    account: &str,
    min_step: u64,
    unix_secs: u64,
) -> Result<Option<u64>> {
    const STEP: u64 = 30;
    let t = totp(secret_b32, issuer, account)?;
    let candidate = code.trim();
    if candidate.len() != 6 || !candidate.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let current = unix_secs / STEP;
    // Evaluate all three skew steps in constant time and keep the highest match
    // so response timing does not distinguish which step in the window matched.
    let mut matched: Option<u64> = None;
    for cand in [current + 1, current, current.saturating_sub(1)] {
        let expected = t.generate(cand * STEP);
        let eq = crate::password::constant_time_eq(expected.as_bytes(), candidate.as_bytes());
        if cand >= min_step && eq && matched.is_none() {
            matched = Some(cand);
        }
    }
    Ok(matched)
}

/// A generated recovery code plus the hash that should be persisted.
pub struct RecoveryCode {
    pub plaintext: String,
    pub hash: String,
}

/// Generate `count` single-use recovery codes formatted `xxxxx-xxxxx`.
pub fn generate_recovery_codes(count: usize) -> Vec<RecoveryCode> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    (0..count)
        .map(|_| {
            let raw: String = (0..10)
                .map(|i| {
                    let c = ALPHABET[OsRng.gen_range(0..ALPHABET.len())] as char;
                    if i == 5 {
                        format!("-{c}")
                    } else {
                        c.to_string()
                    }
                })
                .collect();
            let plaintext = raw;
            let hash = hash_recovery_code(&plaintext);
            RecoveryCode { plaintext, hash }
        })
        .collect()
}

/// Stable hash used to store/compare recovery codes.
pub fn hash_recovery_code(code: &str) -> String {
    let normalized = code.trim().to_ascii_lowercase();
    let mut h = Sha256::new();
    h.update(normalized.as_bytes());
    STANDARD_NO_PAD.encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_step_replay_protection_and_validation() {
        let secret = generate_secret();
        let issuer = "Infinity ID";
        let account = "alice@example.com";
        let t = totp(&secret, issuer, account).unwrap();
        let unix_secs = 1_700_000_100u64;
        let step = unix_secs / 30;
        let code = t.generate(step * 30);

        // First verification at step succeeds.
        assert_eq!(
            verify_totp_step_at(&secret, &code, issuer, account, 0, unix_secs).unwrap(),
            Some(step)
        );
        // Replay at same or next time-step within skew window is blocked when min_step = step + 1.
        assert_eq!(
            verify_totp_step_at(&secret, &code, issuer, account, step + 1, unix_secs).unwrap(),
            None
        );
        assert_eq!(
            verify_totp_step_at(&secret, &code, issuer, account, step + 1, unix_secs + 30).unwrap(),
            None
        );
        // Non-numeric / wrong-length codes are rejected.
        assert_eq!(
            verify_totp_step_at(&secret, "12345a", issuer, account, 0, unix_secs).unwrap(),
            None
        );
        assert_eq!(
            verify_totp_step_at(&secret, "12345", issuer, account, 0, unix_secs).unwrap(),
            None
        );
    }

    #[test]
    fn recovery_codes_hash_is_case_insensitive_and_trimmed() {
        let codes = generate_recovery_codes(4);
        assert_eq!(codes.len(), 4);
        let upper = format!("  {}  ", codes[0].plaintext.to_uppercase());
        assert_eq!(hash_recovery_code(&upper), codes[0].hash);
    }
}
