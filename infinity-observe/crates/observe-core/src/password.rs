//! Password hashing using Argon2id — the OWASP-recommended memory-hard KDF.

use std::hint::black_box;

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{CoreError, Result};

pub const MIN_PASSWORD_BYTES: usize = 8;
pub const MAX_PASSWORD_BYTES: usize = 1024;
pub const MIN_ADMIN_PASSWORD_BYTES: usize = 12;

fn hasher() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Returns true if a bootstrap/admin password is weak or matches known defaults/placeholders.
pub fn is_weak_or_default_password(pw: &str) -> bool {
    let trimmed = pw.trim();
    if trimmed.len() < MIN_ADMIN_PASSWORD_BYTES || trimmed.len() > MAX_PASSWORD_BYTES {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    const FORBIDDEN_SUBSTRINGS: &[&str] = &[
        "changeme",
        "change-me",
        "change_me",
        "chooseastrongone",
        "infinityobserve#2026",
        "infinity#2025",
        "infinity#2026",
        "password",
        "12345678",
        "qwerty",
        "letmein",
    ];
    if FORBIDDEN_SUBSTRINGS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    matches!(
        lower.as_str(),
        "admin" | "admin123" | "administrator" | "root" | "default" | "test1234"
    )
}

pub fn hash_password(plaintext: &str) -> Result<String> {
    if plaintext.len() < MIN_PASSWORD_BYTES {
        return Err(CoreError::Invalid(
            "password must be at least 8 characters".into(),
        ));
    }
    if plaintext.len() > MAX_PASSWORD_BYTES {
        return Err(CoreError::Invalid(
            "password must be at most 1024 bytes".into(),
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    Ok(hasher()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| CoreError::Crypto(e.to_string()))?
        .to_string())
}

pub fn verify_password(plaintext: &str, phc_hash: &str) -> Result<bool> {
    if plaintext.len() > MAX_PASSWORD_BYTES {
        return Ok(false);
    }
    let parsed = PasswordHash::new(phc_hash).map_err(|e| CoreError::Crypto(e.to_string()))?;
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return Ok(false);
    }
    Ok(hasher()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok())
}

pub fn dummy_verify(plaintext: &str) {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    let hash =
        DUMMY.get_or_init(|| hash_password("infinity-enumeration-guard").expect("dummy hash"));
    let bounded = if plaintext.len() > MAX_PASSWORD_BYTES {
        ""
    } else {
        plaintext
    };
    let _ = verify_password(bounded, hash);
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= black_box(*x ^ *y);
    }
    black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("Sup3r-Secret-Admin-Pass!").expect("hash");
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password("Sup3r-Secret-Admin-Pass!", &hash).unwrap());
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn rejects_short_or_oversized_passwords() {
        assert!(hash_password("short").is_err());
        let huge = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(hash_password(&huge).is_err());
        let hash = hash_password("valid-pass-1234").unwrap();
        assert!(!verify_password(&huge, &hash).unwrap());
    }

    #[test]
    fn rejects_weak_or_placeholder_admin_passwords() {
        assert!(is_weak_or_default_password(""));
        assert!(is_weak_or_default_password("short123"));
        assert!(is_weak_or_default_password("ChangeMe_InfinityObserve#2026"));
        assert!(is_weak_or_default_password("ChangeMe_Infinity#2025"));
        assert!(is_weak_or_default_password("password1234"));
        assert!(!is_weak_or_default_password("Sup3r-Secret-Admin-Pass!"));
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
