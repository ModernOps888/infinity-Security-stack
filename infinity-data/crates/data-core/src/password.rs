use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use std::collections::HashSet;
use std::sync::OnceLock;

use crate::error::{CoreError, Result};

pub const MIN_PASSWORD_LEN: usize = 12;
pub const MAX_PASSWORD_LEN: usize = 256;

static DUMMY_HASH: OnceLock<String> = OnceLock::new();

fn hasher() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn dummy_hash() -> &'static str {
    DUMMY_HASH
        .get_or_init(|| hash_password("InfinityData!EnumGuard2026").expect("dummy argon2id hash"))
}

/// Pre-initializes the constant-time dummy Argon2id hash so the very first
/// unknown-user login check does not pay an extra hashing cycle.
pub fn warm_dummy_hash() {
    let _ = dummy_hash();
}

pub fn validate_user_password(plaintext: &str) -> Result<()> {
    if plaintext.len() < MIN_PASSWORD_LEN {
        return Err(CoreError::Invalid(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if plaintext.len() > MAX_PASSWORD_LEN {
        return Err(CoreError::Invalid(format!(
            "password must be at most {MAX_PASSWORD_LEN} characters"
        )));
    }
    if plaintext.chars().any(char::is_control) {
        return Err(CoreError::Invalid(
            "password must not contain control characters".into(),
        ));
    }
    let lower = plaintext.trim().to_ascii_lowercase();
    const BANNED_EXACT: &[&str] = &[
        "password",
        "password123",
        "password1234",
        "password!123",
        "changeme",
        "changeme123",
        "changeme1234",
        "admin",
        "administrator",
        "admin1234567",
        "admin12345678",
        "123456789012",
        "qwerty123456",
        "letmein12345",
        "infinity-data",
        "infinitydata",
    ];
    if BANNED_EXACT.contains(&lower.as_str()) {
        return Err(CoreError::Invalid(
            "password is too common or a known default".into(),
        ));
    }
    let distinct: HashSet<char> = plaintext.chars().collect();
    if distinct.len() < 4 {
        return Err(CoreError::Invalid(
            "password must contain more distinct characters".into(),
        ));
    }
    Ok(())
}

pub fn validate_admin_password(plaintext: &str) -> Result<()> {
    validate_user_password(plaintext)?;
    let lower = plaintext.to_ascii_lowercase();
    const BANNED_SUBSTRINGS: &[&str] = &[
        "changeme",
        "change-me",
        "change_me",
        "placeholder",
        "chooseastrongone",
    ];
    if BANNED_SUBSTRINGS.iter().any(|s| lower.contains(s)) {
        return Err(CoreError::Invalid(
            "admin password must not use a placeholder or default value".into(),
        ));
    }
    let classes = [
        plaintext.chars().any(|c| c.is_ascii_lowercase()),
        plaintext.chars().any(|c| c.is_ascii_uppercase()),
        plaintext.chars().any(|c| c.is_ascii_digit()),
        plaintext
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && !c.is_control()),
    ]
    .into_iter()
    .filter(|&b| b)
    .count();
    if classes < 3 {
        return Err(CoreError::Invalid(
            "admin password must include at least 3 character classes (upper, lower, digit, symbol)"
                .into(),
        ));
    }
    let distinct: HashSet<char> = plaintext.chars().collect();
    if distinct.len() < 6 {
        return Err(CoreError::Invalid(
            "admin password must contain at least 6 distinct characters".into(),
        ));
    }
    Ok(())
}

pub fn hash_password(plaintext: &str) -> Result<String> {
    validate_user_password(plaintext)?;
    let salt = SaltString::generate(&mut OsRng);
    Ok(hasher()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| CoreError::Crypto(e.to_string()))?
        .to_string())
}

pub fn verify_password(plaintext: &str, phc_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| CoreError::Crypto(e.to_string()))?;
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return Err(CoreError::Crypto(
            "unsupported password hash algorithm".into(),
        ));
    }
    Ok(hasher()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok())
}

pub fn dummy_verify(plaintext: &str) {
    let _ = verify_password(plaintext, dummy_hash());
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_roundtrip_and_rejection() {
        let hash = hash_password("StrongTestPass!2026").unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password("StrongTestPass!2026", &hash).unwrap());
        assert!(!verify_password("WrongPassword!2026", &hash).unwrap());
        assert!(hash_password("short1").is_err());
        assert!(hash_password("aaaaaaaaaaaa").is_err());
    }

    #[test]
    fn rejects_weak_and_default_admin_passwords() {
        assert!(validate_admin_password("ChangeMe_Infinity#2025").is_err());
        assert!(validate_admin_password("change-me-admin-123").is_err());
        assert!(validate_admin_password("password1234").is_err());
        assert!(validate_admin_password("admin1234567").is_err());
        assert!(validate_admin_password("Sup3rStrongAdminPass!1").is_ok());
    }

    #[test]
    fn constant_time_eq_checks_exact_equality() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
