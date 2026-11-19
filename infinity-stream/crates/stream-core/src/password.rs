use std::collections::HashSet;
use std::sync::OnceLock;

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{CoreError, Result};

pub const MIN_PASSWORD_LEN: usize = 8;
pub const MIN_ADMIN_PASSWORD_LEN: usize = 12;
pub const MAX_PASSWORD_LEN: usize = 1024;

static DUMMY_HASH: OnceLock<String> = OnceLock::new();

fn hasher() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(plaintext: &str) -> Result<String> {
    if plaintext.len() < MIN_PASSWORD_LEN {
        return Err(CoreError::Invalid(
            "password must be at least 8 characters".into(),
        ));
    }
    if plaintext.len() > MAX_PASSWORD_LEN {
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
    if plaintext.len() > MAX_PASSWORD_LEN {
        return Ok(false);
    }
    let parsed = PasswordHash::new(phc_hash).map_err(|e| CoreError::Crypto(e.to_string()))?;
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return Err(CoreError::Crypto(
            "unsupported password hash algorithm".into(),
        ));
    }
    // Always execute Argon2id verification even when plaintext is empty so
    // callers never leak user existence via an early-return timing oracle.
    Ok(hasher()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok())
}

pub fn warm_dummy_hash() {
    let _ =
        DUMMY_HASH.get_or_init(|| hash_password("infinity-enumeration-guard").expect("dummy hash"));
}

pub fn dummy_verify(plaintext: &str) {
    let hash =
        DUMMY_HASH.get_or_init(|| hash_password("infinity-enumeration-guard").expect("dummy hash"));
    let bounded = if plaintext.len() > MAX_PASSWORD_LEN {
        "infinity-enumeration-fallback"
    } else {
        plaintext
    };
    let _ = verify_password(bounded, hash);
}

/// Rejects known default/placeholder/weak admin passwords.
pub fn is_weak_or_default_password(password: &str) -> bool {
    if password.len() < MIN_ADMIN_PASSWORD_LEN
        || password.len() > MAX_PASSWORD_LEN
        || password.chars().any(|c| c.is_control())
        || password.trim().is_empty()
    {
        return true;
    }
    let lower = password.to_ascii_lowercase();
    const BANNED_SUBSTRINGS: &[&str] = &[
        "changeme",
        "change-me",
        "change_me",
        "chooseastrongone",
        "infinity#202",
        "password123",
        "admin123",
        "qwerty123",
        "12345678",
    ];
    if BANNED_SUBSTRINGS.iter().any(|bad| lower.contains(bad)) {
        return true;
    }
    if matches!(
        lower.as_str(),
        "password" | "admin" | "administrator" | "root" | "infinity" | "letmein" | "welcome"
    ) {
        return true;
    }
    let unique_chars: HashSet<char> = password.chars().collect();
    unique_chars.len() < 6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash_password("V3ry$tr0ng-Str3am-Pass!").unwrap();
        assert!(verify_password("V3ry$tr0ng-Str3am-Pass!", &h).unwrap());
        assert!(!verify_password("wrong-password", &h).unwrap());
        assert!(!verify_password("", &h).unwrap());
        assert!(!verify_password(&"a".repeat(2048), &h).unwrap());
        assert!(hash_password("short").is_err());
        assert!(hash_password(&"x".repeat(1025)).is_err());
    }

    #[test]
    fn verify_rejects_non_argon2id_variants() {
        let h = hash_password("V3ry$tr0ng-Str3am-Pass!").unwrap();
        let downgraded = h.replacen("$argon2id$", "$argon2i$", 1);
        assert!(verify_password("V3ry$tr0ng-Str3am-Pass!", &downgraded).is_err());
    }

    #[test]
    fn weak_and_placeholder_passwords_rejected() {
        for bad in [
            "",
            "short",
            "ChangeMe_Infinity#2025",
            "ChangeMe_Infinity#2026",
            "ChooseAStrongOne#2026",
            "change-me-now",
            "password123456",
            "admin12345678",
            "aaaaaaaaaaaa",
            "bad\npass123456",
        ] {
            assert!(is_weak_or_default_password(bad), "expected weak: {bad:?}");
        }
        assert!(!is_weak_or_default_password("Sup3r-Secret-Admin-Pass!"));
    }
}
