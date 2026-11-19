use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

pub const MAX_RESOURCE_NAME_LEN: usize = 128;
pub const MAX_DOC_ID_LEN: usize = 256;

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

fn is_windows_reserved_stem(stem: &str) -> bool {
    let clean = stem.trim_end_matches([' ', '.']);
    if clean.eq_ignore_ascii_case("CON")
        || clean.eq_ignore_ascii_case("PRN")
        || clean.eq_ignore_ascii_case("AUX")
        || clean.eq_ignore_ascii_case("NUL")
        || clean.eq_ignore_ascii_case("CONIN$")
        || clean.eq_ignore_ascii_case("CONOUT$")
    {
        return true;
    }
    if clean.len() == 4 {
        let prefix = &clean[..3];
        let suffix = clean.as_bytes()[3];
        if (prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT"))
            && suffix.is_ascii_digit()
        {
            return true;
        }
    }
    false
}

/// Validates topic and search-index names: 1..=128 ASCII `[A-Za-z0-9_-]`,
/// rejecting path separators, dots, null bytes, control chars, and Windows
/// reserved device names.
pub fn validate_resource_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= MAX_RESOURCE_NAME_LEN
        && !name.contains(['/', '\\', '\0', '.'])
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !is_windows_reserved_stem(name);
    if ok {
        Ok(())
    } else {
        Err(CoreError::Invalid(
            "name must be 1-128 safe chars of [A-Za-z0-9_-] and not a reserved device name".into(),
        ))
    }
}

/// Validates consumer group names: 1..=128 chars of `[A-Za-z0-9_.-]`,
/// rejecting path traversal (`..`), leading/trailing dots, slashes, null
/// bytes, control chars, and Windows reserved device names.
pub fn validate_group_name(group: &str) -> Result<()> {
    let stem = group.split('.').next().unwrap_or(group);
    let ok = !group.is_empty()
        && group.len() <= MAX_RESOURCE_NAME_LEN
        && group != "."
        && group != ".."
        && !group.contains("..")
        && !group.starts_with('.')
        && !group.ends_with('.')
        && !group.contains(['/', '\\', '\0'])
        && group
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !is_windows_reserved_stem(stem);
    if ok {
        Ok(())
    } else {
        Err(CoreError::Invalid(
            "group must be 1-128 safe chars of [A-Za-z0-9_.-]".into(),
        ))
    }
}

/// Validates document IDs: 1..=256 chars of `[A-Za-z0-9_.:-]`, rejecting
/// path traversal (`..`), leading/trailing dots, slashes, null bytes, and
/// Windows reserved names.
pub fn validate_doc_id(id: &str) -> Result<()> {
    let stem = id.split(['.', ':']).next().unwrap_or(id);
    let ok = !id.is_empty()
        && id.len() <= MAX_DOC_ID_LEN
        && id != "."
        && id != ".."
        && !id.contains("..")
        && !id.starts_with('.')
        && !id.ends_with('.')
        && !id.contains(['/', '\\', '\0'])
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':')
        && !is_windows_reserved_stem(stem);
    if ok {
        Ok(())
    } else {
        Err(CoreError::Invalid(
            "doc.id must be 1-256 safe chars of [A-Za-z0-9_.:-]".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_name_rejects_traversal_and_reserved() {
        assert!(validate_resource_name("orders-v1_2").is_ok());
        for bad in [
            "", "..", ".", "../etc", "a/b", "a\\b", "a\0b", "a\nb", "CON", "con", "NUL", "Prn",
            "AUX", "COM1", "com9", "LPT1", "CONIN$", "CONOUT$",
        ] {
            assert!(
                validate_resource_name(bad).is_err(),
                "expected err for {bad:?}"
            );
        }
        let long = "a".repeat(129);
        assert!(validate_resource_name(&long).is_err());
    }

    #[test]
    fn group_name_and_doc_id_reject_traversal() {
        assert!(validate_group_name("billing.workers-1").is_ok());
        for bad in [
            "..", ".", "a..b", ".hidden", "trail.", "nul.txt", "a/b", "a\\b", "a\0b",
        ] {
            assert!(
                validate_group_name(bad).is_err(),
                "group should fail: {bad:?}"
            );
        }
        assert!(validate_doc_id("prod:item-1.v2").is_ok());
        for bad in [
            "..", ".", "a..b", ".dot", "dot.", "con:1", "a/b", "a\\b", "a\0b",
        ] {
            assert!(validate_doc_id(bad).is_err(), "doc_id should fail: {bad:?}");
        }
    }

    #[test]
    fn constant_time_comparison() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
