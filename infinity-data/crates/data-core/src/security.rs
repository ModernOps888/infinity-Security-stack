use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub const MAX_IDENTIFIER_LEN: usize = 64;

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex(&h.finalize())
}

/// Validates a strict resource/table/collection/role/username identifier:
/// 1-64 ASCII alphanumeric characters, `'_'`, or `'-'`.
pub fn valid_name(name: &str) -> bool {
    (1..=MAX_IDENTIFIER_LEN).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Validates a column/field/alias identifier for tabular queries:
/// 1-64 ASCII alphanumeric characters, `'_'`, `'-'`, or `'.'` (no leading/trailing `'.'` or `".."`).
pub fn valid_column_name(name: &str) -> bool {
    (1..=MAX_IDENTIFIER_LEN).contains(&name.len())
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_validation_rejects_injection_and_control_chars() {
        assert!(valid_name("users_01-prod"));
        assert!(!valid_name(""));
        assert!(!valid_name(&"a".repeat(65)));
        assert!(!valid_name("users; DROP TABLE users;--"));
        assert!(!valid_name("../etc/passwd"));
        assert!(!valid_name("bad name"));
        assert!(!valid_name("bad\nname"));

        assert!(valid_column_name("meta.region_1-a"));
        assert!(!valid_column_name(""));
        assert!(!valid_column_name(".hidden"));
        assert!(!valid_column_name("trail."));
        assert!(!valid_column_name("a..b"));
        assert!(!valid_column_name("amount) OR 1=1--"));
    }
}
