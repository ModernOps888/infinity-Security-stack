//! Role-Based Access Control primitives.
//!
//! Permissions use a `resource:action` convention with `*` wildcards, e.g.
//! `users:read`, `users:*`, or `*:*` for super-admin. Scopes on access tokens
//! are checked against required permissions with the same matcher.

/// Returns true if `granted` satisfies the `required` permission.
///
/// Both permissions must follow strict `resource:action` format with non-empty
/// segments; `*` matches any single segment. Comparison is case-sensitive.
pub fn permission_matches(granted: &str, required: &str) -> bool {
    let Some((gr, ga)) = split_strict(granted) else {
        return false;
    };
    let Some((rr, ra)) = split_strict(required) else {
        return false;
    };
    seg_match(gr, rr) && seg_match(ga, ra)
}

/// Returns true if any of `granted` permissions satisfies `required`.
pub fn any_permission(granted: &[String], required: &str) -> bool {
    granted.iter().any(|g| permission_matches(g, required))
}

/// Validate `resource:action` syntax (two non-empty segments, no whitespace).
pub fn is_valid_permission(p: &str) -> bool {
    split_strict(p).is_some() && !p.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn split_strict(p: &str) -> Option<(&str, &str)> {
    let (r, a) = p.split_once(':')?;
    if r.is_empty() || a.is_empty() || a.contains(':') {
        return None;
    }
    Some((r, a))
}

fn seg_match(granted: &str, required: &str) -> bool {
    granted == "*" || granted == required
}

/// Well-known built-in roles seeded on first run.
pub const ROLE_SUPERADMIN: &str = "superadmin";
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_USER: &str = "user";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(permission_matches("*:*", "users:read"));
        assert!(permission_matches("users:*", "users:delete"));
        assert!(permission_matches("users:read", "users:read"));
        assert!(!permission_matches("users:read", "users:delete"));
        assert!(!permission_matches("clients:*", "users:read"));
        assert!(!permission_matches("users", "users:delete"));
        assert!(!permission_matches("*", "users:delete"));
        assert!(!permission_matches("", "users:read"));
        assert!(!permission_matches("users:", "users:read"));
        assert!(!permission_matches(":read", "users:read"));
    }

    #[test]
    fn any() {
        let g = vec!["users:read".to_string(), "clients:*".to_string()];
        assert!(any_permission(&g, "clients:create"));
        assert!(!any_permission(&g, "roles:create"));
    }
}
