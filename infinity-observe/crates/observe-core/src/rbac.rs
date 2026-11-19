//! RBAC-lite permission matching for dashboard and bearer control-plane access.

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_VIEWER: &str = "viewer";

pub fn permissions_for_role(role: &str) -> Vec<String> {
    match role {
        ROLE_ADMIN => vec!["*:*".into()],
        ROLE_VIEWER => vec![
            "logs:read".into(),
            "metrics:read".into(),
            "traces:read".into(),
            "alerts:read".into(),
            "stats:read".into(),
        ],
        // Fail closed for any unknown/empty role.
        _ => Vec::new(),
    }
}

pub fn permission_matches(granted: &str, required: &str) -> bool {
    let (Some((gr, ga)), Some((rr, ra))) = (split(granted), split(required)) else {
        return false;
    };
    seg_match(gr, rr) && seg_match(ga, ra)
}

pub fn any_permission(granted: &[String], required: &str) -> bool {
    granted.iter().any(|g| permission_matches(g, required))
}

fn split(p: &str) -> Option<(&str, &str)> {
    let (r, a) = p.split_once(':')?;
    if r.is_empty()
        || a.is_empty()
        || r.chars().any(char::is_whitespace)
        || a.chars().any(char::is_whitespace)
    {
        return None;
    }
    Some((r, a))
}

fn seg_match(granted: &str, required: &str) -> bool {
    granted == "*" || granted == required
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(permission_matches("*:*", "logs:read"));
        assert!(permission_matches("alerts:*", "alerts:delete"));
        assert!(!permission_matches("logs:read", "keys:create"));
    }

    #[test]
    fn unknown_role_fails_closed_and_malformed_perms_rejected() {
        assert!(permissions_for_role("").is_empty());
        assert!(permissions_for_role("superadmin").is_empty());
        assert_eq!(permissions_for_role(ROLE_VIEWER).len(), 5);
        assert!(!permission_matches("alerts", "alerts:delete"));
        assert!(!permission_matches("", ""));
        assert!(!permission_matches(":read", "logs:read"));
        assert!(!permission_matches("logs:", "logs:read"));
    }
}
