pub fn permission_matches(granted: &str, required: &str) -> bool {
    let Some((gr, ga)) = split_strict(granted) else {
        return false;
    };
    let Some((rr, ra)) = split_strict(required) else {
        return false;
    };
    (gr == "*" || gr == rr) && (ga == "*" || ga == ra)
}

pub fn any_permission(granted: &[String], required: &str) -> bool {
    granted.iter().any(|g| permission_matches(g, required))
}

fn split_strict(p: &str) -> Option<(&str, &str)> {
    let (res, act) = p.split_once(':')?;
    if res.is_empty()
        || act.is_empty()
        || act.contains(':')
        || res.chars().any(|c| c.is_whitespace() || c.is_control())
        || act.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    Some((res, act))
}

pub const ROLE_SUPERADMIN: &str = "superadmin";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rbac_requires_strict_resource_action_format() {
        assert!(permission_matches("*:*", "topics:delete"));
        assert!(permission_matches("topics:*", "topics:produce"));
        assert!(permission_matches("topics:produce", "topics:produce"));
        assert!(!permission_matches("topics:produce", "topics:delete"));
        // Missing colon must NEVER implicitly become `resource:*`.
        assert!(!permission_matches("topics", "topics:delete"));
        assert!(!permission_matches("*", "topics:delete"));
        assert!(!permission_matches("", ""));
        assert!(!permission_matches("topics:", "topics:read"));
        assert!(!permission_matches(":read", "topics:read"));
        assert!(!permission_matches("topics:read:extra", "topics:read"));
    }
}
