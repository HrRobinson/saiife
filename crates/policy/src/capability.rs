//! Capabilities `resource:verb[:qualifier]` and pattern matching (spec §6.9.1).

use crate::load::PolicyError;

pub const VERBS: &[&str] = &["read", "write", "delete", "export", "admin"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub resource: String,
    pub verb: String,
    pub qualifier: Option<String>,
}

impl Capability {
    /// Parses a concrete capability. No wildcards are allowed here.
    pub fn parse(s: &str) -> Result<Capability, PolicyError> {
        let bad = |why: &str| PolicyError::Invalid {
            path: std::path::PathBuf::from("capability"),
            detail: format!("{s:?}: {why}"),
        };
        let mut it = s.splitn(3, ':');
        let resource = it.next().unwrap_or("");
        let verb = it.next().ok_or_else(|| bad("expected resource:verb"))?;
        let qualifier = it.next();
        if resource.is_empty() || resource.contains('*') {
            return Err(bad("resource must be a name"));
        }
        if !VERBS.contains(&verb) {
            return Err(bad("verb must be read, write, delete, export or admin"));
        }
        if qualifier == Some("") {
            return Err(bad("empty qualifier"));
        }
        Ok(Capability {
            resource: resource.to_string(),
            verb: verb.to_string(),
            qualifier: qualifier.map(str::to_string),
        })
    }
}

/// Does `pattern` match `cap`? A pattern is `resource:verb[:qualifier]`;
/// `*` as the resource or the verb matches exactly one segment. The
/// qualifier is a glob where `*` does not cross `/`. A pattern without a
/// qualifier matches any qualifier. Anything else (including `*` alone)
/// matches nothing.
pub fn matches(pattern: &str, cap: &Capability) -> bool {
    let mut it = pattern.splitn(3, ':');
    let (Some(res), Some(verb)) = (it.next(), it.next()) else {
        return false;
    };
    let qual = it.next();
    if res.is_empty() || verb.is_empty() || qual == Some("") {
        return false;
    }
    if res != "*" && res != cap.resource {
        return false;
    }
    if verb != "*" && verb != cap.verb {
        return false;
    }
    match (qual, &cap.qualifier) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(q)) => glob(p, q),
    }
}

/// Glob match where `*` matches any run of characters except `/`; every
/// other character matches itself.
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // reach[j]: p[..i] matches t[..j] for the current i.
    let mut reach = vec![false; t.len() + 1];
    reach[0] = true;
    for &pc in &p {
        let mut next = vec![false; t.len() + 1];
        if pc == '*' {
            let mut run = false;
            for j in 0..=t.len() {
                run = (run && j > 0 && t[j - 1] != '/') || reach[j];
                next[j] = run;
            }
        } else {
            for j in 0..t.len() {
                next[j + 1] = reach[j] && t[j] == pc;
            }
        }
        reach = next;
    }
    reach[t.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(s: &str) -> Capability {
        Capability::parse(s).unwrap()
    }

    #[test]
    fn parse_forms() {
        let c = cap("issues:write:repo=acme/web");
        assert_eq!(c.resource, "issues");
        assert_eq!(c.verb, "write");
        assert_eq!(c.qualifier.as_deref(), Some("repo=acme/web"));
        // A qualifier may itself contain colons (ARNs).
        assert_eq!(
            cap("s3:read:arn:aws:s3:::b/k").qualifier.as_deref(),
            Some("arn:aws:s3:::b/k")
        );
        for bad in [
            "",
            "orders",
            "orders:",
            ":read",
            "orders:peek",
            "*:read",
            "orders:*",
            "orders:read:",
        ] {
            assert!(Capability::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn capability_star_is_one_segment() {
        assert!(matches("orders:*", &cap("orders:read")));
        assert!(matches("*:delete", &cap("products:delete")));
        assert!(!matches("*:delete", &cap("products:read")));
        assert!(matches("*:*", &cap("a:read")));
        // `*` alone is not a valid pattern.
        assert!(!matches("*", &cap("orders:read")));
        assert!(!matches("", &cap("orders:read")));
        assert!(!matches("orders", &cap("orders:read")));
        assert!(!matches("orders:read:", &cap("orders:read")));
        // `*` is one segment: it does not swallow verb and qualifier.
        assert!(!matches("orders:*", &cap("customers:read")));
    }

    #[test]
    fn qualifier_glob_does_not_cross_slash() {
        let p = "issues:write:repo=acme/*";
        assert!(matches(p, &cap("issues:write:repo=acme/web")));
        assert!(!matches(p, &cap("issues:write:repo=acme/web/x")));
        assert!(!matches(p, &cap("issues:write:repo=other/web")));
        // No qualifier on the request: a qualified pattern does not match.
        assert!(!matches(p, &cap("issues:write")));
    }

    #[test]
    fn pattern_without_qualifier_matches_any_qualifier() {
        assert!(matches("issues:write", &cap("issues:write:repo=acme/web")));
        assert!(matches("issues:write", &cap("issues:write")));
    }

    #[test]
    fn glob_cases() {
        assert!(glob("a*c", "abc"));
        assert!(glob("a*c", "ac"));
        assert!(!glob("a*c", "a/c"));
        assert!(glob("*", "x"));
        assert!(glob("*", ""));
        assert!(!glob("*", "a/b"));
        assert!(glob("a**b", "axb"));
        assert!(glob("*x*", "aaxbb"));
        assert!(!glob("abc", "abd"));
    }
}
