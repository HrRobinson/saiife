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

/// Checks a capability pattern: `resource:verb[:qualifier]` where the
/// resource is a name `[a-z0-9_-]+` or `*`, the verb is one of [`VERBS`] or
/// `*`, and the qualifier, if present, is not empty.
pub fn validate_pattern(pattern: &str) -> Result<(), String> {
    let mut it = pattern.splitn(3, ':');
    let res = it.next().unwrap_or("");
    let verb = it
        .next()
        .ok_or_else(|| "expected resource:verb[:qualifier]".to_string())?;
    let qual = it.next();
    let name_ok = !res.is_empty()
        && res
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'));
    if res != "*" && !name_ok {
        return Err("resource must be a name ([a-z0-9_-]+) or *".to_string());
    }
    if verb != "*" && !VERBS.contains(&verb) {
        return Err("verb must be read, write, delete, export, admin or *".to_string());
    }
    if qual == Some("") {
        return Err("empty qualifier".to_string());
    }
    Ok(())
}

/// Allow-stage match of `pattern` against `cap`; see [`matches_with`].
pub fn matches(pattern: &str, cap: &Capability) -> bool {
    matches_with(pattern, cap, false)
}

/// Does `pattern` match `cap`? A pattern is `resource:verb[:qualifier]`;
/// `*` as the resource or the verb matches exactly one segment. Anything
/// else (including `*` alone) matches nothing. The qualifier is a glob; a
/// pattern without a qualifier matches any qualifier.
///
/// `broad` selects the restrictive stages (deny and ask), which must err
/// towards matching:
/// - narrow (allow): `*` in the qualifier stays within one `/` level, and a
///   qualified pattern does not match a request without a qualifier;
/// - broad (deny, ask): `*` crosses `/`, and a qualified pattern matches a
///   request without a qualifier (fail closed).
///
/// `**` crosses `/` in both.
pub fn matches_with(pattern: &str, cap: &Capability, broad: bool) -> bool {
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
        (Some(_), None) => broad,
        (Some(p), Some(q)) => glob_with(p, q, broad),
    }
}

/// Glob match where `*` matches any run of characters except `/`, `**`
/// matches any run, and every other character matches itself, case
/// exactly (allow-stage semantics).
pub fn glob(pattern: &str, text: &str) -> bool {
    glob_with(pattern, text, false)
}

/// As [`glob`]; with `broad` (deny and ask stages) a single `*` crosses `/`
/// as well and ASCII case is ignored. The allow stage compares case
/// exactly, because case-sensitive backends (S3 keys) would otherwise be
/// widened; the restrictive stages ignore case because a missed deny is
/// worse than a spurious one.
pub fn glob_with(pattern: &str, text: &str, broad: bool) -> bool {
    let fold = |c: char| if broad { c.to_ascii_lowercase() } else { c };
    // Tokens: Some(c) literal, None = star; the bool says it crosses `/`.
    let mut toks: Vec<(Option<char>, bool)> = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '*' {
            let mut n = 1;
            while chars.next_if_eq(&'*').is_some() {
                n += 1;
            }
            toks.push((None, broad || n > 1));
        } else {
            toks.push((Some(fold(c)), false));
        }
    }
    let t: Vec<char> = text.chars().map(fold).collect();
    // reach[j]: the tokens so far match t[..j].
    let mut reach = vec![false; t.len() + 1];
    reach[0] = true;
    for (tok, crosses) in toks {
        let mut next = vec![false; t.len() + 1];
        match tok {
            None => {
                let mut run = false;
                for j in 0..=t.len() {
                    run = (run && j > 0 && (crosses || t[j - 1] != '/')) || reach[j];
                    next[j] = run;
                }
            }
            Some(pc) => {
                for j in 0..t.len() {
                    next[j + 1] = reach[j] && t[j] == pc;
                }
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

    #[test]
    fn validate_pattern_cases() {
        for ok in [
            "orders:read",
            "*:delete",
            "orders:*",
            "*:*",
            "issues:write:repo=acme/*",
            "s3:read:arn:aws:s3:::b/*",
        ] {
            assert!(validate_pattern(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "*",
            "a",
            "customers:exprot",
            "Orders:read",
            "or ders:read",
            ":read",
            "orders:",
            "orders:read:",
            "o*:read",
        ] {
            assert!(validate_pattern(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn broad_matching_fails_closed() {
        // `*` crosses `/` in deny and ask, not in allow.
        let p = "s3:read:arn:aws:s3:::secret/*";
        let c = cap("s3:read:arn:aws:s3:::secret/a/b");
        assert!(matches_with(p, &c, true));
        assert!(!matches_with(p, &c, false));
        // `**` crosses in both.
        assert!(matches("s3:read:arn:aws:s3:::secret/**", &c));
        // A qualified pattern matches an unqualified request only when broad.
        assert!(matches_with(
            "issues:write:repo=acme/*",
            &cap("issues:write"),
            true
        ));
        assert!(!matches_with(
            "issues:write:repo=acme/*",
            &cap("issues:write"),
            false
        ));
        // Case-insensitive in deny and ask only; allow is case-exact.
        let c = cap("issues:write:repo=ACME/Secret");
        assert!(!matches("issues:write:repo=acme/secret", &c));
        assert!(matches("issues:write:repo=ACME/Secret", &c));
        assert!(matches_with("issues:write:repo=acme/secret", &c, true));
        assert!(!matches_with(
            "s3:read:b/public/*",
            &cap("s3:read:b/PUBLIC/x"),
            false
        ));
    }
}
