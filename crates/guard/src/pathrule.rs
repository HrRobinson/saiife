//! Path rules: the globs packs declare in `[[deny_path]]` / `[[allow_path]]`
//! (spec §7.2), and their translation to anchored regexes over canonical
//! absolute paths.
//!
//! Glob syntax (deliberately small):
//!
//! - a glob starts with `/`, `~/`, `**/` or a variable (`$HOME`, `$PROJECT`,
//!   `$SAIIFE_DATA_DIR`, `$SAIIFE_AUDIT_DIR`, `$SAIIFE_BIN`,
//!   `$CLAUDE_CONFIG_DIR`, `$CODEX_HOME`, `$XDG_CONFIG_HOME`, and locked mode's `$SAIIFE_ETC`,
//!   `$SAIIFE_STATE`, `$SAIIFE_LOG`, `$SAIIFE_RUN`, `$SAIIFE_OPT`,
//!   `$SAIIFE_UNIT`), which stands alone or is followed by `/`;
//! - `*` matches within one path component, `?` one character of it;
//! - `**` is a whole component: `**/x` matches `x` in any directory,
//!   `a/**/b` any depth between, and a trailing `/**` matches the directory
//!   itself and everything below it;
//! - every other character is literal.
//!
//! Variables are resolved when the engine is built (`Engine::with_paths`):
//! a rule whose variable has no value on this machine is skipped.

use regex::Regex;
use serde::Deserialize;

use crate::canon::PathVars;

/// What a tool or command does to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

impl Access {
    pub fn label(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
        }
    }
}

/// Which accesses a path rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAccess {
    Read,
    Write,
    Any,
}

impl RuleAccess {
    pub fn covers(self, a: Access) -> bool {
        matches!(
            (self, a),
            (RuleAccess::Any, _)
                | (RuleAccess::Read, Access::Read)
                | (RuleAccess::Write, Access::Write)
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            RuleAccess::Read => "read",
            RuleAccess::Write => "write",
            RuleAccess::Any => "any",
        }
    }
}

/// A path rule as a pack declares it (not yet bound to this machine's
/// directories).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    pub glob: String,
    pub access: RuleAccess,
    pub reason: String,
    /// Match the proper ancestors of the glob's paths instead (write rules
    /// only, variable-rooted, no wildcards): `rm -rf ~/.local/share` removes
    /// the data dir below it.
    pub ancestors: bool,
}

/// Variables a glob may start with.
pub const VARIABLES: &[&str] = &[
    "HOME",
    "PROJECT",
    "SAIIFE_DATA_DIR",
    "SAIIFE_AUDIT_DIR",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "SAIIFE_BIN",
    // `$XDG_CONFIG_HOME`, else `~/.config` (user services, autostart).
    "XDG_CONFIG_HOME",
    // Locked mode's system paths (spec §5.2), always bound to their
    // defaults; only `core.lock` uses them.
    "SAIIFE_ETC",
    "SAIIFE_STATE",
    "SAIIFE_LOG",
    "SAIIFE_RUN",
    "SAIIFE_OPT",
    "SAIIFE_UNIT",
];

/// Split a glob into its leading variable (if any) and the rest. `~` is
/// `$HOME`. Errors name what is wrong, for the load warning.
fn split_var(glob: &str) -> Result<(Option<&'static str>, &str), String> {
    if glob == "~" {
        return Ok((Some("HOME"), ""));
    }
    if let Some(rest) = glob.strip_prefix("~/") {
        return Ok((Some("HOME"), &glob[glob.len() - rest.len() - 1..]));
    }
    let Some(after) = glob.strip_prefix('$') else {
        if glob.starts_with('/') || glob.starts_with("**/") {
            return Ok((None, glob));
        }
        return Err(format!(
            "path glob {glob:?} must start with /, ~/, **/ or a variable"
        ));
    };
    let end = after.find('/').unwrap_or(after.len());
    let name = &after[..end];
    match VARIABLES.iter().find(|v| **v == name) {
        Some(v) => Ok((Some(*v), &after[end..])),
        None => Err(format!(
            "path glob {glob:?} uses unknown variable ${name} (known: {})",
            VARIABLES.join(", ")
        )),
    }
}

/// The variable a valid glob starts with (`~` is `HOME`), if any.
pub fn glob_variable(glob: &str) -> Option<&'static str> {
    split_var(glob).ok().and_then(|(v, _)| v)
}

/// Check a glob's syntax without binding it (used when a pack loads).
pub fn validate_glob(glob: &str) -> Result<(), String> {
    let (_, rest) = split_var(glob)?;
    for (i, comp) in rest.split('/').enumerate() {
        if comp.is_empty() && i > 0 {
            return Err(format!(
                "path glob {glob:?}: empty path component (trailing or doubled `/`)"
            ));
        }
        if comp.contains("**") && comp != "**" {
            return Err(format!(
                "path glob {glob:?}: `**` must be a whole path component"
            ));
        }
        if comp.contains('$') || (i > 0 && comp.starts_with('~')) {
            return Err(format!(
                "path glob {glob:?}: variables and `~` are only allowed at the start"
            ));
        }
    }
    Ok(())
}

/// Check an `ancestors = true` rule: variable-rooted, wildcard-free, write.
pub fn validate_ancestors(glob: &str, access: RuleAccess) -> Result<(), String> {
    validate_glob(glob)?;
    let (var, rest) = split_var(glob)?;
    if var.is_none() || glob.contains(['*', '?']) || rest == "/**" {
        return Err(format!(
            "path glob {glob:?}: `ancestors = true` needs a variable-rooted glob without wildcards"
        ));
    }
    if access != RuleAccess::Write {
        return Err(format!(
            "path glob {glob:?}: `ancestors = true` needs `access = \"write\"`"
        ));
    }
    Ok(())
}

/// Like `compile_glob` for an `ancestors` rule: the regex matches every
/// proper ancestor (including `/`) of each value the glob resolves to.
pub fn compile_ancestors(
    glob: &str,
    vars: &PathVars,
    case_insensitive: bool,
) -> Result<Option<Regex>, String> {
    compile(ancestors_source(glob, vars, case_insensitive)?)
}

fn compile(source: Option<String>) -> Result<Option<Regex>, String> {
    source
        .map(|re| Regex::new(&re).map_err(|e| e.to_string()))
        .transpose()
}

/// The regex source `compile_ancestors` compiles.
pub fn ancestors_source(
    glob: &str,
    vars: &PathVars,
    case_insensitive: bool,
) -> Result<Option<String>, String> {
    validate_glob(glob)?;
    let (var, rest) = split_var(glob)?;
    let Some(name) = var else {
        return Err(format!("path glob {glob:?}: ancestors need a variable"));
    };
    let mut alts: Vec<String> = vec![];
    for v in vars.values(name) {
        let Some(v) = v.to_str() else {
            return Ok(None);
        };
        let full = format!("{}{}", v.trim_end_matches('/'), rest);
        alts.push("/".to_string());
        for (i, c) in full.char_indices() {
            if c == '/' && i > 0 {
                alts.push(regex::escape(&full[..i]));
            }
        }
    }
    if alts.is_empty() {
        return Ok(None);
    }
    let flags = if case_insensitive { "(?is)" } else { "(?s)" };
    Ok(Some(format!("{flags}^(?:{})$", alts.join("|"))))
}

/// Translate a glob into an anchored regex over canonical paths, with its
/// variable replaced by the values in `vars` (an alternation if several).
/// `Ok(None)`: the variable has no value here, so the rule cannot apply.
pub fn compile_glob(
    glob: &str,
    vars: &PathVars,
    case_insensitive: bool,
) -> Result<Option<Regex>, String> {
    compile(glob_source(glob, vars, case_insensitive)?)
}

/// The regex source `compile_glob` compiles.
pub fn glob_source(
    glob: &str,
    vars: &PathVars,
    case_insensitive: bool,
) -> Result<Option<String>, String> {
    validate_glob(glob)?;
    let (var, rest) = split_var(glob)?;
    let mut re = String::from(if case_insensitive { "(?is)^" } else { "(?s)^" });
    if let Some(name) = var {
        let values = vars.values(name);
        if values.is_empty() {
            return Ok(None);
        }
        let mut alts: Vec<String> = Vec::new();
        for v in values {
            let Some(v) = v.to_str() else {
                // Not representable in a regex over UTF-8 paths: skip the
                // rule, like an unbound variable.
                return Ok(None);
            };
            let v = v.trim_end_matches('/');
            // A variable bound to `/` is "" after trimming; the bare
            // variable must still match `/`.
            alts.push(if v.is_empty() && rest.is_empty() {
                "/".to_string()
            } else {
                regex::escape(v)
            });
        }
        re.push_str(&format!("(?:{})", alts.join("|")));
    }
    let comps: Vec<&str> = rest.split('/').collect();
    let last = comps.len() - 1;
    for (i, comp) in comps.iter().enumerate() {
        match (i, *comp) {
            // The empty component before a leading `/` (or after a
            // variable): nothing to add, the separator comes next.
            (0, "") => {}
            (0, "**") => re.push_str("(?:/.*)?"),
            (_, "**") if i == last => re.push_str("(?:/.*)?"),
            (_, "**") => re.push_str("(?:/[^/]+)*"),
            _ => {
                if i > 0 {
                    re.push('/');
                }
                for c in comp.chars() {
                    match c {
                        '*' => re.push_str("[^/]*"),
                        '?' => re.push_str("[^/]"),
                        c => re.push_str(&regex::escape(&c.to_string())),
                    }
                }
            }
        }
    }
    re.push('$');
    Ok(Some(re))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> PathVars {
        PathVars::new()
            .with_var("HOME", "/home/u")
            .with_var("SAIIFE_BIN", "/opt/saiife/bin/saiife")
            .with_var("SAIIFE_BIN", "/usr/local/bin/saiife")
    }

    fn m(glob: &str, path: &str) -> bool {
        compile_glob(glob, &vars(), false)
            .unwrap()
            .unwrap()
            .is_match(path)
    }

    #[test]
    fn any_directory_prefix() {
        assert!(m("**/.env", "/home/u/app/.env"));
        assert!(m("**/.env", "/.env"));
        assert!(!m("**/.env", "/home/u/app/.env.example"));
        assert!(!m("**/.env", "/home/u/app/my.env"));
        assert!(m("**/.env.*", "/p/.env.local"));
        assert!(!m("**/.env.*", "/p/.env"));
    }

    #[test]
    fn home_and_star() {
        assert!(m("~/.ssh/id_*", "/home/u/.ssh/id_ed25519"));
        assert!(m("~/.ssh/id_*", "/home/u/.ssh/id_rsa.pub"));
        assert!(!m("~/.ssh/id_*", "/home/u/.ssh/config"));
        assert!(!m("~/.ssh/id_*", "/home/u/.ssh/keys/id_rsa"));
        assert!(m("$HOME/.kube/config", "/home/u/.kube/config"));
        assert!(m("~/.ssh/id_?sa", "/home/u/.ssh/id_rsa"));
    }

    #[test]
    fn trailing_double_star_includes_the_directory() {
        assert!(m("~/.config/gcloud/**", "/home/u/.config/gcloud"));
        assert!(m(
            "~/.config/gcloud/**",
            "/home/u/.config/gcloud/legacy_credentials/a/adc.json"
        ));
        assert!(!m("~/.config/gcloud/**", "/home/u/.config/gcloudx"));
        assert!(m("**/.saiife/**", "/p/.saiife"));
        assert!(m("**/.saiife/**", "/p/.saiife/config.toml"));
    }

    #[test]
    fn middle_double_star() {
        assert!(m("/a/**/b", "/a/b"));
        assert!(m("/a/**/b", "/a/x/y/b"));
        assert!(!m("/a/**/b", "/a/xb"));
    }

    #[test]
    fn multi_valued_variable_is_an_alternation() {
        assert!(m("$SAIIFE_BIN", "/opt/saiife/bin/saiife"));
        assert!(m("$SAIIFE_BIN", "/usr/local/bin/saiife"));
        assert!(!m("$SAIIFE_BIN", "/usr/local/bin/saiife2"));
    }

    #[test]
    fn literal_characters_are_escaped() {
        assert!(m("/p/a+b(c).txt", "/p/a+b(c).txt"));
        assert!(!m("/p/a.txt", "/p/abtxt"));
    }

    #[test]
    fn unresolved_variable_skips_the_rule() {
        let none = PathVars::new();
        assert!(compile_glob("~/.aws/credentials", &none, false)
            .unwrap()
            .is_none());
        assert!(compile_glob("**/.env", &none, false).unwrap().is_some());
    }

    #[test]
    fn case_insensitive_for_macos() {
        let r = compile_glob("**/.env", &vars(), true).unwrap().unwrap();
        assert!(r.is_match("/p/.ENV"));
    }

    #[test]
    fn bad_globs_are_rejected() {
        for bad in [".env", "src/**", "$NOPE/x", "/a/b**", "/a/$HOME", "/a/~/b"] {
            assert!(validate_glob(bad).is_err(), "{bad}");
        }
        for good in ["/etc/passwd", "~", "~/x", "$HOME", "**/.env", "/a/**"] {
            assert!(validate_glob(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn ancestors_match_proper_ancestors_only() {
        let v = PathVars::new()
            .with_var("SAIIFE_DATA_DIR", "/home/u/.local/share/saiife")
            .with_var("SAIIFE_BIN", "/usr/local/bin/saiife");
        let r = compile_ancestors("$SAIIFE_DATA_DIR", &v, false)
            .unwrap()
            .unwrap();
        for yes in [
            "/",
            "/home",
            "/home/u",
            "/home/u/.local",
            "/home/u/.local/share",
        ] {
            assert!(r.is_match(yes), "{yes}");
        }
        for no in [
            "/home/u/.local/share/saiife",
            "/home/u/.local/share/saiife/audit",
            "/home/u/.local/share/other",
            "/home/u/.local/sharex",
            "/home/u/.local/bin",
            "/usr",
        ] {
            assert!(!r.is_match(no), "{no}");
        }
        let b = compile_ancestors("$SAIIFE_BIN", &v, false)
            .unwrap()
            .unwrap();
        assert!(b.is_match("/usr/local/bin") && b.is_match("/usr") && b.is_match("/"));
        assert!(!b.is_match("/usr/local/bin/saiife"));
        let sub = compile_ancestors("$SAIIFE_DATA_DIR/audit", &v, false)
            .unwrap()
            .unwrap();
        assert!(sub.is_match("/home/u/.local/share/saiife"));
        assert!(compile_ancestors("$HOME", &v, false).unwrap().is_none());
    }

    #[test]
    fn access_coverage() {
        assert!(RuleAccess::Any.covers(Access::Read));
        assert!(RuleAccess::Any.covers(Access::Write));
        assert!(RuleAccess::Read.covers(Access::Read));
        assert!(!RuleAccess::Read.covers(Access::Write));
        assert!(!RuleAccess::Write.covers(Access::Read));
    }

    #[test]
    fn double_star_and_star_match_names_with_newlines() {
        assert!(m("~/.claude/**", "/home/u/.claude/a\nb"));
        assert!(m("**/.env", "/a\nb/.env"));
        assert!(m("/p/*", "/p/a\nb"));
        assert!(!m("/p/*", "/p/a\nb/c"));
        assert!(m("/a/**/b", "/a/x\ny/b"));
    }

    #[test]
    fn empty_components_are_rejected() {
        for bad in ["/a/", "/a//b", "~/", "$HOME/", "/", "**/x/", "/a/**/"] {
            assert!(validate_glob(bad).is_err(), "{bad}");
        }
        for good in ["$HOME/x", "/a/**", "**/x"] {
            assert!(validate_glob(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn a_variable_bound_to_the_root_matches_the_root() {
        let root = PathVars::new().with_var("HOME", "/");
        let c = |g: &str| compile_glob(g, &root, false).unwrap().unwrap();
        assert!(c("~").is_match("/"));
        assert!(!c("~").is_match("/x"));
        assert!(c("$HOME/**").is_match("/"));
        assert!(c("~/.ssh/id_*").is_match("/.ssh/id_rsa"));
        assert!(c("$HOME/x").is_match("/x"));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_variable_value_skips_the_rule() {
        use std::os::unix::ffi::OsStrExt;
        let bad = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/home/\xff"));
        let v = PathVars::new().with_var("HOME", bad);
        assert!(compile_glob("~/.aws/credentials", &v, false)
            .unwrap()
            .is_none());
        assert!(compile_glob("**/.env", &v, false).unwrap().is_some());
    }
}
