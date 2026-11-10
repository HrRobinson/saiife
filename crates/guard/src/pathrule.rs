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

use crate::canon::{PathStyle, PathVars};
use crate::winpath;

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

pub use crate::pack_raw::RuleAccess;

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
        if glob.starts_with('/') || glob.starts_with("**/") || drive_anchored(glob) {
            return Ok((None, glob));
        }
        return Err(format!(
            "path glob {glob:?} must start with /, ~/, **/, a drive (`c:/`, `?:/`) or a variable"
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

/// A glob anchored at a Windows drive: `c:/…` or, for any drive, `?:/…`. Only
/// a Windows path can match it (a Linux path starts with `/`).
fn drive_anchored(glob: &str) -> bool {
    let b = glob.as_bytes();
    b.len() > 3 && (b[0].is_ascii_alphabetic() || b[0] == b'?') && b[1] == b':' && b[2] == b'/'
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
    let windows = vars.style() == PathStyle::Windows;
    let mut alts: Vec<String> = vec![];
    for v in vars.values(name) {
        let Some(v) = v.to_str() else {
            return Ok(None);
        };
        let full = format!("{}{}", v.trim_end_matches('/'), rest);
        let full = if windows { winpath::fold(&full) } else { full };
        alts.push("/".to_string());
        for (i, c) in full.char_indices() {
            if c == '/' && i > 0 {
                let ancestor = &full[..i];
                // A drive's root is `c:/`, never `c:`.
                alts.push(if windows && ancestor.ends_with(':') {
                    regex::escape(&format!("{ancestor}/"))
                } else {
                    regex::escape(ancestor)
                });
            }
        }
    }
    if alts.is_empty() {
        return Ok(None);
    }
    let flags = if case_insensitive || windows {
        "(?is)"
    } else {
        "(?s)"
    };
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
    // Windows: names compare case-folded (the glob is folded here, the regex
    // folds the path), and a path the OS joined may hold a `\` separator.
    let windows = vars.style() == PathStyle::Windows;
    let (sep, name_char) = if windows {
        (r"[/\\]", r"[^/\\]")
    } else {
        ("/", "[^/]")
    };
    let folded;
    let rest = if windows {
        folded = winpath::fold(rest);
        folded.as_str()
    } else {
        rest
    };
    let mut re = String::from(if case_insensitive || windows {
        "(?is)^"
    } else {
        "(?s)^"
    });
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
            } else if windows {
                // A bare variable bound to a drive's root must match `c:/`.
                let v = winpath::fold(v);
                let tail = if rest.is_empty() && v.ends_with(':') {
                    "/"
                } else {
                    ""
                };
                format!("{}{tail}", regex::escape(&v))
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
            // A Windows path starts with its drive or share, not a `/`.
            (0, "**") if windows => re.push_str(".*"),
            (0, "**") => re.push_str("(?:/.*)?"),
            (_, "**") if i == last => re.push_str(&format!("(?:{sep}.*)?")),
            (_, "**") => re.push_str(&format!("(?:{sep}{name_char}+)*")),
            _ => {
                if i > 0 {
                    re.push_str(sep);
                }
                for c in comp.chars() {
                    match c {
                        '*' => re.push_str(&format!("{name_char}*")),
                        '?' => re.push_str(name_char),
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

    #[test]
    fn drive_anchored_globs_are_valid_and_match_only_windows_paths() {
        for g in ["c:/programdata/saiife/**", "?:/programdata/saiife", "D:/x"] {
            assert!(validate_glob(g).is_ok(), "{g}");
        }
        for g in ["cc:/x", "c:x", "c:/", ":/x", "1:/x", "c:\\x"] {
            assert!(validate_glob(g).is_err(), "{g}");
        }
        let win = PathVars::new().with_style(PathStyle::Windows);
        let re = compile_glob("?:/programdata/saiife/**", &win, false)
            .unwrap()
            .unwrap();
        assert!(re.is_match("c:/ProgramData/saiife/bin/saiife.exe"));
        assert!(re.is_match("d:/programdata/saiife/x"));
        assert!(!re.is_match("c:/programdata/other/x"));
        let posix = compile_glob("?:/programdata/saiife/**", &vars(), false)
            .unwrap()
            .unwrap();
        assert!(!posix.is_match("/programdata/saiife/x"));
        assert!(!posix.is_match("/home/u/c:/programdata/saiife/x"));
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

    // POSIX style reads `/home/u` through `std::path`, and a Windows host calls
    // that relative, so the variable never binds. No Windows host runs POSIX style;
    // the `win_vars` tests pin the Windows reading.
    #[cfg(unix)]
    #[test]
    fn home_and_star() {
        assert!(m("~/.ssh/id_*", "/home/u/.ssh/id_ed25519"));
        assert!(m("~/.ssh/id_*", "/home/u/.ssh/id_rsa.pub"));
        assert!(!m("~/.ssh/id_*", "/home/u/.ssh/config"));
        assert!(!m("~/.ssh/id_*", "/home/u/.ssh/keys/id_rsa"));
        assert!(m("$HOME/.kube/config", "/home/u/.kube/config"));
        assert!(m("~/.ssh/id_?sa", "/home/u/.ssh/id_rsa"));
    }

    // POSIX style reads `/home/u` through `std::path`, and a Windows host calls
    // that relative, so the variable never binds. No Windows host runs POSIX style;
    // the `win_vars` tests pin the Windows reading.
    #[cfg(unix)]
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

    // POSIX style reads `/home/u` through `std::path`, and a Windows host calls
    // that relative, so the variable never binds. No Windows host runs POSIX style;
    // the `win_vars` tests pin the Windows reading.
    #[cfg(unix)]
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

    // POSIX style reads `/home/u` through `std::path`, and a Windows host calls
    // that relative, so the variable never binds. No Windows host runs POSIX style;
    // the `win_vars` tests pin the Windows reading.
    #[cfg(unix)]
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

    /// The regex text of POSIX rules is pinned: Linux and macOS behaviour
    /// must not move because Windows rules were added.
    #[test]
    fn posix_regex_sources_are_unchanged() {
        // A root no host has: on macOS `/home` is a firmlink, and a resolved
        // value would add its own alternative to the pinned text.
        let v = PathVars::new()
            .with_style(PathStyle::Posix)
            .with_var("HOME", "/zz/u");
        if cfg!(windows) {
            return;
        }
        let src = |g: &str| glob_source(g, &v, false).unwrap().unwrap();
        assert_eq!(src("**/.env"), r"(?s)^(?:/.*)?/\.env$");
        assert_eq!(src("~/.ssh/id_*"), r"(?s)^(?:/zz/u)/\.ssh/id_[^/]*$");
        assert_eq!(src("~/.ssh/id_?sa"), r"(?s)^(?:/zz/u)/\.ssh/id_[^/]sa$");
        assert_eq!(src("/a/**/b"), r"(?s)^/a(?:/[^/]+)*/b$");
        assert_eq!(src("$HOME/x/**"), r"(?s)^(?:/zz/u)/x(?:/.*)?$");
        assert_eq!(
            glob_source("**/.ENV", &v, true).unwrap().unwrap(),
            r"(?is)^(?:/.*)?/\.ENV$"
        );
        assert_eq!(
            ancestors_source("$HOME/a", &v, false).unwrap().unwrap(),
            "(?s)^(?:/|/zz|/zz/u)$"
        );
    }

    fn win_vars() -> PathVars {
        PathVars::new()
            .with_style(PathStyle::Windows)
            .with_var("USERPROFILE", r"C:\Users\a")
    }

    fn wm(glob: &str, path: &str) -> bool {
        compile_glob(glob, &win_vars(), false)
            .unwrap()
            .unwrap()
            .is_match(path)
    }

    #[test]
    fn windows_globs_match_case_folded_under_any_root() {
        assert!(wm("**/.env", "c:/p/.env"));
        assert!(wm("**/.env", "c:/P/.ENV"));
        assert!(wm("**/.env", "c:/.env"));
        assert!(wm("**/.env", "//server/share/.env"));
        assert!(!wm("**/.env", "c:/p/.env.example"));
        assert!(!wm("**/.env", "c:/p/my.env"));
        assert!(wm("~/.ssh/id_*", "c:/users/A/.SSH/ID_RSA"));
        assert!(wm("~/.ssh/id_*", "c:/Users/a/.ssh/id_rsa"));
        assert!(!wm("~/.ssh/id_*", "c:/Users/b/.ssh/id_rsa"));
        assert!(!wm("~/.ssh/id_*", "c:/Users/a/.ssh/keys/id_rsa"));
        assert!(wm("~/.ssh/ID_*", "c:/Users/a/.ssh/id_rsa"));
        assert!(wm("**/.saiife/**", "c:/p/.saiife"));
        assert!(wm("**/.saiife/**", "c:/p/.SAIIFE/config.toml"));
        // A POSIX-rooted rule never matches a Windows path (W6).
        assert!(!wm("/etc/passwd", "c:/etc/passwd"));
    }

    #[test]
    fn windows_globs_accept_a_separator_the_os_joined() {
        assert!(wm("**/.env", r"c:/p\.env"));
        assert!(wm("~/.ssh/id_*", r"c:/Users/a/.ssh\id_rsa"));
        assert!(!wm("~/.ssh/id_*", r"c:/Users/a/.ssh\keys\id_rsa"));
    }

    #[test]
    fn windows_variable_bound_to_a_drive_root() {
        let v = PathVars::new()
            .with_style(PathStyle::Windows)
            .with_var("HOME", r"C:\");
        let c = |g: &str| compile_glob(g, &v, false).unwrap().unwrap();
        assert!(c("~").is_match("c:/"));
        assert!(!c("~").is_match("c:/x"));
        assert!(c("~/**").is_match("c:/"));
        assert!(c("~/.ssh/id_*").is_match("c:/.ssh/id_rsa"));
    }

    #[test]
    fn windows_ancestors_stop_at_the_drive_root() {
        let v = win_vars().with_var("SAIIFE_DATA_DIR", r"C:\Users\a\AppData\Local\saiife");
        let r = compile_ancestors("$SAIIFE_DATA_DIR", &v, false)
            .unwrap()
            .unwrap();
        for yes in ["c:/", "C:/", "c:/users", "c:/Users/A/AppData/Local"] {
            assert!(r.is_match(yes), "{yes}");
        }
        for no in ["c:", "c:/Users/a/AppData/Local/saiife", "d:/", "c:/other"] {
            assert!(!r.is_match(no), "{no}");
        }
    }

    #[test]
    fn access_coverage() {
        assert!(RuleAccess::Any.covers(Access::Read));
        assert!(RuleAccess::Any.covers(Access::Write));
        assert!(RuleAccess::Read.covers(Access::Read));
        assert!(!RuleAccess::Read.covers(Access::Write));
        assert!(!RuleAccess::Write.covers(Access::Read));
    }

    // POSIX style reads `/home/u` through `std::path`, and a Windows host calls
    // that relative, so the variable never binds. No Windows host runs POSIX style;
    // the `win_vars` tests pin the Windows reading.
    #[cfg(unix)]
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

    // POSIX style reads `/home/u` through `std::path`, and a Windows host calls
    // that relative, so the variable never binds. No Windows host runs POSIX style;
    // the `win_vars` tests pin the Windows reading.
    #[cfg(unix)]
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
