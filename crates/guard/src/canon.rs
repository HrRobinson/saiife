//! Path canonicalization for path rules (spec §7.2): a path is judged by
//! what it really names, not how it was spelled.
//!
//! - `~`, `~/…`, `$HOME/…`, `${HOME}/…` expand to the home directory and
//!   `$PWD/…`, `${PWD}/…` to the working directory;
//! - a relative path is joined to the working directory;
//! - the longest prefix that exists is resolved by the OS (symlinks, `..`
//!   through symlinks), and the rest is normalized lexically (`.` dropped,
//!   `..` pops one component).
//!
//! A path that cannot be made absolute (relative, with no working
//! directory known) yields `None`: the caller decides what that means.
//!
//! Rules are matched against both the resolved path and the path as
//! spelled (made absolute, `..` removed lexically), so a symlink is judged
//! by what it points to AND by its own name: `notes.txt -> .env` reads a
//! secret, and so does `.env -> vars/dev`.

use std::path::{Component, Path, PathBuf};

/// Directories the engine resolves paths and rule variables against.
#[derive(Debug, Clone, Default)]
pub struct PathVars {
    cwd: Option<PathBuf>,
    vars: Vec<(String, PathBuf)>,
}

impl PathVars {
    pub fn new() -> Self {
        Self::default()
    }

    /// The working directory relative paths are joined to. Must be
    /// absolute; anything else is ignored.
    pub fn with_cwd(mut self, cwd: impl AsRef<Path>) -> Self {
        let cwd = cwd.as_ref();
        if cwd.is_absolute() {
            self.cwd = Some(resolve(cwd));
        }
        self
    }

    /// Add a value for a rule variable (`HOME`, `PROJECT`, …). A variable
    /// may have several values (`SAIIFE_BIN`: the running binary and the one
    /// on `PATH`). Relative values are ignored; values are canonicalized.
    pub fn with_var(mut self, name: &str, value: impl AsRef<Path>) -> Self {
        let value = value.as_ref();
        if value.is_absolute() {
            let v = resolve(value);
            if !self.vars.iter().any(|(n, x)| n == name && *x == v) {
                self.vars.push((name.to_string(), v));
            }
        }
        self
    }

    pub fn cwd(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    pub fn home(&self) -> Option<&Path> {
        self.values("HOME").into_iter().next()
    }

    pub fn values(&self, name: &str) -> Vec<&Path> {
        self.vars
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_path())
            .collect()
    }
}

/// Canonicalize `raw` against `cwd` (the working directory at this point
/// of a command line, else the one in `vars`) and the home in `vars`.
pub fn canonicalize(raw: &str, cwd: Option<&Path>, vars: &PathVars) -> Option<PathBuf> {
    absolute(raw, cwd, vars).map(|a| resolve(&a))
}

/// The forms path rules are matched against: the resolved path, and the
/// path as spelled (absolute, lexically normalized) when that differs.
pub fn path_forms(raw: &str, cwd: Option<&Path>, vars: &PathVars) -> Vec<PathBuf> {
    let Some(abs) = absolute(raw, cwd, vars) else {
        return Vec::new();
    };
    let resolved = resolve(&abs);
    let spelled = push_lexical(PathBuf::from("/"), &abs.components().collect::<Vec<_>>());
    if spelled == resolved {
        vec![resolved]
    } else {
        vec![resolved, spelled]
    }
}

/// `raw` with `~`/`$HOME`/`$PWD` expanded and joined to the working
/// directory; not yet resolved.
fn absolute(raw: &str, cwd: Option<&Path>, vars: &PathVars) -> Option<PathBuf> {
    if raw.is_empty() || raw.contains('\0') {
        return None;
    }
    let cwd = cwd.or(vars.cwd());
    let expanded = if let Some(rest) = strip_var(raw, &["~"]) {
        vars.home()?.join(rest)
    } else if let Some(rest) = strip_var(raw, &["$HOME", "${HOME}"]) {
        vars.home()?.join(rest)
    } else if let Some(rest) = strip_var(raw, &["$PWD", "${PWD}"]) {
        cwd?.join(rest)
    } else {
        PathBuf::from(raw)
    };
    if expanded.is_absolute() {
        Some(expanded)
    } else {
        Some(cwd?.join(expanded))
    }
}

/// `raw` starts with one of `prefixes` followed by `/` or the end: the rest
/// (without its leading slashes).
fn strip_var<'a>(raw: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes.iter().find_map(|p| {
        let rest = raw.strip_prefix(p)?;
        if rest.is_empty() {
            Some(rest)
        } else if rest.starts_with('/') {
            Some(rest.trim_start_matches('/'))
        } else {
            None
        }
    })
}

/// Resolve an absolute path: the OS resolves the longest existing prefix,
/// the remaining components are normalized lexically. A second pass
/// resolves what the first one made reachable (`missing/../link`).
fn resolve(abs: &Path) -> PathBuf {
    let once = resolve_once(abs);
    if once == abs {
        once
    } else {
        resolve_once(&once)
    }
}

fn resolve_once(abs: &Path) -> PathBuf {
    let comps: Vec<Component> = abs.components().collect();
    for i in (1..=comps.len()).rev() {
        let prefix: PathBuf = comps[..i].iter().collect();
        if let Ok(real) = std::fs::canonicalize(&prefix) {
            return push_lexical(real, &comps[i..]);
        }
    }
    push_lexical(PathBuf::from("/"), &comps)
}

fn push_lexical(mut base: PathBuf, rest: &[Component]) -> PathBuf {
    for c in rest {
        match c {
            Component::Normal(n) => base.push(n),
            Component::ParentDir => {
                base.pop();
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A temp dir by its canonical path (macOS: /var -> /private/var).
    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = fs::canonicalize(d.path()).unwrap();
        (d, p)
    }

    #[test]
    fn expands_home_and_pwd() {
        let (_d, root) = tmp();
        let home = root.join("home");
        let app = root.join("app");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(&app).unwrap();
        let v = PathVars::new().with_var("HOME", &home).with_cwd(&app);
        let c = |raw| canonicalize(raw, None, &v).unwrap();
        assert_eq!(c("~/.ssh/id_rsa"), home.join(".ssh/id_rsa"));
        assert_eq!(c("~"), home);
        assert_eq!(c("$HOME/.ssh/id_rsa"), home.join(".ssh/id_rsa"));
        assert_eq!(c("${HOME}//.ssh/id_rsa"), home.join(".ssh/id_rsa"));
        assert_eq!(c("$PWD/.env"), app.join(".env"));
        assert_eq!(c(".env"), app.join(".env"));
        assert_eq!(c("./.env"), app.join(".env"));
        // Not variables: left as literal names.
        assert_eq!(c("$HOMEDIR/x"), app.join("$HOMEDIR/x"));
        assert_eq!(c("~user/x"), app.join("~user/x"));
    }

    #[test]
    fn dot_dot_and_missing_components() {
        let (_d, root) = tmp();
        let app = root.join("app");
        fs::create_dir_all(app.join("src")).unwrap();
        let v = PathVars::new().with_cwd(&app);
        let c = |raw| canonicalize(raw, None, &v).unwrap();
        assert_eq!(c("src/../.env"), app.join(".env"));
        assert_eq!(c("nope/../.env"), app.join(".env"));
        assert_eq!(c("src/../../app/.env"), app.join(".env"));
        assert_eq!(c("/../../.."), PathBuf::from("/"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_followed_where_they_exist() {
        let (_d, root) = tmp();
        let app = root.join("app");
        let secrets = root.join("secrets");
        fs::create_dir_all(&app).unwrap();
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join(".env"), "K=v").unwrap();
        std::os::unix::fs::symlink(secrets.join(".env"), app.join("notes.txt")).unwrap();
        std::os::unix::fs::symlink(&secrets, app.join("cfg")).unwrap();
        let v = PathVars::new().with_cwd(&app);
        let c = |raw| canonicalize(raw, None, &v).unwrap();
        assert_eq!(c("notes.txt"), secrets.join(".env"));
        assert_eq!(c("cfg/.env"), secrets.join(".env"));
        // A missing file inside a symlinked directory still resolves.
        assert_eq!(c("cfg/new.txt"), secrets.join("new.txt"));
        // `..` after a symlinked directory is the real parent (the OS rule).
        assert_eq!(c("cfg/../app"), app);
    }

    #[cfg(unix)]
    #[test]
    fn forms_are_the_target_and_the_name() {
        let (_d, root) = tmp();
        fs::write(root.join("vars"), "K=v").unwrap();
        std::os::unix::fs::symlink(root.join("vars"), root.join(".env")).unwrap();
        let v = PathVars::new().with_cwd(&root);
        assert_eq!(
            path_forms("./x/../.env", None, &v),
            vec![root.join("vars"), root.join(".env")]
        );
        assert_eq!(path_forms("vars", None, &v), vec![root.join("vars")]);
        assert!(path_forms("x", None, &PathVars::new()).is_empty());
    }

    #[test]
    fn relative_without_cwd_or_tilde_without_home_is_none() {
        let v = PathVars::new();
        assert_eq!(canonicalize(".env", None, &v), None);
        assert_eq!(canonicalize("~/.ssh/id_rsa", None, &v), None);
        assert_eq!(canonicalize("", None, &v), None);
        assert!(canonicalize("/etc/hosts", None, &v).is_some());
    }

    #[test]
    fn explicit_cwd_wins_over_the_default() {
        let (_d, root) = tmp();
        let v = PathVars::new().with_cwd(root.join("a"));
        assert_eq!(
            canonicalize(".env", Some(&root.join("b")), &v).unwrap(),
            root.join("b/.env")
        );
    }

    #[test]
    fn vars_are_canonical_and_deduplicated() {
        let (_d, root) = tmp();
        let v = PathVars::new()
            .with_var("SAIIFE_BIN", root.join("x/../bin"))
            .with_var("SAIIFE_BIN", root.join("bin"))
            .with_var("SAIIFE_BIN", "relative/ignored");
        assert_eq!(v.values("SAIIFE_BIN"), vec![root.join("bin").as_path()]);
        assert!(v.values("HOME").is_empty());
    }
}
