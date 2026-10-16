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

use std::collections::VecDeque;
use std::ffi::OsString;
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
            self.cwd = resolve(cwd);
        }
        self
    }

    /// Add a value for a rule variable (`HOME`, `PROJECT`, …). A variable
    /// may have several values (`SAIIFE_BIN`: the running binary and the one
    /// on `PATH`). Relative values are ignored; values are canonicalized.
    pub fn with_var(mut self, name: &str, value: impl AsRef<Path>) -> Self {
        let value = value.as_ref();
        if value.is_absolute() {
            if let Some(v) = resolve(value) {
                if !self.vars.iter().any(|(n, x)| n == name && *x == v) {
                    self.vars.push((name.to_string(), v));
                }
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
    absolute(raw, cwd, vars).and_then(|a| resolve(&a))
}

/// The forms path rules are matched against: the resolved path, and the
/// path as spelled (absolute, lexically normalized) when that differs.
pub fn path_forms(raw: &str, cwd: Option<&Path>, vars: &PathVars) -> Vec<PathBuf> {
    let Some(abs) = absolute(raw, cwd, vars) else {
        return Vec::new();
    };
    let Some(resolved) = resolve(&abs) else {
        return Vec::new();
    };
    let spelled = push_lexical(PathBuf::from("/"), &abs.components().collect::<Vec<_>>());
    if spelled == resolved {
        vec![resolved]
    } else {
        vec![resolved, spelled]
    }
}

/// The path as spelled, made absolute with `..` removed lexically: no
/// filesystem access at all, so it can be judged before the (slower)
/// resolution. `cwd` is used as given and should already be canonical
/// (the engine's working directories are).
pub fn lexical_form(raw: &str, cwd: Option<&Path>, vars: &PathVars) -> Option<PathBuf> {
    let abs = absolute_with(raw, cwd.map(Path::to_path_buf), cwd.is_some(), vars)?;
    Some(push_lexical(
        PathBuf::from("/"),
        &abs.components().collect::<Vec<_>>(),
    ))
}

/// `raw` with `~`/`$HOME`/`$PWD` expanded and joined to the working
/// directory; not yet resolved.
fn absolute(raw: &str, cwd: Option<&Path>, vars: &PathVars) -> Option<PathBuf> {
    // An explicit cwd is resolved like `PathVars::with_cwd` does, so the
    // spelled form is canonical too; a relative one cannot anchor anything.
    let explicit = cwd.is_some();
    let cwd = match cwd {
        Some(c) if c.is_absolute() => Some(resolve(c)?),
        Some(c) => Some(c.to_path_buf()),
        None => None,
    };
    absolute_with(raw, cwd, explicit, vars)
}

fn absolute_with(
    raw: &str,
    cwd: Option<PathBuf>,
    explicit: bool,
    vars: &PathVars,
) -> Option<PathBuf> {
    if raw.is_empty() || raw.contains('\0') {
        return None;
    }
    let cwd = if explicit {
        cwd
    } else {
        vars.cwd().map(Path::to_path_buf)
    };
    let cwd = cwd.as_deref();
    let expanded = if let Some(rest) = strip_var(raw, &["~"]) {
        vars.home()?.join(rest)
    } else if let Some(rest) = strip_var(raw, &["$HOME", "${HOME}"]) {
        vars.home()?.join(rest)
    } else if let Some(rest) = strip_var(raw, &["$PWD", "${PWD}"]) {
        cwd?.join(rest)
    } else {
        PathBuf::from(raw)
    };
    let abs = if expanded.is_absolute() {
        expanded
    } else {
        cwd?.join(expanded)
    };
    abs.is_absolute().then_some(abs)
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

/// Resolve an absolute path: the OS resolves the existing part, the rest
/// is normalized lexically. A second pass resolves what the first one made
/// reachable (`missing/../link`). `None`: unresolvable (symlink loop).
fn resolve(abs: &Path) -> Option<PathBuf> {
    let once = resolve_once(abs)?;
    if once == abs {
        Some(once)
    } else {
        resolve_once(&once)
    }
}

/// Longest path the OS accepts; anything longer cannot exist on disk.
const PATH_MAX: usize = 4096;
/// Symlinks followed in one resolution, like the OS's ELOOP limit.
const MAX_HOPS: usize = 40;

/// Walk forward from the root, one component at a time (linear in depth):
/// symlinks, dangling ones included, are replaced by their target; at the
/// first component that does not exist the rest is normalized lexically.
fn resolve_once(abs: &Path) -> Option<PathBuf> {
    if abs.as_os_str().len() > PATH_MAX {
        let comps: Vec<Component> = abs.components().collect();
        return Some(push_lexical(PathBuf::from("/"), &comps));
    }
    // Owned segments: `Some(name)`, or `None` for `..`.
    let seg = |c: Component| match c {
        Component::Normal(n) => Some(Some(n.to_os_string())),
        Component::ParentDir => Some(None),
        _ => None,
    };
    let mut queue: VecDeque<Option<OsString>> = abs.components().filter_map(seg).collect();
    let mut base = PathBuf::from("/");
    let mut hops = 0;
    while let Some(c) = queue.pop_front() {
        match c {
            Some(n) => {
                let next = base.join(n);
                match std::fs::symlink_metadata(&next) {
                    Ok(md) if md.file_type().is_symlink() => {
                        hops += 1;
                        if hops > MAX_HOPS {
                            return None;
                        }
                        let target = std::fs::read_link(&next).ok()?;
                        if target.is_absolute() {
                            base = PathBuf::from("/");
                        }
                        for tc in target.components().rev().filter_map(seg) {
                            queue.push_front(tc);
                        }
                    }
                    Ok(_) => base = next,
                    Err(_) => {
                        base = next;
                        break;
                    }
                }
            }
            None => {
                base.pop();
            }
        }
    }
    for c in queue {
        match c {
            Some(n) => base.push(n),
            None => {
                base.pop();
            }
        }
    }
    Some(base)
}

/// Directory entries one glob expansion may look at before giving up.
pub const GLOB_SCAN_LIMIT: usize = 4096;

/// What a word with unquoted `*`, `?` or `[` expands to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobExpansion {
    /// No glob characters: judge the word as it is.
    NotAGlob,
    /// The existing paths it matches, sorted (absolute, as spelled). Empty:
    /// the shell passes the word literally, so judge it as it is.
    Matches(Vec<PathBuf>),
    /// More than `GLOB_SCAN_LIMIT` directory entries would have to be read.
    Overflow,
}

/// Expand `word` like the shell does (bash defaults: `*`, `?`, `[…]`,
/// `[!…]`/`[^…]`; a leading `.` must be matched explicitly, so `*` skips
/// dotfiles while `.env*` finds them), reading at most `GLOB_SCAN_LIMIT`
/// directory entries. `~`, `$HOME` and relative words are anchored like
/// `canonicalize` does; a word that cannot be anchored matches nothing.
pub fn expand_glob(word: &str, cwd: Option<&Path>, vars: &PathVars) -> GlobExpansion {
    if !word.contains(['*', '?', '[']) {
        return GlobExpansion::NotAGlob;
    }
    let Some(abs) = absolute(word, cwd, vars) else {
        return GlobExpansion::Matches(Vec::new());
    };
    let mut bases = vec![PathBuf::from("/")];
    let mut scanned = 0usize;
    let mut literal_tail = false;
    for c in abs.components() {
        match c {
            Component::Normal(name) => {
                let pat: Vec<char> = name.to_string_lossy().chars().collect();
                if !pat.iter().any(|c| matches!(c, '*' | '?' | '[')) {
                    bases.iter_mut().for_each(|b| b.push(name));
                    literal_tail = true;
                    continue;
                }
                literal_tail = false;
                let mut next = Vec::new();
                for b in &bases {
                    let Ok(entries) = std::fs::read_dir(b) else {
                        continue;
                    };
                    for e in entries.flatten() {
                        scanned += 1;
                        if scanned > GLOB_SCAN_LIMIT {
                            return GlobExpansion::Overflow;
                        }
                        let n = e.file_name();
                        let s: Vec<char> = n.to_string_lossy().chars().collect();
                        if s.first() == Some(&'.') && pat.first() != Some(&'.') {
                            continue;
                        }
                        if glob_match(&pat, &s) {
                            next.push(b.join(&n));
                        }
                    }
                }
                next.sort();
                bases = next;
                if bases.is_empty() {
                    break;
                }
            }
            Component::ParentDir => bases.iter_mut().for_each(|b| b.push("..")),
            _ => {}
        }
    }
    if literal_tail {
        bases.retain(|b| std::fs::symlink_metadata(b).is_ok());
    }
    GlobExpansion::Matches(bases)
}

/// Shell pattern match of one path component.
fn glob_match(p: &[char], s: &[char]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        let step = match p.get(pi) {
            Some('*') => {
                star = Some((pi, si));
                pi += 1;
                continue;
            }
            Some('?') => Some(1),
            Some('[') => match class(&p[pi..], s[si]) {
                Some((true, len)) => Some(len),
                Some((false, _)) => None,
                None => (s[si] == '[').then_some(1),
            },
            Some(c) => (*c == s[si]).then_some(1),
            None => None,
        };
        match step {
            Some(len) => {
                pi += len;
                si += 1;
            }
            None => match star {
                Some((sp, ss)) => {
                    pi = sp + 1;
                    si = ss + 1;
                    star = Some((sp, ss + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// A `[…]` class at the start of `p`: whether `c` is in it and the
/// class's length; `None` if unterminated (then `[` is literal).
fn class(p: &[char], c: char) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = matches!(p.get(i), Some('!' | '^'));
    if negate {
        i += 1;
    }
    let first = i;
    let mut hit = false;
    while i < p.len() {
        if p[i] == ']' && i > first {
            return Some((hit != negate, i + 1));
        }
        if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|e| *e != ']') {
            hit |= p[i] <= c && c <= p[i + 2];
            i += 3;
        } else {
            hit |= p[i] == c;
            i += 1;
        }
    }
    None
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

    #[cfg(unix)]
    #[test]
    fn dangling_symlinks_are_followed() {
        let (_d, root) = tmp();
        let app = root.join("app");
        fs::create_dir_all(&app).unwrap();
        let target = root.join(".claude/settings.local.json");
        std::os::unix::fs::symlink(&target, app.join("x")).unwrap();
        // Relative dangling target, and a chain of two.
        std::os::unix::fs::symlink("../gone/new.txt", app.join("rel")).unwrap();
        std::os::unix::fs::symlink(app.join("x"), app.join("chain")).unwrap();
        let v = PathVars::new().with_cwd(&app);
        assert_eq!(canonicalize("x", None, &v).unwrap(), target);
        assert_eq!(
            path_forms("x", None, &v),
            vec![target.clone(), app.join("x")]
        );
        assert_eq!(
            canonicalize("rel", None, &v).unwrap(),
            root.join("gone/new.txt")
        );
        assert_eq!(canonicalize("chain", None, &v).unwrap(), target);
        // A dangling link used as a directory prefix.
        std::os::unix::fs::symlink(root.join("nodir"), app.join("d")).unwrap();
        assert_eq!(canonicalize("d/f", None, &v).unwrap(), root.join("nodir/f"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loops_are_unresolvable() {
        let (_d, root) = tmp();
        std::os::unix::fs::symlink(root.join("b"), root.join("a")).unwrap();
        std::os::unix::fs::symlink(root.join("a"), root.join("b")).unwrap();
        let v = PathVars::new().with_cwd(&root);
        assert_eq!(canonicalize("a", None, &v), None);
        assert!(path_forms("a/x", None, &v).is_empty());
    }

    #[test]
    fn very_deep_paths_resolve_fast() {
        let (_d, root) = tmp();
        let v = PathVars::new().with_cwd(&root);
        let deep = "a/".repeat(100_000);
        let t = std::time::Instant::now();
        let r = canonicalize(&deep, None, &v).unwrap();
        let forms = path_forms(&format!("{deep}../.env"), None, &v);
        let took = t.elapsed();
        eprintln!("deep path took {took:?}");
        assert!(took < std::time::Duration::from_secs(1), "{took:?}");
        assert!(r.starts_with(&root));
        assert_eq!(forms.len(), 1);
        // Just under PATH_MAX still resolves through the OS.
        let near = "b/".repeat(1000);
        let t = std::time::Instant::now();
        assert!(canonicalize(&near, None, &v).is_some());
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn relative_explicit_cwd_is_none() {
        let (_d, root) = tmp();
        let v = PathVars::new().with_cwd(&root);
        assert_eq!(canonicalize(".env", Some(Path::new("sub")), &v), None);
        assert!(path_forms(".env", Some(Path::new("sub")), &v).is_empty());
        // An absolute path does not need the cwd.
        assert!(canonicalize("/etc/hosts", Some(Path::new("sub")), &v).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_cwd_is_resolved_like_with_cwd() {
        let (_d, root) = tmp();
        fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let v = PathVars::new();
        let forms = path_forms(".env", Some(&root.join("link")), &v);
        assert_eq!(forms, vec![root.join("real/.env")]);
    }

    #[test]
    fn globs_expand_against_the_filesystem() {
        let (_d, root) = tmp();
        let app = root.join("app");
        let home = root.join("home");
        fs::create_dir_all(app.join("src")).unwrap();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        for f in [".env", ".env.local", "a.rs", "b.rs", "src/main.rs"] {
            fs::write(app.join(f), "").unwrap();
        }
        for f in ["id_rsa", "id_rsa.pub"] {
            fs::write(home.join(".ssh").join(f), "").unwrap();
        }
        let v = PathVars::new().with_cwd(&app).with_var("HOME", &home);
        let m = |p: &str| match expand_glob(p, None, &v) {
            GlobExpansion::Matches(m) => m,
            other => panic!("{p}: {other:?}"),
        };
        assert_eq!(m(".env*"), vec![app.join(".env"), app.join(".env.local")]);
        assert_eq!(m("*.rs"), vec![app.join("a.rs"), app.join("b.rs")]);
        // `*` does not match a leading dot (bash without dotglob).
        assert_eq!(
            m("*"),
            vec![app.join("a.rs"), app.join("b.rs"), app.join("src")]
        );
        assert_eq!(m(".e?v"), vec![app.join(".env")]);
        assert_eq!(m(".[e]nv"), vec![app.join(".env")]);
        assert_eq!(m("[!a].rs"), vec![app.join("b.rs")]);
        assert_eq!(m("[^a].rs"), vec![app.join("b.rs")]);
        assert_eq!(m("[a-b].rs"), vec![app.join("a.rs"), app.join("b.rs")]);
        assert_eq!(m("s*/*.rs"), vec![app.join("src/main.rs")]);
        assert_eq!(m("*/main.rs"), vec![app.join("src/main.rs")]);
        assert_eq!(
            m("~/.ssh/*"),
            vec![home.join(".ssh/id_rsa"), home.join(".ssh/id_rsa.pub")]
        );
        assert_eq!(
            m(&format!("{}/.ssh/id_*", home.display())),
            vec![home.join(".ssh/id_rsa"), home.join(".ssh/id_rsa.pub")]
        );
        assert!(m("nope*").is_empty());
        assert!(m("s*/nope").is_empty());
        assert!(matches!(
            expand_glob(".env", None, &v),
            GlobExpansion::NotAGlob
        ));
        assert!(matches!(
            expand_glob("x*", None, &PathVars::new()),
            GlobExpansion::Matches(m) if m.is_empty()
        ));
    }

    #[test]
    fn huge_globs_overflow() {
        let (_d, root) = tmp();
        fs::create_dir_all(root.join("big")).unwrap();
        for i in 0..(GLOB_SCAN_LIMIT + 10) {
            fs::write(root.join(format!("big/f{i}")), "").unwrap();
        }
        let v = PathVars::new().with_cwd(&root);
        assert!(matches!(
            expand_glob("big/*", None, &v),
            GlobExpansion::Overflow
        ));
        assert!(matches!(
            expand_glob("b*/f1", None, &v),
            GlobExpansion::Matches(_)
        ));
    }

    #[test]
    fn lexical_form_needs_no_filesystem() {
        let v = PathVars::new().with_var("HOME", "/h");
        assert_eq!(
            lexical_form("a/../.env", Some(Path::new("/p")), &v),
            Some(PathBuf::from("/p/.env"))
        );
        assert_eq!(
            lexical_form("~/.ssh/id_rsa", None, &v),
            Some(PathBuf::from("/h/.ssh/id_rsa"))
        );
        assert_eq!(lexical_form(".env", None, &v), None);
    }
}
