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
            // The resolved value first, then the value as spelled (`..`
            // removed lexically): a symlinked directory is guarded under
            // both names.
            let spelled = push_lexical(PathBuf::from("/"), &value.components().collect::<Vec<_>>());
            for v in resolve(value).into_iter().chain([spelled]) {
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

/// Words one brace expansion may produce before it is refused.
pub const BRACE_LIMIT: usize = 1024;

/// Bytes one brace expansion may produce in all before it is refused.
pub const BRACE_BYTES: usize = 64 * 1024;
/// Brace characters (`{`, `,`, `}`) one word may hold.
pub const BRACE_MARKS: usize = 512;

/// Bash brace expansion of `word`: `a{b,c}d` is `abd acd`, nested and
/// repeated braces too, empty alternatives allowed (`x{,.bak}`). A brace
/// without a top-level comma (`{a}`, `${HOME}`) is literal. `None`: more
/// than `BRACE_LIMIT` words, `BRACE_BYTES` bytes or `BRACE_MARKS` braces.
pub fn expand_braces(word: &str) -> Option<Vec<String>> {
    let b = word.as_bytes();
    let mut marks = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            // `${…}` is parameter syntax, not a brace expansion.
            b'$' if b.get(i + 1) == Some(&b'{') => {
                let mut depth = 0usize;
                i += 1;
                while i < b.len() {
                    match b[i] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
            }
            b'{' | b',' | b'}' => marks.push(i),
            _ => {}
        }
        i += 1;
    }
    expand_marked(word, &marks)
}

/// Brace expansion where only the `{`, `,` and `}` at byte offsets `marks`
/// (ascending) are structural; the lexer passes the unquoted ones. Both
/// `{a,b}` alternatives and `{x..y[..step]}` sequences (integers or single
/// letters) expand. Each produced word is searched once, in linear time.
pub fn expand_marked(text: &str, marks: &[usize]) -> Option<Vec<String>> {
    if marks.len() > BRACE_MARKS {
        return None;
    }
    let mut done: Vec<String> = Vec::new();
    let mut bytes = text.len();
    let mut stack = vec![(text.to_string(), marks.to_vec())];
    while let Some((w, m)) = stack.pop() {
        let Some(group) = find_marked(&w, &m) else {
            done.push(w);
            continue;
        };
        bytes -= w.len();
        let (open, close) = (m[group.open], m[group.close]);
        // Each alternative: its text and the marks inside it (as offsets
        // into that text).
        let alts: Vec<(String, Vec<usize>)> = match &group.kind {
            Group::Commas(commas) => {
                let mut cuts = vec![open];
                cuts.extend(commas.iter().map(|&j| m[j]));
                cuts.push(close);
                cuts.windows(2)
                    .map(|c| {
                        let (a0, a1) = (c[0] + 1, c[1]);
                        let inner = m[group.open + 1..group.close]
                            .iter()
                            .filter(|&&x| x >= a0 && x < a1)
                            .map(|&x| x - a0)
                            .collect();
                        (w[a0..a1].to_string(), inner)
                    })
                    .collect()
            }
            Group::Sequence(items) => items.iter().map(|i| (i.clone(), Vec::new())).collect(),
        };
        if done.len() + stack.len() + alts.len() > BRACE_LIMIT {
            return None;
        }
        let (prefix, suffix) = (&w[..open], &w[close + 1..]);
        for (alt, inner) in alts.into_iter().rev() {
            let mut nm: Vec<usize> = m[..group.open].to_vec();
            nm.extend(inner.iter().map(|&x| x + open));
            let base = open + alt.len();
            nm.extend(m[group.close + 1..].iter().map(|&x| x - (close + 1) + base));
            let next = format!("{prefix}{alt}{suffix}");
            bytes += next.len();
            if bytes > BRACE_BYTES {
                return None;
            }
            stack.push((next, nm));
        }
    }
    Some(done)
}

/// A brace group that expands: indices into the marks of its `{` and `}`.
struct BraceGroup {
    open: usize,
    close: usize,
    kind: Group,
}

enum Group {
    /// Indices into the marks of its top-level commas.
    Commas(Vec<usize>),
    /// The words of a `{x..y[..step]}` sequence.
    Sequence(Vec<String>),
}

/// The leftmost brace group that expands (it then has no expanding group
/// around it): one pass over the marks with a stack.
fn find_marked(w: &str, m: &[usize]) -> Option<BraceGroup> {
    let b = w.as_bytes();
    // Open groups: (mark index of `{`, commas, has inner marks).
    let mut open: Vec<(usize, Vec<usize>, bool)> = Vec::new();
    let mut best: Option<BraceGroup> = None;
    for (j, &x) in m.iter().enumerate() {
        match b[x] {
            b'{' => {
                if let Some(top) = open.last_mut() {
                    top.2 = true;
                }
                open.push((j, Vec::new(), false));
            }
            b',' => {
                if let Some(top) = open.last_mut() {
                    top.1.push(j);
                    top.2 = true;
                }
            }
            b'}' => {
                let Some((oi, commas, inner)) = open.pop() else {
                    continue;
                };
                if let Some(top) = open.last_mut() {
                    top.2 = true;
                }
                if best.as_ref().is_some_and(|g| g.open < oi) {
                    continue;
                }
                let kind = if !commas.is_empty() {
                    Some(Group::Commas(commas))
                } else if !inner {
                    sequence(&w[m[oi] + 1..x]).map(Group::Sequence)
                } else {
                    None
                };
                if let Some(kind) = kind {
                    best = Some(BraceGroup {
                        open: oi,
                        close: j,
                        kind,
                    });
                }
            }
            _ => {}
        }
    }
    best
}

/// `x..y` or `x..y..step` with integers or single ASCII letters, as bash
/// expands them (zero-padded when an end is written with a leading zero).
/// `None` if not a sequence; a sequence over `BRACE_LIMIT` words is
/// refused by the caller's limit through a too-long list.
fn sequence(body: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = body.split("..").collect();
    if !(2..=3).contains(&parts.len()) {
        return None;
    }
    let step: i64 = match parts.get(2) {
        Some(s) => s.parse::<i64>().ok()?.checked_abs()?.max(1),
        None => 1,
    };
    let int = |s: &str| -> Option<i64> {
        let digits = s.strip_prefix('-').unwrap_or(s);
        (!digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let (x, y, letters) = match (int(parts[0]), int(parts[1])) {
        (Some(x), Some(y)) => (x, y, false),
        _ => {
            let one = |s: &str| -> Option<i64> {
                let mut c = s.chars();
                let ch = c.next()?;
                (c.next().is_none() && ch.is_ascii_alphabetic()).then_some(ch as i64)
            };
            (one(parts[0])?, one(parts[1])?, true)
        }
    };
    let count = (x - y).unsigned_abs() / step as u64 + 1;
    if count > BRACE_LIMIT as u64 {
        // Too many words: an over-limit list the caller refuses.
        return Some(vec![String::new(); BRACE_LIMIT + 1]);
    }
    let padded = |s: &str| {
        let d = s.strip_prefix('-').unwrap_or(s);
        d.len() > 1 && d.starts_with('0')
    };
    let width = if !letters && (padded(parts[0]) || padded(parts[1])) {
        parts[0].len().max(parts[1].len())
    } else {
        0
    };
    let dir = if y >= x { step } else { -step };
    Some(
        (0..count as i64)
            .map(|k| x + k * dir)
            .map(|v| {
                if letters {
                    char::from(v as u8).to_string()
                } else if width > 0 {
                    let sign = if v < 0 { "-" } else { "" };
                    let w = width - sign.len();
                    format!("{sign}{:0w$}", v.abs())
                } else {
                    v.to_string()
                }
            })
            .collect(),
    )
}

/// Expand `word` like the shell does (bash defaults plus globstar):
/// `{a,b}` alternatives, `*`, `?`, `[…]`, `[!…]`/`[^…]` within one
/// component, and `**` for any number of directories. A leading `.` must
/// be matched explicitly, so `*` and `**` skip dotfiles and hidden
/// directories while `.env*` finds them; symlinked directories are not
/// descended into. At most `GLOB_SCAN_LIMIT` directory entries are read
/// in all. `~`, `$HOME` and relative words are anchored like
/// `canonicalize` does; a word that cannot be anchored matches nothing.
pub fn expand_glob(word: &str, cwd: Option<&Path>, vars: &PathVars) -> GlobExpansion {
    match expand_glob_partial(word, cwd, vars) {
        (_, true) => GlobExpansion::Overflow,
        (m, false) if m.is_empty() && is_plain(word) => GlobExpansion::NotAGlob,
        (m, false) => GlobExpansion::Matches(m),
    }
}

/// Directory entries (and directory reads) one whole expansion may cost,
/// the retry after an overflow included.
pub const GLOB_TOTAL_LIMIT: usize = 2 * GLOB_SCAN_LIMIT;
/// Components a pattern may have to be expanded at all.
const GLOB_MAX_COMPONENTS: usize = 256;

/// Like `expand_glob`, but also tells what was found before the scan limit
/// was hit: `(matches, overflowed)`. When it overflowed, the matches are
/// those the first `GLOB_SCAN_LIMIT` entries led to, plus what the rest of
/// the pattern matches below the directories seen so far (one retry, from
/// the same total budget of `GLOB_TOTAL_LIMIT`). With brace alternatives,
/// every alternative is expanded even after one overflowed, and the
/// literal of each alternative that overflowed or matched nothing is in
/// the list, so a caller judges every spelling. A pattern with more than
/// 256 components or longer than `PATH_MAX` overflows without being read.
/// A word without glob characters yields `([], false)`.
pub fn expand_glob_partial(
    word: &str,
    cwd: Option<&Path>,
    vars: &PathVars,
) -> (Vec<PathBuf>, bool) {
    let Some(alternatives) = expand_braces(word) else {
        return (Vec::new(), true);
    };
    expand_alternatives(&alternatives, cwd, vars)
}

/// `expand_glob` for a shell operand the lexer already brace-expanded:
/// braces left in it were quoted, so they are literal here.
pub fn expand_operand_glob(word: &str, cwd: Option<&Path>, vars: &PathVars) -> GlobExpansion {
    if !word.contains(['*', '?', '[']) {
        return GlobExpansion::NotAGlob;
    }
    match expand_alternatives(&[word.to_string()], cwd, vars) {
        (_, true) => GlobExpansion::Overflow,
        (m, false) => GlobExpansion::Matches(m),
    }
}

fn expand_alternatives(
    alternatives: &[String],
    cwd: Option<&Path>,
    vars: &PathVars,
) -> (Vec<PathBuf>, bool) {
    let has_meta = |w: &str| w.contains(['*', '?', '[']);
    if alternatives.len() == 1 && !has_meta(&alternatives[0]) {
        return (Vec::new(), false);
    }
    let several = alternatives.len() > 1;
    let mut budget = Budget::default();
    let mut all = Vec::new();
    let mut overflow = false;
    for alt in alternatives {
        let Some(abs) = absolute(alt, cwd, vars) else {
            continue;
        };
        let comps: Vec<Component> = abs.components().collect();
        if comps.len() > GLOB_MAX_COMPONENTS || abs.as_os_str().len() > PATH_MAX {
            overflow = true;
            if several {
                all.push(abs);
            }
            continue;
        }
        let (found, over) = expand_from(&comps, vec![PathBuf::from("/")], &mut budget);
        overflow |= over;
        if several && (over || found.is_empty()) {
            all.push(push_lexical(PathBuf::from("/"), &comps));
        }
        all.extend(found);
    }
    all.sort();
    all.dedup();
    (all, overflow)
}

/// Directory reads and entries spent, against one stage limit and the
/// total.
#[derive(Default)]
struct Budget {
    spent: usize,
}

impl Budget {
    /// Spend one; false past `limit`.
    fn take(&mut self, limit: usize) -> bool {
        self.spent += 1;
        self.spent <= limit
    }
}

/// A word `expand_glob` leaves as it is: no glob characters after brace
/// expansion (one alternative).
fn is_plain(word: &str) -> bool {
    matches!(expand_braces(word), Some(a) if a.len() == 1 && !a[0].contains(['*', '?', '[']))
}

/// Expand one brace-free absolute pattern: `(matches, overflowed)`. The
/// first pass may spend `GLOB_SCAN_LIMIT`; when it runs out at a
/// component, the rest of the pattern is applied once to what was seen so
/// far, until `GLOB_TOTAL_LIMIT`. There is no retry of the retry.
fn expand_from(
    comps: &[Component],
    bases: Vec<PathBuf>,
    budget: &mut Budget,
) -> (Vec<PathBuf>, bool) {
    match walk(comps, 0, bases, budget, GLOB_SCAN_LIMIT) {
        Walk::Done(m) => (m, false),
        Walk::Stopped { at, seen } => match walk(comps, at + 1, seen, budget, GLOB_TOTAL_LIMIT) {
            Walk::Done(m) => (m, true),
            Walk::Stopped { .. } => (Vec::new(), true),
        },
    }
}

enum Walk {
    Done(Vec<PathBuf>),
    /// Out of budget at component `at`, having matched `seen` there.
    Stopped {
        at: usize,
        seen: Vec<PathBuf>,
    },
}

/// Apply `comps[start..]` to `bases`, spending `budget` up to `limit`.
fn walk(
    comps: &[Component],
    start: usize,
    mut bases: Vec<PathBuf>,
    budget: &mut Budget,
    limit: usize,
) -> Walk {
    let mut literal_tail = false;
    for (idx, c) in comps.iter().enumerate().skip(start) {
        match c {
            Component::Normal(name) => {
                let text = name.to_string_lossy();
                if text == "**" {
                    let last = idx + 1 == comps.len();
                    let mut next = Vec::new();
                    for b in &bases {
                        if descend(b, last, budget, limit, &mut next).is_none() {
                            return Walk::Stopped {
                                at: idx,
                                seen: next,
                            };
                        }
                    }
                    next.sort();
                    bases = next;
                    literal_tail = false;
                    continue;
                }
                let pat: Vec<char> = text.chars().collect();
                if !pat.iter().any(|c| matches!(c, '*' | '?' | '[')) {
                    bases.iter_mut().for_each(|b| b.push(name));
                    literal_tail = true;
                    continue;
                }
                literal_tail = false;
                let mut next = Vec::new();
                for b in &bases {
                    if !budget.take(limit) {
                        return Walk::Stopped {
                            at: idx,
                            seen: next,
                        };
                    }
                    let Ok(entries) = std::fs::read_dir(b) else {
                        continue;
                    };
                    for e in entries.flatten() {
                        if !budget.take(limit) {
                            return Walk::Stopped {
                                at: idx,
                                seen: next,
                            };
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
            }
            Component::ParentDir => bases.iter_mut().for_each(|b| b.push("..")),
            _ => {}
        }
        if bases.is_empty() {
            break;
        }
    }
    if literal_tail {
        bases.retain(|b| std::fs::symlink_metadata(b).is_ok());
    }
    Walk::Done(bases)
}

/// `**`: `base` and every non-hidden directory below it (and, as the last
/// component, every non-hidden file too), without following symlinks.
/// `None` when the budget runs out.
fn descend(
    base: &Path,
    files_too: bool,
    budget: &mut Budget,
    limit: usize,
    out: &mut Vec<PathBuf>,
) -> Option<()> {
    if !base.is_dir() {
        return Some(());
    }
    out.push(base.to_path_buf());
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if !budget.take(limit) {
            return None;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            if !budget.take(limit) {
                return None;
            }
            let n = e.file_name();
            if n.to_string_lossy().starts_with('.') {
                continue;
            }
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            let p = dir.join(&n);
            if is_dir {
                stack.push(p.clone());
                out.push(p);
            } else if files_too {
                out.push(p);
            }
        }
    }
    Some(())
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

    #[test]
    fn braces_expand_like_bash() {
        let b = |w: &str| expand_braces(w).unwrap();
        assert_eq!(b("a{b,c}d"), vec!["abd", "acd"]);
        assert_eq!(b("{.env,.env.example}"), vec![".env", ".env.example"]);
        assert_eq!(b(".{env,x}"), vec![".env", ".x"]);
        assert_eq!(b("x{,.bak}"), vec!["x", "x.bak"]);
        assert_eq!(b("{a,b{c,d}}e"), vec!["ae", "bce", "bde"]);
        assert_eq!(b("{a,b}{1,2}"), vec!["a1", "a2", "b1", "b2"]);
        // Not brace expansions: kept as written.
        for w in ["{a}", "${HOME}/x", "a{b", "a}b", "{}", "plain"] {
            assert_eq!(b(w), vec![w.to_string()], "{w}");
        }
        assert_eq!(b("${HOME}/{a,b}"), vec!["${HOME}/a", "${HOME}/b"]);
        // Too many results: refused, not truncated, and quickly.
        assert!(expand_braces(&"{a,b}".repeat(12)).is_none());
        let t = std::time::Instant::now();
        assert!(expand_braces(&"{a,b}".repeat(40)).is_none());
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
        // Too many bytes.
        let long = format!("{{{},b}}{}", "x".repeat(40_000), "{c,d}");
        assert!(expand_braces(&long).is_none());
        // Too many braces in one word.
        assert!(expand_braces(&"{a}".repeat(1000)).is_none());
    }

    #[test]
    fn globs_support_double_star_and_braces() {
        let (_d, root) = tmp();
        let app = root.join("app");
        for d in ["sub/deep", ".git", "node"] {
            fs::create_dir_all(app.join(d)).unwrap();
        }
        for f in [
            ".env",
            "sub/deep/.env.local",
            ".git/.env",
            "x.toml",
            "y.env",
            "node/z.rs",
        ] {
            fs::write(app.join(f), "").unwrap();
        }
        let v = PathVars::new().with_cwd(&app);
        let m = |p: &str| match expand_glob(p, None, &v) {
            GlobExpansion::Matches(m) => m,
            other => panic!("{p}: {other:?}"),
        };
        // `**` is any number of directories, hidden ones excluded (bash
        // globstar, ripgrep's default).
        assert_eq!(
            m("**/.env*"),
            vec![app.join(".env"), app.join("sub/deep/.env.local")]
        );
        assert_eq!(m("**/z.rs"), vec![app.join("node/z.rs")]);
        assert_eq!(m("sub/**"), vec![app.join("sub"), app.join("sub/deep")]);
        assert_eq!(
            m("*.{env,toml}"),
            vec![app.join("x.toml"), app.join("y.env")]
        );
        // Each brace alternative's spelling is judged too, existing or not.
        assert_eq!(m(".{env,nope}"), vec![app.join(".env"), app.join(".nope")]);
        assert_eq!(
            m("{sub,node}/**/*.rs"),
            vec![app.join("node/z.rs"), app.join("sub/**/*.rs")]
        );
    }

    #[test]
    fn double_star_is_bounded() {
        let (_d, root) = tmp();
        for i in 0..(GLOB_SCAN_LIMIT + 10) {
            fs::create_dir_all(root.join(format!("d{}/e{i}", i % 3))).unwrap();
        }
        let v = PathVars::new().with_cwd(&root);
        assert_eq!(expand_glob("**/.env", None, &v), GlobExpansion::Overflow);
    }

    #[test]
    fn partial_expansion_keeps_what_it_found_before_the_limit() {
        let (_d, root) = tmp();
        for i in 0..GLOB_SCAN_LIMIT + 50 {
            fs::write(root.join(format!("f{i}.txt")), "").unwrap();
        }
        let v = PathVars::new();
        let word = format!("{}/*.txt", root.display());
        let (found, over) = expand_glob_partial(&word, None, &v);
        assert!(over);
        assert!(found.len() >= GLOB_SCAN_LIMIT - 10, "{}", found.len());
        assert_eq!(expand_glob(&word, None, &v), GlobExpansion::Overflow);
        assert_eq!(expand_glob_partial("plain", None, &v), (vec![], false));
    }

    #[test]
    fn variables_keep_the_spelled_form_of_a_symlink() {
        let (_d, root) = tmp();
        fs::create_dir_all(root.join("real")).unwrap();
        fs::write(root.join("real/saiife"), "").unwrap();
        std::os::unix::fs::symlink(root.join("real/saiife"), root.join("link")).unwrap();
        let v = PathVars::new().with_var("SAIIFE_BIN", root.join("link"));
        let vals = v.values("SAIIFE_BIN");
        assert!(vals.contains(&root.join("real/saiife").as_path()));
        assert!(vals.contains(&root.join("link").as_path()));
    }

    #[test]
    fn brace_sequences_expand_like_bash() {
        let b = |w: &str| expand_braces(w).unwrap();
        assert_eq!(b("{1..3}"), vec!["1", "2", "3"]);
        assert_eq!(b("{3..1}"), vec!["3", "2", "1"]);
        assert_eq!(b("{-1..1}"), vec!["-1", "0", "1"]);
        assert_eq!(b("{0..10..5}"), vec!["0", "5", "10"]);
        assert_eq!(b("{01..03}"), vec!["01", "02", "03"]);
        assert_eq!(b("{a..c}"), vec!["a", "b", "c"]);
        assert_eq!(b("{a..e..2}"), vec!["a", "c", "e"]);
        assert_eq!(b(".en{u..w}"), vec![".enu", ".env", ".enw"]);
        assert_eq!(b("x{a,{1..2}}"), vec!["xa", "x1", "x2"]);
        // Not sequences: literal.
        for w in ["{a..}", "{..b}", "{a..bc}", "{1..x}", "{1...3}"] {
            assert_eq!(b(w), vec![w.to_string()], "{w}");
        }
        // Too long: refused.
        assert!(expand_braces("{1..100000}").is_none());
    }

    #[test]
    fn brace_search_is_linear() {
        // Deeply nested brace groups without commas plus a few real ones:
        // every produced word is searched again.
        let word = format!(
            "{}x{}{}",
            "{".repeat(240),
            "}".repeat(240),
            "{a,b}".repeat(7)
        );
        let t = std::time::Instant::now();
        let out = expand_braces(&word).unwrap();
        assert_eq!(out.len(), 128);
        assert!(
            t.elapsed() < std::time::Duration::from_millis(100),
            "{:?}",
            t.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_pathological_glob_shares_one_budget() {
        // A directory over the scan limit that contains itself: every
        // `*` component overflows again.
        let (_d, root) = tmp();
        let w = root.join("w");
        fs::create_dir_all(&w).unwrap();
        for i in 0..GLOB_SCAN_LIMIT {
            fs::write(w.join(format!("f{i}")), "").unwrap();
        }
        std::os::unix::fs::symlink(&w, w.join("l")).unwrap();
        let v = PathVars::new().with_cwd(&w);
        let word = format!("{}x", "*/".repeat(200));
        let t = std::time::Instant::now();
        let (found, over) = expand_glob_partial(&word, None, &v);
        let took = t.elapsed();
        assert!(over);
        assert!(took < std::time::Duration::from_secs(1), "{took:?}");
        let _ = found;
        // Partial matches are still reported for a simple overflow.
        let (found, over) = expand_glob_partial("*", None, &v);
        assert!(over && found.len() >= GLOB_SCAN_LIMIT - 10);
        // Too many components or too long: overflow without scanning.
        let t = std::time::Instant::now();
        assert!(expand_glob_partial(&"*/".repeat(5000), None, &v).1);
        assert!(t.elapsed() < std::time::Duration::from_millis(100));
    }

    #[test]
    fn every_brace_alternative_is_judged_after_an_overflow() {
        let (_d, root) = tmp();
        for i in 0..GLOB_SCAN_LIMIT + 10 {
            fs::write(root.join(format!("f{i}.txt")), "").unwrap();
        }
        fs::write(root.join(".env"), "K=v").unwrap();
        let v = PathVars::new().with_cwd(&root);
        for word in ["{*.txt,.env}", "{.env,*.txt}"] {
            let (found, over) = expand_glob_partial(word, None, &v);
            assert!(over, "{word}");
            assert!(found.contains(&root.join(".env")), "{word}");
        }
        // The literal of an alternative that overflowed is judged too.
        let (found, _) = expand_glob_partial("{*.txt,.env}", None, &v);
        assert!(found.contains(&root.join("*.txt")));
    }

    #[test]
    fn operand_globs_keep_quoted_braces_literal() {
        let (_d, root) = tmp();
        fs::write(root.join("{a,b}x"), "").unwrap();
        fs::write(root.join("ax"), "").unwrap();
        let v = PathVars::new().with_cwd(&root);
        assert_eq!(
            expand_operand_glob("{a,b}*", None, &v),
            GlobExpansion::Matches(vec![root.join("{a,b}x")])
        );
        assert_eq!(
            expand_operand_glob("{a,b}x", None, &v),
            GlobExpansion::NotAGlob
        );
    }
}
