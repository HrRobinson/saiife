//! Where a `cd` earlier in a command line leaves the shell, for the regex
//! rules of `core.filesystem`: `cd / && rm -rf *` is judged as
//! `rm -rf /*`.
//!
//! Purely lexical (no filesystem access, so it stays inside the latency
//! budget): `..` pops a component, a symlink is not followed. A target that
//! cannot be resolved this way (`cd -`, `cd "$(…)"`, `cd $DIR`, `~user`,
//! `popd`) makes the directory unknown, and an unknown directory rewrites
//! nothing: the command is judged as written, as before.
//!
//! The path-rule phases keep their own record (`ShellState::cwds`), which
//! resolves symlinks and keeps every directory the shell may be in.

use std::path::{Component, Path};

use crate::lexer::Word;

/// A directory spelled lexically: from `/`, or from the home directory
/// (`~`), so the rules' `~` / `$HOME` targets match it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Dir {
    home: bool,
    parts: Vec<String>,
}

impl Dir {
    fn root() -> Dir {
        Dir {
            home: false,
            parts: Vec::new(),
        }
    }

    fn home() -> Dir {
        Dir {
            home: true,
            parts: Vec::new(),
        }
    }

    /// `C:/x`: the drive, lower case, is its first part. `..` stops there.
    fn from_windows(path: &str) -> Option<Dir> {
        let bytes = path.as_bytes();
        let rooted = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\');
        if !rooted {
            return None;
        }
        let drive = format!("{}:", path[..1].to_ascii_lowercase());
        let mut dir = Dir {
            home: false,
            parts: vec![drive],
        };
        for part in path[3..].split(['/', '\\']) {
            match part {
                "" | "." => {}
                ".." => {
                    if dir.parts.len() > 1 {
                        dir.parts.pop();
                    }
                }
                p => dir.parts.push(p.to_string()),
            }
        }
        Some(dir)
    }

    fn from_path(path: &Path, windows: bool) -> Option<Dir> {
        if windows {
            if let Some(d) = path.to_str().and_then(Dir::from_windows) {
                return Some(d);
            }
        }
        if !path.is_absolute() {
            return None;
        }
        let mut dir = Dir::root();
        for c in path.components() {
            match c {
                Component::Normal(s) => dir.parts.push(s.to_str()?.to_string()),
                Component::ParentDir => {
                    dir.parts.pop();
                }
                _ => {}
            }
        }
        Some(dir)
    }

    /// `rel` (a relative path) joined onto this directory. `None` when a
    /// `..` climbs above a home directory whose location is unknown. `windows`:
    /// the first part may be a drive.
    fn join(&self, rel: &str, home: Option<&Path>, windows: bool) -> Option<Dir> {
        let mut dir = self.clone();
        for part in rel.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    // A drive is the top: `c:/..` is `c:/`.
                    if windows && dir.parts.len() == 1 && dir.parts[0].ends_with(':') {
                        continue;
                    }
                    if dir.parts.pop().is_none() && dir.home {
                        dir = Dir::from_path(home?, windows)?;
                        dir.parts.pop();
                    }
                }
                p => dir.parts.push(p.to_string()),
            }
        }
        Some(dir)
    }

    /// The directory as the rules spell it: `/`, `/usr/*`, `~`, `~/x`. A
    /// path inside the home directory is spelled from `~`.
    fn render(&self, home: Option<&Path>, windows: bool) -> String {
        let mut dir = self.clone();
        if !dir.home {
            if let Some(h) = home.and_then(|h| Dir::from_path(h, windows)) {
                if !h.parts.is_empty() && dir.parts.starts_with(&h.parts) {
                    dir.parts.drain(..h.parts.len());
                    dir.home = true;
                }
            }
        }
        match (dir.home, dir.parts.is_empty()) {
            (true, true) => "~".to_string(),
            (true, false) => format!("~/{}", dir.parts.join("/")),
            (false, _) if windows && dir.parts.first().is_some_and(|p| p.ends_with(':')) => {
                if dir.parts.len() == 1 {
                    format!("{}/", dir.parts[0])
                } else {
                    dir.parts.join("/")
                }
            }
            (false, _) => format!("/{}", dir.parts.join("/")),
        }
    }
}

/// Distinct directories, and `cd` segments, followed in one command line at
/// most. Past either the set is incomplete for the rest of the line (sticky)
/// and stops changing, so the work per line stays small and linear.
const MAX_DIRS: usize = 16;
const MAX_CDS: usize = 64;

/// Every directory a command line's `cd`s may have left the shell in, for
/// the regex rules over the rest of it (`ShellState`). Each `cd`/`pushd`
/// target only adds to the set: whether a `cd` worked, ran at all, or ran in
/// a subshell is not modelled, so a target is judged against every directory
/// named before it (over-denying `cd /; cd proj && rm -rf *`).
#[derive(Clone, Debug)]
pub(crate) struct RuleCwd {
    /// The known directories the shell may be in.
    dirs: Vec<Dir>,
    /// The shell may also be somewhere unknown (judged as written).
    unknown: bool,
    /// A `cd` ran earlier on the line: only then are operands rewritten
    /// (a line without one is judged exactly as before).
    moved: bool,
    /// `cd` segments seen.
    cds: usize,
    /// Past `MAX_DIRS` / `MAX_CDS`: a relative destructive target can no
    /// longer be judged against every possible directory.
    overflowed: bool,
    /// Paths are spelled the Windows way (`C:\x`, `\\h\s`, `%USERPROFILE%`).
    windows: bool,
}

/// Leading words that make a segment a condition or time it (`if cd /;
/// then …`, `while cd x; do …`, `! cd /`, `time -p cd /`): the command
/// after them still runs in this shell.
const CONDITION_WORDS: &[&str] = &["if", "elif", "while", "until", "!", "time"];

/// How many leading words of `argv` are `CONDITION_WORDS` (unquoted), with
/// the `-p` of `time -p`.
fn condition_prefix_len(argv: &[String], words: &[Word]) -> usize {
    let mut n = 0;
    while let Some(a) = argv.get(n) {
        let quoted = words.get(n).is_some_and(|w| w.quoted);
        let after_time = n > 0 && argv[n - 1] == "time";
        if quoted || !(CONDITION_WORDS.contains(&a.as_str()) || (after_time && a == "-p")) {
            break;
        }
        n += 1;
    }
    n
}

impl RuleCwd {
    /// The directory the command line starts in (the agent's), if known.
    #[cfg(test)]
    pub(crate) fn start(cwd: Option<&Path>) -> RuleCwd {
        RuleCwd::start_styled(cwd, false)
    }

    /// `start`, with paths read the Windows way when `windows`: only then is
    /// `C:/x` a drive, and a colon anything but a character in a name.
    pub(crate) fn start_styled(cwd: Option<&Path>, windows: bool) -> RuleCwd {
        let dirs: Vec<Dir> = cwd
            .and_then(|c| Dir::from_path(c, windows))
            .into_iter()
            .collect();
        RuleCwd {
            unknown: dirs.is_empty(),
            dirs,
            moved: false,
            cds: 0,
            overflowed: false,
            windows,
        }
    }

    /// A segment ran: the target of a `cd`/`pushd` (`argv` normalized,
    /// `words` the resolved words in the same positions) is added to the
    /// set from each directory in it; `popd` adds an unknown one. Any other
    /// command is ignored.
    pub(crate) fn command(&mut self, argv: &[String], words: &[Word], home: Option<&Path>) {
        let lead = condition_prefix_len(argv, words);
        let (argv, words) = (&argv[lead..], words.get(lead..).unwrap_or(&[]));
        let pushd = match argv.first().map(String::as_str) {
            Some("cd") => false,
            // `pushd -n DIR` only edits the directory stack.
            Some("pushd") if !argv.iter().skip(1).any(|a| a == "-n") => true,
            Some("popd") => {
                self.moved = true;
                self.unknown = true;
                return;
            }
            _ => return,
        };
        self.moved = true;
        self.cds += 1;
        if self.cds > MAX_CDS {
            self.overflowed = true;
        }
        if self.overflowed {
            return;
        }
        let froms: Vec<Option<Dir>> = self
            .dirs
            .iter()
            .cloned()
            .map(Some)
            .chain(self.unknown.then_some(None))
            .collect();
        for from in froms {
            match target(from.as_ref(), argv, words, pushd, home, self.windows) {
                Some(d) => self.add(d),
                None => self.unknown = true,
            }
        }
    }

    /// Add `d` to the set; past `MAX_DIRS` the set is incomplete.
    fn add(&mut self, d: Dir) {
        if self.overflowed || self.dirs.contains(&d) {
            return;
        }
        if self.dirs.len() < MAX_DIRS {
            self.dirs.push(d);
        } else {
            self.overflowed = true;
        }
    }

    /// Too many possible directories were seen to judge `argv`: it is a
    /// destructive command (`rm`, `chmod`, `chown`) with a relative path
    /// operand, and the set overflowed earlier on the line.
    pub(crate) fn too_many_dirs_for(&self, argv: &[String]) -> bool {
        self.overflowed && rewrite_in(&Dir::root(), argv, None, self.windows).is_some()
    }

    /// `argv` with the path operands of a filesystem-destructive command
    /// (`rm`, `chmod`, `chown`) joined onto each known directory an earlier
    /// `cd` may have left the shell in, one argv per directory that
    /// changes something. Empty when no `cd` ran or no operand is relative. In
    /// Windows style the starting directory counts without a `cd`: `rd /s /q ..`
    /// from `C:\p` is the drive root. POSIX style stays as written.
    pub(crate) fn rewrite(&self, argv: &[String], home: Option<&Path>) -> Vec<Vec<String>> {
        if !self.moved && !self.windows {
            return Vec::new();
        }
        let mut out: Vec<Vec<String>> = Vec::new();
        for dir in &self.dirs {
            if let Some(v) = rewrite_in(dir, argv, home, self.windows) {
                if !out.contains(&v) {
                    out.push(v);
                }
            }
        }
        out
    }
}

/// Where `cd`/`pushd` `argv` leaves a shell that is in `from` (`None`:
/// unknown). `None` when that cannot be worked out.
fn target(
    from: Option<&Dir>,
    argv: &[String],
    words: &[Word],
    pushd: bool,
    home: Option<&Path>,
    windows: bool,
) -> Option<Dir> {
    let mut operand = None;
    let mut options_done = false;
    for (i, a) in argv.iter().enumerate().skip(1) {
        if !options_done && a == "--" {
            options_done = true;
            continue;
        }
        if !options_done && a.starts_with(['-', '+']) && a != "-" {
            // `pushd +N` / `-N` rotates the stack: unknown.
            if pushd && a[1..].bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            continue;
        }
        operand = Some((a, words.get(i)));
        break;
    }
    let Some((a, word)) = operand else {
        // `cd` alone goes home; `pushd` alone swaps the top two.
        return (!pushd).then(Dir::home);
    };
    if word.is_some_and(|w| w.has_substitution) || a == "-" {
        return None;
    }
    if windows {
        return windows_target(from, a, home);
    }
    let (base, rest) = if let Some(rest) = home_prefixed(a) {
        (Dir::home(), rest)
    } else if a.contains('$') || a.starts_with('~') {
        return None;
    } else if let Some(rest) = a.strip_prefix('/') {
        (Dir::root(), rest)
    } else {
        (from?.clone(), a.as_str())
    };
    base.join(rest, home, false)
}

/// Where `cd a` leaves a shell in `from`, with `a` spelled the Windows way.
/// `/x` and `\x` are on `from`'s drive. `C:x` is relative to that drive's
/// directory and `\\h\s` is a share: neither is known here, and an unknown
/// directory is judged as written. `/c/x` is Git Bash's `c:/x`.
fn windows_target(from: Option<&Dir>, a: &str, home: Option<&Path>) -> Option<Dir> {
    if let Some(d) = git_bash_drive(a) {
        return Some(d);
    }
    let a = a.replace('\\', "/");
    if let Some(d) = Dir::from_windows(&a) {
        return Some(d);
    }
    let lower = a.to_ascii_lowercase();
    if let Some(rest) = lower
        .strip_prefix("%userprofile%")
        .filter(|r| r.is_empty() || r.starts_with('/'))
    {
        let rest = a[a.len() - rest.len()..].trim_start_matches('/');
        return Dir::home().join(rest, home, true);
    }
    if let Some(rest) = home_prefixed(&a) {
        return Dir::home().join(rest, home, true);
    }
    if a.contains(['$', '%', '!', ':']) || a.starts_with(['~']) || a.starts_with("//") {
        return None;
    }
    if let Some(rest) = a.strip_prefix('/') {
        return drive_of(from?, home)?.join(rest, home, true);
    }
    from?.join(&a, home, true)
}

/// The root of the drive `dir` is on.
fn drive_of(dir: &Dir, home: Option<&Path>) -> Option<Dir> {
    let full = if dir.home {
        Dir::from_path(home?, true)?
    } else {
        dir.clone()
    };
    let drive = full.parts.first().filter(|p| p.ends_with(':'))?;
    Some(Dir {
        home: false,
        parts: vec![drive.clone()],
    })
}

/// `/c`, `/c/x`: Git Bash's drive `c:`.
fn git_bash_drive(a: &str) -> Option<Dir> {
    let rest = a.strip_prefix('/')?;
    let rest = rest.replace('\\', "/");
    let (drive, tail) = rest.split_once('/').unwrap_or((&rest, ""));
    let letter = drive.chars().next().filter(|c| c.is_ascii_alphabetic())?;
    (drive.len() == 1).then(|| Dir::from_windows(&format!("{letter}:/{tail}")))?
}

/// `argv` with its relative path operands joined onto `dir`; `None` when
/// the command is not one `core.filesystem` judges by target or nothing
/// changes.
fn rewrite_in(
    dir: &Dir,
    argv: &[String],
    home: Option<&Path>,
    windows: bool,
) -> Option<Vec<String>> {
    // The mode / owner operand of chmod / chown is not a path.
    let mut not_paths = match argv.first().map(String::as_str) {
        Some("rm") => 0,
        Some("chmod" | "chown") => 1,
        _ => return None,
    };
    let mut out = argv.to_vec();
    let mut changed = false;
    let mut options_done = false;
    for a in out.iter_mut().skip(1) {
        if !options_done && a == "--" {
            options_done = true;
            continue;
        }
        if !options_done && a.starts_with('-') {
            continue;
        }
        if not_paths > 0 {
            not_paths -= 1;
            continue;
        }
        if a.is_empty() || a.starts_with(['/', '~', '$']) {
            continue;
        }
        // Rooted, on a share, or a variable: not relative to `dir`.
        if windows && (a.starts_with(['\\', '%', '!']) || a.contains(':')) {
            continue;
        }
        let spelled = if windows {
            a.replace('\\', "/")
        } else {
            a.clone()
        };
        if let Some(joined) = dir.join(&spelled, home, windows) {
            *a = joined.render(home, windows);
            changed = true;
        }
    }
    changed.then_some(out)
}

/// The rest of a path spelled from the home directory (`~`, `~/x`,
/// `$HOME/x`, `${HOME}`), without its leading `/`.
fn home_prefixed(a: &str) -> Option<&str> {
    ["~", "$HOME", "${HOME}"].iter().find_map(|p| {
        let rest = a.strip_prefix(p)?;
        if rest.is_empty() {
            Some(rest)
        } else {
            rest.strip_prefix('/')
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_string).collect()
    }

    /// The rewritten lines after `cds`, joined with ` | `; `None` when
    /// nothing is rewritten.
    fn after(cds: &[&str], start: Option<&str>, home: Option<&str>, cmd: &str) -> Option<String> {
        let home = home.map(Path::new);
        let mut cwd = RuleCwd::start(start.map(Path::new));
        for cd in cds {
            let a = argv(cd);
            let words: Vec<Word> = a.iter().map(|_| Word::default()).collect();
            cwd.command(&a, &words, home);
        }
        let lines: Vec<String> = cwd
            .rewrite(&argv(cmd), home)
            .iter()
            .map(|v| v.join(" "))
            .collect();
        (!lines.is_empty()).then(|| lines.join(" | "))
    }

    #[test]
    fn joins_relative_operands_onto_the_cd_target() {
        let r = |cds: &[&str], cmd| after(cds, None, None, cmd);
        assert_eq!(r(&["cd /"], "rm -rf *").as_deref(), Some("rm -rf /*"));
        assert_eq!(r(&["cd ~"], "rm -rf .").as_deref(), Some("rm -rf ~"));
        assert_eq!(
            r(&["cd $HOME"], "rm -rf .*").as_deref(),
            Some("rm -rf ~/.*")
        );
        assert_eq!(
            r(&["cd ${HOME}/x"], "rm -rf ..").as_deref(),
            Some("rm -rf ~")
        );
        assert_eq!(
            r(&["cd /usr/../.."], "rm -rf *").as_deref(),
            Some("rm -rf /*")
        );
        assert_eq!(r(&["cd"], "rm -rf *").as_deref(), Some("rm -rf ~/*"));
        assert_eq!(
            r(&["cd -P -- /"], "rm -rf -- ./a/").as_deref(),
            Some("rm -rf -- /a")
        );
        assert_eq!(
            r(&["cd /"], "chown -R root:root .").as_deref(),
            Some("chown -R root:root /")
        );
        assert_eq!(
            r(&["cd /"], "chmod -R 777 *").as_deref(),
            Some("chmod -R 777 /*")
        );
        assert_eq!(r(&["if cd /"], "rm -rf *").as_deref(), Some("rm -rf /*"));
        assert_eq!(
            r(&["! time -p cd /"], "rm -rf *").as_deref(),
            Some("rm -rf /*")
        );
    }

    /// `x:` is a directory like any other in POSIX style.
    #[test]
    fn a_colon_is_no_drive_in_posix_style() {
        let r = |cds: &[&str], cmd| after(cds, None, None, cmd);
        assert_eq!(
            r(&["cd /x:"], "rm -rf ../etc").as_deref(),
            Some("rm -rf /etc")
        );
        assert_eq!(
            r(&["cd /x:", "cd .."], "rm -rf etc").as_deref(),
            Some("rm -rf /x:/etc | rm -rf /etc")
        );
        assert_eq!(r(&["cd /x:"], "rm -rf .").as_deref(), Some("rm -rf /x:"));
        // A cwd named like a drive is not one either.
        let relative = RuleCwd::start(Some(Path::new("c:/x")));
        assert!(relative.unknown && relative.dirs.is_empty());
    }

    #[test]
    fn every_target_adds_to_the_set() {
        let r = |cds: &[&str], cmd| after(cds, None, None, cmd);
        assert_eq!(
            r(&["cd /usr", "cd .."], "rm -rf *").as_deref(),
            Some("rm -rf /usr/* | rm -rf /*")
        );
        assert_eq!(
            r(&["cd /", "cd /tmp"], "rm -rf *").as_deref(),
            Some("rm -rf /* | rm -rf /tmp/*")
        );
        // Unknown targets keep the known directories.
        assert_eq!(
            r(&["cd /", "cd -"], "rm -rf *").as_deref(),
            Some("rm -rf /*")
        );
        assert_eq!(
            r(&["cd /", "popd"], "rm -rf *").as_deref(),
            Some("rm -rf /*")
        );
        // `pushd -n` is not a move.
        assert_eq!(
            r(&["cd /tmp", "pushd -n /"], "rm -rf *").as_deref(),
            Some("rm -rf /tmp/*")
        );
    }

    #[test]
    fn leaves_the_line_alone_when_nothing_is_known() {
        let r = |cds: &[&str], cmd| after(cds, None, None, cmd);
        assert_eq!(r(&[], "rm -rf *"), None);
        assert_eq!(r(&["cd -"], "rm -rf *"), None);
        assert_eq!(r(&["cd $TMP"], "rm -rf *"), None);
        assert_eq!(r(&["cd ~bob"], "rm -rf *"), None);
        assert_eq!(r(&["cd build"], "rm -rf *"), None);
        assert_eq!(r(&["pushd"], "rm -rf *"), None);
        assert_eq!(r(&["pushd +1"], "rm -rf *"), None);
        assert_eq!(r(&["popd"], "rm -rf *"), None);
        assert_eq!(r(&["cd /"], "rm -rf /x ~/y $D"), None);
        assert_eq!(r(&["cd /"], "ls *"), None);
    }

    #[test]
    fn a_known_start_resolves_relative_cds() {
        let home = Some("/home/u");
        let start = Some("/home/u/proj");
        let r = |cds: &[&str], cmd| after(cds, start, home, cmd);
        assert_eq!(r(&[], "rm -rf *"), None);
        assert_eq!(
            r(&["cd build"], "rm -rf *").as_deref(),
            Some("rm -rf ~/proj/* | rm -rf ~/proj/build/*")
        );
        assert_eq!(
            r(&["cd ../.."], "rm -rf *").as_deref(),
            Some("rm -rf ~/proj/* | rm -rf /home/*")
        );
        assert_eq!(
            after(&["cd /home/u"], None, home, "rm -rf .").as_deref(),
            Some("rm -rf ~")
        );
        assert_eq!(
            after(&["cd ~", "cd .."], None, home, "rm -rf *").as_deref(),
            Some("rm -rf ~/* | rm -rf /home/*")
        );
    }

    #[test]
    fn overflow_is_sticky_and_stops_tracking() {
        let cd = |a: &str| {
            let a = argv(a);
            let words: Vec<Word> = a.iter().map(|_| Word::default()).collect();
            (a, words)
        };
        let mut cwd = RuleCwd::start(None);
        for i in 0..MAX_DIRS {
            let (a, w) = cd(&format!("cd /d{i}"));
            cwd.command(&a, &w, None);
        }
        assert!(!cwd.too_many_dirs_for(&argv("rm -rf *")));
        let (a, w) = cd("cd /etc");
        cwd.command(&a, &w, None);
        assert!(cwd.too_many_dirs_for(&argv("rm -rf *")));
        assert!(cwd.too_many_dirs_for(&argv("rm -rf ./build")));
        assert!(!cwd.too_many_dirs_for(&argv("rm -rf /tmp/x")));
        assert!(!cwd.too_many_dirs_for(&argv("ls *")));
        // Nothing after the overflow is tracked, and it stays set.
        let (a, w) = cd("cd /");
        cwd.command(&a, &w, None);
        assert!(!cwd
            .rewrite(&argv("rm -rf *"), None)
            .iter()
            .any(|v| v[2] == "/*"));
        assert!(cwd.too_many_dirs_for(&argv("rm -rf *")));

        // Past MAX_CDS segments, even repeating one directory.
        let mut cwd = RuleCwd::start(None);
        let (a, w) = cd("cd /tmp");
        for _ in 0..MAX_CDS {
            cwd.command(&a, &w, None);
        }
        assert!(!cwd.too_many_dirs_for(&argv("rm -rf *")));
        cwd.command(&a, &w, None);
        assert!(cwd.too_many_dirs_for(&argv("rm -rf *")));
    }

    #[test]
    fn a_substitution_target_is_unknown() {
        let mut cwd = RuleCwd::start(None);
        let a = argv("cd $(mktemp)");
        let words = vec![
            Word::default(),
            Word {
                has_substitution: true,
                ..Word::default()
            },
        ];
        cwd.command(&a, &words, None);
        assert!(cwd.rewrite(&argv("rm -rf *"), None).is_empty());
    }
}
