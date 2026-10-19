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

use crate::lexer::{pipeline_prefix_len, Operator, Word};

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

    fn from_path(path: &Path) -> Option<Dir> {
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
    /// `..` climbs above a home directory whose location is unknown.
    fn join(&self, rel: &str, home: Option<&Path>) -> Option<Dir> {
        let mut dir = self.clone();
        for part in rel.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    if dir.parts.pop().is_none() && dir.home {
                        dir = Dir::from_path(home?)?;
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
    fn render(&self, home: Option<&Path>) -> String {
        let mut dir = self.clone();
        if !dir.home {
            if let Some(h) = home.and_then(Dir::from_path) {
                if !h.parts.is_empty() && dir.parts.starts_with(&h.parts) {
                    dir.parts.drain(..h.parts.len());
                    dir.home = true;
                }
            }
        }
        match (dir.home, dir.parts.is_empty()) {
            (true, true) => "~".to_string(),
            (true, false) => format!("~/{}", dir.parts.join("/")),
            (false, _) => format!("/{}", dir.parts.join("/")),
        }
    }
}

/// Directories the regex rules are judged against at most. Past it a new
/// directory is dropped (the set is marked incomplete: `unknown`) and the
/// ones already held are kept, except that `/` and `~` are always added.
const MAX_DIRS: usize = 16;

/// Where a command line's earlier `cd`s may have left the shell, for the
/// regex rules over the rest of it (`ShellState`). A `cd` that always runs
/// replaces the set; one that may be skipped (`a || cd x`, `a && cd x`, an
/// `if`/loop body) adds to it, so a target is judged against every
/// directory the shell may be in.
#[derive(Clone, Debug)]
pub(crate) struct RuleCwd {
    /// The known directories the shell may be in.
    dirs: Vec<Dir>,
    /// The shell may also be somewhere unknown (judged as written).
    unknown: bool,
    /// A `cd` ran earlier on the line: only then are operands rewritten
    /// (a line without one is judged exactly as before).
    moved: bool,
    /// A directory was dropped past `MAX_DIRS`: a relative destructive
    /// target can no longer be judged against every possible directory.
    overflowed: bool,
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
    pub(crate) fn start(cwd: Option<&Path>) -> RuleCwd {
        let dirs: Vec<Dir> = cwd.and_then(Dir::from_path).into_iter().collect();
        RuleCwd {
            unknown: dirs.is_empty(),
            dirs,
            moved: false,
            overflowed: false,
        }
    }

    /// A segment ran: a `cd`/`pushd`/`popd` (`argv` normalized, `words`
    /// the resolved words in the same positions) moves the set; any other
    /// command is ignored. `may_skip`: the segment may not run at all.
    pub(crate) fn command(
        &mut self,
        argv: &[String],
        words: &[Word],
        home: Option<&Path>,
        may_skip: bool,
    ) {
        let lead = condition_prefix_len(argv, words);
        let (argv, words) = (&argv[lead..], words.get(lead..).unwrap_or(&[]));
        let next = match argv.first().map(String::as_str) {
            Some("cd") => self.targets(argv, words, false, home),
            Some("pushd") => {
                // `pushd -n DIR` only edits the directory stack.
                if argv.iter().skip(1).any(|a| a == "-n") {
                    return;
                }
                self.targets(argv, words, true, home)
            }
            Some("popd") => RuleCwd {
                dirs: Vec::new(),
                unknown: true,
                moved: true,
                overflowed: false,
            },
            _ => return,
        };
        self.then(next, may_skip);
    }

    /// The state after something that ran in this shell and left it in
    /// `next` (a `cd`, an `eval`): replaces this one, or adds to it when
    /// it may have been skipped.
    pub(crate) fn then(&mut self, next: RuleCwd, may_skip: bool) {
        if may_skip {
            self.unknown |= next.unknown;
            self.moved |= next.moved;
            self.overflowed |= next.overflowed;
            for d in next.dirs {
                self.add(d);
            }
        } else {
            *self = next;
        }
    }

    /// Add `d` to the set. Past `MAX_DIRS` the directories already held
    /// are kept and `d` is dropped (the set is then incomplete), unless it
    /// is `/` or `~` itself.
    fn add(&mut self, d: Dir) {
        if self.dirs.contains(&d) {
            return;
        }
        if self.dirs.len() < MAX_DIRS || d.parts.is_empty() {
            self.dirs.push(d);
        } else {
            self.unknown = true;
            self.overflowed = true;
        }
    }

    /// Too many possible directories were seen to judge `argv`: it is a
    /// destructive command (`rm`, `chmod`, `chown`) with a relative path
    /// operand, and a directory it may run in was dropped past `MAX_DIRS`.
    pub(crate) fn too_many_dirs_for(&self, argv: &[String]) -> bool {
        self.overflowed && rewrite_in(&Dir::root(), argv, None).is_some()
    }

    /// Where `cd`/`pushd` `argv` leaves the shell, from each directory it
    /// may be in now.
    fn targets(
        &self,
        argv: &[String],
        words: &[Word],
        pushd: bool,
        home: Option<&Path>,
    ) -> RuleCwd {
        let mut next = RuleCwd {
            dirs: Vec::new(),
            unknown: false,
            moved: true,
            overflowed: false,
        };
        let froms: Vec<Option<&Dir>> = self
            .dirs
            .iter()
            .map(Some)
            .chain(self.unknown.then_some(None))
            .collect();
        for from in froms {
            match target(from, argv, words, pushd, home) {
                Some(d) => next.add(d),
                None => next.unknown = true,
            }
        }
        next
    }

    /// `argv` with the path operands of a filesystem-destructive command
    /// (`rm`, `chmod`, `chown`) joined onto each known directory an earlier
    /// `cd` may have left the shell in, one argv per directory that
    /// changes something. Empty when no `cd` ran or no operand is relative.
    pub(crate) fn rewrite(&self, argv: &[String], home: Option<&Path>) -> Vec<Vec<String>> {
        if !self.moved {
            return Vec::new();
        }
        let mut out: Vec<Vec<String>> = Vec::new();
        for dir in &self.dirs {
            if let Some(v) = rewrite_in(dir, argv, home) {
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
    let (base, rest) = if let Some(rest) = home_prefixed(a) {
        (Dir::home(), rest)
    } else if a.contains('$') || a.starts_with('~') {
        return None;
    } else if let Some(rest) = a.strip_prefix('/') {
        (Dir::root(), rest)
    } else {
        (from?.clone(), a.as_str())
    };
    base.join(rest, home)
}

/// `argv` with its relative path operands joined onto `dir`; `None` when
/// the command is not one `core.filesystem` judges by target or nothing
/// changes.
fn rewrite_in(dir: &Dir, argv: &[String], home: Option<&Path>) -> Option<Vec<String>> {
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
        if let Some(joined) = dir.join(a, home) {
            *a = joined.render(home);
            changed = true;
        }
    }
    changed.then_some(out)
}

/// How a command line's structure moves `RuleCwd` between its segments.
///
/// A `cd` replaces the set only when what follows depends on it having
/// worked: the next operator is `&&`, or it is the condition of the
/// `if`/`while`/`until` whose body follows. Every other `cd` may fail or
/// be skipped and only adds to the set. Within an and-or list a replaced
/// set holds until the list ends (`;`, newline, `&`, a group's close) or
/// reaches `||`; there every set the list passed through (its start and
/// each `&&`) is added back, since any command in it may have failed. After a block (`fi`, `done`,
/// `esac`) the set from before it is added back. Bodies of blocks,
/// function definitions and groups opened after `&&`/`||` may be skipped.
pub(crate) struct LineFlow {
    /// Open `(` / `{` groups.
    groups: Vec<Group>,
    /// The sets the current and-or list has passed through (at its start
    /// and at each `&&`): where the shell is when a command in it fails.
    list_pre: RuleCwd,
    /// The set before each open block.
    blocks: Vec<RuleCwd>,
    /// A block head just started: (the set before it, it has a condition).
    opening: Option<(RuleCwd, bool)>,
    /// The next group is a function body (`f()`, `function f`).
    fn_pending: bool,
    /// The previous segment was an `if`/`while`/`until` condition: the
    /// `;` after it does not end its list.
    cond_head: bool,
}

struct Group {
    /// The set to restore at a subshell's `)`.
    saved: Option<RuleCwd>,
    /// The group may not run.
    skip: bool,
    /// The enclosing list's `list_pre`.
    outer_pre: RuleCwd,
}

/// A segment's first word after `!` / `time [-p]`, if unquoted: a block
/// keyword when it is one.
fn block_head(seg: &[Word]) -> Option<&str> {
    seg.get(pipeline_prefix_len(seg))
        .filter(|w| !w.quoted)
        .map(|w| w.text.as_str())
}

impl LineFlow {
    pub(crate) fn new(cwd: &RuleCwd) -> LineFlow {
        LineFlow {
            groups: Vec::new(),
            list_pre: cwd.clone(),
            blocks: Vec::new(),
            opening: None,
            fn_pending: false,
            cond_head: false,
        }
    }

    fn skipping(&self) -> bool {
        !self.blocks.is_empty() || self.groups.iter().any(|g| g.skip)
    }

    /// The operators in front of a segment move `cwd`; returns the last.
    pub(crate) fn operators(&mut self, ops: &[Operator], cwd: &mut RuleCwd) -> Option<Operator> {
        let mut last = None;
        let mut k = 0;
        while let Some(&op) = ops.get(k) {
            k += 1;
            match op {
                // `f()`: a function definition; its body follows.
                Operator::LParen if ops.get(k) == Some(&Operator::RParen) => {
                    self.fn_pending = true;
                    k += 1;
                    last = Some(Operator::RParen);
                    continue;
                }
                Operator::LParen | Operator::LBrace => {
                    let skip = self.fn_pending
                        || self.skipping()
                        || matches!(last, Some(Operator::AndAnd | Operator::OrOr));
                    self.fn_pending = false;
                    let outer_pre = std::mem::replace(&mut self.list_pre, cwd.clone());
                    self.groups.push(Group {
                        saved: (op == Operator::LParen).then(|| cwd.clone()),
                        skip,
                        outer_pre,
                    });
                }
                Operator::RParen | Operator::RBrace => {
                    cwd.then(self.list_pre.clone(), true);
                    if let Some(g) = self.groups.pop() {
                        self.list_pre = g.outer_pre;
                        if let Some(saved) = g.saved {
                            *cwd = saved;
                        }
                    }
                }
                Operator::OrOr => cwd.then(self.list_pre.clone(), true),
                Operator::Semi | Operator::Newline | Operator::Amp | Operator::CaseParen => {
                    if !std::mem::take(&mut self.cond_head) {
                        cwd.then(self.list_pre.clone(), true);
                    }
                    self.list_pre = cwd.clone();
                }
                // The command before `&&` may be the one that fails.
                Operator::AndAnd => self.list_pre.then(cwd.clone(), true),
                Operator::Pipe => {}
            }
            last = Some(op);
        }
        last
    }

    /// A segment is about to run, between `last` and `next`: closes the
    /// block it ends and says whether a `cd` in it only adds to the set.
    pub(crate) fn segment(
        &mut self,
        seg: &[Word],
        last: Option<Operator>,
        next: Option<Operator>,
        cwd: &mut RuleCwd,
    ) -> bool {
        let head = block_head(seg);
        if matches!(head, Some("fi" | "done" | "esac")) {
            if let Some(pre) = self.blocks.pop() {
                cwd.then(pre, true);
            }
        }
        let condition = matches!(head, Some("if" | "while" | "until"));
        if condition || matches!(head, Some("for" | "select" | "case")) {
            self.opening = Some((cwd.clone(), condition));
        }
        if head == Some("function") {
            self.fn_pending = true;
        }
        if condition {
            return self.skipping();
        }
        self.skipping()
            || next != Some(Operator::AndAnd)
            || matches!(
                last,
                Some(Operator::OrOr | Operator::CaseParen | Operator::RParen | Operator::RBrace)
            )
    }

    /// The segment ran: a block it heads is now open.
    pub(crate) fn after_segment(&mut self) {
        if let Some((pre, condition)) = self.opening.take() {
            self.blocks.push(pre);
            self.cond_head = condition;
        }
    }

    /// The line ended: what it leaves `cwd` as (for `eval`).
    pub(crate) fn finish(&self, cwd: &mut RuleCwd) {
        cwd.then(self.list_pre.clone(), true);
    }
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

    /// The rewritten lines after `cds` (a leading `?` marks one that may
    /// be skipped), joined with ` | `; `None` when nothing is rewritten.
    fn after(cds: &[&str], start: Option<&str>, home: Option<&str>, cmd: &str) -> Option<String> {
        let home = home.map(Path::new);
        let mut cwd = RuleCwd::start(start.map(Path::new));
        for cd in cds {
            let (cd, may_skip) = match cd.strip_prefix('?') {
                Some(rest) => (rest, true),
                None => (*cd, false),
            };
            let a = argv(cd);
            let words: Vec<Word> = a.iter().map(|_| Word::default()).collect();
            cwd.command(&a, &words, home, may_skip);
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
            r(&["cd /usr", "cd .."], "rm -rf *").as_deref(),
            Some("rm -rf /*")
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
    }

    #[test]
    fn leaves_the_line_alone_when_nothing_is_known() {
        let r = |cds: &[&str], cmd| after(cds, None, None, cmd);
        assert_eq!(r(&[], "rm -rf *"), None);
        assert_eq!(r(&["cd -"], "rm -rf *"), None);
        assert_eq!(r(&["cd $TMP"], "rm -rf *"), None);
        assert_eq!(r(&["cd ~bob"], "rm -rf *"), None);
        assert_eq!(r(&["cd build"], "rm -rf *"), None);
        assert_eq!(r(&["cd ~", "cd .."], "rm -rf *"), None);
        assert_eq!(r(&["cd /", "popd"], "rm -rf *"), None);
        assert_eq!(r(&["cd /", "cd -"], "rm -rf *"), None);
        // A skipped cd to somewhere unknown keeps the known directory.
        assert_eq!(
            r(&["cd /", "?cd -"], "rm -rf *").as_deref(),
            Some("rm -rf /*")
        );
        assert_eq!(r(&["pushd"], "rm -rf *"), None);
        assert_eq!(r(&["pushd +1"], "rm -rf *"), None);
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
            Some("rm -rf ~/proj/build/*")
        );
        assert_eq!(r(&["cd .."], "rm -rf *").as_deref(), Some("rm -rf ~/*"));
        assert_eq!(
            r(&["cd ../.."], "rm -rf *").as_deref(),
            Some("rm -rf /home/*")
        );
        assert_eq!(r(&["cd /home/u"], "rm -rf .").as_deref(), Some("rm -rf ~"));
        assert_eq!(
            after(&["cd ~", "cd .."], None, home, "rm -rf *").as_deref(),
            Some("rm -rf /home/*")
        );
    }

    #[test]
    fn skipped_and_condition_cds() {
        let r = |cds: &[&str], cmd| after(cds, None, None, cmd);
        assert_eq!(
            r(&["cd /usr", "?cd .."], "rm -rf *").as_deref(),
            Some("rm -rf /usr/* | rm -rf /*")
        );
        assert_eq!(r(&["if cd /"], "rm -rf *").as_deref(), Some("rm -rf /*"));
        assert_eq!(r(&["! cd /"], "rm -rf *").as_deref(), Some("rm -rf /*"));
        assert_eq!(
            r(&["! time -p cd /"], "rm -rf *").as_deref(),
            Some("rm -rf /*")
        );
        assert_eq!(
            r(&["cd /", "pushd -n /tmp"], "rm -rf *").as_deref(),
            Some("rm -rf /*")
        );
    }

    #[test]
    fn past_the_bound_held_directories_are_kept() {
        let r = |cds: &[&str], cmd| after(cds, None, None, cmd);
        let many: Vec<String> = (0..=MAX_DIRS).map(|i| format!("?cd /d{i}")).collect();
        let mut cds: Vec<&str> = vec!["cd /"];
        cds.extend(many.iter().map(String::as_str));
        let got = r(&cds, "rm -rf *").unwrap();
        assert!(got.starts_with("rm -rf /* | "), "{got}");
        // `/` plus MAX_DIRS - 1 others; the rest were dropped.
        assert_eq!(got.matches(" | ").count(), MAX_DIRS - 1, "{got}");
        // `/` and `~` are added even past the bound.
        let mut cds: Vec<&str> = many.iter().map(String::as_str).collect();
        cds.push("?cd ~");
        cds.push("?cd /");
        let got = r(&cds, "rm -rf *").unwrap();
        assert!(
            got.contains("rm -rf ~/*") && got.contains("rm -rf /*"),
            "{got}"
        );
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
        cwd.command(&a, &words, None, false);
        assert!(cwd.rewrite(&argv("rm -rf *"), None).is_empty());
    }
}
