//! The decision engine: tokenize -> segment -> per segment (build argv ->
//! guarded-substitution check -> pre-filter -> match allow before deny) ->
//! decide, with a structural inline `-c` re-entry and a hard latency cap
//! that fails open unless what is left of the line denies on a cheap look.
//!
//! Segmentation (see `crate::lexer`) closes the command-chaining bypass:
//! deny patterns are `^`-anchored, so `echo hi && rm -rf /` must be split
//! into `echo hi` and `rm -rf /` and each judged independently, or the deny
//! pattern for `rm` never gets a chance to match anything but the start of
//! the whole line. Unlike the naive character scan this used to be, the
//! lexer resolves quoting, escaping and adjacent-string concatenation
//! *before* deciding where the boundaries are, so a hidden operator
//! (`a&&rm -rf /`) is never missed and a quoted one (`echo "a && b"`) is
//! never manufactured.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use regex::{Regex, RegexSet};

use crate::canon::{
    canonicalize, expand_operand_glob_dots, fs_is_dir, fs_next_entry, fs_over, fs_read_dir,
    lexical_form, meter_fs, path_forms, GlobExpansion, PathStyle, PathVars, GLOB_SCAN_LIMIT,
};
use crate::cdtrack::RuleCwd;
use crate::cmdexe;
use crate::lexer::{
    find_all_substitution_kinds, literal_word, split_segments_noted, split_substitution_noted,
    Word, BRACES_PAST_LINE_LIMIT,
};
use crate::normalize::{build_argv, windows_program_names};
use crate::operands::{operands, Operand, Source};
use crate::pack::{Hit, Pack};
use crate::pathrule::{ancestors_source, glob_source, Access, RuleAccess};
use crate::payload::{inline_payload, watch_payload, Dialects};
use crate::prefilter::Prefilter;
use crate::pwsh;
use crate::subst::{command_position_substitution_kind, may_expand_to_nothing};
use crate::winpath;
use crate::wintable::{self, Dialect};
use crate::wrappers::{
    effective_command, env_split_payloads, is_env_assignment, peeled_wrappers,
    unknown_wrapper_options, unwrap_transparent_prefix, wrapper_reads,
};

/// Default latency budget for a single evaluation. Exceeding it yields
/// `Allow { .. timed_out: true }`, unless the cheap look at the rest of the
/// line denies (`Engine::out_of_budget`) — continuity wins over a stalled guard.
pub const DEFAULT_BUDGET: Duration = Duration::from_millis(50);

/// Bound on structural re-entry recursion depth: `bash -c '...'`-style
/// inline payloads, and a command substitution occupying command position
/// (`$(rm -rf /)`, including nested `$( $(rm -rf /) )`). Fail-open beyond
/// this: we stop looking deeper rather than risk unbounded recursion on
/// adversarial nesting.
const MAX_INLINE_DEPTH: u32 = 8;

/// The pack label used for the engine's own tokenizer-derived policy
/// (command substitution in a guarded argument position), as opposed to a
/// decision that came from a loaded pack's regex rule.
const SUBSTITUTION_GUARD_PACK: &str = "saiifeguard.core";

/// The pack whose rules also judge a destructive command's relative
/// operands joined onto the directory an earlier `cd` on the line moved to
/// (`cd / && rm -rf *` is matched as `rm -rf /*`); see `crate::cdtrack`.
/// Other packs see the command as written.
const CD_RESOLVED_PACK: &str = "core.filesystem";

/// What a deny for a Windows path that cannot be read names as its pack and
/// pattern: no rule of any pack decided it.
const UNREADABLE_PACK: &str = "guard.winpath";
const UNREADABLE_PATTERN: &str = "unreadable Windows path";

/// Why a value that decides what runs is not judged (`eval "$x"`, an
/// `-EncodedCommand` that does not decode).
pub(crate) const UNRESOLVED_REASON: &str = "eval of a command substitution cannot be judged";

/// The deny for what the PowerShell or cmd reader could not read.
const UNREADABLE_COMMAND_PATTERN: &str = "reader-could-not-judge";

/// The guarded-argument fail-safe's pattern (`command_rules_phase`).
const GUARDED_SUBSTITUTION_PATTERN: &str = "guarded-command-substitution-argument";

/// The engine's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The command is permitted. `trace` explains why (no pack matched, an
    /// allow rule carved it out, or the guard failed open).
    Allow { trace: AllowTrace },
    /// The command is blocked by a deny rule.
    Deny {
        pack: String,
        pattern: String,
        reason: String,
        /// Set when the match was found inside an inline `-c '…'` payload.
        via_inline: Option<String>,
    },
}

/// Why a command was allowed — surfaced by `explain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowTrace {
    /// No pack's deny rule matched.
    NoMatch,
    /// An allow rule short-circuited a would-be deny.
    AllowRule {
        pack: String,
        pattern: String,
        reason: String,
    },
    /// The guard failed open (budget exceeded); the command was not judged.
    FailedOpenTimeout,
    /// There was nothing the guard could judge (a path that cannot be
    /// resolved); allowed, and the caller records it as a fail-open.
    Unjudgeable { reason: String },
}

impl Decision {
    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }
}

/// The loaded engine: packs plus a combined pre-filter over all their triggers.
pub struct Engine {
    packs: Vec<Pack>,
    combined: Prefilter,
    budget: Duration,
    /// How long one evaluation may spend compiling operand patterns before any
    /// further pattern counts as a match: `pack::MAX_PATTERN_COMPILE`.
    pattern_allowance: Duration,
    /// Case-folded command names that at least one active pack has a deny
    /// rule for. Used only to scope the command-substitution-in-a-guarded-
    /// position policy — see `command_rules_phase`.
    guarded_commands: HashSet<String>,
    /// Directories paths are resolved against and rule variables bound to.
    vars: PathVars,
    /// Each pack's path rules, bound to `vars` on first use (compiling the
    /// globs is a large part of a hook call's fixed cost).
    path_rules: OnceLock<Vec<PackPaths>>,
    /// Some active pack has `deny_path` rules: `path_rules` is not empty.
    has_path_rules: bool,
}

/// One pack's path rules with their globs compiled for this machine.
struct PackPaths {
    pack: String,
    allow: Vec<BoundPathRule>,
    deny: Vec<BoundPathRule>,
    /// All of `allow` / `deny` in one automaton, so a path costs one scan
    /// per list instead of one per rule (`None`: too large, scan each).
    allow_set: Option<RegexSet>,
    deny_set: Option<RegexSet>,
}

/// `rules` with their automaton. Each regex is compiled on its own only if
/// the set does not compile; then a rule whose regex does not compile is
/// dropped.
fn rule_set(mut rules: Vec<BoundPathRule>) -> (Vec<BoundPathRule>, Option<RegexSet>) {
    match RegexSet::new(rules.iter().map(|r| r.source.as_str())) {
        Ok(set) => (rules, Some(set)),
        Err(_) => {
            rules.retain_mut(|r| {
                r.regex = Regex::new(&r.source).ok();
                r.regex.is_some()
            });
            (rules, None)
        }
    }
}

struct BoundPathRule {
    glob: String,
    /// The glob as a regex over canonical paths.
    source: String,
    /// `source` compiled; only when the list has no `RegexSet`.
    regex: Option<Regex>,
    access: RuleAccess,
    reason: String,
}

/// Path rules match case-insensitively where the usual filesystem is
/// case-insensitive (macOS: `.ENV` opens `.env`).
const PATHS_CASE_INSENSITIVE: bool = cfg!(target_os = "macos");

/// What `$null` is depends on the shell. To PowerShell it is the null device. To
/// cmd it is a file by that name, and no rule protects that. To bash it is a
/// variable, which `null=.env; cat $null` sets, so under a shell known to be POSIX
/// (Git Bash) it stays a variable. Where the shell is not known, `npm test > $null`
/// must not be denied for what its POSIX reading would mean, so an unquoted `$null`
/// after a redirection discards there, if nothing on the line can set it.
fn null_device_words(segments: &mut [Vec<Word>], dialect: Dialect, redirect_discards: bool) {
    let is_null = |w: &Word| w.text.eq_ignore_ascii_case("$null");
    let discard = |w: &mut Word| {
        w.text = "NUL".to_string();
        w.has_substitution = false;
        w.literal_dollars = false;
    };
    for seg in segments {
        if dialect != Dialect::Posix {
            seg.iter_mut().filter(|w| is_null(w)).for_each(discard);
        } else if redirect_discards {
            for at in 1..seg.len() {
                if seg[at - 1].redirect && is_null(&seg[at]) && !seg[at].quoted {
                    discard(&mut seg[at]);
                }
            }
        }
    }
}

/// What a Windows-style host means by a segment's words: its programs' names
/// (`normalize::windows_program_names`), and for a reader a leading `//`, which
/// is a share there. `build_argv` would collapse it to `/`.
fn windows_words(segments: &mut [Vec<Word>], reader: bool, dialect: Dialect) {
    for seg in segments {
        // `C:` at cmd's prompt moves there, as it does in PowerShell (`pwsh`):
        // to that drive's own current directory, which a new shell has at its root.
        // Read as the root: `cd C:` alone would only print where that is. First,
        // because a program name loses what follows a colon.
        if dialect == Dialect::Cmd && seg.first().is_some_and(is_bare_drive) {
            let mut place = seg[0].clone();
            place.text.push('\\');
            seg[0].text = "cd".to_string();
            seg.insert(1, place);
        }
        windows_program_names(seg);
        if reader {
            for w in seg.iter_mut().skip(1).filter(|w| !w.has_substitution) {
                if let Some(share) = wintable::unc_text(&w.text) {
                    w.text = share;
                }
            }
        }
    }
}

fn is_bare_drive(w: &Word) -> bool {
    let t = w.text.as_bytes();
    !w.quoted && !w.has_substitution && t.len() == 2 && t[0].is_ascii_alphabetic() && t[1] == b':'
}

/// The name `null` on the line in any form but `$null` and `/dev/null`, so a POSIX
/// shell may be given a value for it (`null=x`, `read null`, `${null:-x}`).
fn names_null(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';
    lower.match_indices("null").any(|(at, _)| {
        let before = &lower[..at];
        !before.ends_with(is_name)
            && !lower[at + 4..].starts_with(is_name)
            && !before.ends_with('$')
            && !before.ends_with("/dev/")
    })
}

impl Engine {
    /// Build an engine from loaded packs.
    pub fn new(packs: Vec<Pack>) -> Self {
        let triggers: Vec<String> = packs.iter().flat_map(|p| p.triggers.clone()).collect();
        let guarded_commands = packs
            .iter()
            .filter(|p| p.has_deny() && p.substitution_failsafe)
            .flat_map(|p| p.triggers.iter())
            .filter(|t| looks_like_bare_command_name(t))
            .map(|t| t.to_ascii_lowercase())
            .collect();
        Self {
            combined: Prefilter::new(triggers),
            has_path_rules: packs.iter().any(|p| !p.deny_path.is_empty()),
            packs,
            budget: DEFAULT_BUDGET,
            pattern_allowance: crate::pack::MAX_PATTERN_COMPILE,
            guarded_commands,
            vars: PathVars::default(),
            path_rules: OnceLock::new(),
        }
    }

    /// Resolve paths against these directories and supply the variables
    /// (`~`, `$SAIIFE_BIN`, …) the path rules use. The rules are bound to
    /// them on the first evaluation, not here; the gain is that each glob
    /// is compiled once per engine rather than on every call. Without
    /// this, only rules without variables apply and relative paths cannot
    /// be judged.
    pub fn with_paths(mut self, vars: PathVars) -> Self {
        // Both come from `PathStyle::host()` in production. A test that forces a
        // style must load the packs for it (`Catalog::builtin_for`), or it
        // judges without the rules it means to test.
        debug_assert!(
            self.packs.iter().all(|p| p.fits(vars.style())),
            "packs loaded for another host style than these paths"
        );
        self.vars = vars;
        self.path_rules = OnceLock::new();
        self
    }

    /// [`crate::pack::MAX_PATTERN_COMPILE`] in place of its default. That one is
    /// wall-clock time, so a test whose verdict must not depend on how loaded the
    /// machine is sets this, as it sets `with_budget`.
    pub fn with_pattern_allowance(mut self, allowance: Duration) -> Self {
        self.pattern_allowance = allowance;
        self
    }

    /// The path rules bound to `vars`. Called before an evaluation starts
    /// its latency clock, so binding never spends the budget.
    fn path_rules(&self) -> &[PackPaths] {
        self.path_rules.get_or_init(|| self.bind_paths())
    }

    fn bind_paths(&self) -> Vec<PackPaths> {
        let bind = |rules: &[crate::pathrule::PathRule]| -> Vec<BoundPathRule> {
            rules
                .iter()
                .filter_map(|r| {
                    // Globs were validated at load; a rule whose variable
                    // has no value on this machine cannot apply.
                    let source = if r.ancestors {
                        ancestors_source(&r.glob, &self.vars, PATHS_CASE_INSENSITIVE)
                    } else {
                        glob_source(&r.glob, &self.vars, PATHS_CASE_INSENSITIVE)
                    };
                    Some(BoundPathRule {
                        glob: r.glob.clone(),
                        source: source.ok().flatten()?,
                        regex: None,
                        access: r.access,
                        reason: r.reason.clone(),
                    })
                })
                .collect()
        };
        self.packs
            .iter()
            .filter(|p| !p.deny_path.is_empty())
            .map(|p| {
                let (allow, allow_set) = rule_set(bind(&p.allow_path));
                let (deny, deny_set) = rule_set(bind(&p.deny_path));
                PackPaths {
                    pack: p.id.clone(),
                    allow,
                    deny,
                    allow_set,
                    deny_set,
                }
            })
            .collect()
    }

    /// `path` as the path rules see it: absolute, symlinks and `..`
    /// resolved. `None` if it cannot be made absolute.
    pub fn resolve_path(&self, path: &str) -> Option<PathBuf> {
        canonicalize(path, None, &self.vars)
    }

    /// Judge a file tool's access to `path` against the active packs' path
    /// rules (spec §7.2). Same budget and fail-open rules as `evaluate`.
    pub fn evaluate_path(&self, access: Access, path: &str) -> Decision {
        self.path_rules();
        let start = Instant::now();
        let forms = path_forms(path, None, &self.vars);
        if forms.is_empty() {
            if let Some(d) = self.unreadable(path, None) {
                return d;
            }
            return Decision::Allow {
                trace: AllowTrace::Unjudgeable {
                    reason: format!("cannot resolve {path:?} to an absolute path"),
                },
            };
        }
        let mut carved = None;
        for form in &forms {
            match self.judge_path(access, form, start) {
                JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return d,
                JudgeOutcome::Decided(d) => carved = carved.or(Some(d)),
                JudgeOutcome::TimedOut => {
                    return Decision::Allow {
                        trace: AllowTrace::FailedOpenTimeout,
                    }
                }
                JudgeOutcome::Clean => {}
            }
        }
        carved.unwrap_or(Decision::Allow {
            trace: AllowTrace::NoMatch,
        })
    }

    /// Windows only: a deny when `raw` cannot be read at all (an unknown
    /// variable, a device namespace path, …). It could name a protected file,
    /// so it fails closed; a relative path with no working directory does not
    /// count, and is treated as in POSIX style. `None` also when no path rule
    /// is active: nothing is protected then.
    fn unreadable(&self, raw: &str, cwd: Option<&Path>) -> Option<Decision> {
        if self.vars.style() != PathStyle::Windows || !self.has_path_rules {
            return None;
        }
        match winpath::read(raw, cwd, &self.vars) {
            Err(winpath::Unread::Unreadable(why)) => Some(Self::unreadable_deny(raw, why)),
            _ => None,
        }
    }

    fn unreadable_deny(raw: &str, why: &str) -> Decision {
        Decision::Deny {
            pack: UNREADABLE_PACK.to_string(),
            pattern: UNREADABLE_PATTERN.to_string(),
            reason: format!("cannot read the Windows path {raw:?} ({why}), so it cannot be judged"),
            via_inline: None,
        }
    }

    /// `unreadable`, for a word of a shell command: the shell may be PowerShell,
    /// so a provider drive is judged by what is done to it.
    fn unreadable_operand(
        &self,
        raw: &str,
        cwd: Option<&Path>,
        access: Access,
    ) -> Option<Decision> {
        if self.vars.style() != PathStyle::Windows || !self.has_path_rules {
            return None;
        }
        match winpath::provider_access(raw, access == Access::Write) {
            Some(Ok(())) => None,
            Some(Err(why)) => Some(Self::unreadable_deny(raw, why)),
            None => self.unreadable(raw, cwd),
        }
    }

    /// Path rules for one resolved path: per pack, an `allow_path` match
    /// exempts the path from that pack's `deny_path` rules; the first deny
    /// in any pack wins.
    fn judge_path(&self, access: Access, real: &Path, start: Instant) -> JudgeOutcome {
        let text = real.to_string_lossy();
        let mut carved: Option<Decision> = None;
        for pp in self.path_rules() {
            if start.elapsed() > self.budget {
                return JudgeOutcome::TimedOut;
            }
            let hit = |rules: &[BoundPathRule], set: &Option<RegexSet>| match set {
                Some(set) => set
                    .matches(&text)
                    .into_iter()
                    .find(|&i| rules[i].access.covers(access)),
                None => rules.iter().position(|r| {
                    r.access.covers(access) && r.regex.as_ref().is_some_and(|re| re.is_match(&text))
                }),
            };
            if let Some(i) = hit(&pp.allow, &pp.allow_set) {
                let r = &pp.allow[i];
                carved.get_or_insert(Decision::Allow {
                    trace: AllowTrace::AllowRule {
                        pack: pp.pack.clone(),
                        pattern: r.glob.clone(),
                        reason: r.reason.clone(),
                    },
                });
                continue;
            }
            if let Some(i) = hit(&pp.deny, &pp.deny_set) {
                let r = &pp.deny[i];
                return JudgeOutcome::Decided(Decision::Deny {
                    pack: pp.pack.clone(),
                    pattern: r.glob.clone(),
                    reason: format!("{} ({}: {text})", r.reason, access.label()),
                    via_inline: None,
                });
            }
        }
        match carved {
            Some(d) => JudgeOutcome::Decided(d),
            None => JudgeOutcome::Clean,
        }
    }

    /// Override the latency budget (mainly for tests).
    pub fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// Number of loaded packs.
    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }

    /// The id of `pack`'s `[[deny]]` rule with `pattern` (what a
    /// [`Decision::Deny`] names), if it has one.
    pub fn rule_id(&self, pack: &str, pattern: &str) -> Option<&str> {
        self.packs
            .iter()
            .filter(|p| p.id == pack)
            .flat_map(|p| p.deny_rules())
            .find(|r| r.pattern == pattern)
            .and_then(|r| r.id.as_deref())
    }

    /// This engine (same paths and budget) without the `[[deny]]` rules
    /// `(pack, id)` names. A command it allows was denied only by them.
    pub fn without_deny_rules(&self, rules: &[(&str, &str)]) -> Engine {
        let packs = self
            .packs
            .iter()
            .map(|p| {
                let ids: Vec<&str> = rules
                    .iter()
                    .filter(|(pack, _)| *pack == p.id)
                    .map(|(_, id)| *id)
                    .collect();
                if ids.is_empty() {
                    p.clone()
                } else {
                    p.without_deny_ids(&ids)
                }
            })
            .collect();
        Engine::new(packs)
            .with_paths(self.vars.clone())
            .with_budget(self.budget)
            .with_pattern_allowance(self.pattern_allowance)
    }

    /// Evaluate a raw command line and return the decision.
    pub fn evaluate(&self, raw_cmd: &str) -> Decision {
        self.reading(raw_cmd, Dialect::Posix)
    }

    /// Evaluate `raw_cmd` as written in `dialects`. `Strictest`: every reading,
    /// and the stricter wins (`stricter`). A reading's outcome is what the
    /// engine found; `evaluate_call` is what a hook answers.
    pub fn evaluate_in(&self, raw_cmd: &str, dialects: Dialects) -> Decision {
        self.readings(raw_cmd, dialects, |_, d| d)
    }

    /// `evaluate_in` for a hook call: what the PowerShell or cmd reader could
    /// not read (a note, a value it cannot see) is a deny, in every mode, not a
    /// recorded allow. A misread command is a live bypass there, and `eval`'s
    /// POSIX outcome stays as it was. Running out of budget is no such thing: it
    /// stays `FailedOpenTimeout`, which the caller answers by its fail policy.
    pub fn evaluate_call(&self, raw_cmd: &str, dialects: Dialects) -> Decision {
        self.readings(raw_cmd, dialects, |dialect, d| {
            if dialect == Dialect::Posix {
                d
            } else {
                closed_reading(d)
            }
        })
    }

    fn readings(
        &self,
        raw_cmd: &str,
        dialects: Dialects,
        finish: impl Fn(Dialect, Decision) -> Decision,
    ) -> Decision {
        let (a, b) = match dialects {
            Dialects::One(d) => return finish(d, self.reading(raw_cmd, d)),
            Dialects::Strictest(a, b) => (a, b),
        };
        let first = finish(a, self.reading_as(raw_cmd, a, true));
        let second = finish(b, self.reading_as(raw_cmd, b, true));
        let both = if a == Dialect::PowerShell || b != Dialect::PowerShell {
            stricter(first, second)
        } else {
            stricter(second, first)
        };
        if a == Dialect::Cmd || b == Dialect::Cmd {
            return both;
        }
        with_cmd_reading(both, self.reading_as(raw_cmd, Dialect::Cmd, true))
    }

    /// One reading of a line whose shell is known.
    fn reading(&self, raw_cmd: &str, dialect: Dialect) -> Decision {
        self.reading_as(raw_cmd, dialect, false)
    }

    /// One reading, with a budget of its own. `undecided`: this is one of
    /// several readings, because the shell is not known.
    fn reading_as(&self, raw_cmd: &str, dialect: Dialect, undecided: bool) -> Decision {
        self.path_rules();
        let start = Instant::now();
        let state = ShellState {
            cwds: self.vars.cwd().map(Path::to_path_buf).into_iter().collect(),
            plain_cwds: usize::from(self.vars.cwd().is_some()),
            cwd_unknown: false,
            rule_cwd: RuleCwd::start_styled(
                self.vars.cwd(),
                self.vars.style() == PathStyle::Windows,
            ),
            env_changed: false,
            ifs_named: false,
            null_redirect_discards: undecided && !names_null(raw_cmd),
        };
        let clock = Clock {
            start,
            spent: Cell::default(),
            last_look: false,
            lines_left: Cell::new(0),
            paths_left: Rc::default(),
            #[cfg(test)]
            runs: Cell::default(),
        };
        let decision = self.evaluate_inner(raw_cmd, &clock, 0, &state, false, None, dialect);
        #[cfg(test)]
        LAST_RUNS.with(|last| last.set(clock.runs.get()));
        decision
    }

    /// `state`: the shell state at the start of `raw_cmd`; a nested
    /// evaluation inherits it. `sub_body`: `raw_cmd` is the body of a
    /// `$(…)` (lexed as bash lexes one: `split_substitution_noted`).
    /// `out`: receives where the line's `cd`s leave the shell (for a line
    /// that runs in the calling shell: `eval`), unless it is denied.
    /// `dialect`: which reader reads `raw_cmd`.
    #[allow(clippy::too_many_arguments)]
    fn evaluate_inner(
        &self,
        raw_cmd: &str,
        clock: &Clock,
        depth: u32,
        state: &ShellState,
        sub_body: bool,
        out: Option<&mut RuleCwd>,
        dialect: Dialect,
    ) -> Decision {
        #[cfg(test)]
        clock.runs.set(clock.runs.get() + 1);
        let start = clock.start;
        let mut state = state.clone();
        let reader = dialect != Dialect::Posix;
        // The line names IFS somewhere (`IFS=: …`, `export IFS`, a
        // comment): values are still judged, the unresolved words too.
        state.ifs_named |= !reader && mentions_ifs(raw_cmd);
        let mut found = Findings::default();
        let (mut segments, lex_note) = match dialect {
            Dialect::PowerShell => {
                pwsh::split_for_host(raw_cmd, self.vars.style() == PathStyle::Windows)
            }
            Dialect::Cmd => cmdexe::split_segments_noted(raw_cmd),
            Dialect::Posix if sub_body => split_substitution_noted(raw_cmd),
            Dialect::Posix => split_segments_noted(raw_cmd),
        };
        if lex_note == Some(BRACES_PAST_LINE_LIMIT) {
            return too_costly(BRACES_PAST_LINE_LIMIT);
        }
        // What the line made is what it costs: each nested line has its own brace
        // limit, and 14,000 of `eval '{1..1000}'` fit in one 256 KiB line.
        let words: usize = segments.iter().map(Vec::len).sum();
        if !clock.afford_line(words * CHEAP_WORD_COST) {
            return too_costly("too many words in its lines");
        }
        // Bash on Windows moves the profile too, and `evaluate_call` closes only a
        // reader's line, so this one closes itself at the end, after the rules.
        let profile_moved = if reader {
            reader_assignments(&mut segments, &mut found);
            false
        } else {
            self.vars.style() == PathStyle::Windows
                && posix_profile_assignments(raw_cmd, &mut segments, &mut found)
        };
        null_device_words(&mut segments, dialect, state.null_redirect_discards);
        if self.vars.style() == PathStyle::Windows {
            windows_words(&mut segments, reader, dialect);
        }
        if let Some(reason) = lex_note {
            found.unjudged(reason);
        }
        let cx = Ctx {
            start,
            depth,
            // Both checks read POSIX quoting off the raw line. A reader's
            // `PATH` assignment always counts as a change.
            literal_path: reader
                || has_literal_path_ref(raw_cmd)
                || !path_refs_are_plain(raw_cmd, &segments),
            // A reserved word the lexer dropped was no part of `segments`, but
            // `! ( bash )` or `coproc { cmd; }` is not that one command alone.
            only_command: depth == 0
                && segments.iter().filter(|s| !s.is_empty()).count() == 1
                && (reader
                    || self.vars.style() != PathStyle::Windows
                    || !plain_words(raw_cmd).any(heads_a_compound)),
            clock,
            dialect,
        };

        for (at, seg) in segments.iter().enumerate() {
            if start.elapsed() > self.budget {
                let rest = &segments[at..];
                return self.out_of_budget(rest, &cx, &mut state, &mut found, profile_moved);
            }
            if seg.is_empty() {
                continue;
            }
            if let Some(d) = self.evaluate_segment(seg, &cx, &mut state, &mut found) {
                if is_timed_out(&d) {
                    let rest = &segments[at..];
                    return self.out_of_budget(rest, &cx, &mut state, &mut found, profile_moved);
                }
                return d;
            }
        }
        if let Some(out) = out {
            *out = state.rule_cwd.clone();
        }
        let decision = found.finish();
        if profile_moved {
            return closed_reading(decision);
        }
        decision
    }

    /// The budget ran out with `segments` left to judge. That must not be a way
    /// past the rules, in any dialect or path style: padding, or a reader whose
    /// cost grows with the line, could spend the budget before `rm -rf /` or
    /// `rd /s /q C:\` is reached. So what is left still gets the rules and the path
    /// rules, symlinks and globs included, with no clock. Only a deny comes of it,
    /// and a line that closes itself still closes (`profile_moved`); otherwise the
    /// answer is the timeout it was.
    ///
    /// A nested line only reports the timeout: the outermost one starts again
    /// from its current segment, which holds the nested line, so nothing is
    /// judged once per level. Every segment of the line is judged, at a cost
    /// linear in its words. What multiplies that cost has `MAX_CHEAP_WORK`
    /// (`Clock::afford_line`, `Clock::afford_paths`), and brace expansion, the
    /// one way to many more words than bytes, has its limit in the lexer. System
    /// calls are paid from `paths_left` too, `canon::FS_CALL_COST` each, so they
    /// come to a fixed count, the same on every run. Past any of these the line is
    /// denied (`too_costly`): dropping a directory, a nested line or a path to save
    /// the time could allow what a rule would deny.
    fn out_of_budget(
        &self,
        segments: &[Vec<Word>],
        cx: &Ctx,
        state: &mut ShellState,
        found: &mut Findings,
        profile_moved: bool,
    ) -> Decision {
        if cx.clock.last_look || cx.depth > 0 {
            return timed_out();
        }
        // An `Instant` ahead of now has no time elapsed: nothing is over budget.
        let Some(start) = Instant::now().checked_add(Duration::from_secs(86_400)) else {
            return timed_out();
        };
        let clock = Clock {
            start,
            spent: Cell::default(),
            last_look: true,
            lines_left: Cell::new(max_cheap_work()),
            paths_left: Rc::new(Cell::new(max_cheap_work())),
            #[cfg(test)]
            runs: Cell::default(),
        };
        let _metered = meter_fs(Rc::clone(&clock.paths_left));
        let cx = Ctx {
            start,
            depth: cx.depth,
            literal_path: cx.literal_path,
            only_command: false,
            clock: &clock,
            dialect: cx.dialect,
        };
        for seg in segments.iter().filter(|s| !s.is_empty()) {
            match self.evaluate_segment(seg, &cx, state, found) {
                Some(d) if d.is_deny() => return d,
                _ => {}
            }
            if fs_over() {
                return too_costly(PATHS_PAST_LIMIT);
            }
        }
        // As `evaluate_inner` ends: this line's reads went through a moved profile.
        if profile_moved {
            let closed = closed_reading(std::mem::take(found).finish());
            if closed.is_deny() {
                return closed;
            }
        }
        timed_out()
    }

    /// Judge one segment, phase by phase. `Some` ends the whole evaluation
    /// with that decision (a deny, or the budget ran out).
    fn evaluate_segment(
        &self,
        seg: &[Word],
        cx: &Ctx,
        state: &mut ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        // A word whose brace expansion was too large is judged as
        // written, and the command is recorded as not fully judged.
        if seg.iter().any(|w| w.brace_overflow) {
            found.unjudged("brace expansion too large to judge");
        }
        // Peel off transparent wrapper commands (`command`, `env`,
        // `nohup`, `nice`, `stdbuf`, `ionice`, `sudo`) before judging —
        // the engine reasons about the *effective* command, not the
        // wrapper, so packs never need to know these wrappers exist.
        let effective = unwrap_transparent_prefix(seg);
        // Both phases read a word's text as POSIX. The readers already made
        // segments of what a `$(…)` holds, and noted what they could not read.
        if cx.dialect == Dialect::Posix {
            match self.command_position_phase(seg, cx, state, found) {
                Flow::Proceed => {}
                Flow::NextSegment => return None,
                Flow::Done(d) => return Some(d),
            }
            if let Some(d) = self.embedded_substitutions_phase(seg, cx, state, found) {
                return Some(d);
            }
        }
        // `$x rm -rf /`, `$(true) rm -rf /`: if a word in command position
        // comes out empty, the shell runs the next one. Judged that way as
        // well as the way it is written, with no second look at substitutions
        // (done above). As written, the command is that word, so the phases
        // below that recurse have nothing to read there.
        // POSIX only: a reader's `$x rm` is a syntax error or a program named `$x`.
        let mut without = if cx.dialect == Dialect::Posix {
            without_leading_empty_expansions(seg)
        } else {
            None
        };
        // `windows_words` stopped at the word that may vanish, so what it hid
        // still has its Windows name: `$v rm.exe` must read as `rm`.
        if let Some(words) = &mut without {
            if self.vars.style() == PathStyle::Windows {
                windows_program_names(words);
            }
            if let Some(first) = words.first_mut() {
                first.behind_reserved = true;
            }
        }
        let full = without.as_deref().unwrap_or(seg);
        // A wrapper option saiife does not know may take a value, which
        // would make the wrong word the command: not fully judged.
        for opt in unknown_wrapper_options(full) {
            found.unjudged(format!(
                "unknown or ambiguous wrapper option `{opt}`: the command after it may not be judged"
            ));
        }
        // `env -S 'sudo ls'`: the split string is a command line of its own.
        for split in env_split_payloads(full) {
            // env has its own escapes (`\_` is a space, `\c` ends the
            // string), `${NAME}` expansion and `#` comments, which the
            // shell lexer does not model: fail closed.
            if split.string.contains(['\\', '#']) || split.string.contains("${") {
                return Some(Decision::Deny {
                    pack: SUBSTITUTION_GUARD_PACK.to_string(),
                    pattern: "env-split-string-escape".to_string(),
                    reason: "env -S escapes are not judged".to_string(),
                    via_inline: None,
                });
            }
            let nested = self.recurse_in(
                Dialect::Posix,
                &split.line,
                cx,
                state,
                false,
                "env -S command",
                None,
            );
            if let Some(d) = found.nested(nested) {
                return Some(d);
            }
        }
        if let Some(without) = &without {
            let effective = unwrap_transparent_prefix(without);
            if let Some(d) = self.judge_command(without, effective, cx, state, found) {
                return Some(d);
            }
        }
        self.judge_command(seg, effective, cx, state, found)
    }

    /// The phases that judge a segment's command, its arguments and its
    /// redirections.
    fn judge_command(
        &self,
        seg: &[Word],
        effective: &[Word],
        cx: &Ctx,
        state: &mut ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        #[cfg(test)]
        cx.clock.runs.set(cx.clock.runs.get() + 1);
        let view = SegmentView::new(seg, effective, state, cx, &self.vars, found);
        if view.argv.is_empty() || view.argv[0].is_empty() {
            return self.bare_segment_phase(&view, cx, state, found);
        }
        if let Some(d) = self.command_rules_phase(&view, cx, state, found) {
            return Some(d);
        }
        if let Some(d) = self.operands_phase(&view, cx, state, found) {
            return Some(d);
        }
        if let Some(d) = self.eval_phase(&view, cx, state, found) {
            return Some(d);
        }
        Self::environment_phase(&view, cx, state);
        if let Some(d) = self.cd_phase(&view, state, cx) {
            return Some(d);
        }
        if let Some(d) = self.inline_payload_phase(&view, cx, state, found) {
            return Some(d);
        }
        self.nested_shell_phase(&view, cx, state, found)
    }

    /// A reader on a Windows-style host: a value it cannot see, on a command a
    /// pack names, may be that pack's verdict (`saiife ('in'+'it') --off`). The
    /// packs that opt out of the fail-safe do so for bash, where most such values
    /// resolve or the command is common. A reader's value resolves to nothing, so
    /// it counts here, but for `set`, which is no program in PowerShell, and for
    /// `kill` without a name: `Stop-Process -Id $p` names no program (W7).
    fn reader_guards(&self, view: &SegmentView, cx: &Ctx) -> bool {
        if cx.dialect == Dialect::Posix
            || self.vars.style() != PathStyle::Windows
            || !view.resolved.iter().skip(1).any(|w| w.has_substitution)
        {
            return false;
        }
        let name = view.argv[0].as_str();
        match name {
            "set" => false,
            "kill" => view.rule_args.iter().any(|a| a == "-n"),
            _ => self.packs.iter().filter(|p| p.has_deny()).any(|p| {
                p.triggers
                    .iter()
                    .any(|t| looks_like_bare_command_name(t) && t.eq_ignore_ascii_case(name))
            }),
        }
    }

    /// The one place that enforces `MAX_INLINE_DEPTH`, the budget, and the
    /// "… nested too deeply to judge" note: judge `inner` as a command line
    /// of its own, one level deeper, with the shell state it inherits.
    /// `what` names the construct in that note.
    fn recurse(
        &self,
        inner: &str,
        cx: &Ctx,
        state: &ShellState,
        sub_body: bool,
        what: &str,
        out: Option<&mut RuleCwd>,
    ) -> Nested {
        self.recurse_in(cx.dialect, inner, cx, state, sub_body, what, out)
    }

    /// `recurse`, with `inner` read in `dialect`.
    #[allow(clippy::too_many_arguments)]
    fn recurse_in(
        &self,
        dialect: Dialect,
        inner: &str,
        cx: &Ctx,
        state: &ShellState,
        sub_body: bool,
        what: &str,
        out: Option<&mut RuleCwd>,
    ) -> Nested {
        let (start, depth) = (cx.start, cx.depth);
        // Fail open (recorded) beyond the cap rather than recursing
        // unboundedly on adversarial nesting.
        if depth >= MAX_INLINE_DEPTH {
            return Nested::Unjudged(format!("{what} nested too deeply to judge"));
        }
        if start.elapsed() > self.budget {
            return Nested::TimedOut;
        }
        if !cx.clock.afford_line(inner.len() + state.weight()) {
            return Nested::Deny(too_costly(&format!("{what} past the work limit")));
        }
        #[cfg(test)]
        crate::work::add(1 + inner.len());
        match self.evaluate_inner(inner, cx.clock, depth + 1, state, sub_body, out, dialect) {
            Decision::Deny {
                pack,
                pattern,
                reason,
                ..
            } => Nested::Deny(Decision::Deny {
                pack,
                pattern,
                reason,
                via_inline: Some(inner.to_string()),
            }),
            Decision::Allow {
                trace: AllowTrace::FailedOpenTimeout,
            } => Nested::TimedOut,
            Decision::Allow {
                trace: AllowTrace::Unjudgeable { reason },
            } => Nested::Unjudged(reason),
            Decision::Allow { trace } => Nested::Clean(trace),
        }
    }

    /// A segment that is one command substitution (`$(rm -rf /)`,
    /// `` `id` ``) or one assignment of it (`X=$(rm -rf /)`): a real shell
    /// evaluates it eagerly, so `$(rm -rf /)` runs `rm -rf /` for real
    /// regardless of what (if anything) consumes its output. There's no
    /// argv[0] here for a pack to match against — recurse into the inner
    /// text and judge that instead, the same structural re-entry used for
    /// inline `bash -c '...'` payloads (same depth cap, same budget).
    ///
    /// With any other word in the segment (`$(true) $(cat .env)`,
    /// `$(true) < .env`, `X=$(true) Y=$(cat .env)`, `sudo $(id)`) the later
    /// phases must see those words too: `embedded_substitutions_phase`
    /// judges every substitution, the rest the redirections and arguments.
    fn command_position_phase(
        &self,
        seg: &[Word],
        cx: &Ctx,
        state: &mut ShellState,
        found: &mut Findings,
    ) -> Flow {
        if seg.len() != 1 {
            return Flow::Proceed;
        }
        let Some((inner, dollar)) = command_position_substitution_kind(seg) else {
            return Flow::Proceed;
        };
        let nested = self.recurse(&inner, cx, state, dollar, "command substitution", None);
        if let Some(d) = found.nested(nested) {
            return Flow::Done(d);
        }
        // A bare `HOME=$(mktemp -d)` stays set for what follows.
        state.env_changed |= effective_is_empty_assignments(seg, cx.literal_path);
        // Depth cap reached, or the recursion above resolved to a
        // (non-timeout) allow: there is no literal argv[0] in this segment
        // to judge against packs, so move on to the next segment rather
        // than trying to match "$(...)" as if it were a literal command
        // name.
        Flow::NextSegment
    }

    /// Command substitution embedded ANYWHERE else in this segment — not
    /// filling the whole command position (handled above), but sitting
    /// inside an argument, inside a wrapper's own words (e.g. an
    /// `env FOO=$(...)` assignment later peeled off by unwrapping), or only
    /// part of a larger concatenated word (`$(cmd)suffix`). A real shell
    /// evaluates every `$(...)`/`` `...` `` eagerly wherever it appears,
    /// before deciding what the surrounding word means — so leaving any of
    /// these unjudged is a full, silent bypass regardless of position,
    /// quoting, or whether the outer command is one a pack guards.
    /// Scanned over the *original* (pre-unwrap) segment so a substitution
    /// hiding in a word a wrapper's unwrapping would otherwise consume is
    /// not missed either. Recurse into each one found — same depth cap and
    /// budget as every other structural re-entry; a deny in any of them
    /// denies the whole segment. A benign inner (`echo $(date)`) still
    /// resolves to ALLOW here; only a guarded/destructive inner denies.
    /// This does not replace the guarded-argument fail-safe in
    /// `command_rules_phase`, which covers a different risk (a *benign*
    /// inner whose result is still an unknowable, dynamic target for an
    /// already-guarded command, e.g. `rm -rf $(echo /)`).
    fn embedded_substitutions_phase(
        &self,
        seg: &[Word],
        cx: &Ctx,
        state: &ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        for word in seg {
            if !word.has_substitution {
                continue;
            }
            for (inner, dollar) in find_all_substitution_kinds(&word.text) {
                // Past the depth cap: recorded on this one substitution,
                // and the rest of the segment is still scanned.
                let nested = self.recurse(&inner, cx, state, dollar, "command substitution", None);
                if let Some(d) = found.nested(nested) {
                    return Some(d);
                }
            }
        }
        None
    }

    /// A bare wrapper (`env`, `sudo -l`) or bare redirection
    /// (`>/dev/sda`): only whole-segment rules, the redirections and the
    /// path rules can apply.
    fn bare_segment_phase(
        &self,
        view: &SegmentView,
        cx: &Ctx,
        state: &mut ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        let segment_line = segment_line(view.seg);
        if self.combined.might_match(&segment_line) {
            let lines = Lines {
                matching: &view.peeled,
                args: "",
                segment: &segment_line,
                wrappers: &view.wrappers,
                operands: &[],
            };
            match self.judge(lines, view.env_changed, cx.start, &cx.clock.spent) {
                JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return Some(d),
                JudgeOutcome::TimedOut => return Some(timed_out()),
                _ => {}
            }
        }
        state.env_changed |= effective_is_empty_assignments(view.seg, cx.literal_path);
        let alt_ops = view
            .alternatives
            .iter()
            .map(|(_, t)| self.shell_ops(t, &[], &[], view.reads.clone()));
        let all_ops: Vec<Vec<Operand>> =
            std::iter::once(self.shell_ops(&view.seg_ops, &[], &[], view.reads.clone()))
                .chain(alt_ops)
                .collect();
        for ops in all_ops {
            let Some(dirs) = Self::dirs_to_judge(&ops, state, cx) else {
                return Some(too_costly(PATHS_PAST_LIMIT));
            };
            let judged =
                self.judge_operands(ops, dirs, state.cwd_unknown, cx.start, cx.clock.last_look);
            if let Some(d) = found.operands(judged) {
                return Some(d);
            }
        }
        None
    }

    /// The pack rules on the effective command. `Some` on a deny or when
    /// the budget runs out; an allow rule that carved it out is noted.
    fn command_rules_phase(
        &self,
        view: &SegmentView,
        cx: &Ctx,
        state: &ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        let argv = &view.argv;
        // Fail-safe: a guarded command (one an active pack has a deny
        // rule for) with a command-substitution argument can't be
        // proven safe — we don't evaluate `$(...)`/`` `...` ``, so we
        // don't know what it resolves to. Scoped to arguments only
        // (never argv[0] itself) and to already-guarded commands, so an
        // unguarded command with a substitution (`echo $(date)`) gains
        // no new scrutiny.
        if (self.guarded_commands.contains(&argv[0]) || self.reader_guards(view, cx))
            && (view.resolved.iter().skip(1).any(|w| w.has_substitution)
                || (state.ifs_named
                    && view
                        .unresolved
                        .iter()
                        .skip(1)
                        .any(|w| w.has_substitution && !w.dq_substitution)))
        {
            return Some(Decision::Deny {
                pack: SUBSTITUTION_GUARD_PACK.to_string(),
                pattern: GUARDED_SUBSTITUTION_PATTERN.to_string(),
                reason: format!(
                    "{} has a command-substitution argument; the guard cannot see \
                     what it expands to, so it fails safe and blocks",
                    argv[0]
                ),
                via_inline: None,
            });
        }
        let matching_line = &view.matching_line;
        let segment_line = view.segment_line();
        if !self.combined.might_match(matching_line)
            && !(view.whole.is_some() && self.combined.might_match(segment_line))
        {
            return None;
        }
        let lines = Lines {
            matching: matching_line,
            args: &view.args_line,
            segment: segment_line,
            wrappers: &view.wrappers,
            operands: &view.rule_args,
        };
        match self.judge(lines, view.env_changed, cx.start, &cx.clock.spent) {
            JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return Some(d),
            JudgeOutcome::Decided(Decision::Allow { trace }) => {
                found.allow_trace = Some(trace);
            }
            JudgeOutcome::TimedOut => return Some(timed_out()),
            JudgeOutcome::Clean => {}
        }
        self.cd_resolved_phase(view, cx, state)
    }

    /// A destructive command's relative operands after a `cd` on the same
    /// line, joined onto its target (`cd / && rm -rf *` is `rm -rf /*`),
    /// judged by `CD_RESOLVED_PACK` alone. `Some` on a deny or when the
    /// budget runs out.
    fn cd_resolved_phase(
        &self,
        view: &SegmentView,
        cx: &Ctx,
        state: &ShellState,
    ) -> Option<Decision> {
        if state.rule_cwd.too_many_dirs_for(&view.argv) {
            return Some(Decision::Deny {
                pack: CD_RESOLVED_PACK.to_string(),
                pattern: "cd-tracking-overflow".to_string(),
                reason: "too many possible working directories to judge safely".to_string(),
                via_inline: None,
            });
        }
        let rewrites = state.rule_cwd.weight() + MAX_CWDS * view.matching_line.len();
        if !cx.clock.afford_paths(rewrites) {
            return Some(too_costly(PATHS_PAST_LIMIT));
        }
        // `build_argv` collapses a leading `//`, which on Windows is a share.
        let written = self.path_argv(&view.argv, &view.resolved);
        for argv in state
            .rule_cwd
            .rewrite(&written, self.vars.home(), &self.vars)
        {
            let mut line = argv.join(" ");
            if !view.peeled.is_empty() {
                line.push(' ');
                line.push_str(&view.peeled);
            }
            let lines = Lines {
                matching: &line,
                args: "",
                segment: &line,
                wrappers: &view.wrappers,
                operands: &[],
            };
            match self.judge_in(
                Some(CD_RESOLVED_PACK),
                lines,
                view.env_changed,
                cx.start,
                &cx.clock.spent,
            ) {
                JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return Some(d),
                JudgeOutcome::TimedOut => return Some(timed_out()),
                _ => {}
            }
        }
        None
    }

    /// Files the command reads or writes, judged by the path rules that
    /// also guard the agents' file tools; then the other interpretations of
    /// the values (unsplit): the same rules and path rules on each as a
    /// command of its own.
    fn operands_phase(
        &self,
        view: &SegmentView,
        cx: &Ctx,
        state: &ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        if cx.dialect != Dialect::Posix && self.reader_path_is_unknown(view) {
            found.unjudged(UNRESOLVED_REASON);
        }
        let ops = self.shell_ops(
            &view.seg_ops,
            &view.resolved,
            &view.argv,
            view.reads.clone(),
        );
        let Some(dirs) = Self::dirs_to_judge(&ops, state, cx) else {
            return Some(too_costly(PATHS_PAST_LIMIT));
        };
        let judged =
            self.judge_operands(ops, dirs, state.cwd_unknown, cx.start, cx.clock.last_look);
        if let Some(d) = found.operands(judged) {
            return Some(d);
        }
        for (alt_eff, alt_seg) in &view.alternatives {
            let alt_argv = build_argv(alt_eff);
            if alt_argv.is_empty() {
                continue;
            }
            let mut line = alt_argv.join(" ");
            if !view.peeled.is_empty() {
                line.push(' ');
                line.push_str(&view.peeled);
            }
            if self.combined.might_match(&line) {
                let alt_args = without_redirections(alt_eff, &alt_argv);
                let alt_args_line = args_line(&alt_argv, &alt_args);
                let lines = Lines {
                    matching: &line,
                    args: &alt_args_line,
                    segment: view.segment_line(),
                    wrappers: &view.wrappers,
                    operands: &alt_args,
                };
                match self.judge(lines, view.env_changed, cx.start, &cx.clock.spent) {
                    JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return Some(d),
                    JudgeOutcome::TimedOut => return Some(timed_out()),
                    _ => {}
                }
            }
            let ops = self.shell_ops(alt_seg, alt_eff, &alt_argv, view.reads.clone());
            let Some(dirs) = Self::dirs_to_judge(&ops, state, cx) else {
                return Some(too_costly(PATHS_PAST_LIMIT));
            };
            let judged =
                self.judge_operands(ops, dirs, state.cwd_unknown, cx.start, cx.clock.last_look);
            if let Some(d) = found.operands(judged) {
                return Some(d);
            }
        }
        None
    }

    /// `eval ARGS` runs its joined arguments as a command line in this
    /// shell. What a substitution inside it expands to cannot be judged:
    /// recorded, not silent.
    fn eval_phase(
        &self,
        view: &SegmentView,
        cx: &Ctx,
        state: &mut ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        if view.argv[0] != "eval" {
            return None;
        }
        let effective = &view.resolved;
        if effective.iter().any(|w| w.has_substitution) {
            found.unjudged(UNRESOLVED_REASON);
        }
        // `eval -- ARGS`: the `--` ends eval's (empty) options.
        let args = match effective.get(1) {
            Some(w) if w.text == "--" => &effective[2..],
            _ => effective.get(1..).unwrap_or(&[]),
        };
        let inner = args
            .iter()
            .map(|w| w.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        if inner.trim().is_empty() {
            return None;
        }
        // eval runs in this shell: the targets of its `cd`s (added to the
        // set it started from) hold for the rest of the line.
        let mut after = state.rule_cwd.clone();
        let nested = self.recurse(&inner, cx, state, false, "eval", Some(&mut after));
        state.rule_cwd = after;
        found.nested(nested)
    }

    /// A builtin that changes PATH, HOME or XDG_DATA_HOME changes them for
    /// the rest of the command line (and for nested evaluations).
    fn environment_phase(view: &SegmentView, cx: &Ctx, state: &mut ShellState) {
        state.env_changed |= changes_environment(&view.argv, &view.resolved, cx.literal_path);
    }

    /// `cd`/`pushd`: the later segments may run in its target too.
    /// `Some`: its target cannot be read (Windows), so what follows could not
    /// be judged either.
    fn cd_phase(&self, view: &SegmentView, state: &mut ShellState, cx: &Ctx) -> Option<Decision> {
        if !cx.clock.afford_paths(state.rule_cwd.weight()) {
            return Some(too_costly(PATHS_PAST_LIMIT));
        }
        state
            .rule_cwd
            .command(&view.argv, &view.resolved, self.vars.home());
        if view.argv[0] == "cd" || view.argv[0] == "pushd" {
            // Read and resolved from each directory there is.
            if !cx.clock.afford_paths(state.weight()) {
                return Some(too_costly(PATHS_PAST_LIMIT));
            }
            let words = winpath::path_words(&view.resolved, &self.vars);
            let argv = self.path_argv(&view.argv, &words);
            let target = argv
                .iter()
                .zip(words.iter())
                .skip(1)
                .find(|(a, _)| !a.starts_with('-'))
                .filter(|(_, w)| !w.has_substitution);
            if let Some((a, _)) = target {
                // From any directory the shell may be in: `cd /; cd c/Users`
                // reads fine from the old one.
                let d = match state.cwds.as_slice() {
                    [] => self.unreadable(a, None),
                    cwds => cwds.iter().find_map(|c| self.unreadable(a, Some(c))),
                };
                if d.is_some() {
                    return d;
                }
            }
            let behind = view.seg.first().is_some_and(|w| w.behind_reserved);
            state.cwd_unknown |= self.cd(&argv, &words, state, behind);
        }
        None
    }

    /// `argv` as the path rules read it. `build_argv` collapses leading
    /// slashes for the pack regexes, but on Windows `//host/share` and
    /// `//./C:/x` are not `/host/share` and `/C:/x`: there the words stay as
    /// written.
    fn path_argv<'a>(&self, argv: &'a [String], effective: &[Word]) -> Cow<'a, [String]> {
        if self.vars.style() != PathStyle::Windows {
            return Cow::Borrowed(argv);
        }
        Cow::Owned(
            argv.iter()
                .enumerate()
                .map(|(i, a)| match effective.get(i) {
                    Some(w) if i > 0 => w.text.clone(),
                    _ => a.clone(),
                })
                .collect(),
        )
    }

    /// Windows: `path` is on a host the command chose, so asking the OS about
    /// it would be a call to that host.
    fn is_remote(&self, path: &Path) -> bool {
        self.vars.style() == PathStyle::Windows && path.to_string_lossy().starts_with("//")
    }

    /// Structural inline-payload re-entry: `bash -c '…'`, `su -c '…'`, and
    /// `watch CMD …` (which joins its remaining args and runs them via
    /// `sh -c`). Not gated behind the pre-filter — the payload may only
    /// resolve to something trigger-bearing once it is *re-lexed* on its
    /// own (a nested quote inside an outer single-quoted `-c` argument is
    /// invisible to the outer scan by design; the recursive call
    /// re-tokenizes it correctly). The two extractors are mutually
    /// exclusive on argv[0], so trying one then the other never
    /// double-recurses the same segment. An allowed payload does not end
    /// the evaluation: later segments still get judged.
    fn inline_payload_phase(
        &self,
        view: &SegmentView,
        cx: &Ctx,
        state: &ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        // cmd's quotes are not a POSIX shell's. The program splits its own command
        // line: `bash -c 'cat x'` from cmd is `cat x`.
        if cx.dialect == Dialect::Cmd
            && self.vars.style() == PathStyle::Windows
            && wintable::is_posix_shell(&view.argv[0])
            && view.argv.iter().any(|a| a.contains('\''))
        {
            let line = view.argv.join(" ");
            let nested = self.recurse_in(
                Dialect::Posix,
                &line,
                cx,
                state,
                false,
                "inline command",
                None,
            );
            if let Some(d) = found.nested(nested) {
                return Some(d);
            }
        }
        let inner = inline_payload(&view.argv).or_else(|| watch_payload(&view.argv))?;
        // The program is a POSIX shell, whichever shell started it.
        let nested = self.recurse_in(
            Dialect::Posix,
            &inner,
            cx,
            state,
            false,
            "inline command",
            None,
        );
        found.nested(nested)
    }

    /// The directories to judge `ops` in: all of them. `None` when the last
    /// look has spent its work on paths, and judging fewer could miss a rule.
    fn dirs_to_judge<'a>(
        ops: &[Operand],
        state: &'a ShellState,
        cx: &Ctx,
    ) -> Option<&'a [PathBuf]> {
        if !cx.clock.last_look {
            return Some(&state.cwds);
        }
        let dirs = state.cwds.len().max(1);
        let per_path = CHEAP_PATH_COST * dirs
            + state
                .cwds
                .iter()
                .map(|c| c.as_os_str().len())
                .sum::<usize>();
        let cost = ops
            .iter()
            .map(|op| (1 + op.into.len()) * (per_path + dirs * op.path.len()))
            .sum();
        cx.clock.afford_paths(cost).then_some(state.cwds.as_slice())
    }

    /// `powershell -enc …`, `cmd /c …`, `iex '…'`: the text is a command line
    /// in that shell's own dialect. Under POSIX only on a Windows host (Git
    /// Bash starting `powershell`): POSIX style stays as it was.
    fn nested_shell_phase(
        &self,
        view: &SegmentView,
        cx: &Ctx,
        state: &ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        let windows = self.vars.style() == PathStyle::Windows;
        if cx.dialect == Dialect::Posix && !windows {
            return None;
        }
        if !windows {
            let (dialect, inner) = cmdexe::nested(&view.resolved)?;
            let nested = self.recurse_in(dialect, &inner, cx, state, false, "nested command", None);
            return found.nested(nested);
        }
        // A redirection is the outer shell's, and judged there: it is no text of
        // the nested command, and `powershell > f` still reads stdin.
        let words = wintable::without_redirects(&view.resolved);
        // Under a reader a line it could not read is `Unjudgeable`, which
        // `evaluate_call` closes at the top. The POSIX route closes it here (W5).
        let unread = |reason: String, found: &mut Findings| {
            if cx.dialect == Dialect::Posix {
                Some(unreadable_command(reason))
            } else {
                found.unjudged(reason);
                None
            }
        };
        if let Some(lines) = wintable::wsl_lines(&words) {
            for line in lines {
                if line == wintable::UNRESOLVED {
                    return unread(wintable::NOTE_WSL.to_string(), found);
                }
                let nested =
                    self.recurse_in(Dialect::Posix, &line, cx, state, false, "wsl command", None);
                if let Some(d) = found.nested(nested) {
                    return Some(d);
                }
            }
            return None;
        }
        if let Some(reason) = wintable::unread_shell(&words) {
            // `exec bash` alone: nothing here gives it a stdin to run, so there
            // is nothing unread to judge. A pipe or a nested line is another
            // command on the line, and a redirection is in this segment. A word
            // that is no plain option (`cmd x.bat`) may name what it runs.
            let fed = view.seg.iter().any(|w| w.redirect && w.text.contains('<'));
            let plain_option = |w: &Word| {
                !w.has_substitution
                    && w.text.starts_with(['-', '/'])
                    && !w.text[1..].contains(['/', '\\', '.'])
            };
            if cx.only_command && !fed && words.iter().skip(1).all(plain_option) {
                return None;
            }
            return unread(reason.to_string(), found);
        }
        let (dialect, inner) = cmdexe::nested(&words)?;
        match self.recurse_in(dialect, &inner, cx, state, false, "nested command", None) {
            Nested::Unjudged(reason) => unread(reason, found),
            nested => found.nested(nested),
        }
    }

    /// Judge every path the segment reads or writes, against every
    /// directory the shell may be in. `Some` on a deny, when the budget runs
    /// out, or (`Unjudgeable`) when a glob was too large to expand. A path
    /// that cannot be made absolute is skipped.
    ///
    /// Two passes: first the paths as spelled, made absolute lexically (no
    /// filesystem access, so `cat f1 … f5000 .env` is denied before the
    /// budget is spent on syscalls); then the resolved forms (symlinks),
    /// glob matches and copy targets that are directories. `last_look`
    /// (`out_of_budget`): the first pass also judges a copy target both ways.
    fn judge_operands(
        &self,
        ops: Vec<Operand>,
        cwds: &[PathBuf],
        cwd_unknown: bool,
        start: Instant,
        last_look: bool,
    ) -> Option<Decision> {
        if !self.has_path_rules || ops.is_empty() {
            return None;
        }
        let all: Vec<Option<&Path>> = if cwds.is_empty() {
            vec![None]
        } else {
            cwds.iter().map(|c| Some(c.as_path())).collect()
        };
        // A path that does not depend on the working directory is judged
        // once.
        // On Windows `/x` and `~+` depend on it: `/x` is on the current drive.
        let windows = self.vars.style() == PathStyle::Windows;
        let absolute = |raw: &str| {
            if windows {
                (raw.starts_with('~') && !raw.starts_with("~+")) || raw.starts_with("$HOME")
            } else {
                raw.starts_with('/') || raw.starts_with('~') || raw.starts_with("$HOME")
            }
        };
        let anchors = |raw: &str| -> &[Option<&Path>] {
            if absolute(raw) {
                &all[..1]
            } else {
                &all
            }
        };
        let timed_out = || {
            Some(Decision::Allow {
                trace: AllowTrace::FailedOpenTimeout,
            })
        };

        for op in &ops {
            // A copy target that may be a directory waits for pass 2. In the last
            // look, which may not get there, it is judged as a directory and as
            // the file here too.
            let plain = op.into.iter().all(|s| !s.glob && !s.contents);
            let mut landing = if op.into.is_empty() {
                vec![op.path.clone()]
            } else if (last_look || op.path.ends_with('/')) && plain {
                let names: Vec<String> = op
                    .into
                    .iter()
                    .filter_map(|s| base_name(&s.path, self.vars.style()))
                    .collect();
                into_dir(&op.path, &names)
            } else if last_look {
                Vec::new()
            } else {
                continue;
            };
            if last_look && !op.into.is_empty() && !op.path.ends_with('/') {
                landing.push(op.path.clone());
            }
            for raw in &landing {
                for cwd in anchors(raw) {
                    // A provider's word has its own verdict; a name that reads
                    // as a file (`temp:x`) is also judged as one.
                    if let Some(d) = self.unreadable_operand(raw, *cwd, op.access) {
                        return Some(d);
                    }
                    let Some(form) = lexical_form(raw, *cwd, &self.vars) else {
                        continue;
                    };
                    #[cfg(test)]
                    crate::work::add(1 + form.as_os_str().len());
                    match self.judge_path(op.access, &form, start) {
                        JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return Some(d),
                        JudgeOutcome::TimedOut => return timed_out(),
                        _ => {}
                    }
                }
            }
        }

        // What follows reaches the filesystem.
        let mut unjudged = None;
        for op in &ops {
            for cwd in anchors(&op.path) {
                if start.elapsed() > self.budget {
                    return timed_out();
                }
                let words = if op.glob {
                    match expand_operand_glob_dots(&op.path, *cwd, &self.vars, op.dots) {
                        GlobExpansion::Matches(m) if !m.is_empty() => m
                            .into_iter()
                            .map(|p| p.to_string_lossy().into_owned())
                            .collect(),
                        GlobExpansion::Overflow => {
                            unjudged = Some("glob too large to judge".to_string());
                            continue;
                        }
                        _ => vec![op.path.clone()],
                    }
                } else {
                    vec![op.path.clone()]
                };
                for word in words {
                    let landing = if op.into.is_empty() {
                        vec![word]
                    } else {
                        let (landing, forms, err) = self.landing(&word, &op.into, *cwd);
                        if let Some(reason) = err {
                            unjudged.get_or_insert(reason);
                        }
                        for form in &forms {
                            match self.judge_path(op.access, form, start) {
                                JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return Some(d),
                                JudgeOutcome::TimedOut => return timed_out(),
                                _ => {}
                            }
                        }
                        landing
                    };
                    for raw in landing {
                        if let Some(d) = self.unreadable_operand(&raw, *cwd, op.access) {
                            return Some(d);
                        }
                        for form in path_forms(&raw, *cwd, &self.vars) {
                            match self.judge_path(op.access, &form, start) {
                                JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return Some(d),
                                JudgeOutcome::TimedOut => return timed_out(),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        if cwd_unknown && ops.iter().any(|op| !absolute(&op.path)) {
            unjudged.get_or_insert_with(|| "working directory unknown after cd".to_string());
        }
        unjudged.map(|reason| Decision::Allow {
            trace: AllowTrace::Unjudgeable { reason },
        })
    }

    /// The paths a shell segment touches (`operands`), plus `extra` (files
    /// a peeled-off wrapper reads). Empty without path rules.
    /// POSIX style (`pwsh` on Linux or macOS): `operands` skips a word it cannot
    /// see, so `Get-Content $x` would have no path to judge. A reader's word is
    /// a path it does not know, as `winpath::path_words` makes it on Windows.
    fn reader_path_is_unknown(&self, view: &SegmentView) -> bool {
        if !self.has_path_rules
            || self.vars.style() == PathStyle::Windows
            || !view.seg_ops.iter().any(|w| w.has_substitution)
        {
            return false;
        }
        let seen = |words: &[Word]| -> Vec<Word> {
            words
                .iter()
                .cloned()
                .map(|mut w| {
                    w.has_substitution = false;
                    w
                })
                .collect()
        };
        let all = operands(&seen(&view.seg_ops), &seen(&view.resolved), &view.argv);
        view.seg_ops
            .iter()
            .filter(|w| w.has_substitution)
            .any(|w| all.iter().any(|op| op.path.contains(&w.text)))
    }

    fn shell_ops(
        &self,
        seg: &[Word],
        effective: &[Word],
        argv: &[String],
        extra: Vec<Operand>,
    ) -> Vec<Operand> {
        if !self.has_path_rules {
            return Vec::new();
        }
        let seg = winpath::path_words(seg, &self.vars);
        let effective = winpath::path_words(effective, &self.vars);
        let mut ops = operands(&seg, &effective, &self.path_argv(argv, &effective));
        ops.extend(extra);
        ops
    }

    /// What a copy/move into `target` writes. Paths to judge in full:
    /// `target/<name>` for each source when `target` is a directory (glob
    /// sources expanded first), `target` itself otherwise or when a source
    /// is a `contents` copy. Forms to judge as they are: for a `contents`
    /// source (`cp -T dir t`, `rsync dir/ t`, globs expanded first), each
    /// top-level entry under each form of `target` (one resolution of
    /// `target`, none per entry). A reason when a glob or a source directory
    /// is too large to list; what was seen is still returned.
    fn landing(
        &self,
        target: &str,
        sources: &[Source],
        cwd: Option<&Path>,
    ) -> (Vec<String>, Vec<PathBuf>, Option<String>) {
        let mut names = Vec::new();
        let mut entries = Vec::new();
        let mut err = None;
        let mut scanned = 0usize;
        for src in sources {
            let paths: Vec<String> = if src.glob {
                match expand_operand_glob_dots(&src.path, cwd, &self.vars, src.dots) {
                    GlobExpansion::Matches(m) if !m.is_empty() => {
                        m.iter().map(|p| p.to_string_lossy().into_owned()).collect()
                    }
                    GlobExpansion::Overflow => {
                        err = Some("glob too large to judge".to_string());
                        vec![src.path.clone()]
                    }
                    _ => vec![src.path.clone()],
                }
            } else {
                vec![src.path.clone()]
            };
            for path in paths {
                if !src.contents {
                    names.extend(base_name(&path, self.vars.style()));
                    continue;
                }
                let Some(dir) = canonicalize(&path, cwd, &self.vars) else {
                    continue;
                };
                if self.is_remote(&dir) {
                    continue;
                }
                let Some(list) = fs_read_dir(&dir) else {
                    continue;
                };
                for e in list.flatten() {
                    scanned += 1;
                    if scanned > GLOB_SCAN_LIMIT {
                        err = Some("copy source too large to judge".to_string());
                        break;
                    }
                    if !fs_next_entry() {
                        break;
                    }
                    entries.push(e.file_name());
                }
            }
        }
        let is_dir = target.ends_with('/')
            || canonicalize(target, cwd, &self.vars)
                .is_some_and(|p| !self.is_remote(&p) && fs_is_dir(&p));
        let mut full = Vec::new();
        if is_dir {
            full.extend(into_dir(target, &names));
        }
        let contents = sources.iter().any(|s| s.contents);
        if !is_dir || contents {
            full.push(target.to_string());
        }
        let mut forms = Vec::new();
        if !entries.is_empty() {
            for base in path_forms(target, cwd, &self.vars) {
                forms.extend(entries.iter().map(|e| base.join(e)));
            }
        }
        (full, forms, err)
    }

    /// Add where `cd`/`pushd` may leave the shell to `cwds`: its operand
    /// resolved against each directory, home without one. The old
    /// directories always stay. Returns true when the shell may now be
    /// somewhere `cwds` does not hold: `cd -`, a target with a substitution,
    /// one that cannot be resolved, or more directories than `MAX_CWDS` in its
    /// tier, where nothing more is resolved.
    ///
    /// `behind`: the `cd` stands behind a reserved word or a word that may vanish.
    /// What it reaches, and what a plain `cd` reaches from there, goes in the second
    /// tier (`ShellState::plain_cwds`), so padding of such `cd`s cannot use up the
    /// slots a plain one needs, before or after it.
    fn cd(
        &self,
        argv: &[String],
        effective: &[Word],
        state: &mut ShellState,
        behind: bool,
    ) -> bool {
        let arg = argv
            .iter()
            .zip(effective)
            .skip(1)
            .find(|(a, _)| !a.starts_with('-') || *a == "-");
        // Each new directory, and whether it is for the plain tier.
        let (new, mut unknown): (Vec<(PathBuf, bool)>, bool) = match arg {
            None => match self.vars.home() {
                Some(h) => (vec![(h.to_path_buf(), !behind)], false),
                None => (Vec::new(), true),
            },
            // A `$` is a variable to POSIX. On Windows `path_words` has already
            // told a variable from a name.
            Some((a, w))
                if a == "-"
                    || w.has_substitution
                    || (self.vars.style() == PathStyle::Posix && a.contains('$')) =>
            {
                (Vec::new(), true)
            }
            Some((a, _)) => {
                let plain_full = state.plain_cwds >= MAX_CWDS;
                let other_full = state.cwds.len() - state.plain_cwds >= MAX_CWDS;
                let anchors: Vec<(Option<&Path>, bool)> = if state.cwds.is_empty() {
                    vec![(None, !behind)]
                } else {
                    state
                        .cwds
                        .iter()
                        .enumerate()
                        .map(|(i, c)| (Some(c.as_path()), !behind && i < state.plain_cwds))
                        .collect()
                };
                let all = anchors.len();
                let anchors: Vec<_> = anchors
                    .into_iter()
                    .filter(|(_, plain)| if *plain { !plain_full } else { !other_full })
                    .collect();
                let mut unknown = anchors.len() < all;
                #[cfg(test)]
                CD_RESOLVES.with(|n| n.set(n.get() + anchors.len()));
                let mut new = Vec::with_capacity(anchors.len());
                for (c, plain) in anchors {
                    match canonicalize(a, c, &self.vars) {
                        Some(d) => new.push((d, plain)),
                        None => unknown = true,
                    }
                }
                (new, unknown)
            }
        };
        for (n, plain) in new {
            let tier = if plain {
                0..state.plain_cwds
            } else {
                state.plain_cwds..state.cwds.len()
            };
            if state.cwds[tier.clone()].contains(&n) {
                continue;
            }
            if tier.len() >= MAX_CWDS {
                unknown = true;
                continue;
            }
            state.cwds.insert(tier.end, n);
            if plain {
                state.plain_cwds += 1;
            }
        }
        unknown
    }

    /// Run allow-before-deny per pack, across all packs, for one segment: a
    /// pack whose allow rule matches skips only its own deny rules, so the
    /// first deny of any other pack still wins over an allow. Rules match
    /// the effective command's line (its argv after wrappers like `sudo` are
    /// peeled off, case-folded/dir-stripped/slash-collapsed, joined with
    /// single spaces); `whole_segment` rules match the line of the whole
    /// segment, wrappers and leading assignments included. An empty
    /// `matching_line` (a bare wrapper) leaves only `whole_segment` rules.
    fn judge(
        &self,
        lines: Lines,
        env_changed: bool,
        start: Instant,
        spent: &Cell<Duration>,
    ) -> JudgeOutcome {
        self.judge_in(None, lines, env_changed, start, spent)
    }

    /// `judge`, over the pack `only` names when it is set.
    fn judge_in(
        &self,
        only: Option<&str>,
        lines: Lines,
        env_changed: bool,
        start: Instant,
        spent: &Cell<Duration>,
    ) -> JudgeOutcome {
        let Lines {
            matching: matching_line,
            args: args_line,
            segment: segment_line,
            wrappers,
            operands,
        } = lines;
        let line = |rule: &crate::pack::Rule| -> Option<&str> {
            if rule.peeled_wrappers {
                (!wrappers.is_empty()).then_some(wrappers)
            } else if rule.after_env_change {
                (env_changed && !matching_line.is_empty()).then_some(matching_line)
            } else if rule.whole_segment {
                Some(segment_line)
            } else if rule.no_redirections {
                (!matching_line.is_empty() && !args_line.is_empty()).then_some(args_line)
            } else if matching_line.is_empty() {
                None
            } else {
                Some(matching_line)
            }
        };
        // The rule's line matches, the command was given the option the
        // rule asks for (and has no operand, when the rule asks for that),
        // and an operand names a target when the rule asks
        // for one.
        let over_budget = || start.elapsed() > self.budget;
        let matches = |rule: &crate::pack::Rule| -> Hit {
            if !line(rule).is_some_and(|l| {
                #[cfg(test)]
                crate::work::add(1 + l.len());
                rule.regex.is_match(l)
            }) {
                return Hit::No;
            }
            if rule
                .when_option
                .as_ref()
                .is_some_and(|w| !w.matches(operands))
            {
                return Hit::No;
            }
            match (&rule.operands, &rule.table) {
                (None, _) => Hit::Yes,
                // Read with the command's own options: `pkill -u 0 node`
                // has the one operand `node`.
                (Some(m), Some(t)) => m.hits_within(
                    &t.operand_args(operands),
                    &over_budget,
                    spent,
                    self.pattern_allowance,
                ),
                (Some(m), None) => {
                    m.hits_within(operands, &over_budget, spent, self.pattern_allowance)
                }
            }
        };
        let mut allowed: Option<AllowTrace> = None;
        for pack in &self.packs {
            if start.elapsed() > self.budget {
                return JudgeOutcome::TimedOut;
            }
            if only.is_some_and(|id| id != pack.id) {
                continue;
            }
            let pf = pack.prefilter();
            if !pf.might_match(matching_line) && !pf.might_match(segment_line) {
                continue;
            }
            // An allow match exempts only this pack's own deny rules (as
            // `allow_path` does); later packs still judge the command.
            let mut allow_rule = None;
            for r in pack.allow_rules() {
                match matches(r) {
                    Hit::Yes => {
                        allow_rule = Some(r);
                        break;
                    }
                    Hit::OutOfBudget => return JudgeOutcome::TimedOut,
                    Hit::No => {}
                }
            }
            if let Some(rule) = allow_rule {
                allowed.get_or_insert_with(|| AllowTrace::AllowRule {
                    pack: pack.id.clone(),
                    pattern: rule.pattern.clone(),
                    reason: rule.reason.clone(),
                });
                continue;
            }
            // Deny rules — first match wins.
            for rule in pack.deny_rules() {
                let hit = matches(rule);
                if hit == Hit::OutOfBudget {
                    return JudgeOutcome::TimedOut;
                }
                if hit == Hit::Yes {
                    return JudgeOutcome::Decided(Decision::Deny {
                        pack: pack.id.clone(),
                        pattern: rule.pattern.clone(),
                        reason: rule.reason.clone(),
                        via_inline: None,
                    });
                }
            }
        }
        if let Some(trace) = allowed {
            return JudgeOutcome::Decided(Decision::Allow { trace });
        }
        JudgeOutcome::Clean
    }
}

/// Directories a command line's paths are judged against at most, in each of the
/// two tiers of `ShellState::plain_cwds` (the plain one holds the starting one).
const MAX_CWDS: usize = 16;

/// The last component of `path` (`a/b/` is `b`). Under Windows style `\\`
/// separates too: `cp 'C:\\x\\settings.json' .claude/` lands on that one name.
fn base_name(path: &str, style: PathStyle) -> Option<String> {
    let seps: &[char] = if style == PathStyle::Windows {
        &['/', '\\']
    } else {
        &['/']
    };
    path.trim_end_matches(seps)
        .rsplit(seps)
        .next()
        .filter(|b| !b.is_empty())
        .map(str::to_string)
}

/// The path rules on one already-read segment, for the readers' tests:
/// Task 6 wires the PowerShell and cmd readers into `evaluate`.
#[cfg(test)]
impl Engine {
    pub(crate) fn judge_words(&self, seg: &[Word]) -> Option<Decision> {
        self.path_rules();
        let argv = crate::normalize::build_argv(seg);
        let seg = winpath::path_words(seg, &self.vars);
        let ops = operands(&seg, &seg, &self.path_argv(&argv, &seg));
        let cwds: Vec<PathBuf> = self.vars.cwd().map(Path::to_path_buf).into_iter().collect();
        self.judge_operands(ops, &cwds, false, Instant::now(), false)
    }
}

/// The stricter of two decisions; `a` when they rank alike. Deny, then what
/// was not judged (never hidden by a reading that judged it), then an allow
/// rule's trace, then no match.
fn stricter(a: Decision, b: Decision) -> Decision {
    let rank = |d: &Decision| match d {
        Decision::Deny { .. } => 4,
        Decision::Allow { trace } => match trace {
            AllowTrace::FailedOpenTimeout => 3,
            AllowTrace::Unjudgeable { .. } => 2,
            AllowTrace::AllowRule { .. } => 1,
            AllowTrace::NoMatch => 0,
        },
    };
    if rank(&b) > rank(&a) {
        b
    } else {
        a
    }
}

/// `both` readings, and the shell may be cmd (`ComSpec`), which neither sees:
/// `r^d /s /q C:\`. cmd's grammar over text meant for another shell is noise (`%`
/// in `git log --format=%h%d`, `'` is no quote), so only a deny by a rule denies.
/// What it could not judge stays on the record, for the caller's fail policy:
/// a fail-safe deny, a note and a timeout are all that.
fn with_cmd_reading(both: Decision, cmd: Decision) -> Decision {
    match cmd {
        Decision::Deny { pattern, .. } if pattern == GUARDED_SUBSTITUTION_PATTERN => stricter(
            both,
            Decision::Allow {
                trace: AllowTrace::Unjudgeable {
                    reason: "as cmd, a variable decides this command".to_string(),
                },
            },
        ),
        d @ (Decision::Deny { .. }
        | Decision::Allow {
            trace: AllowTrace::Unjudgeable { .. } | AllowTrace::FailedOpenTimeout,
        }) => stricter(both, d),
        Decision::Allow { .. } => both,
    }
}

/// A reader's decision as a hook call answers it: what it could not read is a
/// deny (the attacker picks that syntax). A timeout passes: its answer is the
/// caller's fail policy, and it must not be recorded as a deny.
fn closed_reading(d: Decision) -> Decision {
    let Decision::Allow {
        trace: AllowTrace::Unjudgeable { reason },
    } = &d
    else {
        return d;
    };
    let why = reason.as_str();
    Decision::Deny {
        pack: SUBSTITUTION_GUARD_PACK.to_string(),
        pattern: UNREADABLE_COMMAND_PATTERN.to_string(),
        reason: format!("{why}; the guard cannot read this command, so it fails safe and blocks"),
        via_inline: None,
    }
}

/// `closed_reading` of what could not be read, for `reason`.
fn unreadable_command(reason: String) -> Decision {
    closed_reading(Decision::Allow {
        trace: AllowTrace::Unjudgeable { reason },
    })
}

/// Variable names ignore case on Windows, and the profile's variables are its
/// `HOME`: an assignment as `PROTECTED_ENV` reads it. A path spelled with one
/// of them means something else after it, so the line is not fully judged.
fn reader_assignments(segments: &mut [Vec<Word>], found: &mut Findings) {
    for w in segments.iter_mut().flatten().filter(|w| w.assignment) {
        let Some((name, value)) = w.text.split_once('=') else {
            continue;
        };
        let (name, plus) = match name.strip_suffix('+') {
            Some(n) => (n, "+"),
            None => (name, ""),
        };
        let mut upper = name.to_ascii_uppercase();
        if is_profile_variable(&upper) {
            found.unjudged(PROFILE_MOVED);
            upper = "HOME".to_string();
        }
        w.text = format!("{upper}{plus}={value}");
    }
}

const PROFILE_MOVED: &str = "a profile variable changes on this line";

const PROFILE_VARIABLES: &[&str] = &[
    "home",
    "userprofile",
    "homedrive",
    "homepath",
    "localappdata",
    "appdata",
];

fn is_profile_variable(name: &str) -> bool {
    PROFILE_VARIABLES
        .iter()
        .any(|p| name.eq_ignore_ascii_case(p))
}

/// What may stand in front of an assignment in a POSIX segment.
const POSIX_LEADING_WORDS: &[&str] = &[
    "if", "then", "elif", "else", "while", "until", "do", "{", "(", "!", "time",
];

/// How deep quoted command text is read for a read through a moved variable.
const MAX_PROFILE_TEXT_DEPTH: u32 = 4;

/// The shape of a POSIX segment, as far as assignments go.
struct PosixAssignments {
    /// The words in front of the command.
    leading: Vec<usize>,
    /// The command's word: past `builtin` and `command`.
    command: Option<usize>,
    /// The arguments of `export` and its kin, which stay set, or of `env`, which
    /// the command under it sees.
    arguments: Vec<usize>,
}

/// The lexer flags `NAME=` in any position, so only what the shell or `env` assigns
/// counts. `echo HOME=x` assigns nothing.
fn posix_assignments(seg: &[Word]) -> PosixAssignments {
    let mut i = 0;
    let mut leading = Vec::new();
    while let Some(w) = seg.get(i) {
        if w.redirect {
            i += 2;
        } else if w.assignment {
            leading.push(i);
            i += 1;
        } else if !w.quoted && POSIX_LEADING_WORDS.contains(&w.text.as_str()) {
            i += 1;
        } else {
            break;
        }
    }
    let plain = |w: &Word, names: &[&str]| !w.quoted && names.contains(&w.text.as_str());
    while seg
        .get(i)
        .is_some_and(|w| plain(w, &["builtin", "command"]))
    {
        i += 1;
    }
    let command = (i < seg.len()).then_some(i);
    let names_values = command.is_some_and(|c| {
        plain(
            &seg[c],
            &["export", "readonly", "declare", "typeset", "local", "env"],
        )
    });
    let arguments = if names_values {
        (i + 1..seg.len())
            .filter(|&at| seg[at].assignment)
            .collect()
    } else {
        Vec::new()
    };
    PosixAssignments {
        leading,
        command,
        arguments,
    }
}

fn assigned_profile_variable(w: &Word) -> bool {
    w.text
        .split_once('=')
        .is_some_and(|(name, _)| is_profile_variable(name.strip_suffix('+').unwrap_or(name)))
}

/// `reader_assignments` for a POSIX line on a Windows host. Other names keep their
/// case, since `$x` is not `$X` to bash. Moving a profile variable alone judges
/// nothing (`HOME=/tmp/x cargo test`): only a later read through it leaves a path
/// that is not what it says. True when the line has one.
fn posix_profile_assignments(
    raw_cmd: &str,
    segments: &mut [Vec<Word>],
    found: &mut Findings,
) -> bool {
    let any_order = posix_runs_out_of_order(raw_cmd, segments);
    let reads = reads_moved_profile(segments, false, any_order, 0).0;
    for seg in segments.iter_mut() {
        let shape = posix_assignments(seg);
        for at in shape.leading.into_iter().chain(shape.arguments) {
            let w = &mut seg[at];
            if !assigned_profile_variable(w) {
                continue;
            }
            let Some((name, value)) = w.text.split_once('=') else {
                continue;
            };
            let plus = if name.ends_with('+') { "+" } else { "" };
            w.text = format!("HOME{plus}={value}");
        }
    }
    if reads {
        found.unjudged(PROFILE_MOVED);
    }
    reads
}

/// A loop or a function runs text written before the move after it. The lexer does
/// not keep a function's `()`, and drops these words from the front of a segment, so
/// both are looked for on the line too.
fn posix_runs_out_of_order(raw_cmd: &str, segments: &[Vec<Word>]) -> bool {
    let unspaced: String = raw_cmd.split_whitespace().collect();
    let repeats = |word: &str| matches!(word, "for" | "while" | "until" | "select" | "function");
    unspaced.contains("()")
        || plain_words(raw_cmd).any(repeats)
        || segments
            .iter()
            .flatten()
            .any(|w| !w.quoted && repeats(&w.text))
}

/// A reserved word the POSIX lexer drops from the front of a segment.
fn heads_a_compound(word: &str) -> bool {
    matches!(
        word,
        "!" | "if"
            | "elif"
            | "while"
            | "until"
            | "for"
            | "select"
            | "coproc"
            | "function"
            | "repeat"
            | "not"
            | "and"
            | "or"
            | "begin"
    )
}

/// The words of a POSIX line with no quote or backslash anywhere in them, in one
/// pass. Quoted text is skipped, not parsed: a word in `$(…)` counts.
fn plain_words(raw: &str) -> impl Iterator<Item = &str> {
    let (mut single, mut double, mut escaped) = (false, false, false);
    raw.split(move |c: char| {
        if std::mem::take(&mut escaped) {
            return false;
        }
        match c {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            _ => {}
        }
        !single && !double && (c.is_whitespace() || ";&|()`".contains(c))
    })
    .filter(|word| !word.contains(['\'', '"', '\\']))
}

/// Does a word read through a profile variable moved before it, and is one moved at
/// the end of `segments`? With `any_order`, a move counts for every word.
///
/// A persisting assignment (one alone, or under `export`) reaches everything after
/// it. An inline one ends with its command, and bash expands that command's words
/// before it applies, so `HOME=/x cat ~/y` reads the real `~/y`, which the rules
/// judge as that. It does reach `cd`, the words that are assignments too, and quoted
/// text the command may run itself: `HOME=/x bash -c 'cat ~/y'`.
fn reads_moved_profile(
    segments: &[Vec<Word>],
    moved_before: bool,
    any_order: bool,
    depth: u32,
) -> (bool, bool) {
    let mut moved = moved_before
        || (any_order
            && segments.iter().any(|seg| {
                let shape = posix_assignments(seg);
                shape
                    .leading
                    .iter()
                    .chain(&shape.arguments)
                    .any(|&at| assigned_profile_variable(&seg[at]))
            }));
    for seg in segments {
        let shape = posix_assignments(seg);
        let keeps = |at: usize| {
            shape.command.is_none()
                || (shape.arguments.contains(&at)
                    && shape.command.is_some_and(|c| seg[c].text != "env"))
        };
        let mut inline = false;
        for (at, w) in seg.iter().enumerate() {
            let assigns = shape.leading.contains(&at) || shape.arguments.contains(&at);
            let text = if assigns {
                w.text.split_once('=').map_or("", |(_, value)| value)
            } else {
                w.text.as_str()
            };
            if (moved || (inline && (assigns || w.quoted)))
                && (names_profile_read(text) || (w.quoted && runs_bare_cd(text, depth)))
            {
                return (true, moved);
            }
            if assigns && assigned_profile_variable(w) {
                if keeps(at) {
                    moved = true;
                } else {
                    inline = true;
                }
            }
        }
        let Some(command) = shape.command else {
            continue;
        };
        if (moved || inline) && is_bare_cd(&seg[command..]) {
            return (true, moved);
        }
        // `eval` runs its words in this shell, so what they move stays moved.
        if !seg[command].quoted && seg[command].text == "eval" && depth < MAX_PROFILE_TEXT_DEPTH {
            let text: Vec<&str> = seg[command + 1..].iter().map(|w| w.text.as_str()).collect();
            let (inner, _) = split_segments_noted(&text.join(" "));
            let (reads, after) = reads_moved_profile(&inner, moved, any_order, depth + 1);
            if reads {
                return (true, after);
            }
            moved = after;
        }
    }
    (false, moved)
}

/// `cd` that goes to `HOME`: no directory, whatever its options.
fn is_bare_cd(words: &[Word]) -> bool {
    words.first().is_some_and(|w| w.text == "cd")
        && !words
            .iter()
            .skip(1)
            .any(|w| !w.redirect && !matches!(w.text.as_str(), "-L" | "-P" | "-e" | "-@" | "--"))
}

/// Quoted text that, run as a line, reads through a moved variable by `cd` alone.
fn runs_bare_cd(text: &str, depth: u32) -> bool {
    if depth >= MAX_PROFILE_TEXT_DEPTH || !text.contains("cd") {
        return false;
    }
    let (inner, _) = split_segments_noted(text);
    reads_moved_profile(&inner, true, false, depth + 1).0
}

/// Text spelling a read of a profile variable, in any shell's way, or of `~`. Names
/// fold case, and quoting is not told apart: `echo '$HOME'` over-reads.
fn names_profile_read(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let ends_name = |rest: &str| {
        !rest
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let names = |prefix: &str, name: &str| {
        let spelled = format!("{prefix}{name}");
        lower
            .match_indices(&spelled)
            .any(|(at, _)| ends_name(&lower[at + spelled.len()..]))
    };
    let variable = PROFILE_VARIABLES.iter().any(|name| {
        ["$", "${", "${#", "${!", "env:"]
            .iter()
            .any(|prefix| names(prefix, name))
            || lower.contains(&format!("%{name}%"))
    });
    variable || names_tilde(&lower)
}

/// `~` where a shell expands it: at the start of a word, not `HEAD~1` or `~bob`.
fn names_tilde(text: &str) -> bool {
    let bytes = text.as_bytes();
    text.match_indices('~').any(|(at, _)| {
        let starts = at == 0
            || matches!(
                bytes[at - 1],
                b' ' | b'\t'
                    | b'\n'
                    | b':'
                    | b'='
                    | b'('
                    | b';'
                    | b'|'
                    | b'&'
                    | b'`'
                    | b'"'
                    | b'\''
            );
        let ends = bytes.get(at + 1).is_none_or(|b| {
            matches!(
                b,
                b'/' | b'\\'
                    | b' '
                    | b'\t'
                    | b'\n'
                    | b':'
                    | b')'
                    | b';'
                    | b'|'
                    | b'&'
                    | b'`'
                    | b'"'
                    | b'\''
            )
        });
        starts && ends
    })
}

/// `dir/<name>` for each name copied or moved into `dir`.
fn into_dir(dir: &str, names: &[String]) -> Vec<String> {
    let dir = dir.trim_end_matches('/');
    names.iter().map(|n| format!("{dir}/{n}")).collect()
}

/// Does the command text name `IFS` (as a whole word: `IFS=:`,
/// `export IFS`, `read -r IFS`, `${IFS:=x}`)?
fn mentions_ifs(raw: &str) -> bool {
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = raw.as_bytes();
    raw.match_indices("IFS").any(|(i, _)| {
        (i == 0 || !ident(bytes[i - 1])) && bytes.get(i + 3).is_none_or(|&b| !ident(b))
    })
}

/// Words with their plain-data substitutions replaced by the values they
/// print (`git commit -m "$(cat <<'EOF' … EOF)"`, `$(echo x)`), so they
/// are judged like any literal word; the inner commands are judged
/// separately. `targets_only`: only redirection targets (the words after a
/// redirection operator); otherwise every word but the command name.
/// - `"$(…)"` (the whole word one double-quoted substitution): one word.
/// - An unquoted `$(…)`: how it splits depends on `IFS`, which may be set
///   anywhere (or inherited), so two interpretations are returned, each a
///   whole word list of its own (positions matter: `cp x $(…)` writes its
///   last operand): `forms[0]` splits on blanks (each part globbed) and
///   `forms[1]`, present only when some value splits, keeps every value
///   one word. As a redirection target the split form takes the single
///   part, else keeps the word unresolved (bash refuses an ambiguous
///   redirect); the unsplit form takes the value.
/// - A word mixing substitutions with text: one word, when no value holds
///   blanks or glob characters (`literal_word`).
///
/// Also returned: whether an unquoted value was resolved at all (its
/// splitting then depends on IFS).
fn resolve_forms(words: &[Word], targets_only: bool) -> (Vec<Vec<Word>>, bool) {
    let mut split_form = Vec::with_capacity(words.len());
    let mut whole_form = Vec::with_capacity(words.len());
    let mut splits = false;
    let mut unquoted = false;
    for (i, w) in words.iter().enumerate() {
        let target = i > 0 && words[i - 1].redirect;
        let wanted = if targets_only { target } else { i > 0 };
        let value = (wanted && w.has_substitution && !w.redirect)
            .then(|| literal_word(&w.text))
            .flatten();
        let one = |text: &str, glob: bool| Word {
            text: text.to_string(),
            has_substitution: false,
            glob,
            ..w.clone()
        };
        let globby = |t: &str| t.contains(['*', '?', '[']);
        match value {
            Some((text, _)) if w.dq_substitution => {
                split_form.push(one(&text, false));
                whole_form.push(one(&text, false));
            }
            None => {
                split_form.push(w.clone());
                whole_form.push(w.clone());
            }
            Some((text, true)) => {
                unquoted = true;
                let parts: Vec<&str> = text
                    .split([' ', '\t', '\n'])
                    .filter(|p| !p.is_empty())
                    .collect();
                splits |= parts.len() != 1 || parts[0] != text;
                match parts.as_slice() {
                    [p] => split_form.push(one(p, globby(p))),
                    _ if target => split_form.push(w.clone()),
                    _ => split_form.extend(parts.iter().map(|p| one(p, globby(p)))),
                }
                if text.trim().is_empty() && !target {
                    // An empty value is no word at all.
                } else {
                    whole_form.push(one(&text, globby(&text)));
                }
            }
            Some((text, false)) => {
                unquoted = true;
                split_form.push(one(&text, w.glob));
                whole_form.push(one(&text, w.glob));
            }
        }
    }
    let mut forms = vec![split_form];
    if splits {
        forms.push(whole_form);
    }
    (forms, unquoted)
}

/// The redirections (operator and target) among the words peeled off in
/// front of a command, as they appear on a matching line.
fn peeled_redirections(prefix: &[Word]) -> String {
    let mut out: Vec<String> = Vec::new();
    for (i, w) in prefix.iter().enumerate() {
        if w.redirect {
            out.push(w.text.clone());
            if let Some(t) = prefix.get(i + 1) {
                out.extend(
                    build_argv(&[Word::default(), t.clone()])
                        .into_iter()
                        .skip(1),
                );
            }
        }
    }
    out.join(" ")
}

/// Variables whose change moves saiife's audit/integrity records, the
/// binary lookup or the settings the hooks live in: Gemini's two system
/// settings paths, Codex's `CODEX_HOME` and Claude Code's
/// `CLAUDE_CONFIG_DIR` (each moves where that agent reads its hook config).
const PROTECTED_ENV: &[&str] = &[
    "HOME",
    "XDG_DATA_HOME",
    "PATH",
    "GEMINI_CLI_SYSTEM_SETTINGS_PATH",
    "GEMINI_CLI_SYSTEM_DEFAULTS_PATH",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
];

/// Is every `$PATH` / `${PATH}` in the command line's words spelled
/// plainly in `raw` (unquoted or inside double quotes, no backslash, no
/// quote boundary inside it)? Word texts are dequoted, so `"$"PATH`,
/// `$\PATH`, `$""PATH` and `$'\x24'PATH` all read `$PATH` there; then the
/// words hold more references than `raw` spells plainly and every PATH
/// assignment counts as a change (fail closed). A plain reference that
/// does not reach a word (a comment, a here-document body) also fails
/// closed: the counts must be equal.
fn path_refs_are_plain(raw: &str, segments: &[Vec<Word>]) -> bool {
    let in_words: usize = segments
        .iter()
        .flatten()
        .map(|w| count_path_refs(w.text.as_bytes(), |_| true))
        .sum();
    if in_words == 0 {
        return true;
    }
    // Plain references in `raw`: outside single quotes, not escaped.
    let b = raw.as_bytes();
    let mut plain_at = vec![false; b.len()];
    let (mut sq, mut dq, mut i) = (false, false, 0);
    while i < b.len() {
        match b[i] {
            b'\\' if !sq => i += 1,
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'$' if !sq => plain_at[i] = true,
            _ => {}
        }
        i += 1;
    }
    count_path_refs(b, |i| plain_at[i]) == in_words
}

/// Count `$PATH` (not followed by a name character) and `${PATH}` in `b`
/// whose `$` sits at an index `ok` accepts.
fn count_path_refs(b: &[u8], ok: impl Fn(usize) -> bool) -> usize {
    let name = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    (0..b.len())
        .filter(|&i| {
            b[i] == b'$'
                && ok(i)
                && (b[i..].starts_with(b"${PATH}")
                    || (b[i..].starts_with(b"$PATH") && !b.get(i + 5).is_some_and(|&c| name(c))))
        })
        .count()
}

/// Is `$PATH` / `${PATH` written literally anywhere in `raw` (inside single
/// quotes or after a backslash)? Word texts are dequoted, so this is the
/// only place that can tell `PATH='$PATH':x` (a literal directory) from an
/// append.
fn has_literal_path_ref(raw: &str) -> bool {
    let b = raw.as_bytes();
    let is_ref = |i: usize| b[i..].starts_with(b"$PATH") || b[i..].starts_with(b"${PATH");
    let (mut sq, mut dq, mut i) = (false, false, 0);
    while i < b.len() {
        match b[i] {
            b'\\' if !sq => {
                if i + 1 < b.len() && is_ref(i + 1) {
                    return true;
                }
                i += 1;
            }
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'$' if sq && is_ref(i) => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Does this assignment (`NAME=value`, `NAME+=value`) change what saiife
/// relies on: a protected variable, with `PATH` exempt only when it appends
/// to the old value (an exact `$PATH` / `${PATH}` first, then `:` or the
/// end) and `$PATH` is not written literally anywhere in the command?
fn assignment_changes_environment(text: &str, literal_path: bool) -> bool {
    let Some((name, value)) = text.split_once('=') else {
        return false;
    };
    let (name, plus) = match name.strip_suffix('+') {
        Some(n) => (n, true),
        None => (name, false),
    };
    if !PROTECTED_ENV.contains(&name) {
        return false;
    }
    if name != "PATH" {
        return true;
    }
    if literal_path {
        return true;
    }
    if plus {
        return false;
    }
    let rest = value
        .strip_prefix("${PATH}")
        .or_else(|| value.strip_prefix("$PATH"));
    !matches!(rest, Some(r) if r.is_empty() || r.starts_with(':'))
}

/// The segment without the words in command position that may expand to
/// nothing, at every point the command could start: `$v env $w rm` is
/// `env rm`, with wrappers, assignments and redirections kept. Words with no
/// command after them stay: `env "$@"` is a wrapper around its list, not a
/// bare `env`. `None` when nothing was removed. One pass over the segment.
fn without_leading_empty_expansions(seg: &[Word]) -> Option<Vec<Word>> {
    if !seg
        .iter()
        .any(|w| w.text.is_empty() || w.text.starts_with(['$', '`']))
    {
        return None;
    }
    let mut kept: Vec<Word> = Vec::new();
    let mut last_command: Option<Option<usize>> = None;
    let mut removed = false;
    let mut cursor = seg;
    loop {
        let rest = effective_command(cursor);
        kept.extend_from_slice(&cursor[..cursor.len() - rest.len()]);
        let empty = rest.iter().take_while(|w| may_expand_to_nothing(w)).count();
        let after = seg.len() - (rest.len() - empty);
        let command_follows = empty > 0
            && last_command
                .get_or_insert_with(|| last_command_word(seg))
                .is_some_and(|last| last >= after);
        if !command_follows {
            kept.extend_from_slice(rest);
            break;
        }
        removed = true;
        cursor = &rest[empty..];
    }
    removed.then_some(kept)
}

/// The last of `words` that is more than an assignment, a redirection with
/// its target, or a word that may expand to nothing.
fn last_command_word(words: &[Word]) -> Option<usize> {
    let mut last = None;
    let mut i = 0;
    while let Some(w) = words.get(i) {
        #[cfg(test)]
        crate::work::add(1);
        if w.redirect {
            i += 2;
            continue;
        }
        if !w.assignment && !may_expand_to_nothing(w) {
            last = Some(i);
        }
        i += 1;
    }
    last
}

/// A segment of bare assignments (`PATH=/x`, no command): they stay set.
fn effective_is_empty_assignments(seg: &[Word], literal_path: bool) -> bool {
    seg.iter()
        .any(|w| w.assignment && assignment_changes_environment(&w.text, literal_path))
        && seg.iter().all(|w| w.assignment || w.redirect)
}

/// A builtin that sets or may set a protected variable of the running
/// shell, in any form: `export`/`readonly`/`declare`/`typeset`/`local`
/// assignments (quoted or not, with or without `-x`: HOME and PATH are
/// already exported), `printf -v`, `read`/`mapfile`/`readarray` naming one,
/// and `eval`/`source`/`.` (effect unknown, so assumed to change it). Over-
/// denying a pipe or subshell (`export HOME=x | claude`) is harmless.
fn changes_environment(argv: &[String], effective: &[Word], literal_path: bool) -> bool {
    let skip = argv.iter().take_while(|a| *a == "builtin").count();
    let (Some(cmd), Some(args)) = (argv.get(skip), effective.get(skip + 1..)) else {
        return false;
    };
    let protected = |t: &str| PROTECTED_ENV.contains(&t);
    match cmd.as_str() {
        "eval" | "source" | "." => true,
        // `-n` makes a nameref: a later `ref=x` assigns whatever it names.
        "declare" | "typeset" | "local"
            if args.iter().any(|w| {
                w.text.starts_with('-') && !w.text.starts_with("--") && w.text.contains('n')
            }) =>
        {
            true
        }
        "export" | "readonly" | "declare" | "typeset" | "local" => args
            .iter()
            .any(|w| assignment_changes_environment(&w.text, literal_path)),
        // `printf -v NAME` and the attached `printf -vNAME`.
        "printf" => args.iter().enumerate().any(|(i, w)| {
            let name = match w.text.strip_prefix("-v") {
                Some("") => args.get(i + 1).map_or("", |n| n.text.as_str()),
                Some(attached) => attached,
                None => return false,
            };
            protected(name.split('[').next().unwrap_or(""))
        }),
        "read" | "mapfile" | "readarray" => args
            .iter()
            .any(|w| !w.text.starts_with('-') && protected(&w.text)),
        _ => false,
    }
}

/// The whole segment's matching line for `whole_segment` rules: like
/// `build_argv`, but a leading `NAME=value` assignment is kept as written
/// (`PATH=/tmp/x claude` must not become `x claude`).
fn segment_line(seg: &[Word]) -> String {
    let mut argv = build_argv(seg);
    if let (Some(first), Some(word)) = (argv.first_mut(), seg.first()) {
        if is_env_assignment(&word.text) {
            first.clone_from(&word.text);
        }
    }
    argv.join(" ")
}

/// A trigger literal is treated as naming a guarded *command* only if it
/// looks like a bare command-name token (alphanumeric plus `_`/`-`/`.`) —
/// this excludes structural triggers like `/dev/` while including real
/// program names (`rm`, `git`, `gcloud`, `gsutil`, `dropdb`, …) and SQL
/// keyword triggers (`drop`, `truncate`, `delete`) that would only ever
/// equal argv[0] in a contrived case, harmlessly.
fn looks_like_bare_command_name(trigger: &str) -> bool {
    !trigger.is_empty()
        && trigger
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// The shell state a command line starts in; a nested evaluation inherits
/// it, and its segments update their own copy.
#[derive(Clone)]
struct ShellState {
    /// The directories the shell may be in. A `cd` adds its target for the
    /// segments after it but never drops the old ones: it may fail
    /// (`cd /nonexistent; …`), run in a subshell (`(cd x); …`) or go
    /// somewhere unknown (`cd $(…)`).
    cwds: Vec<PathBuf>,
    /// The first this many of `cwds` come from plain `cd`s, up to `MAX_CWDS`; the
    /// rest, up to `MAX_CWDS` more, from a `cd` behind a reserved word or a word that
    /// may vanish, or from one of those directories. Without the split, padding of
    /// `! cd x` would use up the slots of a real `cd ~/.ssh`.
    plain_cwds: usize,
    /// A `cd` went somewhere `cwds` does not hold (`cd $(…)`, `cd -`, an
    /// unresolvable target, or past `MAX_CWDS`).
    cwd_unknown: bool,
    /// Where the regex rules of `CD_RESOLVED_PACK` place relative
    /// operands: the directory an earlier `cd` on the line moved to.
    rule_cwd: RuleCwd,
    /// An earlier segment changed PATH, HOME or XDG_DATA_HOME for the rest
    /// of the command line (and for nested evaluations).
    env_changed: bool,
    /// The line names IFS somewhere: values are still judged, the
    /// unresolved words too.
    ifs_named: bool,
    /// `> $null` discards under a POSIX reading (`null_device_words`).
    null_redirect_discards: bool,
}

impl ShellState {
    /// What each path judged, and each copy of this state, costs on top of the
    /// words themselves, in bytes.
    fn weight(&self) -> usize {
        let dirs: usize = self.cwds.iter().map(|c| c.as_os_str().len()).sum();
        dirs + self.rule_cwd.weight()
    }
}

/// The outcome of a nested evaluation (`Engine::recurse`).
enum Nested {
    /// Denied; `via_inline` names the nested text.
    Deny(Decision),
    /// Not judged (past the depth cap, or the nested line was not fully
    /// judged): a recorded fail-open unless something else denies.
    Unjudged(String),
    /// The budget ran out.
    TimedOut,
    /// Allowed, with the nested trace (no match, or an allow rule).
    Clean(AllowTrace),
}

/// What the command-position phase tells the segment loop.
enum Flow {
    /// Judge the rest of this segment.
    Proceed,
    /// Nothing more to judge in this segment.
    NextSegment,
    /// End the evaluation with this decision.
    Done(Decision),
}

/// Fixed for one evaluation of one command line.
struct Ctx<'a> {
    start: Instant,
    depth: u32,
    /// The line holds a path reference spelled out literally (see
    /// `has_literal_path_ref`, `path_refs_are_plain`).
    literal_path: bool,
    /// The line is this one command and is no nested line: no pipe, group or
    /// outer shell can be giving it a stdin.
    only_command: bool,
    clock: &'a Clock,
    /// Which reader read this line.
    dialect: Dialect,
}

/// One evaluation's clock, shared by its nested lines.
struct Clock {
    start: Instant,
    /// Time spent compiling operand patterns so far
    /// (`pack::MAX_PATTERN_COMPILE`).
    spent: Cell<Duration>,
    /// The budget ran out: this clock is the last look's, and its work is counted
    /// rather than timed (`Engine::out_of_budget`).
    last_look: bool,
    /// What the last look may still spend on nested lines, in bytes.
    lines_left: Cell<usize>,
    /// What it may still spend on paths, in bytes and in system calls
    /// (`canon::FS_CALL_COST`, paid by `canon` itself). Apart from `lines_left`, so
    /// paths cannot use up what nested lines need.
    paths_left: Rc<Cell<usize>>,
    /// Lines evaluated and segment views judged, so a test can bound the
    /// work without reading a clock.
    #[cfg(test)]
    runs: Cell<usize>,
}

impl Clock {
    /// May the last look judge a nested line of this cost? Always before
    /// the budget runs out: that part has its clock.
    fn afford_line(&self, cost: usize) -> bool {
        !self.last_look || spend(&self.lines_left, CHEAP_LINE_COST + cost)
    }

    /// May the last look spend `cost` on paths? As `afford_line`.
    fn afford_paths(&self, cost: usize) -> bool {
        !self.last_look || spend(&self.paths_left, cost)
    }
}

/// Takes `cost` from `left` if it is all there.
fn spend(left: &Cell<usize>, cost: usize) -> bool {
    match left.get().checked_sub(cost) {
        Some(rest) => {
            left.set(rest);
            true
        }
        None => false,
    }
}

/// What a nested line costs the last look before its bytes: setting it up
/// takes as long as judging about this many bytes.
const CHEAP_LINE_COST: usize = 1024;

/// What judging one word of a line costs the last look, measured the same way:
/// about 1.5 µs, against about a second for `MAX_CHEAP_WORK`.
const CHEAP_WORD_COST: usize = 256;

/// What judging one path in one directory costs the last look before its
/// bytes, measured the same way.
const CHEAP_PATH_COST: usize = 256;

/// How much the last look may spend on each of what multiplies its work, once the
/// budget has run out: nested lines, and paths and their system calls. Each comes to
/// about a second in an optimized build, measured on the worst shapes a 256 KiB line
/// can have. Past it the line is denied (`too_costly`). That is 16 Ki system calls or
/// about 200,000 short paths in one directory, and an ordinary line can get there
/// when it is a whole script or a long brace expansion: a build script of
/// `cd pkgN; cp a b c d; cd ../..` 1600 times (92 KB) does, through its directories.
const MAX_CHEAP_WORK: usize = 64 * 1024 * 1024;

const PATHS_PAST_LIMIT: &str = "paths in too many long directories";

fn max_cheap_work() -> usize {
    #[cfg(test)]
    if let Some(limit) = CHEAP_WORK_LIMIT.with(Cell::get) {
        return limit;
    }
    MAX_CHEAP_WORK
}

#[cfg(test)]
thread_local! {
    /// A lower `MAX_CHEAP_WORK` for this thread.
    static CHEAP_WORK_LIMIT: Cell<Option<usize>> = const { Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// `Clock::runs` of this thread's last `evaluate`.
    static LAST_RUNS: Cell<usize> = const { Cell::new(0) };
    /// Directories this thread's `cd`s have resolved against.
    static CD_RESOLVES: Cell<usize> = const { Cell::new(0) };
}

/// What the segments of one command line found short of a deny.
#[derive(Default)]
struct Findings {
    /// The trace of the latest allow (an allow rule, or a nested no-match).
    allow_trace: Option<AllowTrace>,
    /// Something could not be judged (a glob too large to expand): the
    /// outcome is a recorded fail-open unless something else denies. The
    /// first reason is kept.
    unjudged: Option<String>,
}

impl Findings {
    fn unjudged(&mut self, reason: impl Into<String>) {
        if self.unjudged.is_none() {
            self.unjudged = Some(reason.into());
        }
    }

    /// Record a nested evaluation; `Some` when it ends this one. An
    /// unjudgeable part makes the whole command unjudgeable (unless
    /// something denies), otherwise the latest trace wins.
    fn nested(&mut self, nested: Nested) -> Option<Decision> {
        match nested {
            Nested::Deny(d) => Some(d),
            Nested::TimedOut => Some(timed_out()),
            Nested::Unjudged(reason) => {
                self.unjudged(reason);
                None
            }
            Nested::Clean(trace) => {
                self.allow_trace = Some(trace);
                None
            }
        }
    }

    /// Note the path rules' verdict on a segment's operands; `Some` when it
    /// ends the evaluation.
    fn operands(&mut self, judged: Option<Decision>) -> Option<Decision> {
        match judged? {
            Decision::Allow {
                trace: AllowTrace::Unjudgeable { reason },
            } => {
                self.unjudged(reason);
                None
            }
            d => Some(d),
        }
    }

    fn finish(self) -> Decision {
        if let Some(reason) = self.unjudged {
            return Decision::Allow {
                trace: AllowTrace::Unjudgeable { reason },
            };
        }
        Decision::Allow {
            trace: self.allow_trace.unwrap_or(AllowTrace::NoMatch),
        }
    }
}

fn timed_out() -> Decision {
    Decision::Allow {
        trace: AllowTrace::FailedOpenTimeout,
    }
}

/// The deny for a line that costs more to judge than a line should. No rule decided
/// it, and the agent can do something about it.
fn too_costly(why: &str) -> Decision {
    Decision::Deny {
        pack: SUBSTITUTION_GUARD_PACK.to_string(),
        pattern: "line-too-costly-to-judge".to_string(),
        reason: format!(
            "this line is too costly to judge ({why}), so it fails safe and blocks; \
             split it into smaller commands"
        ),
        via_inline: None,
    }
}

fn is_timed_out(d: &Decision) -> bool {
    matches!(
        d,
        Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout
        }
    )
}

/// A segment with its leading words peeled off and its arguments resolved,
/// as the rule and path-rule phases judge it.
struct SegmentView<'a> {
    seg: &'a [Word],
    /// The effective command before its arguments were resolved.
    unresolved: &'a [Word],
    /// The effective command, plain-data substitutions replaced by their
    /// values.
    resolved: Vec<Word>,
    argv: Vec<String>,
    /// The segment with its redirection targets resolved.
    seg_ops: Vec<Word>,
    /// Other interpretations (the unsplit values): (effective command,
    /// segment) pairs judged as commands of their own.
    alternatives: Vec<(Vec<Word>, Vec<Word>)>,
    /// Files a peeled-off wrapper reads itself (`xargs -a FILE`).
    reads: Vec<Operand>,
    /// The environment of this segment's own command changed.
    env_changed: bool,
    /// The peeled-off redirections.
    peeled: String,
    /// What the rules match: argv plus the peeled-off redirections.
    matching_line: String,
    /// The arguments without redirections (`2>/dev/null`, `2>&1`): what
    /// option and operand tests read.
    rule_args: Vec<String>,
    /// The command and `rule_args` (`no_redirections` rules).
    args_line: String,
    /// The whole segment's line, when it differs.
    whole: Option<String>,
    /// The names of the peeled-off wrappers, joined with spaces.
    wrappers: String,
}

impl<'a> SegmentView<'a> {
    fn new(
        seg: &'a [Word],
        effective: &'a [Word],
        state: &ShellState,
        cx: &Ctx,
        vars: &PathVars,
        found: &mut Findings,
    ) -> Self {
        let literal_path = cx.literal_path;
        // Leading assignments and redirections (`LANG=C sort f`,
        // `2>/dev/null cat f`) are not the command either.
        let effective = effective_command(effective);
        // An argument that is one substitution printing plain data
        // (`git commit -m "$(cat <<'EOF' … EOF)"`, `$(echo x)`) is
        // judged by its value, like any literal argument; its inner
        // command was already judged by
        // `embedded_substitutions_phase`.
        // Words in front of the command (wrappers, assignments,
        // redirections), counted before the arguments are resolved.
        let prefix_len = seg.len() - effective.len();
        // `resolve_forms` reads a word's `$(…)` as POSIX: a reader's stays
        // unknown.
        let posix = cx.dialect == Dialect::Posix;
        let (mut forms, args_unquoted) = if posix {
            resolve_forms(effective, false)
        } else {
            (vec![effective.to_vec()], false)
        };
        // Redirection targets are resolved the same way.
        let (mut target_forms, targets_unquoted) = if posix {
            resolve_forms(seg, true)
        } else {
            (vec![seg.to_vec()], false)
        };
        // A line naming IFS may split a value anywhere: what was judged
        // is a guess, so a non-deny outcome is recorded.
        if state.ifs_named && (args_unquoted || targets_unquoted) {
            found.unjudged("IFS is set on this line: substitution values may split differently");
        }
        // Other interpretations (the unsplit values) are judged as
        // commands of their own after this one.
        let alternatives: Vec<(Vec<Word>, Vec<Word>)> = {
            let n = forms.len().max(target_forms.len());
            (1..n)
                .map(|i| {
                    (
                        forms.get(i).unwrap_or(&forms[0]).clone(),
                        target_forms.get(i).unwrap_or(&target_forms[0]).clone(),
                    )
                })
                .collect()
        };
        let resolved = forms.swap_remove(0);
        let seg_ops = target_forms.swap_remove(0);
        let reads: Vec<Operand> = wrapper_reads(&winpath::path_words(seg, vars))
            .into_iter()
            .map(|(path, glob)| Operand {
                path,
                access: Access::Read,
                glob,
                dots: false,
                into: Vec::new(),
            })
            .collect();
        // Assignments in front of this segment's own command
        // (`HOME=$(mktemp -d -p /tmp x) claude`, `env CODEX_HOME=x codex`)
        // change its environment too.
        let env_changed = state.env_changed
            || seg[..prefix_len].iter().any(|w| {
                !w.redirect
                    && (w.assignment || is_env_assignment(&w.text))
                    && assignment_changes_environment(&w.text, literal_path)
            });
        // The peeled-off redirections stay visible to the regex rules
        // (`>/dev/sda cat x` is judged like `cat x > /dev/sda`).
        let peeled = peeled_redirections(&seg[..prefix_len]);
        let argv = build_argv(&resolved);
        let mut matching_line = argv.join(" ");
        if !peeled.is_empty() {
            matching_line.push(' ');
            matching_line.push_str(&peeled);
        }
        // The whole segment's line differs only when a wrapper was
        // peeled off or the segment starts with an assignment.
        let whole = (prefix_len > 0 || is_env_assignment(&seg[0].text)).then(|| segment_line(seg));
        let rule_args = without_redirections(&resolved, &argv);
        let args_line = args_line(&argv, &rule_args);
        SegmentView {
            seg,
            unresolved: effective,
            resolved,
            argv,
            seg_ops,
            alternatives,
            reads,
            env_changed,
            peeled,
            matching_line,
            rule_args,
            args_line,
            whole,
            wrappers: if prefix_len > 0 {
                peeled_wrappers(seg).join(" ")
            } else {
                String::new()
            },
        }
    }

    /// The line `whole_segment` rules match.
    fn segment_line(&self) -> &str {
        self.whole.as_deref().unwrap_or(&self.matching_line)
    }
}

/// `argv[1..]` without its redirections: each redirection operator word
/// (`2>`, `>&`, `<`) and the target word after it. `words` and `argv` are
/// the same command, word for word.
fn without_redirections(words: &[Word], argv: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        if words.get(i).is_some_and(|w| w.redirect) {
            i += 2;
            continue;
        }
        out.push(argv[i].clone());
        i += 1;
    }
    out
}

/// The command name and its arguments without redirections, joined with
/// single spaces.
fn args_line(argv: &[String], args: &[String]) -> String {
    std::iter::once(argv.first().map(String::as_str).unwrap_or(""))
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The lines a segment's rules match: the effective command's
/// (`matching`), the whole segment's (`whole_segment` rules) and the peeled
/// wrappers' names (`peeled_wrappers` rules); and the effective command's
/// operands, for rules with `operand_match`.
#[derive(Clone, Copy)]
struct Lines<'a> {
    matching: &'a str,
    /// The effective command without its redirections
    /// (`no_redirections` rules).
    args: &'a str,
    segment: &'a str,
    wrappers: &'a str,
    operands: &'a [String],
}

enum JudgeOutcome {
    Decided(Decision),
    Clean,
    TimedOut,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::load_pack_str;

    /// Generous budget so a loaded runner cannot turn an exact trace into a
    /// latency fail-open; `budget_overrun_fails_open_visibly` and
    /// `evaluate_path_fails_open_over_budget` inject a zero budget instead.
    const TEST_BUDGET: Duration = Duration::from_secs(5);

    fn test_engine() -> Engine {
        let toml = r#"
[pack]
id = "test.git"
triggers = ["git"]

[[allow]]
pattern = '^git\s+reset\s+--hard\s+HEAD~\d+\b'
reason = "soft-ish reset by N commits is intentional"

[[deny]]
pattern = '^git\s+reset\s+--hard\b'
reason = "discards uncommitted work"

[[deny]]
pattern = '^git\s+clean\s+-[a-z]*f'
reason = "deletes untracked files"
"#;
        let mut w = Vec::new();
        let pack = load_pack_str("<t>", toml, &mut w).unwrap();
        Engine::new(vec![pack]).with_budget(TEST_BUDGET)
    }

    #[test]
    fn deny_reports_pack_pattern_reason() {
        let d = test_engine().evaluate("git reset --hard");
        match d {
            Decision::Deny {
                pack,
                reason,
                via_inline,
                ..
            } => {
                assert_eq!(pack, "test.git");
                assert!(reason.contains("uncommitted"));
                assert!(via_inline.is_none());
            }
            _ => panic!("expected deny, got {d:?}"),
        }
    }

    #[test]
    fn allow_in_one_pack_does_not_hide_another_packs_deny() {
        let a = "[pack]\nid = \"test.a\"\n[[allow]]\npattern = '^foo'\n";
        let b = "[pack]\nid = \"test.b\"\n[[deny]]\npattern = '^foo bar'\nreason = \"b says no\"\n";
        let mut w = Vec::new();
        let packs = vec![
            load_pack_str("<a>", a, &mut w).unwrap(),
            load_pack_str("<b>", b, &mut w).unwrap(),
        ];
        let e = Engine::new(packs).with_budget(TEST_BUDGET);
        match e.evaluate("foo bar") {
            Decision::Deny { pack, .. } => assert_eq!(pack, "test.b"),
            d => panic!("expected deny, got {d:?}"),
        }
        assert!(matches!(
            e.evaluate("foo baz"),
            Decision::Allow {
                trace: AllowTrace::AllowRule { .. }
            }
        ));
    }

    #[test]
    fn own_pack_allow_still_allows() {
        let (packs, _) = crate::builtins::builtin_packs();
        let e = Engine::new(crate::profile::select_active(packs, &[])).with_budget(TEST_BUDGET);
        match e.evaluate("git reset --hard HEAD~1") {
            Decision::Allow {
                trace: AllowTrace::AllowRule { pack, .. },
            } => assert_eq!(pack, "core.git"),
            d => panic!("expected core.git allow rule, got {d:?}"),
        }
        assert!(!e.evaluate("git push --force-with-lease").is_deny());
    }

    #[test]
    fn allow_rule_beats_deny() {
        // Matches the allow carve-out AND the broad deny; allow must win.
        let d = test_engine().evaluate("git reset --hard HEAD~2");
        assert!(!d.is_deny());
        assert!(matches!(
            d,
            Decision::Allow {
                trace: AllowTrace::AllowRule { .. }
            }
        ));
    }

    #[test]
    fn safe_command_allowed() {
        let d = test_engine().evaluate("git status");
        assert_eq!(
            d,
            Decision::Allow {
                trace: AllowTrace::NoMatch
            }
        );
    }

    #[test]
    fn prefilter_skips_unrelated_command() {
        let d = test_engine().evaluate("ls -la");
        assert_eq!(
            d,
            Decision::Allow {
                trace: AllowTrace::NoMatch
            }
        );
    }

    #[test]
    fn first_matching_deny_wins() {
        let d = test_engine().evaluate("git clean -fd");
        match d {
            Decision::Deny { reason, .. } => assert!(reason.contains("untracked")),
            _ => panic!("expected deny"),
        }
    }

    #[test]
    fn denies_a_chained_command_joined_with_and_and() {
        let d = test_engine().evaluate("echo hi && git reset --hard");
        assert!(d.is_deny(), "expected DENY, got {d:?}");
    }

    #[test]
    fn denies_a_chained_command_joined_with_semicolon() {
        let d = test_engine().evaluate("true; git clean -fd");
        assert!(d.is_deny(), "expected DENY, got {d:?}");
    }

    #[test]
    fn denies_a_chained_command_joined_with_pipe() {
        let d = test_engine().evaluate("echo hi | git reset --hard");
        assert!(d.is_deny(), "expected DENY, got {d:?}");
    }

    #[test]
    fn allows_a_benign_chained_command() {
        let d = test_engine().evaluate("cd foo && ls");
        assert!(!d.is_deny(), "expected ALLOW, got {d:?}");
    }

    #[test]
    fn allow_rule_in_one_segment_does_not_block_the_chain() {
        // The first segment hits the allow carve-out; the second is entirely
        // unrelated to the pack. Overall must still allow.
        let d = test_engine().evaluate("git reset --hard HEAD~2 && git status");
        assert!(!d.is_deny(), "expected ALLOW, got {d:?}");
    }

    #[test]
    fn inline_payload_is_judged() {
        let d = test_engine().evaluate("bash -c 'git reset --hard'");
        match d {
            Decision::Deny {
                via_inline, reason, ..
            } => {
                assert_eq!(via_inline.as_deref(), Some("git reset --hard"));
                assert!(reason.contains("uncommitted"));
            }
            _ => panic!("expected inline deny, got {d:?}"),
        }
    }

    #[test]
    fn case_folded_command_name_is_still_caught() {
        let d = test_engine().evaluate("Git reset --hard");
        assert!(d.is_deny(), "expected DENY, got {d:?}");
    }

    const PATH_PACK: &str = r#"
[pack]
id = "test.paths"

[[deny_path]]
glob = "**/.env"
access = "read"
reason = "secret file"

[[deny_path]]
glob = "**/.env.*"
access = "read"
reason = "secret file"

[[allow_path]]
glob = "**/.env.example"
access = "read"
reason = "template, no secrets"

[[deny_path]]
glob = "~/.ssh/id_*"
access = "any"
reason = "private key"

[[deny_path]]
glob = "$PROJECT/.locked/**"
access = "write"
reason = "locked"

[[deny_path]]
glob = "**/.claude/settings.json"
access = "write"
reason = "agent hook config"

[[deny_path]]
glob = "**/.claude"
access = "write"
reason = "agent folder"

[[deny_path]]
glob = "**/conf/secret.json"
access = "write"
reason = "test landing"

[[deny_path]]
glob = "**/.saiife/**"
access = "write"
reason = "saiife config"
"#;

    fn path_engine(vars: PathVars) -> Engine {
        let mut w = Vec::new();
        let pack = load_pack_str("<t>", PATH_PACK, &mut w).unwrap();
        assert!(w.is_empty(), "{w:?}");
        Engine::new(vec![pack])
            .with_budget(TEST_BUDGET)
            .with_paths(vars)
    }

    fn canonical_tmp() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = std::fs::canonicalize(d.path()).unwrap();
        (d, p)
    }

    /// The cmd reading under `Strictest`: a timeout or a note stays on the
    /// record and does not deny; a clean one adds nothing; a rule's deny denies.
    #[test]
    fn the_cmd_reading_is_never_dropped() {
        let allow = |trace| Decision::Allow { trace };
        let clean = || allow(AllowTrace::NoMatch);
        let timeout = || allow(AllowTrace::FailedOpenTimeout);
        let note = || {
            allow(AllowTrace::Unjudgeable {
                reason: "a note".to_string(),
            })
        };
        let deny = |pattern: &str| Decision::Deny {
            pack: "p".to_string(),
            pattern: pattern.to_string(),
            reason: "r".to_string(),
            via_inline: None,
        };
        assert_eq!(with_cmd_reading(clean(), timeout()), timeout());
        assert_eq!(with_cmd_reading(clean(), note()), note());
        assert_eq!(with_cmd_reading(clean(), clean()), clean());
        assert_eq!(with_cmd_reading(note(), timeout()), timeout());
        assert_eq!(with_cmd_reading(clean(), deny("rule")), deny("rule"));
        assert!(matches!(
            with_cmd_reading(clean(), deny(GUARDED_SUBSTITUTION_PATTERN)),
            Decision::Allow {
                trace: AllowTrace::Unjudgeable { .. }
            }
        ));
        // Another reading's deny stands.
        assert_eq!(with_cmd_reading(deny("a"), timeout()), deny("a"));
    }

    #[test]
    fn evaluate_path_denies_and_carves_out() {
        let (_d, root) = canonical_tmp();
        let app = root.join("app");
        std::fs::create_dir_all(&app).unwrap();
        let e = path_engine(
            PathVars::new()
                .with_cwd(&app)
                .with_var("HOME", root.join("home"))
                .with_var("PROJECT", &app),
        );
        let d = e.evaluate_path(Access::Read, ".env");
        match &d {
            Decision::Deny {
                pack,
                pattern,
                reason,
                ..
            } => {
                assert_eq!(pack, "test.paths");
                assert_eq!(pattern, "**/.env");
                assert!(reason.contains("secret file"), "{reason}");
                let form = lexical_form(".env", Some(&app), &PathVars::new()).unwrap();
                assert!(reason.contains(&form.display().to_string()), "{reason}");
            }
            other => panic!("expected deny, got {other:?}"),
        }
        assert!(e.evaluate_path(Access::Read, ".env.local").is_deny());
        assert!(matches!(
            e.evaluate_path(Access::Read, ".env.example"),
            Decision::Allow {
                trace: AllowTrace::AllowRule { .. }
            }
        ));
        // Access matters: `.env` rules are read-only; the key rule is "any".
        assert!(!e.evaluate_path(Access::Write, ".env").is_deny());
        assert!(e.evaluate_path(Access::Write, "~/.ssh/id_rsa").is_deny());
        assert!(e.evaluate_path(Access::Write, ".locked/x").is_deny());
        assert!(!e.evaluate_path(Access::Read, ".locked/x").is_deny());
        assert_eq!(
            e.evaluate_path(Access::Read, "src/main.rs"),
            Decision::Allow {
                trace: AllowTrace::NoMatch
            }
        );
    }

    #[test]
    fn evaluate_path_without_cwd_or_home() {
        let e = path_engine(PathVars::new());
        assert!(matches!(
            e.evaluate_path(Access::Read, ".env"),
            Decision::Allow {
                trace: AllowTrace::Unjudgeable { .. }
            }
        ));
        // Rules without variables still apply to absolute paths; rules with
        // an unbound variable do not.
        let (env, key) = if cfg!(windows) {
            (r"C:\srv\app\.env", r"C:\Users\u\.ssh\id_rsa")
        } else {
            ("/srv/app/.env", "/home/u/.ssh/id_rsa")
        };
        assert!(e.evaluate_path(Access::Read, env).is_deny());
        assert!(!e.evaluate_path(Access::Read, key).is_deny());
    }

    #[test]
    fn evaluate_path_fails_open_over_budget() {
        let (_d, root) = canonical_tmp();
        let e = path_engine(PathVars::new().with_cwd(&root)).with_budget(Duration::ZERO);
        assert_eq!(
            e.evaluate_path(Access::Read, ".env"),
            Decision::Allow {
                trace: AllowTrace::FailedOpenTimeout
            }
        );
    }

    #[test]
    fn allow_path_only_exempts_from_its_own_pack() {
        let other = r#"
[pack]
id = "test.other"
[[deny_path]]
glob = "**/.env.example"
access = "read"
reason = "other pack says no"
"#;
        let mut w = Vec::new();
        let packs = vec![
            load_pack_str("<t>", PATH_PACK, &mut w).unwrap(),
            load_pack_str("<o>", other, &mut w).unwrap(),
        ];
        let e = Engine::new(packs)
            .with_budget(TEST_BUDGET)
            .with_paths(PathVars::new().with_cwd("/p"));
        match e.evaluate_path(Access::Read, ".env.example") {
            Decision::Deny { pack, .. } => assert_eq!(pack, "test.other"),
            d => panic!("expected deny, got {d:?}"),
        }
    }

    fn shell_path_engine(root: &Path) -> Engine {
        path_engine(
            PathVars::new()
                .with_cwd(root.join("app"))
                .with_var("HOME", root.join("home"))
                .with_var("PROJECT", root.join("app")),
        )
    }

    #[test]
    fn shell_commands_are_judged_by_path_rules() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app/src")).unwrap();
        std::fs::create_dir_all(root.join("home/.ssh")).unwrap();
        let e = shell_path_engine(&root);
        for cmd in [
            "cat .env",
            "cat ./src/../.env",
            "sudo cat .env",
            "bash -c 'head -5 .env'",
            "echo hi | cat - .env",
            "cat $HOME/.ssh/id_rsa",
            "cp ~/.ssh/id_ed25519 /tmp/k",
            "cd src && cat ../.env",
            "cd ~/.ssh; cat id_rsa",
            "python x.py < .env",
            "echo x > .locked/state",
            // A substitution printing literal data is judged by its value.
            "cat $(echo .env)",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
        for cmd in [
            "cat .env.example",
            "cat README.md",
            "grep -r TODO src",
            "cd src && cat .env.example",
            "cat .locked/state",
            "echo x > notes.txt",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
        // A path no reader can see: unjudged on POSIX, a deny under Windows
        // style (W5, ruling on nested non-POSIX Unjudged).
        assert_eq!(
            e.evaluate("cat $(ls -t | head -1)").is_deny(),
            cfg!(windows)
        );
    }

    #[cfg(unix)]
    #[test]
    fn shell_path_through_a_symlink_is_caught() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        std::fs::write(root.join("app/.env"), "K=v").unwrap();
        std::os::unix::fs::symlink(root.join("app/.env"), root.join("app/notes.txt")).unwrap();
        let e = shell_path_engine(&root);
        assert!(e.evaluate("cat notes.txt").is_deny());
        assert!(e.evaluate_path(Access::Read, "notes.txt").is_deny());
    }

    #[test]
    fn unspaced_redirections_are_judged() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        let e = shell_path_engine(&root);
        for cmd in [
            "echo x>.claude/settings.json",
            "echo x>>.saiife/config.toml",
            "cat .env>/tmp/x",
            "cat<.env",
            "python x.py<.env",
            "echo x &>.claude/settings.json",
            "echo x 2>.claude/settings.json",
            "echo x >&.claude/settings.json",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
        for cmd in [
            r#"grep ">" .claude/settings.json"#,
            "cat .claude/settings.json",
            "make 2>&1 | tee build.log",
            "echo x >&2",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
    }

    #[test]
    fn glob_operands_are_expanded() {
        let (_d, root) = canonical_tmp();
        let app = root.join("app");
        std::fs::create_dir_all(app.join(".claude")).unwrap();
        std::fs::create_dir_all(root.join("home/.ssh")).unwrap();
        std::fs::write(app.join(".env"), "K=v").unwrap();
        std::fs::write(app.join("README.md"), "").unwrap();
        std::fs::write(app.join(".claude/settings.json"), "{}").unwrap();
        std::fs::write(root.join("home/.ssh/id_rsa"), "").unwrap();
        let e = shell_path_engine(&root);
        for cmd in [
            "cat .env*",
            "cat ~/.ssh/*",
            "rm .claude/settings.*",
            "cat .e?v",
            "cat .[e]nv",
            "sed -i s/a/b/ .claude/*.json",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
        for cmd in ["cat *.md", "grep TODO *", "cat '.env*'", "cat nothing*"] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
    }

    #[test]
    fn operand_braces_are_expanded_once() {
        // The lexer already brace-expanded unquoted braces; braces left in
        // an operand were quoted and are literal, so `"{.e,x}{n,y}v"*`
        // looks for names starting with `{.e,x}{n,y}v`, not for `.env*`.
        let (_d, root) = canonical_tmp();
        let app = root.join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join(".env"), "K=v").unwrap();
        let e = shell_path_engine(&root);
        assert!(e.evaluate("cat {.e,x}{n,y}v*").is_deny());
        for cmd in ["cat \"{.e,x}{n,y}v\"*", "cp README.md \"{.e,x}{n,y}\"*"] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
    }

    #[test]
    fn a_glob_too_large_is_unjudgeable_unless_something_denies() {
        let (_d, root) = canonical_tmp();
        let big = root.join("app/big");
        std::fs::create_dir_all(&big).unwrap();
        for i in 0..(crate::canon::GLOB_SCAN_LIMIT + 1) {
            std::fs::write(big.join(format!("f{i}")), "").unwrap();
        }
        let e = shell_path_engine(&root);
        assert_eq!(
            e.evaluate("cat big/*"),
            Decision::Allow {
                trace: AllowTrace::Unjudgeable {
                    reason: "glob too large to judge".to_string()
                }
            }
        );
        assert!(e.evaluate("cat big/*; cat .env").is_deny());
        assert!(e.evaluate("cat big/* .env").is_deny());
    }

    #[test]
    fn copy_into_a_directory_judges_the_landing_path() {
        let (_d, root) = canonical_tmp();
        let app = root.join("app");
        std::fs::create_dir_all(app.join(".claude")).unwrap();
        std::fs::create_dir_all(app.join("x")).unwrap();
        let e = shell_path_engine(&root);
        for cmd in [
            "cp review.md .claude/",
            "cp review.md .claude",
            "mv notes.md .claude/",
            "cp -t .claude review.md",
            "cp -r docs .claude/",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
        for cmd in [
            "cp x/settings.json .claude/",
            "cp settings.json .claude",
            "mv settings.json .claude/",
            "cp -t .claude settings.json",
            "git mv settings.json .claude/",
            "cp review.md new/.claude",
            "rm -rf .claude/",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
    }

    #[test]
    fn a_cd_that_may_have_failed_keeps_the_old_directory() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app/sub")).unwrap();
        let e = shell_path_engine(&root);
        for cmd in [
            "cd /nonexistent; echo x > .locked/state",
            "cd sub || true; echo x > .locked/state",
            "(cd sub); echo x > .locked/state",
            "cd $(echo sub); echo x > .locked/state",
            "cd sub; cd /tmp; echo x > .locked/state",
            "cd sub && echo x > ../.locked/state",
            "pushd /tmp; echo x > .locked/state",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
        for cmd in ["cd sub && echo x > notes.txt", "cd sub && cat .env.example"] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
    }

    #[test]
    fn many_operands_with_default_packs_deny_or_fail_open_visibly() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        let (mut packs, w) = crate::builtins::builtin_packs();
        assert!(w.is_empty());
        let mut w = Vec::new();
        packs.push(load_pack_str("<t>", PATH_PACK, &mut w).unwrap());
        let e = Engine::new(packs).with_paths(
            PathVars::new()
                .with_cwd(root.join("app"))
                .with_var("HOME", root.join("home"))
                .with_var("PROJECT", root.join("app")),
        );
        let cmd = |n: usize| {
            let files: Vec<String> = (0..n).map(|i| format!("src/deep/dir/f{i}.rs")).collect();
            format!("cat {} .env", files.join(" "))
        };
        // 5000 operands: a deny, or a recorded budget fail-open under a
        // loaded debug run, never a silent allow or a hang.
        let t = Instant::now();
        let d = e.evaluate(&cmd(5000));
        let took = t.elapsed();
        eprintln!("5000 operands: {took:?} -> {d:?}");
        assert!(
            d.is_deny()
                || d == Decision::Allow {
                    trace: AllowTrace::FailedOpenTimeout
                },
            "{d:?}"
        );
        assert!(took < Duration::from_secs(2), "{took:?}");
        // With time to finish, the flood is denied (not merely skipped).
        let e = e.with_budget(Duration::from_secs(10));
        assert!(e.evaluate(&cmd(5000)).is_deny());
    }

    #[test]
    fn an_allowed_inline_payload_does_not_end_the_evaluation() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        let mut w = Vec::new();
        let packs = vec![
            load_pack_str("<t>", PATH_PACK, &mut w).unwrap(),
            test_engine().packs.remove(0),
        ];
        let e = Engine::new(packs)
            .with_budget(TEST_BUDGET)
            .with_paths(PathVars::new().with_cwd(root.join("app")));
        assert!(e
            .evaluate("bash -c 'git reset --hard HEAD~1'; cat .env")
            .is_deny());
        assert!(e
            .evaluate("bash -c 'git reset --hard HEAD~1'; git reset --hard")
            .is_deny());
    }

    #[test]
    fn everyday_commands_stay_allowed() {
        let (_d, root) = canonical_tmp();
        let app = root.join("app");
        std::fs::create_dir_all(app.join("src")).unwrap();
        std::fs::create_dir_all(app.join(".claude")).unwrap();
        std::fs::write(app.join(".env"), "K=v").unwrap();
        std::fs::write(app.join("src/main.rs"), "").unwrap();
        let e = shell_path_engine(&root);
        for cmd in [
            "git status",
            r#"git commit -m "a > b""#,
            "cargo test 2>&1 | tail -5",
            "npm install",
            "ls -la .claude",
            "grep -r TODO src",
            "grep TODO *",
            "cat src/*.rs",
            "sed -i s/a/b/ src/main.rs",
            "cp src/main.rs src/lib.rs",
            "echo done > /dev/null",
            "make 2>&1 | tee build.log",
            "find . -name '*.rs'",
            "tar czf out.tgz src",
            "curl -sSo out.html https://example.com",
            "rm -rf target",
            "cd src && cargo build",
            "git checkout -- src/main.rs",
            "mv notes.txt docs/",
            "cat .claude/settings.json",
            "echo KEY=1 >> .env",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
    }

    #[test]
    fn leading_assignments_and_redirections_do_not_hide_the_command() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        let e = shell_path_engine(&root);
        for cmd in [
            "LANG=C sort .env",
            "RUST_LOG=debug cat .env",
            "A=1 B=2 cat .env",
            "FOO=1 rm .claude/settings.json",
            "2>/dev/null cat .env",
            "</dev/null cat .env",
            ">/tmp/out cat .env",
            "2>&1 FOO=1 sudo cat .env",
            "FOO=1 sudo BAR=2 cat .env",
            ">.claude/settings.json echo x",
            "a[0]=1 cat .env",
            "A+=1 cat .env",
            "X[k]+=v cat .env",
            r#"a["x"]=1 cat .env"#,
            "a[$(id)]=1 cat .env",
            "a[k=v]=1 cat .env",
            "a[b[1]]=1 cat .env",
            "sudo FOO=1 cat .env",
            "sudo -- FOO=1 cat .env",
            r#"env "FOO=1" cat .env"#,
            r#"sudo "FOO=1" cat .env"#,
            "env -- FOO=1 cat .env",
            "sudo -u x FOO=1 rm -rf .saiife",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
        for cmd in [
            "LANG=C sort notes.txt",
            "RUST_LOG=debug cargo test",
            "2>/dev/null cat README.md",
            r#""FOO=1" cat .env"#,
            "'A=1' cat .env",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
        let g = test_engine();
        assert!(g.evaluate("FOO=1 git reset --hard").is_deny());
        assert!(g.evaluate("2>/dev/null git reset --hard").is_deny());
        assert!(g.evaluate("A=1 2>/dev/null B=2 git clean -fd").is_deny());
        assert!(!g.evaluate("FOO=1 git status").is_deny());
    }

    // `cd $(x)` is unjudged only on POSIX: under Windows style what the reader cannot
    // read denies (W5), pinned by `corpus_windows_round1`. Also `/tmp`, `/d0` are
    // POSIX absolutes here.
    #[cfg(unix)]
    #[test]
    fn an_unknown_working_directory_is_recorded() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("app/l2"), root.join("app/l1")).unwrap();
            std::os::unix::fs::symlink(root.join("app/l1"), root.join("app/l2")).unwrap();
        }
        let e = shell_path_engine(&root);
        let unknown = Decision::Allow {
            trace: AllowTrace::Unjudgeable {
                reason: "working directory unknown after cd".to_string(),
            },
        };
        assert_eq!(e.evaluate("cd $(x) && cat notes.txt"), unknown);
        assert_eq!(e.evaluate("cd - && cat notes.txt"), unknown);
        #[cfg(unix)]
        assert_eq!(e.evaluate("cd l1 && cat notes.txt"), unknown);
        let many: String = (0..MAX_CWDS + 1).map(|i| format!("cd /d{i}; ")).collect();
        assert_eq!(e.evaluate(&format!("{many}cat notes.txt")), unknown);
        // A deny under a known directory still denies.
        assert!(e.evaluate("cd $(x) && cat .env").is_deny());
        // Nothing relative to judge: no record.
        for cmd in [
            "cd $(git rev-parse --show-toplevel) && cargo test",
            "cd $(x) && cat /etc/hosts",
            "cd - && ls",
        ] {
            assert_eq!(
                e.evaluate(cmd),
                Decision::Allow {
                    trace: AllowTrace::NoMatch
                },
                "{cmd}"
            );
        }
        assert_eq!(
            e.evaluate("cd /tmp && cat notes.txt"),
            Decision::Allow {
                trace: AllowTrace::NoMatch
            }
        );
    }

    /// Lines of about `kb` KB built from one repeated part, for the growth
    /// test: reserved words, assignments, wrappers and expansions, mixed.
    const REPEATED: &[&str] = &[
        "$v X=1 ",
        "$(true) X=1 ",
        "$v ",
        "$(true) ",
        "\"$@\" ",
        "{,} ",
        "$v env ",
        "$(true) env ",
        "\"$@\" env ",
        "$v env X=1 ",
        "$v sudo -u u ",
        "$v > f ",
        "> f $v ",
        "X=1 ",
        "env ",
        "time ",
        "time -p ",
        "! ",
        "if ",
        "while ",
        "then ",
        "for i do ",
        "repeat 3 ",
        "function f ",
        "coproc ",
        "! if time $v X=1 env \"$@\" ",
        "! time -p ! $v env X=1 \"$@\" > f ",
        "! $v; ",
        "if $v X=1 env \"$@\"; then ",
        "echo [[ ",
        "[[ x ]] ",
        "(( 1 )) ",
        "case ",
        "esac ",
        "cat <<A ",
        "bash <<A ",
        "! bash <<A ",
        "cat <<A; ",
    ];

    /// Work for one line: the repeated part, then a command, then a deny.
    fn work_for(part: &str, kb: usize) -> usize {
        let line = format!("{}x; git reset --hard", part.repeat(kb * 1024 / part.len()));
        let e = test_engine().with_budget(Duration::from_secs(60));
        crate::work::take();
        assert!(e.evaluate(&line).is_deny(), "{part:?} x {kb} KB");
        crate::work::take()
    }

    #[test]
    fn the_stripping_path_grows_linearly_with_the_line() {
        let mut failures = Vec::new();
        for part in REPEATED {
            let (w10, w20, w40) = (work_for(part, 10), work_for(part, 20), work_for(part, 40));
            // About double each time.
            if w20 > w10 * 5 / 2 || w40 > w20 * 5 / 2 {
                failures.push(format!("{part:?}: {w10} {w20} {w40}"));
            }
        }
        assert!(failures.is_empty(), "superlinear:\n{}", failures.join("\n"));
    }

    #[test]
    fn one_word_of_many_expansions_is_linear() {
        for part in ["$(true)", "`true`", "$v", "\"$@\"", "${x:-${y}}"] {
            let line = |kb: usize| {
                let word = part.repeat(kb * 1024 / part.len());
                let line = format!("{word} x; git reset --hard");
                let e = test_engine().with_budget(Duration::from_secs(60));
                crate::work::take();
                assert!(e.evaluate(&line).is_deny(), "{part:?} x {kb} KB");
                crate::work::take()
            };
            let (w10, w20) = (line(10), line(20));
            assert!(w20 <= w10 * 5 / 2, "{part:?}: {w10} {w20}");
        }
    }

    /// `$v env ` x40 + `$(…) z`, nested `levels` deep around `true`.
    fn nested_empties(levels: usize) -> String {
        let mut line = "true".to_string();
        for _ in 0..levels {
            line = format!("{}$({line}) z", "$v env ".repeat(40));
        }
        line
    }

    #[test]
    fn empty_expansions_across_wrappers_cost_one_extra_view() {
        let e = test_engine();
        // Per level: the line, and the segment as written and without its
        // empties. The innermost `true` is a line and a view.
        for levels in [1, 2, 8] {
            let line = nested_empties(levels);
            assert!(!e.evaluate(&line).is_deny(), "{line}");
            let runs = LAST_RUNS.with(Cell::get);
            assert_eq!(runs, 3 * levels + 2, "{levels} levels");
        }
        // No substitution judged twice, however many runs of empties.
        e.evaluate(&format!("{}$(true) z", "$v env ".repeat(40)));
        assert_eq!(LAST_RUNS.with(Cell::get), 5);
        // A line with no empties judges each segment once.
        e.evaluate("ls; git status");
        assert_eq!(LAST_RUNS.with(Cell::get), 3);
    }

    #[test]
    fn budget_overrun_fails_open_visibly() {
        // The budget path, taken by injecting a zero budget rather than a
        // heavy input: recorded as a fail-open, never a silent allow, unless
        // what is left denies.
        let timeout = Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout,
        };
        let e = test_engine().with_budget(Duration::ZERO);
        assert_eq!(e.evaluate("git status"), timeout);
        assert_eq!(
            e.evaluate("git reset --hard"),
            test_engine().evaluate("git reset --hard")
        );
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        let e = shell_path_engine(&root).with_budget(Duration::ZERO);
        assert_eq!(e.evaluate("cat notes.txt"), timeout);
        assert_eq!(
            e.evaluate("cat .env"),
            shell_path_engine(&root).evaluate("cat .env")
        );
    }

    /// The default packs and path rules, with no budget: everything goes
    /// through the last look.
    fn cheap_engine(root: &Path) -> Engine {
        let (packs, _) = crate::builtins::builtin_packs();
        Engine::new(crate::profile::select_active(packs, &[]))
            .with_budget(Duration::ZERO)
            .with_paths(
                PathVars::new()
                    .with_cwd(root.join("home/app"))
                    .with_var("HOME", root.join("home"))
                    .with_var("PROJECT", root.join("home/app")),
            )
    }

    /// Enough `cd`s for `MAX_CWDS` directories, the most a path is judged in.
    fn all_the_dirs() -> String {
        (0..MAX_CWDS).map(|i| format!("cd /d{i}; ")).collect()
    }

    /// The work the last look does on a line must double with the line,
    /// on what is slow in the budgeted pass and with every directory tracked.
    #[test]
    fn the_lexical_pass_grows_linearly_with_the_line() {
        let (_d, root) = canonical_tmp();
        let e = cheap_engine(&root);
        let dirs = all_the_dirs();
        let shapes = [
            ("", "! cd x; "),
            ("", "if cd x; then "),
            ("", "while cd x; do "),
            ("", "$v cd x; "),
            ("", "cd x; "),
            ("", "$v eval "),
            ("", "eval "),
            ("", "> f "),
            ("", "eval \"$(eval \"$(true)\")\" "),
            ("cat ", "a "),
            ("cat ", "{a,b}{c,d} "),
            (dirs.as_str(), "cat a; "),
            (dirs.as_str(), "$(true) "),
            (dirs.as_str(), "$(cat a) "),
            (dirs.as_str(), "rm a; "),
        ];
        let bare = REPEATED.iter().map(|part| ("", *part));
        let mut failures = Vec::new();
        for (prefix, part) in bare.chain(shapes) {
            let work = |kb: usize| {
                let pad = part.repeat(kb * 1024 / part.len());
                crate::work::take();
                let d = e.evaluate(&format!("{prefix}{pad}x; rm -rf /"));
                assert!(d.is_deny(), "{prefix:?} {part:?} x {kb} KB: {d:?}");
                crate::work::take()
            };
            let (w10, w20, w40) = (work(10), work(20), work(40));
            if w20 > w10 * 5 / 2 || w40 > w20 * 5 / 2 {
                failures.push(format!("{prefix:?} {part:?}: {w10} {w20} {w40}"));
            }
        }
        assert!(failures.is_empty(), "superlinear:\n{}", failures.join("\n"));
    }

    /// The same, on a Windows-style host, in each dialect a hook call can be
    /// read in. The readers' own cost is timed by the release probe, not counted.
    #[test]
    fn the_lexical_pass_grows_linearly_on_windows() {
        let (packs, _) = crate::builtins::Catalog::builtin_for(PathStyle::Windows).load_active(&[]);
        let e = Engine::new(packs).with_budget(Duration::ZERO).with_paths(
            PathVars::new()
                .with_style(PathStyle::Windows)
                .with_var("USERPROFILE", r"C:\Users\a")
                .with_cwd(r"C:\p"),
        );
        let shapes = [
            (Dialect::Posix, "! cd x; ", "x; rm.exe -rf /c/Windows"),
            (Dialect::Posix, "$v cd x; ", "x; rm.exe -rf /c/Windows"),
            (Dialect::Posix, "$v rm.exe a; ", "x; rm.exe -rf /c/Windows"),
            (Dialect::Posix, "$(true) ", "x; rm.exe -rf /c/Windows"),
            (Dialect::Posix, "$v eval ", "x; rm.exe -rf /c/Windows"),
            (Dialect::Posix, "while a; do ", "x; rm.exe -rf /c/Windows"),
            (Dialect::PowerShell, "cd x; ", "x; rm.exe -rf /c/Windows"),
            (Dialect::PowerShell, "gci a; ", "x; rm.exe -rf /c/Windows"),
            (Dialect::Cmd, "cd x & ", "x & rm.exe -rf /c/Windows"),
            (Dialect::Cmd, "dir a & ", "x & rm.exe -rf /c/Windows"),
        ];
        let mut failures = Vec::new();
        for (dialect, part, tail) in shapes {
            let work = |kb: usize| {
                let pad = part.repeat(kb * 1024 / part.len());
                crate::work::take();
                let d = e.evaluate_in(&format!("{pad}{tail}"), Dialects::One(dialect));
                assert!(d.is_deny(), "{dialect:?} {part:?} x {kb} KB: {d:?}");
                crate::work::take()
            };
            let (w10, w20, w40) = (work(10), work(20), work(40));
            if w20 > w10 * 5 / 2 || w40 > w20 * 5 / 2 {
                failures.push(format!("{dialect:?} {part:?}: {w10} {w20} {w40}"));
            }
        }
        assert!(failures.is_empty(), "superlinear:\n{}", failures.join("\n"));
    }

    /// Past the limit the line is denied and says why: dropping a nested line or a
    /// directory could allow what a rule denies. A rule found first keeps its name.
    #[test]
    fn past_the_work_limit_the_line_is_denied() {
        let (_d, root) = canonical_tmp();
        let e = cheap_engine(&root);
        let costly = |d: Decision| match d {
            Decision::Deny {
                pattern, reason, ..
            } => pattern == "line-too-costly-to-judge" && reason.contains("split"),
            _ => false,
        };
        let moved = "cd ~/.ssh; cat id_rsa";
        assert!(!costly(e.evaluate(moved)));
        assert!(!costly(e.evaluate("$(cat .env)")));

        CHEAP_WORK_LIMIT.with(|l| l.set(Some(0)));
        assert!(costly(e.evaluate("$(cat .env)")));
        assert!(costly(e.evaluate("ls a; $(ls)")));
        assert!(costly(e.evaluate(moved)));
        match e.evaluate("rm -rf /") {
            Decision::Deny { pack, .. } => assert_eq!(pack, "core.filesystem"),
            d => panic!("{d:?}"),
        }

        // Below the limit nothing changes.
        CHEAP_WORK_LIMIT.with(|l| l.set(Some(1 << 20)));
        assert_eq!(
            e.evaluate("ls"),
            Decision::Allow {
                trace: AllowTrace::FailedOpenTimeout,
            }
        );
        // Paths cannot use up what nested lines need, nor the other way.
        let line = format!("{}cat {}; $(rm -rf /)", all_the_dirs(), "a ".repeat(4096));
        assert!(e.evaluate(&line).is_deny(), "after spent paths");
        CHEAP_WORK_LIMIT.with(|l| l.set(None));
    }

    /// A project of `n` files and a link to `.env`, with the default rules.
    #[cfg(unix)]
    fn project_with_a_link(n: usize) -> (tempfile::TempDir, PathBuf, Engine) {
        let (d, root) = canonical_tmp();
        let app = root.join("home/app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join(".env"), "x").unwrap();
        std::os::unix::fs::symlink(".env", app.join("link")).unwrap();
        for i in 0..n {
            std::fs::write(app.join(format!("f{i}")), "x").unwrap();
        }
        let e = cheap_engine(&root);
        (d, root, e)
    }

    #[cfg(unix)]
    fn is_too_costly(d: &Decision) -> bool {
        matches!(d, Decision::Deny { pattern, .. } if pattern == "line-too-costly-to-judge")
    }

    /// The system calls of one evaluation, and its verdict.
    #[cfg(unix)]
    fn counted(e: &Engine, line: &str) -> (usize, Decision) {
        crate::canon::take_fs_calls();
        let d = e.evaluate(line);
        (crate::canon::take_fs_calls(), d)
    }

    /// Bounded means a count of system calls: past it, a path that cannot be
    /// resolved denies. The same line makes the same calls and gets the same verdict.
    #[cfg(unix)]
    #[test]
    fn the_last_look_makes_a_fixed_count_of_system_calls() {
        let (_d, _root, e) = project_with_a_link(0);
        let names: Vec<String> = (0..20_000).map(|i| format!("cat n{i}")).collect();
        for ending in ["cat link", "ls"] {
            let line = format!("{}; {ending}", names.join("; "));
            let (calls, verdict) = counted(&e, &line);
            assert!(is_too_costly(&verdict), "{ending}: {verdict:?}");
            assert!(
                calls <= MAX_CHEAP_WORK / crate::canon::FS_CALL_COST,
                "{calls}"
            );
            assert!(calls > 1000, "{calls}");
            assert_eq!(counted(&e, &line), (calls, verdict), "{ending}");
        }
    }

    /// One call of each kind counts: a `cd`, a glob and a copy target, each past the
    /// bound on its own.
    #[cfg(unix)]
    #[test]
    fn past_the_bound_a_link_a_glob_and_a_cd_deny() {
        let (_d, _root, e) = project_with_a_link(64);
        for (line, calls) in [
            ("cat link", 4),
            ("cat .en*", 4),
            ("cat f*", 4),
            ("cd link; ls", 4),
            ("cp a link", 4),
        ] {
            CHEAP_WORK_LIMIT.with(|l| l.set(Some(calls * crate::canon::FS_CALL_COST)));
            let (spent, d) = counted(&e, line);
            CHEAP_WORK_LIMIT.with(|l| l.set(None));
            assert!(is_too_costly(&d), "{line}: {d:?}");
            assert!(spent <= calls, "{line}: {spent}");
        }
    }

    /// Asking again costs nothing: a padded line of one path does not use up the bound
    /// on what follows it.
    #[cfg(unix)]
    #[test]
    fn the_same_path_again_makes_no_system_call() {
        let (_d, _root, e) = project_with_a_link(0);
        let (once, _) = counted(&e, "cat a");
        let (many, d) = counted(&e, &"cat a; ".repeat(10_000));
        assert_eq!(d, timed_out());
        assert!(once > 0, "{once}");
        assert_eq!(many, once);
        let (_, d) = counted(&e, &format!("{}cat link", "cat a; ".repeat(10_000)));
        assert!(d.is_deny() && !is_too_costly(&d), "{d:?}");
    }

    /// A path long enough to cost more to look up than a call makes is charged too.
    #[cfg(unix)]
    #[test]
    fn long_paths_cannot_outrun_the_bound() {
        let (_d, root, e) = project_with_a_link(0);
        let deep = "d/".repeat(300);
        std::fs::create_dir_all(root.join("home/app").join(&deep)).unwrap();
        let (calls, d) = counted(
            &e,
            &format!("{}cat link", format!("cat {deep}x; ").repeat(1000)),
        );
        assert!(is_too_costly(&d), "{d:?}");
        assert!(calls < 1000, "known answers make no call: {calls}");
    }

    /// Past `MAX_CWDS` in its tier a `cd` is not resolved at all: each one before
    /// adds a directory, and resolves against those there are so far. Plain ones
    /// start from the one directory with 15 slots left, the others with 16.
    #[test]
    fn a_cd_past_the_directory_limit_resolves_nothing() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        let e = shell_path_engine(&root);
        let unknown = Decision::Allow {
            trace: AllowTrace::Unjudgeable {
                reason: "working directory unknown after cd".to_string(),
            },
        };
        for (part, resolves) in [
            ("cd x; ", (1..16).sum::<usize>()),
            ("! cd x; ", (1..17).sum()),
            ("if cd x; then ", (1..17).sum()),
            ("$v cd x; ", (1..17).sum()),
        ] {
            CD_RESOLVES.with(|n| n.set(0));
            let line = format!("{}cat notes.txt", part.repeat(240));
            assert_eq!(e.evaluate(&line), unknown, "{part:?}");
            assert_eq!(CD_RESOLVES.with(Cell::get), resolves, "{part:?}");
        }
    }

    #[test]
    fn brace_expansion_is_judged() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        let e = shell_path_engine(&root);
        for cmd in [
            "diff {.env,.env.example}",
            "cat .{env,x}",
            "cat {.env,x}",
            "cp {.env,/tmp/x}",
            "mv .claude/settings.json{,.bak}",
            r#"cat {".env",x}"#,
            "cat {'.env',x}",
            r"cat {\.env,x}",
            "cat {$HOME/.ssh/id_rsa,x}",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
        for cmd in [
            "cat {a,b}.md",
            "echo {1,2}",
            "{ cat README.md; }",
            "cat '{.env,x}'",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
        let big = "{a,b}".repeat(40);
        assert_eq!(
            e.evaluate(&format!("cat {big}")),
            Decision::Allow {
                trace: AllowTrace::Unjudgeable {
                    reason: "brace expansion too large to judge".to_string()
                }
            }
        );
        assert!(e.evaluate(&format!("cat {big} .env")).is_deny());
        assert!(e.evaluate(&format!("cat {big}; cat .env")).is_deny());
        // Brace expansion in command position runs the expanded words.
        assert!(test_engine().evaluate("{git,reset,--hard}").is_deny());
        assert!(test_engine().evaluate("{ git reset --hard; }").is_deny());
    }

    #[test]
    fn copy_landing_names_follow_globs_and_contents() {
        let (_d, root) = canonical_tmp();
        let app = root.join("app");
        for d in [".claude", "backup", "other", "conf", "big"] {
            std::fs::create_dir_all(app.join(d)).unwrap();
        }
        std::fs::write(app.join("backup/settings.json"), "{}").unwrap();
        std::fs::write(app.join("backup/secret.json"), "{}").unwrap();
        std::fs::write(app.join("other/readme.md"), "").unwrap();
        for i in 0..(crate::canon::GLOB_SCAN_LIMIT + 1) {
            std::fs::write(app.join(format!("big/f{i}")), "").unwrap();
        }
        let e = shell_path_engine(&root);
        for cmd in [
            "cp backup/*.json .claude/",
            "cp backup/* .claude",
            "cp -rT backup conf",
            "cp -rT backup newdir/conf",
            "rsync -a backup/ conf",
            "rsync -a backup/ conf/",
            "rsync -a back*/ conf",
            "cp -rT back* conf",
            "cp -rT backu? conf",
            // Entries already read before an overflow are still judged.
            "rsync -a backup/ big/ conf",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
        for cmd in [
            "cp other/* .claude/",
            "cp -rT other conf",
            "rsync -a backup conf",
            "rsync -a other/ conf",
            "rsync -a oth*/ conf",
            "rsync -a nomatch*/ conf",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
        assert_eq!(
            e.evaluate("cp -rT big conf"),
            Decision::Allow {
                trace: AllowTrace::Unjudgeable {
                    reason: "copy source too large to judge".to_string()
                }
            }
        );
    }

    #[test]
    fn combined_shell_flags_with_c_are_inline_payloads() {
        let g = test_engine();
        for cmd in [
            "bash -lc 'git reset --hard'",
            "bash -c -l 'git reset --hard'",
            "sh -ec 'git reset --hard'",
            "bash -o pipefail -c 'git reset --hard'",
            "zsh -ic 'git reset --hard'",
            "bash --login -c 'git reset --hard'",
            "dash -xc 'git reset --hard'",
        ] {
            assert!(g.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
        for cmd in [
            "bash -l script.sh",
            "bash -lc 'git status'",
            "bash -o pipefail x.sh",
        ] {
            assert!(!g.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        assert!(shell_path_engine(&root)
            .evaluate("bash -lc 'cat .env'")
            .is_deny());
    }

    #[test]
    fn heredoc_bodies_are_data_unless_a_shell_reads_them() {
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        let e = shell_path_engine(&root);
        for cmd in [
            "cat > run.sh <<'EOF'\n#!/bin/sh\nsource .env\nnpm start\nEOF",
            "cat > notes.md <<EOF\nrm -rf .claude\nEOF",
            "cat <<-EOF > x\n\tcat .env\n\tEOF\necho done",
            "python3 - <<EOF\nprint(open('.env').read())\nEOF",
            "cat <<EOF\ncat .env",
            "cat <<A <<B\ncat .env\nA\nrm -rf .claude\nB\necho ok",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
        for cmd in [
            "bash <<'EOF'\ncat .env\nEOF",
            "sh <<-EOF\n\tcat .env\n\tEOF",
            "sudo bash <<EOF\ncat .env\nEOF",
            "cat <<EOF | bash\ncat .env\nEOF",
            "source /dev/stdin <<EOF\ncat .env\nEOF",
            "cat <<EOF > x\nhi\nEOF\ncat .env",
            "cat <<A; bash <<B\nsource .env\nA\ncat .env\nB",
        ] {
            assert!(e.evaluate(cmd).is_deny(), "expected DENY for {cmd:?}");
        }
    }

    const SEGMENT_PACK: &str = r#"
[pack]
id = "test.segment"
triggers = ["env", "gh"]
substitution_failsafe = false

[[deny]]
pattern = '^(?:sudo\s+)?env$'
reason = "env dump"
whole_segment = true

[[deny]]
pattern = '^gh\s+auth\s+token\b'
reason = "token"
"#;

    #[test]
    fn whole_segment_rules_see_wrappers_and_bare_wrappers() {
        let mut w = Vec::new();
        let e = Engine::new(vec![load_pack_str("<t>", SEGMENT_PACK, &mut w).unwrap()])
            .with_budget(TEST_BUDGET);
        assert!(e.evaluate("env").is_deny());
        assert!(e.evaluate("sudo env").is_deny());
        assert!(e.evaluate("echo a; env | sort").is_deny());
        assert!(!e.evaluate("env FOO=1 ls").is_deny());
        assert!(e.evaluate("gh auth token").is_deny());
    }

    #[test]
    fn substitution_failsafe_can_be_turned_off_per_pack() {
        let mut w = Vec::new();
        let e = Engine::new(vec![load_pack_str("<t>", SEGMENT_PACK, &mut w).unwrap()])
            .with_budget(TEST_BUDGET);
        assert!(!e
            .evaluate("gh pr view $(git branch --show-current)")
            .is_deny());
        // The default stays on: test.git guards `git`.
        assert!(test_engine().evaluate("git reset --hard $(x)").is_deny());
    }

    #[test]
    fn nested_quote_inside_inline_payload_is_caught_by_recursion() {
        // The outer lexer sees this as one single-quoted, fully literal
        // argument. `g"it"` never resolves to a contiguous "git" substring
        // at the outer level (there's a literal `"` between the letters),
        // so the outer combined pre-filter can't see a trigger here at all
        // — the inline-payload recursion must not be gated behind it. Only
        // once the inner string is re-lexed on its own does the nested
        // double-quote resolve and concatenate into the real command name.
        let d = test_engine().evaluate(r#"bash -c 'g"it" reset --hard'"#);
        assert!(d.is_deny(), "expected DENY, got {d:?}");
    }
}
