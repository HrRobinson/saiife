//! The decision engine: tokenize -> segment -> per segment (build argv ->
//! guarded-substitution check -> pre-filter -> match allow before deny) ->
//! decide, with a structural inline `-c` re-entry and a hard latency cap
//! that fails open.
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

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use regex::{Regex, RegexSet};

use crate::canon::{canonicalize, expand_glob, lexical_form, path_forms, GlobExpansion, PathVars};
use crate::lexer::{find_all_substitutions, split_segments, Word};
use crate::normalize::build_argv;
use crate::operands::operands;
use crate::pack::Pack;
use crate::pathrule::{compile_glob, Access, RuleAccess};
use crate::payload::{inline_payload, watch_payload};
use crate::prefilter::Prefilter;
use crate::subst::command_position_substitution;
use crate::wrappers::{is_env_assignment, unwrap_transparent_prefix};

/// Default latency budget for a single evaluation. Exceeding it yields
/// `Allow { .. timed_out: true }` — continuity wins over a stalled guard.
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
    /// Case-folded command names that at least one active pack has a deny
    /// rule for. Used only to scope the command-substitution-in-a-guarded-
    /// position policy — see `evaluate_segment`.
    guarded_commands: HashSet<String>,
    /// Directories paths are resolved against and rule variables bound to.
    vars: PathVars,
    /// Each pack's path rules, bound to `vars`.
    path_rules: Vec<PackPaths>,
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

fn rule_set(rules: &[BoundPathRule]) -> Option<RegexSet> {
    RegexSet::new(rules.iter().map(|r| r.regex.as_str())).ok()
}

struct BoundPathRule {
    glob: String,
    regex: Regex,
    access: RuleAccess,
    reason: String,
}

/// Path rules match case-insensitively where the usual filesystem is
/// case-insensitive (macOS: `.ENV` opens `.env`).
const PATHS_CASE_INSENSITIVE: bool = cfg!(target_os = "macos");

impl Engine {
    /// Build an engine from loaded packs.
    pub fn new(packs: Vec<Pack>) -> Self {
        let triggers: Vec<String> = packs.iter().flat_map(|p| p.triggers.clone()).collect();
        let guarded_commands = packs
            .iter()
            .filter(|p| !p.deny.is_empty() && p.substitution_failsafe)
            .flat_map(|p| p.triggers.iter())
            .filter(|t| looks_like_bare_command_name(t))
            .map(|t| t.to_ascii_lowercase())
            .collect();
        let mut engine = Self {
            combined: Prefilter::new(triggers),
            packs,
            budget: DEFAULT_BUDGET,
            guarded_commands,
            vars: PathVars::default(),
            path_rules: Vec::new(),
        };
        engine.bind_paths();
        engine
    }

    /// Resolve paths against these directories and bind the path rules'
    /// variables (`~`, `$SAIIFE_BIN`, …) to them. Without this, only rules
    /// without variables apply and relative paths cannot be judged.
    pub fn with_paths(mut self, vars: PathVars) -> Self {
        self.vars = vars;
        self.bind_paths();
        self
    }

    fn bind_paths(&mut self) {
        let bind = |rules: &[crate::pathrule::PathRule]| -> Vec<BoundPathRule> {
            rules
                .iter()
                .filter_map(|r| {
                    // Globs were validated at load; a rule whose variable
                    // has no value on this machine cannot apply.
                    let regex = compile_glob(&r.glob, &self.vars, PATHS_CASE_INSENSITIVE)
                        .ok()
                        .flatten()?;
                    Some(BoundPathRule {
                        glob: r.glob.clone(),
                        regex,
                        access: r.access,
                        reason: r.reason.clone(),
                    })
                })
                .collect()
        };
        self.path_rules = self
            .packs
            .iter()
            .filter(|p| !p.deny_path.is_empty())
            .map(|p| {
                let allow = bind(&p.allow_path);
                let deny = bind(&p.deny_path);
                PackPaths {
                    pack: p.id.clone(),
                    allow_set: rule_set(&allow),
                    deny_set: rule_set(&deny),
                    allow,
                    deny,
                }
            })
            .collect();
    }

    /// `path` as the path rules see it: absolute, symlinks and `..`
    /// resolved. `None` if it cannot be made absolute.
    pub fn resolve_path(&self, path: &str) -> Option<PathBuf> {
        canonicalize(path, None, &self.vars)
    }

    /// Judge a file tool's access to `path` against the active packs' path
    /// rules (spec §7.2). Same budget and fail-open rules as `evaluate`.
    pub fn evaluate_path(&self, access: Access, path: &str) -> Decision {
        let start = Instant::now();
        let forms = path_forms(path, None, &self.vars);
        if forms.is_empty() {
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

    /// Path rules for one resolved path: per pack, an `allow_path` match
    /// exempts the path from that pack's `deny_path` rules; the first deny
    /// in any pack wins.
    fn judge_path(&self, access: Access, real: &Path, start: Instant) -> JudgeOutcome {
        let text = real.to_string_lossy();
        let mut carved: Option<Decision> = None;
        for pp in &self.path_rules {
            if start.elapsed() > self.budget {
                return JudgeOutcome::TimedOut;
            }
            let hit = |rules: &[BoundPathRule], set: &Option<RegexSet>| match set {
                Some(set) => set
                    .matches(&text)
                    .into_iter()
                    .find(|&i| rules[i].access.covers(access)),
                None => rules
                    .iter()
                    .position(|r| r.access.covers(access) && r.regex.is_match(&text)),
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

    /// Evaluate a raw command line and return the decision.
    pub fn evaluate(&self, raw_cmd: &str) -> Decision {
        let start = Instant::now();
        let cwds: Vec<PathBuf> = self.vars.cwd().map(Path::to_path_buf).into_iter().collect();
        self.evaluate_inner(raw_cmd, start, 0, &cwds)
    }

    /// `cwds`: the directories the shell may be in at the start of
    /// `raw_cmd`. A `cd` adds its target for the segments after it but
    /// never drops the old ones: it may fail (`cd /nonexistent; …`), run
    /// in a subshell (`(cd x); …`) or go somewhere unknown (`cd $(…)`).
    fn evaluate_inner(
        &self,
        raw_cmd: &str,
        start: Instant,
        depth: u32,
        cwds: &[PathBuf],
    ) -> Decision {
        let mut allow_trace: Option<AllowTrace> = None;
        // Something could not be judged (a glob too large to expand): the
        // outcome is a recorded fail-open unless something else denies.
        let mut unjudged: Option<String> = None;
        let mut cwds: Vec<PathBuf> = cwds.to_vec();

        for seg in split_segments(raw_cmd) {
            if start.elapsed() > self.budget {
                return Decision::Allow {
                    trace: AllowTrace::FailedOpenTimeout,
                };
            }
            if seg.is_empty() {
                continue;
            }
            // Peel off transparent wrapper commands (`command`, `env`,
            // `nohup`, `nice`, `stdbuf`, `ionice`, `sudo`) before judging —
            // the engine reasons about the *effective* command, not the
            // wrapper, so packs never need to know these wrappers exist.
            let effective = unwrap_transparent_prefix(&seg);

            // Command substitution occupying *command position* — the
            // whole (unwrapped) segment, or the value of a leading
            // `NAME=$(...)` assignment word: a real shell evaluates
            // `$(...)`/`` `...` `` eagerly, so `$(rm -rf /)` runs `rm -rf /`
            // for real regardless of what (if anything) consumes its
            // output. There's no argv[0] here for a pack to match against —
            // recurse into the substitution's inner text and judge that
            // instead, the same structural re-entry already used for inline
            // `bash -c '...'` payloads below (same depth cap, same budget).
            if let Some(inner) = command_position_substitution(effective) {
                if depth < MAX_INLINE_DEPTH {
                    if start.elapsed() > self.budget {
                        return Decision::Allow {
                            trace: AllowTrace::FailedOpenTimeout,
                        };
                    }
                    match self.evaluate_inner(&inner, start, depth + 1, &cwds) {
                        Decision::Deny {
                            pack,
                            pattern,
                            reason,
                            ..
                        } => {
                            return Decision::Deny {
                                pack,
                                pattern,
                                reason,
                                via_inline: Some(inner),
                            }
                        }
                        Decision::Allow {
                            trace: AllowTrace::FailedOpenTimeout,
                        } => {
                            return Decision::Allow {
                                trace: AllowTrace::FailedOpenTimeout,
                            }
                        }
                        Decision::Allow { trace } => {
                            note(trace, &mut allow_trace, &mut unjudged);
                        }
                    }
                }
                // Depth cap reached, or the recursion above resolved to a
                // (non-timeout) allow: there is no literal argv[0] in this
                // segment to judge against packs, so move on to the next
                // segment rather than trying to match "$(...)" as if it
                // were a literal command name.
                continue;
            }

            // Command substitution embedded ANYWHERE else in this segment —
            // not filling the whole command position (handled above), but
            // sitting inside an argument, inside a wrapper's own words (e.g.
            // an `env FOO=$(...)` assignment later peeled off by
            // unwrapping), or only part of a larger concatenated word
            // (`$(cmd)suffix`). A real shell evaluates every `$(...)`/
            // `` `...` `` eagerly wherever it appears, before deciding what
            // the surrounding word means — so leaving any of these
            // unjudged is a full, silent bypass regardless of position,
            // quoting, or whether the outer command is one a pack guards.
            // Scanned over the *original* (pre-unwrap) segment so a
            // substitution hiding in a word a wrapper's unwrapping would
            // otherwise consume is not missed either. Recurse into each one
            // found — same depth cap and budget as every other structural
            // re-entry in this function; a deny in any of them denies the
            // whole segment. A benign inner (`echo $(date)`) still resolves
            // to ALLOW here; only a guarded/destructive inner denies. This
            // does not replace the guarded-argument fail-safe below, which
            // covers a different risk (a *benign* inner whose result is
            // still an unknowable, dynamic target for an already-guarded
            // command, e.g. `rm -rf $(echo /)`).
            for word in &seg {
                if !word.has_substitution {
                    continue;
                }
                for inner in find_all_substitutions(&word.text) {
                    if depth >= MAX_INLINE_DEPTH {
                        // Depth cap reached: fail open on this one
                        // substitution and keep scanning the rest of the
                        // segment rather than recursing unboundedly.
                        continue;
                    }
                    if start.elapsed() > self.budget {
                        return Decision::Allow {
                            trace: AllowTrace::FailedOpenTimeout,
                        };
                    }
                    match self.evaluate_inner(&inner, start, depth + 1, &cwds) {
                        Decision::Deny {
                            pack,
                            pattern,
                            reason,
                            ..
                        } => {
                            return Decision::Deny {
                                pack,
                                pattern,
                                reason,
                                via_inline: Some(inner),
                            }
                        }
                        Decision::Allow {
                            trace: AllowTrace::FailedOpenTimeout,
                        } => {
                            return Decision::Allow {
                                trace: AllowTrace::FailedOpenTimeout,
                            }
                        }
                        Decision::Allow { trace } => {
                            note(trace, &mut allow_trace, &mut unjudged);
                        }
                    }
                }
            }

            let argv = build_argv(effective);
            if argv.is_empty() || argv[0].is_empty() {
                let segment_line = segment_line(&seg);
                // A bare wrapper (`env`, `sudo -l`): only whole-segment
                // rules and redirections can apply.
                if self.combined.might_match(&segment_line) {
                    match self.judge("", &segment_line, start) {
                        JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return d,
                        JudgeOutcome::TimedOut => {
                            return Decision::Allow {
                                trace: AllowTrace::FailedOpenTimeout,
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(d) = self.judge_operands(&seg, &[], &[], &cwds, start) {
                    match d {
                        Decision::Allow {
                            trace: AllowTrace::Unjudgeable { reason },
                        } => {
                            unjudged.get_or_insert(reason);
                        }
                        d => return d,
                    }
                }
                continue;
            }

            // Fail-safe: a guarded command (one an active pack has a deny
            // rule for) with a command-substitution argument can't be
            // proven safe — we don't evaluate `$(...)`/`` `...` ``, so we
            // don't know what it resolves to. Scoped to arguments only
            // (never argv[0] itself) and to already-guarded commands, so an
            // unguarded command with a substitution (`echo $(date)`) gains
            // no new scrutiny.
            if self.guarded_commands.contains(&argv[0])
                && effective.iter().skip(1).any(|w| w.has_substitution)
            {
                return Decision::Deny {
                    pack: SUBSTITUTION_GUARD_PACK.to_string(),
                    pattern: "guarded-command-substitution-argument".to_string(),
                    reason: format!(
                        "{} has a command-substitution argument; the guard cannot see \
                         what it expands to, so it fails safe and blocks",
                        argv[0]
                    ),
                    via_inline: None,
                };
            }

            let matching_line = argv.join(" ");
            // The whole segment's line differs only when a wrapper was
            // peeled off or the segment starts with an assignment.
            let whole = (effective.len() != seg.len() || is_env_assignment(&seg[0].text))
                .then(|| segment_line(&seg));
            let segment_line = whole.as_deref().unwrap_or(&matching_line);
            if self.combined.might_match(&matching_line)
                || (whole.is_some() && self.combined.might_match(segment_line))
            {
                match self.judge(&matching_line, segment_line, start) {
                    JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return d,
                    JudgeOutcome::Decided(Decision::Allow { trace }) => {
                        allow_trace = Some(trace);
                    }
                    JudgeOutcome::TimedOut => {
                        return Decision::Allow {
                            trace: AllowTrace::FailedOpenTimeout,
                        }
                    }
                    JudgeOutcome::Clean => {}
                }
            }

            // Files the command reads or writes, judged by the path rules
            // that also guard the agents' file tools.
            if let Some(d) = self.judge_operands(&seg, effective, &argv, &cwds, start) {
                match d {
                    Decision::Allow {
                        trace: AllowTrace::Unjudgeable { reason },
                    } => {
                        unjudged.get_or_insert(reason);
                    }
                    d => return d,
                }
            }
            if argv[0] == "cd" || argv[0] == "pushd" {
                self.cd(&argv, effective, &mut cwds);
            }

            // Structural inline-payload re-entry: `bash -c '…'`, `su -c '…'`,
            // and `watch CMD …` (which joins its remaining args and runs them
            // via `sh -c`). Not gated behind the pre-filter above — the
            // payload may only resolve to something trigger-bearing once it is
            // *re-lexed* on its own (a nested quote inside an outer
            // single-quoted `-c` argument is invisible to the outer scan by
            // design; the recursive call re-tokenizes it correctly). The two
            // extractors are mutually exclusive on argv[0], so trying one then
            // the other never double-recurses the same segment.
            if depth < MAX_INLINE_DEPTH {
                if let Some(inner) = inline_payload(&argv).or_else(|| watch_payload(&argv)) {
                    if start.elapsed() > self.budget {
                        return Decision::Allow {
                            trace: AllowTrace::FailedOpenTimeout,
                        };
                    }
                    match self.evaluate_inner(&inner, start, depth + 1, &cwds) {
                        Decision::Deny {
                            pack,
                            pattern,
                            reason,
                            ..
                        } => {
                            return Decision::Deny {
                                pack,
                                pattern,
                                reason,
                                via_inline: Some(inner),
                            }
                        }
                        Decision::Allow {
                            trace: AllowTrace::FailedOpenTimeout,
                        } => {
                            return Decision::Allow {
                                trace: AllowTrace::FailedOpenTimeout,
                            }
                        }
                        // An allowed payload does not end the evaluation:
                        // later segments still get judged.
                        Decision::Allow { trace } => {
                            note(trace, &mut allow_trace, &mut unjudged);
                        }
                    }
                }
            }
        }

        if let Some(reason) = unjudged {
            return Decision::Allow {
                trace: AllowTrace::Unjudgeable { reason },
            };
        }
        Decision::Allow {
            trace: allow_trace.unwrap_or(AllowTrace::NoMatch),
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
    /// glob matches and copy targets that are directories.
    fn judge_operands(
        &self,
        seg: &[Word],
        effective: &[Word],
        argv: &[String],
        cwds: &[PathBuf],
        start: Instant,
    ) -> Option<Decision> {
        if self.path_rules.is_empty() {
            return None;
        }
        let ops = operands(seg, effective, argv);
        if ops.is_empty() {
            return None;
        }
        let all: Vec<Option<&Path>> = if cwds.is_empty() {
            vec![None]
        } else {
            cwds.iter().map(|c| Some(c.as_path())).collect()
        };
        // A path that does not depend on the working directory is judged
        // once.
        let anchors = |raw: &str| -> &[Option<&Path>] {
            if raw.starts_with('/') || raw.starts_with('~') || raw.starts_with("$HOME") {
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
            // A copy target that may be a directory waits for pass 2.
            let landing = if op.into.is_empty() {
                vec![op.path.clone()]
            } else if op.path.ends_with('/') {
                into_dir(&op.path, &op.into)
            } else {
                continue;
            };
            for raw in &landing {
                for cwd in anchors(raw) {
                    let Some(form) = lexical_form(raw, *cwd, &self.vars) else {
                        continue;
                    };
                    match self.judge_path(op.access, &form, start) {
                        JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return Some(d),
                        JudgeOutcome::TimedOut => return timed_out(),
                        _ => {}
                    }
                }
            }
        }

        let mut unjudged = None;
        for op in &ops {
            for cwd in anchors(&op.path) {
                if start.elapsed() > self.budget {
                    return timed_out();
                }
                let words = if op.glob {
                    match expand_glob(&op.path, *cwd, &self.vars) {
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
                    let is_dir = !op.into.is_empty()
                        && (word.ends_with('/')
                            || canonicalize(&word, *cwd, &self.vars).is_some_and(|p| p.is_dir()));
                    let landing = if is_dir {
                        into_dir(&word, &op.into)
                    } else {
                        vec![word]
                    };
                    for raw in landing {
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
        unjudged.map(|reason| Decision::Allow {
            trace: AllowTrace::Unjudgeable { reason },
        })
    }

    /// Add where `cd`/`pushd` may leave the shell to `cwds`: its operand
    /// resolved against each directory, home without one. `cd -` and a
    /// target with a substitution add nothing (the old directories stay).
    fn cd(&self, argv: &[String], effective: &[Word], cwds: &mut Vec<PathBuf>) {
        let arg = argv
            .iter()
            .zip(effective)
            .skip(1)
            .find(|(a, _)| !a.starts_with('-') || *a == "-");
        let new: Vec<PathBuf> = match arg {
            None => self
                .vars
                .home()
                .map(Path::to_path_buf)
                .into_iter()
                .collect(),
            Some((a, w)) if a == "-" || w.has_substitution => Vec::new(),
            Some((a, _)) if cwds.is_empty() => {
                canonicalize(a, None, &self.vars).into_iter().collect()
            }
            Some((a, _)) => cwds
                .iter()
                .filter_map(|c| canonicalize(a, Some(c), &self.vars))
                .collect(),
        };
        for n in new {
            if cwds.len() >= MAX_CWDS {
                break;
            }
            if !cwds.contains(&n) {
                cwds.push(n);
            }
        }
    }

    /// Run allow-before-deny across all packs for one segment. Rules match
    /// the effective command's line (its argv after wrappers like `sudo` are
    /// peeled off, case-folded/dir-stripped/slash-collapsed, joined with
    /// single spaces); `whole_segment` rules match the line of the whole
    /// segment, wrappers and leading assignments included. An empty
    /// `matching_line` (a bare wrapper) leaves only `whole_segment` rules.
    fn judge(&self, matching_line: &str, segment_line: &str, start: Instant) -> JudgeOutcome {
        let line = |rule: &crate::pack::Rule| -> Option<&str> {
            if rule.whole_segment {
                Some(segment_line)
            } else if matching_line.is_empty() {
                None
            } else {
                Some(matching_line)
            }
        };
        for pack in &self.packs {
            if start.elapsed() > self.budget {
                return JudgeOutcome::TimedOut;
            }
            let pf = pack.prefilter();
            if !pf.might_match(matching_line) && !pf.might_match(segment_line) {
                continue;
            }
            // Allow rules first — a match short-circuits to ALLOW.
            for rule in &pack.allow {
                if line(rule).is_some_and(|l| rule.regex.is_match(l)) {
                    return JudgeOutcome::Decided(Decision::Allow {
                        trace: AllowTrace::AllowRule {
                            pack: pack.id.clone(),
                            pattern: rule.pattern.clone(),
                            reason: rule.reason.clone(),
                        },
                    });
                }
            }
            // Then deny rules — first match wins.
            for rule in &pack.deny {
                if line(rule).is_some_and(|l| rule.regex.is_match(l)) {
                    return JudgeOutcome::Decided(Decision::Deny {
                        pack: pack.id.clone(),
                        pattern: rule.pattern.clone(),
                        reason: rule.reason.clone(),
                        via_inline: None,
                    });
                }
            }
        }
        JudgeOutcome::Clean
    }
}

/// Directories a command line's paths are judged against at most (the
/// starting one plus `cd` targets).
const MAX_CWDS: usize = 16;

/// `dir/<name>` for each name copied or moved into `dir`.
fn into_dir(dir: &str, names: &[String]) -> Vec<String> {
    let dir = dir.trim_end_matches('/');
    names.iter().map(|n| format!("{dir}/{n}")).collect()
}

/// Record a recursive evaluation's allow: an unjudgeable part makes the
/// whole command unjudgeable (unless something denies), otherwise the
/// latest trace wins.
fn note(trace: AllowTrace, allow_trace: &mut Option<AllowTrace>, unjudged: &mut Option<String>) {
    match trace {
        AllowTrace::Unjudgeable { reason } => {
            unjudged.get_or_insert(reason);
        }
        t => *allow_trace = Some(t),
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

enum JudgeOutcome {
    Decided(Decision),
    Clean,
    TimedOut,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::load_pack_str;

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
        Engine::new(vec![pack])
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
glob = "**/.saiife/**"
access = "write"
reason = "saiife config"
"#;

    fn path_engine(vars: PathVars) -> Engine {
        let mut w = Vec::new();
        let pack = load_pack_str("<t>", PATH_PACK, &mut w).unwrap();
        assert!(w.is_empty(), "{w:?}");
        Engine::new(vec![pack]).with_paths(vars)
    }

    fn canonical_tmp() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = std::fs::canonicalize(d.path()).unwrap();
        (d, p)
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
                assert!(
                    reason.contains(&app.join(".env").display().to_string()),
                    "{reason}"
                );
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
        assert!(e.evaluate_path(Access::Read, "/srv/app/.env").is_deny());
        assert!(!e
            .evaluate_path(Access::Read, "/home/u/.ssh/id_rsa")
            .is_deny());
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
        let e = Engine::new(packs).with_paths(PathVars::new().with_cwd("/p"));
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
            "cat $(echo .env)",
        ] {
            assert!(!e.evaluate(cmd).is_deny(), "expected ALLOW for {cmd:?}");
        }
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
        let files: Vec<String> = (0..5000).map(|i| format!("src/deep/dir/f{i}.rs")).collect();
        let cmd = format!("cat {} .env", files.join(" "));
        let t = Instant::now();
        let d = e.evaluate(&cmd);
        let took = t.elapsed();
        eprintln!("5000 operands: {took:?} -> {d:?}");
        // The cheap lexical pass sees `.env` before any syscall.
        assert!(d.is_deny(), "{d:?}");
        assert!(took < Duration::from_secs(2), "{took:?}");
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
        let e = Engine::new(packs).with_paths(PathVars::new().with_cwd(root.join("app")));
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
        let e = Engine::new(vec![load_pack_str("<t>", SEGMENT_PACK, &mut w).unwrap()]);
        assert!(e.evaluate("env").is_deny());
        assert!(e.evaluate("sudo env").is_deny());
        assert!(e.evaluate("echo a; env | sort").is_deny());
        assert!(!e.evaluate("env FOO=1 ls").is_deny());
        assert!(e.evaluate("gh auth token").is_deny());
    }

    #[test]
    fn substitution_failsafe_can_be_turned_off_per_pack() {
        let mut w = Vec::new();
        let e = Engine::new(vec![load_pack_str("<t>", SEGMENT_PACK, &mut w).unwrap()]);
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
