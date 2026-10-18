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

use crate::canon::{
    canonicalize, expand_operand_glob, lexical_form, path_forms, GlobExpansion, PathVars,
    GLOB_SCAN_LIMIT,
};
use crate::lexer::{
    find_all_substitution_kinds, literal_word, split_segments_noted, split_substitution_noted, Word,
};
use crate::normalize::build_argv;
use crate::operands::{operands, Operand, Source};
use crate::pack::Pack;
use crate::pathrule::{compile_ancestors, compile_glob, Access, RuleAccess};
use crate::payload::{inline_payload, watch_payload};
use crate::prefilter::Prefilter;
use crate::subst::{command_position_substitution, command_position_substitution_kind};
use crate::wrappers::{
    effective_command, is_env_assignment, unwrap_transparent_prefix, wrapper_reads,
};

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
    /// position policy — see `command_rules_phase`.
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
                    let compiled = if r.ancestors {
                        compile_ancestors(&r.glob, &self.vars, PATHS_CASE_INSENSITIVE)
                    } else {
                        compile_glob(&r.glob, &self.vars, PATHS_CASE_INSENSITIVE)
                    };
                    let regex = compiled.ok().flatten()?;
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
        let state = ShellState {
            cwds: self.vars.cwd().map(Path::to_path_buf).into_iter().collect(),
            cwd_unknown: false,
            env_changed: false,
            ifs_named: false,
        };
        self.evaluate_inner(raw_cmd, start, 0, &state, false)
    }

    /// `state`: the shell state at the start of `raw_cmd`; a nested
    /// evaluation inherits it. `sub_body`: `raw_cmd` is the body of a
    /// `$(…)` (lexed as bash lexes one: `split_substitution_noted`).
    fn evaluate_inner(
        &self,
        raw_cmd: &str,
        start: Instant,
        depth: u32,
        state: &ShellState,
        sub_body: bool,
    ) -> Decision {
        let mut state = state.clone();
        // The line names IFS somewhere (`IFS=: …`, `export IFS`, a
        // comment): values are still judged, the unresolved words too.
        state.ifs_named |= mentions_ifs(raw_cmd);
        let mut found = Findings::default();
        let (segments, lex_note) = if sub_body {
            split_substitution_noted(raw_cmd)
        } else {
            split_segments_noted(raw_cmd)
        };
        if let Some(reason) = lex_note {
            found.unjudged(reason);
        }
        let cx = Ctx {
            start,
            depth,
            literal_path: has_literal_path_ref(raw_cmd) || !path_refs_are_plain(raw_cmd, &segments),
        };

        for seg in segments {
            if start.elapsed() > self.budget {
                return timed_out();
            }
            if seg.is_empty() {
                continue;
            }
            if let Some(d) = self.evaluate_segment(&seg, &cx, &mut state, &mut found) {
                return d;
            }
        }
        found.finish()
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
        match self.command_position_phase(seg, effective, cx, state, found) {
            Flow::Proceed => {}
            Flow::NextSegment => return None,
            Flow::Done(d) => return Some(d),
        }
        if let Some(d) = self.embedded_substitutions_phase(seg, cx, state, found) {
            return Some(d);
        }
        let view = SegmentView::new(seg, effective, state, cx.literal_path, found);
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
        self.environment_phase(&view, cx, state);
        self.cd_phase(&view, state);
        self.inline_payload_phase(&view, cx, state, found)
    }

    /// The one place that enforces `MAX_INLINE_DEPTH`, the budget, and the
    /// "… nested too deeply to judge" note: judge `inner` as a command line
    /// of its own, one level deeper, with the shell state it inherits.
    /// `what` names the construct in that note.
    fn recurse(
        &self,
        inner: &str,
        start: Instant,
        depth: u32,
        state: &ShellState,
        sub_body: bool,
        what: &str,
    ) -> Nested {
        // Fail open (recorded) beyond the cap rather than recursing
        // unboundedly on adversarial nesting.
        if depth >= MAX_INLINE_DEPTH {
            return Nested::Unjudged(format!("{what} nested too deeply to judge"));
        }
        if start.elapsed() > self.budget {
            return Nested::TimedOut;
        }
        match self.evaluate_inner(inner, start, depth + 1, state, sub_body) {
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

    /// Command substitution occupying *command position* — the whole
    /// (unwrapped) segment, or the value of a leading `NAME=$(...)`
    /// assignment word: a real shell evaluates `$(...)`/`` `...` ``
    /// eagerly, so `$(rm -rf /)` runs `rm -rf /` for real regardless of
    /// what (if anything) consumes its output. There's no argv[0] here for
    /// a pack to match against — recurse into the substitution's inner text
    /// and judge that instead, the same structural re-entry used for inline
    /// `bash -c '...'` payloads (same depth cap, same budget).
    fn command_position_phase(
        &self,
        seg: &[Word],
        effective: &[Word],
        cx: &Ctx,
        state: &mut ShellState,
        found: &mut Findings,
    ) -> Flow {
        // A leading `NAME=$(…)` assignment in front of a real command
        // (`FOO=$(date) git reset --hard`) is not the command: the
        // command after it is judged below and the substitution by the
        // embedded-substitution scan.
        let substitution_is_the_command = {
            let rest = effective_command(effective);
            rest.is_empty()
                || rest.first().is_some_and(|w| {
                    command_position_substitution(rest).is_some() && w.has_substitution
                })
        };
        let Some((inner, dollar)) =
            command_position_substitution_kind(effective).filter(|_| substitution_is_the_command)
        else {
            return Flow::Proceed;
        };
        let nested = self.recurse(
            &inner,
            cx.start,
            cx.depth,
            state,
            dollar,
            "command substitution",
        );
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
                let nested = self.recurse(
                    &inner,
                    cx.start,
                    cx.depth,
                    state,
                    dollar,
                    "command substitution",
                );
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
            match self.judge(&view.peeled, &segment_line, view.env_changed, cx.start) {
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
            let judged = self.judge_operands(ops, &state.cwds, state.cwd_unknown, cx.start);
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
        if self.guarded_commands.contains(&argv[0])
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
                pattern: "guarded-command-substitution-argument".to_string(),
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
        match self.judge(matching_line, segment_line, view.env_changed, cx.start) {
            JudgeOutcome::Decided(d @ Decision::Deny { .. }) => Some(d),
            JudgeOutcome::Decided(Decision::Allow { trace }) => {
                found.allow_trace = Some(trace);
                None
            }
            JudgeOutcome::TimedOut => Some(timed_out()),
            JudgeOutcome::Clean => None,
        }
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
        let ops = self.shell_ops(
            &view.seg_ops,
            &view.resolved,
            &view.argv,
            view.reads.clone(),
        );
        let judged = self.judge_operands(ops, &state.cwds, state.cwd_unknown, cx.start);
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
                match self.judge(&line, view.segment_line(), view.env_changed, cx.start) {
                    JudgeOutcome::Decided(d @ Decision::Deny { .. }) => return Some(d),
                    JudgeOutcome::TimedOut => return Some(timed_out()),
                    _ => {}
                }
            }
            let ops = self.shell_ops(alt_seg, alt_eff, &alt_argv, view.reads.clone());
            let judged = self.judge_operands(ops, &state.cwds, state.cwd_unknown, cx.start);
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
        state: &ShellState,
        found: &mut Findings,
    ) -> Option<Decision> {
        if view.argv[0] != "eval" {
            return None;
        }
        let effective = &view.resolved;
        if effective.iter().any(|w| w.has_substitution) {
            found.unjudged("eval of a command substitution cannot be judged");
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
        found.nested(self.recurse(&inner, cx.start, cx.depth, state, false, "eval"))
    }

    /// A builtin that changes PATH, HOME or XDG_DATA_HOME changes them for
    /// the rest of the command line (and for nested evaluations).
    fn environment_phase(&self, view: &SegmentView, cx: &Ctx, state: &mut ShellState) {
        state.env_changed |= changes_environment(&view.argv, &view.resolved, cx.literal_path);
    }

    /// `cd`/`pushd`: the later segments may run in its target too.
    fn cd_phase(&self, view: &SegmentView, state: &mut ShellState) {
        if view.argv[0] == "cd" || view.argv[0] == "pushd" {
            state.cwd_unknown |= self.cd(&view.argv, &view.resolved, &mut state.cwds);
        }
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
        let inner = inline_payload(&view.argv).or_else(|| watch_payload(&view.argv))?;
        let nested = self.recurse(&inner, cx.start, cx.depth, state, false, "inline command");
        found.nested(nested)
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
        ops: Vec<Operand>,
        cwds: &[PathBuf],
        cwd_unknown: bool,
        start: Instant,
    ) -> Option<Decision> {
        if self.path_rules.is_empty() || ops.is_empty() {
            return None;
        }
        let all: Vec<Option<&Path>> = if cwds.is_empty() {
            vec![None]
        } else {
            cwds.iter().map(|c| Some(c.as_path())).collect()
        };
        // A path that does not depend on the working directory is judged
        // once.
        let absolute =
            |raw: &str| raw.starts_with('/') || raw.starts_with('~') || raw.starts_with("$HOME");
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
            // A copy target that may be a directory waits for pass 2.
            let landing = if op.into.is_empty() {
                vec![op.path.clone()]
            } else if op.path.ends_with('/') && op.into.iter().all(|s| !s.glob && !s.contents) {
                let names: Vec<String> =
                    op.into.iter().filter_map(|s| base_name(&s.path)).collect();
                into_dir(&op.path, &names)
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
                    match expand_operand_glob(&op.path, *cwd, &self.vars) {
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
    fn shell_ops(
        &self,
        seg: &[Word],
        effective: &[Word],
        argv: &[String],
        extra: Vec<Operand>,
    ) -> Vec<Operand> {
        if self.path_rules.is_empty() {
            return Vec::new();
        }
        let mut ops = operands(seg, effective, argv);
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
                match expand_operand_glob(&src.path, cwd, &self.vars) {
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
                    names.extend(base_name(&path));
                    continue;
                }
                let Some(dir) = canonicalize(&path, cwd, &self.vars) else {
                    continue;
                };
                let Ok(list) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for e in list.flatten() {
                    scanned += 1;
                    if scanned > GLOB_SCAN_LIMIT {
                        err = Some("copy source too large to judge".to_string());
                        break;
                    }
                    entries.push(e.file_name());
                }
            }
        }
        let is_dir = target.ends_with('/')
            || canonicalize(target, cwd, &self.vars).is_some_and(|p| p.is_dir());
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
    /// one that cannot be resolved, or more directories than `MAX_CWDS`.
    fn cd(&self, argv: &[String], effective: &[Word], cwds: &mut Vec<PathBuf>) -> bool {
        let arg = argv
            .iter()
            .zip(effective)
            .skip(1)
            .find(|(a, _)| !a.starts_with('-') || *a == "-");
        let (new, mut unknown): (Vec<PathBuf>, bool) = match arg {
            None => match self.vars.home() {
                Some(h) => (vec![h.to_path_buf()], false),
                None => (Vec::new(), true),
            },
            Some((a, w)) if a == "-" || w.has_substitution || a.contains('$') => (Vec::new(), true),
            Some((a, _)) => {
                let anchors: Vec<Option<&Path>> = if cwds.is_empty() {
                    vec![None]
                } else {
                    cwds.iter().map(|c| Some(c.as_path())).collect()
                };
                let resolved: Vec<Option<PathBuf>> = anchors
                    .into_iter()
                    .map(|c| canonicalize(a, c, &self.vars))
                    .collect();
                let unknown = resolved.iter().any(Option::is_none);
                (resolved.into_iter().flatten().collect(), unknown)
            }
        };
        for n in new {
            if cwds.contains(&n) {
                continue;
            }
            if cwds.len() >= MAX_CWDS {
                unknown = true;
                break;
            }
            cwds.push(n);
        }
        unknown
    }

    /// Run allow-before-deny across all packs for one segment. Rules match
    /// the effective command's line (its argv after wrappers like `sudo` are
    /// peeled off, case-folded/dir-stripped/slash-collapsed, joined with
    /// single spaces); `whole_segment` rules match the line of the whole
    /// segment, wrappers and leading assignments included. An empty
    /// `matching_line` (a bare wrapper) leaves only `whole_segment` rules.
    fn judge(
        &self,
        matching_line: &str,
        segment_line: &str,
        env_changed: bool,
        start: Instant,
    ) -> JudgeOutcome {
        let line = |rule: &crate::pack::Rule| -> Option<&str> {
            if rule.after_env_change {
                (env_changed && !matching_line.is_empty()).then_some(matching_line)
            } else if rule.whole_segment {
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

/// The last component of `path` (`a/b/` is `b`).
fn base_name(path: &str) -> Option<String> {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|b| !b.is_empty())
        .map(str::to_string)
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
    /// A `cd` went somewhere `cwds` does not hold (`cd $(…)`, `cd -`, an
    /// unresolvable target, or past `MAX_CWDS`).
    cwd_unknown: bool,
    /// An earlier segment changed PATH, HOME or XDG_DATA_HOME for the rest
    /// of the command line (and for nested evaluations).
    env_changed: bool,
    /// The line names IFS somewhere: values are still judged, the
    /// unresolved words too.
    ifs_named: bool,
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
struct Ctx {
    start: Instant,
    depth: u32,
    /// The line holds a path reference spelled out literally (see
    /// `has_literal_path_ref`, `path_refs_are_plain`).
    literal_path: bool,
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
    /// The whole segment's line, when it differs.
    whole: Option<String>,
}

impl<'a> SegmentView<'a> {
    fn new(
        seg: &'a [Word],
        effective: &'a [Word],
        state: &ShellState,
        literal_path: bool,
        found: &mut Findings,
    ) -> Self {
        // Leading assignments and redirections (`LANG=C sort f`,
        // `2>/dev/null cat f`) are not the command either.
        let effective = effective_command(effective);
        // An argument that is one substitution printing plain data
        // (`git commit -m "$(cat <<'EOF' … EOF)"`, `$(echo x)`) is
        // judged by its value, like any literal argument; its inner
        // command was judged above.
        // Words in front of the command (wrappers, assignments,
        // redirections), counted before the arguments are resolved.
        let prefix_len = seg.len() - effective.len();
        let (mut forms, args_unquoted) = resolve_forms(effective, false);
        // Redirection targets are resolved the same way.
        let (mut target_forms, targets_unquoted) = resolve_forms(seg, true);
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
        let reads: Vec<Operand> = wrapper_reads(seg)
            .into_iter()
            .map(|(path, glob)| Operand {
                path,
                access: Access::Read,
                glob,
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
            whole,
        }
    }

    /// The line `whole_segment` rules match.
    fn segment_line(&self) -> &str {
        self.whole.as_deref().unwrap_or(&self.matching_line)
    }
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
            "cat $(ls -t | head -1)",
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

    #[test]
    fn budget_overrun_fails_open_visibly() {
        // The budget path, taken by injecting a zero budget rather than a
        // heavy input: recorded as a fail-open, never a silent allow.
        let timeout = Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout,
        };
        let e = test_engine().with_budget(Duration::ZERO);
        assert_eq!(e.evaluate("git reset --hard"), timeout);
        let (_d, root) = canonical_tmp();
        std::fs::create_dir_all(root.join("app")).unwrap();
        let e = shell_path_engine(&root).with_budget(Duration::ZERO);
        assert_eq!(e.evaluate("cat .env"), timeout);
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
