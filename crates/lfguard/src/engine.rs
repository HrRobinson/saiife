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
use std::time::{Duration, Instant};

use crate::lexer::{find_all_substitutions, split_segments};
use crate::normalize::build_argv;
use crate::pack::Pack;
use crate::payload::{inline_payload, watch_payload};
use crate::prefilter::Prefilter;
use crate::subst::command_position_substitution;
use crate::wrappers::unwrap_transparent_prefix;

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
const SUBSTITUTION_GUARD_PACK: &str = "lfguard.core";

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
}

impl Engine {
    /// Build an engine from loaded packs.
    pub fn new(packs: Vec<Pack>) -> Self {
        let triggers: Vec<String> = packs.iter().flat_map(|p| p.triggers.clone()).collect();
        let guarded_commands = packs
            .iter()
            .filter(|p| !p.deny.is_empty())
            .flat_map(|p| p.triggers.iter())
            .filter(|t| looks_like_bare_command_name(t))
            .map(|t| t.to_ascii_lowercase())
            .collect();
        Self {
            combined: Prefilter::new(triggers),
            packs,
            budget: DEFAULT_BUDGET,
            guarded_commands,
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
        self.evaluate_inner(raw_cmd, start, 0)
    }

    fn evaluate_inner(&self, raw_cmd: &str, start: Instant, depth: u32) -> Decision {
        let mut allow_trace: Option<AllowTrace> = None;

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
                    match self.evaluate_inner(&inner, start, depth + 1) {
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
                            allow_trace = Some(trace);
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
                    match self.evaluate_inner(&inner, start, depth + 1) {
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
                            allow_trace = Some(trace);
                        }
                    }
                }
            }

            let argv = build_argv(effective);
            if argv.is_empty() || argv[0].is_empty() {
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
            if self.combined.might_match(&matching_line) {
                match self.judge(&matching_line, start) {
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
                    match self.evaluate_inner(&inner, start, depth + 1) {
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
                        allow @ Decision::Allow {
                            trace: AllowTrace::AllowRule { .. },
                        } => return allow,
                        Decision::Allow {
                            trace: AllowTrace::FailedOpenTimeout,
                        } => {
                            return Decision::Allow {
                                trace: AllowTrace::FailedOpenTimeout,
                            }
                        }
                        Decision::Allow {
                            trace: AllowTrace::NoMatch,
                        } => {}
                    }
                }
            }
        }

        Decision::Allow {
            trace: allow_trace.unwrap_or(AllowTrace::NoMatch),
        }
    }

    /// Run allow-before-deny across all packs for one segment's matching
    /// line (its argv, case-folded/dir-stripped/slash-collapsed, joined
    /// with single spaces).
    fn judge(&self, matching_line: &str, start: Instant) -> JudgeOutcome {
        for pack in &self.packs {
            if start.elapsed() > self.budget {
                return JudgeOutcome::TimedOut;
            }
            if !pack.prefilter().might_match(matching_line) {
                continue;
            }
            // Allow rules first — a match short-circuits to ALLOW.
            for rule in &pack.allow {
                if rule.regex.is_match(matching_line) {
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
                if rule.regex.is_match(matching_line) {
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
