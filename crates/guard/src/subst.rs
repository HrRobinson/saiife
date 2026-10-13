//! Command substitution occupying *command position*.
//!
//! The engine's existing guarded-argument fail-safe (see `engine.rs`) only
//! covers `$(...)`/`` `...` `` appearing as an *argument* to an
//! already-guarded command (`rm -rf $(x)`) — it never asks whether the
//! substitution itself is standing in for the command. But a real shell
//! evaluates `$(...)`/`` `...` `` eagerly, before anything about "is this a
//! guarded command" is decided: `$(rm -rf /)` runs `rm -rf /` for its
//! output (discarded, since the surrounding line has no other content to
//! consume it) exactly as if it had been typed directly. Left unhandled,
//! that's a full bypass — the segment's only "command" is the opaque
//! substitution token, no pack's argv[0]-anchored regex has anything to
//! match, and the command runs for real, unjudged.
//!
//! `command_position_substitution` recognizes the shapes where a
//! substitution fills that role:
//! - the whole segment is one substitution: `$(rm -rf /)`, `` `rm -rf /` ``;
//! - it is the value of a leading `NAME=$(...)` assignment word, itself
//!   possibly preceded by further plain `NAME=val` assignment words:
//!   `FOO=$(rm -rf /)`, `FOO=bar BAZ=$(rm -rf /)`.
//!
//! The caller (`engine::evaluate_inner`) re-enters the whole pipeline on the
//! extracted inner text — the same recursive-judging shape already used for
//! `bash -c '...'` inline payloads, including its depth cap and latency
//! budget, so nested substitutions (`$( $(rm -rf /) )`) resolve for free
//! (each layer is a fresh call that re-lexes and re-detects) and adversarial
//! nesting still fails open rather than stalling or overflowing the stack.
//!
//! Deliberately narrow: this only detects a substitution *replacing* the
//! command name, not one merely concatenated into it (`pre$(cmd)post` is
//! left alone here — real shells behave very differently there depending on
//! what the substitution expands to, and guessing is out of scope, matching
//! the project's "static token structure only" stance elsewhere).
//!
//! This module only ever handles the command-position shape. A substitution
//! anywhere *else* in a segment — an argument to a guarded or unguarded
//! command, or one merely concatenated into a larger word (including the
//! `pre$(cmd)post` shape this module skips) — is handled separately by
//! `crate::lexer::find_all_substitutions`, called directly from the engine
//! for every word in the segment. The two are complementary, not
//! overlapping: the engine tries this module's whole-segment/assignment
//! check first (and `continue`s the segment on a match, since there is no
//! literal argv[0] left to judge), then falls through to the more general
//! any-position scan only when this one found nothing.

use crate::lexer::{pure_substitution_body, Word};

/// If `seg`'s effective command position is filled by a command
/// substitution, return its raw, unevaluated inner text so the caller can
/// recurse into it. `seg` should already have transparent wrappers
/// (`sudo`, `env`, `command`, …) peeled off, so `sudo $(rm -rf /)` and
/// `env FOO=bar $(rm -rf /)` are covered the same as the bare form.
pub fn command_position_substitution(seg: &[Word]) -> Option<String> {
    for word in seg {
        match assignment_value(&word.text) {
            Some(value) => {
                if let Some(inner) = pure_substitution_body(value) {
                    return Some(inner);
                }
                // A plain `NAME=val` assignment (or a shape more complex
                // than a pure substitution value, e.g. `NAME=pre$(x)post`,
                // which is out of scope — see module docs): keep scanning
                // in case a later word is the real command-position
                // substitution.
                continue;
            }
            None => {
                // Not an assignment word: this is the effective command.
                // It's either a pure substitution (return it) or a real
                // command name (nothing to recurse into) — either way, the
                // search ends here; a substitution can never occupy command
                // position *behind* a real command word.
                return pure_substitution_body(&word.text);
            }
        }
    }
    None
}

/// If `tok` is a `NAME=value` shell-assignment word, return `value` (the
/// text after the first `=`). Mirrors `wrappers::is_env_assignment`'s
/// notion of a valid assignment name (alphanumeric/`_`, not starting with a
/// digit).
fn assignment_value(tok: &str) -> Option<&str> {
    let idx = tok.find('=')?;
    if idx == 0 {
        return None;
    }
    let name = &tok[..idx];
    let valid_name = name
        .chars()
        .next()
        .map(|c| c.is_ascii_alphabetic() || c == '_')
        .unwrap_or(false)
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if valid_name {
        Some(&tok[idx + 1..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Word {
        Word {
            text: text.to_string(),
            has_substitution: text.contains("$(") || text.contains('`'),
        }
    }

    #[test]
    fn bare_dollar_paren_segment() {
        let seg = vec![w("$(rm -rf /)")];
        assert_eq!(
            command_position_substitution(&seg),
            Some("rm -rf /".to_string())
        );
    }

    #[test]
    fn bare_backtick_segment() {
        let seg = vec![w("`rm -rf /`")];
        assert_eq!(
            command_position_substitution(&seg),
            Some("rm -rf /".to_string())
        );
    }

    #[test]
    fn assignment_prefixed_dollar_paren() {
        for seg in [vec![w("FOO=$(rm -rf /)")], vec![w("x=$(rm -rf /)")]] {
            assert_eq!(
                command_position_substitution(&seg),
                Some("rm -rf /".to_string())
            );
        }
    }

    #[test]
    fn multiple_leading_plain_assignments_then_substitution() {
        let seg = vec![w("FOO=bar"), w("BAZ=$(rm -rf /)")];
        assert_eq!(
            command_position_substitution(&seg),
            Some("rm -rf /".to_string())
        );
    }

    #[test]
    fn nested_substitution_stays_raw_for_the_caller_to_recurse_into() {
        let seg = vec![w("$(echo $(date))")];
        assert_eq!(
            command_position_substitution(&seg),
            Some("echo $(date)".to_string())
        );
    }

    #[test]
    fn real_command_word_is_not_a_substitution() {
        assert_eq!(command_position_substitution(&[w("rm"), w("-rf"), w("/")]), None);
    }

    #[test]
    fn plain_assignment_only_with_no_command_yields_none() {
        assert_eq!(command_position_substitution(&[w("FOO=bar")]), None);
    }

    #[test]
    fn substitution_as_an_argument_is_not_command_position() {
        // `rm` is the real command; `$(x)` is an argument, not command
        // position — this function must not treat it as one (the engine's
        // separate guarded-argument fail-safe handles that case).
        let seg = vec![w("rm"), w("-rf"), w("$(x)")];
        assert_eq!(command_position_substitution(&seg), None);
    }

    #[test]
    fn concatenated_substitution_is_not_pure() {
        // `$(rm -rf /)suffix` is a substitution glued to trailing text, not
        // a pure command-position substitution — out of scope (see module
        // docs), and must not be treated as one.
        let seg = vec![w("$(rm -rf /)suffix")];
        assert_eq!(command_position_substitution(&seg), None);
    }

    #[test]
    fn assignment_with_non_pure_value_keeps_scanning() {
        let seg = vec![w("FOO=pre$(rm -rf /)post"), w("$(rm -rf /)")];
        assert_eq!(
            command_position_substitution(&seg),
            Some("rm -rf /".to_string())
        );
    }

    #[test]
    fn empty_segment_yields_none() {
        assert_eq!(command_position_substitution(&[]), None);
    }
}
