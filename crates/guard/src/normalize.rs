//! Post-tokenization normalization.
//!
//! The `lexer` module resolves quoting, escaping, and adjacent-string
//! concatenation into structured words — that used to be `normalize`'s job
//! (via ad-hoc, non-shell-aware quote stripping) and it is gone from here.
//! What is left is genuinely semantic canonicalization applied to the
//! already-resolved argv:
//!
//! - **argv[0] case-folding**: the command name is lower-cased for matching
//!   purposes (so `RM -RF /` and `Git reset --hard` are caught — macOS's
//!   case-insensitive filesystem resolves `RM` to the same binary as `rm`).
//!   Only the command token is folded; arguments are matching-sensitive and
//!   are left exactly as the lexer resolved them.
//! - **argv[0] directory stripping**: `/usr/bin/git` -> `git`, so rules match
//!   the tool name regardless of how it was invoked. Only the program token
//!   is stripped; a path *argument* (e.g. `rm -rf /var/data`) is untouched.
//! - **Leading-slash collapsing** on non-program tokens: `//`, `///etc` are
//!   the same target as `/`, `/etc`; packs should not have to spell out
//!   every repeated-slash spelling of a catastrophic path.

use crate::lexer::Word;

/// Build the matching argv for one segment: `argv[0]` case-folded and
/// directory-stripped, every other token with its leading slashes collapsed.
/// This is what pack regexes are matched against (joined with single
/// spaces) and what the tokenizer-aware checks (case-fold, command
/// substitution in a guarded position) operate on.
pub fn build_argv(words: &[Word]) -> Vec<String> {
    words
        .iter()
        .enumerate()
        .map(|(i, w)| {
            if i == 0 {
                strip_program_dir(&w.text.to_lowercase())
            } else {
                collapse_leading_slashes(&w.text)
            }
        })
        .collect()
}

/// Strip a leading directory from the program token only. A token with no
/// path separator is returned unchanged.
fn strip_program_dir(program: &str) -> String {
    match program.rfind('/') {
        Some(idx) => program[idx + 1..].to_string(),
        None => program.to_string(),
    }
}

/// Collapse a run of leading slashes on a token to a single slash
/// (`//`, `///etc` are the same path as `/`, `/etc`). Tokens that don't
/// start with `/` are returned unchanged.
fn collapse_leading_slashes(tok: &str) -> String {
    match tok.strip_prefix('/') {
        Some(rest) => format!("/{}", rest.trim_start_matches('/')),
        None => tok.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Word {
        Word {
            text: text.to_string(),
            has_substitution: false,
        }
    }

    #[test]
    fn case_folds_only_the_program_token() {
        let argv = build_argv(&[w("RM"), w("-RF"), w("/")]);
        assert_eq!(argv, vec!["rm", "-RF", "/"]);
    }

    #[test]
    fn strips_absolute_program_path() {
        let argv = build_argv(&[w("/usr/bin/git"), w("status")]);
        assert_eq!(argv, vec!["git", "status"]);
    }

    #[test]
    fn strips_relative_program_path() {
        let argv = build_argv(&[w("./scripts/deploy.sh"), w("--now")]);
        assert_eq!(argv, vec!["deploy.sh", "--now"]);
    }

    #[test]
    fn preserves_path_arguments() {
        let argv = build_argv(&[w("rm"), w("-rf"), w("/var/data")]);
        assert_eq!(argv, vec!["rm", "-rf", "/var/data"]);
    }

    #[test]
    fn collapses_repeated_leading_slashes_on_arguments_only() {
        let argv = build_argv(&[w("rm"), w("-rf"), w("//")]);
        assert_eq!(argv, vec!["rm", "-rf", "/"]);
        let argv = build_argv(&[w("rm"), w("-rf"), w("///etc")]);
        assert_eq!(argv, vec!["rm", "-rf", "/etc"]);
    }

    #[test]
    fn program_case_fold_and_dir_strip_compose() {
        let argv = build_argv(&[w("/USR/BIN/GIT"), w("Reset"), w("--Hard")]);
        assert_eq!(argv, vec!["git", "Reset", "--Hard"]);
    }

    #[test]
    fn empty_words_is_empty_argv() {
        let argv = build_argv(&[]);
        assert!(argv.is_empty());
    }
}
