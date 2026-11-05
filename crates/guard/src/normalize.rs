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
use crate::wrappers::effective_command;

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

/// A Windows-style host: each program word of a segment as the name it runs,
/// here and past every wrapper (`sudo.exe env rm.EXE`). Every phase after this
/// reads word text as a POSIX name (the wrappers, the rules, `operands`, `bash
/// -c`), so the word itself changes. Each pass starts where the last stopped, so
/// a long chain of wrappers stays linear.
pub fn windows_program_names(seg: &mut [Word]) {
    let mut from = 0;
    while from < seg.len() {
        let at = seg.len() - effective_command(&seg[from..]).len();
        let Some(w) = seg.get_mut(at) else {
            return;
        };
        if w.has_substitution || w.redirect {
            return;
        }
        let Some(name) = windows_program_text(&w.text) else {
            return;
        };
        w.text = name;
        from = at;
    }
}

/// `text` as a program name on Windows, if that differs: `/` for `\\`, no
/// extension `.exe`, `.cmd`, `.bat` or `.com` (in any case), and none of what
/// Win32 ignores at the end of a name: dots, blanks, a stream (`rm.exe::$DATA`).
/// A name that is only that (`.exe`, `.`, `..`) stays: `.` is a command.
fn windows_program_text(text: &str) -> Option<String> {
    let forward = text.replace('\\', "/");
    let (dir, file) = match forward.rfind('/') {
        Some(at) => forward.split_at(at + 1),
        None => ("", forward.as_str()),
    };
    // `C:rm.exe`: the drive is no stream.
    let (drive, file) = match file.as_bytes() {
        [letter, b':', ..] if dir.is_empty() && letter.is_ascii_alphabetic() => file.split_at(2),
        _ => ("", file),
    };
    let file = file.split(':').next().unwrap_or(file);
    let name = file.trim_end_matches(['.', ' ']);
    let stem = match name.rfind('.') {
        Some(at)
            if at > 0
                && [".exe", ".cmd", ".bat", ".com"]
                    .iter()
                    .any(|e| name[at..].eq_ignore_ascii_case(e)) =>
        {
            &name[..at]
        }
        _ => name,
    };
    let stem = if stem.is_empty() { file } else { stem };
    // A drive stands for a directory: `build_argv` drops it with the rest.
    let sep = if drive.is_empty() { "" } else { "/" };
    let out = format!("{dir}{drive}{sep}{stem}");
    (out != text).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(text: &str) -> Word {
        Word {
            text: text.to_string(),
            has_substitution: false,
            ..Default::default()
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
    fn a_windows_program_loses_what_windows_ignores() {
        for (text, want) in [
            ("rm.exe", "rm"),
            ("RM.EXE", "RM"),
            ("git.Cmd", "git"),
            ("x.bat", "x"),
            ("format.com", "format"),
            (r"C:\Git\usr\bin\rm.exe", "C:/Git/usr/bin/rm"),
            ("/usr/bin/rm.exe", "/usr/bin/rm"),
            ("./rm.exe", "./rm"),
            ("rm.exe.", "rm"),
            ("rm.exe ", "rm"),
            ("rm.exe::$DATA", "rm"),
            ("C:rm.exe", "C:/rm"),
            // Only one extension: `a.exe.exe` is the file `a.exe`.
            ("a.exe.exe", "a.exe"),
        ] {
            assert_eq!(windows_program_text(text).as_deref(), Some(want), "{text}");
        }
        for text in [
            "rm", ".exe", ".cmd", ".", "..", "x.txt", "x.ps1", "a/b", "./x",
        ] {
            assert_eq!(windows_program_text(text), None, "{text}");
        }
    }

    #[test]
    fn program_names_are_stripped_past_wrappers_only() {
        let mut seg = vec![
            w("sudo.exe"),
            w("-u"),
            w("x.exe"),
            w("env.EXE"),
            w("A=b.exe"),
            w("rm.cmd"),
            w("c.exe"),
        ];
        windows_program_names(&mut seg);
        let texts: Vec<&str> = seg.iter().map(|w| w.text.as_str()).collect();
        assert_eq!(
            texts,
            ["sudo", "-u", "x.exe", "env", "A=b.exe", "rm", "c.exe"]
        );
    }

    #[test]
    fn empty_words_is_empty_argv() {
        let argv = build_argv(&[]);
        assert!(argv.is_empty());
    }
}
