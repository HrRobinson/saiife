//! Hook-payload parsing and inline `-c` extraction.
//!
//! `command_from_hook_json` pulls the proposed command out of an agent
//! PreToolUse-shaped JSON payload (Claude Code delivers this on stdin to a
//! `PreToolUse` hook). Unknown shapes and oversize input return `Err` so the
//! caller can fail open.
//!
//! `inline_payload` handles the common obfuscation shape where a real command
//! is smuggled inside `bash -c '…'` / `sh -c "…"` / `python -c '…'`. It used
//! to be a regex scan over raw text; now that the engine tokenizes the whole
//! line first, this is a structural check over an already-resolved `argv`
//! instead — which is strictly more correct, since it works the same
//! regardless of which quoting style wrapped the payload (the tokenizer
//! already resolved that), and it composes with re-lexing: the caller
//! re-runs the whole pipeline on the extracted string, so a payload smuggled
//! behind a layer of quoting the *outer* lexer could not see into (e.g. a
//! single-quoted outer argument containing a further-quoted inner command)
//! is still caught once the inner string is lexed on its own.

use serde_json::Value;

/// Hard cap on hook-payload size. Anything larger is refused (fail open) rather
/// than parsed — a guard must not become a memory amplifier.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    #[error("payload exceeds {MAX_PAYLOAD_BYTES} bytes")]
    TooLarge,
    #[error("payload is not valid JSON: {0}")]
    Json(String),
    #[error("no command found in hook payload")]
    NoCommand,
}

/// Extract the command string from a PreToolUse-shaped hook payload.
///
/// Tolerant of shape: it looks for the Bash tool's `command` under
/// `tool_input`/`toolInput`/`input`/`params`, then falls back to a top-level
/// `command`. Anything it cannot find yields `NoCommand` (caller fails open).
pub fn command_from_hook_json(input: &str, max_bytes: usize) -> Result<String, PayloadError> {
    if input.len() > max_bytes {
        return Err(PayloadError::TooLarge);
    }
    let v: Value = serde_json::from_str(input).map_err(|e| PayloadError::Json(e.to_string()))?;

    for container in ["tool_input", "toolInput", "input", "params"] {
        if let Some(cmd) = v
            .get(container)
            .and_then(|c| c.get("command"))
            .and_then(Value::as_str)
        {
            if !cmd.trim().is_empty() {
                return Ok(cmd.to_string());
            }
        }
    }
    if let Some(cmd) = v.get("command").and_then(Value::as_str) {
        if !cmd.trim().is_empty() {
            return Ok(cmd.to_string());
        }
    }
    Err(PayloadError::NoCommand)
}

/// Interpreters whose `-c <payload>` invocation smuggles a real command line.
///
/// `su` belongs here, NOT in `wrappers::TRANSPARENT_PREFIXES`: its first
/// operand is a *username* (`su root` means "become root", not "run `root`"),
/// so a blind prefix-skip would misread it. The wrapped command is only ever
/// the single string behind `-c` (`su root -c 'rm -rf /'`) — exactly the
/// `bash -c '…'` shape this path already handles, wherever the username or
/// login options sit relative to `-c`. util-linux `su` additionally accepts
/// the long form `--command COMMAND` (separate token) or `--command=COMMAND`
/// (attached) as an alias for `-c` — see `inline_payload`.
const INLINE_INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "python", "python3", "node", "ruby", "perl", "su",
];

/// If `argv` is an interpreter invocation carrying a `-c <payload>` flag,
/// return the payload argument. For most interpreters this is the exact
/// token right after `-c`; `su` additionally recognizes the long-form alias
/// `--command COMMAND` (separate token) and `--command=COMMAND` (attached) —
/// gated to `su` specifically, since no other `INLINE_INTERPRETERS` entry has
/// a `--command` flag, so this cannot create a false positive for `bash`,
/// `sh`, `python`, etc. `argv[0]` must already be case-folded and
/// directory-stripped, which the engine does before calling this (so
/// `/usr/bin/Bash -c '...'` is still recognized). Returns `None` for anything
/// else, including interpreter invocations with no `-c`/`--command`.
pub fn inline_payload(argv: &[String]) -> Option<String> {
    let prog = argv.first()?;
    if !INLINE_INTERPRETERS.contains(&prog.as_str()) {
        return None;
    }
    if prog == "su" {
        for (i, a) in argv.iter().enumerate() {
            if let Some(val) = a.strip_prefix("--command=") {
                return Some(val.to_string());
            }
            if a == "--command" {
                return argv.get(i + 1).cloned();
            }
        }
    }
    let idx = argv.iter().position(|a| a == "-c")?;
    argv.get(idx + 1).cloned()
}

/// If `argv` is a `watch [OPTIONS] COMMAND [ARG]…` invocation, return the
/// wrapped command line so the caller can recurse into it.
///
/// `watch` joins its remaining arguments with spaces and runs the result via
/// `sh -c`, so both `watch rm -rf /` (multi-token) and `watch 'rm -rf /'`
/// (single quoted string) mean the same thing; joining-and-recursing is
/// faithful to that and covers both forms uniformly. Leading options are
/// skipped, consuming the separate value token of `-n`/`--interval`; attached
/// forms (`-n5`, `--interval=5`) are a single token. `argv[0]` must already be
/// case-folded/dir-stripped (the engine does this before calling). Returns
/// `None` for a non-`watch` argv or one with no command after its options.
pub fn watch_payload(argv: &[String]) -> Option<String> {
    if argv.first().map(String::as_str) != Some("watch") {
        return None;
    }
    let mut rest = &argv[1..];
    while let Some(tok) = rest.first() {
        if !tok.starts_with('-') || tok == "-" {
            break; // start of the command.
        }
        if tok == "--" {
            rest = &rest[1..];
            break;
        }
        if tok == "-n" || tok == "--interval" {
            // Separate-token value form: consume the flag and its value.
            rest = &rest[1..];
            if !rest.is_empty() {
                rest = &rest[1..];
            }
            continue;
        }
        // Any other option (boolean, bundled, or attached value like `-n5`)
        // is a single token.
        rest = &rest[1..];
    }
    if rest.is_empty() {
        return None;
    }
    Some(rest.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_claude_pretooluse_bash_command() {
        let json = r#"{
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "git reset --hard", "description": "reset" }
        }"#;
        assert_eq!(
            command_from_hook_json(json, MAX_PAYLOAD_BYTES).unwrap(),
            "git reset --hard"
        );
    }

    #[test]
    fn top_level_command_fallback() {
        let json = r#"{ "command": "rm -rf /tmp/x" }"#;
        assert_eq!(
            command_from_hook_json(json, MAX_PAYLOAD_BYTES).unwrap(),
            "rm -rf /tmp/x"
        );
    }

    #[test]
    fn oversize_is_refused() {
        let big = format!(r#"{{"command":"{}"}}"#, "a".repeat(100));
        let err = command_from_hook_json(&big, 20).unwrap_err();
        assert!(matches!(err, PayloadError::TooLarge));
    }

    #[test]
    fn malformed_json_errors() {
        let err = command_from_hook_json("{not json", MAX_PAYLOAD_BYTES).unwrap_err();
        assert!(matches!(err, PayloadError::Json(_)));
    }

    #[test]
    fn no_command_errors() {
        let err = command_from_hook_json(r#"{"tool_name":"Read"}"#, MAX_PAYLOAD_BYTES).unwrap_err();
        assert!(matches!(err, PayloadError::NoCommand));
    }

    #[test]
    fn extracts_single_quoted_payload() {
        let argv = vec!["bash".to_string(), "-c".to_string(), "rm -rf /".to_string()];
        assert_eq!(inline_payload(&argv), Some("rm -rf /".to_string()));
    }

    #[test]
    fn extracts_double_quoted_payload() {
        let argv = vec![
            "python3".to_string(),
            "-c".to_string(),
            "git reset --hard".to_string(),
        ];
        assert_eq!(inline_payload(&argv), Some("git reset --hard".to_string()));
    }

    #[test]
    fn no_inline_payload_when_not_an_interpreter() {
        let argv = vec!["git".to_string(), "status".to_string()];
        assert_eq!(inline_payload(&argv), None);
    }

    #[test]
    fn no_inline_payload_when_no_dash_c() {
        let argv = vec!["bash".to_string(), "script.sh".to_string()];
        assert_eq!(inline_payload(&argv), None);
    }

    #[test]
    fn dash_c_with_nothing_after_it_yields_none() {
        let argv = vec!["bash".to_string(), "-c".to_string()];
        assert_eq!(inline_payload(&argv), None);
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn su_dash_c_payload_is_extracted() {
        // The wrapped command is always the single string right after `-c`,
        // wherever su's username/options sit.
        assert_eq!(
            inline_payload(&argv(&["su", "-c", "rm -rf /"])),
            Some("rm -rf /".to_string())
        );
        assert_eq!(
            inline_payload(&argv(&["su", "root", "-c", "rm -rf /"])),
            Some("rm -rf /".to_string())
        );
        assert_eq!(
            inline_payload(&argv(&["su", "-", "-c", "rm -rf /"])),
            Some("rm -rf /".to_string())
        );
        assert_eq!(
            inline_payload(&argv(&["su", "-l", "root", "-c", "git reset --hard"])),
            Some("git reset --hard".to_string())
        );
    }

    #[test]
    fn su_dash_dash_command_payload_is_extracted() {
        // util-linux `su` also accepts `--command COMMAND` (separate token)
        // and `--command=COMMAND` (attached) as an alias for `-c`.
        assert_eq!(
            inline_payload(&argv(&["su", "--command", "rm -rf /"])),
            Some("rm -rf /".to_string())
        );
        assert_eq!(
            inline_payload(&argv(&["su", "--command=rm -rf /"])),
            Some("rm -rf /".to_string())
        );
        assert_eq!(
            inline_payload(&argv(&["su", "-l", "root", "--command", "rm -rf /"])),
            Some("rm -rf /".to_string())
        );
    }

    #[test]
    fn dash_dash_command_is_not_recognized_for_other_interpreters() {
        // `--command` is a `su`-specific alias for `-c`; other
        // INLINE_INTERPRETERS entries have no such flag, so it must not be
        // treated as a payload marker for them.
        assert_eq!(
            inline_payload(&argv(&["bash", "--command", "rm -rf /"])),
            None
        );
        assert_eq!(
            inline_payload(&argv(&["python3", "--command=rm -rf /"])),
            None
        );
    }

    #[test]
    fn watch_payload_multi_token_and_single_string() {
        assert_eq!(
            watch_payload(&argv(&["watch", "rm", "-rf", "/"])),
            Some("rm -rf /".to_string())
        );
        // single quoted string arrives as one token
        assert_eq!(
            watch_payload(&argv(&["watch", "rm -rf /"])),
            Some("rm -rf /".to_string())
        );
    }

    #[test]
    fn watch_payload_skips_interval_option() {
        assert_eq!(
            watch_payload(&argv(&["watch", "-n", "5", "rm", "-rf", "/"])),
            Some("rm -rf /".to_string())
        );
        assert_eq!(
            watch_payload(&argv(&["watch", "-n5", "rm", "-rf", "/"])),
            Some("rm -rf /".to_string())
        );
        assert_eq!(
            watch_payload(&argv(&["watch", "--interval=5", "df", "-h"])),
            Some("df -h".to_string())
        );
    }

    #[test]
    fn watch_payload_none_for_non_watch_or_no_command() {
        assert_eq!(watch_payload(&argv(&["git", "status"])), None);
        assert_eq!(watch_payload(&argv(&["watch"])), None);
        assert_eq!(watch_payload(&argv(&["watch", "-n", "5"])), None);
    }

    #[test]
    fn su_without_dash_c_is_not_a_payload() {
        // `su rm` must NOT be read as running `rm` (su's first operand is a
        // username, not a command); `su root` opens an interactive shell.
        assert_eq!(inline_payload(&argv(&["su", "rm"])), None);
        assert_eq!(inline_payload(&argv(&["su", "root"])), None);
        assert_eq!(inline_payload(&argv(&["su"])), None);
    }
}
