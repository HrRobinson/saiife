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
const INLINE_INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "python", "python3", "node", "ruby", "perl",
];

/// If `argv` is an interpreter invocation carrying a `-c <payload>` flag,
/// return the payload argument (the exact token right after `-c`) —
/// `argv[0]` must already be case-folded and directory-stripped, which the
/// engine does before calling this (so `/usr/bin/Bash -c '...'` is still
/// recognized). Returns `None` for anything else, including interpreter
/// invocations with no `-c`.
pub fn inline_payload(argv: &[String]) -> Option<String> {
    let prog = argv.first()?;
    if !INLINE_INTERPRETERS.contains(&prog.as_str()) {
        return None;
    }
    let idx = argv.iter().position(|a| a == "-c")?;
    argv.get(idx + 1).cloned()
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
}
