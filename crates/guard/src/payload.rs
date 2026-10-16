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

use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer};

/// Hard cap on hook-payload size. Anything larger is refused (fail open) rather
/// than parsed — a guard must not become a memory amplifier.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    #[error("payload exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("payload is not valid JSON: {0}")]
    Json(String),
    #[error("no command found in hook payload")]
    NoCommand,
}

/// A string field of the wrong type is absent, not an error.
fn lenient_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum L {
        S(String),
        Other(IgnoredAny),
    }
    Ok(match L::deserialize(d)? {
        L::S(s) => Some(s),
        L::Other(_) => None,
    })
}

/// A list of strings; anything else is absent.
fn lenient_list<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum L {
        List(Vec<String>),
        Other(IgnoredAny),
    }
    Ok(match L::deserialize(d)? {
        L::List(v) => Some(v),
        L::Other(_) => None,
    })
}

/// An object of the wrong type is absent, not an error.
fn lenient_object<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum L<T> {
        Obj(T),
        Other(IgnoredAny),
    }
    Ok(match L::<T>::deserialize(d)? {
        L::Obj(t) => Some(t),
        L::Other(_) => None,
    })
}

/// `include` is a string for Gemini `grep_search` and a list for
/// `read_many_files`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Include {
    One(String),
    Many(Vec<String>),
    Other(IgnoredAny),
}

impl Default for Include {
    fn default() -> Self {
        Include::Other(IgnoredAny)
    }
}

/// The parts of `tool_input` the guard reads. Everything else (a `Write`'s
/// `content`, an `Edit`'s `new_string`, `edits`, ...) is skipped while
/// parsing and never copied, so judging does not depend on how large it is.
#[derive(Debug, Default, Deserialize)]
struct ToolInput {
    #[serde(default, deserialize_with = "lenient_string")]
    command: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    input: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    file_path: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    notebook_path: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    path: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    dir_path: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    glob: Option<String>,
    #[serde(default)]
    include: Include,
    #[serde(default, deserialize_with = "lenient_list")]
    paths: Option<Vec<String>>,
}

/// The parts of a hook payload the guard reads.
#[derive(Debug, Default, Deserialize)]
struct Envelope {
    #[serde(default, deserialize_with = "lenient_string")]
    tool_name: Option<String>,
    #[serde(default, rename = "toolName", deserialize_with = "lenient_string")]
    tool_name_camel: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    session_id: Option<String>,
    #[serde(default, rename = "sessionId", deserialize_with = "lenient_string")]
    session_id_camel: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    cwd: Option<String>,
    #[serde(default, deserialize_with = "lenient_string")]
    command: Option<String>,
    #[serde(default, deserialize_with = "lenient_object")]
    tool_input: Option<ToolInput>,
    #[serde(default, rename = "toolInput", deserialize_with = "lenient_object")]
    tool_input_camel: Option<ToolInput>,
    #[serde(default, deserialize_with = "lenient_object")]
    input: Option<ToolInput>,
    #[serde(default, deserialize_with = "lenient_object")]
    params: Option<ToolInput>,
}

fn envelope(input: &str, max_bytes: usize) -> Result<Envelope, PayloadError> {
    if input.len() > max_bytes {
        return Err(PayloadError::TooLarge { limit: max_bytes });
    }
    serde_json::from_str(input).map_err(|e| PayloadError::Json(e.to_string()))
}

impl Envelope {
    fn tool(&self) -> Option<&str> {
        [&self.tool_name, &self.tool_name_camel]
            .into_iter()
            .find_map(|t| t.as_deref())
            .filter(|t| !t.is_empty())
    }

    fn command(&self) -> Result<String, PayloadError> {
        let containers = [
            &self.tool_input,
            &self.tool_input_camel,
            &self.input,
            &self.params,
        ];
        for c in containers.into_iter().flatten() {
            if let Some(cmd) = c.command.as_deref().filter(|c| !c.trim().is_empty()) {
                return Ok(cmd.to_string());
            }
        }
        match self.command.as_deref().filter(|c| !c.trim().is_empty()) {
            Some(cmd) => Ok(cmd.to_string()),
            None => Err(PayloadError::NoCommand),
        }
    }
}

/// Extract the command string from a PreToolUse-shaped hook payload.
///
/// Tolerant of shape: it looks for the Bash tool's `command` under
/// `tool_input`/`toolInput`/`input`/`params`, then falls back to a top-level
/// `command`. Anything it cannot find yields `NoCommand` (caller fails open).
pub fn command_from_hook_json(input: &str, max_bytes: usize) -> Result<String, PayloadError> {
    envelope(input, max_bytes)?.command()
}

/// What a hook call asks to do, by kind of tool. Shell commands go to the
/// command guard; file tools carry the path(s) they touch (judged by path
/// rules from plan 3 on); anything else is recorded but not judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCall {
    Shell {
        command: String,
    },
    File {
        tool: String,
        paths: Vec<String>,
        write: bool,
    },
    Other {
        tool: String,
    },
}

/// Shell tools: Claude Code and Codex `Bash`, Gemini `run_shell_command`.
const SHELL_TOOLS: &[&str] = &["Bash", "run_shell_command"];

/// File tools that only read or list.
const READ_TOOLS: &[&str] = &[
    "Read",
    "Grep",
    "Glob",
    "LS",
    "read_file",
    "read_many_files",
    "list_directory",
    "glob",
    "grep_search",
];

/// File tools that change files.
const WRITE_TOOLS: &[&str] = &[
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "write_file",
    "replace",
    "apply_patch",
];

/// Classify a hook payload by its `tool_name`.
///
/// - Shell tools yield their `tool_input.command`.
/// - File tools yield the path(s) they touch. Codex `apply_patch` carries the
///   patch text in `tool_input.command`; it is parsed for file headers and
///   never treated as a shell command.
/// - A payload with no `tool_name` keeps the old behavior: it is a shell
///   call if a command can be found.
/// - Any other tool that carries a string `tool_input.command` is treated as
///   a shell call, so a renamed shell tool is still judged.
/// - Everything else is `Other`.
///
/// Errors (oversize, not JSON, shell call without a command) make the caller
/// fail open.
pub fn classify(input: &str, max_bytes: usize) -> Result<ToolCall, PayloadError> {
    let env = envelope(input, max_bytes)?;
    let Some(tool) = env.tool() else {
        return env.command().map(|command| ToolCall::Shell { command });
    };
    if SHELL_TOOLS.contains(&tool) {
        return env.command().map(|command| ToolCall::Shell { command });
    }
    let empty = ToolInput::default();
    let tool_input = env.tool_input.as_ref().unwrap_or(&empty);
    let write = WRITE_TOOLS.contains(&tool);
    if write || READ_TOOLS.contains(&tool) {
        let mut paths = if tool == "apply_patch" {
            let patch = tool_input
                .command
                .as_deref()
                .or(tool_input.input.as_deref())
                .unwrap_or("");
            patch_paths(patch)
        } else {
            tool_paths(tool_input, tool == "read_many_files")
        };
        if paths.is_empty() && !write {
            // Search and list tools default to the working directory
            // (what they read); a write with no path has nothing to judge.
            if let Some(cwd) = env.cwd.as_deref().filter(|c| !c.is_empty()) {
                paths.push(cwd.to_string());
            }
        }
        return Ok(ToolCall::File {
            tool: tool.to_string(),
            paths,
            write,
        });
    }
    match tool_input.command.as_deref() {
        Some(cmd) if !cmd.trim().is_empty() => Ok(ToolCall::Shell {
            command: cmd.to_string(),
        }),
        _ => Ok(ToolCall::Other {
            tool: tool.to_string(),
        }),
    }
}

/// The file filter of a search tool (Claude `Grep` `glob`, Gemini
/// `grep_search` `include`): a pattern relative to the search root that
/// selects the files whose content is read. Empty when there is none.
pub fn search_globs(input: &str, max_bytes: usize) -> Vec<String> {
    let Ok(env) = envelope(input, max_bytes) else {
        return Vec::new();
    };
    if !matches!(env.tool(), Some("Grep" | "grep_search")) {
        return Vec::new();
    }
    let Some(ti) = env.tool_input.as_ref() else {
        return Vec::new();
    };
    let include = match &ti.include {
        Include::One(s) => Some(s.as_str()),
        _ => None,
    };
    [ti.glob.as_deref(), include]
        .into_iter()
        .flatten()
        .filter(|g| !g.is_empty())
        .map(str::to_string)
        .collect()
}

/// Path fields of the Claude Code and Gemini CLI file tools, in a fixed order.
fn tool_paths(ti: &ToolInput, paths_list: bool) -> Vec<String> {
    let mut out: Vec<String> = [&ti.file_path, &ti.notebook_path, &ti.path, &ti.dir_path]
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty())
        .cloned()
        .collect();
    if let Include::Many(list) = &ti.include {
        out.extend(list.iter().filter(|p| !p.is_empty()).cloned());
    }
    if paths_list {
        out.extend(ti.paths.iter().flatten().filter(|p| !p.is_empty()).cloned());
    }
    out
}

/// File paths named in a Codex `apply_patch` body, in patch order.
fn patch_paths(patch: &str) -> Vec<String> {
    const HEADERS: &[&str] = &[
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    let mut out: Vec<String> = Vec::new();
    for line in patch.lines() {
        let line = line.trim_end_matches('\r');
        for h in HEADERS {
            if let Some(p) = line.strip_prefix(h) {
                let p = p.trim();
                if !p.is_empty() && !out.iter().any(|q| q == p) {
                    out.push(p.to_string());
                }
            }
        }
    }
    out
}

/// Metadata about a hook call, for the audit log. Best-effort: any field the
/// payload does not carry (or an unparseable payload) is `None`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HookContext {
    pub tool: Option<String>,
    pub session: Option<String>,
    pub cwd: Option<String>,
}

pub fn context_from_hook_json(input: &str) -> HookContext {
    context_from_hook_json_bounded(input, MAX_PAYLOAD_BYTES)
}

/// `context_from_hook_json` with a caller-chosen size cap, for callers that
/// still want the context of a payload above `MAX_PAYLOAD_BYTES` (a `Write`
/// of a large file).
pub fn context_from_hook_json_bounded(input: &str, max_bytes: usize) -> HookContext {
    let Ok(env) = envelope(input, max_bytes) else {
        return HookContext::default();
    };
    let field = |a: &Option<String>, b: &Option<String>| {
        [a, b]
            .into_iter()
            .find_map(|x| x.as_deref())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    HookContext {
        tool: field(&env.tool_name, &env.tool_name_camel),
        session: field(&env.session_id, &env.session_id_camel),
        cwd: env.cwd.clone().filter(|c| !c.is_empty()),
    }
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
    if SH_FAMILY.contains(&prog.as_str()) {
        return sh_command_string(&argv[1..]);
    }
    let idx = argv.iter().position(|a| a == "-c")?;
    argv.get(idx + 1).cloned()
}

/// POSIX shells: `-c` may sit in any short-option cluster (`-lc`, `-ec`,
/// `-c -l`), and the command string is then the first operand.
const SH_FAMILY: &[&str] = &["bash", "sh", "zsh", "dash", "ksh"];

/// The command string of `sh [options] -c STRING`: options (and the values
/// of `-o`/`-O`/`+o`/`+O`, `--rcfile`, `--init-file`) are skipped; the first
/// operand is the string when any cluster held `c`.
fn sh_command_string(args: &[String]) -> Option<String> {
    let mut has_c = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" || a == "-" {
            i += 1;
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            if matches!(long, "rcfile" | "init-file") {
                i += 1;
            }
        } else if (a.starts_with('-') || a.starts_with('+')) && a.len() > 1 {
            let cluster = &a[1..];
            has_c |= a.starts_with('-') && cluster.contains('c');
            if cluster.contains(['o', 'O']) {
                i += 1; // the option name
            }
        } else {
            break;
        }
        i += 1;
    }
    if has_c {
        args.get(i).cloned()
    } else {
        None
    }
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
        assert!(matches!(err, PayloadError::TooLarge { .. }));
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

    fn call(json: serde_json::Value) -> ToolCall {
        classify(&json.to_string(), MAX_PAYLOAD_BYTES).unwrap()
    }

    #[test]
    fn classify_shell_tools() {
        for tool in ["Bash", "run_shell_command"] {
            let c =
                call(serde_json::json!({"tool_name": tool, "tool_input": {"command": "rm -rf /"}}));
            assert_eq!(
                c,
                ToolCall::Shell {
                    command: "rm -rf /".into()
                },
                "{tool}"
            );
        }
    }

    #[test]
    fn classify_claude_file_tools() {
        let read = call(
            serde_json::json!({"tool_name": "Read", "tool_input": {"file_path": "/p/.env", "offset": 1}}),
        );
        assert_eq!(
            read,
            ToolCall::File {
                tool: "Read".into(),
                paths: vec!["/p/.env".into()],
                write: false
            }
        );
        let nb = call(
            serde_json::json!({"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "/p/a.ipynb", "new_source": "x"}}),
        );
        assert_eq!(
            nb,
            ToolCall::File {
                tool: "NotebookEdit".into(),
                paths: vec!["/p/a.ipynb".into()],
                write: true
            }
        );
        for tool in ["Write", "Edit", "MultiEdit"] {
            let c = call(
                serde_json::json!({"tool_name": tool, "tool_input": {"file_path": "/p/x.rs"}}),
            );
            assert_eq!(
                c,
                ToolCall::File {
                    tool: tool.into(),
                    paths: vec!["/p/x.rs".into()],
                    write: true
                }
            );
        }
    }

    #[test]
    fn classify_claude_glob_and_ls() {
        let c = call(
            serde_json::json!({"cwd": "/p", "tool_name": "Glob", "tool_input": {"pattern": "**/*.rs"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "Glob".into(),
                paths: vec!["/p".into()],
                write: false
            }
        );
        let c =
            call(serde_json::json!({"tool_name": "LS", "tool_input": {"path": "/home/u/.ssh"}}));
        assert_eq!(
            c,
            ToolCall::File {
                tool: "LS".into(),
                paths: vec!["/home/u/.ssh".into()],
                write: false
            }
        );
        // No path and no cwd: nothing to judge.
        let c = call(serde_json::json!({"tool_name": "Glob", "tool_input": {"pattern": "*"}}));
        assert_eq!(
            c,
            ToolCall::File {
                tool: "Glob".into(),
                paths: vec![],
                write: false
            }
        );
    }

    #[test]
    fn huge_content_does_not_hide_the_path() {
        let big = serde_json::json!({
            "tool_name": "Write", "cwd": "/p", "session_id": "s",
            "tool_input": {"file_path": "/p/a", "content": "x".repeat(3 * 1024 * 1024)}
        })
        .to_string();
        let limit = 64 * 1024 * 1024;
        assert_eq!(
            classify(&big, limit).unwrap(),
            ToolCall::File {
                tool: "Write".into(),
                paths: vec!["/p/a".into()],
                write: true
            }
        );
        let ctx = context_from_hook_json_bounded(&big, limit);
        assert_eq!(ctx.cwd.as_deref(), Some("/p"));
        let err = classify(&big, 1000).unwrap_err();
        assert!(err.to_string().contains("1000"), "{err}");
    }

    #[test]
    fn writes_without_a_path_have_no_cwd_default() {
        let c = call(
            serde_json::json!({"cwd": "/p", "tool_name": "Write", "tool_input": {"content": "x"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "Write".into(),
                paths: vec![],
                write: true
            }
        );
    }

    #[test]
    fn read_many_files_names_files_in_paths_too() {
        let c = call(
            serde_json::json!({"tool_name": "read_many_files", "tool_input": {"paths": ["a", ".env*"]}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "read_many_files".into(),
                paths: vec!["a".into(), ".env*".into()],
                write: false
            }
        );
    }

    #[test]
    fn search_globs_only_for_grep_tools() {
        let g = |t: &str| {
            search_globs(
                &serde_json::json!({"tool_name": t, "tool_input": {"glob": "*.rs", "include": "x"}}).to_string(),
                MAX_PAYLOAD_BYTES,
            )
        };
        assert!(!g("Grep").is_empty() && !g("grep_search").is_empty());
        assert!(g("Read").is_empty() && g("LS").is_empty() && g("Glob").is_empty());
    }

    #[test]
    fn search_globs_are_the_file_filters_of_grep_tools() {
        let g = |v: serde_json::Value| search_globs(&v.to_string(), MAX_PAYLOAD_BYTES);
        assert_eq!(
            g(
                serde_json::json!({"tool_name": "Grep", "tool_input": {"pattern": "x", "glob": ".env*"}})
            ),
            vec![".env*".to_string()]
        );
        assert_eq!(
            g(
                serde_json::json!({"tool_name": "grep_search", "tool_input": {"pattern": "x", "include": "*.rs"}})
            ),
            vec!["*.rs".to_string()]
        );
        // read_many_files `include` is a list of paths, not a filter.
        assert!(g(
            serde_json::json!({"tool_name": "read_many_files", "tool_input": {"include": ["a"]}})
        )
        .is_empty());
        assert!(
            g(serde_json::json!({"tool_name": "Grep", "tool_input": {"pattern": "x"}})).is_empty()
        );
    }

    #[test]
    fn classify_grep_without_path_uses_cwd() {
        let c = call(
            serde_json::json!({"cwd": "/p", "tool_name": "Grep", "tool_input": {"pattern": "TODO"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "Grep".into(),
                paths: vec!["/p".into()],
                write: false
            }
        );
        let c = call(
            serde_json::json!({"cwd": "/p", "tool_name": "Grep", "tool_input": {"pattern": "x", "path": "/p/src"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "Grep".into(),
                paths: vec!["/p/src".into()],
                write: false
            }
        );
    }

    #[test]
    fn classify_gemini_file_tools() {
        let c = call(
            serde_json::json!({"tool_name": "list_directory", "tool_input": {"dir_path": "/p/src"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "list_directory".into(),
                paths: vec!["/p/src".into()],
                write: false
            }
        );
        let c = call(
            serde_json::json!({"tool_name": "read_many_files", "tool_input": {"include": ["src/**/*.rs", ".env"], "exclude": ["target"]}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "read_many_files".into(),
                paths: vec!["src/**/*.rs".into(), ".env".into()],
                write: false
            }
        );
        let c = call(
            serde_json::json!({"tool_name": "replace", "tool_input": {"file_path": "/p/a", "old_string": "a", "new_string": "b"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "replace".into(),
                paths: vec!["/p/a".into()],
                write: true
            }
        );
    }

    #[test]
    fn classify_apply_patch_never_yields_a_shell_command() {
        let patch = "*** Begin Patch\n*** Add File: hello.txt\n+rm -rf /\n*** Update File: src/main.rs\n*** Move to: src/app.rs\n@@\n-a\n+b\n*** Delete File: old.txt\n*** End Patch\n";
        let c =
            call(serde_json::json!({"tool_name": "apply_patch", "tool_input": {"command": patch}}));
        assert_eq!(
            c,
            ToolCall::File {
                tool: "apply_patch".into(),
                paths: vec![
                    "hello.txt".into(),
                    "src/main.rs".into(),
                    "src/app.rs".into(),
                    "old.txt".into()
                ],
                write: true
            }
        );
        let c = call(
            serde_json::json!({"tool_name": "apply_patch", "tool_input": {"command": "rm -rf /"}}),
        );
        assert_eq!(
            c,
            ToolCall::File {
                tool: "apply_patch".into(),
                paths: vec![],
                write: true
            }
        );
    }

    #[test]
    fn classify_unknown_tools() {
        let c =
            call(serde_json::json!({"tool_name": "WebFetch", "tool_input": {"url": "https://x"}}));
        assert_eq!(
            c,
            ToolCall::Other {
                tool: "WebFetch".into()
            }
        );
        // A shell tool under a name this version does not know is still judged.
        let c =
            call(serde_json::json!({"tool_name": "shell", "tool_input": {"command": "rm -rf /"}}));
        assert_eq!(
            c,
            ToolCall::Shell {
                command: "rm -rf /".into()
            }
        );
    }

    #[test]
    fn classify_without_tool_name_keeps_old_shape() {
        let c = call(serde_json::json!({"command": "ls"}));
        assert_eq!(
            c,
            ToolCall::Shell {
                command: "ls".into()
            }
        );
        assert!(matches!(
            classify(r#"{"x":1}"#, MAX_PAYLOAD_BYTES),
            Err(PayloadError::NoCommand)
        ));
    }

    #[test]
    fn classify_errors() {
        assert!(matches!(
            classify("{not json", MAX_PAYLOAD_BYTES),
            Err(PayloadError::Json(_))
        ));
        assert!(matches!(
            classify(r#"{"tool_name":"Bash"}"#, 10),
            Err(PayloadError::TooLarge { .. })
        ));
        assert!(matches!(
            classify(
                r#"{"tool_name":"Bash","tool_input":{"command":"  "}}"#,
                MAX_PAYLOAD_BYTES
            ),
            Err(PayloadError::NoCommand)
        ));
    }

    #[test]
    fn bounded_context_reads_past_the_default_cap() {
        let big = format!(
            r#"{{"tool_name":"Write","session_id":"s","cwd":"/p","tool_input":{{"file_path":"/p/a","content":"{}"}}}}"#,
            "a".repeat(MAX_PAYLOAD_BYTES)
        );
        assert_eq!(context_from_hook_json(&big), HookContext::default());
        let ctx = context_from_hook_json_bounded(&big, 2 * MAX_PAYLOAD_BYTES);
        assert_eq!(ctx.tool.as_deref(), Some("Write"));
        assert_eq!(ctx.cwd.as_deref(), Some("/p"));
    }

    #[test]
    fn context_reads_claude_fields() {
        let json = r#"{"session_id":"abc","cwd":"/home/u/app","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let ctx = context_from_hook_json(json);
        assert_eq!(ctx.tool.as_deref(), Some("Bash"));
        assert_eq!(ctx.session.as_deref(), Some("abc"));
        assert_eq!(ctx.cwd.as_deref(), Some("/home/u/app"));
    }

    #[test]
    fn context_reads_camel_case_and_tolerates_garbage() {
        let ctx = context_from_hook_json(r#"{"toolName":"shell","sessionId":"x"}"#);
        assert_eq!(ctx.tool.as_deref(), Some("shell"));
        assert_eq!(ctx.session.as_deref(), Some("x"));
        assert_eq!(context_from_hook_json("{not json"), HookContext::default());
        let huge = "a".repeat(MAX_PAYLOAD_BYTES + 1);
        assert_eq!(context_from_hook_json(&huge), HookContext::default());
    }
}
