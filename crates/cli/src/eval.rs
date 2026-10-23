//! Judging one hook payload, shared by the developer hook (`check`) and the
//! locked-mode worker (`saiife __eval`, spawned by `check --managed`).
//!
//! The worker runs the guard in its own process so that an abort, a signal
//! or a stack overflow in the engine becomes a clean `error_denied` in the
//! parent instead of a dead hook (spec §6.1.2).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use saiifeguard::builtins::Catalog;
use saiifeguard::canon::{expand_glob_partial, PathVars};
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::pathrule::Access;
use saiifeguard::payload::{
    classify, context_from_hook_json_bounded, search_globs, PayloadError, ToolCall,
    MAX_PAYLOAD_BYTES,
};

use crate::paths::{path_vars_locked, LockedPaths};

/// Memory-safety cap on what is read from stdin. Parsing skips the content
/// of a `Write`/`Edit` while it extracts the tool, `cwd` and path fields, so
/// file calls are judged at any size up to this cap; a shell command above
/// `MAX_PAYLOAD_BYTES` is not judged but its command goes into the audit
/// record. Above this cap nothing is parsed.
pub const PARSE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Largest `EvalRequest` the worker reads, and largest `EvalAnswer` the
/// parent reads: a payload at `PARSE_MAX_BYTES`, JSON-escaped (at most
/// twice its size for a payload that is itself JSON), plus the envelope.
pub const MAX_EVAL_BYTES: usize = 2 * PARSE_MAX_BYTES + 64 * 1024;

/// Longest payload `cwd` that is used (Linux `PATH_MAX`). A longer one, or
/// one with a NUL, is never looked up: walking it can take longer than the
/// agent's hook timeout.
pub const MAX_CWD_BYTES: usize = 4096;

/// `Err` with the reason when the payload `cwd` must not be used.
pub fn check_cwd(cwd: Option<&str>) -> Result<(), String> {
    match cwd {
        Some(c) if c.len() > MAX_CWD_BYTES => Err(format!(
            "hook payload cwd is longer than {MAX_CWD_BYTES} bytes; not judged"
        )),
        Some(c) if c.contains('\0') => {
            Err("hook payload cwd contains a NUL byte; not judged".to_string())
        }
        _ => Ok(()),
    }
}

/// What the parent sends the worker on stdin.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvalRequest {
    /// The hook payload as read from the agent.
    pub payload: String,
    /// Every active pack id (default-on ones included).
    pub packs: Vec<String>,
    /// The engine's latency budget (`[guard] budget_ms`).
    pub budget_ms: u64,
    /// The system config's paths, bound as extra rule-variable values.
    #[serde(default)]
    pub locked: Option<LockedPaths>,
    /// The hook event when it is not a tool call (`config-change`).
    #[serde(default)]
    pub event: Option<String>,
}

/// What the worker answers on stdout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalAnswer {
    pub verdict: Verdict,
    /// The command, or the paths one per line; empty when there is none.
    pub input: String,
    pub tool: Option<String>,
    pub pack: Option<String>,
    pub rule: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
    /// The guard could not judge the call: an unusable payload, an engine
    /// over its budget, an unresolvable path, a glob too large, a shell
    /// command over `MAX_PAYLOAD_BYTES`, a write without a path.
    Unjudged,
}

/// What one hook payload asks the guard to judge.
#[derive(Debug)]
pub enum Plan {
    Shell {
        command: String,
    },
    Files(FileCall),
    /// A write with no path to judge (an `apply_patch` without file
    /// headers, an `Edit` without a path).
    NoPath,
    /// A tool the guard does not judge (§6.1.1).
    Other,
    /// A shell call in a payload over `MAX_PAYLOAD_BYTES`: not judged.
    TooLarge {
        command: String,
    },
    Unusable(PayloadError),
}

/// A file tool call: the paths it touches and how.
#[derive(Debug)]
pub struct FileCall {
    pub paths: Vec<String>,
    pub access: Access,
    /// Search filters (`glob`/`include`) selecting files under each path.
    pub filters: Vec<String>,
    /// `read_many_files` names its files by pattern.
    pub expand_paths: bool,
}

impl FileCall {
    /// The paths, one per line, as recorded.
    pub fn input(&self) -> String {
        self.paths.join("\n")
    }
}

/// Classify `buf` (a payload of at most `PARSE_MAX_BYTES`) into what the
/// guard must judge.
pub fn plan(buf: &str) -> Plan {
    match classify(buf, PARSE_MAX_BYTES) {
        Ok(ToolCall::Shell { command }) if buf.len() > MAX_PAYLOAD_BYTES => {
            Plan::TooLarge { command }
        }
        Ok(ToolCall::Shell { command }) => Plan::Shell { command },
        Ok(ToolCall::File {
            tool,
            mut paths,
            write,
        }) => {
            if paths.is_empty() && !write {
                // A search or list tool with neither `path` nor `cwd`
                // reads the directory the hook runs in.
                if let Ok(d) = std::env::current_dir() {
                    paths.push(d.display().to_string());
                }
            }
            if paths.is_empty() {
                return Plan::NoPath;
            }
            Plan::Files(FileCall {
                paths,
                access: if write { Access::Write } else { Access::Read },
                // Only search tools filter by `glob`/`include`, and only
                // `read_many_files` names its files by pattern.
                filters: search_globs(buf, PARSE_MAX_BYTES),
                expand_paths: tool == "read_many_files",
            })
        }
        Ok(ToolCall::Other { .. }) => Plan::Other,
        Err(e) => Plan::Unusable(e),
    }
}

/// Judge every file `call` reads or writes. A glob too large to expand
/// fails open as unjudgeable unless a path is denied or ran out of budget.
pub fn judge_files(engine: &Engine, vars: &PathVars, call: &FileCall) -> Decision {
    let (targets, overflow) = expand_targets(vars, &call.paths, &call.filters, call.expand_paths);
    let d = judge_paths(engine, call.access, &targets);
    // A deny stays; so does a latency fail-open (it ranks above).
    if overflow && !d.is_deny() && rank(&d) < 3 {
        return Decision::Allow {
            trace: AllowTrace::Unjudgeable {
                reason: "glob too large to judge".into(),
            },
        };
    }
    d
}

/// What a file call reads or writes: its paths, with the patterns of
/// `read_many_files` (`expand_paths`) expanded, and every file a search
/// tool's `filters` select under each of its paths (ripgrep semantics: a
/// filter without `/` matches at any depth, one with `/` is relative to the
/// root). A pattern that matches nothing is judged as spelled (the shell
/// would pass it through). When a pattern is too large to expand, the
/// matches found before the limit are judged along with the pattern as
/// spelled, and the flag is set.
pub fn expand_targets(
    vars: &PathVars,
    paths: &[String],
    filters: &[String],
    expand_paths: bool,
) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut overflow = false;
    let mut add = |word: &str, out: &mut Vec<String>| {
        let (found, over) = expand_glob_partial(word, None, vars);
        if over {
            overflow = true;
        }
        if found.is_empty() || over {
            out.push(word.to_string());
        }
        out.extend(found.iter().map(|p| p.display().to_string()));
    };
    for p in paths {
        if expand_paths {
            add(p, &mut out);
        } else {
            out.push(p.clone());
        }
    }
    for p in paths {
        for f in filters {
            let root = p.trim_end_matches('/');
            let word = if f.contains('/') {
                format!("{root}/{f}")
            } else {
                format!("{root}/**/{f}")
            };
            add(&word, &mut out);
        }
    }
    (out, overflow)
}

/// How much a file-call result matters when several paths are judged:
/// a latency fail-open, an unjudgeable path, a carve-out, a plain allow.
pub fn rank(d: &Decision) -> u8 {
    match d {
        Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout,
        } => 3,
        Decision::Allow {
            trace: AllowTrace::Unjudgeable { .. },
        } => 2,
        Decision::Allow {
            trace: AllowTrace::AllowRule { .. },
        } => 1,
        _ => 0,
    }
}

/// Judge every path of one file tool call: any deny denies the call.
/// Otherwise the call is a fail-open if any path ran out of budget or could
/// not be resolved, else an allow (by a carve-out, if one applied).
pub fn judge_paths(engine: &Engine, access: Access, paths: &[String]) -> Decision {
    let mut result = Decision::Allow {
        trace: AllowTrace::NoMatch,
    };
    for p in paths {
        let d = engine.evaluate_path(access, p);
        if d.is_deny() {
            return d;
        }
        if rank(&d) > rank(&result) {
            result = d;
        }
    }
    result
}

/// `judge_with` on a host with the default system paths.
#[cfg(test)]
pub fn judge(payload: &str, packs: &[String], budget: Duration) -> EvalAnswer {
    judge_with(payload, packs, budget, None)
}

/// Judge one hook payload with exactly `packs` compiled and `budget` for
/// the engine, and a locked host's system paths (`locked`) bound as extra
/// rule-variable values. A tool the guard does not judge is an `Allow` with
/// reason `tool not judged` (§6.1.1).
pub fn judge_with(
    payload: &str,
    packs: &[String],
    budget: Duration,
    locked: Option<&LockedPaths>,
) -> EvalAnswer {
    let ctx = context_from_hook_json_bounded(payload, PARSE_MAX_BYTES);
    let answer = |verdict, input: String, reason: &str| EvalAnswer {
        verdict,
        input,
        tool: ctx.tool.clone(),
        pack: None,
        rule: None,
        reason: Some(reason.to_string()),
    };
    if let Err(reason) = check_cwd(ctx.cwd.as_deref()) {
        return answer(Verdict::Unjudged, String::new(), &reason);
    }
    let engine = || engine_for(packs, ctx.cwd.as_deref(), budget, locked);
    match plan(payload) {
        Plan::TooLarge { command } => {
            let e = PayloadError::TooLarge {
                limit: MAX_PAYLOAD_BYTES,
            };
            answer(
                Verdict::Unjudged,
                command,
                &format!("hook payload not usable: {e}"),
            )
        }
        Plan::Unusable(e) => answer(
            Verdict::Unjudged,
            String::new(),
            &format!("hook payload not usable: {e}"),
        ),
        Plan::NoPath => answer(Verdict::Unjudged, String::new(), "no path to judge"),
        Plan::Other => answer(Verdict::Allow, String::new(), "tool not judged"),
        Plan::Shell { command } => {
            let (engine, _) = engine();
            let d = engine.evaluate(&command);
            from_decision(command, ctx.tool.clone(), d)
        }
        Plan::Files(call) => {
            let (engine, vars) = engine();
            let d = judge_files(&engine, &vars, &call);
            from_decision(call.input(), ctx.tool.clone(), d)
        }
    }
}

/// The engine with exactly `packs` compiled (every default-on pack is
/// compiled as well), path rules bound to `cwd` (else this process's
/// directory), its project and the locked host's system paths.
fn engine_for(
    packs: &[String],
    cwd: Option<&str>,
    budget: Duration,
    locked: Option<&LockedPaths>,
) -> (Engine, PathVars) {
    let start = match cwd {
        Some(c) => PathBuf::from(c),
        None => std::env::current_dir().unwrap_or_default(),
    };
    let project = saiife_agents::config::find_project_root(&start);
    // Broken built-ins are skipped; their rules are not in force.
    let (packs, _warnings) = Catalog::builtin().load_active(packs);
    let vars = path_vars_locked(Some(&start), project.as_deref(), locked);
    let engine = Engine::new(packs)
        .with_paths(vars.clone())
        .with_budget(budget);
    (engine, vars)
}

fn from_decision(input: String, tool: Option<String>, d: Decision) -> EvalAnswer {
    let (verdict, pack, rule, reason) = match d {
        Decision::Deny {
            pack,
            pattern,
            reason,
            ..
        } => (Verdict::Deny, Some(pack), Some(pattern), Some(reason)),
        Decision::Allow {
            trace:
                AllowTrace::AllowRule {
                    pack,
                    pattern,
                    reason,
                },
        } => (Verdict::Allow, Some(pack), Some(pattern), Some(reason)),
        Decision::Allow {
            trace: AllowTrace::NoMatch,
        } => (Verdict::Allow, None, None, None),
        Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout,
        } => (
            Verdict::Unjudged,
            None,
            None,
            Some("guard exceeded its latency budget".to_string()),
        ),
        Decision::Allow {
            trace: AllowTrace::Unjudgeable { reason },
        } => (Verdict::Unjudged, None, None, Some(reason)),
    };
    EvalAnswer {
        verdict,
        input,
        tool,
        pack,
        rule,
        reason,
    }
}

/// The top-level settings keys a session may change (spec §6.1.1). A
/// settings file changed during a session may set only these; any other
/// top-level key (`hooks`, `permissions`, `env`, `apiKeyHelper`,
/// `statusLine`, `enabledPlugins`, the MCP server switches, the auth
/// helpers, and every key Claude Code adds later) denies the change. The
/// check is presence-based: a harmless edit to a file that already holds a
/// locked key is denied too (it applies from the next session).
pub const HARMLESS_SETTINGS_KEYS: [&str; 10] = [
    "$schema",
    "model",
    "theme",
    "verbose",
    "cleanupPeriodDays",
    "includeCoAuthoredBy",
    "outputStyle",
    "spinnerTipsEnabled",
    "alwaysThinkingEnabled",
    "language",
];

/// Largest settings file `judge_config_change` reads.
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

/// Judge a Claude Code `ConfigChange` payload (spec §6.1.1): the changed
/// settings file may set only `HARMLESS_SETTINGS_KEYS`. A change to the
/// managed settings (root's) is allowed, and so is a skills change (not a
/// settings file). Anything that cannot be verified is denied: a relative
/// path, a symlink, a FIFO, a removed file, a file that is not a JSON
/// object. The file is read after Claude Code saw the change, so this is a
/// heuristic that turns an attempt into a record; managed precedence is
/// the real control.
pub fn judge_config_change(payload: &str) -> EvalAnswer {
    let v: Option<serde_json::Value> = serde_json::from_str(payload).ok();
    let field = |k: &str| {
        v.as_ref()
            .and_then(|v| v.get(k))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let source = field("source");
    let file_path = field("file_path");
    let answer = |verdict, reason: String| {
        let deny = verdict == Verdict::Deny;
        EvalAnswer {
            verdict,
            input: format!("{source} {file_path}"),
            tool: Some("ConfigChange".to_string()),
            pack: deny.then(|| "core.self".to_string()),
            rule: deny.then(|| "config-change".to_string()),
            reason: Some(reason),
        }
    };
    if !v.as_ref().is_some_and(serde_json::Value::is_object) {
        return answer(
            Verdict::Unjudged,
            "hook payload not usable: not a JSON object".to_string(),
        );
    }
    let unchecked = |why: &str| {
        answer(
            Verdict::Deny,
            format!("settings change could not be checked: {why}"),
        )
    };
    match source.as_str() {
        "policy_settings" => return answer(Verdict::Allow, "managed settings changed".into()),
        "skills" => return answer(Verdict::Allow, "skills changed".into()),
        _ => {}
    }
    if file_path.is_empty() {
        return unchecked("no file_path");
    }
    let path = std::path::Path::new(&file_path);
    if !path.is_absolute() {
        return unchecked("file_path is not absolute");
    }
    // Never through a symlink: its target could change between the read
    // and Claude Code's.
    let bytes = match crate::system_view::read_regular(path, false, MAX_SETTINGS_BYTES) {
        Ok(Some(b)) => b,
        Ok(None) => return answer(Verdict::Deny, "settings file cannot be verified".into()),
        Err(e) => return unchecked(&e),
    };
    let settings: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => return unchecked(&format!("not valid JSON ({e})")),
    };
    let Some(map) = settings.as_object() else {
        return unchecked("not a JSON object");
    };
    match map
        .keys()
        .find(|k| !HARMLESS_SETTINGS_KEYS.contains(&k.as_str()))
    {
        Some(key) => answer(
            Verdict::Deny,
            format!(
                "settings change touches {key} (only {} may change during a session)",
                HARMLESS_SETTINGS_KEYS.join(", ")
            ),
        ),
        None => answer(Verdict::Allow, "settings change allowed".into()),
    }
}

/// Whether an MCP tool may be used in locked mode (spec §6.1.4).
// Used by the locked hook, which is Linux-only in this version.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpCheck {
    /// Not an MCP tool.
    NotMcp,
    /// Its server is in `[guard.mcp] allow_servers`.
    Allowed,
    /// Its server (or, when the name cannot be split safely, the whole
    /// tool name) is not listed.
    Denied(String),
    /// A Gemini MCP call without a server identity in the payload:
    /// `mcp_<server>_<tool>` cannot be split safely (an unlisted `linear_x`
    /// would pass as `linear`), so the server is unknown.
    Unknown,
}

/// The MCP server identity a payload states (Gemini CLI's `mcp_context`).
// Used by the locked hook, which is Linux-only in this version.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpIdentity {
    /// No `mcp_context` key.
    Absent,
    /// An `mcp_context` key (any value, `null` included) without a string
    /// `server_name`: an MCP call whose server is unknown.
    NoServer,
    /// `mcp_context.server_name`.
    Server(String),
}

/// Judge `tool` of `agent` against `allow`.
///
/// Claude Code and Codex name MCP tools `mcp__<server>__<tool>`. The name
/// is matched against the listed servers: the longest listed `s` with
/// `mcp__<s>__` as a prefix. When the rest of the name holds another `__`,
/// or starts with `_`, a longer, unlisted server could be meant
/// (`mcp__linear__evil__x` from a server `linear__evil`, `mcp__linear___x`
/// from `linear_`): denied as ambiguous.
///
/// Gemini CLI names them `mcp_<server>_<tool>`, which cannot be split, so a
/// Gemini MCP call (a name starting `mcp_` or holding `__`, or any payload
/// with `mcp_context`) is allowed only when the payload's `identity` names
/// a listed server. Other agents: the double form, else the Gemini rule.
// Used by the locked hook, which is Linux-only in this version.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn mcp_check(agent: &str, tool: &str, identity: &McpIdentity, allow: &[String]) -> McpCheck {
    let listed = |s: &str| allow.iter().any(|a| a == s);
    let double = |tool: &str| {
        let rest = tool.strip_prefix("mcp__")?;
        let best = allow
            .iter()
            .filter(|s| !s.is_empty())
            .filter(|s| {
                rest.strip_prefix(s.as_str())
                    .is_some_and(|r| r.starts_with("__"))
            })
            .max_by_key(|s| s.len());
        Some(match best {
            Some(s) => {
                let name = &rest[s.len() + 2..];
                // `mcp__linear___x` may come from an unlisted `linear_`
                // (Claude Code turns `linear.` into `linear_`).
                if name.is_empty() || name.contains("__") || name.starts_with('_') {
                    McpCheck::Denied(tool.to_string())
                } else {
                    McpCheck::Allowed
                }
            }
            None => match rest.split_once("__") {
                Some((s, _)) if !s.is_empty() => McpCheck::Denied(s.to_string()),
                _ => McpCheck::Denied(tool.to_string()),
            },
        })
    };
    let single = |tool: &str| {
        let mcp =
            tool.starts_with("mcp_") || tool.contains("__") || *identity != McpIdentity::Absent;
        mcp.then(|| match identity {
            McpIdentity::Server(s) if listed(s) => McpCheck::Allowed,
            McpIdentity::Server(s) => McpCheck::Denied(s.clone()),
            McpIdentity::Absent | McpIdentity::NoServer => McpCheck::Unknown,
        })
    };
    let found = match agent {
        "claude" | "codex" => double(tool),
        "gemini" => single(tool),
        _ => double(tool).or_else(|| single(tool)),
    };
    found.unwrap_or(McpCheck::NotMcp)
}

/// The MCP server identity `payload` states. A payload that does not parse
/// (the worker denies it as unusable) states none, unless its raw text
/// mentions `"mcp_context"` (a duplicate key, say): then it is an MCP call
/// whose server is unknown.
// Used by the locked hook, which is Linux-only in this version.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn mcp_identity(payload: &str) -> McpIdentity {
    /// `Some` whenever the key is present, `null` included.
    fn present<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<serde_json::Value>, D::Error> {
        serde_json::Value::deserialize(d).map(Some)
    }
    #[derive(Deserialize)]
    struct P {
        #[serde(default, deserialize_with = "present")]
        mcp_context: Option<serde_json::Value>,
    }
    let Ok(p) = serde_json::from_str::<P>(payload) else {
        return if payload.contains("\"mcp_context\"") {
            McpIdentity::NoServer
        } else {
            McpIdentity::Absent
        };
    };
    match p.mcp_context {
        None => McpIdentity::Absent,
        Some(ctx) => match ctx.get("server_name").and_then(serde_json::Value::as_str) {
            Some(s) => McpIdentity::Server(s.to_string()),
            None => McpIdentity::NoServer,
        },
    }
}

/// `saiife __eval`: read one `EvalRequest` from stdin, write one
/// `EvalAnswer` to stdout, exit 0. Any other exit is a worker failure,
/// which the parent turns into `error_denied`.
pub fn worker_main() -> ExitCode {
    #[cfg(debug_assertions)]
    if fault() == "noread" {
        std::thread::sleep(Duration::from_secs(10));
    }
    let mut buf = Vec::new();
    let read = std::io::stdin()
        .lock()
        .take(MAX_EVAL_BYTES as u64 + 1)
        .read_to_end(&mut buf);
    if read.is_err() || buf.len() > MAX_EVAL_BYTES {
        return ExitCode::from(1);
    }
    let Ok(req) = serde_json::from_slice::<EvalRequest>(&buf) else {
        return ExitCode::from(1);
    };
    drop(buf);
    #[cfg(debug_assertions)]
    fault_seam();
    let answer = match req.event.as_deref() {
        None => judge_with(
            &req.payload,
            &req.packs,
            Duration::from_millis(req.budget_ms),
            req.locked.as_ref(),
        ),
        Some("config-change") => judge_config_change(&req.payload),
        Some(other) => EvalAnswer {
            verdict: Verdict::Unjudged,
            input: String::new(),
            tool: None,
            pack: None,
            rule: None,
            reason: Some(format!("unknown hook event {other:?}")),
        },
    };
    let mut out = std::io::stdout().lock();
    if serde_json::to_writer(&mut out, &answer)
        .map_err(std::io::Error::from)
        .and_then(|()| out.flush())
        .is_err()
    {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// The `SAIIFE_EVAL_FAULT` test seam's value (debug builds only).
#[cfg(debug_assertions)]
pub fn fault() -> String {
    std::env::var("SAIIFE_EVAL_FAULT").unwrap_or_default()
}

/// Test seam, debug builds only:
/// `SAIIFE_EVAL_FAULT=abort|segv|hang|overflow|flood` makes the worker fail
/// the way a broken engine could (`noread`: it never reads its request;
/// `parent_hang` and `watchdog_spawn` are the parent's).
#[cfg(debug_assertions)]
fn fault_seam() {
    match fault().as_str() {
        "abort" => std::process::abort(),
        #[cfg(unix)]
        "segv" => {
            // std's SIGSEGV handler (stack-overflow detection) takes the
            // first signal, finds no guard-page hit and restores the
            // default action; the second one kills the process.
            for _ in 0..2 {
                let _ = rustix::process::kill_process(
                    rustix::process::getpid(),
                    rustix::process::Signal::SEGV,
                );
            }
            // Never judge after the seam fired.
            std::process::abort();
        }
        "hang" => std::thread::sleep(Duration::from_secs(10)),
        "overflow" => {
            overflow(1);
        }
        "flood" => {
            let chunk = [b'x'; 64 * 1024];
            let mut out = std::io::stdout().lock();
            // Keeps writing, errors (EPIPE) included, until killed.
            loop {
                let _ = out.write_all(&chunk);
            }
        }
        _ => {}
    }
}

#[cfg(debug_assertions)]
#[allow(unconditional_recursion)]
fn overflow(n: u64) -> u64 {
    let frame = std::hint::black_box([n; 64]);
    overflow(frame[0] + 1) + frame[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::path_vars;
    use saiifeguard::builtins::builtin_packs;
    use saiifeguard::profile::select_active;

    const DEFAULTS: &[&str] = &[
        "core.filesystem",
        "core.git",
        "core.secrets",
        "core.self",
        "core.process",
    ];

    fn defaults() -> Vec<String> {
        DEFAULTS.iter().map(|s| s.to_string()).collect()
    }

    const BUDGET: Duration = Duration::from_secs(5);

    fn payload(cwd: &str, tool: &str, input: serde_json::Value) -> String {
        serde_json::json!({
            "session_id": "s",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
        })
        .to_string()
    }

    /// The developer path's engine for `cwd`: default-on packs, path rules
    /// bound the same way.
    fn dev_engine(cwd: &std::path::Path) -> Engine {
        let (packs, _) = builtin_packs();
        Engine::new(select_active(packs, &[]))
            .with_paths(path_vars(Some(cwd), None))
            .with_budget(BUDGET)
    }

    fn pack_rule(d: &Decision) -> (Option<String>, Option<String>) {
        match d {
            Decision::Deny { pack, pattern, .. } => (Some(pack.clone()), Some(pattern.clone())),
            Decision::Allow {
                trace: AllowTrace::AllowRule { pack, pattern, .. },
            } => (Some(pack.clone()), Some(pattern.clone())),
            Decision::Allow { .. } => (None, None),
        }
    }

    #[test]
    fn judge_matches_developer_engine() {
        let p = tempfile::tempdir().unwrap();
        let cwd = p.path().to_str().unwrap();
        let engine = dev_engine(p.path());
        for (cmd, verdict) in [("rm -rf /", Verdict::Deny), ("ls", Verdict::Allow)] {
            let a = judge(
                &payload(cwd, "Bash", serde_json::json!({ "command": cmd })),
                &defaults(),
                BUDGET,
            );
            assert_eq!(a.verdict, verdict, "{cmd}: {a:?}");
            assert_eq!((a.pack, a.rule), pack_rule(&engine.evaluate(cmd)), "{cmd}");
            assert_eq!(a.input, cmd);
            assert_eq!(a.tool.as_deref(), Some("Bash"));
        }
        let home = dirs::home_dir().unwrap();
        let key = home.join(".ssh/id_rsa").display().to_string();
        let a = judge(
            &payload(cwd, "Read", serde_json::json!({ "file_path": key })),
            &defaults(),
            BUDGET,
        );
        assert_eq!(a.verdict, Verdict::Deny, "{a:?}");
        let want = pack_rule(&engine.evaluate_path(Access::Read, &key));
        assert!(want.0.is_some());
        assert_eq!((a.pack, a.rule), want);
        assert_eq!(a.input, key);
    }

    #[test]
    fn opt_in_pack_applies_only_when_listed() {
        let p = tempfile::tempdir().unwrap();
        let cwd = p.path().to_str().unwrap();
        let drop = payload(
            cwd,
            "Bash",
            serde_json::json!({ "command": "psql -c 'DROP DATABASE prod'" }),
        );
        assert_eq!(judge(&drop, &defaults(), BUDGET).verdict, Verdict::Allow);
        let mut packs = defaults();
        packs.push("db.postgres".into());
        let a = judge(&drop, &packs, BUDGET);
        assert_eq!(a.verdict, Verdict::Deny);
        assert_eq!(a.pack.as_deref(), Some("db.postgres"));
    }

    #[test]
    fn oversized_shell_is_unjudged() {
        let cmd = format!("echo {}", "a".repeat(300 * 1024));
        let a = judge(
            &payload("/", "Bash", serde_json::json!({ "command": cmd })),
            &defaults(),
            BUDGET,
        );
        assert_eq!(a.verdict, Verdict::Unjudged);
        assert_eq!(a.input, cmd);
        assert!(a.reason.unwrap().contains("exceeds"));
    }

    #[test]
    fn untouched_tool_is_allow_not_judged() {
        let a = judge(
            &payload(
                "/",
                "WebFetch",
                serde_json::json!({ "url": "https://example.com" }),
            ),
            &defaults(),
            BUDGET,
        );
        assert_eq!(a.verdict, Verdict::Allow);
        assert_eq!(a.reason.as_deref(), Some("tool not judged"));
        assert_eq!(a.tool.as_deref(), Some("WebFetch"));
        assert_eq!((a.pack, a.rule), (None, None));
    }

    #[test]
    fn unusable_payload_and_pathless_write_are_unjudged() {
        let a = judge("not json", &defaults(), BUDGET);
        assert_eq!(a.verdict, Verdict::Unjudged);
        assert!(a.reason.unwrap().starts_with("hook payload not usable"));
        let a = judge(
            &payload("/", "apply_patch", serde_json::json!({ "command": "x" })),
            &defaults(),
            BUDGET,
        );
        assert_eq!(a.verdict, Verdict::Unjudged);
        assert_eq!(a.reason.as_deref(), Some("no path to judge"));
    }

    #[test]
    fn over_budget_is_unjudged() {
        let a = judge(
            &payload(
                "/",
                "Bash",
                serde_json::json!({ "command": "rm -rf /tmp/x" }),
            ),
            &defaults(),
            Duration::ZERO,
        );
        assert_eq!(a.verdict, Verdict::Unjudged, "{a:?}");
        assert_eq!(
            a.reason.as_deref(),
            Some("guard exceeded its latency budget")
        );
    }

    #[test]
    fn unusable_cwd_is_unjudged() {
        let long = format!("/{}", "a".repeat(MAX_CWD_BYTES));
        for cwd in [long.as_str(), "/tmp/a\0b"] {
            let a = judge(
                &payload(cwd, "Bash", serde_json::json!({ "command": "ls" })),
                &defaults(),
                BUDGET,
            );
            assert_eq!(a.verdict, Verdict::Unjudged, "{a:?}");
            assert!(a.reason.unwrap().contains("cwd"));
        }
        assert!(check_cwd(Some(&"/".repeat(MAX_CWD_BYTES))).is_ok());
        assert!(check_cwd(None).is_ok());
    }

    fn config_change(source: &str, file_path: &str) -> String {
        serde_json::json!({
            "session_id": "s",
            "cwd": "/",
            "hook_event_name": "ConfigChange",
            "source": source,
            "file_path": file_path,
        })
        .to_string()
    }

    fn settings_file(dir: &std::path::Path, text: &str) -> String {
        let f = dir.join("settings.json");
        std::fs::write(&f, text).unwrap();
        f.display().to_string()
    }

    #[test]
    fn config_change_with_hooks_key_denied() {
        let d = tempfile::tempdir().unwrap();
        let f = settings_file(d.path(), r#"{"hooks":{}}"#);
        let a = judge_config_change(&config_change("user_settings", &f));
        assert_eq!(a.verdict, Verdict::Deny, "{a:?}");
        assert_eq!(a.pack.as_deref(), Some("core.self"));
        assert_eq!(a.rule.as_deref(), Some("config-change"));
        assert_eq!(
            a.reason.as_deref(),
            Some(
                "settings change touches hooks (only $schema, model, theme, verbose, \
                 cleanupPeriodDays, includeCoAuthoredBy, outputStyle, spinnerTipsEnabled, \
                 alwaysThinkingEnabled, language may change during a session)"
            )
        );
        assert_eq!(a.tool.as_deref(), Some("ConfigChange"));
        assert_eq!(a.input, format!("user_settings {f}"));
    }

    /// Every key outside the allowlist denies, the ones that grant or run
    /// something above all.
    #[test]
    fn config_change_unlisted_keys_denied() {
        let d = tempfile::tempdir().unwrap();
        for key in [
            "hooks",
            "disableAllHooks",
            "permissions",
            "env",
            "apiKeyHelper",
            "statusLine",
            "enabledPlugins",
            "extraKnownMarketplaces",
            "otelHeadersHelper",
            "awsAuthRefresh",
            "awsCredentialExport",
            "enableAllProjectMcpServers",
            "enabledMcpjsonServers",
            "disabledMcpjsonServers",
            "someFutureKey",
        ] {
            let f = settings_file(d.path(), &format!(r#"{{"theme":"x","{key}":1}}"#));
            let a = judge_config_change(&config_change("project_settings", &f));
            assert_eq!(a.verdict, Verdict::Deny, "{key}: {a:?}");
            assert!(
                a.reason
                    .unwrap()
                    .starts_with(&format!("settings change touches {key} ")),
                "{key}"
            );
        }
    }

    #[test]
    fn config_change_harmless_allowed() {
        let d = tempfile::tempdir().unwrap();
        let all: serde_json::Map<String, serde_json::Value> = HARMLESS_SETTINGS_KEYS
            .iter()
            .map(|k| (k.to_string(), serde_json::json!("x")))
            .collect();
        for text in [
            r#"{"theme":"dark"}"#.to_string(),
            "{}".to_string(),
            serde_json::Value::Object(all).to_string(),
        ] {
            let f = settings_file(d.path(), &text);
            let a = judge_config_change(&config_change("local_settings", &f));
            assert_eq!(a.verdict, Verdict::Allow, "{text}: {a:?}");
            assert_eq!(a.tool.as_deref(), Some("ConfigChange"));
            assert_eq!(a.input, format!("local_settings {f}"));
            assert_eq!((a.pack, a.rule), (None, None));
        }
    }

    /// A removed file cannot be verified: denied.
    #[test]
    fn config_change_removed_file_denied() {
        let d = tempfile::tempdir().unwrap();
        let gone = d.path().join("gone.json").display().to_string();
        for source in [
            "user_settings",
            "project_settings",
            "local_settings",
            "other",
        ] {
            let a = judge_config_change(&config_change(source, &gone));
            assert_eq!(a.verdict, Verdict::Deny, "{source}: {a:?}");
            assert_eq!(
                a.reason.as_deref(),
                Some("settings file cannot be verified")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn config_change_symlink_denied() {
        let d = tempfile::tempdir().unwrap();
        let real = settings_file(d.path(), r#"{"theme":"dark"}"#);
        let link = d.path().join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let a = judge_config_change(&config_change("user_settings", &link.display().to_string()));
        assert_eq!(a.verdict, Verdict::Deny, "{a:?}");
        assert!(a
            .reason
            .unwrap()
            .starts_with("settings change could not be checked: not a regular file"));
    }

    #[test]
    fn config_change_policy_settings_allowed() {
        // Never opened: the managed file is root's.
        let a = judge_config_change(&config_change(
            "policy_settings",
            "/nonexistent/dir/managed-settings.json",
        ));
        assert_eq!(a.verdict, Verdict::Allow, "{a:?}");
        assert_eq!(a.reason.as_deref(), Some("managed settings changed"));
        assert_eq!(
            a.input,
            "policy_settings /nonexistent/dir/managed-settings.json"
        );
    }

    #[test]
    fn config_change_unparsable_denied() {
        let d = tempfile::tempdir().unwrap();
        for text in ["{\"hooks\": ", "not json", "[1,2]"] {
            let f = settings_file(d.path(), text);
            let a = judge_config_change(&config_change("user_settings", &f));
            assert_eq!(a.verdict, Verdict::Deny, "{text}: {a:?}");
            assert_eq!(a.pack.as_deref(), Some("core.self"));
            assert_eq!(a.rule.as_deref(), Some("config-change"));
            assert!(
                a.reason
                    .as_deref()
                    .unwrap()
                    .starts_with("settings change could not be checked: "),
                "{a:?}"
            );
        }
        // Larger than 1 MiB.
        let f = settings_file(
            d.path(),
            &format!("{{\"theme\":\"{}\"}}", "x".repeat(1 << 20)),
        );
        let a = judge_config_change(&config_change("user_settings", &f));
        assert_eq!(a.verdict, Verdict::Deny, "{a:?}");
    }

    #[cfg(unix)]
    #[test]
    fn config_change_fifo_denied_quickly() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("settings.json");
        let ok = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(ok.success());
        let t = std::time::Instant::now();
        let a = judge_config_change(&config_change("user_settings", &fifo.display().to_string()));
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
        assert_eq!(a.verdict, Verdict::Deny, "{a:?}");
        assert!(a
            .reason
            .unwrap()
            .starts_with("settings change could not be checked: "));
    }

    #[test]
    fn config_change_relative_path_denied() {
        for p in ["settings.json", ".claude/settings.json", ""] {
            let a = judge_config_change(&config_change("project_settings", p));
            assert_eq!(a.verdict, Verdict::Deny, "{p}: {a:?}");
            assert_eq!(a.rule.as_deref(), Some("config-change"));
        }
        // No file_path at all.
        let a =
            judge_config_change(r#"{"hook_event_name":"ConfigChange","source":"user_settings"}"#);
        assert_eq!(a.verdict, Verdict::Deny, "{a:?}");
    }

    #[test]
    fn config_change_unusable_payload_is_unjudged() {
        let a = judge_config_change("not json");
        assert_eq!(a.verdict, Verdict::Unjudged, "{a:?}");
        assert_eq!(a.tool.as_deref(), Some("ConfigChange"));
    }

    fn list(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    const NONE: McpIdentity = McpIdentity::Absent;

    fn server(s: &str) -> McpIdentity {
        McpIdentity::Server(s.to_string())
    }

    #[test]
    fn mcp_check_claude() {
        let allow = list(&["linear"]);
        for agent in ["claude", "codex", "unknown"] {
            assert_eq!(
                mcp_check(agent, "mcp__linear__create", &NONE, &allow),
                McpCheck::Allowed,
                "{agent}"
            );
            assert_eq!(
                mcp_check(agent, "mcp__other__x", &NONE, &allow),
                McpCheck::Denied("other".into()),
                "{agent}"
            );
            assert_eq!(mcp_check(agent, "Bash", &NONE, &allow), McpCheck::NotMcp);
            // A claimed server identity does not override the tool name.
            assert_eq!(
                mcp_check(agent, "mcp__other__x", &server("linear"), &allow),
                McpCheck::Denied("other".into()),
                "{agent}"
            );
            // No tool part: the whole name.
            for t in ["mcp__linear", "mcp__linear__"] {
                assert_eq!(
                    mcp_check(agent, t, &NONE, &allow),
                    McpCheck::Denied(t.into()),
                    "{agent} {t}"
                );
            }
            assert_eq!(
                mcp_check(agent, "mcp____x", &NONE, &list(&[""])),
                McpCheck::Denied("mcp____x".into()),
                "{agent}"
            );
        }
        assert_eq!(
            mcp_check("claude", "mcp__linear__create", &NONE, &[]),
            McpCheck::Denied("linear".into())
        );
    }

    /// Controller ruling: Gemini's `mcp_<server>_<tool>` is ambiguous (an
    /// unlisted `linear_x` would pass a prefix match), so only an explicit
    /// server identity in the payload allows the call.
    #[test]
    fn mcp_check_gemini_prefix() {
        let allow = list(&["linear"]);
        assert_eq!(
            mcp_check("gemini", "mcp_linear_x", &server("linear"), &allow),
            McpCheck::Allowed
        );
        assert_eq!(
            mcp_check("gemini", "mcp_linear_x", &NONE, &allow),
            McpCheck::Unknown
        );
        assert_eq!(
            mcp_check("gemini", "mcp_linear_x", &McpIdentity::NoServer, &allow),
            McpCheck::Unknown
        );
        assert_eq!(
            mcp_check("gemini", "mcp_linear_x_y", &server("linear_x"), &allow),
            McpCheck::Denied("linear_x".into())
        );
        assert_eq!(
            mcp_check("gemini", "read_file", &NONE, &allow),
            McpCheck::NotMcp
        );
        // Names that do not say MCP, but still are.
        assert_eq!(
            mcp_check("gemini", "search", &server("other"), &allow),
            McpCheck::Denied("other".into())
        );
        assert_eq!(
            mcp_check("gemini", "search", &McpIdentity::NoServer, &allow),
            McpCheck::Unknown
        );
        assert_eq!(
            mcp_check("gemini", "linear__search", &NONE, &allow),
            McpCheck::Unknown
        );
        // Other agents: the single-underscore form follows the Gemini rule.
        assert_eq!(
            mcp_check("unknown", "mcp_linear_x", &NONE, &allow),
            McpCheck::Unknown
        );
        assert_eq!(
            mcp_check("unknown", "mcp_linear_x", &server("linear"), &allow),
            McpCheck::Allowed
        );
    }

    /// A server named `linear__evil` must not pass as `linear`: the rest of
    /// the name after a listed server may not hold another `__` unless the
    /// longer server is listed too.
    #[test]
    fn mcp_check_double_underscore_server_name() {
        for agent in ["claude", "codex"] {
            assert_eq!(
                mcp_check(agent, "mcp__linear__evil__x", &NONE, &list(&["linear"])),
                McpCheck::Denied("mcp__linear__evil__x".into()),
                "{agent}"
            );
            assert_eq!(
                mcp_check(
                    agent,
                    "mcp__linear__evil__x",
                    &NONE,
                    &list(&["linear", "linear__evil"])
                ),
                McpCheck::Allowed,
                "{agent}"
            );
            assert_eq!(
                mcp_check(agent, "mcp__a__b__c", &NONE, &list(&["a__b"])),
                McpCheck::Allowed,
                "{agent}"
            );
            // `linear_` (from `linear.`) does not pass as `linear`.
            assert_eq!(
                mcp_check(agent, "mcp__linear___x", &NONE, &list(&["linear"])),
                McpCheck::Denied("mcp__linear___x".into()),
                "{agent}"
            );
            assert_eq!(
                mcp_check(agent, "mcp__linear___x", &NONE, &list(&["linear_"])),
                McpCheck::Allowed,
                "{agent}"
            );
            assert_eq!(
                mcp_check(
                    agent,
                    "mcp__linear___x",
                    &NONE,
                    &list(&["linear", "linear_"])
                ),
                McpCheck::Allowed,
                "{agent}"
            );
            assert_eq!(
                mcp_check(agent, "mcp__a__b__c", &NONE, &list(&["a__b__c"])),
                McpCheck::Denied("a".into()),
                "{agent}"
            );
        }
        // On Gemini the double form is only another MCP name.
        assert_eq!(
            mcp_check("gemini", "mcp__a__b", &NONE, &list(&["a"])),
            McpCheck::Unknown
        );
    }

    #[test]
    fn mcp_identity_has_three_states() {
        let p = serde_json::json!({
            "tool_name": "mcp_linear_x",
            "mcp_context": {"server_name": "linear", "tool_name": "x"},
        })
        .to_string();
        assert_eq!(mcp_identity(&p), server("linear"));
        for p in [
            r#"{"tool_name":"search","mcp_context":{}}"#,
            r#"{"mcp_context":{"server_name":7}}"#,
            r#"{"mcp_context":"linear"}"#,
            r#"{"mcp_context":null}"#,
        ] {
            assert_eq!(mcp_identity(p), McpIdentity::NoServer, "{p}");
        }
        for p in [r#"{"tool_name":"mcp_linear_x"}"#, "not json"] {
            assert_eq!(mcp_identity(p), McpIdentity::Absent, "{p}");
        }
        // Unparsable, yet it names an `mcp_context`.
        let dup =
            r#"{"tool_name":"search","mcp_context":{"server_name":"linear"},"mcp_context":{}}"#;
        assert_eq!(mcp_identity(dup), McpIdentity::NoServer);
        assert_eq!(mcp_identity(r#"{"mcp_context": {"#), McpIdentity::NoServer);
        // The ruling's case end to end.
        let p = r#"{"tool_name":"search","mcp_context":{}}"#;
        assert_eq!(
            mcp_check("gemini", "search", &mcp_identity(p), &list(&["linear"])),
            McpCheck::Unknown
        );
    }

    #[test]
    fn answer_json_is_snake_case() {
        let a = EvalAnswer {
            verdict: Verdict::Unjudged,
            input: "x".into(),
            tool: None,
            pack: None,
            rule: None,
            reason: None,
        };
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["verdict"], "unjudged");
        let back: EvalAnswer = serde_json::from_value(v).unwrap();
        assert_eq!(back, a);
    }
}
