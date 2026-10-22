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

use crate::paths::path_vars;

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

/// What the parent sends the worker on stdin.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvalRequest {
    /// The hook payload as read from the agent.
    pub payload: String,
    /// Every active pack id (default-on ones included).
    pub packs: Vec<String>,
    /// The engine's latency budget (`[guard] budget_ms`).
    pub budget_ms: u64,
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

/// Judge one hook payload with exactly `packs` compiled and `budget` for
/// the engine. A tool the guard does not judge is an `Allow` with reason
/// `tool not judged` (§6.1.1).
pub fn judge(payload: &str, packs: &[String], budget: Duration) -> EvalAnswer {
    let ctx = context_from_hook_json_bounded(payload, PARSE_MAX_BYTES);
    let answer = |verdict, input: String, reason: &str| EvalAnswer {
        verdict,
        input,
        tool: ctx.tool.clone(),
        pack: None,
        rule: None,
        reason: Some(reason.to_string()),
    };
    let engine = || engine_for(packs, ctx.cwd.as_deref(), budget);
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
/// directory) and its project.
fn engine_for(packs: &[String], cwd: Option<&str>, budget: Duration) -> (Engine, PathVars) {
    let start = match cwd {
        Some(c) => PathBuf::from(c),
        None => std::env::current_dir().unwrap_or_default(),
    };
    let project = saiife_agents::config::find_project_root(&start);
    // Broken built-ins are skipped; their rules are not in force.
    let (packs, _warnings) = Catalog::builtin().load_active(packs);
    let vars = path_vars(Some(&start), project.as_deref());
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

/// `saiife __eval`: read one `EvalRequest` from stdin, write one
/// `EvalAnswer` to stdout, exit 0. Any other exit is a worker failure,
/// which the parent turns into `error_denied`.
pub fn worker_main() -> ExitCode {
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
    let answer = judge(
        &req.payload,
        &req.packs,
        Duration::from_millis(req.budget_ms),
    );
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

/// Test seam, debug builds only: `SAIIFE_EVAL_FAULT=abort|segv|hang|overflow`
/// makes the worker fail the way a broken engine could.
#[cfg(debug_assertions)]
fn fault_seam() {
    match std::env::var("SAIIFE_EVAL_FAULT").as_deref() {
        Ok("abort") => std::process::abort(),
        #[cfg(unix)]
        Ok("segv") => {
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
        Ok("hang") => std::thread::sleep(Duration::from_secs(10)),
        Ok("overflow") => {
            overflow(1);
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
    use saiifeguard::builtins::builtin_packs;
    use saiifeguard::profile::select_active;

    const DEFAULTS: &[&str] = &["core.filesystem", "core.git", "core.secrets", "core.self"];

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
