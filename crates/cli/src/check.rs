//! `saiife check`: hook mode. Read the agent's pre-tool JSON on stdin, decide,
//! audit, and answer in the agent's contract. FAIL OPEN on every error.

use std::io::Read;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::ExitCode;

use saiife_audit::{store, DecisionKind, NewRecord, Record};
use saiifeguard::canon::{expand_glob_partial, PathVars};
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::pathrule::Access;
use saiifeguard::payload::{
    classify, context_from_hook_json_bounded, search_globs, HookContext, PayloadError, ToolCall,
    MAX_PAYLOAD_BYTES,
};
use saiifeguard::profile::select_active;
use saiifeguard::Pack;

use crate::paths::path_vars;
use crate::project::project_packs;
use crate::warn;

/// Memory-safety cap on what is read from stdin. Parsing skips the content
/// of a `Write`/`Edit` while it extracts the tool, `cwd` and path fields, so
/// file calls are judged at any size up to this cap; a shell command above
/// `MAX_PAYLOAD_BYTES` is not judged but its command goes into the audit
/// record. Above this cap nothing is parsed: a recorded fail-open.
const PARSE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// `packs`: every built-in pack; `cli_packs`: `--pack` ids. The project's
/// own packs are added from the `.saiife/config.toml` at or above the
/// payload's `cwd`.
pub fn run(packs: Vec<Pack>, cli_packs: &[String], hook_exit: bool, agent: &str) -> ExitCode {
    let mut buf = String::new();
    let mut stdin = std::io::stdin().lock();
    let read = (&mut stdin)
        .take(PARSE_MAX_BYTES as u64 + 1)
        .read_to_string(&mut buf);
    if read.is_ok() && buf.len() > PARSE_MAX_BYTES {
        // Drain the rest so the agent gets no EPIPE.
        let _ = std::io::copy(&mut stdin, &mut std::io::sink());
        let audit = Audit::new(agent, HookContext::default());
        let reason = format!("hook payload larger than {PARSE_MAX_BYTES} bytes; not judged");
        warn(&format!("{reason}; failing open (allow)"));
        audit.write("", DecisionKind::ErrorAllowed, None, Some(&reason));
        return allow();
    }
    drop(stdin);
    if read.is_err() {
        let audit = Audit::new(agent, HookContext::default());
        warn("could not read hook payload; failing open (allow)");
        audit.write(
            "",
            DecisionKind::ErrorAllowed,
            None,
            Some("could not read hook payload"),
        );
        return allow();
    }
    let audit = Audit::new(agent, context_from_hook_json_bounded(&buf, PARSE_MAX_BYTES));
    match classify(&buf, PARSE_MAX_BYTES) {
        Ok(ToolCall::Shell { command }) if buf.len() > MAX_PAYLOAD_BYTES => fail_open(
            &audit,
            &command,
            &PayloadError::TooLarge {
                limit: MAX_PAYLOAD_BYTES,
            },
        ),
        Ok(ToolCall::Shell { command }) => {
            // Built inside `decide`'s unwind guard: a panic while reading
            // the project config or building the engine fails open too.
            let cwd = audit.ctx.cwd.clone();
            decide(&audit, &command, hook_exit, |c| {
                engine_for(packs, cli_packs, cwd.as_deref()).0.evaluate(c)
            })
        }
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
                // A write (an apply_patch without file headers, an Edit
                // without a path): allowed, but never recorded as a judged
                // allow.
                audit.write(
                    "",
                    DecisionKind::ErrorAllowed,
                    None,
                    Some("no path to judge"),
                );
                return allow();
            }
            let cwd = audit.ctx.cwd.clone();
            let access = if write { Access::Write } else { Access::Read };
            // Only search tools filter by `glob`/`include`, and only
            // `read_many_files` names its files by pattern.
            let filters = search_globs(&buf, PARSE_MAX_BYTES);
            let expand_paths = tool == "read_many_files";
            decide(&audit, &paths.join("\n"), hook_exit, |_| {
                let (engine, vars) = engine_for(packs, cli_packs, cwd.as_deref());
                let (targets, overflow) = expand_targets(&vars, &paths, &filters, expand_paths);
                let d = judge_paths(&engine, access, &targets);
                // A deny stays; so does a latency fail-open (it ranks above).
                if overflow && !d.is_deny() && rank(&d) < 3 {
                    return Decision::Allow {
                        trace: AllowTrace::Unjudgeable {
                            reason: "glob too large to judge".into(),
                        },
                    };
                }
                d
            })
        }
        Ok(ToolCall::Other { .. }) => {
            audit.write("", DecisionKind::Allow, None, Some("tool not guarded"));
            allow()
        }
        Err(e) => fail_open(&audit, "", &e),
    }
}

/// `saiife check` got arguments it cannot parse: it fails open, so record
/// that like every other fail-open (spec §1.2 rule 5). Best effort and never
/// panics: the agent is taken from `--agent` in `args` if present, the
/// payload is read up to the usual bound (draining the rest, so the agent
/// gets no EPIPE). The caller exits 0 with nothing on stdout.
pub fn record_arg_error(args: &[String], error: &str) {
    let _ = std::panic::catch_unwind(|| {
        let agent = agent_from_args(args).unwrap_or("unknown");
        let mut bytes = Vec::new();
        let mut stdin = std::io::stdin().lock();
        let _ = (&mut stdin)
            .take(PARSE_MAX_BYTES as u64)
            .read_to_end(&mut bytes);
        let _ = std::io::copy(&mut stdin, &mut std::io::sink());
        let buf = String::from_utf8_lossy(&bytes);
        let audit = Audit::new(agent, context_from_hook_json_bounded(&buf, PARSE_MAX_BYTES));
        audit.write(
            "",
            DecisionKind::ErrorAllowed,
            None,
            Some(&format!("bad hook arguments: {error}")),
        );
    });
}

/// The value of `--agent <name>` or `--agent=<name>`.
fn agent_from_args(args: &[String]) -> Option<&str> {
    args.iter().enumerate().find_map(|(i, a)| {
        if a == "--agent" {
            args.get(i + 1).map(String::as_str)
        } else {
            a.strip_prefix("--agent=")
        }
    })
}

/// The engine for this call: default-on packs, `--pack` ids, and the packs
/// of the project that `cwd` (or this process's directory) belongs to,
/// with path rules bound to that directory and this machine's saiife dirs
/// (the bindings are returned too, for expanding globs).
fn engine_for(packs: Vec<Pack>, cli_packs: &[String], cwd: Option<&str>) -> (Engine, PathVars) {
    let start = match cwd {
        Some(c) => PathBuf::from(c),
        None => std::env::current_dir().unwrap_or_default(),
    };
    let project = project_packs(&start, &packs);
    for w in &project.warnings {
        warn(w);
    }
    let mut enabled = cli_packs.to_vec();
    enabled.extend(project.enabled);
    let vars = path_vars(Some(&start), project.root.as_deref());
    let engine = Engine::new(select_active(packs, &enabled)).with_paths(vars.clone());
    (engine, vars)
}

/// What a file call reads or writes: its paths, with the patterns of
/// `read_many_files` (`expand_paths`) expanded, and every file a search
/// tool's `filters` select under each of its paths (ripgrep semantics: a
/// filter without `/` matches at any depth, one with `/` is relative to the
/// root). A pattern that matches nothing is judged as spelled (the shell
/// would pass it through). When a pattern is too large to expand, the
/// matches found before the limit are judged along with the pattern as
/// spelled, and the flag is set.
fn expand_targets(
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
fn rank(d: &Decision) -> u8 {
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
fn judge_paths(engine: &Engine, access: Access, paths: &[String]) -> Decision {
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

/// The payload could not be judged: allow, and record why.
fn fail_open(audit: &Audit, input: &str, e: &PayloadError) -> ExitCode {
    warn(&format!(
        "hook payload not usable ({e}); failing open (allow)"
    ));
    audit.write(
        input,
        DecisionKind::ErrorAllowed,
        None,
        Some(&format!("hook payload not usable: {e}")),
    );
    allow()
}

/// Judge `command` with `evaluate`, audit the decision and answer the hook.
/// Split out so the crash path can be tested with a panicking evaluator.
fn decide(
    audit: &Audit,
    command: &str,
    hook_exit: bool,
    evaluate: impl FnOnce(&str) -> Decision,
) -> ExitCode {
    // A panicking engine must not turn into a non-zero exit the agent may
    // read as "block" or as a hook error: fail open, and say so in the log.
    // (Release keeps the default panic=unwind, so this is reachable.)
    let decision = match std::panic::catch_unwind(AssertUnwindSafe(|| evaluate(command))) {
        Ok(d) => d,
        Err(_) => {
            warn("guard crashed; failing open (allow)");
            audit.write(
                command,
                DecisionKind::ErrorAllowed,
                None,
                Some("guard crashed"),
            );
            return allow();
        }
    };
    match &decision {
        Decision::Deny {
            pack,
            pattern,
            reason,
            ..
        } => audit.write(
            command,
            DecisionKind::Deny,
            Some((pack, pattern)),
            Some(reason),
        ),
        Decision::Allow {
            trace:
                AllowTrace::AllowRule {
                    pack,
                    pattern,
                    reason,
                },
        } => audit.write(
            command,
            DecisionKind::Allow,
            Some((pack, pattern)),
            Some(reason),
        ),
        Decision::Allow {
            trace: AllowTrace::NoMatch,
        } => audit.write(command, DecisionKind::Allow, None, None),
        Decision::Allow {
            trace: AllowTrace::FailedOpenTimeout,
        } => audit.write(
            command,
            DecisionKind::ErrorAllowed,
            None,
            Some("guard exceeded its latency budget"),
        ),
        Decision::Allow {
            trace: AllowTrace::Unjudgeable { reason },
        } => audit.write(command, DecisionKind::ErrorAllowed, None, Some(reason)),
    }

    match decision {
        Decision::Deny {
            pack,
            reason,
            via_inline,
            ..
        } => {
            // Same "BLOCKED by <pack>: <reason> (inline: ...)" shape as
            // `test`/`explain`: the hook path is what a real user hits.
            let where_ = via_inline
                .as_deref()
                .map(|i| format!(" (inline: {i})"))
                .unwrap_or_default();
            let msg = format!("BLOCKED by {pack}: {reason}{where_}");
            if hook_exit {
                warn(&msg);
                ExitCode::from(2)
            } else {
                emit_deny(&msg)
            }
        }
        Decision::Allow { .. } => allow(),
    }
}

/// Everything about this hook call except the decision, so each exit path
/// writes a complete record with one call.
struct Audit {
    dir: Option<PathBuf>,
    agent: String,
    ctx: HookContext,
    project: String,
}

impl Audit {
    fn new(agent: &str, ctx: HookContext) -> Self {
        let project = ctx.cwd.clone().unwrap_or_else(|| {
            std::env::current_dir()
                .map(|d| d.display().to_string())
                .unwrap_or_default()
        });
        let dir = store::default_dir();
        if dir.is_none() {
            warn("could not determine the audit directory; this decision is not audited");
        }
        Self {
            dir,
            agent: agent.to_string(),
            ctx,
            project,
        }
    }

    /// Best-effort: a failed write is reported on stderr and otherwise ignored.
    fn write(
        &self,
        input: &str,
        decision: DecisionKind,
        rule: Option<(&String, &String)>,
        reason: Option<&str>,
    ) {
        let Some(dir) = &self.dir else {
            return;
        };
        let rec = Record::new(
            NewRecord {
                agent: &self.agent,
                project: &self.project,
                session: self.ctx.session.as_deref(),
                tool: self.ctx.tool.as_deref().unwrap_or("unknown"),
                input,
                decision,
                pack: rule.map(|(p, _)| p.as_str()),
                rule: rule.map(|(_, r)| r.as_str()),
                reason,
            },
            env!("CARGO_PKG_VERSION"),
        );
        if let Err(e) = store::append(dir, &rec) {
            warn(&format!("audit write failed ({e}); decision unaffected"));
        }
    }
}

/// Allow = exit 0 with NOTHING on stdout, for every agent and both modes.
/// An explicit `permissionDecision: "allow"` would skip Claude Code's own
/// permission prompts, and Codex treats an allow without `updatedInput` as a
/// failed hook. Silence means "no objection": the agent's normal flow runs.
fn allow() -> ExitCode {
    ExitCode::SUCCESS
}

/// Emit a PreToolUse "deny" response with a reason and exit 0 (the JSON
/// carries the block decision).
fn emit_deny(reason: &str) -> ExitCode {
    let payload = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    });
    println!("{payload}");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_is_taken_from_args_when_present() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            agent_from_args(&a(&["check", "--agent", "codex", "--x"])),
            Some("codex")
        );
        assert_eq!(
            agent_from_args(&a(&["check", "--agent=gemini"])),
            Some("gemini")
        );
        assert_eq!(agent_from_args(&a(&["check", "--x", "--agent"])), None);
        assert_eq!(agent_from_args(&a(&["check"])), None);
    }

    fn audit_in(dir: &std::path::Path) -> Audit {
        Audit {
            dir: Some(dir.to_path_buf()),
            agent: "claude".into(),
            ctx: HookContext::default(),
            project: "/p".into(),
        }
    }

    #[test]
    fn engine_panic_fails_open_and_is_audited() {
        let dir = tempfile::tempdir().unwrap();
        let code = decide(&audit_in(dir.path()), "rm -rf /tmp/x", true, |_| {
            panic!("engine bug")
        });
        assert_eq!(code, ExitCode::SUCCESS);
        let recs = store::read_all(dir.path()).records;
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].decision, DecisionKind::ErrorAllowed);
        assert_eq!(recs[0].input, "rm -rf /tmp/x");
        assert_eq!(recs[0].reason.as_deref(), Some("guard crashed"));
    }

    #[test]
    fn normal_decision_still_flows_through_decide() {
        let dir = tempfile::tempdir().unwrap();
        let code = decide(&audit_in(dir.path()), "ls", true, |_| Decision::Allow {
            trace: AllowTrace::NoMatch,
        });
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            store::read_all(dir.path()).records[0].decision,
            DecisionKind::Allow
        );
    }
}
