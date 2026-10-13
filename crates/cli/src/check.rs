//! `saiife check`: hook mode. Read the agent's pre-tool JSON on stdin, decide,
//! audit, and answer in the agent's contract. FAIL OPEN on every error.

use std::io::Read;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::process::ExitCode;

use saiife_audit::{store, DecisionKind, NewRecord, Record};
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::payload::{
    command_from_hook_json, context_from_hook_json, HookContext, PayloadError, MAX_PAYLOAD_BYTES,
};

use crate::warn;

pub fn run(engine: &Engine, hook_exit: bool, agent: &str) -> ExitCode {
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        let audit = Audit::new(agent, HookContext::default());
        warn("could not read hook payload; failing open (allow)");
        audit.write(
            "",
            DecisionKind::ErrorAllowed,
            None,
            Some("could not read hook payload"),
        );
        return allow(hook_exit);
    }
    let audit = Audit::new(agent, context_from_hook_json(&buf));
    let command = match command_from_hook_json(&buf, MAX_PAYLOAD_BYTES) {
        Ok(c) => c,
        Err(e) => {
            warn(&format!(
                "hook payload not usable ({e}); failing open (allow)"
            ));
            audit.write(
                &salvage_command(&buf, &e),
                DecisionKind::ErrorAllowed,
                None,
                Some(&format!("hook payload not usable: {e}")),
            );
            return allow(hook_exit);
        }
    };

    decide(&audit, &command, hook_exit, |c| engine.evaluate(c))
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
            return allow(hook_exit);
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
        Decision::Allow { .. } => allow(hook_exit),
    }
}

/// Payloads up to this size are still parsed after `TooLarge`, only to put
/// the command in the audit record. Bounded so this stays cheap.
const SALVAGE_MAX_BYTES: usize = 4 * MAX_PAYLOAD_BYTES;

/// For an oversize payload that is otherwise valid JSON with a command, the
/// command (the record masks and truncates it), so the log shows what ran
/// unjudged. Empty for anything else. Never affects the verdict.
fn salvage_command(buf: &str, err: &PayloadError) -> String {
    match err {
        PayloadError::TooLarge => {
            command_from_hook_json(buf, SALVAGE_MAX_BYTES).unwrap_or_default()
        }
        _ => String::new(),
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

fn allow(hook_exit: bool) -> ExitCode {
    if hook_exit {
        ExitCode::SUCCESS
    } else {
        emit_allow()
    }
}

/// Emit a PreToolUse "allow" response and exit 0.
fn emit_allow() -> ExitCode {
    println!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}}"#
    );
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
