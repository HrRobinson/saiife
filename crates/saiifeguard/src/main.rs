//! saiifeguard CLI.
//!
//! - `saiifeguard test "<cmd>"` -> exit 0 allow / exit 1 deny (reason to stderr)
//! - `saiifeguard explain "<cmd>"` -> decision trace to stdout, always exit 0
//! - `saiifeguard check` -> read agent PreToolUse JSON on stdin, emit the hook
//!   allow/block response; FAIL OPEN on error.

use std::io::{Read, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::payload::{command_from_hook_json, MAX_PAYLOAD_BYTES};
use saiifeguard::profile::select_active;

#[derive(Parser)]
#[command(name = "saiifeguard", version, about = "saiife command guard")]
struct Cli {
    /// Enable an opt-in pack by id (repeatable), e.g. `--pack cloud.gcloud`.
    /// Default-on packs (core.*) are always active.
    #[arg(long = "pack", global = true, value_name = "PACK_ID")]
    packs: Vec<String>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Judge a command: exit 0 = allow, exit 1 = deny.
    Test { command: String },
    /// Print the full decision trace for a command (always exit 0).
    Explain { command: String },
    /// Hook mode: read a PreToolUse JSON payload on stdin, emit the response.
    Check {
        /// Deny via exit code 2 + stderr reason (universal agent contract)
        /// instead of the JSON permissionDecision payload.
        #[arg(long = "hook-exit")]
        hook_exit: bool,
        /// Append a JSONL record for each DENY to this file (best-effort).
        #[arg(long = "audit-log", value_name = "PATH")]
        audit_log: Option<String>,
        /// Tag (pane id) attached to audit records.
        #[arg(long = "audit-tag", value_name = "TAG")]
        audit_tag: Option<String>,
        /// Overwrite a per-tag invocation marker at <PATH>/<audit-tag> on EVERY
        /// evaluation (allow or deny), so saiife can observe that the hook
        /// actually fired for this pane. Best-effort; overwrite (truncate)
        /// semantics — one small file per tag, no unbounded growth.
        #[arg(long = "seen-dir", value_name = "PATH")]
        seen_dir: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Load the shipped built-in packs. Warnings are surfaced on stderr but are
    // never fatal (fail open). The default profile is default-on packs only;
    // `--pack <id>` additively enables opt-in packs.
    let (packs, warnings) = builtin_packs();
    for w in &warnings {
        warn(&format!("pack warning ({}): {}", w.source, w.message));
    }
    let engine = Engine::new(select_active(packs, &cli.packs));

    match cli.command {
        Cmd::Test { command } => cmd_test(&engine, &command),
        Cmd::Explain { command } => cmd_explain(&engine, &command),
        Cmd::Check {
            hook_exit,
            audit_log,
            audit_tag,
            seen_dir,
        } => cmd_check(
            &engine,
            hook_exit,
            audit_log.as_deref(),
            audit_tag.as_deref(),
            seen_dir.as_deref(),
        ),
    }
}

fn cmd_test(engine: &Engine, command: &str) -> ExitCode {
    match engine.evaluate(command) {
        Decision::Deny {
            pack,
            reason,
            via_inline,
            ..
        } => {
            let where_ = via_inline
                .as_deref()
                .map(|i| format!(" (inline: {i})"))
                .unwrap_or_default();
            warn(&format!("BLOCKED by {pack}: {reason}{where_}"));
            ExitCode::from(1)
        }
        Decision::Allow { .. } => ExitCode::SUCCESS,
    }
}

fn cmd_explain(engine: &Engine, command: &str) -> ExitCode {
    let decision = engine.evaluate(command);
    let mut out = String::new();
    out.push_str(&format!("command: {command}\n"));
    match decision {
        Decision::Deny {
            pack,
            pattern,
            reason,
            via_inline,
        } => {
            out.push_str("decision: DENY\n");
            out.push_str(&format!("pack:     {pack}\n"));
            out.push_str(&format!("rule:     {pattern}\n"));
            out.push_str(&format!("reason:   {reason}\n"));
            if let Some(inner) = via_inline {
                out.push_str(&format!("matched inside inline payload: {inner}\n"));
            }
        }
        Decision::Allow { trace } => {
            out.push_str("decision: ALLOW\n");
            match trace {
                AllowTrace::NoMatch => {
                    out.push_str("reason:   no pack deny rule matched\n");
                }
                AllowTrace::AllowRule {
                    pack,
                    pattern,
                    reason,
                } => {
                    out.push_str(&format!("allowed by pack: {pack}\n"));
                    out.push_str(&format!("allow rule:      {pattern}\n"));
                    out.push_str(&format!("reason:          {reason}\n"));
                }
                AllowTrace::FailedOpenTimeout => {
                    out.push_str("reason:   guard exceeded its latency budget; failed open\n");
                }
            }
        }
    }
    print!("{out}");
    ExitCode::SUCCESS
}

fn cmd_check(
    engine: &Engine,
    hook_exit: bool,
    audit_log: Option<&str>,
    audit_tag: Option<&str>,
    seen_dir: Option<&str>,
) -> ExitCode {
    // Fail open: any error reading/parsing the payload -> allow.
    let mut buf = String::new();
    if std::io::stdin().read_to_string(&mut buf).is_err() {
        warn("could not read hook payload; failing open (allow)");
        return if hook_exit {
            ExitCode::SUCCESS
        } else {
            emit_allow()
        };
    }
    let command = match command_from_hook_json(&buf, MAX_PAYLOAD_BYTES) {
        Ok(c) => c,
        Err(e) => {
            warn(&format!(
                "hook payload not usable ({e}); failing open (allow)"
            ));
            return if hook_exit {
                ExitCode::SUCCESS
            } else {
                emit_allow()
            };
        }
    };
    let decision = engine.evaluate(&command);
    // Best-effort invocation marker: proves the hook fired for this pane. Placed
    // after evaluate and before any verdict return so the verdict is emitted
    // regardless of marker outcome (observability, never enforcement).
    if let Some(dir) = seen_dir {
        write_seen_marker(dir, audit_tag);
    }
    if let (Some(path), Decision::Deny { reason, pack, .. }) = (audit_log, &decision) {
        append_audit(path, audit_tag, &command, reason, pack);
    }
    match decision {
        Decision::Deny {
            pack,
            reason,
            via_inline,
            ..
        } => {
            // Same "BLOCKED by <pack>: <reason> (inline: ...)" shape as
            // `cmd_test`/`cmd_explain` for this identical Decision::Deny — the
            // hook path is what a real user hits day to day, so it must not
            // drop the pack name the other two paths already surface. This
            // only enriches the message; the decision itself (deny, exit 2 /
            // permissionDecision: deny) is unchanged.
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
        Decision::Allow { .. } => {
            if hook_exit {
                ExitCode::SUCCESS
            } else {
                emit_allow()
            }
        }
    }
}

/// Best-effort append of one JSONL deny record. Never fails the process.
fn append_audit(path: &str, tag: Option<&str>, command: &str, reason: &str, pack: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let rec = serde_json::json!({
        "ts": ts, "tag": tag, "command": command, "reason": reason, "pack": pack,
    });
    use std::io::Write as _;
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| writeln!(f, "{rec}"));
}

/// Best-effort per-tag invocation marker. Overwrites <dir>/<tag> with the
/// current epoch-ms each call — one small file per tag, rewritten in place,
/// so the directory never grows. Any error (bad dir, permissions, unusable
/// tag) is swallowed: this is observability, never enforcement, and must
/// never influence the guard verdict.
fn write_seen_marker(dir: &str, tag: Option<&str>) {
    let Some(tag) = tag else { return };
    // Defense in depth: never let a tag escape `dir`. Guard tags are pane
    // UUIDs ([A-Za-z0-9-]+); reject anything with a separator or `..`.
    if tag.is_empty() || tag.contains('/') || tag.contains('\\') || tag.contains("..") {
        return;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(std::path::Path::new(dir).join(tag), ts.to_string());
}

/// Emit a PreToolUse "allow" response and exit 0.
fn emit_allow() -> ExitCode {
    println!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow"}}}}"#
    );
    ExitCode::SUCCESS
}

/// Emit a PreToolUse "deny" response with a reason and exit 0 (the JSON carries
/// the block decision).
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

fn warn(msg: &str) {
    let _ = writeln!(std::io::stderr(), "saiifeguard: {msg}");
}
