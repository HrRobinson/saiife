//! saiife CLI.
//!
//! - `saiife test "<cmd>"` -> exit 0 allow / exit 1 deny (reason to stderr)
//! - `saiife explain "<cmd>"` -> decision trace to stdout, always exit 0
//! - `saiife check` -> read agent pre-tool JSON on stdin, audit, answer the hook (silent allow / block); FAIL OPEN on error.
//! - `saiife init [--off]` -> hook the agents into this project (or remove exactly that)
//! - `saiife status` -> tamper checks; exit 1 if any fails
//! - `saiife packs` -> list packs and which are on here
//! - `saiife audit` -> the audit log as a table

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod audit_cmd;
mod check;
mod init_cmd;
mod packs_cmd;
mod paths;
mod project;
mod status_cmd;

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::profile::select_active;

#[derive(Parser)]
#[command(
    name = "saiife",
    version,
    about = "Guard and audit for AI coding agents"
)]
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
    /// Hook mode: read a pre-tool JSON payload on stdin, decide, audit, respond.
    Check {
        /// Deny via exit code 2 + stderr reason (universal agent contract)
        /// instead of the JSON permissionDecision payload.
        #[arg(long = "hook-exit")]
        hook_exit: bool,
        /// Which agent is calling (claude, codex, gemini); recorded in the audit log.
        #[arg(long = "agent", default_value = "unknown")]
        agent: String,
    },
    /// Turn saiife on for this project: write the guard hook into each
    /// agent's project config and create .saiife/config.toml.
    Init {
        /// Agent to set up (claude, codex, gemini; repeatable). Default: every
        /// supported agent found on PATH.
        #[arg(long = "agent", value_name = "AGENT")]
        agents: Vec<String>,
        /// Remove exactly what `saiife init` added.
        #[arg(long, conflicts_with = "agents")]
        off: bool,
    },
    /// Check that this project is still guarded; exit 1 if any check fails.
    Status,
    /// List packs: id, on by default, on here, rule count, summary.
    Packs,
    /// Show the audit log: every allowed, blocked and fail-open decision.
    Audit {
        /// Only records newer than this, e.g. 30m, 24h, 7d.
        #[arg(long)]
        since: Option<String>,
        /// Only records from this project directory (or below it).
        #[arg(long)]
        project: Option<String>,
        /// Only records from this agent (claude, codex, gemini).
        #[arg(long)]
        agent: Option<String>,
        /// Only blocked actions.
        #[arg(long)]
        blocked: bool,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => return arg_error(e),
    };

    // Load the shipped built-in packs. Warnings are surfaced on stderr but are
    // never fatal (fail open). The default profile is default-on packs only;
    // `--pack <id>` additively enables opt-in packs.
    let (packs, warnings) = builtin_packs();
    for w in &warnings {
        warn(&format!("pack warning ({}): {}", w.source, w.message));
    }
    // `test`/`explain` resolve relative paths against this directory, like
    // a hook resolves them against the agent's.
    let cwd = std::env::current_dir().ok();
    let project = cwd
        .as_deref()
        .and_then(saiife_agents::config::find_project_root);
    let engine = || {
        Engine::new(select_active(packs.clone(), &cli.packs))
            .with_paths(paths::path_vars(cwd.as_deref(), project.as_deref()))
    };

    match cli.command {
        Cmd::Test { command } => cmd_test(&engine(), &command),
        Cmd::Explain { command } => cmd_explain(&engine(), &command),
        Cmd::Check { hook_exit, agent } => check::run(packs, &cli.packs, hook_exit, &agent),
        Cmd::Init { off: true, .. } => init_cmd::off(),
        Cmd::Init { agents, off: false } => init_cmd::run(&packs, &agents, &cli.packs),
        Cmd::Status => status_cmd::run(&packs),
        Cmd::Packs => packs_cmd::run(&packs, &cli.packs),
        Cmd::Audit {
            since,
            project,
            agent,
            blocked,
        } => audit_cmd::run(
            since.as_deref(),
            project.as_deref(),
            agent.as_deref(),
            blocked,
        ),
    }
}

/// Bad arguments. In hook mode (`saiife check …`) clap's usual exit 2 would
/// read as "block" to every agent, e.g. after a newer saiife wrote a hook
/// flag this binary does not know: warn and fail open, silently on stdout.
/// Everything else (and `--help` / `--version`) keeps clap's behavior.
fn arg_error(e: clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    let hook_mode = std::env::args_os().nth(1).is_some_and(|a| a == "check");
    if hook_mode && !matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
        let first = e.to_string();
        let first = first
            .lines()
            .next()
            .unwrap_or("")
            .trim_start_matches("error: ");
        warn(&format!(
            "bad hook arguments ({first}); failing open (allow)"
        ));
        let args: Vec<String> = std::env::args_os()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        check::record_arg_error(&args, first);
        return ExitCode::SUCCESS;
    }
    e.exit()
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
                AllowTrace::Unjudgeable { reason } => {
                    out.push_str(&format!("reason:   not judged ({reason}); failed open\n"));
                }
            }
        }
    }
    print!("{out}");
    ExitCode::SUCCESS
}

pub(crate) fn warn(msg: &str) {
    let _ = writeln!(std::io::stderr(), "saiife: {msg}");
}
