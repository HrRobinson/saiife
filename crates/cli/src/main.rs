//! saiife CLI.
//!
//! - `saiife test "<cmd>"` -> exit 0 allow / exit 1 deny (reason to stderr)
//! - `saiife explain "<cmd>"` / `--read <path>` / `--write <path>` -> decision trace to stdout, always exit 0
//! - `saiife check` -> read agent pre-tool JSON on stdin, audit, answer the hook (silent allow / block); FAIL OPEN on error.
//! - `saiife check --managed` -> locked mode: guard in a worker, record through the daemon; FAIL CLOSED on error.
//! - `saiife init [--off]` -> hook the agents into this project (or remove exactly that)
//! - `saiife status` -> tamper checks; exit 1 if any fails
//! - `saiife packs [ID]` -> list packs and which are on here, or one pack's rules
//! - `saiife audit` -> the audit log as a table
//! - `saiife daemon --system` -> saiifed, the locked-mode daemon (Linux, as the daemon user)
//! - `saiife system install|uninstall` -> set up or remove locked mode (Linux, root)
//! - `saiife secret add|list|rotate|remove|import` -> the vault, through the daemon (Linux, admin)
//! - `saiife api <service> <operation> [k=v ...]` / `--list` -> connector calls through the daemon (Linux)
//! - `saiife policy check|test <file>` / `show` / `reload` -> check and test a policy file; show or reload the one in force
//! - `saiife doctor [--json]` -> locked-mode host checks; exit 0 pass / 1 warning / 2 failure

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[macro_use]
mod out;

mod api_cmd;
mod approvals_cmd;
mod audit_cmd;
mod check;
mod check_managed;
mod connect_cmd;
mod doctor_cmd;
mod eval;
#[cfg(target_os = "linux")]
mod import_cmd;
mod init_cmd;
mod lockdown_cmd;
mod packs_cmd;
mod paths;
mod policy_cmd;
mod project;
mod report;
mod report_html;
mod run_cmd;
mod secret_cmd;
mod status_cmd;
mod system_cmd;
mod system_view;
mod text;

use saiifeguard::builtins::builtin_packs;
use saiifeguard::engine::{AllowTrace, Decision, Engine};
use saiifeguard::pathrule::Access;
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
    /// Print the full decision trace for a command, or for a file tool
    /// reading or writing a path (always exit 0).
    #[command(group(clap::ArgGroup::new("what").required(true).args(["command", "read", "write"])))]
    Explain {
        command: Option<String>,
        /// Explain a read tool (Read, read_file, …) opening this path.
        #[arg(long, value_name = "PATH")]
        read: Option<String>,
        /// Explain a write tool (Write, Edit, apply_patch, …) changing this path.
        #[arg(long, value_name = "PATH")]
        write: Option<String>,
    },
    /// Hook mode: read a pre-tool JSON payload on stdin, decide, audit, respond.
    Check {
        /// Deny via exit code 2 + stderr reason (universal agent contract)
        /// instead of the JSON permissionDecision payload.
        #[arg(long = "hook-exit")]
        hook_exit: bool,
        /// Which agent is calling (claude, codex, gemini); recorded in the audit log.
        #[arg(long = "agent", default_value = "unknown")]
        agent: String,
        /// Locked mode (Linux): judge in a worker process, record through
        /// the saiife daemon, fail closed on every error. Implies --hook-exit.
        #[arg(long)]
        managed: bool,
        /// The system config (default /etc/saiife/config.toml). The
        /// developer hook reads which agents are managed and whether to
        /// fail closed from it.
        #[arg(long = "system-config", hide = true)]
        system_config: Option<std::path::PathBuf>,
        /// The hook event when it is not a tool call (Claude Code's
        /// ConfigChange hook: `config-change`). Locked mode only.
        #[arg(long, value_parser = ["config-change"], requires = "managed")]
        event: Option<String>,
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
        /// Read the locked-mode tree under this directory (tests).
        #[arg(long, hide = true, value_name = "DIR")]
        root: Option<std::path::PathBuf>,
    },
    /// Check that this project is still guarded; exit 1 if any check fails.
    Status {
        /// Read the locked-mode tree under this directory (tests).
        #[arg(long, hide = true, value_name = "DIR")]
        root: Option<std::path::PathBuf>,
    },
    /// List packs: id, on by default, on here, rule count, summary. With a
    /// pack id: that pack's command and path rules.
    Packs {
        /// Show the rules of this pack.
        #[arg(value_name = "ID")]
        id: Option<String>,
    },
    /// Show the audit log: every allowed, blocked and fail-open decision.
    #[command(args_conflicts_with_subcommands = true)]
    Audit {
        #[command(subcommand)]
        action: Option<AuditAction>,
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
        /// Write a self-contained HTML report instead of the table (default name: saiife-report-YYYY-MM-DD.html here).
        #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "")]
        report: Option<String>,
    },
    /// Run saiifed, the locked-mode daemon, as the `[daemon] user` (Linux).
    Daemon {
        /// System daemon mode (the only mode in this version).
        #[arg(long)]
        system: bool,
        /// Personal broker mode (after v2.0).
        #[arg(long)]
        user: bool,
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long, value_name = "FILE")]
        config: Option<std::path::PathBuf>,
        /// Where the signing key lives (default $STATE_DIRECTORY, else /var/lib/saiife).
        #[arg(long = "state-dir", value_name = "DIR")]
        state_dir: Option<std::path::PathBuf>,
        /// Where `vault-key` lives (default $CREDENTIALS_DIRECTORY).
        #[arg(long = "credentials-dir", value_name = "DIR", hide = true)]
        credentials_dir: Option<std::path::PathBuf>,
    },
    /// Check the machine locked mode relies on: exit 0 all pass, 1 a
    /// warning, 2 a failure.
    Doctor {
        /// Check this agent user (root only, unless it is you).
        #[arg(long, value_name = "NAME")]
        user: Option<String>,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
        /// Check the locked-mode tree under this directory (tests).
        #[arg(long, hide = true, value_name = "DIR")]
        root: Option<std::path::PathBuf>,
    },
    /// The locked-mode guard worker (`check --managed` spawns it).
    #[command(name = "__eval", hide = true)]
    Eval,
    /// Locked mode (Linux, admin): add, list, rotate or remove the
    /// secrets in the daemon's vault. Values never leave the daemon.
    Secret {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true, global = true)]
        system_config: Option<std::path::PathBuf>,
        #[command(subcommand)]
        action: secret_cmd::SecretAction,
    },
    /// Locked mode (Linux, admin): set up a connector service. Stores its
    /// secret and writes policy.d/<service>.toml with every operation
    /// commented out (deny-all until you edit it).
    Connect(connect_cmd::ConnectArgs),
    /// Locked mode (Linux): run one allowed, root-owned command with a
    /// secret in its environment; its output is masked.
    ///
    /// Trust boundary: any process of the agent's uid can lease a listed
    /// secret from the daemon; the executable check binds only this honest
    /// client. The boundary is the uid plus its scope. The command runs as
    /// you and holds the value while it runs. Prefer a connector wherever
    /// one exists, and list only purpose-built, argument-constrained
    /// programs in run_allow.
    Run {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true)]
        system_config: Option<std::path::PathBuf>,
        /// The secret and the variable to set: NAME or NAME:ENV_VAR.
        #[arg(long = "secret", value_name = "NAME[:ENV_VAR]", required = true)]
        secrets: Vec<String>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// Locked mode (Linux): call a connector operation through the daemon,
    /// or list the ones you may call. The credential never reaches you.
    Api(api_cmd::ApiArgs),
    /// Locked mode (Linux): list, show and decide ask-gated requests.
    /// `approvals [list] [--all|--pending] [--json]`, `approvals show <id>`.
    Approvals {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true, global = true)]
        system_config: Option<std::path::PathBuf>,
        #[command(flatten)]
        list: approvals_cmd::ListArgs,
        #[command(subcommand)]
        action: Option<approvals_cmd::ApprovalsAction>,
    },
    /// Locked mode (Linux, approver): approve request <id>. For your own
    /// request (`same_user = "reauth"`) you are asked to authenticate.
    Approve {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true)]
        system_config: Option<std::path::PathBuf>,
        /// The request's id.
        id: u64,
        /// A note, recorded with the decision.
        #[arg(long)]
        note: Option<String>,
        /// Approve a request whose body is over 1 MiB and was shown cut.
        #[arg(long)]
        accept_truncated: bool,
    },
    /// Locked mode (Linux, approver): reject request <id>.
    Reject {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true)]
        system_config: Option<std::path::PathBuf>,
        /// The request's id.
        id: u64,
        /// A note, recorded with the decision.
        #[arg(long)]
        note: Option<String>,
    },
    /// Locked mode (Linux, admin or approver): `on` denies every connector
    /// request (`--scope connectors`) or also every hook call (`--scope
    /// all`); `off` lifts it; no subcommand shows the state.
    Lockdown {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true, global = true)]
        system_config: Option<std::path::PathBuf>,
        #[command(subcommand)]
        action: Option<lockdown_cmd::LockdownAction>,
    },
    /// Check and test a policy kept in a file (`check`, `test`), or show
    /// and reload the one in force (`show`, `reload`: locked mode).
    Policy {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true, global = true)]
        system_config: Option<std::path::PathBuf>,
        #[command(subcommand)]
        action: policy_cmd::PolicyAction,
    },
    /// Locked mode on Linux: install or uninstall the system setup (root).
    System {
        #[command(subcommand)]
        action: system_cmd::SystemAction,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Check that the audit log has not been edited, reordered or cut.
    Verify {
        /// A forwarded copy (one JSONL file, or a dir of month files): the
        /// local log must hold every checkpoint it has and reach its end.
        #[arg(long, value_name = "FILE|DIR")]
        external: Option<std::path::PathBuf>,
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true)]
        system_config: Option<std::path::PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => return arg_error(e),
    };

    // Hook mode compiles only the packs it needs (it runs on every agent
    // tool call); every other command lists or judges across all packs.
    if let Cmd::Check {
        hook_exit,
        agent,
        managed,
        system_config,
        event,
    } = &cli.command
    {
        if *managed {
            let config = system_config
                .as_deref()
                .unwrap_or(std::path::Path::new(check_managed::SYSTEM_CONFIG));
            return check_managed::run(agent, config, event.as_deref());
        }
        return check::run(&cli.packs, *hook_exit, agent, system_config.as_deref());
    }
    if let Cmd::Eval = cli.command {
        return eval::worker_main();
    }
    if let Cmd::Daemon {
        system,
        user,
        config,
        state_dir,
        credentials_dir,
    } = cli.command
    {
        return cmd_daemon(system, user, config, state_dir, credentials_dir);
    }
    if let Cmd::Secret {
        system_config,
        action,
    } = cli.command
    {
        return secret_cmd::run(system_config, action);
    }
    if let Cmd::Connect(args) = cli.command {
        return connect_cmd::run(args);
    }
    if let Cmd::Run {
        system_config,
        secrets,
        command,
    } = cli.command
    {
        return run_cmd::run(run_cmd::RunArgs {
            system_config,
            secrets,
            command,
        });
    }
    if let Cmd::Lockdown {
        system_config,
        action,
    } = cli.command
    {
        return lockdown_cmd::run(system_config, action);
    }
    if let Cmd::Approvals {
        system_config,
        list,
        action,
    } = cli.command
    {
        return approvals_cmd::run(system_config, list, action);
    }
    if let Cmd::Approve {
        system_config,
        id,
        note,
        accept_truncated,
    } = cli.command
    {
        return approvals_cmd::decide(
            system_config,
            approvals_cmd::Decision::Approve {
                id,
                note,
                accept_truncated,
            },
        );
    }
    if let Cmd::Reject {
        system_config,
        id,
        note,
    } = cli.command
    {
        return approvals_cmd::decide(system_config, approvals_cmd::Decision::Reject { id, note });
    }
    if let Cmd::Api(a) = cli.command {
        return api_cmd::run(a);
    }
    if let Cmd::Policy {
        system_config,
        action,
    } = cli.command
    {
        return policy_cmd::run(system_config, action);
    }
    if let Cmd::System { action } = cli.command {
        return system_cmd::run(action);
    }
    if let Cmd::Doctor { user, json, root } = cli.command {
        return doctor_cmd::run(user, json, root);
    }
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
    let vars = || paths::path_vars(cwd.as_deref(), project.as_deref());
    let engine = || Engine::new(select_active(packs.clone(), &cli.packs)).with_paths(vars());

    let active = || select_active(packs.clone(), &cli.packs);

    match cli.command {
        Cmd::Test { command } => cmd_test(&engine(), &command),
        Cmd::Explain {
            command,
            read,
            write,
        } => match (command, read, write) {
            (_, Some(path), _) => {
                cmd_explain_path(&engine(), &active(), &vars(), Access::Read, &path)
            }
            (_, _, Some(path)) => {
                cmd_explain_path(&engine(), &active(), &vars(), Access::Write, &path)
            }
            (command, _, _) => {
                cmd_explain(&engine(), &active(), &vars(), &command.unwrap_or_default())
            }
        },
        Cmd::Check { .. }
        | Cmd::Eval
        | Cmd::Daemon { .. }
        | Cmd::System { .. }
        | Cmd::Secret { .. }
        | Cmd::Connect(..)
        | Cmd::Run { .. }
        | Cmd::Api(_)
        | Cmd::Lockdown { .. }
        | Cmd::Approvals { .. }
        | Cmd::Policy { .. }
        | Cmd::Approve { .. }
        | Cmd::Reject { .. }
        | Cmd::Doctor { .. } => {
            unreachable!("handled above")
        }
        Cmd::Init {
            off: true, root, ..
        } => init_cmd::off(root),
        Cmd::Init {
            agents,
            off: false,
            root,
        } => init_cmd::run(&packs, &agents, &cli.packs, root),
        Cmd::Status { root } => status_cmd::run(&packs, root),
        Cmd::Packs { id } => packs_cmd::run(&packs, &cli.packs, &vars(), id.as_deref()),
        Cmd::Audit {
            action:
                Some(AuditAction::Verify {
                    external,
                    system_config,
                }),
            ..
        } => audit_cmd::verify(external.as_deref(), system_config.as_deref()),
        Cmd::Audit {
            action: None,
            since,
            project,
            agent,
            blocked,
            report,
        } => audit_cmd::run(
            since.as_deref(),
            project.as_deref(),
            agent.as_deref(),
            blocked,
            report.as_deref(),
            &packs,
        ),
    }
}

/// Bad arguments. In hook mode (`saiife check …`) clap's usual exit 2 would
/// read as "block" to every agent, e.g. after a newer saiife wrote a hook
/// flag this binary does not know: warn and fail open, silently on stdout.
/// Everything else (and `--help` / `--version`) keeps clap's behavior.
/// `saiife daemon --system`: the system daemon, as the `[daemon] user`.
fn cmd_daemon(
    system: bool,
    user: bool,
    config: Option<std::path::PathBuf>,
    state_dir: Option<std::path::PathBuf>,
    credentials_dir: Option<std::path::PathBuf>,
) -> ExitCode {
    if !system || user {
        eprintln!(
            "saiife: use `saiife daemon --system` (personal broker mode, --user, comes after v2.0)"
        );
        return ExitCode::from(2);
    }
    let (packs, warnings) = builtin_packs();
    for w in &warnings {
        warn(&format!("pack warning ({}): {}", w.source, w.message));
    }
    let catalog = packs
        .iter()
        .map(|p| saiife_policy::PackInfo {
            id: p.id.clone(),
            version: p.version,
            default_on: p.default_on,
            rules: p.deny_rules().iter().filter_map(|r| r.id.clone()).collect(),
        })
        .collect();
    // systemd's StateDirectory= may list several dirs, colon-separated.
    let state_dir = state_dir
        .or_else(|| {
            std::env::var_os("STATE_DIRECTORY")
                .and_then(|v| v.to_str().and_then(|s| s.split(':').next()).map(Into::into))
                .filter(|p: &std::path::PathBuf| !p.as_os_str().is_empty())
        })
        .unwrap_or_else(|| "/var/lib/saiife".into());
    saiife_daemon::run(saiife_daemon::DaemonOptions {
        config: config.unwrap_or_else(|| "/etc/saiife/config.toml".into()),
        state_dir,
        credentials_dir: credentials_dir
            .or_else(|| std::env::var_os("CREDENTIALS_DIRECTORY").map(Into::into))
            .filter(|p: &std::path::PathBuf| !p.as_os_str().is_empty()),
        catalog,
        directory: Box::new(saiife_policy::Getent),
    })
}

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
        let args: Vec<String> = std::env::args_os()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // Locked mode never falls back to allow, not even on a flag this
        // binary does not know.
        if args.iter().any(|a| a == "--managed") {
            return check_managed::run_bad_args(&args, first);
        }
        // `--event` belongs to managed hooks only: a hook that passes it
        // without `--managed` is miswritten, not from a newer saiife.
        if args
            .iter()
            .any(|a| a == "--event" || a.starts_with("--event="))
        {
            e.exit()
        }
        return check::arg_error(&args, first);
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

fn cmd_explain(
    engine: &Engine,
    active: &[saiifeguard::Pack],
    vars: &saiifeguard::canon::PathVars,
    command: &str,
) -> ExitCode {
    let decision = engine.evaluate(command);
    out!(
        "command: {command}\n{}{}",
        trace(decision),
        packs_cmd::inactive_summary(active, vars)
    );
    ExitCode::SUCCESS
}

fn cmd_explain_path(
    engine: &Engine,
    active: &[saiifeguard::Pack],
    vars: &saiifeguard::canon::PathVars,
    access: Access,
    path: &str,
) -> ExitCode {
    let decision = engine.evaluate_path(access, path);
    let resolved = engine
        .resolve_path(path)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(cannot be resolved)".into());
    out!(
        "path:     {path}\nresolved: {resolved}\naccess:   {}\n{}{}",
        access.label(),
        trace(decision),
        packs_cmd::inactive_summary(active, vars)
    );
    ExitCode::SUCCESS
}

/// The decision part of an `explain` trace.
fn trace(decision: Decision) -> String {
    let mut out = String::new();
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
    out
}

pub(crate) fn warn(msg: &str) {
    let _ = writeln!(std::io::stderr(), "saiife: {msg}");
}
