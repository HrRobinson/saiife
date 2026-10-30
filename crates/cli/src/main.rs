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
//! - `saiife daemon --system` -> saiifed, the locked-mode daemon (Linux or macOS, as the daemon user)
//! - `saiife daemon --user` -> the personal broker, as the logged-in user (Linux; not a security boundary)
//! - `saiife system install|uninstall` -> set up or remove locked mode (Linux, root)
//! - `saiife secret add|list|rotate|remove|import` -> the vault, through the daemon (Linux or macOS, admin)
//! - `saiife api <service> <operation> [k=v ...]` / `--list` -> connector calls through the daemon (Linux or macOS)
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
mod audit_locked;
#[cfg(unix)]
mod broker;
mod check;
mod check_managed;
// Used by `saiife api collection`, which needs Linux or macOS.
#[cfg_attr(not(unix), allow(dead_code))]
mod collection;
mod connect_cmd;
mod doctor_cmd;
mod env_cmd;
mod eval;
#[cfg(debug_assertions)]
mod fake_mcp;
#[cfg(unix)]
mod import_cmd;
mod init_cmd;
mod lockdown_cmd;
mod mcp_cmd;
#[cfg(target_os = "linux")]
mod mcp_spawn;
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
        /// Locked mode (Linux, macOS): judge in a worker process, record through
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
        /// Only records of this kind (locked mode).
        #[arg(long, value_parser = ["connector", "approval", "guard"])]
        kind: Option<String>,
        /// Only records of this connector service (locked mode).
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true)]
        system_config: Option<std::path::PathBuf>,
        /// The personal broker's log ($XDG_DATA_HOME/saiife/broker/audit;
        /// not a security boundary).
        #[arg(long, conflicts_with = "system_config")]
        broker: bool,
        /// Write a self-contained HTML report instead of the table (default name: saiife-report-YYYY-MM-DD.html here).
        #[arg(long, value_name = "PATH", num_args = 0..=1, default_missing_value = "")]
        report: Option<String>,
    },
    /// Run saiifed: the locked-mode daemon (--system, as the `[daemon] user`) or the personal broker (--user) (Linux).
    Daemon {
        /// System daemon mode (locked mode).
        #[arg(long, conflicts_with = "user")]
        system: bool,
        /// Personal broker mode, as your own user ($XDG_RUNTIME_DIR/saiife/;
        /// not a security boundary).
        #[arg(long)]
        user: bool,
        /// With --user: print the systemd user unit or the launchd plist
        /// for this binary and exit (writes no file, runs no service manager).
        #[arg(long = "print-unit", value_name = "KIND", requires = "user", value_parser = ["systemd", "launchd"])]
        print_unit: Option<String>,
        /// Test seam (debug builds): the locked-host marker to check.
        #[cfg(debug_assertions)]
        #[arg(long = "locked-marker", value_name = "PATH", hide = true)]
        locked_marker: Option<std::path::PathBuf>,
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long, value_name = "FILE")]
        config: Option<std::path::PathBuf>,
        /// Where the signing key lives (default $STATE_DIRECTORY, else /var/lib/saiife).
        #[arg(long = "state-dir", value_name = "DIR")]
        state_dir: Option<std::path::PathBuf>,
        /// Where `vault-key` lives (default $CREDENTIALS_DIRECTORY; macOS:
        /// `vault.key` in /var/db/saiife/keys).
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
    /// The MCP gateway's spawn helper (the daemon runs it): reads a spawn
    /// spec on stdin, confines itself, execs the server.
    #[command(name = "__mcp-spawn", hide = true)]
    McpSpawn,
    /// Test seam (debug builds): a scripted MCP stdio server.
    #[cfg(debug_assertions)]
    #[command(name = "__fake-mcp-server", hide = true)]
    FakeMcpServer(fake_mcp::FakeArgs),
    /// Locked mode (Linux, macOS, admin): add, list, rotate or remove the
    /// secrets in the daemon's vault. Values never leave the daemon.
    Secret {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true, global = true)]
        system_config: Option<std::path::PathBuf>,
        #[command(subcommand)]
        action: secret_cmd::SecretAction,
    },
    /// Locked mode (Linux, macOS, admin): set up a connector service. Stores its
    /// secret and writes policy.d/<service>.toml with every operation
    /// commented out (deny-all until you edit it).
    Connect(connect_cmd::ConnectArgs),
    /// Locked mode (Linux, macOS): run one allowed, root-owned command with a
    /// secret in its environment; its output is masked.
    ///
    /// Trust boundary: any process of the agent's uid can lease a listed
    /// secret from the daemon; the executable check binds only this honest
    /// client. The boundary is the uid plus its scope. The command runs as
    /// you and holds the value while it runs. Prefer a connector wherever
    /// one exists, and list only purpose-built, argument-constrained
    /// programs in run_allow.
    ///
    /// `--cloud <service>` (STS mode) instead puts AWS session credentials
    /// for that service in the command's environment: at most 15 minutes,
    /// scoped by a session policy built from the saiife policy. As with
    /// `--secret`, any process of your uid can obtain these credentials
    /// from the daemon; the executable check binds only this client.
    #[command(group(
        clap::ArgGroup::new("lease")
            .required(true)
            .args(["secrets", "cloud"])
    ))]
    Run {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true)]
        system_config: Option<std::path::PathBuf>,
        /// The secret and the variable to set: NAME or NAME:ENV_VAR.
        #[arg(long = "secret", value_name = "NAME[:ENV_VAR]")]
        secrets: Vec<String>,
        /// STS mode: short AWS credentials for this service (`mode = "sts"`).
        /// Any process of your uid can obtain them from the daemon; the
        /// executable check binds only this client.
        #[arg(long = "cloud", value_name = "SERVICE")]
        cloud: Option<String>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// Locked mode (Linux, macOS): call a connector operation through the daemon,
    /// or list the ones you may call. The credential never reaches you.
    Api(api_cmd::ApiArgs),
    /// Locked mode (Linux, macOS): an MCP server on stdio that offers the
    /// connector operations you may call as tools, each call brokered by
    /// the daemon like `saiife api`.
    Mcp(mcp_cmd::McpArgs),
    /// Locked mode (Linux, macOS): list, show and decide ask-gated requests.
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
    /// Locked mode (Linux, macOS, approver): approve request <id>. For your own
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
    /// Locked mode (Linux, macOS, approver): reject request <id>.
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
    /// Locked mode (Linux, macOS, admin or approver): `on` denies every connector
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
    /// Environments (`[environments.<name>]`): list them, or choose the
    /// one that applies (locked mode: root rebinds a scope).
    Env {
        /// The system config (default /etc/saiife/config.toml).
        #[arg(long = "system-config", hide = true, global = true)]
        system_config: Option<std::path::PathBuf>,
        #[command(subcommand)]
        action: env_cmd::EnvAction,
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
        /// Check the personal broker's log instead (not a security boundary).
        #[arg(long, conflicts_with_all = ["system_config", "external"])]
        broker: bool,
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
    if let Cmd::McpSpawn = cli.command {
        #[cfg(target_os = "linux")]
        return mcp_spawn::run();
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("saiife: __mcp-spawn: the MCP gateway needs Linux");
            return ExitCode::from(126);
        }
    }
    #[cfg(debug_assertions)]
    if let Cmd::FakeMcpServer(args) = cli.command {
        return fake_mcp::run(args);
    }
    if let Cmd::Daemon {
        system,
        user,
        print_unit,
        #[cfg(debug_assertions)]
        locked_marker,
        config,
        state_dir,
        credentials_dir,
    } = cli.command
    {
        // Release builds have no `--locked-marker`: always the real one.
        #[cfg(not(debug_assertions))]
        let locked_marker: Option<std::path::PathBuf> = None;
        return cmd_daemon(DaemonArgs {
            system,
            user,
            print_unit,
            locked_marker,
            config,
            state_dir,
            credentials_dir,
        });
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
        cloud,
        command,
    } = cli.command
    {
        return run_cmd::run(run_cmd::RunArgs {
            system_config,
            secrets,
            cloud,
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
    if let Cmd::Mcp(a) = cli.command {
        return mcp_cmd::run(a);
    }
    if let Cmd::Policy {
        system_config,
        action,
    } = cli.command
    {
        return policy_cmd::run(system_config, action);
    }
    if let Cmd::Env {
        system_config,
        action,
    } = cli.command
    {
        return env_cmd::run(system_config, action);
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
        #[cfg(debug_assertions)]
        Cmd::FakeMcpServer(_) => unreachable!("handled above"),
        Cmd::Check { .. }
        | Cmd::Eval
        | Cmd::McpSpawn
        | Cmd::Daemon { .. }
        | Cmd::System { .. }
        | Cmd::Secret { .. }
        | Cmd::Connect(..)
        | Cmd::Run { .. }
        | Cmd::Api(_)
        | Cmd::Mcp(_)
        | Cmd::Lockdown { .. }
        | Cmd::Approvals { .. }
        | Cmd::Policy { .. }
        | Cmd::Env { .. }
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
                    broker,
                }),
            ..
        } => audit_cmd::verify(external.as_deref(), system_config.as_deref(), broker),
        Cmd::Audit {
            action: None,
            since,
            project,
            agent,
            blocked,
            kind,
            service,
            system_config,
            broker,
            report,
        } => audit_cmd::run(
            audit_cmd::RunArgs {
                since: since.as_deref(),
                project: project.as_deref(),
                agent: agent.as_deref(),
                blocked,
                kind: kind.as_deref(),
                service: service.as_deref(),
                report: report.as_deref(),
                system_config,
                broker,
            },
            &packs,
        ),
    }
}

/// The `saiife daemon` flags.
struct DaemonArgs {
    system: bool,
    user: bool,
    print_unit: Option<String>,
    /// `--locked-marker` (debug builds); `None` is the real marker.
    locked_marker: Option<std::path::PathBuf>,
    config: Option<std::path::PathBuf>,
    state_dir: Option<std::path::PathBuf>,
    credentials_dir: Option<std::path::PathBuf>,
}

/// `saiife daemon --system`: the system daemon, as the `[daemon] user`.
/// `saiife daemon --user`: the personal broker, as the logged-in user.
fn cmd_daemon(a: DaemonArgs) -> ExitCode {
    if a.system == a.user {
        eprintln!(
            "saiife: use `saiife daemon --system` (locked mode) or `saiife daemon --user` (personal broker)"
        );
        return ExitCode::from(2);
    }
    if a.user {
        return cmd_daemon_user(a);
    }
    let DaemonArgs {
        config,
        state_dir,
        credentials_dir,
        ..
    } = a;
    let platform = saiife_system::layout::Platform::current()
        .unwrap_or(saiife_system::layout::Platform::Linux);
    // systemd's StateDirectory= may list several dirs, colon-separated.
    let state_dir = state_dir
        .or_else(|| {
            std::env::var_os("STATE_DIRECTORY")
                .and_then(|v| v.to_str().and_then(|s| s.split(':').next()).map(Into::into))
                .filter(|p: &std::path::PathBuf| !p.as_os_str().is_empty())
        })
        .unwrap_or_else(|| daemon_default_dirs(platform).0.into());
    saiife_daemon::run(saiife_daemon::DaemonOptions {
        config: config.unwrap_or_else(|| daemon_default_config(platform).into()),
        state_dir,
        credentials_dir: credentials_dir
            .or_else(|| std::env::var_os("CREDENTIALS_DIRECTORY").map(Into::into))
            .filter(|p: &std::path::PathBuf| !p.as_os_str().is_empty())
            .or_else(|| daemon_default_dirs(platform).1.map(Into::into)),
        catalog: daemon_catalog(),
        directory: Box::new(saiife_policy::Getent),
        mode: saiife_daemon::DaemonMode::System,
    })
}

/// `saiife daemon --system`'s config when `--config` does not name one:
/// the platform's `layout::CONFIG`.
fn daemon_default_config(p: saiife_system::layout::Platform) -> &'static str {
    use saiife_system::layout::{macos_path, Platform, CONFIG};
    match p {
        Platform::Linux => CONFIG,
        Platform::Macos => macos_path(CONFIG).unwrap_or(CONFIG),
    }
}

/// `saiife daemon --system`'s state and credentials dirs when neither a
/// flag nor systemd (`$STATE_DIRECTORY`, `$CREDENTIALS_DIRECTORY`) names
/// them. launchd sets neither, so macOS has both (spec 5.3).
fn daemon_default_dirs(p: saiife_system::layout::Platform) -> (&'static str, Option<&'static str>) {
    use saiife_system::layout::{macos_path, Platform, KEYS_DIR, STATE_DIR};
    match p {
        Platform::Linux => (STATE_DIR, None),
        Platform::Macos => (
            macos_path(STATE_DIR).unwrap_or(STATE_DIR),
            macos_path(KEYS_DIR),
        ),
    }
}

/// `saiife daemon --user` (plan 16): the personal paths, the refusals that
/// need nothing opened, then the keychain. A keychain that cannot be
/// opened still starts the broker, with the vault unavailable.
fn cmd_daemon_user(a: DaemonArgs) -> ExitCode {
    if let Some(kind) = &a.print_unit {
        return print_unit(kind);
    }
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        eprintln!("{}", saiife_daemon::PERSONAL_UNSUPPORTED);
        return ExitCode::from(2);
    }
    if a.config.is_some() || a.state_dir.is_some() || a.credentials_dir.is_some() {
        eprintln!(
            "saiife: daemon --user takes no --config, --state-dir or --credentials-dir: its paths are fixed (XDG)"
        );
        return ExitCode::from(2);
    }
    let home = dirs::home_dir();
    let paths =
        match saiife_system::personal::personal_paths(&|k| std::env::var_os(k), home.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("saiife: {e}");
                return ExitCode::from(2);
            }
        };
    let locked_marker = a
        .locked_marker
        .unwrap_or_else(|| saiife_system::layout::INSTALLED.into());
    // A locked host, root or a bad runtime dir is refused before the
    // keychain is touched.
    if let Err(e) =
        saiife_daemon::personal_preflight(&paths.config, &paths.socket_dir, &locked_marker)
    {
        eprintln!("saiife: {e}");
        return ExitCode::from(2);
    }
    let keychain: Box<dyn saiife_keychain::Keychain> = match saiife_keychain::from_env() {
        Ok(k) => k,
        Err(e) => Box::new(saiife_daemon::UnavailableKeychain(e)),
    };
    saiife_daemon::run(saiife_daemon::DaemonOptions {
        config: paths.config,
        state_dir: paths.state_dir,
        credentials_dir: None,
        catalog: daemon_catalog(),
        directory: Box::new(saiife_policy::Getent),
        mode: saiife_daemon::DaemonMode::Personal {
            socket_dir: paths.socket_dir,
            audit_dir: paths.audit_dir,
            keychain,
            locked_marker,
        },
    })
}

/// `saiife daemon --user --print-unit systemd|launchd`: the text for this
/// binary on stdout.
fn print_unit(kind: &str) -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("saiife: cannot find this binary: {e}");
            return ExitCode::from(2);
        }
    };
    let text = match kind {
        "systemd" => saiife_system::user_unit::user_unit_text(&exe),
        _ => saiife_system::user_unit::launchd_plist_text(&exe),
    };
    match text {
        Ok(t) => {
            print!("{t}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("saiife: {e}");
            ExitCode::from(2)
        }
    }
}

/// The built-in packs as the daemon's policy catalog.
fn daemon_catalog() -> Vec<saiife_policy::PackInfo> {
    let (packs, warnings) = builtin_packs();
    for w in &warnings {
        warn(&format!("pack warning ({}): {}", w.source, w.message));
    }
    packs
        .iter()
        .map(|p| saiife_policy::PackInfo {
            id: p.id.clone(),
            version: p.version,
            default_on: p.default_on,
            rules: p.deny_rules().iter().filter_map(|r| r.id.clone()).collect(),
        })
        .collect()
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

#[cfg(test)]
mod daemon_default_tests {
    use super::{daemon_default_config, daemon_default_dirs};
    use saiife_system::layout::Platform;

    #[test]
    fn daemon_defaults_per_platform() {
        assert_eq!(
            daemon_default_dirs(Platform::Linux),
            ("/var/lib/saiife", None)
        );
        assert_eq!(
            daemon_default_dirs(Platform::Macos),
            ("/var/db/saiife", Some("/var/db/saiife/keys"))
        );
        assert_eq!(
            daemon_default_config(Platform::Linux),
            "/etc/saiife/config.toml"
        );
        assert_eq!(
            daemon_default_config(Platform::Macos),
            "/etc/saiife/config.toml"
        );
    }
}
