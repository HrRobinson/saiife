//! `saiife system install|uninstall`: locked mode on Linux (spec §7). The
//! hidden `--root <dir>` runs the same steps against a tree below `<dir>`
//! with a fake host (tests); without it, the real machine (root only).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use saiife_agents::Agent;
use saiife_policy::Getent;
use saiife_system::doctor::{self, DoctorOptions};
use saiife_system::fleet::fleet_options;
use saiife_system::install::{install, InstallError, InstallOptions};
use saiife_system::uninstall::{uninstall, UninstallOptions};
use saiife_system::{host_for, refusal_line, Host, Layout};

#[derive(Subcommand)]
pub enum SystemAction {
    /// Install locked mode: users, the binary in /opt/saiife, /etc/saiife,
    /// the vault key, the systemd unit and the managed agent hooks; then
    /// start the daemon. Idempotent. Needs root.
    Install {
        /// The system config to install (validated; must say `locked = true`).
        /// Default: keep the current one, or write a commented default.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Agents to lock with managed hooks.
        #[arg(
            long,
            value_name = "LIST",
            value_delimiter = ',',
            value_parser = parse_agent,
            default_value = "claude,codex,gemini"
        )]
        agents: Vec<Agent>,
        /// Approvers for a new default config: users or group:<name>.
        #[arg(long, value_name = "LIST", value_delimiter = ',')]
        approvers: Vec<String>,
        /// Never ask (install asks nothing yet; for scripts).
        #[arg(long)]
        non_interactive: bool,
        /// Read the install options from /etc/saiife/fleet/ (packages and MDM tools)
        #[arg(long, conflicts_with_all = ["config", "agents", "approvers"])]
        fleet: bool,
        /// Install below this directory with a fake host (tests only).
        #[arg(long, hide = true, value_name = "DIR")]
        root: Option<PathBuf>,
        /// Install a dynamically linked or debug-assertions build (the CI
        /// job locked-linux only). Never for production: such a binary lets
        /// an agent inject code into, or hang, the managed hook.
        #[arg(long, hide = true)]
        allow_test_build: bool,
    },
    /// Remove exactly what `system install` listed in installed.toml. The
    /// config, vault key, state, audit, users and groups are kept unless
    /// --purge. Needs root.
    Uninstall {
        /// Keep the audit, state, config and users (the default).
        #[arg(long, conflicts_with = "purge")]
        keep_audit: bool,
        /// Also remove the state dir and the audit, and what install
        /// created: config.toml and the vault key (only if install wrote
        /// them, never an admin's), the users, groups and group memberships.
        #[arg(long)]
        purge: bool,
        /// Uninstall below this directory with a fake host (tests only).
        #[arg(long, hide = true, value_name = "DIR")]
        root: Option<PathBuf>,
    },
}

fn parse_agent(s: &str) -> Result<Agent, String> {
    Agent::from_name(s).ok_or_else(|| format!("unknown agent {s:?} (claude, codex, gemini)"))
}

fn layout_for(root: Option<PathBuf>) -> Layout {
    root.map(Layout::under).unwrap_or_else(Layout::system)
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(2)
}

fn report_error(cmd: &str, e: InstallError) -> ExitCode {
    match e {
        InstallError::NotRoot => fail(format!(
            "saiife: system {cmd} needs root (run it with sudo)"
        )),
        InstallError::Unsupported(why) => fail(refusal_line(&why)),
        InstallError::Refused { path, detail } => fail(format!(
            "saiife: {cmd} failed at check: {}: {detail}",
            path.display()
        )),
        InstallError::Step { step, detail } => {
            fail(format!("saiife: {cmd} failed at {step}: {detail}"))
        }
    }
}

/// `doctor` after a successful install (spec §7): its text on stdout.
/// Exit 0 when it found nothing worse than a warning, 1 on a failure (the
/// install itself stays done; install errors are exit 2).
fn after_install_doctor(layout: &Layout, host: &dyn Host) -> ExitCode {
    let opts = DoctorOptions {
        user: None,
        home: std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute()),
    };
    let report = doctor::run(layout, host, &Getent, &opts);
    outln!();
    out!("{}", report.to_text());
    if report.exit_code() == 2 {
        eprintln!(
            "saiife: installed, but doctor found failures: fix them before relying on the lock"
        );
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

pub fn run(action: SystemAction) -> ExitCode {
    match action {
        SystemAction::Install {
            config,
            agents,
            approvers,
            non_interactive,
            fleet,
            root,
            allow_test_build,
        } => {
            let layout = layout_for(root);
            let host = match host_for(&layout) {
                Ok(h) => h,
                Err(e) => return fail(format!("saiife: install failed at host: {e}")),
            };
            let binary = match std::env::current_exe() {
                Ok(b) => b,
                Err(e) => {
                    return fail(format!(
                        "saiife: install failed at binary: cannot find this program: {e}"
                    ))
                }
            };
            let opts = if fleet {
                match fleet_options(&layout, host.as_ref()) {
                    Ok(o) => InstallOptions {
                        allow_test_build,
                        ..o
                    },
                    Err(e) => return report_error("install", e),
                }
            } else {
                InstallOptions {
                    config,
                    agents,
                    approvers,
                    non_interactive,
                    allow_test_build,
                }
            };
            match install(&layout, host.as_ref(), &opts, &binary) {
                Ok(r) => {
                    for w in &r.warnings {
                        eprintln!("saiife: warning: {w}");
                    }
                    for c in &r.changed {
                        println!("  {c}");
                    }
                    if r.changed.is_empty() {
                        println!("saiife: locked mode is installed; nothing changed");
                    } else {
                        println!("saiife: locked mode is installed; the daemon is running");
                    }
                    after_install_doctor(&layout, host.as_ref())
                }
                Err(e) => report_error("install", e),
            }
        }
        SystemAction::Uninstall {
            keep_audit: _,
            purge,
            root,
        } => {
            let layout = layout_for(root);
            let host = match host_for(&layout) {
                Ok(h) => h,
                Err(e) => return fail(format!("saiife: uninstall failed at host: {e}")),
            };
            match uninstall(&layout, host.as_ref(), &UninstallOptions { purge }) {
                Ok(lines) => {
                    if lines.is_empty() {
                        println!("saiife: nothing to uninstall (no installed.toml)");
                    }
                    for l in lines {
                        match l.strip_prefix("warning: ") {
                            Some(w) => eprintln!("saiife: warning: {w}"),
                            None => println!("{l}"),
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => report_error("uninstall", e),
            }
        }
    }
}
