//! `saiife system install|uninstall`: locked mode on Linux (spec §7). The
//! hidden `--root <dir>` runs the same steps against a tree below `<dir>`
//! with a fake host (tests); without it, the real machine (root only).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use saiife_agents::Agent;
#[cfg(unix)]
use saiife_policy::Getent;
use saiife_system::doctor::{self, DoctorOptions};
use saiife_system::fleet::fleet_options;
use saiife_system::install::{
    install_locked, lock_install, package_exit, write_package_log, InstallError, InstallOptions,
    NOTHING_CHANGED,
};
use saiife_system::layout::Platform;
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
        /// For a package's install action, with --fleet: installed with doctor findings
        /// exits 0, not 1, so the package does not roll back; a failed install still exits 2.
        /// On Windows the doctor's text also goes to the install log.
        #[arg(long, requires = "fleet")]
        package: bool,
        /// Install below this directory with a fake host (tests only).
        #[arg(long, hide = true, value_name = "DIR")]
        root: Option<PathBuf>,
        /// Install a dynamically linked or debug-assertions build (the CI
        /// jobs locked-linux, locked-macos and macos-pkg only). Never for
        /// production: such a binary lets an agent inject code into, or hang,
        /// the managed hook. A release build does not have this flag.
        #[cfg(debug_assertions)]
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
        InstallError::NotElevated => fail(format!("saiife: {}", InstallError::NotElevated)),
        InstallError::Unsupported(why) => fail(refusal_line(&why)),
        InstallError::Refused { path, detail } => fail(format!(
            "saiife: {cmd} failed at check: {}: {detail}",
            path.display()
        )),
        InstallError::Step { step, detail } => {
            fail(format!("saiife: {cmd} failed at {step}: {detail}"))
        }
        InstallError::SipRequired => fail(format!("saiife: {}", saiife_system::sip::SIP_REQUIRED)),
    }
}

/// An install that failed before its first change: the error, then the line
/// that says so, last (the pkg's `postinstall` matches on it).
fn report_untouched(e: InstallError) -> ExitCode {
    let code = report_error("install", e);
    eprintln!("{NOTHING_CHANGED}");
    code
}

/// `doctor` after a successful install (spec §7): its text on stdout.
/// Returns that text, and true when it found a failure (the caller exits 1;
/// the install itself stays done; install errors are exit 2).
fn after_install_doctor(layout: &Layout, host: &dyn Host) -> (String, bool) {
    #[cfg(unix)]
    let (dir, home) = (
        Getent,
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute()),
    );
    // The profile comes from the registry by SID: the environment is the caller's.
    #[cfg(windows)]
    let (dir, home) = (saiife_policy::WinDirectory::system(), None);
    let opts = DoctorOptions { user: None, home };
    let (text, failed) = doctor::after_install(layout, host, &dir, &opts);
    outln!();
    out!("{text}");
    if failed {
        eprintln!(
            "saiife: installed, but doctor found failures: fix them before relying on the lock"
        );
    }
    (text, failed)
}

/// The command an admin runs to restart the daemon on `platform`.
fn restart_command(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => "systemctl restart saiifed",
        Platform::Macos => "launchctl kickstart -k system/com.saiife.saiifed",
        Platform::Windows => "Restart-Service saiifed",
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
            package,
            root,
            #[cfg(debug_assertions)]
            allow_test_build,
        } => {
            #[cfg(not(debug_assertions))]
            let allow_test_build = false;
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
            // Before the fleet files are read: an overlapping run may be
            // about to change what they say.
            let lock = match lock_install(&layout, host.as_ref()) {
                Ok(l) => l,
                Err(e) => return report_untouched(e),
            };
            let opts = if fleet {
                match fleet_options(&layout, host.as_ref()) {
                    Ok(o) => InstallOptions {
                        allow_test_build,
                        ..o
                    },
                    Err(e) => return report_untouched(e),
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
            let began = std::cell::Cell::new(false);
            match install_locked(&lock, &layout, host.as_ref(), &opts, &binary, &began) {
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
                    if let Some(h) = &r.policy_hash {
                        println!("saiife: the daemon reloaded the new config (policy {h})");
                    }
                    let (doctor_text, doctor_failed) = after_install_doctor(&layout, host.as_ref());
                    if package {
                        // The install is done: a log that cannot be written is no reason
                        // to roll it back.
                        if let Err(e) = write_package_log(&layout, &doctor_text) {
                            eprintln!("saiife: warning: the install log: {e}");
                        }
                    }
                    // Last, so it is the line an admin sees: the old policy
                    // may still be in force.
                    if let Some(p) = &r.reload_problem {
                        eprintln!("saiife: error: {p}");
                        eprintln!(
                            "saiife: installed, but the running daemon may still enforce the old \
                             policy: fix the config, then run `saiife policy reload` or \
                             `{}`",
                            restart_command(layout.platform())
                        );
                    }
                    if let Some(p) = &r.policy_failure {
                        eprintln!("saiife: error: {p}");
                    }
                    ExitCode::from(package_exit(r.exit_code(doctor_failed), package))
                }
                Err(e) if began.get() => report_error("install", e),
                Err(e) => report_untouched(e),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_command_follows_the_platform() {
        assert_eq!(
            restart_command(Platform::Linux),
            "systemctl restart saiifed"
        );
        assert_eq!(
            restart_command(Platform::Macos),
            format!("launchctl kickstart -k {}", saiife_system::launchd::SERVICE)
        );
    }
}
