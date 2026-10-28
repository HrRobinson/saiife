//! `saiife lockdown [on|off]` (spec §6.18): the kill switch. `on` denies
//! every connector request (`--scope connectors`) or also every hook call
//! (`--scope all`, the default); `off` lifts it; no subcommand shows the
//! state. For root, `[admin] groups` and `[approval] approvers`; `off`, or
//! narrowing or replacing an active lockdown, by an approver who is not an
//! admin needs polkit re-authentication (`same_user = "reauth"`), so the
//! CLI says what it changes and starts `pkttyagent` first (as `approve`
//! does). Linux only. Exit codes: 0 ok,
//! 2 refused, 5 the daemon cannot be reached.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};

#[derive(Clone, Copy, ValueEnum)]
pub enum ScopeArg {
    /// Connector requests and every hook call (the agents stop working).
    All,
    /// Connector requests only.
    Connectors,
}

#[derive(Subcommand)]
pub enum LockdownAction {
    /// Turn lockdown on.
    On {
        /// What to stop.
        #[arg(long, value_enum, default_value = "all")]
        scope: ScopeArg,
        /// Why (shown to the agents, and recorded).
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
    },
    /// Turn lockdown off.
    Off,
}

#[cfg(not(target_os = "linux"))]
pub fn run(_config: Option<PathBuf>, _action: Option<LockdownAction>) -> ExitCode {
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(target_os = "linux")]
pub fn run(config: Option<PathBuf>, action: Option<LockdownAction>) -> ExitCode {
    use crate::secret_cmd::linux::call;
    use serde_json::{json, Map, Value};

    let config = config.unwrap_or_else(|| PathBuf::from("/etc/saiife/config.toml"));
    let shown = |a: &Map<String, Value>, key: &str| match a.get(key) {
        Some(Value::Object(l)) => {
            let s = |k: &str| l.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let uid = l.get("by_uid").and_then(Value::as_u64).unwrap_or(0);
            let reason = s("reason");
            let reason = if reason.is_empty() {
                String::new()
            } else {
                format!(": {}", crate::text::sanitize(&reason))
            };
            outln!(
                "lockdown: on (scope {}) since {} by uid {uid}{reason}",
                s("scope"),
                s("since")
            );
        }
        _ => outln!("lockdown: off"),
    };
    let done = match action {
        None => call(&config, "status", Map::new()).map(|a| shown(&a, "lockdown")),
        Some(LockdownAction::On { scope, reason }) => {
            let scope = match scope {
                ScopeArg::All => "all",
                ScopeArg::Connectors => "connectors",
            };
            let mut args = Map::new();
            args.insert("on".into(), json!(true));
            args.insert("scope".into(), json!(scope));
            if let Some(r) = reason {
                args.insert("reason".into(), json!(r));
            }
            // Only turning it on when off, or widening `connectors` to
            // `all`, is free; any other change of an active lockdown may
            // ask for a password (the daemon decides; this only prepares).
            let active = if rustix::process::geteuid().is_root() {
                None
            } else {
                call(&config, "status", Map::new()).ok().and_then(|a| {
                    a.get("lockdown")
                        .and_then(|l| l.get("scope"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
            };
            let _agent = match active.as_deref() {
                Some(cur) if !(cur == "connectors" && scope == "all") => {
                    eprintln!(
                        "saiife: changing an active lockdown (polkit may ask for your password)"
                    );
                    crate::approvals_cmd::start_agent()
                }
                _ => None,
            };
            call(&config, "lockdown.set", args).map(|a| shown(&a, "lockdown"))
        }
        Some(LockdownAction::Off) => {
            let mut args = Map::new();
            args.insert("on".into(), json!(false));
            // Root never re-authenticates; anyone else may be asked for a
            // password, so say first what it is for.
            let _agent = if rustix::process::geteuid().is_root() {
                None
            } else {
                eprintln!("saiife: turning lockdown off (polkit may ask for your password)");
                crate::approvals_cmd::start_agent()
            };
            call(&config, "lockdown.set", args).map(|a| shown(&a, "lockdown"))
        }
    };
    match done {
        Ok(()) => ExitCode::SUCCESS,
        Err(stop) => {
            let (code, m) = exit_of(stop);
            eprintln!("saiife: {m}");
            ExitCode::from(code)
        }
    }
}

#[cfg(target_os = "linux")]
/// The exit code and message for a stop. `Unrecorded` (the change is made
/// but not on record) is exit 5 like an unreachable daemon, as in
/// `approvals_cmd`: the caller must check.
fn exit_of(stop: crate::secret_cmd::linux::Stop) -> (u8, String) {
    use crate::secret_cmd::linux::Stop;
    match stop {
        Stop::Refused(m) | Stop::Forbidden(m) => (2, m),
        Stop::Unavailable(m) | Stop::NotFound(m) | Stop::Unrecorded(m) => (5, m),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod exit_tests {
    use super::*;
    use crate::secret_cmd::linux::Stop;

    #[test]
    fn unrecorded_exits_5_like_unavailable() {
        assert_eq!(exit_of(Stop::Unrecorded("x".into())).0, 5);
        assert_eq!(exit_of(Stop::Unavailable("x".into())).0, 5);
        assert_eq!(exit_of(Stop::Refused("x".into())).0, 2);
    }
}
