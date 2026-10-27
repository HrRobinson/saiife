//! `saiife lockdown [on|off]` (spec §6.18): the kill switch. `on` denies
//! every connector request (`--scope connectors`) or also every hook call
//! (`--scope all`, the default); `off` lifts it; no subcommand shows the
//! state. For root, `[admin] groups` and `[approval] approvers`. Linux
//! only. Exit codes: 0 ok, 2 refused, 5 the daemon cannot be reached.

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
    use crate::secret_cmd::linux::{call, Stop};
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
            call(&config, "lockdown.set", args).map(|a| shown(&a, "lockdown"))
        }
        Some(LockdownAction::Off) => {
            let mut args = Map::new();
            args.insert("on".into(), json!(false));
            call(&config, "lockdown.set", args).map(|a| shown(&a, "lockdown"))
        }
    };
    match done {
        Ok(()) => ExitCode::SUCCESS,
        Err(Stop::Refused(m) | Stop::Forbidden(m) | Stop::Unrecorded(m)) => {
            eprintln!("saiife: {m}");
            ExitCode::from(2)
        }
        Err(Stop::Unavailable(m) | Stop::NotFound(m)) => {
            eprintln!("saiife: {m}");
            ExitCode::from(5)
        }
    }
}
