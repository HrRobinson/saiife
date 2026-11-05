//! The doctor checks that read only the install record and the config, so they say the
//! same on every OS. Each check id is fixed; fleet tools match on it.

use super::report::{Check, Status};
use super::Ctx;
use crate::layout::Platform;
use saiife_agents::lock::{label_for, LockLabel, LockPlatform};
use saiife_agents::Agent;
use saiife_policy::installed::Installed;
use serde_json::{Map, Value};
use std::path::Path;

pub(super) const NOT_INSTALLED: &str = "locked mode is not installed: developer mode checks only";
pub(super) const HEALTH_TITLE: &str = "daemon health";

/// The warning for `saiife` in `[guard.mcp] allow_servers` while an agent
/// that does not pin its command (Codex, Gemini CLI) is installed: there
/// the listing allows any server registered under that name.
pub const SAIIFE_LISTED_UNPINNED: &str = "MCP server saiife is listed: on Codex and Gemini CLI any server named saiife is allowed, and nothing pins its command";

/// Whether `agent` may run any MCP server named `saiife` (nothing pins its
/// command): every agent but Claude Code, whose managed drop-in pins it.
pub fn unpinned_saiife(agent: &str) -> bool {
    agent != "claude"
}

/// The lock-label platform of the layout being checked.
fn lock_platform(ctx: &Ctx) -> LockPlatform {
    match ctx.layout.platform() {
        Platform::Linux => LockPlatform::Linux,
        Platform::Macos => LockPlatform::Macos,
        Platform::Windows => LockPlatform::Windows,
    }
}

/// One `warn` per service in STS mode (plan 15): `run --cloud` hands a
/// short-lived AWS credential to agent-controlled code, which can copy it.
/// With any, one `info` notes how far `run_allow` is checked.
pub(super) fn cloud_sts(config: &saiife_policy::SystemConfig) -> Vec<Check> {
    use saiife_policy::CloudMode;
    let mut out: Vec<Check> = config
        .services
        .iter()
        .filter(|(_, s)| s.mode == CloudMode::Sts)
        .map(|(name, _)| {
            Check::new(
                format!("cloud_sts.{name}"),
                Status::Warn,
                format!(
                    "service {name} is in STS mode: run --cloud hands a 15-minute AWS credential to agent-controlled code, which can copy it"
                ),
                "",
            )
        })
        .collect();
    if !out.is_empty() {
        out.push(Check::new(
            "cloud_sts.run_allow",
            Status::Info,
            "STS run_allow entries are checked by basename only",
            "a symlink to an interpreter is not caught at config time; run --cloud checks the resolved path at runtime",
        ));
    }
    out
}

/// The `[audit.forward.*]` targets of the system config, by name and
/// type. Their live state (`connected`, `failing`, ...) is in the audit
/// log as `forward` records, not here: doctor does not ask the targets.
pub(super) fn forwarding_detail(config: &Result<saiife_policy::LoadedPolicy, String>) -> String {
    use saiife_policy::ForwardCfg;
    let Ok(p) = config else {
        return "unknown: the system config does not load".into();
    };
    let targets = &p.config.audit.forward;
    if targets.is_empty() {
        return "not configured".into();
    }
    let names: Vec<String> = targets
        .iter()
        .map(|(name, t)| {
            let kind = match t {
                ForwardCfg::Syslog { .. } => "syslog",
                ForwardCfg::File { .. } => "file",
                ForwardCfg::Https { .. } => "https",
            };
            format!("{name} ({kind})")
        })
        .collect();
    let s = if names.len() == 1 { "" } else { "s" };
    format!(
        "{} target{s}: {}; their state is in the audit log (forward records)",
        names.len(),
        names.join(", ")
    )
}

pub(super) fn install_record(ctx: &Ctx) -> Check {
    const TITLE: &str = "install record";
    match (&ctx.installed, &ctx.installed_error) {
        (_, Some(e)) => Check::new("install.record", Status::Fail, TITLE, e.clone()),
        (Some(i), None) => Check::new(
            "install.record",
            Status::Pass,
            TITLE,
            format!("saiife {}, installed {}", i.saiife, i.installed_at),
        ),
        (None, None) => Check::new("install.record", Status::Info, TITLE, NOT_INSTALLED),
    }
}

pub(super) fn config_valid(ctx: &Ctx) -> Check {
    const TITLE: &str = "system config";
    match &ctx.config {
        Ok(p) if p.warnings.is_empty() => Check::new("config.valid", Status::Pass, TITLE, ""),
        Ok(p) => Check::new("config.valid", Status::Warn, TITLE, p.warnings.join("; ")),
        Err(e) => Check::new(
            "config.valid",
            Status::Fail,
            TITLE,
            format!("{e}. Every managed hook call is denied, and nothing is recorded"),
        ),
    }
}

/// The fingerprint of saiife's entry in a shared managed file (Codex,
/// Gemini CLI; §8.3), as `system install` recorded it.
pub(super) fn entry_fingerprint(agent: &str, file: &Path) -> Result<Option<String>, String> {
    let r = match agent {
        "codex" => saiife_agents::codex::managed_entry(file),
        "gemini" => saiife_agents::gemini::managed_entry(file),
        other => return Err(format!("unknown managed agent {other:?}")),
    };
    r.map_err(|e| e.to_string())
}

/// One warning per server `[guard.mcp] allow_servers` lets past saiife.
pub(super) fn allow_server_warnings(ctx: &Ctx) -> Vec<Check> {
    let Ok(p) = &ctx.config else {
        return Vec::new();
    };
    // A listed `saiife` changes nothing on Claude Code (pinned by
    // command there). On Codex and Gemini CLI it allows any server a
    // project or user config registers under that name.
    let unpinned = ctx
        .installed
        .as_ref()
        .is_some_and(|i| i.agents.iter().any(|a| unpinned_saiife(&a.agent)));
    p.config
        .guard
        .mcp
        .allow_servers
        .iter()
        .filter_map(|s| {
            let title = if s != "saiife" {
                format!("MCP server {s} bypasses saiife: its requests are not brokered or limited")
            } else if unpinned {
                SAIIFE_LISTED_UNPINNED.to_string()
            } else {
                return None;
            };
            Some(Check::new(format!("mcp.{s}"), Status::Warn, title, ""))
        })
        .collect()
}

/// For Codex and Gemini CLI: only the hook restricts MCP servers.
pub(super) fn mcp_restrictions(ctx: &Ctx, i: &Installed) -> Vec<Check> {
    let saiife_listed = ctx.config.as_ref().is_ok_and(|p| {
        p.config
            .guard
            .mcp
            .allow_servers
            .iter()
            .any(|s| s == "saiife")
    });
    let saiife = if saiife_listed {
        "the saiife server is not brokered here (nothing pins its command); it is in [guard.mcp] allow_servers, so its calls are allowed by name; nothing checks which program serves them"
    } else {
        "the saiife server is not brokered here (nothing pins its command); its tools are denied unless [guard.mcp] allow_servers lists \"saiife\""
    };
    i.agents
        .iter()
        .filter(|a| matches!(a.agent.as_str(), "codex" | "gemini"))
        .filter_map(|a| {
            let ag = Agent::from_name(&a.agent)?;
            Some(Check::new(
                format!("mcp.{}.restriction", a.agent),
                Status::Info,
                format!(
                    "MCP servers for {} are restricted by the hook only",
                    ag.label()
                ),
                saiife,
            ))
        })
        .collect()
}

/// The label recorded for the layout's platform (the host's, outside
/// tests), so a macOS tree checked from Linux reads as a Mac reads it.
pub(super) fn agent_label(ctx: &Ctx, name: &str) -> Check {
    let id = format!("agents.{name}.label");
    match Agent::from_name(name) {
        Some(a) => {
            let l = label_for(a, lock_platform(ctx));
            let title = format!("{} lock label", a.label());
            let status = if l == LockLabel::Lockable {
                Status::Pass
            } else {
                Status::Warn
            };
            Check::new(id, status, title, l.wording())
        }
        None => Check::new(
            id,
            Status::Warn,
            format!("{name} lock label"),
            "unknown agent",
        ),
    }
}

/// `daemon.health` from the daemon's answer to `status`, or why it gave none.
pub(super) fn health_check(status: Result<Map<String, Value>, String>) -> Check {
    let fail = |d: String| Check::new("daemon.health", Status::Fail, HEALTH_TITLE, d);
    let m = match status {
        Ok(m) => m,
        Err(e) => return fail(e),
    };
    if m.get("policy_ok").and_then(Value::as_bool) != Some(true) {
        return fail("policy not loaded: connector calls are denied".into());
    }
    let show = |k: &str| match m.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => "none".to_string(),
        Some(v) => v.to_string(),
    };
    Check::new(
        "daemon.health",
        Status::Pass,
        HEALTH_TITLE,
        format!(
            "chain {}, head seq {}, last checkpoint seq {}",
            show("chain"),
            show("head_seq"),
            show("last_checkpoint_seq")
        ),
    )
}
