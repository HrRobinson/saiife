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

/// Claude Code needs `onFailure: "block"` (spec §5.6).
pub const CLAUDE_MIN: (u32, u32, u32) = (2, 1, 295);

/// The first `N.N.N` in `out`.
pub fn parse_agent_version(out: &str) -> Option<(u32, u32, u32)> {
    out.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find_map(|word| {
            let mut n = word.split('.').map(|p| p.parse::<u32>().ok());
            Some((n.next()??, n.next()??, n.next()??))
        })
}

pub(super) fn fmt_version((a, b, c): (u32, u32, u32)) -> String {
    format!("{a}.{b}.{c}")
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

/// What `daemon.health`, `cosign.listen` and `hooks.no-verdict` read: the one answer to
/// `status`, or why there was none.
pub(super) type DaemonStatus = Result<Map<String, Value>, String>;

/// Whether `installed.toml` lists Claude Code.
pub(super) fn claude_installed(ctx: &Ctx) -> bool {
    ctx.installed
        .as_ref()
        .is_some_and(|i| i.agents.iter().any(|a| a.agent == "claude"))
}

/// `cosign.listen` (plan 20): with Claude Code installed, the daemon's co-signer must be
/// listening on [`COSIGN_ADDR`], or Claude Code blocks every call (`onFailure`).
///
/// [`COSIGN_ADDR`]: crate::layout::COSIGN_ADDR
pub(super) fn cosign_listen(claude: bool, status: &DaemonStatus) -> Check {
    use crate::layout::COSIGN_ADDR;
    const ID: &str = "cosign.listen";
    const TITLE: &str = "Claude Code co-signer";
    if !claude {
        return Check::new(
            ID,
            Status::Info,
            TITLE,
            "Claude Code is not installed: no co-signer needed",
        );
    }
    let Ok(m) = status else {
        return Check::new(ID, Status::Info, TITLE, NO_ANSWER);
    };
    let fail = |why: String| {
        Check::new(
            ID,
            Status::Fail,
            TITLE,
            format!(
                "the co-signer is not listening on {COSIGN_ADDR} ({why}), so Claude Code \
                 blocks every call"
            ),
        )
    };
    let Some(c) = m.get("cosign") else {
        return fail("the daemon does not report a co-signer: an older daemon?".into());
    };
    match c.get("addr") {
        Some(Value::String(a)) if a == COSIGN_ADDR => {
            Check::new(ID, Status::Pass, TITLE, format!("listening on {a}"))
        }
        Some(Value::String(a)) => fail(format!("it listens on {a} instead")),
        _ => fail(match c.get("error") {
            Some(Value::String(e)) if !e.is_empty() => e.clone(),
            _ => "no error given".into(),
        }),
    }
}

/// What `cosign.listen` and `hooks.no-verdict` say without a `status` answer:
/// `daemon.health` fails then, so they do not fail again.
const NO_ANSWER: &str = "not checked: the daemon did not answer (see daemon.health)";

/// `hooks.no-verdict` (plan 20): hooks that ended without a verdict since the daemon
/// started. Record only: a warning, never a failure, and no lockdown (owner ruling
/// 2026-11-06).
pub(super) fn hooks_no_verdict(status: &DaemonStatus) -> Check {
    const ID: &str = "hooks.no-verdict";
    const TITLE: &str = "hooks without a verdict";
    let Ok(m) = status else {
        return Check::new(ID, Status::Info, TITLE, NO_ANSWER);
    };
    let h = m.get("hooks_no_verdict");
    let Some(n) = h.and_then(|h| h.get("since_start")).and_then(Value::as_u64) else {
        return Check::new(
            ID,
            Status::Warn,
            TITLE,
            "the daemon does not count hooks without a verdict: an older daemon?",
        );
    };
    if n == 0 {
        return Check::new(
            ID,
            Status::Pass,
            TITLE,
            "every hook call since the daemon started ended with a verdict",
        );
    }
    let last = h
        .and_then(|h| h.get("last_ts"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    Check::new(
        ID,
        Status::Warn,
        TITLE,
        format!(
            "{n} hook call(s) ended without a verdict since the daemon started (last {last}): \
             a hook was killed, crashed or timed out; see saiife audit --kind hook"
        ),
    )
}

/// The proxy variables Claude Code honours, upper and lower case.
const PROXY_VARS: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];
/// Where hosts are exempt from the proxy.
const NO_PROXY_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// The proxy variables [`proxy_check`] reads from one source, which `source` names.
pub(super) struct EnvLayer {
    pub source: String,
    pub vars: std::collections::BTreeMap<String, String>,
}

impl EnvLayer {
    /// The proxy variables `get` answers (a process environment, a registry key).
    pub fn from_lookup(source: String, get: impl Fn(&str) -> Option<String>) -> EnvLayer {
        let vars = PROXY_VARS
            .iter()
            .chain(&NO_PROXY_VARS)
            .filter_map(|k| Some((k.to_string(), get(k)?)))
            .collect();
        EnvLayer { source, vars }
    }

    /// The proxy variables of a Claude Code settings file's `env` object.
    pub fn from_settings(source: String, settings: &[u8]) -> EnvLayer {
        let v: Value = serde_json::from_slice(settings).unwrap_or(Value::Null);
        EnvLayer::from_lookup(source, |k| v["env"][k].as_str().map(str::to_string))
    }
}

/// One `NO_PROXY` entry covers `127.0.0.1` (the co-signer): `*`, the address itself (with
/// or without the co-signer's port), or an IPv4 CIDR that holds it. `localhost` does not:
/// the hook URL names the address.
fn no_proxy_entry_covers(entry: &str) -> bool {
    let e = entry.trim();
    if e == "*" || e == "127.0.0.1" || e == crate::layout::COSIGN_ADDR {
        return true;
    }
    let Some((net, bits)) = e.split_once('/') else {
        return false;
    };
    match (net.parse::<std::net::Ipv4Addr>(), bits.parse::<u32>()) {
        (Ok(net), Ok(bits)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(net) & mask == u32::from(std::net::Ipv4Addr::LOCALHOST) & mask
        }
        _ => false,
    }
}

/// A `NO_PROXY` value covers `127.0.0.1`: one of its entries (comma or space separated) does.
pub(super) fn no_proxy_covers_loopback(value: &str) -> bool {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .any(no_proxy_entry_covers)
}

/// `user.<name>.proxy` (owner ruling 2026-11-09): with a proxy set for the agent and
/// `127.0.0.1` not in `NO_PROXY`, Claude Code may send the co-sign request to the proxy and
/// block every call. `layers` go from weakest to strongest: a later source sets a variable
/// over an earlier one (a settings `env` overwrites the shell's). A warning, never a
/// failure. The proxy's value is never shown: it may hold a password.
pub(super) fn proxy_check(id: String, layers: &[EnvLayer]) -> Check {
    const TITLE: &str = "proxy for the Claude Code co-signer";
    let get = |k: &str| {
        layers
            .iter()
            .rev()
            .find_map(|l| l.vars.get(k).map(|v| (v.as_str(), l.source.as_str())))
            .filter(|(v, _)| !v.trim().is_empty())
    };
    let Some((var, source)) = PROXY_VARS.iter().find_map(|k| get(k).map(|(_, s)| (*k, s))) else {
        return Check::new(id, Status::Pass, TITLE, "no HTTP(S) proxy is set");
    };
    // Each exemption variable that is set must cover the address: tools differ in which
    // spelling they read.
    let exempt: Vec<&str> = NO_PROXY_VARS
        .iter()
        .filter_map(|k| get(k).map(|(v, _)| v))
        .collect();
    if !exempt.is_empty() && exempt.iter().all(|v| no_proxy_covers_loopback(v)) {
        return Check::new(
            id,
            Status::Pass,
            TITLE,
            format!("{var} is set and NO_PROXY covers 127.0.0.1"),
        );
    }
    Check::new(
        id,
        Status::Warn,
        TITLE,
        format!(
            "{var} is set (in {source}) and NO_PROXY does not cover 127.0.0.1: Claude Code may \
             send the co-sign request to the proxy and block every call; add 127.0.0.1 to \
             NO_PROXY"
        ),
    )
}

#[cfg(test)]
mod plan20_tests {
    use super::*;

    fn layer(source: &str, vars: &[(&str, &str)]) -> EnvLayer {
        EnvLayer {
            source: source.into(),
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn no_proxy_entries_that_cover_loopback() {
        for v in [
            "*",
            "127.0.0.1",
            "localhost,127.0.0.1",
            "example.com 127.0.0.1:7433",
            "127.0.0.0/8",
            "0.0.0.0/0",
            " 127.0.0.1/32 ",
        ] {
            assert!(no_proxy_covers_loopback(v), "{v}");
        }
        for v in [
            "",
            "localhost",
            "::1",
            ".local,10.0.0.0/8",
            "127.0.0.2/32",
            "127.0.0.1:80",
            "127.0.0.0/40",
            "127.0.0.10",
        ] {
            assert!(!no_proxy_covers_loopback(v), "{v}");
        }
    }

    #[test]
    fn proxy_without_no_proxy_warns_and_names_no_value() {
        let secret = concat!("http://user:", "pw", "@proxy.test:3128");
        let c = proxy_check(
            "user.a.proxy".into(),
            &[layer("the environment", &[("https_proxy", secret)])],
        );
        assert_eq!(c.status, Status::Warn, "{c:?}");
        assert!(c
            .detail
            .starts_with("https_proxy is set (in the environment)"));
        assert!(!c.detail.contains("proxy.test"), "{c:?}");
    }

    #[test]
    fn proxy_checks_follow_the_layers() {
        let id = || "user.a.proxy".to_string();
        assert_eq!(proxy_check(id(), &[]).status, Status::Pass);
        let shell = layer("the environment", &[("HTTP_PROXY", "http://p:1")]);
        let covered = layer("s", &[("NO_PROXY", "127.0.0.1")]);
        assert_eq!(proxy_check(id(), &[shell, covered]).status, Status::Pass);
        // A settings `env` that empties the proxy wins over the shell.
        let shell = layer("the environment", &[("HTTP_PROXY", "http://p:1")]);
        let cleared = layer("s", &[("HTTP_PROXY", "")]);
        assert_eq!(proxy_check(id(), &[shell, cleared]).status, Status::Pass);
        // A settings `env` that narrows NO_PROXY wins too.
        let shell = layer(
            "the environment",
            &[("HTTP_PROXY", "http://p:1"), ("NO_PROXY", "127.0.0.1")],
        );
        let narrowed = layer("s", &[("NO_PROXY", "localhost")]);
        assert_eq!(proxy_check(id(), &[shell, narrowed]).status, Status::Warn);
        // Both spellings set: each must cover the address.
        let both = layer(
            "s",
            &[
                ("HTTPS_PROXY", "http://p:1"),
                ("NO_PROXY", "127.0.0.1"),
                ("no_proxy", "localhost"),
            ],
        );
        assert_eq!(proxy_check(id(), &[both]).status, Status::Warn);
    }

    #[test]
    fn settings_env_is_read() {
        let l = EnvLayer::from_settings(
            "s".into(),
            br#"{"env":{"HTTPS_PROXY":"http://p:1","OTHER":"x","NO_PROXY":7}}"#,
        );
        assert_eq!(l.vars.len(), 1);
        assert_eq!(l.vars["HTTPS_PROXY"], "http://p:1");
        assert!(EnvLayer::from_settings("s".into(), b"not json")
            .vars
            .is_empty());
    }
}
