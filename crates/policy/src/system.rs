//! `/etc/saiife/config.toml` (spec §8.1). Every section rejects unknown keys
//! (typos in a security config are errors) and every default is the §8.1
//! value. `forward` and `example` stay raw tables until plan 12 types them.

use crate::service::{SecretCfg, ServiceCfg};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// The whole system config after drop-ins are merged.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemConfig {
    /// Must be 2.
    pub version: u32,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub daemon: DaemonCfg,
    #[serde(default)]
    pub admin: AdminCfg,
    #[serde(default)]
    pub guard: GuardCfg,
    #[serde(default)]
    pub audit: AuditCfg,
    #[serde(default)]
    pub approval: ApprovalCfg,
    #[serde(default)]
    pub notify: NotifyCfg,
    #[serde(default)]
    pub gateway: GatewayCfg,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceCfg>,
    /// `[secrets.<name>]`: per-secret admin settings (`run_allow`).
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretCfg>,
    #[serde(default)]
    pub scope: Vec<Scope>,
    #[serde(default)]
    pub example: Vec<toml::Table>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonCfg {
    pub user: String,
    pub socket_dir: PathBuf,
}

impl Default for DaemonCfg {
    fn default() -> Self {
        DaemonCfg {
            user: "saiife".to_string(),
            socket_dir: PathBuf::from("/run/saiife"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminCfg {
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardCfg {
    pub packs: Vec<String>,
    pub ask: Vec<String>,
    pub budget_ms: u64,
    pub fail: Fail,
    pub mcp: McpCfg,
}

impl Default for GuardCfg {
    fn default() -> Self {
        GuardCfg {
            packs: Vec::new(),
            ask: Vec::new(),
            budget_ms: 50,
            fail: Fail::Closed,
            mcp: McpCfg::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpCfg {
    pub allow_servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditCfg {
    pub dir: PathBuf,
    pub retention_months: u32,
    pub checkpoint_every: u64,
    #[serde(with = "crate::duration::as_secs")]
    pub checkpoint_interval: Duration,
    pub min_free_mb: u64,
    pub fsync: Fsync,
    pub forward: BTreeMap<String, toml::Table>,
}

impl Default for AuditCfg {
    fn default() -> Self {
        AuditCfg {
            dir: PathBuf::from("/var/log/saiife/audit"),
            retention_months: 24,
            checkpoint_every: 1000,
            checkpoint_interval: Duration::from_secs(15 * 60),
            min_free_mb: 512,
            fsync: Fsync::Checkpoint,
            forward: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalCfg {
    pub approvers: Vec<String>,
    pub same_user: SameUser,
    #[serde(with = "crate::duration::as_secs")]
    pub timeout: Duration,
    #[serde(with = "crate::duration::as_secs")]
    pub grant_ttl: Duration,
}

impl Default for ApprovalCfg {
    fn default() -> Self {
        ApprovalCfg {
            approvers: Vec::new(),
            same_user: SameUser::Deny,
            timeout: Duration::from_secs(30 * 60),
            grant_ttl: Duration::from_secs(15 * 60),
        }
    }
}

impl ApprovalCfg {
    /// Each `approvers` entry is a user name or `group:<name>`; a name is not
    /// empty, does not start with `-` and holds no `:`, whitespace or control
    /// characters. `Err` names the first bad entry.
    pub fn check_approvers(&self) -> Result<(), String> {
        for e in &self.approvers {
            let name = e.strip_prefix("group:").unwrap_or(e);
            if !valid_name(name) {
                return Err(format!(
                    "[approval] approvers entry {e:?} is not a user name or group:<name>"
                ));
            }
        }
        Ok(())
    }
}

/// A user or group name (as `users::valid_name`).
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && !name
            .chars()
            .any(|c| c == ':' || c.is_whitespace() || c.is_control())
}

/// The load warning when `[guard] ask` routes calls to approval but
/// `[approval] approvers` is empty.
pub const NO_APPROVERS_WARNING: &str = "[approval] approvers is empty: nobody can approve requests";

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayCfg {
    pub tcp: String,
    pub max_response_bytes: u64,
    #[serde(with = "crate::duration::as_secs")]
    pub upstream_timeout: Duration,
}

impl Default for GatewayCfg {
    fn default() -> Self {
        GatewayCfg {
            tcp: String::new(),
            max_response_bytes: 5_242_880,
            upstream_timeout: Duration::from_secs(30),
        }
    }
}

impl GatewayCfg {
    /// `tcp` as a socket address: `Ok(None)` when empty (no listener). An
    /// address that is not an IP literal with a port, or whose IP is not
    /// loopback (`127.0.0.0/8`, `::1`), is an error. Port 0 (an ephemeral
    /// port, which the daemon reports in `status`) is accepted.
    pub fn tcp_addr(&self) -> Result<Option<SocketAddr>, String> {
        let t = self.tcp.trim();
        if t.is_empty() {
            return Ok(None);
        }
        let a: SocketAddr = t.parse().map_err(|_| {
            format!(
                "[gateway] tcp = {t:?} is not an IP address with a port (like \"127.0.0.1:7431\")"
            )
        })?;
        if !a.ip().is_loopback() {
            return Err(format!(
                "[gateway] tcp = {t:?} is not a loopback address (127.0.0.0/8 or ::1)"
            ));
        }
        Ok(Some(a))
    }
}

/// One `[[scope]]`. A uid matches at most one scope (builder's call 6).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub name: String,
    /// OS user names or `group:<name>`.
    #[serde(default)]
    pub users: Vec<String>,
    /// Attribution only; never selects a scope or an environment.
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub env: Option<String>,
}

/// What a notification is about (spec §6.10.3). Unknown names are errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    ApprovalCreated,
    LimitReached,
    ErrorDeniedBurst,
    ChainBreak,
    ForwardFailing,
    Lockdown,
}

impl Event {
    pub const ALL: [Event; 6] = [
        Event::ApprovalCreated,
        Event::LimitReached,
        Event::ErrorDeniedBurst,
        Event::ChainBreak,
        Event::ForwardFailing,
        Event::Lockdown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Event::ApprovalCreated => "approval_created",
            Event::LimitReached => "limit_reached",
            Event::ErrorDeniedBurst => "error_denied_burst",
            Event::ChainBreak => "chain_break",
            Event::ForwardFailing => "forward_failing",
            Event::Lockdown => "lockdown",
        }
    }
}

/// `[notify]`: which events are sent, and where.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyCfg {
    /// Every event when absent.
    pub on: Vec<Event>,
    pub targets: BTreeMap<String, TargetCfg>,
}

impl Default for NotifyCfg {
    fn default() -> Self {
        NotifyCfg {
            on: Event::ALL.to_vec(),
            targets: BTreeMap::new(),
        }
    }
}

/// One `[notify.targets.<name>]`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TargetCfg {
    Webhook(WebhookCfg),
    Smtp(SmtpCfg),
    Command(CommandCfg),
}

/// Exactly one of `url` and `url_secret` (a vault secret holding the URL).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookCfg {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub url_secret: Option<String>,
}

/// `secret` names a vault secret of kind `basic` (`AUTH PLAIN`).
/// `starttls = false` means implicit TLS (port 465). When absent it follows
/// the port: implicit TLS on 465, STARTTLS on anything else (587, 25).
/// `starttls = false` on 587 or 25 is refused at load.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpCfg {
    pub host: String,
    pub port: u16,
    pub from: String,
    pub to: Vec<String>,
    pub secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starttls: Option<bool>,
}

impl SmtpCfg {
    /// STARTTLS (true) or implicit TLS (false), after the port default.
    pub fn starttls(&self) -> bool {
        self.starttls.unwrap_or(self.port != 465)
    }
}

/// A mail address the notifier will put in an SMTP command: 1 to 254
/// printable ASCII characters, none of `,;"<>` and no space.
pub fn valid_address(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= 254
        && a.bytes()
            .all(|b| b.is_ascii_graphic() && !b",;\"<>".contains(&b))
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandCfg {
    pub path: PathBuf,
}

impl NotifyCfg {
    /// The checks a parse cannot make; `Err` names the target.
    pub fn validate(&self) -> Result<(), String> {
        for (name, t) in &self.targets {
            let bad = |why: &str| Err(format!("[notify.targets.{name}]: {why}"));
            match t {
                TargetCfg::Webhook(w) => match (&w.url, &w.url_secret) {
                    (Some(_), Some(_)) | (None, None) => {
                        return bad("set exactly one of url and url_secret")
                    }
                    (Some(u), None) if !u.starts_with("https://") => {
                        return bad("url must start with https://")
                    }
                    _ => {}
                },
                TargetCfg::Smtp(s) => {
                    if s.host.is_empty() || s.from.is_empty() || s.secret.is_empty() {
                        return bad("host, from and secret must not be empty");
                    }
                    if s.to.is_empty() {
                        return bad("to needs at least one address");
                    }
                    if !valid_address(&s.from) || !s.to.iter().all(|a| valid_address(a)) {
                        return bad(
                            "addresses must be printable ASCII without space or any of , ; \" < >",
                        );
                    }
                    if s.starttls == Some(false) && matches!(s.port, 587 | 25) {
                        return bad("starttls = false is refused on port 587 and 25");
                    }
                }
                TargetCfg::Command(c) => {
                    if !c.path.is_absolute() {
                        return bad("command path must be absolute");
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fail {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fsync {
    Always,
    Checkpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SameUser {
    Deny,
    Reauth,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_are_lowercase() {
        let c: SystemConfig = toml::from_str(
            "version = 2\n[guard]\nfail = \"open\"\n[audit]\nfsync = \"always\"\n[approval]\nsame_user = \"reauth\"\n",
        )
        .unwrap();
        assert_eq!(c.guard.fail, Fail::Open);
        assert_eq!(c.audit.fsync, Fsync::Always);
        assert_eq!(c.approval.same_user, SameUser::Reauth);
        assert!(toml::from_str::<SystemConfig>("version = 2\n[guard]\nfail = \"Open\"\n").is_err());
    }

    #[test]
    fn config_unknown_event_is_error() {
        let t = |body: &str| toml::from_str::<SystemConfig>(&format!("version = 2\n{body}"));
        assert!(t("[notify]\non = [\"approval_created\"]\n").is_ok());
        assert!(t("[notify]\non = [\"nope\"]\n").is_err());
        assert!(t("[notify]\nonn = []\n").is_err());
        assert!(t("[notify.targets.a]\ntype = \"pager\"\n").is_err());
        assert!(t("[notify.targets.a]\ntype = \"command\"\npath = \"/x\"\nextra = 1\n").is_err());
        let c = t("[notify.targets.a]\ntype = \"webhook\"\nurl = \"https://h.test/x\"\n").unwrap();
        assert!(c.notify.validate().is_ok());
        assert_eq!(c.notify.on.len(), 6);
    }

    #[test]
    fn notify_targets_are_validated() {
        let v = |body: &str| {
            toml::from_str::<SystemConfig>(&format!("version = 2\n[notify.targets.a]\n{body}"))
                .unwrap()
                .notify
                .validate()
        };
        assert!(v("type = \"webhook\"\n").is_err());
        assert!(v("type = \"webhook\"\nurl = \"https://h.test\"\nurl_secret = \"s\"\n").is_err());
        assert!(v("type = \"webhook\"\nurl = \"http://h.test\"\n").is_err());
        assert!(v("type = \"webhook\"\nurl_secret = \"s\"\n").is_ok());
        assert!(v("type = \"command\"\npath = \"rel/x\"\n").is_err());
        assert!(v("type = \"command\"\npath = \"/usr/bin/logger\"\n").is_ok());
        let smtp =
            "type = \"smtp\"\nhost = \"m.test\"\nport = 465\nfrom = \"a@b\"\nsecret = \"s\"\n";
        assert!(v(&format!("{smtp}to = [\"c@d\"]\n")).is_ok());
        assert!(v(&format!("{smtp}to = []\n")).is_err());
        for bad in [
            "a b@c.test",
            "a,b@c.test",
            "a;b@c.test",
            "\\\"a\\\"@c.test",
            "<a@c.test>",
            "\\u00e9@c.test",
            "a\\n@c.test",
            "a\\u0001@c.test",
        ] {
            assert!(v(&format!("{smtp}to = [\"{bad}\"]\n")).is_err(), "{bad}");
        }
        // starttls follows the port; false is refused on 587 and 25.
        let on = |port: u16, extra: &str| {
            format!("type = \"smtp\"\nhost = \"m.test\"\nport = {port}\nfrom = \"a@b\"\nto = [\"c@d\"]\nsecret = \"s\"\n{extra}")
        };
        assert!(v(&on(587, "starttls = false\n")).is_err());
        assert!(v(&on(25, "starttls = false\n")).is_err());
        assert!(v(&on(587, "")).is_ok() && v(&on(465, "starttls = false\n")).is_ok());
        let st = |port, extra: &str| {
            let c = toml::from_str::<SystemConfig>(&format!(
                "version = 2\n[notify.targets.a]\n{}",
                on(port, extra)
            ))
            .unwrap();
            match &c.notify.targets["a"] {
                TargetCfg::Smtp(s) => s.starttls(),
                _ => unreachable!(),
            }
        };
        assert!(st(587, "") && st(25, "") && !st(465, ""));
    }

    #[test]
    fn approvers_entries_are_names_or_groups() {
        let a = |v: &[&str]| ApprovalCfg {
            approvers: v.iter().map(|s| s.to_string()).collect(),
            ..ApprovalCfg::default()
        };
        a(&[]).check_approvers().unwrap();
        a(&["alice", "group:ops", "svc-bot", "j.doe"])
            .check_approvers()
            .unwrap();
        for bad in [
            "",
            "group:",
            "-x",
            "group:-x",
            "a b",
            "a:b",
            "group:a:b",
            "x\n",
        ] {
            let e = a(&["alice", bad]).check_approvers().unwrap_err();
            assert!(e.contains("approvers"), "{bad:?}: {e}");
        }
    }

    #[test]
    fn tcp_off_by_default() {
        let c: SystemConfig = toml::from_str("version = 2\n").unwrap();
        assert_eq!(c.gateway.tcp, "");
        assert_eq!(c.gateway.tcp_addr(), Ok(None));
    }

    #[test]
    fn non_loopback_tcp_is_config_error() {
        let g = |t: &str| GatewayCfg {
            tcp: t.into(),
            ..GatewayCfg::default()
        };
        for ok in [
            "127.0.0.1:7431",
            "127.0.0.1:0",
            "127.9.8.7:80",
            "[::1]:7431",
        ] {
            assert!(g(ok).tcp_addr().unwrap().is_some(), "{ok}");
        }
        for bad in [
            "0.0.0.0:7431",
            "[::]:7431",
            "192.168.1.5:7431",
            "10.0.0.1:1",
            "[::ffff:127.0.0.1]:7431",
            "localhost:7431",
            "127.0.0.1",
            "7431",
        ] {
            assert!(g(bad).tcp_addr().is_err(), "{bad}");
        }
        assert!(g("0.0.0.0:1").tcp_addr().unwrap_err().contains("loopback"));
    }

    #[test]
    fn scope_rejects_unknown_key() {
        let e = toml::from_str::<SystemConfig>(
            "version = 2\n[[scope]]\nname = \"a\"\nuser = [\"x\"]\n",
        )
        .unwrap_err();
        assert!(e.to_string().contains("user"), "{e}");
    }
}
