//! `/etc/saiife/config.toml` (spec §8.1). Every section rejects unknown keys
//! (typos in a security config are errors) and every default is the §8.1
//! value. `example` stays a raw table list until plan 12 types them.

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
    pub forward: BTreeMap<String, ForwardCfg>,
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

/// `[audit.forward.<name>]` (spec §6.5): where a copy of the audit log goes.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ForwardCfg {
    Syslog {
        /// `unix:/dev/log` or `tls://host:port`.
        address: String,
        #[serde(default)]
        format: SyslogFormat,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        facility: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca: Option<PathBuf>,
    },
    File {
        path: PathBuf,
    },
    Https {
        url: String,
        /// Vault secret holding the `Authorization` header value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_secret: Option<String>,
        #[serde(default)]
        format: HttpsFormat,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum SyslogFormat {
    #[default]
    #[serde(rename = "rfc5424")]
    Rfc5424,
    #[serde(rename = "rfc5424-json")]
    Rfc5424Json,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum HttpsFormat {
    #[default]
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "splunk-hec")]
    SplunkHec,
}

fn has_ws(s: &str) -> bool {
    s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// `host:port` (split on the last `:`), port 1..=65535. An IPv6 host must be
/// bracketed. With `port_required` false the port may be absent (URLs).
fn valid_host_port(hp: &str, port_required: bool) -> bool {
    if hp.is_empty() || has_ws(hp) || hp.contains(['/', '@', '?', '#']) {
        return false;
    }
    let (host, port) = if hp.starts_with('[') {
        match hp.find(']') {
            Some(i) if i + 1 == hp.len() => (hp, None),
            Some(i) => match hp[i + 1..].strip_prefix(':') {
                Some(p) => (&hp[..=i], Some(p)),
                None => return false,
            },
            None => return false,
        }
    } else {
        match hp.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hp, None),
        }
    };
    let host_ok = if let Some(inner) = host.strip_prefix('[') {
        inner.strip_suffix(']').is_some_and(|i| {
            !i.is_empty()
                && i.chars()
                    .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        })
    } else {
        !host.is_empty() && !host.contains([':', '[', ']'])
    };
    let port_ok = match port {
        Some(p) => p.parse::<u16>().is_ok_and(|n| n >= 1) && p.bytes().all(|b| b.is_ascii_digit()),
        None => !port_required,
    };
    host_ok && port_ok
}

fn valid_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    if has_ws(url) {
        return false;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    valid_host_port(&rest[..end], false)
}

/// The syslog facility number for a validated name (RFC 5424): `user` 1,
/// `daemon` 3, `local0`..`local7` 16..23. `None` for anything else; the
/// forwarder uses `facility_code(f).unwrap_or(16)` (default `local0`).
pub fn facility_code(name: Option<&str>) -> Option<u8> {
    match name {
        None => Some(16),
        Some("user") => Some(1),
        Some("daemon") => Some(3),
        Some(f) => {
            let n: u8 = f.strip_prefix("local")?.parse().ok()?;
            let canonical = f.len() == "local0".len();
            (n <= 7 && canonical).then_some(16 + n)
        }
    }
}

impl AuditCfg {
    /// The checks a parse cannot make; `Err` names the target.
    pub fn validate(&self) -> Result<(), String> {
        for (name, t) in &self.forward {
            let bad = |why: &str| Err(format!("[audit.forward.{name}]: {why}"));
            if name.is_empty()
                || name.len() > 32
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
            {
                return bad("target name must match [a-z0-9_-]{1,32}");
            }
            let abs = |p: &PathBuf| p.is_absolute();
            match t {
                ForwardCfg::Syslog {
                    address,
                    facility,
                    ca,
                    ..
                } => {
                    let unix = address.starts_with("unix:");
                    let ok = match address.strip_prefix("unix:") {
                        Some(p) => p.starts_with('/') && p.len() > 1 && !has_ws(p),
                        None => address
                            .strip_prefix("tls://")
                            .is_some_and(|hp| valid_host_port(hp, true)),
                    };
                    if !ok {
                        return bad("address must be unix:/absolute/path or tls://host:port");
                    }
                    if unix && ca.is_some() {
                        return bad("ca applies to tls:// addresses only");
                    }
                    if let Some(f) = facility {
                        if facility_code(Some(f)).is_none() {
                            return bad("facility must be local0..local7, user or daemon");
                        }
                    }
                    if ca.as_ref().is_some_and(|p| !abs(p)) {
                        return bad("ca must be an absolute path");
                    }
                }
                ForwardCfg::File { path } => {
                    if !abs(path) {
                        return bad("path must be absolute");
                    }
                }
                ForwardCfg::Https {
                    url,
                    auth_secret,
                    ca,
                    ..
                } => {
                    if !valid_https_url(url) {
                        return bad("url must be https://host[:port]/... with a host");
                    }
                    if auth_secret.as_deref() == Some("") {
                        return bad("auth_secret must not be empty");
                    }
                    if ca.as_ref().is_some_and(|p| !abs(p)) {
                        return bad("ca must be an absolute path");
                    }
                }
            }
        }
        Ok(())
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

    fn fwd(body: &str) -> Result<SystemConfig, toml::de::Error> {
        toml::from_str(&format!("version = 2\n{body}"))
    }

    fn fwd_valid(body: &str) -> Result<(), String> {
        fwd(body).unwrap().audit.validate()
    }

    #[test]
    fn forward_types_parse() {
        let c = fwd(concat!(
            "[audit.forward.siem]\ntype = \"syslog\"\naddress = \"tls://log.test:6514\"\n",
            "format = \"rfc5424-json\"\nfacility = \"local3\"\nca = \"/etc/saiife/ca/x.pem\"\n",
            "[audit.forward.local]\ntype = \"syslog\"\naddress = \"unix:/dev/log\"\n",
            "[audit.forward.copy]\ntype = \"file\"\npath = \"/mnt/x\"\n",
            "[audit.forward.hec]\ntype = \"https\"\nurl = \"https://h.test/e\"\n",
            "auth_secret = \"splunk\"\nformat = \"splunk-hec\"\n",
        ))
        .unwrap();
        assert!(c.audit.validate().is_ok());
        assert_eq!(c.audit.forward.len(), 4);
        assert!(matches!(
            &c.audit.forward["siem"],
            ForwardCfg::Syslog { format: SyslogFormat::Rfc5424Json, facility: Some(f), .. } if f == "local3"
        ));
        assert!(matches!(
            &c.audit.forward["local"],
            ForwardCfg::Syslog {
                format: SyslogFormat::Rfc5424,
                facility: None,
                ca: None,
                ..
            }
        ));
        assert!(matches!(
            &c.audit.forward["hec"],
            ForwardCfg::Https {
                format: HttpsFormat::SplunkHec,
                auth_secret: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn unknown_key_is_error() {
        assert!(fwd("[audit.forward.a]\ntype = \"file\"\npath = \"/x\"\nextra = 1\n").is_err());
        assert!(fwd("[audit.forward.a]\ntype = \"file\"\n").is_err());
        assert!(fwd("[audit.forward.a]\ntype = \"kafka\"\n").is_err());
        assert!(fwd("[audit.forward.a]\npath = \"/x\"\n").is_err());
        assert!(fwd(
            "[audit.forward.a]\ntype = \"https\"\nurl = \"https://h\"\nformat = \"xml\"\n"
        )
        .is_err());
        // keys of another type are unknown here
        assert!(
            fwd("[audit.forward.a]\ntype = \"file\"\npath = \"/x\"\nurl = \"https://h\"\n")
                .is_err()
        );
    }

    #[test]
    fn http_url_refused() {
        assert!(
            fwd_valid("[audit.forward.a]\ntype = \"https\"\nurl = \"http://h.test/\"\n").is_err()
        );
        assert!(fwd_valid("[audit.forward.a]\ntype = \"https\"\nurl = \"https://\"\n").is_err());
        assert!(
            fwd_valid("[audit.forward.a]\ntype = \"https\"\nurl = \"https://h.test/\"\n").is_ok()
        );
        assert!(
            fwd_valid("[audit.forward.a]\ntype = \"syslog\"\naddress = \"tcp://h:514\"\n").is_err()
        );
        assert!(
            fwd_valid("[audit.forward.a]\ntype = \"syslog\"\naddress = \"tls://h\"\n").is_err()
        );
        assert!(
            fwd_valid("[audit.forward.a]\ntype = \"syslog\"\naddress = \"unix:dev/log\"\n")
                .is_err()
        );
    }

    #[test]
    fn url_negatives() {
        for u in [
            "https:///x",
            "https://:443",
            "https://ho st/",
            "https://user@/",
            "https://h.test:0/",
            "https://h.test:99999/",
            "https://h.test:/",
            "https://::1/",
        ] {
            let b = format!("[audit.forward.a]\ntype = \"https\"\nurl = \"{u}\"\n");
            assert!(fwd_valid(&b).is_err(), "{u}");
        }
        for u in [
            "https://h.test",
            "https://h.test:8443/x?y#z",
            "https://[::1]:8443/",
        ] {
            let b = format!("[audit.forward.a]\ntype = \"https\"\nurl = \"{u}\"\n");
            assert!(fwd_valid(&b).is_ok(), "{u}");
        }
    }

    #[test]
    fn bad_syslog_address_refused() {
        for a in [
            "tls://h",
            "tls://h:0",
            "tls://h:65536",
            "tls://:6514",
            "tls://h/x:6514",
            "tls://h h:6514",
            "tls://::1:6514",
            "tls://[::1]",
            "unix:/",
            "unix:dev/log",
            "unix:",
            "udp://h:514",
        ] {
            let b = format!("[audit.forward.a]\ntype = \"syslog\"\naddress = \"{a}\"\n");
            assert!(fwd_valid(&b).is_err(), "{a}");
        }
        for a in [
            "tls://[::1]:6514",
            "tls://h.test:6514",
            "tls://h:65535",
            "unix:/dev/log",
        ] {
            let b = format!("[audit.forward.a]\ntype = \"syslog\"\naddress = \"{a}\"\n");
            assert!(fwd_valid(&b).is_ok(), "{a}");
        }
        let b =
            "[audit.forward.a]\ntype = \"syslog\"\naddress = \"unix:/dev/log\"\nca = \"/x.pem\"\n";
        assert!(fwd_valid(b).is_err());
    }

    #[test]
    fn facility_codes() {
        assert_eq!(facility_code(None), Some(16));
        assert_eq!(facility_code(Some("user")), Some(1));
        assert_eq!(facility_code(Some("daemon")), Some(3));
        assert_eq!(facility_code(Some("local0")), Some(16));
        assert_eq!(facility_code(Some("local7")), Some(23));
        assert_eq!(facility_code(Some("local8")), None);
        assert_eq!(facility_code(Some("local07")), None);
        assert_eq!(facility_code(Some("kern")), None);
    }

    #[test]
    fn relative_path_refused() {
        assert!(fwd_valid("[audit.forward.a]\ntype = \"file\"\npath = \"out\"\n").is_err());
        assert!(fwd_valid(
            "[audit.forward.a]\ntype = \"https\"\nurl = \"https://h\"\nca = \"ca.pem\"\n"
        )
        .is_err());
        assert!(fwd_valid(
            "[audit.forward.a]\ntype = \"syslog\"\naddress = \"unix:/dev/log\"\nca = \"ca.pem\"\n"
        )
        .is_err());
    }

    #[test]
    fn bad_facility_refused() {
        for f in ["local8", "kern", "LOCAL0", "local", ""] {
            let b = format!(
                "[audit.forward.a]\ntype = \"syslog\"\naddress = \"unix:/dev/log\"\nfacility = \"{f}\"\n"
            );
            assert!(fwd_valid(&b).is_err(), "{f}");
        }
        for f in ["local0", "local7", "user", "daemon"] {
            let b = format!(
                "[audit.forward.a]\ntype = \"syslog\"\naddress = \"unix:/dev/log\"\nfacility = \"{f}\"\n"
            );
            assert!(fwd_valid(&b).is_ok(), "{f}");
        }
    }

    #[test]
    fn bad_target_name_refused() {
        for n in ["Siem", "a.b", "has space", &"a".repeat(33)] {
            let b = format!("[audit.forward.\"{n}\"]\ntype = \"file\"\npath = \"/x\"\n");
            assert!(fwd_valid(&b).is_err(), "{n}");
        }
        for n in ["a", "siem_1-b", &"a".repeat(32)] {
            let b = format!("[audit.forward.\"{n}\"]\ntype = \"file\"\npath = \"/x\"\n");
            assert!(fwd_valid(&b).is_ok(), "{n}");
        }
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
