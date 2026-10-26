//! `/etc/saiife/config.toml` (spec §8.1). Every section rejects unknown keys
//! (typos in a security config are errors) and every default is the §8.1
//! value. `forward`, `notify` and `example` stay raw tables until plans 11 and 12
//! type them.

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
    pub notify: toml::Table,
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
