//! The Windows service of the daemon (plan 19b, W10): its fixed spec and the
//! operations a service host performs. Pure data and text: nothing here
//! talks to the service control manager.

use crate::layout::{
    Layout, Platform, BINARY, WIN_DAEMON_ACCOUNT, WIN_SERVICE, WIN_SERVICE_DISPLAY,
    WIN_SERVICE_SDDL,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

/// When the service starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StartKind {
    /// `SERVICE_AUTO_START`.
    Auto,
    /// `SERVICE_DEMAND_START`.
    Manual,
    /// `SERVICE_DISABLED`.
    Disabled,
}

impl StartKind {
    fn name(self) -> &'static str {
        match self {
            StartKind::Auto => "auto",
            StartKind::Manual => "manual",
            StartKind::Disabled => "disabled",
        }
    }
}

/// The service SID type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SidType {
    None,
    /// `SERVICE_SID_TYPE_UNRESTRICTED`: the service SID is added to the token.
    Unrestricted,
    Restricted,
}

impl SidType {
    fn name(self) -> &'static str {
        match self {
            SidType::None => "none",
            SidType::Unrestricted => "unrestricted",
            SidType::Restricted => "restricted",
        }
    }
}

/// What the service manager does when the service fails: the analogue of
/// `Restart=always`, `RestartSec=1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailurePolicy {
    /// Restart after this delay, `restarts` times.
    pub restart_delay: Duration,
    pub restarts: u32,
    /// The failure count resets after this long without a failure.
    pub reset_after: Duration,
    /// Also restart when the service exits with a non-zero code without
    /// crashing (`SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`).
    pub on_non_crash: bool,
}

/// Everything `Create`/`Update` needs to set up the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    pub name: String,
    pub display: String,
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub account: String,
    pub start: StartKind,
    pub sid_type: SidType,
    pub failure: FailurePolicy,
    pub sddl: String,
}

impl ServiceSpec {
    /// The W10 values. Below a layout root that is not the real machine
    /// (a test tree), the binary sits below that root.
    pub fn saiifed(layout: &Layout) -> ServiceSpec {
        let windows = if layout.is_system() {
            Layout::system_for(Platform::Windows)
        } else {
            Layout::under_for(layout.root(), Platform::Windows)
        };
        let binary = windows.at(BINARY);
        ServiceSpec {
            name: WIN_SERVICE.to_string(),
            display: WIN_SERVICE_DISPLAY.to_string(),
            binary,
            args: vec!["daemon".to_string(), "--system".to_string()],
            account: WIN_DAEMON_ACCOUNT.to_string(),
            start: StartKind::Auto,
            sid_type: SidType::Unrestricted,
            failure: FailurePolicy {
                restart_delay: Duration::from_secs(1),
                restarts: 3,
                reset_after: Duration::from_secs(86_400),
                on_non_crash: true,
            },
            sddl: WIN_SERVICE_SDDL.to_string(),
        }
    }

    /// The canonical `key=value;…` text the fingerprint hashes. Strings
    /// are Debug-quoted, so no value can forge another key.
    pub fn canonical(&self) -> String {
        format!(
            "name={:?};display={:?};binary={:?};args={:?};account={:?};start={};sid_type={};\
             restart_delay_ms={};restarts={};reset_after_s={};on_non_crash={};sddl={:?}",
            self.name,
            self.display,
            self.binary.to_string_lossy(),
            self.args,
            self.account,
            self.start.name(),
            self.sid_type.name(),
            self.failure.restart_delay.as_millis(),
            self.failure.restarts,
            self.failure.reset_after.as_secs(),
            self.failure.on_non_crash,
            self.sddl,
        )
    }

    /// SHA-256 (hex) of [`ServiceSpec::canonical`].
    pub fn fingerprint(&self) -> String {
        Sha256::digest(self.canonical().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// One operation on the service, as a service host performs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceOp {
    Query,
    Create(ServiceSpec),
    Update(ServiceSpec),
    Start,
    Stop {
        wait: Duration,
    },
    Delete,
    SetSddl(String),
    /// `SERVICE_CONTROL_PARAMCHANGE`: reload the policy.
    ParamChange,
}

/// Where the service is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    Missing,
    Stopped,
    Running {
        pid: u32,
    },
    /// Start-pending, stop-pending, paused and the like, as a word.
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn spec() -> ServiceSpec {
        ServiceSpec::saiifed(&Layout::system())
    }

    #[test]
    fn saiifed_spec_values() {
        let s = spec();
        assert_eq!(s.name, "saiifed");
        assert_eq!(s.display, "saiife daemon");
        assert_eq!(
            s.binary,
            PathBuf::from(r"C:\ProgramData\saiife\bin\saiife.exe")
        );
        assert_eq!(s.args, ["daemon", "--system"]);
        assert_eq!(s.account, r"NT SERVICE\saiifed");
        assert_eq!(s.start, StartKind::Auto);
        assert_eq!(s.sid_type, SidType::Unrestricted);
        assert_eq!(s.failure.restart_delay, Duration::from_secs(1));
        assert_eq!(s.failure.restarts, 3);
        assert_eq!(s.failure.reset_after, Duration::from_secs(86_400));
        assert!(s.failure.on_non_crash);
        assert_eq!(
            s.sddl,
            "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\
             (A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLORC;;;AU)"
        );
    }

    /// One source of truth: the layout's values, in every field.
    #[test]
    fn spec_uses_the_layouts_values() {
        use crate::layout::{self, windows_path, Platform, BINARY};
        let dir = tempfile::tempdir().unwrap();
        let tree = Layout::under_for(dir.path(), Platform::Windows);
        let s = ServiceSpec::saiifed(&tree);
        assert_eq!(s.name, layout::WIN_SERVICE);
        assert_eq!(s.display, layout::WIN_SERVICE_DISPLAY);
        assert_eq!(s.account, layout::WIN_DAEMON_ACCOUNT);
        assert_eq!(s.sddl, layout::WIN_SERVICE_SDDL);
        assert_eq!(s.binary, tree.at(BINARY));
        let sys = Layout::system_for(Platform::Windows);
        assert_eq!(
            ServiceSpec::saiifed(&sys).binary,
            Path::new(windows_path(BINARY).unwrap())
        );
    }

    /// Task 8's `daemon.unit` compares this parsed: the service rights print as the
    /// directory-service letters, and `SU` is in the aliases.
    #[test]
    fn service_sddl_parses() {
        let sd = saiife_win::sddl::parse(crate::layout::WIN_SERVICE_SDDL).unwrap();
        assert_eq!(sd.aces.len(), 5);
        assert!(sd.aces.iter().all(|a| a.allow));
        assert_eq!(sd.aces[3].sid, "S-1-5-6");
        // CCLCSWRPWPDTLOCRRC, CCDCLCSWRPWPDTLOCRSDRCWDWO, CCLCSWLOCRRC, CCLCSWLORC.
        assert_eq!(sd.aces[0].mask, 0x0002_01fd);
        assert_eq!(sd.aces[1].mask, 0x000f_01ff);
        assert_eq!(sd.aces[2].mask, 0x0002_018d);
        assert_eq!(sd.aces[4].mask, 0x0002_008d);
    }

    #[test]
    fn test_tree_binary_sits_below_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let s = ServiceSpec::saiifed(&Layout::under(dir.path()));
        assert!(s.binary.starts_with(Layout::under(dir.path()).root()));
        assert!(s.binary.ends_with("saiife.exe"));
    }

    #[test]
    fn fingerprint_is_stable_hex() {
        let (a, b) = (spec().fingerprint(), spec().fingerprint());
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_changes_with_any_field() {
        let base = spec().fingerprint();
        type Edit = fn(&mut ServiceSpec);
        let edits: Vec<(&str, Edit)> = vec![
            ("name", |s| s.name.push('x')),
            ("display", |s| s.display.push('x')),
            ("binary", |s| s.binary.push("x")),
            ("args", |s| s.args.push("x".into())),
            ("args split", |s| s.args = vec!["daemon --system".into()]),
            ("account", |s| s.account.push('x')),
            ("start", |s| s.start = StartKind::Manual),
            ("sid_type", |s| s.sid_type = SidType::Restricted),
            ("restart_delay", |s| {
                s.failure.restart_delay = Duration::from_millis(1001)
            }),
            ("restarts", |s| s.failure.restarts = 4),
            ("reset_after", |s| {
                s.failure.reset_after = Duration::from_secs(86_401)
            }),
            ("on_non_crash", |s| s.failure.on_non_crash = false),
            ("sddl", |s| s.sddl.push('x')),
        ];
        for (what, edit) in edits {
            let mut s = spec();
            edit(&mut s);
            assert_ne!(s.fingerprint(), base, "{what}");
        }
    }
}
