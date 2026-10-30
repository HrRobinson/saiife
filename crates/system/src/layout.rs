//! Every locked-mode path (spec §5.2), under a root prefix. `Layout::system()`
//! is the real machine; `Layout::under(tmp)` (the hidden `--root` flag) puts
//! the same tree below `tmp`, so tests never touch `/etc`, `/opt`, `/var` or
//! `/run`.

use saiife_agents::Agent;
use std::io;
use std::path::{Component, Path, PathBuf};

pub const OPT_DIR: &str = "/opt/saiife";
pub const BIN_DIR: &str = "/opt/saiife/bin";
pub const BINARY: &str = "/opt/saiife/bin/saiife";
pub const ETC_DIR: &str = "/etc/saiife";
pub const CONFIG: &str = "/etc/saiife/config.toml";
pub const POLICY_D: &str = "/etc/saiife/policy.d";
pub const CREDSTORE: &str = "/etc/saiife/credstore";
pub const VAULT_KEY: &str = "/etc/saiife/credstore/vault-key";
pub const INSTALLED: &str = "/etc/saiife/installed.toml";
/// The polkit action file for approval re-authentication (spec §6.10.2).
pub const POLKIT_DIR: &str = "/usr/share/polkit-1/actions";
pub const POLKIT_ACTION: &str = "/usr/share/polkit-1/actions/com.saiife.approve.policy";
/// Present (and root-owned) when polkit re-authentication can work.
pub const PKCHECK: &str = "/usr/bin/pkcheck";
pub const POLKIT_ACTION_ID: &str = "com.saiife.approve";
/// The warning when re-authentication is unavailable (install and doctor).
pub const REAUTH_UNAVAILABLE: &str =
    "re-authentication unavailable: approvals need a second account";
/// macOS refuses every same-user approval (install and doctor).
pub const MAC_SAME_USER_OFF: &str =
    "same-user approval is off on macOS: approvals need a second account";
pub const UNIT: &str = "/etc/systemd/system/saiifed.service";
/// The warning when an install lists no agents (install and doctor).
pub const NO_AGENTS: &str = "no agents listed: no agent is guarded";
/// Root-owned install options for packages and MDM tools (`system install
/// --fleet`, plan 18 decision 2).
pub const FLEET_DIR: &str = "/etc/saiife/fleet";
/// The fleet's system config: copied to [`CONFIG`] on every `--fleet` run.
pub const FLEET_CONFIG: &str = "/etc/saiife/fleet/config.toml";
/// The fleet's `agents` and `approvers`.
pub const FLEET_INSTALL: &str = "/etc/saiife/fleet/install.toml";
/// The staging copy a Linux package ships; `install` copies it to [`BINARY`].
#[cfg(target_os = "linux")]
pub const PACKAGE_BINARY: &str = "/usr/libexec/saiife/saiife";

/// The polkit action file, byte for byte. `auth_self`, never
/// `auth_self_keep`: every approval asks for the password again. The
/// daemon user ([`DAEMON_USER`]) is the action's owner: polkit lets only
/// root or an action owner check another user's process (and pass
/// details); `$(request)` is the `--detail request` the daemon sends.
pub const POLKIT_POLICY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>saiife</vendor>
  <action id="com.saiife.approve">
    <description>Approve a saiife request</description>
    <message>Authentication is required to approve saiife request $(request)</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:saiife</annotate>
  </action>
</policyconfig>
"#;
pub const STATE_DIR: &str = "/var/lib/saiife";
pub const KEYS_DIR: &str = "/var/lib/saiife/keys";
pub const AUDIT_KEY: &str = "/var/lib/saiife/keys/audit.ed25519";
pub const LOG_DIR: &str = "/var/log/saiife";
pub const AUDIT_DIR: &str = "/var/log/saiife/audit";
pub const RUN_DIR: &str = "/run/saiife";
pub const SOCKET: &str = "/run/saiife/saiife.sock";
pub const CLAUDE_MANAGED_DIR: &str = "/etc/claude-code/managed-settings.d";
pub const CLAUDE_MANAGED: &str = "/etc/claude-code/managed-settings.d/50-saiife.json";
/// The managed MCP allowlist drop-in, derived from `[guard.mcp]` policy.
pub const CLAUDE_MCP: &str = "/etc/claude-code/managed-settings.d/60-saiife-mcp.json";
pub const CODEX_DIR: &str = "/etc/codex";
pub const CODEX_REQUIREMENTS: &str = "/etc/codex/requirements.toml";
pub const GEMINI_DIR: &str = "/etc/gemini-cli";
pub const GEMINI_SETTINGS: &str = "/etc/gemini-cli/settings.json";

pub const DAEMON_USER: &str = "saiife";
pub const DAEMON_GROUP: &str = "saiife";
pub const AUDIT_GROUP: &str = "saiife-audit";
pub const UNIT_NAME: &str = "saiifed.service";

// ------------------------------------------------ macOS (spec §5.3)

/// The daemon's stderr on macOS, which has no journal for it.
pub const DAEMON_LOG: &str = "/var/log/saiife/daemon.log";
/// An MDM profile that may also deliver Claude Code managed settings.
pub const CLAUDE_MDM_PROFILE: &str = "/Library/Managed Preferences/com.anthropic.claudecode.plist";
pub const MACOS_DAEMON_USER: &str = "_saiife";
pub const MACOS_DAEMON_GROUP: &str = "_saiife";
pub const MACOS_AUDIT_GROUP: &str = "_saiifeaudit";
pub const LAUNCHD_LABEL: &str = "com.saiife.saiifed";

/// The platform a layout is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Macos,
}

impl Platform {
    /// The platform this binary runs on; `None` on any other OS.
    pub fn current() -> Option<Platform> {
        if cfg!(target_os = "linux") {
            Some(Platform::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Platform::Macos)
        } else {
            None
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Macos => "macos",
        }
    }
}

/// The macOS path (spec §5.3) for a Linux path constant, when it differs.
/// Every other constant is the same on both platforms.
pub fn macos_path(linux: &str) -> Option<&'static str> {
    Some(match linux {
        STATE_DIR => "/var/db/saiife",
        KEYS_DIR => "/var/db/saiife/keys",
        AUDIT_KEY => "/var/db/saiife/keys/audit.ed25519",
        VAULT_KEY => "/var/db/saiife/keys/vault.key",
        RUN_DIR => "/var/db/saiife-run",
        SOCKET => "/var/db/saiife-run/saiife.sock",
        UNIT => "/Library/LaunchDaemons/com.saiife.saiifed.plist",
        CLAUDE_MANAGED_DIR => "/Library/Application Support/ClaudeCode/managed-settings.d",
        CLAUDE_MANAGED => {
            "/Library/Application Support/ClaudeCode/managed-settings.d/50-saiife.json"
        }
        CLAUDE_MCP => {
            "/Library/Application Support/ClaudeCode/managed-settings.d/60-saiife-mcp.json"
        }
        GEMINI_DIR => "/Library/Application Support/GeminiCli",
        GEMINI_SETTINGS => "/Library/Application Support/GeminiCli/settings.json",
        _ => return None,
    })
}

/// Where the locked-mode tree lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// Canonical (symlinks and `..` resolved) when `resolved`.
    root: PathBuf,
    resolved: bool,
    platform: Platform,
}

/// The platform `Layout::system()` and `Layout::under` use.
fn host_platform() -> Platform {
    Platform::current().unwrap_or(Platform::Linux)
}

impl Layout {
    /// The real machine (root `/`).
    pub fn system() -> Layout {
        Layout {
            root: PathBuf::from("/"),
            resolved: true,
            platform: host_platform(),
        }
    }

    /// The same tree below `root`. The root is resolved first, so an alias
    /// of `/` (`/tmp/..`, a symlink to `/`) is the system layout, not a
    /// test tree that happens to write to the real machine. A root that
    /// does not exist yet resolves through its nearest existing ancestor.
    /// When it cannot be resolved (`..` below a missing directory),
    /// [`Layout::is_resolved`] is false and `host_for` refuses it.
    pub fn under(root: impl Into<PathBuf>) -> Layout {
        Layout::under_for(root, host_platform())
    }

    /// [`Layout::under`] with `platform`'s paths, so Linux tests can drive
    /// the macOS tree.
    pub fn under_for(root: impl Into<PathBuf>, platform: Platform) -> Layout {
        let raw = root.into();
        match resolve_root(&raw) {
            Some(root) => Layout {
                root,
                resolved: true,
                platform,
            },
            None => Layout {
                root: raw,
                resolved: false,
                platform,
            },
        }
    }

    pub fn platform(&self) -> Platform {
        self.platform
    }

    /// The path constant `abs` (spelled as on Linux) as this platform
    /// names it, without the root.
    pub fn logical<'a>(&self, abs: &'a str) -> &'a str {
        match self.platform {
            Platform::Linux => abs,
            Platform::Macos => macos_path(abs).unwrap_or(abs),
        }
    }

    pub fn daemon_user(&self) -> &'static str {
        match self.platform {
            Platform::Linux => DAEMON_USER,
            Platform::Macos => MACOS_DAEMON_USER,
        }
    }

    pub fn daemon_group(&self) -> &'static str {
        match self.platform {
            Platform::Linux => DAEMON_GROUP,
            Platform::Macos => MACOS_DAEMON_GROUP,
        }
    }

    pub fn audit_group(&self) -> &'static str {
        match self.platform {
            Platform::Linux => AUDIT_GROUP,
            Platform::Macos => MACOS_AUDIT_GROUP,
        }
    }

    /// The systemd unit, or the launchd label on macOS.
    pub fn unit_name(&self) -> &'static str {
        match self.platform {
            Platform::Linux => UNIT_NAME,
            Platform::Macos => LAUNCHD_LABEL,
        }
    }

    /// False when the root given to [`Layout::under`] could not be resolved.
    pub fn is_resolved(&self) -> bool {
        self.resolved
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// True for the real machine: the (resolved) root is `/`.
    pub fn is_system(&self) -> bool {
        self.resolved && self.root == Path::new("/")
    }

    /// `abs` (one of the path constants) below the root, as this platform
    /// names it ([`macos_path`]). Panics on a path that could leave the
    /// root; use [`Layout::try_at`] for any path that is not a constant of
    /// this module (it is joined as given, never mapped).
    pub fn at(&self, abs: &str) -> PathBuf {
        self.try_at(Path::new(self.logical(abs)))
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// `abs` below the root. `abs` must be absolute with plain components
    /// only (no `..`, no `.`), so the result never leaves the root.
    /// Never pass a layout constant: it is joined as given, never mapped,
    /// so map it with [`Layout::logical`] first (or use [`Layout::at`]).
    pub fn try_at(&self, abs: &Path) -> io::Result<PathBuf> {
        let mut parts = abs.components();
        let rooted = parts.next() == Some(Component::RootDir);
        let rest = parts.as_path();
        if !rooted || !rest.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} leaves the root: only absolute paths with plain components are allowed",
                    abs.display()
                ),
            ));
        }
        Ok(self.root.join(rest))
    }

    /// The managed config file for `a` (spec §5.2, §8.3).
    pub fn managed_file(&self, a: Agent) -> PathBuf {
        self.at(match a {
            Agent::Claude => CLAUDE_MANAGED,
            Agent::Codex => CODEX_REQUIREMENTS,
            Agent::Gemini => GEMINI_SETTINGS,
        })
    }
}

/// `raw` with symlinks and `..` resolved. The part below the nearest
/// existing ancestor must be plain names.
fn resolve_root(raw: &Path) -> Option<PathBuf> {
    if let Ok(c) = std::fs::canonicalize(raw) {
        return Some(c);
    }
    for anc in raw.ancestors().skip(1) {
        let probe = if anc.as_os_str().is_empty() {
            Path::new(".")
        } else {
            anc
        };
        let Ok(base) = std::fs::canonicalize(probe) else {
            continue;
        };
        let rest = raw.strip_prefix(anc).ok()?;
        if !rest.components().all(|c| matches!(c, Component::Normal(_))) {
            return None;
        }
        return Some(base.join(rest));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_agents::Agent;
    use std::path::Path;

    #[test]
    #[cfg(target_os = "linux")]
    fn under_joins_every_path() {
        let l = Layout::under("/x");
        assert_eq!(l.root(), Path::new("/x"));
        assert!(!l.is_system());
        assert_eq!(
            l.at(AUDIT_KEY),
            Path::new("/x/var/lib/saiife/keys/audit.ed25519")
        );
        assert_eq!(l.at(SOCKET), Path::new("/x/run/saiife/saiife.sock"));
        assert_eq!(
            l.managed_file(Agent::Codex),
            Path::new("/x/etc/codex/requirements.toml")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn system_layout_is_the_real_paths() {
        let l = Layout::system();
        assert!(l.is_system());
        assert_eq!(l.root(), Path::new("/"));
        assert_eq!(l.at(BINARY), Path::new("/opt/saiife/bin/saiife"));
        assert_eq!(
            l.managed_file(Agent::Claude),
            Path::new("/etc/claude-code/managed-settings.d/50-saiife.json")
        );
        assert_eq!(
            l.managed_file(Agent::Gemini),
            Path::new("/etc/gemini-cli/settings.json")
        );
        assert!(Layout::under("/").is_system());
    }

    #[test]
    fn aliases_of_slash_are_the_system_layout() {
        // `<tmp>/../../..` up to `/`, through the real directory names.
        let dir = tempfile::tempdir().unwrap();
        let canon = std::fs::canonicalize(dir.path()).unwrap();
        let mut alias = canon.clone();
        for _ in 0..canon.components().count() - 1 {
            alias.push("..");
        }
        let l = Layout::under(&alias);
        assert!(l.is_system(), "{alias:?} -> {:?}", l.root());
        assert_eq!(l.root(), Path::new("/"));
        // A symlink to `/`.
        let link = dir.path().join("slash");
        std::os::unix::fs::symlink("/", &link).unwrap();
        assert!(Layout::under(&link).is_system());
        // Through a real directory below `/`: `usr` is one on Linux and
        // macOS (`etc` is not: on macOS it is a symlink to `private/etc`,
        // so `/etc/..` is `/private`).
        assert!(!std::fs::symlink_metadata("/usr").unwrap().is_symlink());
        assert!(Layout::under(link.join("usr/..")).is_system());
    }

    #[test]
    fn tempdir_root_is_not_system_and_is_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let l = Layout::under(dir.path());
        assert!(!l.is_system());
        assert!(l.is_resolved());
        assert_eq!(l.root(), std::fs::canonicalize(dir.path()).unwrap());
        // A root that does not exist yet resolves through its parent.
        let l = Layout::under(dir.path().join("new/tree"));
        assert!(l.is_resolved() && !l.is_system());
        assert!(l.root().ends_with("new/tree"));
        // `..` below a missing directory cannot be resolved.
        let l = Layout::under(dir.path().join("missing/../../.."));
        assert!(!l.is_resolved());
        assert!(!l.is_system());
    }

    #[test]
    fn try_at_refuses_paths_that_leave_the_root() {
        let l = Layout::under("/x");
        assert_eq!(
            l.try_at(Path::new("/etc/saiife")).unwrap(),
            Path::new("/x/etc/saiife")
        );
        for bad in ["/etc/../../y", "etc/saiife", "../y", "./etc", ""] {
            assert!(l.try_at(Path::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    #[should_panic(expected = "leaves the root")]
    fn at_panics_on_a_path_that_leaves_the_root() {
        Layout::under("/x").at("/etc/../../y");
    }

    #[test]
    fn system_paths_are_spec_values() {
        assert_eq!(OPT_DIR, "/opt/saiife");
        assert_eq!(BIN_DIR, "/opt/saiife/bin");
        assert_eq!(BINARY, "/opt/saiife/bin/saiife");
        assert_eq!(ETC_DIR, "/etc/saiife");
        assert_eq!(CONFIG, "/etc/saiife/config.toml");
        assert_eq!(POLICY_D, "/etc/saiife/policy.d");
        assert_eq!(CREDSTORE, "/etc/saiife/credstore");
        assert_eq!(VAULT_KEY, "/etc/saiife/credstore/vault-key");
        assert_eq!(INSTALLED, "/etc/saiife/installed.toml");
        assert_eq!(UNIT, "/etc/systemd/system/saiifed.service");
        assert_eq!(STATE_DIR, "/var/lib/saiife");
        assert_eq!(KEYS_DIR, "/var/lib/saiife/keys");
        assert_eq!(AUDIT_KEY, "/var/lib/saiife/keys/audit.ed25519");
        assert_eq!(LOG_DIR, "/var/log/saiife");
        assert_eq!(AUDIT_DIR, "/var/log/saiife/audit");
        assert_eq!(RUN_DIR, "/run/saiife");
        assert_eq!(SOCKET, "/run/saiife/saiife.sock");
        assert_eq!(CLAUDE_MANAGED_DIR, "/etc/claude-code/managed-settings.d");
        assert_eq!(
            CLAUDE_MANAGED,
            "/etc/claude-code/managed-settings.d/50-saiife.json"
        );
        assert_eq!(CODEX_DIR, "/etc/codex");
        assert_eq!(CODEX_REQUIREMENTS, "/etc/codex/requirements.toml");
        assert_eq!(GEMINI_DIR, "/etc/gemini-cli");
        assert_eq!(GEMINI_SETTINGS, "/etc/gemini-cli/settings.json");
        assert_eq!(DAEMON_USER, "saiife");
        assert_eq!(DAEMON_GROUP, "saiife");
        assert_eq!(AUDIT_GROUP, "saiife-audit");
        assert_eq!(UNIT_NAME, "saiifed.service");
        assert_eq!(FLEET_DIR, "/etc/saiife/fleet");
        assert_eq!(FLEET_CONFIG, "/etc/saiife/fleet/config.toml");
        assert_eq!(FLEET_INSTALL, "/etc/saiife/fleet/install.toml");
        #[cfg(target_os = "linux")]
        assert_eq!(PACKAGE_BINARY, "/usr/libexec/saiife/saiife");
    }

    /// The Linux constants that differ on macOS, with their §5.3 value.
    const MACOS_TABLE: [(&str, &str); 12] = [
        (STATE_DIR, "/var/db/saiife"),
        (KEYS_DIR, "/var/db/saiife/keys"),
        (AUDIT_KEY, "/var/db/saiife/keys/audit.ed25519"),
        (VAULT_KEY, "/var/db/saiife/keys/vault.key"),
        (RUN_DIR, "/var/db/saiife-run"),
        (SOCKET, "/var/db/saiife-run/saiife.sock"),
        (UNIT, "/Library/LaunchDaemons/com.saiife.saiifed.plist"),
        (
            CLAUDE_MANAGED_DIR,
            "/Library/Application Support/ClaudeCode/managed-settings.d",
        ),
        (
            CLAUDE_MANAGED,
            "/Library/Application Support/ClaudeCode/managed-settings.d/50-saiife.json",
        ),
        (
            CLAUDE_MCP,
            "/Library/Application Support/ClaudeCode/managed-settings.d/60-saiife-mcp.json",
        ),
        (GEMINI_DIR, "/Library/Application Support/GeminiCli"),
        (
            GEMINI_SETTINGS,
            "/Library/Application Support/GeminiCli/settings.json",
        ),
    ];

    /// Every path constant of this module.
    const ALL_PATHS: [&str; 27] = [
        OPT_DIR,
        BIN_DIR,
        BINARY,
        ETC_DIR,
        CONFIG,
        POLICY_D,
        CREDSTORE,
        VAULT_KEY,
        INSTALLED,
        POLKIT_DIR,
        POLKIT_ACTION,
        PKCHECK,
        UNIT,
        STATE_DIR,
        KEYS_DIR,
        AUDIT_KEY,
        LOG_DIR,
        AUDIT_DIR,
        RUN_DIR,
        SOCKET,
        CLAUDE_MANAGED_DIR,
        CLAUDE_MANAGED,
        CLAUDE_MCP,
        CODEX_DIR,
        CODEX_REQUIREMENTS,
        GEMINI_DIR,
        GEMINI_SETTINGS,
    ];

    fn differs(p: &str) -> bool {
        MACOS_TABLE.iter().any(|(l, _)| *l == p)
    }

    #[test]
    fn macos_paths_are_spec_values() {
        for (linux, mac) in MACOS_TABLE {
            assert_eq!(macos_path(linux), Some(mac), "{linux}");
        }
        for p in ALL_PATHS.into_iter().filter(|p| !differs(p)) {
            assert_eq!(macos_path(p), None, "{p} is the same on macOS");
        }
        assert_eq!(macos_path("/etc/saiife/other"), None);
        assert_eq!(DAEMON_LOG, "/var/log/saiife/daemon.log");
        assert_eq!(
            CLAUDE_MDM_PROFILE,
            "/Library/Managed Preferences/com.anthropic.claudecode.plist"
        );
        assert_eq!(MACOS_DAEMON_USER, "_saiife");
        assert_eq!(MACOS_DAEMON_GROUP, "_saiife");
        assert_eq!(MACOS_AUDIT_GROUP, "_saiifeaudit");
        assert_eq!(LAUNCHD_LABEL, "com.saiife.saiifed");
    }

    #[test]
    fn under_for_macos_maps_every_differing_constant() {
        let l = Layout::under_for("/x", Platform::Macos);
        assert_eq!(l.platform(), Platform::Macos);
        assert!(!l.is_system());
        for (linux, mac) in MACOS_TABLE {
            assert_eq!(l.at(linux), Path::new("/x").join(&mac[1..]), "{linux}");
        }
        for p in ALL_PATHS.into_iter().filter(|p| !differs(p)) {
            assert_eq!(l.at(p), Path::new("/x").join(&p[1..]), "{p}");
        }
        assert_eq!(
            l.managed_file(Agent::Claude),
            Path::new(
                "/x/Library/Application Support/ClaudeCode/managed-settings.d/50-saiife.json"
            )
        );
        assert_eq!(
            l.managed_file(Agent::Gemini),
            Path::new("/x/Library/Application Support/GeminiCli/settings.json")
        );
        assert_eq!(
            l.managed_file(Agent::Codex),
            Path::new("/x/etc/codex/requirements.toml")
        );
        // `try_at` joins as given: it is for paths that are not constants.
        assert_eq!(
            l.try_at(Path::new(STATE_DIR)).unwrap(),
            Path::new("/x/var/lib/saiife")
        );
        let sys = Layout::under_for("/", Platform::Macos);
        assert!(sys.is_system());
        assert_eq!(sys.at(SOCKET), Path::new("/var/db/saiife-run/saiife.sock"));
    }

    #[test]
    fn linux_layout_unchanged() {
        let l = Layout::under_for("/x", Platform::Linux);
        assert_eq!(l.platform(), Platform::Linux);
        for p in ALL_PATHS {
            assert_eq!(l.at(p), Path::new("/x").join(&p[1..]), "{p}");
            assert_eq!(l.logical(p), p);
        }
        let sys = Layout::under_for("/", Platform::Linux);
        assert!(sys.is_system());
        assert_eq!(sys.at(AUDIT_KEY), Path::new(AUDIT_KEY));
        #[cfg(target_os = "linux")]
        {
            assert_eq!(Layout::system().platform(), Platform::Linux);
            assert_eq!(Layout::under("/x"), l);
        }
    }

    #[test]
    fn names_per_platform() {
        assert_eq!(Platform::Linux.name(), "linux");
        assert_eq!(Platform::Macos.name(), "macos");
        #[cfg(target_os = "linux")]
        assert_eq!(Platform::current(), Some(Platform::Linux));
        #[cfg(target_os = "macos")]
        assert_eq!(Platform::current(), Some(Platform::Macos));
        let l = Layout::under_for("/x", Platform::Linux);
        assert_eq!(
            (
                l.daemon_user(),
                l.daemon_group(),
                l.audit_group(),
                l.unit_name()
            ),
            ("saiife", "saiife", "saiife-audit", "saiifed.service")
        );
        let m = Layout::under_for("/x", Platform::Macos);
        assert_eq!(
            (
                m.daemon_user(),
                m.daemon_group(),
                m.audit_group(),
                m.unit_name()
            ),
            ("_saiife", "_saiife", "_saiifeaudit", "com.saiife.saiifed")
        );
    }
}
