//! Every locked-mode path (spec §5.2), under a root prefix. `Layout::system()`
//! is the real machine; `Layout::under(tmp)` (the hidden `--root` flag) puts
//! the same tree below `tmp`, so tests never touch `/etc`, `/opt`, `/var` or
//! `/run`.
//!
//! The constants are spelled as on Linux. [`macos_path`] and [`windows_path`]
//! map them. On Windows `X:\a\b` sits at `<root>/X/a/b`, so Linux tests drive
//! the Windows tree too.

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
/// Windows refuses every same-user approval (W16): install, doctor and the refusal. An
/// agent running as the user can capture a password prompted for on its own desktop.
pub const WIN_SAME_USER_OFF: &str =
    "same-user approval is off on Windows: approvals need a second account, from a separate session";
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
/// Held while `system install` runs. Beside `/etc/saiife`, not in it: a
/// refused install leaves `/etc/saiife` alone.
pub const INSTALL_LOCK: &str = "/etc/saiife-install.lock";
/// The staging copy a package ships; `install` copies it to [`BINARY`].
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
/// The Claude Code co-signer's loopback address (plan 20; fixed, not configurable). The
/// managed drop-in's HTTP hook names it in `saiife_agents::claude::COSIGN_URL`.
pub const COSIGN_ADDR: &str = "127.0.0.1:7433";
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

// ------------------------------------------------ Windows (spec §5.3a)

/// The root CA dir (`<config dir>/ca`), named here for [`windows_path`].
pub const CA_DIR: &str = "/etc/saiife/ca";
/// Held while `system install` runs (the Windows [`INSTALL_LOCK`]): inside the root, whose
/// descriptor is checked before this is opened, because Users may create entries in
/// `C:\ProgramData`. Gone when its handle closes.
pub const WIN_INSTALL_LOCK: &str = r"C:\ProgramData\saiife\install.lock";
/// A plain uninstall's copy of `installed.toml` (the Windows `PREVIOUS`).
pub const WIN_PREVIOUS: &str = r"C:\ProgramData\saiife\etc\installed.previous.toml";
/// Where `--package` appends the doctor's text (W20).
pub const WIN_INSTALL_LOG: &str = r"C:\ProgramData\saiife\log\install.log";
/// The control endpoint (W11).
pub const WIN_PIPE: &str = r"\\.\pipe\saiife";
/// The personal broker's pipe is this and the user's SID (W25).
pub const WIN_PERSONAL_PIPE_PREFIX: &str = r"\\.\pipe\saiife-user-";
pub const WIN_SERVICE: &str = "saiifed";
pub const WIN_SERVICE_DISPLAY: &str = "saiife daemon";
pub const WIN_DAEMON_ACCOUNT: &str = r"NT SERVICE\saiifed";
pub const WIN_AUDIT_GROUP: &str = "saiife-audit";
/// The hook's binary: forward slashes and no spaces, so it survives Git Bash,
/// PowerShell and cmd without quotes (W9).
pub const WIN_HOOK_BINARY: &str = "C:/ProgramData/saiife/bin/saiife.exe";
/// Claude Code's machine policy, which wins over its files (W24).
pub const CLAUDE_HKLM_KEY: &str = r"SOFTWARE\Policies\ClaudeCode";
/// The service's own DACL (W10): only SYSTEM and Administrators can stop,
/// pause, reconfigure or delete it.
pub const WIN_SERVICE_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLORC;;;AU)";

/// The platform a layout is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Macos,
    /// Locked mode's paths and names are [`windows_path`] and the `WIN_*`
    /// constants (spec §5.3a).
    Windows,
}

impl Platform {
    /// The platform this binary runs on; `None` on any other OS.
    pub fn current() -> Option<Platform> {
        if cfg!(target_os = "linux") {
            Some(Platform::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Platform::Macos)
        } else if cfg!(windows) {
            Some(Platform::Windows)
        } else {
            None
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Macos => "macos",
            Platform::Windows => "windows",
        }
    }
}

/// The mode of the installed binary ([`BINARY`], root-owned).
///
/// - Linux `0711`: an exec needs only execute permission, and the kernel
///   makes a process whose binary it cannot read not dumpable, so `ptrace`,
///   `/proc/<pid>/mem` and `process_vm_writev` refuse a hook to its own user.
/// - macOS `0755`: the hardened runtime already refuses `task_for_pid`.
/// - Windows: not used (the file's DACL is set instead).
pub fn binary_mode(platform: Platform) -> u32 {
    match platform {
        Platform::Linux => 0o711,
        Platform::Macos | Platform::Windows => 0o755,
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
        // SIP protects /usr, except /usr/local.
        PACKAGE_BINARY => "/usr/local/libexec/saiife/saiife",
        _ => return None,
    })
}

/// The Windows path (spec §5.3a, W9) for a Linux path constant. `None` means
/// the constant has no Windows path: there is no run dir, unit file, polkit or
/// credstore there, and the install lock is [`WIN_INSTALL_LOCK`], not a constant of this
/// table, so it can never pass for a path outside a checked directory.
pub fn windows_path(linux: &str) -> Option<&'static str> {
    Some(match linux {
        OPT_DIR => r"C:\ProgramData\saiife",
        BIN_DIR => r"C:\ProgramData\saiife\bin",
        BINARY => r"C:\ProgramData\saiife\bin\saiife.exe",
        ETC_DIR => r"C:\ProgramData\saiife\etc",
        CONFIG => r"C:\ProgramData\saiife\etc\config.toml",
        POLICY_D => r"C:\ProgramData\saiife\etc\policy.d",
        INSTALLED => r"C:\ProgramData\saiife\etc\installed.toml",
        CA_DIR => r"C:\ProgramData\saiife\etc\ca",
        FLEET_DIR => r"C:\ProgramData\saiife\etc\fleet",
        FLEET_CONFIG => r"C:\ProgramData\saiife\etc\fleet\config.toml",
        FLEET_INSTALL => r"C:\ProgramData\saiife\etc\fleet\install.toml",
        STATE_DIR => r"C:\ProgramData\saiife\state",
        KEYS_DIR => r"C:\ProgramData\saiife\state\keys",
        AUDIT_KEY => r"C:\ProgramData\saiife\state\keys\audit.ed25519",
        VAULT_KEY => r"C:\ProgramData\saiife\state\keys\vault.key",
        LOG_DIR => r"C:\ProgramData\saiife\log",
        AUDIT_DIR => r"C:\ProgramData\saiife\log\audit",
        DAEMON_LOG => r"C:\ProgramData\saiife\log\daemon\daemon.log",
        CLAUDE_MANAGED_DIR => r"C:\Program Files\ClaudeCode\managed-settings.d",
        CLAUDE_MANAGED => r"C:\Program Files\ClaudeCode\managed-settings.d\50-saiife.json",
        CLAUDE_MCP => r"C:\Program Files\ClaudeCode\managed-settings.d\60-saiife-mcp.json",
        CODEX_DIR => r"C:\ProgramData\OpenAI\Codex",
        CODEX_REQUIREMENTS => r"C:\ProgramData\OpenAI\Codex\requirements.toml",
        GEMINI_DIR => r"C:\ProgramData\gemini-cli",
        GEMINI_SETTINGS => r"C:\ProgramData\gemini-cli\settings.json",
        PACKAGE_BINARY => r"C:\Program Files\saiife\saiife.exe",
        _ => return None,
    })
}

/// Where a client reaches the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Unix(PathBuf),
    Pipe(String),
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
    /// The real machine (root `/`; `C:\` on Windows).
    pub fn system() -> Layout {
        Layout::system_for(host_platform())
    }

    /// [`Layout::system`] for `platform`, so Linux tests can read the real
    /// Windows spellings.
    pub(crate) fn system_for(platform: Platform) -> Layout {
        Layout {
            root: PathBuf::from(match platform {
                Platform::Windows => WINDOWS_SYSTEM_ROOT,
                Platform::Linux | Platform::Macos => "/",
            }),
            resolved: true,
            platform,
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
    /// the macOS and Windows trees.
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
    /// names it, without the root. On Windows a constant with no Windows
    /// path keeps its Linux spelling, which [`Layout::at`] refuses.
    pub fn logical<'a>(&self, abs: &'a str) -> &'a str {
        match self.platform {
            Platform::Linux => abs,
            Platform::Macos => macos_path(abs).unwrap_or(abs),
            Platform::Windows => windows_path(abs).unwrap_or(abs),
        }
    }

    pub fn daemon_user(&self) -> &'static str {
        match self.platform {
            Platform::Linux => DAEMON_USER,
            Platform::Macos => MACOS_DAEMON_USER,
            Platform::Windows => WIN_DAEMON_ACCOUNT,
        }
    }

    pub fn daemon_group(&self) -> &'static str {
        match self.platform {
            Platform::Linux => DAEMON_GROUP,
            Platform::Macos => MACOS_DAEMON_GROUP,
            // No group of its own: the virtual account is its own principal (W10).
            Platform::Windows => WIN_DAEMON_ACCOUNT,
        }
    }

    pub fn audit_group(&self) -> &'static str {
        match self.platform {
            Platform::Linux => AUDIT_GROUP,
            Platform::Macos => MACOS_AUDIT_GROUP,
            Platform::Windows => WIN_AUDIT_GROUP,
        }
    }

    /// The systemd unit, the launchd label on macOS, the service on Windows.
    pub fn unit_name(&self) -> &'static str {
        match self.platform {
            Platform::Linux => UNIT_NAME,
            Platform::Macos => LAUNCHD_LABEL,
            Platform::Windows => WIN_SERVICE,
        }
    }

    /// Where a client reaches the daemon: the pipe on Windows, else the
    /// socket below the root.
    pub fn control_endpoint(&self) -> Endpoint {
        match self.platform {
            Platform::Windows => Endpoint::Pipe(WIN_PIPE.to_string()),
            Platform::Linux | Platform::Macos => Endpoint::Unix(self.at(SOCKET)),
        }
    }

    /// False when the root given to [`Layout::under`] could not be resolved.
    pub fn is_resolved(&self) -> bool {
        self.resolved
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// True for the real machine: the (resolved) root is `/`, or `C:\` for
    /// the Windows layout.
    pub fn is_system(&self) -> bool {
        self.resolved && (self.root == Path::new("/") || self.on_windows_system_root())
    }

    /// The Windows layout at `C:\`, spelled plainly or as `canonicalize`
    /// spells it. Any other root holds the tree below it, drive letter and all.
    fn on_windows_system_root(&self) -> bool {
        self.platform == Platform::Windows
            && self.root.to_str().is_some_and(|r| {
                r.strip_prefix(r"\\?\")
                    .unwrap_or(r)
                    .eq_ignore_ascii_case(WINDOWS_SYSTEM_ROOT)
            })
    }

    /// `abs` (one of the path constants) below the root, as this platform
    /// names it ([`macos_path`]). Panics on a path that could leave the
    /// root; use [`Layout::try_at`] for any path that is not a constant of
    /// this module (it is joined as given, never mapped).
    ///
    /// On Windows it also panics on a constant with no Windows path, rather
    /// than make `C:\run\saiife`, which any user could have created first.
    /// `uninstall.rs` passes such a constant (`INSTALL_LOCK`) only after its Windows
    /// branch, and `doctor/system.rs` (`RUN_DIR`, `CREDSTORE`, `UNIT`) branches at each
    /// call. `status_client` in `crates/cli/src/status_cmd.rs` (`RUN_DIR`) has a Windows form
    /// that names the pipe, so its `RUN_DIR` is never asked for there.
    pub fn at(&self, abs: &str) -> PathBuf {
        self.try_at(Path::new(self.logical(abs)))
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// `abs` below the root. `abs` must be absolute with plain components
    /// only (no `..`, no `.`), so the result never leaves the root.
    /// Never pass a layout constant: it is joined as given, never mapped,
    /// so map it with [`Layout::logical`] first (or use [`Layout::at`]).
    ///
    /// On Windows `abs` must be `X:\a\b` with plain names ([`windows_parts`]),
    /// whatever OS this runs on.
    pub fn try_at(&self, abs: &Path) -> io::Result<PathBuf> {
        if self.platform == Platform::Windows {
            return self.try_at_windows(abs);
        }
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

    fn try_at_windows(&self, abs: &Path) -> io::Result<PathBuf> {
        let refused = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} leaves the root: only absolute X:\\ paths with plain names are allowed",
                    abs.display()
                ),
            )
        };
        let (drive, names) = abs.to_str().and_then(windows_parts).ok_or_else(refused)?;
        if self.on_windows_system_root() {
            if !drive.eq_ignore_ascii_case(&'C') {
                return Err(refused());
            }
            return Ok(PathBuf::from(format!(r"{drive}:\{}", names.join(r"\"))));
        }
        let mut out = self.root.join(drive.to_string());
        out.extend(names);
        Ok(out)
    }

    /// The drive letter and names of `path`, a path of this Windows layout.
    /// `None` for another layout, or a path outside it or not plainly spelled
    /// (see [`windows_parts`]), so nothing can pass for a path of the tree.
    pub(crate) fn windows_location(&self, path: &Path) -> Option<(char, Vec<String>)> {
        if self.platform != Platform::Windows || !self.resolved {
            return None;
        }
        if self.on_windows_system_root() {
            let (drive, names) = windows_parts(path.to_str()?)?;
            return Some((drive, names.into_iter().map(str::to_string).collect()));
        }
        let mut parts = Vec::new();
        for part in path.strip_prefix(&self.root).ok()?.components() {
            let Component::Normal(name) = part else {
                return None;
            };
            parts.push(name.to_str()?.to_string());
        }
        let mut chars = parts.first()?.chars();
        let (Some(drive), None) = (chars.next(), chars.next()) else {
            return None;
        };
        let names = parts.split_off(1);
        (drive.is_ascii_alphabetic() && names.iter().all(|n| plain_windows_name(n)))
            .then_some((drive, names))
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

/// `Layout::system()` on Windows.
const WINDOWS_SYSTEM_ROOT: &str = r"C:\";

/// `X:\a\b` (either slash) as its drive letter and names. `None` for anything
/// else: relative and drive-relative paths, UNC and `\\?\` paths, doubled or
/// trailing slashes, and any name that is not [`plain_windows_name`].
fn windows_parts(path: &str) -> Option<(char, Vec<&str>)> {
    let mut chars = path.chars();
    let (drive, colon, slash) = (chars.next()?, chars.next()?, chars.next()?);
    if !drive.is_ascii_alphabetic() || colon != ':' || !matches!(slash, '\\' | '/') {
        return None;
    }
    let rest = chars.as_str();
    if rest.is_empty() {
        return Some((drive, Vec::new()));
    }
    let names: Vec<&str> = rest.split(['\\', '/']).collect();
    names
        .iter()
        .all(|n| plain_windows_name(n))
        .then_some((drive, names))
}

/// A name Windows takes as it reads. Win32 drops a trailing dot or space, so
/// `.. ` is `..` and `vault.key.` is `vault.key`; `name:stream` is an alternate
/// data stream of `name`.
fn plain_windows_name(name: &str) -> bool {
    !name.is_empty()
        && !name.ends_with(['.', ' '])
        && !name.chars().any(|c| {
            c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        })
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
mod platform_tests {
    use super::*;

    #[test]
    fn platform_windows_name() {
        assert_eq!(Platform::Windows.name(), "windows");
        #[cfg(windows)]
        assert_eq!(Platform::current(), Some(Platform::Windows));
    }
}

#[cfg(test)]
mod windows_tests {
    use super::*;
    use saiife_agents::Agent;

    /// Every Linux constant with a Windows path, with its §5.3a value.
    const WINDOWS_TABLE: [(&str, &str); 26] = [
        (OPT_DIR, r"C:\ProgramData\saiife"),
        (BIN_DIR, r"C:\ProgramData\saiife\bin"),
        (BINARY, r"C:\ProgramData\saiife\bin\saiife.exe"),
        (ETC_DIR, r"C:\ProgramData\saiife\etc"),
        (CONFIG, r"C:\ProgramData\saiife\etc\config.toml"),
        (POLICY_D, r"C:\ProgramData\saiife\etc\policy.d"),
        (INSTALLED, r"C:\ProgramData\saiife\etc\installed.toml"),
        (CA_DIR, r"C:\ProgramData\saiife\etc\ca"),
        (FLEET_DIR, r"C:\ProgramData\saiife\etc\fleet"),
        (FLEET_CONFIG, r"C:\ProgramData\saiife\etc\fleet\config.toml"),
        (
            FLEET_INSTALL,
            r"C:\ProgramData\saiife\etc\fleet\install.toml",
        ),
        (STATE_DIR, r"C:\ProgramData\saiife\state"),
        (KEYS_DIR, r"C:\ProgramData\saiife\state\keys"),
        (AUDIT_KEY, r"C:\ProgramData\saiife\state\keys\audit.ed25519"),
        (VAULT_KEY, r"C:\ProgramData\saiife\state\keys\vault.key"),
        (LOG_DIR, r"C:\ProgramData\saiife\log"),
        (AUDIT_DIR, r"C:\ProgramData\saiife\log\audit"),
        (DAEMON_LOG, r"C:\ProgramData\saiife\log\daemon\daemon.log"),
        (
            CLAUDE_MANAGED_DIR,
            r"C:\Program Files\ClaudeCode\managed-settings.d",
        ),
        (
            CLAUDE_MANAGED,
            r"C:\Program Files\ClaudeCode\managed-settings.d\50-saiife.json",
        ),
        (
            CLAUDE_MCP,
            r"C:\Program Files\ClaudeCode\managed-settings.d\60-saiife-mcp.json",
        ),
        (CODEX_DIR, r"C:\ProgramData\OpenAI\Codex"),
        (
            CODEX_REQUIREMENTS,
            r"C:\ProgramData\OpenAI\Codex\requirements.toml",
        ),
        (GEMINI_DIR, r"C:\ProgramData\gemini-cli"),
        (GEMINI_SETTINGS, r"C:\ProgramData\gemini-cli\settings.json"),
        (PACKAGE_BINARY, r"C:\Program Files\saiife\saiife.exe"),
    ];

    /// The constants W9 gives no Windows path, those it does not name, and a
    /// string that is no constant.
    const NO_WINDOWS_PATH: [&str; 9] = [
        RUN_DIR,
        SOCKET,
        UNIT,
        POLKIT_DIR,
        POLKIT_ACTION,
        PKCHECK,
        CREDSTORE,
        INSTALL_LOCK,
        "/etc/saiife/other",
    ];

    /// `windows` below `root`: the drive letter, then each name.
    fn below(root: &Path, windows: &str) -> PathBuf {
        let (drive, rest) = windows.split_once(r":\").unwrap();
        let mut out = root.join(drive);
        out.extend(rest.split('\\'));
        out
    }

    #[test]
    fn windows_paths_are_spec_values() {
        for (linux, win) in WINDOWS_TABLE {
            assert_eq!(windows_path(linux), Some(win), "{linux}");
        }
        for p in NO_WINDOWS_PATH {
            assert_eq!(windows_path(p), None, "{p}");
        }
        assert_eq!(WIN_PIPE, "\\\\.\\pipe\\saiife");
        assert_eq!(WIN_PERSONAL_PIPE_PREFIX, "\\\\.\\pipe\\saiife-user-");
        assert_eq!(WIN_SERVICE, "saiifed");
        assert_eq!(WIN_SERVICE_DISPLAY, "saiife daemon");
        assert_eq!(WIN_DAEMON_ACCOUNT, "NT SERVICE\\saiifed");
        assert_eq!(WIN_AUDIT_GROUP, "saiife-audit");
        assert_eq!(WIN_HOOK_BINARY, "C:/ProgramData/saiife/bin/saiife.exe");
        assert_eq!(CLAUDE_HKLM_KEY, "SOFTWARE\\Policies\\ClaudeCode");
        assert_eq!(
            WIN_SERVICE_SDDL,
            "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\
             (A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLORC;;;AU)"
        );
    }

    /// The hook binary is [`BINARY`] with forward slashes, and needs no quotes.
    #[test]
    fn hook_binary_is_the_locked_binary() {
        assert_eq!(
            WIN_HOOK_BINARY.replace('/', "\\"),
            windows_path(BINARY).unwrap()
        );
        assert!(!WIN_HOOK_BINARY.contains(' '));
    }

    /// Only SYSTEM and Administrators may start, stop, pause, reconfigure or
    /// delete the service: `RP`, `WP`, `DT`, `DC`, `SD`, `WD`, `WO`.
    #[test]
    fn service_dacl_gives_control_only_to_admins() {
        let mut seen = Vec::new();
        for ace in WIN_SERVICE_SDDL
            .strip_prefix("D:(")
            .unwrap()
            .strip_suffix(')')
            .unwrap()
            .split(")(")
        {
            let f: Vec<&str> = ace.split(';').collect();
            let (rights, who) = (f[2], f[5]);
            seen.push(who);
            let codes: Vec<&str> = rights
                .as_bytes()
                .chunks(2)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect();
            if !matches!(who, "SY" | "BA") {
                for code in ["RP", "WP", "DT", "DC", "SD", "WD", "WO"] {
                    assert!(!codes.contains(&code), "{who} holds {code}");
                }
            }
        }
        assert_eq!(seen, ["SY", "BA", "IU", "SU", "AU"]);
    }

    #[test]
    fn under_for_windows_maps_every_constant() {
        let dir = tempfile::tempdir().unwrap();
        let l = Layout::under_for(dir.path(), Platform::Windows);
        assert_eq!(l.platform(), Platform::Windows);
        assert!(!l.is_system());
        for (linux, win) in WINDOWS_TABLE {
            assert_eq!(l.at(linux), below(l.root(), win), "{linux}");
            assert_eq!(l.logical(linux), win, "{linux}");
            assert!(l.at(linux).starts_with(l.root()), "{linux}");
        }
        assert_eq!(
            l.managed_file(Agent::Claude),
            below(l.root(), windows_path(CLAUDE_MANAGED).unwrap())
        );
        assert_eq!(
            l.managed_file(Agent::Codex),
            below(l.root(), windows_path(CODEX_REQUIREMENTS).unwrap())
        );
        assert_eq!(
            l.managed_file(Agent::Gemini),
            below(l.root(), windows_path(GEMINI_SETTINGS).unwrap())
        );
    }

    /// The real spellings: `Layout::system()` on Windows.
    #[test]
    fn windows_system_layout_is_the_real_paths() {
        let l = Layout::system_for(Platform::Windows);
        assert!(l.is_system());
        assert_eq!(l.root(), Path::new(r"C:\"));
        for (linux, win) in WINDOWS_TABLE {
            assert_eq!(l.at(linux), Path::new(win), "{linux}");
        }
        #[cfg(windows)]
        {
            assert_eq!(Layout::system(), l);
            assert!(Layout::under(r"C:\").is_system());
        }
    }

    /// A constant with no Windows path never lands on the drive root, or
    /// anywhere else, under any root.
    #[test]
    fn constants_with_no_windows_path_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for l in [
            Layout::under_for(dir.path(), Platform::Windows),
            Layout::system_for(Platform::Windows),
        ] {
            for p in NO_WINDOWS_PATH {
                assert!(l.try_at(Path::new(l.logical(p))).is_err(), "{p}");
                let at = std::panic::catch_unwind(|| l.at(p));
                assert!(at.is_err(), "{p} gave {at:?}");
            }
        }
    }

    #[test]
    fn windows_try_at_takes_only_plain_absolute_paths() {
        let dir = tempfile::tempdir().unwrap();
        let test = Layout::under_for(dir.path(), Platform::Windows);
        let sys = Layout::system_for(Platform::Windows);
        for l in [&test, &sys] {
            for bad in [
                "",
                "C:",
                "C:a",
                "a\\b",
                "/etc/saiife",
                r"\etc\saiife",
                r"\\server\share\a",
                r"\\?\C:\a",
                r"\\.\pipe\saiife",
                r"1:\a",
                r"C:\a\..\..\b",
                r"C:\a\.\b",
                r"C:\a\.. \b",
                r"C:\a\..\",
                r"C:\a\\b",
                r"C:\a\",
                r"C:\a.",
                r"C:\a ",
                r"C:\a:b",
                r"C:\a::$DATA",
                r"C:\a*",
                "C:\\a\nb",
            ] {
                assert!(l.try_at(Path::new(bad)).is_err(), "{bad:?}");
            }
        }
        assert_eq!(
            test.try_at(Path::new(r"D:\x\y")).unwrap(),
            below(test.root(), r"D:\x\y")
        );
        assert_eq!(
            sys.try_at(Path::new(r"C:\x/y")).unwrap(),
            Path::new(r"C:\x\y")
        );
        // The system root holds drive C only.
        assert!(sys.try_at(Path::new(r"D:\x")).is_err());
    }

    #[test]
    fn control_endpoint_per_platform() {
        let dir = tempfile::tempdir().unwrap();
        for l in [
            Layout::under_for(dir.path(), Platform::Windows),
            Layout::system_for(Platform::Windows),
        ] {
            assert_eq!(
                l.control_endpoint(),
                Endpoint::Pipe("\\\\.\\pipe\\saiife".to_string())
            );
        }
        for p in [Platform::Linux, Platform::Macos] {
            let l = Layout::under_for(dir.path(), p);
            assert_eq!(l.control_endpoint(), Endpoint::Unix(l.at(SOCKET)));
        }
    }

    #[test]
    fn windows_names() {
        let l = Layout::system_for(Platform::Windows);
        assert_eq!(l.daemon_user(), r"NT SERVICE\saiifed");
        assert_eq!(l.audit_group(), "saiife-audit");
        assert_eq!(l.unit_name(), "saiifed");
    }
}

// The path constants and the root resolution are POSIX; the Windows layout is
// tested above, so these tests assume Unix paths and do not run on Windows.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use saiife_agents::Agent;
    use std::path::Path;

    /// The daemon listens where the drop-in's HTTP hook posts, and the allow-list admits it.
    #[test]
    fn cosign_addr_matches_the_claude_url() {
        assert_eq!(COSIGN_ADDR, "127.0.0.1:7433");
        assert_eq!(
            saiife_agents::claude::COSIGN_URL,
            format!("http://{COSIGN_ADDR}/v1/cosign/claude")
        );
        assert_eq!(
            saiife_agents::claude::COSIGN_URL_PATTERN,
            format!("http://{COSIGN_ADDR}/*")
        );
        assert!(COSIGN_ADDR.parse::<std::net::SocketAddr>().is_ok());
    }

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
        assert_eq!(PACKAGE_BINARY, "/usr/libexec/saiife/saiife");
    }

    /// The Linux constants that differ on macOS, with their §5.3 value.
    const MACOS_TABLE: [(&str, &str); 13] = [
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
        (PACKAGE_BINARY, "/usr/local/libexec/saiife/saiife"),
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

    /// Plan 19b's Windows table changes nothing on the other two: every path
    /// and name, against literals.
    #[test]
    fn linux_and_macos_layouts_unchanged() {
        let l = Layout::under_for("/x", Platform::Linux);
        let m = Layout::under_for("/x", Platform::Macos);
        for (constant, linux, mac) in [
            (BINARY, "/opt/saiife/bin/saiife", "/opt/saiife/bin/saiife"),
            (CONFIG, "/etc/saiife/config.toml", "/etc/saiife/config.toml"),
            (
                VAULT_KEY,
                "/etc/saiife/credstore/vault-key",
                "/var/db/saiife/keys/vault.key",
            ),
            (
                DAEMON_LOG,
                "/var/log/saiife/daemon.log",
                "/var/log/saiife/daemon.log",
            ),
            (
                SOCKET,
                "/run/saiife/saiife.sock",
                "/var/db/saiife-run/saiife.sock",
            ),
            (
                INSTALL_LOCK,
                "/etc/saiife-install.lock",
                "/etc/saiife-install.lock",
            ),
            (CA_DIR, "/etc/saiife/ca", "/etc/saiife/ca"),
        ] {
            assert_eq!(l.logical(constant), linux);
            assert_eq!(m.logical(constant), mac);
            assert_eq!(l.at(constant), Path::new("/x").join(&linux[1..]));
            assert_eq!(m.at(constant), Path::new("/x").join(&mac[1..]));
        }
        for p in ALL_PATHS {
            assert_eq!(l.at(p), Path::new("/x").join(&p[1..]), "{p}");
            assert_eq!(l.logical(p), p, "{p}");
            assert_eq!(macos_path(p).unwrap_or(p), m.logical(p), "{p}");
        }
        assert_eq!(l.unit_name(), "saiifed.service");
        assert_eq!(m.unit_name(), "com.saiife.saiifed");
        assert_eq!(l.daemon_user(), "saiife");
        assert_eq!(m.daemon_user(), "_saiife");
        assert_eq!(
            Layout::under_for("/", Platform::Linux).at(SOCKET),
            Path::new("/run/saiife/saiife.sock")
        );
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
        // Windows has no daemon group: the virtual account stands for itself.
        let w = Layout::under_for("/x", Platform::Windows);
        assert_eq!(w.daemon_group(), WIN_DAEMON_ACCOUNT);
    }
}
