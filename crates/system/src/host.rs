//! Every privileged action of locked mode goes through [`Host`]:
//! [`RealHost`] acts on the machine, [`FakeHost`] keeps a record in
//! `<root>/.fakehost.json` instead (tests and the hidden `--root` flag).
//! Programs always run from absolute paths.

use crate::layout::{
    Layout, AUDIT_GROUP, DAEMON_GROUP, DAEMON_USER, MACOS_AUDIT_GROUP, MACOS_DAEMON_GROUP,
    MACOS_DAEMON_USER,
};
use crate::winservice::{ServiceOp, ServiceSpec, ServiceState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::ops::RangeInclusive;
#[cfg(unix)]
use std::os::fd::BorrowedFd;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const USERADD: &str = "/usr/sbin/useradd";
pub const GROUPADD: &str = "/usr/sbin/groupadd";
pub const USERMOD: &str = "/usr/sbin/usermod";
pub const USERDEL: &str = "/usr/sbin/userdel";
pub const GROUPDEL: &str = "/usr/sbin/groupdel";
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
pub const SYSTEMD_CREDS: &str = "/usr/bin/systemd-creds";
pub const DETECT_VIRT: &str = "/usr/bin/systemd-detect-virt";
pub const GPASSWD: &str = "/usr/bin/gpasswd";
pub const SUDO: &str = "/usr/bin/sudo";
// macOS (plan 13).
pub const DSCL: &str = "/usr/bin/dscl";
pub const DSEDITGROUP: &str = "/usr/sbin/dseditgroup";
pub const LAUNCHCTL: &str = "/bin/launchctl";
pub const SW_VERS: &str = "/usr/bin/sw_vers";
pub const SECURITY: &str = "/usr/bin/security";

// Windows (plan 19b). `exec` runs them by this path, never through `PATH`.
pub const NET_EXE: &str = r"C:\Windows\System32\net.exe";
pub const SC_EXE: &str = r"C:\Windows\System32\sc.exe";
/// The registry key of `CurrentBuildNumber` and `InstallationType`, below HKLM.
pub const REG_NT_CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// The uids and gids the macOS daemon accounts may take (spec §5.3): below
/// 500, where macOS keeps its hidden system accounts.
pub const MACOS_ID_RANGE: RangeInclusive<u32> = 200..=400;

/// Every program locked mode runs on Windows.
pub const WIN_PROGRAMS: &[&str] = &[NET_EXE, SC_EXE];

/// Every program locked mode runs (plan 9b global constraints), always by
/// absolute path.
pub const PROGRAMS: &[&str] = &[
    USERADD,
    GROUPADD,
    USERMOD,
    USERDEL,
    GROUPDEL,
    GPASSWD,
    SYSTEMCTL,
    SYSTEMD_CREDS,
    DETECT_VIRT,
    SUDO,
    DSCL,
    DSEDITGROUP,
    LAUNCHCTL,
    SW_VERS,
    SECURITY,
];

/// How long the user and group tools may take.
const ADMIN_TIMEOUT: Duration = Duration::from_secs(30);
/// `systemctl enable --now` waits for the daemon's start-up notification.
#[cfg(unix)]
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(90);
#[cfg(unix)]
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Most bytes kept of a program's stdout and of its stderr (64 KiB).
const OUTPUT_CAP: usize = 64 * 1024;
/// How long to wait for the pipes to close once the program has exited.
const PIPE_GRACE: Duration = Duration::from_millis(200);

/// What a program printed and how it ended (`128 + signal` when killed).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CmdOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// The daemon's answer to `policy.reload` (spec §7): whether the policy
/// on disk now is the one it enforces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadAnswer {
    /// `result = "loaded"`; anything else is a rejection.
    pub loaded: bool,
    /// Why it was rejected (empty when loaded).
    pub reason: String,
    /// The policy hash the daemon enforces after the call.
    pub hash: Option<String>,
}

impl ReloadAnswer {
    /// From the `policy.reload` answer fields.
    pub fn from_answer(a: &serde_json::Map<String, serde_json::Value>) -> ReloadAnswer {
        let s = |k: &str| a.get(k).and_then(serde_json::Value::as_str);
        let result = s("result").unwrap_or("");
        ReloadAnswer {
            loaded: result == "loaded",
            reason: match s("reason") {
                Some(r) if !r.is_empty() => r.to_string(),
                _ if result == "loaded" => String::new(),
                _ if result.is_empty() => "no result in the answer".to_string(),
                _ => format!("result {result:?}"),
            },
            hash: s("hash").map(str::to_string),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: String,
}

/// A Windows build, from `CurrentBuildNumber` and `InstallationType`.
/// This process's own token, as [`Host::own_token`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnToken {
    /// The token's user SID: the identity.
    pub sid: String,
    /// The token holds `Administrators` enabled, at any integrity level, or
    /// [`Host::elevated`] says so.
    pub elevated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinBuild {
    pub build: u32,
    pub server: bool,
}

/// A value in a [`FakeState`]'s registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegValue {
    Str(String),
    Dword(u32),
    /// Any other type: `reg_string` and `reg_dword` cannot read it, and
    /// `reg_value_present` still finds it.
    Other,
}

pub trait Host: Send + Sync {
    fn euid(&self) -> u32;
    /// The user from `/etc/passwd` (not NSS: a locked-mode user must be
    /// local).
    fn user(&self, name: &str) -> Option<UserInfo>;
    /// The group id from `/etc/group`.
    fn group_id(&self, name: &str) -> Option<u32>;
    /// The supplementary members of the group from `/etc/group` (primary
    /// members are not listed there); `None` when the group does not exist.
    /// On macOS, from the local node; members that cannot be named (nested
    /// groups, a GUID member without a name, an unreadable record) appear
    /// as `<…>` entries, which are never a user name, so a "no other
    /// members" check refuses them.
    fn group_members(&self, name: &str) -> Option<Vec<String>>;
    /// Users in `/etc/passwd` whose primary group is `gid` (they are not
    /// listed as members in `/etc/group`). On macOS an `Err` when the
    /// directory could not be asked: callers refuse then.
    fn users_with_primary_gid(&self, gid: u32) -> io::Result<Vec<String>>;
    fn create_system_group(&self, name: &str) -> io::Result<()>;
    /// A system user with primary group `group`, no home and no login shell.
    fn create_system_user(&self, name: &str, group: &str) -> io::Result<()>;
    fn add_to_group(&self, user: &str, group: &str) -> io::Result<()>;
    fn delete_user(&self, name: &str) -> io::Result<()>;
    fn delete_group(&self, name: &str) -> io::Result<()>;
    /// Removes `user` from the supplementary group `group`.
    fn remove_from_group(&self, user: &str, group: &str) -> io::Result<()>;
    /// Changes owner and group of `path` itself; never follows a symlink.
    fn chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()>;
    /// Changes owner and group of the open file `fd` (`fchown`), so a path
    /// swapped after it was checked cannot redirect the change. `shown`
    /// names it in errors (and in a fake's record).
    #[cfg(unix)]
    fn fchown(&self, fd: BorrowedFd<'_>, shown: &Path, uid: u32, gid: u32) -> io::Result<()>;
    /// Runs `systemctl <args>`. A non-zero exit is an `Ok` with its status.
    fn systemctl(&self, args: &[&str]) -> io::Result<CmdOutput>;
    fn systemd_version(&self) -> io::Result<u32>;
    /// Encrypts `secret` as the systemd credential `name` into `out`.
    fn encrypt_credential(&self, name: &str, secret: &[u8], out: &Path) -> io::Result<()>;
    /// The container technology when running inside one.
    fn container(&self) -> Option<String>;
    /// Runs `program` (an absolute path) with no stdin; killed after
    /// `timeout`. A non-zero exit is an `Ok` with its status.
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> io::Result<CmdOutput>;
    /// Runs `launchctl <args>` (macOS). A non-zero exit is an `Ok` with its
    /// status.
    fn launchctl(&self, args: &[&str]) -> io::Result<CmdOutput>;
    /// The macOS (major, minor) from `sw_vers -productVersion`.
    fn macos_version(&self) -> io::Result<(u32, u32)>;
    /// macOS: System Integrity Protection is on, by `csrutil status`
    /// ([`crate::sip::parse_status`]). An error, or any answer but the
    /// plain "enabled." line, is false (fail closed).
    fn sip_enabled(&self) -> bool;
    /// [`Host::run`] with `input` written to the program's stdin.
    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        timeout: Duration,
    ) -> io::Result<CmdOutput>;
    /// The owner of `path`, whose `lstat`/`fstat` says `on_disk`. The real
    /// host returns `on_disk`; the fake host applies the chowns it recorded
    /// (its chowns are never applied on disk).
    fn owner_uid(&self, path: &Path, on_disk: u32) -> u32;
    /// Asks the running daemon on the socket in `socket_dir` (owned by
    /// `daemon_uid`) to load the policy again, synchronously, and returns
    /// its answer. Waits at most `wait` for the socket and the answer.
    fn policy_reload(
        &self,
        socket_dir: &Path,
        daemon_uid: u32,
        wait: Duration,
    ) -> io::Result<ReloadAnswer>;
    /// Windows: sets the owner, a protected DACL and any group of `path`, which must
    /// not be a reparse point. The text must name an owner and say `D:P`.
    ///
    /// This propagates inheritable entries to existing children that inherit, as CI
    /// showed (`SetSecurityInfo` on a directory handle). It does not reach a
    /// protected child (`P`) or an explicit entry a child holds. To set those too,
    /// call [`crate::winacl::set_sddl_tree`], which sets each entry itself.
    fn set_sddl(&self, path: &Path, sddl: &str) -> io::Result<()>;
    /// Windows: the owner, group and DACL of `path`. A reparse point is an error.
    fn get_sddl(&self, path: &Path) -> io::Result<String>;
    /// Windows: creates the dir `path` with this descriptor from its first moment.
    /// An existing path is an error.
    fn create_dir_sddl(&self, path: &Path, sddl: &str) -> io::Result<()>;
    /// Windows: the SID of an account. The SID is the identity; a uid is a label.
    fn lookup_sid(&self, name: &str) -> Option<String>;
    /// A string value below HKLM. `REG_EXPAND_SZ` comes back unexpanded.
    fn reg_string(&self, key: &str, value: &str) -> Option<String>;
    /// A `DWORD` value below HKLM.
    fn reg_dword(&self, key: &str, value: &str) -> Option<u32>;
    /// Whether a value exists below HKLM, of any type. Only "not found", of the key
    /// or the value, is `false`: any other failure is an `Err`, for callers that must
    /// fail closed. `reg_string` and `reg_dword` cannot tell those cases apart.
    fn reg_value_present(&self, key: &str, value: &str) -> io::Result<bool>;
    /// The Windows build. Unreadable or unrecognised values are an error.
    fn windows_build(&self) -> io::Result<WinBuild>;
    /// One operation on the service `saiifed`.
    fn service(&self, op: ServiceOp) -> io::Result<ServiceState>;
    /// Whether this process may do what needs root or an elevated administrator. On
    /// Windows that is more than [`Host::euid`]: a low-integrity or restricted child of an
    /// elevated admin still holds `Administrators`, enabled (W26).
    fn elevated(&self) -> bool {
        self.euid() == 0
    }
    /// Windows: the SID of the local group `name`. `Ok(None)` when no account has that
    /// name; an account of another kind is an `Err`, as is a failed lookup.
    fn lookup_local_group(&self, name: &str) -> io::Result<Option<String>>;
    /// Windows: holds the directory `path` so it cannot be renamed or deleted until the
    /// result is dropped. A reparse point is an error.
    fn hold_dir(&self, path: &Path) -> io::Result<Hold>;
    /// Windows: takes the lock file `path`, which goes when the result is dropped or the
    /// process ends. `Ok(None)` when another holds it.
    fn lock_file(&self, path: &Path) -> io::Result<Option<Hold>>;
    /// Windows: whether Claude Code's machine policy leaves saiife's drop-in in force
    /// (W24).
    fn claude_hklm_policy(&self) -> saiife_agents::claude::HklmPolicy;
    /// Windows: connects to the daemon's pipe, checking its owner, within `wait`.
    fn wait_for_pipe(&self, wait: Duration) -> io::Result<()>;
    /// Windows: the service `saiifed` as the service manager has it now, so doctor can
    /// compare it with W10. `Ok(None)` when it does not exist. Its `sddl` is what
    /// `sc.exe sdshow` prints, which may hold a SACL.
    fn service_spec(&self) -> io::Result<Option<crate::winservice::ServiceSpec>> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    /// Windows: `WinVerifyTrust`'s answer for the file's embedded signature, in this
    /// process: see [`crate::binary::authenticode_verdict`].
    fn authenticode_status(&self, path: &Path) -> io::Result<i32> {
        let _ = path;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    /// Windows: the local groups `user` is in, nested ones included. Names only, and
    /// they are localized, so compare the SIDs [`Host::lookup_sid`] gives for them.
    fn local_groups_of(&self, user: &str) -> io::Result<Vec<String>> {
        let _ = user;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    /// Windows: the daemon's answer to `status` over its pipe, whose owner is checked,
    /// within `wait`.
    fn daemon_status(
        &self,
        wait: Duration,
    ) -> io::Result<serde_json::Map<String, serde_json::Value>> {
        let _ = wait;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    /// Renames a file. Its descriptor goes with it, which the fake must be told.
    fn rename_file(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }
    /// Windows: this process's own token. A token that cannot be read is an `Err`, which
    /// callers must treat as elevated.
    fn own_token(&self) -> io::Result<OwnToken> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// Something [`Host`] keeps open for as long as this lives.
pub type Hold = Box<dyn std::any::Any + Send>;

/// [`Host::policy_reload`] over the control socket. A socket that does not
/// answer yet is tried again until `wait` has passed. Linux and macOS: the
/// caller passes the configured socket dir (`/run/saiife`, or
/// `/var/db/saiife-run` on macOS).
#[cfg(unix)]
pub fn call_policy_reload(
    socket_dir: &Path,
    daemon_uid: u32,
    wait: Duration,
) -> io::Result<ReloadAnswer> {
    use saiife_ipc::client::{Client, ClientError};
    use saiife_ipc::msg::OP_POLICY_RELOAD;
    let deadline = Instant::now() + wait;
    loop {
        let err = match Client::connect(socket_dir, daemon_uid, deadline) {
            Ok(mut c) => {
                return match c.call(OP_POLICY_RELOAD, serde_json::Map::new(), deadline) {
                    Ok(a) => Ok(ReloadAnswer::from_answer(&a)),
                    Err(ClientError::Timeout) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("no answer to policy.reload within {} s", wait.as_secs()),
                    )),
                    Err(e) => Err(io::Error::other(format!("policy.reload: {e}"))),
                };
            }
            Err(e) => e,
        };
        let pause = Duration::from_millis(200);
        if Instant::now() + pause >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the daemon socket did not answer within {} s: {err}",
                    wait.as_secs()
                ),
            ));
        }
        std::thread::sleep(pause);
    }
}

/// What `container` reports when it cannot tell (systemd-detect-virt
/// missing or not answering on a systemd host). The supported check refuses
/// it: locked mode fails closed.
pub const CONTAINER_UNKNOWN: &str = "unknown";

/// Which host a resolved root gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    Real,
    Fake,
}

/// The decision behind [`host_for`]: `/` is the machine; any other root is
/// a fake tree, which root may not use (a fake tree run as root would mix
/// fake bookkeeping with real privileges).
pub fn host_kind(canonical_root: &Path, euid: u32) -> Result<HostKind, String> {
    if canonical_root == Path::new("/") {
        Ok(HostKind::Real)
    } else if euid == 0 {
        Err(format!(
            "refusing --root {} as root: a test root is only for unprivileged runs",
            canonical_root.display()
        ))
    } else {
        Ok(HostKind::Fake)
    }
}

/// The host for `layout`: the machine itself for the real root, a
/// [`FakeHost`] for any other root. Refuses a root that could not be
/// resolved, and a test root when running as root.
pub fn host_for(layout: &Layout) -> io::Result<Box<dyn Host>> {
    if !layout.is_resolved() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "root {} cannot be resolved (`..` below a missing directory)",
                layout.root().display()
            ),
        ));
    }
    #[cfg(windows)]
    if layout.is_system() {
        return Ok(Box::new(RealHost));
    }
    let euid = own_euid();
    match host_kind(layout.root(), euid) {
        Ok(HostKind::Real) => Ok(Box::new(RealHost)),
        Ok(HostKind::Fake) => Ok(Box::new(FakeHost::open(layout.root())?)),
        Err(msg) => Err(io::Error::new(io::ErrorKind::PermissionDenied, msg)),
    }
}

// ---------------------------------------------------------------- RealHost

/// The machine. These are the only calls in saiife that need root.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealHost;

#[cfg(windows)]
#[path = "host_win.rs"]
mod win;

#[cfg(unix)]
fn own_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}
#[cfg(unix)]
fn own_uid() -> u32 {
    rustix::process::getuid().as_raw()
}
#[cfg(unix)]
fn own_gid() -> u32 {
    rustix::process::getgid().as_raw()
}
#[cfg(windows)]
use win::{own_euid, own_uid};
/// Windows has no primary group a fake's test user needs.
#[cfg(windows)]
fn own_gid() -> u32 {
    0
}

/// What a call answers on an OS it does not exist on.
fn windows_only() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "this call does not exist on this OS",
    )
}

#[cfg(unix)]
impl Host for RealHost {
    fn euid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn user(&self, name: &str) -> Option<UserInfo> {
        accounts::user(name)
    }

    fn group_id(&self, name: &str) -> Option<u32> {
        accounts::group_id(name)
    }

    fn group_members(&self, name: &str) -> Option<Vec<String>> {
        accounts::group_members(name)
    }

    fn users_with_primary_gid(&self, gid: u32) -> io::Result<Vec<String>> {
        accounts::users_with_primary_gid(gid)
    }

    fn create_system_group(&self, name: &str) -> io::Result<()> {
        accounts::create_system_group(name)
    }

    fn create_system_user(&self, name: &str, group: &str) -> io::Result<()> {
        accounts::create_system_user(name, group)
    }

    fn add_to_group(&self, user: &str, group: &str) -> io::Result<()> {
        accounts::add_to_group(user, group)
    }

    fn delete_user(&self, name: &str) -> io::Result<()> {
        accounts::delete_user(name)
    }

    fn delete_group(&self, name: &str) -> io::Result<()> {
        accounts::delete_group(name)
    }

    fn remove_from_group(&self, user: &str, group: &str) -> io::Result<()> {
        accounts::remove_from_group(user, group)
    }

    fn chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()> {
        if uid == u32::MAX || gid == u32::MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid id -1"));
        }
        rustix::fs::chownat(
            rustix::fs::CWD,
            path,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(gid)),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|e| {
            io::Error::new(
                io::Error::from(e).kind(),
                format!("chown {}: {e}", path.display()),
            )
        })
    }

    fn fchown(&self, fd: BorrowedFd<'_>, shown: &Path, uid: u32, gid: u32) -> io::Result<()> {
        if uid == u32::MAX || gid == u32::MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid id -1"));
        }
        rustix::fs::fchown(
            fd,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(gid)),
        )
        .map_err(|e| {
            io::Error::new(
                io::Error::from(e).kind(),
                format!("chown {}: {e}", shown.display()),
            )
        })
    }

    fn systemctl(&self, args: &[&str]) -> io::Result<CmdOutput> {
        exec(SYSTEMCTL, args, None, SYSTEMCTL_TIMEOUT)
    }

    fn systemd_version(&self) -> io::Result<u32> {
        let out = exec(SYSTEMCTL, &["--version"], None, QUERY_TIMEOUT)?;
        parse_systemd_version(&out.stdout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{SYSTEMCTL} --version printed no version"),
            )
        })
    }

    fn encrypt_credential(&self, name: &str, secret: &[u8], out: &Path) -> io::Result<()> {
        let argv = argv_encrypt(name, out)?;
        let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
        let res = exec(&argv[0], &args, Some(secret), ADMIN_TIMEOUT)?;
        check_status(&argv, &res)
    }

    fn container(&self) -> Option<String> {
        container_from(
            exec(DETECT_VIRT, &["--container"], None, QUERY_TIMEOUT),
            Path::new("/run/systemd/system").is_dir(),
        )
    }

    fn owner_uid(&self, _path: &Path, on_disk: u32) -> u32 {
        on_disk
    }

    fn policy_reload(
        &self,
        socket_dir: &Path,
        daemon_uid: u32,
        wait: Duration,
    ) -> io::Result<ReloadAnswer> {
        call_policy_reload(socket_dir, daemon_uid, wait)
    }

    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> io::Result<CmdOutput> {
        exec(program, args, None, timeout)
    }

    fn launchctl(&self, args: &[&str]) -> io::Result<CmdOutput> {
        exec(LAUNCHCTL, args, None, ADMIN_TIMEOUT)
    }

    fn sip_enabled(&self) -> bool {
        exec(crate::sip::CSRUTIL, &["status"], None, QUERY_TIMEOUT)
            .is_ok_and(|o| crate::sip::parse_status(&o))
    }

    fn macos_version(&self) -> io::Result<(u32, u32)> {
        // SYSTEM_VERSION_COMPAT=1 makes sw_vers answer 10.16 on macOS 11
        // and later.
        let out = exec_with(
            SW_VERS,
            &["-productVersion"],
            None,
            QUERY_TIMEOUT,
            &["SYSTEM_VERSION_COMPAT"],
        )?;
        if out.status != 0 {
            return Err(io::Error::other(format!(
                "{SW_VERS} -productVersion failed (exit {}): {}",
                out.status,
                out.stderr.trim()
            )));
        }
        parse_sw_vers(&out.stdout)
    }

    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        timeout: Duration,
    ) -> io::Result<CmdOutput> {
        exec(program, args, Some(input), timeout)
    }

    fn set_sddl(&self, _path: &Path, _sddl: &str) -> io::Result<()> {
        Err(windows_only())
    }

    fn get_sddl(&self, _path: &Path) -> io::Result<String> {
        Err(windows_only())
    }

    fn create_dir_sddl(&self, _path: &Path, _sddl: &str) -> io::Result<()> {
        Err(windows_only())
    }

    fn lookup_sid(&self, _name: &str) -> Option<String> {
        None
    }

    fn reg_string(&self, _key: &str, _value: &str) -> Option<String> {
        None
    }

    fn reg_dword(&self, _key: &str, _value: &str) -> Option<u32> {
        None
    }

    fn reg_value_present(&self, _key: &str, _value: &str) -> io::Result<bool> {
        Err(windows_only())
    }

    fn windows_build(&self) -> io::Result<WinBuild> {
        Err(windows_only())
    }

    fn service(&self, _op: ServiceOp) -> io::Result<ServiceState> {
        Err(windows_only())
    }

    fn lookup_local_group(&self, _name: &str) -> io::Result<Option<String>> {
        Err(windows_only())
    }

    fn hold_dir(&self, _path: &Path) -> io::Result<Hold> {
        Err(windows_only())
    }

    fn lock_file(&self, _path: &Path) -> io::Result<Option<Hold>> {
        Err(windows_only())
    }

    fn claude_hklm_policy(&self) -> saiife_agents::claude::HklmPolicy {
        saiife_agents::claude::HklmPolicy::Absent
    }

    fn wait_for_pipe(&self, _wait: Duration) -> io::Result<()> {
        Err(windows_only())
    }
}

/// The account calls of [`RealHost`] on Linux (and any other unix): the
/// files `/etc/passwd` and `/etc/group`, and the shadow-utils tools.
#[cfg(all(unix, not(target_os = "macos")))]
mod accounts {
    use super::*;

    pub(super) fn user(name: &str) -> Option<UserInfo> {
        find_passwd(&std::fs::read_to_string("/etc/passwd").ok()?, name)
    }

    pub(super) fn group_id(name: &str) -> Option<u32> {
        find_group(&std::fs::read_to_string("/etc/group").ok()?, name)
    }

    pub(super) fn group_members(name: &str) -> Option<Vec<String>> {
        find_group_members(&std::fs::read_to_string("/etc/group").ok()?, name)
    }

    pub(super) fn users_with_primary_gid(gid: u32) -> io::Result<Vec<String>> {
        // As before: an unreadable /etc/passwd lists no one.
        Ok(std::fs::read_to_string("/etc/passwd")
            .map(|t| find_primary_gid_users(&t, gid))
            .unwrap_or_default())
    }

    pub(super) fn create_system_group(name: &str) -> io::Result<()> {
        admin(&argv_create_group(name)?)
    }

    pub(super) fn create_system_user(name: &str, group: &str) -> io::Result<()> {
        admin(&argv_create_user(name, group)?)
    }

    pub(super) fn add_to_group(user: &str, group: &str) -> io::Result<()> {
        admin(&argv_add_to_group(user, group)?)
    }

    pub(super) fn delete_user(name: &str) -> io::Result<()> {
        admin(&argv_delete_user(name)?)
    }

    pub(super) fn delete_group(name: &str) -> io::Result<()> {
        admin(&argv_delete_group(name)?)
    }

    pub(super) fn remove_from_group(user: &str, group: &str) -> io::Result<()> {
        admin(&argv_remove_from_group(user, group)?)
    }
}

/// The account calls of [`RealHost`] on macOS: lookups through the
/// directory service (nix's safe `getpwnam_r` and `getgrnam_r`), changes
/// through `dscl` and `dseditgroup` on the local node.
#[cfg(target_os = "macos")]
mod accounts {
    use super::*;
    use nix::unistd::{Gid, Group, Uid, User};

    /// Runs one admin argv (the runner [`create_account`] is given).
    fn run_admin(argv: &[String]) -> io::Result<CmdOutput> {
        let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
        exec(&argv[0], &args, None, ADMIN_TIMEOUT)
    }

    /// Whether `record` (`/Users/x`, `/Groups/x`) is on the local node.
    fn local_record(record: &str) -> io::Result<bool> {
        dscl_read_found(run_admin(&argv_dscl_read(record)))
    }

    /// A saiife name (`_saiife…`) counts only as a local record: one only
    /// another directory node has reads as absent here, and creating it
    /// is then refused (see [`create_account`]).
    fn local_if_ours(name: &str, record: &str) -> bool {
        !name.starts_with(MACOS_DAEMON_USER) || local_record(record).unwrap_or(false)
    }

    pub(super) fn user(name: &str) -> Option<UserInfo> {
        let u = User::from_name(name).ok()??;
        if !local_if_ours(name, &format!("/Users/{name}")) {
            return None;
        }
        Some(UserInfo {
            uid: u.uid.as_raw(),
            gid: u.gid.as_raw(),
            home: u.dir,
            shell: u.shell.to_string_lossy().into_owned(),
        })
    }

    pub(super) fn group_id(name: &str) -> Option<u32> {
        let g = Group::from_name(name).ok()??;
        local_if_ours(name, &format!("/Groups/{name}")).then(|| g.gid.as_raw())
    }

    /// From the local node's record, so nested groups and GUID-only
    /// members show (see [`group_members_from`]).
    pub(super) fn group_members(name: &str) -> Option<Vec<String>> {
        if !valid_name(name) {
            return None;
        }
        group_members_from(run_admin(&argv_dscl_read(&format!("/Groups/{name}"))))
    }

    pub(super) fn users_with_primary_gid(gid: u32) -> io::Result<Vec<String>> {
        let argv = argv_dscl_search_gid(gid);
        let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
        primary_gid_users_from(exec(DSCL, &args, None, QUERY_TIMEOUT), gid)
    }

    /// Every uid and every gid of the local node, refused unless root's
    /// uid and wheel's gid are among them.
    fn taken_ids() -> io::Result<(BTreeSet<u32>, BTreeSet<u32>)> {
        let list = |path: &str, attr: &str| -> io::Result<BTreeSet<u32>> {
            let argv = owned(&[DSCL, ".", "-list", path, attr]);
            let out = run_admin(&argv)?;
            check_status(&argv, &out)?;
            Ok(parse_dscl_ids(&out.stdout))
        };
        let uids = list("/Users", "UniqueID")?;
        let gids = list("/Groups", "PrimaryGroupID")?;
        check_id_anchors(&uids, &gids)?;
        Ok((uids, gids))
    }

    /// An id some directory node (not only the local one) already gives a
    /// user or a group. A lookup error counts as taken.
    fn taken_elsewhere(id: u32) -> bool {
        !matches!(User::from_uid(Uid::from_raw(id)), Ok(None))
            || !matches!(Group::from_gid(Gid::from_raw(id)), Ok(None))
    }

    fn no_free_id() -> io::Error {
        io::Error::other(format!(
            "no free id in {}..={} for the saiife accounts: every one is taken by a user or a group",
            MACOS_ID_RANGE.start(),
            MACOS_ID_RANGE.end()
        ))
    }

    fn found_anywhere_user(name: &str) -> bool {
        !matches!(User::from_name(name), Ok(None))
    }

    fn found_anywhere_group(name: &str) -> bool {
        !matches!(Group::from_name(name), Ok(None))
    }

    pub(super) fn create_system_group(name: &str) -> io::Result<()> {
        check_names(&[name])?;
        create_account(
            &format!("/Groups/{name}"),
            found_anywhere_group(name),
            &mut run_admin,
            || {
                let (uids, gids) = taken_ids()?;
                let gid =
                    pick_free_id_avoiding(&uids, &gids, &taken_elsewhere).ok_or_else(no_free_id)?;
                Ok(argv_dscl_group(name, gid))
            },
        )
    }

    pub(super) fn create_system_user(name: &str, group: &str) -> io::Result<()> {
        check_names(&[name, group])?;
        let gid = group_id(group).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("group {group} does not exist"),
            )
        })?;
        create_account(
            &format!("/Users/{name}"),
            found_anywhere_user(name),
            &mut run_admin,
            || {
                let (uids, gids) = taken_ids()?;
                // The user's own primary gid is its group's: only the
                // uid must be free on other nodes.
                let uid = pick_user_id_avoiding(gid, &uids, &gids, &|id| {
                    !matches!(User::from_uid(Uid::from_raw(id)), Ok(None))
                })
                .ok_or_else(no_free_id)?;
                Ok(argv_dscl_user(name, uid, gid))
            },
        )
    }

    pub(super) fn add_to_group(user: &str, group: &str) -> io::Result<()> {
        admin(&argv_dseditgroup(true, user, group)?)
    }

    pub(super) fn delete_user(name: &str) -> io::Result<()> {
        admin(&argv_dscl_delete_user(name)?)
    }

    pub(super) fn delete_group(name: &str) -> io::Result<()> {
        admin(&argv_dscl_delete_group(name)?)
    }

    pub(super) fn remove_from_group(user: &str, group: &str) -> io::Result<()> {
        admin(&argv_dseditgroup(false, user, group)?)
    }
}

/// `systemd-detect-virt --container`'s answer. Exit 0 names the container;
/// `none` means none. Anything else (missing program, timeout, an error)
/// is [`CONTAINER_UNKNOWN`] on a systemd host, so the check fails closed;
/// without systemd the systemd check refuses anyway.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn container_from(res: io::Result<CmdOutput>, systemd_running: bool) -> Option<String> {
    if let Ok(out) = &res {
        let name = out.stdout.trim();
        if name == "none" {
            return None;
        }
        if out.status == 0 && !name.is_empty() {
            return Some(name.to_string());
        }
    }
    systemd_running.then(|| CONTAINER_UNKNOWN.to_string())
}

/// A user or group name safe to pass to the user tools:
/// `^[a-z_][a-z0-9_-]{0,31}$`. No option injection (`-`), no lists (`,`
/// for `usermod -aG`), no all-digit names (read as ids, `0` = root).
pub(crate) fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && matches!(b[0], b'a'..=b'z' | b'_')
        && b[1..]
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

fn check_names(names: &[&str]) -> io::Result<()> {
    match names.iter().find(|n| !valid_name(n)) {
        Some(bad) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid user or group name {bad:?}"),
        )),
        None => Ok(()),
    }
}

fn owned(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|s| s.to_string()).collect()
}

#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn argv_create_user(name: &str, group: &str) -> io::Result<Vec<String>> {
    check_names(&[name, group])?;
    Ok(owned(&[
        USERADD,
        "--system",
        "--no-create-home",
        "--home-dir",
        "/nonexistent",
        "--shell",
        "/usr/sbin/nologin",
        "--gid",
        group,
        name,
    ]))
}

#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn argv_create_group(name: &str) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    Ok(owned(&[GROUPADD, "--system", name]))
}

#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn argv_add_to_group(user: &str, group: &str) -> io::Result<Vec<String>> {
    check_names(&[user, group])?;
    Ok(owned(&[USERMOD, "-aG", group, user]))
}

#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn argv_delete_user(name: &str) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    Ok(owned(&[USERDEL, name]))
}

#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn argv_remove_from_group(user: &str, group: &str) -> io::Result<Vec<String>> {
    check_names(&[user, group])?;
    Ok(owned(&[GPASSWD, "-d", user, group]))
}

#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn argv_delete_group(name: &str) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    Ok(owned(&[GROUPDEL, name]))
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn argv_encrypt(name: &str, out: &Path) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    let out_s = out.to_str().filter(|_| out.is_absolute()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("credential path {} must be absolute UTF-8", out.display()),
        )
    })?;
    Ok(vec![
        SYSTEMD_CREDS.to_string(),
        "encrypt".to_string(),
        format!("--name={name}"),
        "-".to_string(),
        out_s.to_string(),
    ])
}

// ------------------------------------------------------------- macOS argv

/// The lowest id in [`MACOS_ID_RANGE`] that neither a user (`uids`) nor a
/// group (`gids`) has; `None` when the range is full.
pub fn pick_free_id(uids: &BTreeSet<u32>, gids: &BTreeSet<u32>) -> Option<u32> {
    pick_free_id_avoiding(uids, gids, &|_| false)
}

/// [`pick_free_id`], also skipping every id `elsewhere` says another
/// directory node already gives out.
pub fn pick_free_id_avoiding(
    uids: &BTreeSet<u32>,
    gids: &BTreeSet<u32>,
    elsewhere: &dyn Fn(u32) -> bool,
) -> Option<u32> {
    MACOS_ID_RANGE
        .clone()
        .find(|id| !uids.contains(id) && !gids.contains(id) && !elsewhere(*id))
}

/// The uid for a user whose primary group is `gid`: `gid` itself when it
/// lies in [`MACOS_ID_RANGE`] and no user has it, else [`pick_free_id`].
pub fn pick_user_id(gid: u32, uids: &BTreeSet<u32>, gids: &BTreeSet<u32>) -> Option<u32> {
    pick_user_id_avoiding(gid, uids, gids, &|_| false)
}

/// [`pick_user_id`], where `elsewhere` names the uids another directory
/// node already gives out.
pub fn pick_user_id_avoiding(
    gid: u32,
    uids: &BTreeSet<u32>,
    gids: &BTreeSet<u32>,
    elsewhere: &dyn Fn(u32) -> bool,
) -> Option<u32> {
    if MACOS_ID_RANGE.contains(&gid) && !uids.contains(&gid) && !elsewhere(gid) {
        Some(gid)
    } else {
        pick_free_id_avoiding(uids, gids, elsewhere)
    }
}

/// The local node's id lists must hold root's uid 0 and wheel's gid 0;
/// anything else is a listing that went wrong, and no id is picked from it.
pub fn check_id_anchors(uids: &BTreeSet<u32>, gids: &BTreeSet<u32>) -> io::Result<()> {
    if uids.contains(&0) && gids.contains(&0) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "could not read the local uids/gids (root's uid 0 or wheel's gid 0 is missing from dscl's list)",
        ))
    }
}

/// `dscl . -search /Users PrimaryGroupID <gid>`.
pub fn argv_dscl_search_gid(gid: u32) -> Vec<String> {
    owned(&[
        DSCL,
        ".",
        "-search",
        "/Users",
        "PrimaryGroupID",
        &gid.to_string(),
    ])
}

/// The users [`argv_dscl_search_gid`] found. A spawn error, a timeout or
/// a non-zero exit is an `Err`, never an empty list.
pub fn primary_gid_users_from(res: io::Result<CmdOutput>, gid: u32) -> io::Result<Vec<String>> {
    let out = res?;
    check_status(&argv_dscl_search_gid(gid), &out)?;
    Ok(parse_dscl_search(&out.stdout, gid))
}

/// `dscl . -read <record>`.
pub fn argv_dscl_read(record: &str) -> Vec<String> {
    owned(&[DSCL, ".", "-read", record])
}

/// What `dscl . -read <record>` says: exit 0 is found; a `-14136`
/// (`eDSRecordNotFound`) answer is absent; anything else (a timeout, a
/// spawn error, another failure) is an error, so callers fail closed.
pub fn dscl_read_found(res: io::Result<CmdOutput>) -> io::Result<bool> {
    let out = res?;
    if out.status == 0 {
        return Ok(true);
    }
    let said = |s: &str| out.stdout.contains(s) || out.stderr.contains(s);
    if said("eDSRecordNotFound") || said("-14136") {
        return Ok(false);
    }
    Err(io::Error::other(format!(
        "dscl -read failed (exit {}): {}",
        out.status,
        out.stderr.trim()
    )))
}

/// Creates the local record `record` (`/Users/x`, `/Groups/x`) with the
/// argv lists `steps` makes, each run through `run`.
///
/// - The record must be absent on the local node (`dscl . -read`): one
///   that exists is `AlreadyExists`, and nothing is created or deleted.
/// - `any_node` (the name resolves through the directory service) while
///   the local node lacks it means another node has it: refused.
/// - When a step after the first fails, the record this call made is
///   deleted again (best effort) and that failure returned. Only a record
///   this call created is ever deleted.
pub fn create_account(
    record: &str,
    any_node: bool,
    run: &mut dyn FnMut(&[String]) -> io::Result<CmdOutput>,
    steps: impl FnOnce() -> io::Result<Vec<Vec<String>>>,
) -> io::Result<()> {
    if dscl_read_found(run(&argv_dscl_read(record)))? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{record} already exists on the local node"),
        ));
    }
    if any_node {
        return Err(io::Error::other(format!(
            "{record} exists in a directory node other than the local one; \
             saiife needs its accounts local (remove that record or rename it first)"
        )));
    }
    let steps = steps()?;
    for (i, argv) in steps.iter().enumerate() {
        let res = run(argv).and_then(|out| check_status(argv, &out));
        if let Err(e) = res {
            if i > 0 {
                let _ = run(&owned(&[DSCL, ".", "-delete", record]));
            }
            return Err(e);
        }
    }
    Ok(())
}

/// The attributes of `dscl . -read` output: `Key: v1 v2` lines, or `Key:`
/// followed by indented value lines.
pub fn parse_dscl_attrs(out: &str) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in out.lines() {
        if line.starts_with(char::is_whitespace) {
            if let Some(k) = &current {
                map.entry(k.clone())
                    .or_default()
                    .extend(line.split_whitespace().map(str::to_string));
            }
            continue;
        }
        let (key, values) = if let Some(i) = line.find(": ") {
            (&line[..i], &line[i + 2..])
        } else if let Some(k) = line.strip_suffix(':') {
            (k, "")
        } else {
            current = None;
            continue;
        };
        current = Some(key.to_string());
        map.entry(key.to_string())
            .or_default()
            .extend(values.split_whitespace().map(str::to_string));
    }
    map
}

/// The members [`Host::group_members`] reports on macOS, from
/// `dscl . -read /Groups/<g>`: `None` when the group is absent. The
/// `GroupMembership` names, plus a `<…>` entry (never a user name) for
/// each nested group, for `GroupMembers` GUIDs beyond the named members,
/// and for a record that could not be read.
pub fn group_members_from(res: io::Result<CmdOutput>) -> Option<Vec<String>> {
    let out = match res {
        Ok(out) => out,
        Err(e) => return Some(vec![format!("<members unreadable: {e}>")]),
    };
    let stdout = out.stdout.clone();
    match dscl_read_found(Ok(out)) {
        Ok(false) => return None,
        Err(e) => return Some(vec![format!("<members unreadable: {e}>")]),
        Ok(true) => {}
    }
    let attrs = parse_dscl_attrs(&stdout);
    let get = |k: &str| attrs.get(k).cloned().unwrap_or_default();
    let mut members = get("GroupMembership");
    let named = members.len();
    let guids = get("GroupMembers").len();
    for n in get("NestedGroups") {
        members.push(format!("<nested group {n}>"));
    }
    if guids > named {
        members.push(format!(
            "<{} member(s) by GUID without a name>",
            guids - named
        ));
    }
    Some(members)
}

/// The ids of `dscl . -list /Users UniqueID` (or `/Groups PrimaryGroupID`):
/// one `name  id` per line. Lines without a numeric last word (and
/// negative ids such as nobody's -2) are skipped.
pub fn parse_dscl_ids(out: &str) -> BTreeSet<u32> {
    out.lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            let _name = words.next()?;
            digits_u32(words.next_back()?)
        })
        .collect()
}

/// The users of `dscl . -search /Users PrimaryGroupID <gid>` whose value
/// is `gid`. Each match is a `name<TAB><TAB>PrimaryGroupID = (` line,
/// then the values one per indented line, then `)`; a value on the same
/// line (`… = 20` or `… = ( 20 )`) is read as well.
pub fn parse_dscl_search(out: &str, gid: u32) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut current: Option<&str> = None;
    let has_gid = |text: &str| {
        text.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .any(|w| digits_u32(w) == Some(gid))
    };
    for line in out.lines() {
        let values = if line.starts_with(char::is_whitespace) || line.trim() == ")" {
            line
        } else {
            let (name, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            current = (!name.is_empty() && rest.contains('=')).then_some(name);
            rest.split_once('=').map_or("", |(_, v)| v)
        };
        if let Some(name) = current.filter(|_| has_gid(values)) {
            if !names.iter().any(|n| n == name) {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// `sw_vers -productVersion` (`15.1`, `26.0.1`) as (major, minor); a bare
/// major is `.0`.
pub fn parse_sw_vers(out: &str) -> io::Result<(u32, u32)> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{SW_VERS} printed no version: {:?}", out.trim()),
        )
    };
    let mut parts = out.trim().split('.');
    let major = parts.next().and_then(digits_u32).ok_or_else(bad)?;
    let minor = match parts.next() {
        None => 0,
        Some(m) => digits_u32(m).ok_or_else(bad)?,
    };
    Ok((major, minor))
}

/// A plain decimal number: ASCII digits only (no sign, no space).
fn digits_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn dscl_set(record: &str, attr: &str, value: &str) -> Vec<String> {
    owned(&[DSCL, ".", "-create", record, attr, value])
}

/// The `dscl` calls that make the hidden group `name` with `gid`. Callers
/// check the name first ([`valid_name`]).
pub fn argv_dscl_group(name: &str, gid: u32) -> Vec<Vec<String>> {
    let rec = format!("/Groups/{name}");
    vec![
        owned(&[DSCL, ".", "-create", &rec]),
        dscl_set(&rec, "PrimaryGroupID", &gid.to_string()),
        dscl_set(&rec, "RealName", name),
        dscl_set(&rec, "Password", "*"),
    ]
}

/// The `dscl` calls that make the hidden daemon user `name` (spec §5.3):
/// no password, shell `/usr/bin/false`, home `/var/empty`. Callers check
/// the name first ([`valid_name`]).
pub fn argv_dscl_user(name: &str, uid: u32, gid: u32) -> Vec<Vec<String>> {
    let rec = format!("/Users/{name}");
    vec![
        owned(&[DSCL, ".", "-create", &rec]),
        dscl_set(&rec, "UniqueID", &uid.to_string()),
        dscl_set(&rec, "PrimaryGroupID", &gid.to_string()),
        dscl_set(&rec, "UserShell", "/usr/bin/false"),
        dscl_set(&rec, "NFSHomeDirectory", "/var/empty"),
        dscl_set(&rec, "RealName", "saiife daemon"),
        dscl_set(&rec, "Password", "*"),
        dscl_set(&rec, "IsHidden", "1"),
    ]
}

/// `dseditgroup -o edit -a|-d <user> -t user <group>`: adds (`add`) or
/// removes a supplementary member.
pub fn argv_dseditgroup(add: bool, user: &str, group: &str) -> io::Result<Vec<String>> {
    check_names(&[user, group])?;
    Ok(owned(&[
        DSEDITGROUP,
        "-o",
        "edit",
        if add { "-a" } else { "-d" },
        user,
        "-t",
        "user",
        group,
    ]))
}

pub fn argv_dscl_delete_user(name: &str) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    Ok(owned(&[DSCL, ".", "-delete", &format!("/Users/{name}")]))
}

pub fn argv_dscl_delete_group(name: &str) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    Ok(owned(&[DSCL, ".", "-delete", &format!("/Groups/{name}")]))
}

// ----------------------------------------------------------- Windows argv

/// A name safe to give `net.exe`, which reads anything starting with `/` as a switch
/// and `-` as an option on other tools. Windows names may hold spaces and `\`
/// (`DOMAIN\name`), but never `/`.
pub fn valid_win_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && !name.chars().any(|c| c == '/' || c.is_control())
}

fn check_win_names(names: &[&str]) -> io::Result<()> {
    match names.iter().find(|n| !valid_win_name(n)) {
        Some(bad) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid user or group name {bad:?}"),
        )),
        None => Ok(()),
    }
}

/// `net.exe localgroup <name> /add`.
pub fn argv_net_create_group(name: &str) -> io::Result<Vec<String>> {
    check_win_names(&[name])?;
    Ok(owned(&[NET_EXE, "localgroup", name, "/add"]))
}

/// `net.exe localgroup <name> /delete`.
pub fn argv_net_delete_group(name: &str) -> io::Result<Vec<String>> {
    check_win_names(&[name])?;
    Ok(owned(&[NET_EXE, "localgroup", name, "/delete"]))
}

/// `net.exe localgroup <group> <user> /add`.
pub fn argv_net_add_member(user: &str, group: &str) -> io::Result<Vec<String>> {
    check_win_names(&[user, group])?;
    Ok(owned(&[NET_EXE, "localgroup", group, user, "/add"]))
}

/// `net.exe localgroup <group> <user> /delete`.
pub fn argv_net_remove_member(user: &str, group: &str) -> io::Result<Vec<String>> {
    check_win_names(&[user, group])?;
    Ok(owned(&[NET_EXE, "localgroup", group, user, "/delete"]))
}

/// `sc.exe sdset <service> <sddl>`.
pub fn argv_sc_sdset(service: &str, sddl: &str) -> io::Result<Vec<String>> {
    check_win_names(&[service])?;
    saiife_win::sddl::parse(sddl).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(owned(&[SC_EXE, "sdset", service, sddl]))
}

/// `sc.exe control <service> paramchange`.
pub fn argv_sc_paramchange(service: &str) -> io::Result<Vec<String>> {
    check_win_names(&[service])?;
    Ok(owned(&[SC_EXE, "control", service, "paramchange"]))
}

/// A Windows tool's result, by exit code only: its text is localized.
pub fn check_exit(argv: &[String], out: &CmdOutput) -> io::Result<()> {
    if out.status == 0 {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{} failed (exit {})",
        argv.join(" "),
        out.status
    )))
}

/// [`WinBuild`] from the registry's `CurrentBuildNumber` and `InstallationType`
/// (`Client`, `Server`, `Server Core`, `Nano Server`). A missing or unknown value is
/// an error, so the supported check fails closed.
pub fn parse_win_build(build: Option<String>, kind: Option<String>) -> io::Result<WinBuild> {
    let bad = |what: &str, v: &Option<String>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the registry's {what} is {v:?}"),
        )
    };
    let number = build
        .as_deref()
        .and_then(digits_u32)
        .ok_or_else(|| bad("CurrentBuildNumber", &build))?;
    let server = match kind.as_deref() {
        Some("Client") => false,
        Some(k) if k.contains("Server") => true,
        _ => return Err(bad("InstallationType", &kind)),
    };
    Ok(WinBuild {
        build: number,
        server,
    })
}

/// Runs an admin tool and turns a non-zero exit into an error.
#[cfg_attr(windows, allow(dead_code))]
fn admin(argv: &[String]) -> io::Result<()> {
    let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    let out = exec(&argv[0], &args, None, ADMIN_TIMEOUT)?;
    check_status(argv, &out)
}

#[cfg_attr(windows, allow(dead_code))]
fn check_status(argv: &[String], out: &CmdOutput) -> io::Result<()> {
    if out.status == 0 {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{} failed (exit {}): {}",
        argv.join(" "),
        out.status,
        out.stderr.trim()
    )))
}

/// The whole environment of a program Windows' [`RealHost`] runs, and its working
/// directory. Nothing is inherited. Doctor and install run elevated, and an agent running
/// as the admin's own user can set `HKCU\\Environment`, which the next shell inherits:
/// `PATH` decides what `net.exe` starts as `net1.exe`, `__COMPAT_LAYER` applies shims to any
/// program, and a dir the caller chose must not be where a program looks for a DLL.
pub const WINDOWS_CHILD_ENV: [(&str, &str); 8] = [
    ("SystemRoot", r"C:\Windows"),
    ("windir", r"C:\Windows"),
    ("SystemDrive", "C:"),
    ("Path", r"C:\Windows\System32;C:\Windows"),
    ("PATHEXT", ".COM;.EXE"),
    ("ComSpec", r"C:\Windows\System32\cmd.exe"),
    ("TEMP", r"C:\Windows\Temp"),
    ("TMP", r"C:\Windows\Temp"),
];
/// See [`WINDOWS_CHILD_ENV`].
pub const WINDOWS_CHILD_DIR: &str = r"C:\Windows\System32";

/// Spawns `program` (absolute) with `stdin` (or none), collects its output
/// and kills it after `timeout`. On Windows it inherits no environment and no working
/// directory: [`WINDOWS_CHILD_ENV`].
fn exec(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<CmdOutput> {
    exec_with(program, args, stdin, timeout, &[])
}

/// [`exec`] with the variables `remove_env` taken out of the program's
/// environment.
fn exec_with(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
    remove_env: &[&str],
) -> io::Result<CmdOutput> {
    if !Path::new(program).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{program}: programs run from an absolute path only"),
        ));
    }
    let mut cmd = Command::new(program);
    for v in remove_env {
        cmd.env_remove(v);
    }
    #[cfg(windows)]
    cmd.env_clear()
        .envs(WINDOWS_CHILD_ENV)
        .current_dir(WINDOWS_CHILD_DIR);
    let mut child = cmd
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => {
                io::Error::new(io::ErrorKind::NotFound, format!("{program} not found"))
            }
            k => io::Error::new(k, format!("{program}: {e}")),
        })?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // Written from its own thread, so a program that does not read its
        // input (or fills its output first) is still killed at the
        // deadline below; the write then ends with a broken pipe. The copy
        // is wiped when the thread ends: the input may be a secret.
        let bytes = zeroize::Zeroizing::new(bytes.to_vec());
        std::thread::spawn(move || {
            // A failed write shows as the program's own error below.
            let _ = pipe.write_all(&bytes);
        });
    }
    // Each pipe is read on its own thread: the first OUTPUT_CAP bytes are
    // kept, the rest drained so the program never blocks on a full pipe.
    let reader = |pipe: Option<Box<dyn Read + Send>>| {
        let buf = std::sync::Arc::new(Mutex::new(Vec::new()));
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let shared = buf.clone();
        std::thread::spawn(move || {
            if let Some(mut p) = pipe {
                let mut chunk = [0u8; 8192];
                loop {
                    match p.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut b = shared.lock().unwrap_or_else(|e| e.into_inner());
                            let room = OUTPUT_CAP.saturating_sub(b.len());
                            b.extend_from_slice(&chunk[..n.min(room)]);
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            }
            let _ = done_tx.send(());
        });
        (buf, done_rx)
    };
    let out_t = reader(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err_t = reader(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // The reader threads end when the last holder of the pipes exits.
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{program} did not finish within {} ms", timeout.as_millis()),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // A grandchild may keep the pipes open: wait for their end only a
    // little after the program itself exits.
    let collect = |(buf, done): (
        std::sync::Arc<Mutex<Vec<u8>>>,
        std::sync::mpsc::Receiver<()>,
    )| {
        let _ = done.recv_timeout(PIPE_GRACE);
        let b = buf.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&b).into_owned()
    };
    let stdout = collect(out_t);
    let stderr = collect(err_t);
    #[cfg(unix)]
    let code = status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        128 + status.signal().unwrap_or(0)
    });
    // On Windows every process has an exit code.
    #[cfg(windows)]
    let code = status.code().unwrap_or(-1);
    Ok(CmdOutput {
        status: code,
        stdout,
        stderr,
    })
}

/// The `N` of `systemctl --version`'s first line, `systemd N (…)`.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn parse_systemd_version(out: &str) -> Option<u32> {
    let mut words = out.lines().next()?.split_whitespace();
    if words.next()? != "systemd" {
        return None;
    }
    words.next()?.parse().ok()
}

/// The `name` entry of `/etc/passwd` text.
#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn find_passwd(text: &str, name: &str) -> Option<UserInfo> {
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 || f[0] != name {
            return None;
        }
        Some(UserInfo {
            uid: f[2].parse().ok()?,
            gid: f[3].parse().ok()?,
            home: PathBuf::from(f[5]),
            shell: f[6].to_string(),
        })
    })
}

/// The gid of `name` in `/etc/group` text.
#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn find_group(text: &str, name: &str) -> Option<u32> {
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 3 || f[0] != name {
            return None;
        }
        f[2].parse().ok()
    })
}

/// The member list of `name` in `/etc/group` text.
/// Names in `/etc/passwd` text whose primary gid (field 4) is `gid`.
#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn find_primary_gid_users(text: &str, gid: u32) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            (f.len() >= 7 && f[3].parse::<u32>().ok() == Some(gid)).then(|| f[0].to_string())
        })
        .collect()
}

#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(crate) fn find_group_members(text: &str, name: &str) -> Option<Vec<String>> {
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 || f[0] != name || f[2].parse::<u32>().is_err() {
            return None;
        }
        Some(
            f[3].split(',')
                .filter(|m| !m.is_empty())
                .map(str::to_string)
                .collect(),
        )
    })
}

// ---------------------------------------------------------------- FakeHost

const STATE_FILE: &str = ".fakehost.json";

/// The names install creates. In a [`FakeHost`] they exist only once
/// created; every other name resolves to the test user.
const CREATED_NAMES: [&str; 6] = [
    DAEMON_USER,
    DAEMON_GROUP,
    AUDIT_GROUP,
    MACOS_DAEMON_USER,
    MACOS_DAEMON_GROUP,
    MACOS_AUDIT_GROUP,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chown {
    pub path: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

/// What a [`FakeHost`] remembers, in `<root>/.fakehost.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FakeState {
    /// Default: this process's euid.
    pub euid: u32,
    /// Created or set users. A name not here resolves to the test user
    /// (`getuid()`/`getgid()`), except the names install creates.
    pub users: BTreeMap<String, UserInfo>,
    /// Created or set groups, by the same rule.
    pub groups: BTreeMap<String, u32>,
    /// Supplementary members added with `add_to_group`, by group.
    pub members: BTreeMap<String, Vec<String>>,
    /// Every chown, in order. None is applied.
    pub chowns: Vec<Chown>,
    /// Every `systemctl`, `launchctl`, `run`, `run_input` and
    /// `encrypt_credential` call, as one line. A `run_input` line ends
    /// `<stdin N bytes>`: the input's length, never its bytes.
    pub calls: Vec<String>,
    /// What `systemd_version` returns (default 255).
    pub systemd: u32,
    /// What `macos_version` returns (default 15.0).
    pub macos: (u32, u32),
    /// What `csrutil status` prints for `sip_enabled` (default: the plain
    /// "enabled." line); `None` fails the call.
    pub csrutil: Option<CmdOutput>,
    /// What `container` returns (default none).
    pub container: Option<String>,
    /// Canned outputs by call line (`"systemctl enable --now saiifed.service"`,
    /// `"/usr/bin/sudo -n true"`; for `run_input`, the line without its
    /// stdin note). A `run` or `run_input` without one exits 1 with no
    /// output; a `systemctl` or `launchctl` without one exits 0.
    pub run: BTreeMap<String, CmdOutput>,
    /// Paths whose `chown` fails (tests of a step failing part-way).
    pub fail_chown: Vec<PathBuf>,
    /// Gids whose `users_with_primary_gid` fails (a directory that could
    /// not be asked, as dscl failing on macOS).
    pub fail_primary_gid: Vec<u32>,
    /// Acts as macOS's local directory (default false): a created group or
    /// user gets an id from [`MACOS_ID_RANGE`] ([`pick_free_id`],
    /// [`pick_user_id`]), a user gets shell `/usr/bin/false` and home
    /// `/var/empty` and answers `dscl . -read /Users/<name>` as hidden, and
    /// every account change records its `dscl`/`dseditgroup` argv in
    /// `calls`.
    pub dscl: bool,
    /// What `policy_reload` answers (default: loaded, hash `fake`).
    pub policy_reload: ReloadAnswer,
    /// When set, `policy_reload` fails with this error instead.
    pub policy_reload_error: Option<String>,
    /// Acts as Windows' accounts (default false): names follow [`valid_win_name`],
    /// a created group gets a SID in `sids`, every group change records its `net.exe`
    /// argv in `calls`, and `create_system_user`, `delete_user` and `chown` are
    /// `Unsupported`, as on the real host.
    pub net: bool,
    /// What `get_sddl` reads: what was set or created, by path.
    pub sddl: BTreeMap<PathBuf, String>,
    /// What `lookup_sid` answers, by account name.
    pub sids: BTreeMap<String, String>,
    /// HKLM, by (key, value). The default holds a stock machine's folders.
    #[serde(with = "registry_entries")]
    pub registry: BTreeMap<(String, String), RegValue>,
    /// When set, `reg_value_present` fails with this error (access denied, say).
    pub reg_probe_error: Option<String>,
    /// What `windows_build` returns (default 26100, server).
    pub build: WinBuild,
    /// The services that exist, by name. `service` acts on `saiifed`.
    pub services: BTreeMap<String, ServiceSpec>,
    /// Whether `saiifed` is running.
    pub service_running: bool,
    /// The token holds `Administrators` but cannot use it (low integrity, or restricted
    /// SIDs): `elevated` answers false whatever `euid` says.
    pub limited_token: bool,
    /// Accounts that exist and are no local group: `lookup_local_group` refuses them.
    pub not_local_groups: Vec<String>,
    /// When set, `wait_for_pipe` fails with this error: the daemon never answered, or
    /// somebody else owns the pipe.
    pub pipe_error: Option<String>,
    /// `service` answers `Stop` with a timeout, and the service keeps running.
    pub service_will_not_stop: bool,
    /// What `local_groups_of` answers, by user (default: no groups).
    pub local_groups: BTreeMap<String, Vec<String>>,
    /// When set, `local_groups_of` fails with this error.
    pub local_groups_error: Option<String>,
    /// What `daemon_status` answers; `None` is a daemon that does not answer.
    pub daemon_status: Option<serde_json::Map<String, serde_json::Value>>,
    /// When set, `service_spec` fails with this error.
    pub service_spec_error: Option<String>,
    /// Paths whose `get_sddl` is access denied, as a plain user's is on `state`.
    pub sddl_denied: Vec<PathBuf>,
    /// `service_spec` is access denied.
    pub service_spec_denied: bool,
    /// `local_groups_of` is access denied.
    pub local_groups_denied: bool,
    /// When set, `service(Query)` fails with this error: the service manager cannot be
    /// asked.
    pub service_query_error: Option<String>,
    /// What `authenticode_status` answers; `None` fails the call.
    pub authenticode: Option<i32>,
    /// The SID `own_token` answers with; `None` is a token that cannot be read. Whether
    /// it is elevated is what `elevated` answers.
    pub own_sid: Option<String>,
}

/// JSON maps need string keys, so the registry is saved as a list.
mod registry_entries {
    use super::RegValue;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    type Map = BTreeMap<(String, String), RegValue>;

    pub fn serialize<S: Serializer>(map: &Map, out: S) -> Result<S::Ok, S::Error> {
        let list: Vec<(&(String, String), &RegValue)> = map.iter().collect();
        list.serialize(out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Map, D::Error> {
        let list = Vec::<((String, String), RegValue)>::deserialize(input)?;
        Ok(list.into_iter().collect())
    }
}

/// What a stock machine's registry holds for the folder check: `ProgramData` is
/// really stored with the variable.
fn stock_registry() -> BTreeMap<(String, String), RegValue> {
    use crate::supported::{REG_CURRENT_VERSION, REG_PROFILE_LIST};
    [
        (REG_CURRENT_VERSION, "ProgramFilesDir", r"C:\Program Files"),
        (
            REG_PROFILE_LIST,
            "ProgramData",
            r"%SystemDrive%\ProgramData",
        ),
        (REG_NT_CURRENT_VERSION, "SystemRoot", r"C:\Windows"),
    ]
    .into_iter()
    .map(|(k, v, d)| ((k.to_string(), v.to_string()), RegValue::Str(d.to_string())))
    .collect()
}

impl Default for FakeState {
    fn default() -> FakeState {
        FakeState {
            euid: own_euid(),
            users: BTreeMap::new(),
            groups: BTreeMap::new(),
            members: BTreeMap::new(),
            chowns: Vec::new(),
            calls: Vec::new(),
            systemd: 255,
            macos: (15, 0),
            csrutil: Some(CmdOutput {
                status: 0,
                stdout: format!("{}\n", crate::sip::SIP_ENABLED_LINE),
                stderr: String::new(),
            }),
            container: None,
            run: BTreeMap::new(),
            fail_chown: Vec::new(),
            fail_primary_gid: Vec::new(),
            dscl: false,
            policy_reload: ReloadAnswer {
                loaded: true,
                reason: String::new(),
                hash: Some("fake".into()),
            },
            policy_reload_error: None,
            net: false,
            sddl: BTreeMap::new(),
            sids: BTreeMap::new(),
            registry: stock_registry(),
            reg_probe_error: None,
            build: WinBuild {
                build: 26100,
                server: true,
            },
            services: BTreeMap::new(),
            service_running: false,
            limited_token: false,
            not_local_groups: Vec::new(),
            pipe_error: None,
            service_will_not_stop: false,
            local_groups: BTreeMap::new(),
            local_groups_error: None,
            daemon_status: None,
            service_spec_error: None,
            sddl_denied: Vec::new(),
            service_spec_denied: false,
            local_groups_denied: false,
            service_query_error: None,
            authenticode: None,
            own_sid: None,
        }
    }
}

/// What the fake's `dscl . -read /Users/<name>` prints for a user it made.
fn fake_dscl_read(uid: u32, gid: u32) -> String {
    format!(
        "IsHidden: 1\nNFSHomeDirectory: /var/empty\nPrimaryGroupID: {gid}\n\
         UniqueID: {uid}\nUserShell: /usr/bin/false\n"
    )
}

/// The call line of `dscl . -read /Users/<name>`.
pub(crate) fn dscl_read_line(name: &str) -> String {
    argv_dscl_read(&format!("/Users/{name}")).join(" ")
}

impl FakeState {
    fn taken_ids(&self) -> (BTreeSet<u32>, BTreeSet<u32>) {
        (
            self.users.values().map(|u| u.uid).collect(),
            self.groups.values().copied().collect(),
        )
    }

    fn record_argv(&mut self, argv: &[String]) {
        self.calls.push(argv.join(" "));
    }

    fn user(&self, name: &str) -> Option<UserInfo> {
        if let Some(u) = self.users.get(name) {
            return Some(u.clone());
        }
        if CREATED_NAMES.contains(&name) {
            return None;
        }
        Some(UserInfo {
            uid: own_uid(),
            gid: own_gid(),
            home: if name == "root" {
                PathBuf::from("/root")
            } else {
                PathBuf::from("/home").join(name)
            },
            shell: "/bin/bash".to_string(),
        })
    }

    fn group_id(&self, name: &str) -> Option<u32> {
        if let Some(g) = self.groups.get(name) {
            return Some(*g);
        }
        if CREATED_NAMES.contains(&name) {
            return None;
        }
        Some(own_gid())
    }

    fn check_names(&self, names: &[&str]) -> io::Result<()> {
        if self.net {
            check_win_names(names)
        } else {
            check_names(names)
        }
    }

    fn refuse_on_windows(&self) -> io::Result<()> {
        if self.net {
            Err(windows_only())
        } else {
            Ok(())
        }
    }
}

/// A host that records instead of acting. Its state survives across
/// processes, so a test can run the CLI with `--root` and then read what it
/// did.
#[derive(Debug)]
pub struct FakeHost {
    root: PathBuf,
    lock: Mutex<()>,
}

fn call_line(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

fn already(what: &str, name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("{what} {name} already exists"),
    )
}

/// What the real `set_sddl` refuses: a reparse point (here, a symlink), a file
/// with more than one hard link (here, on Unix), and a path whose handle really is
/// somewhere else (a link above the last component). A missing path is an error too.
fn refuse_like_windows(root: &Path, path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a reparse point", path.display()),
        ));
    }
    // Against the root's own resolved path, so a temp dir below a system link (macOS's
    // `/var`) is no redirect.
    let real = std::fs::canonicalize(path)?;
    let want = std::fs::canonicalize(root)?.join(path.strip_prefix(root).unwrap_or(path));
    if real != want {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is really {}: a reparse point is on the way",
                path.display(),
                real.display()
            ),
        ));
    }
    #[cfg(unix)]
    if meta.is_file() && std::os::unix::fs::MetadataExt::nlink(&meta) > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has more than one hard link", path.display()),
        ));
    }
    Ok(())
}

fn missing(what: &str, name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("{what} {name} does not exist"),
    )
}

impl FakeHost {
    /// Opens the fake host of `root`, creating `root` and a default state
    /// file when they are missing.
    pub fn open(root: &Path) -> io::Result<FakeHost> {
        std::fs::create_dir_all(root)?;
        // The same spelling as `Layout::under` gives its paths.
        let h = FakeHost::unopened(&std::fs::canonicalize(root)?);
        let state = h.load()?;
        if !h.state_path().exists() {
            h.save(&state)?;
        }
        Ok(h)
    }

    fn unopened(root: &Path) -> FakeHost {
        FakeHost {
            root: root.to_path_buf(),
            lock: Mutex::new(()),
        }
    }

    fn state_path(&self) -> PathBuf {
        self.root.join(STATE_FILE)
    }

    fn load(&self) -> io::Result<FakeState> {
        match std::fs::read(self.state_path()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", self.state_path().display()),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(FakeState::default()),
            Err(e) => Err(e),
        }
    }

    fn save(&self, s: &FakeState) -> io::Result<()> {
        let tmp = self
            .root
            .join(format!("{STATE_FILE}.tmp.{}", std::process::id()));
        let json = serde_json::to_vec_pretty(s).map_err(io::Error::other)?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, self.state_path())
    }

    /// Load, change, save, under the in-process lock.
    fn update<T>(&self, f: impl FnOnce(&mut FakeState) -> io::Result<T>) -> io::Result<T> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut s = self.load()?;
        let r = f(&mut s)?;
        self.save(&s)?;
        Ok(r)
    }

    fn read(&self) -> io::Result<FakeState> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        self.load()
    }

    /// The current state (for tests). Panics when the state file cannot be
    /// read.
    pub fn state(&self) -> FakeState {
        self.read()
            .unwrap_or_else(|e| panic!("fake host state: {e}"))
    }

    /// Changes the state (for tests). Panics when the state file cannot be
    /// read or written.
    pub fn set(&self, f: impl FnOnce(&mut FakeState)) {
        self.update(|s| {
            f(s);
            Ok(())
        })
        .unwrap_or_else(|e| panic!("fake host state: {e}"))
    }

    /// `path` lies below the root (lexically, no `..`).
    fn inside(&self, path: &Path) -> bool {
        path.starts_with(&self.root) && !path.components().any(|c| c == Component::ParentDir)
    }
}

impl Host for FakeHost {
    fn euid(&self) -> u32 {
        self.read().map(|s| s.euid).unwrap_or_else(|_| own_euid())
    }

    fn user(&self, name: &str) -> Option<UserInfo> {
        self.read().ok()?.user(name)
    }

    fn group_id(&self, name: &str) -> Option<u32> {
        self.read().ok()?.group_id(name)
    }

    fn users_with_primary_gid(&self, gid: u32) -> io::Result<Vec<String>> {
        let Ok(s) = self.read() else {
            return Ok(Vec::new());
        };
        if s.fail_primary_gid.contains(&gid) {
            return Err(io::Error::other(format!(
                "users of primary gid {gid}: fake failure"
            )));
        }
        Ok(s.users
            .iter()
            .filter(|(_, u)| u.gid == gid)
            .map(|(n, _)| n.clone())
            .collect())
    }

    fn group_members(&self, name: &str) -> Option<Vec<String>> {
        let s = self.read().ok()?;
        s.group_id(name)?;
        Some(s.members.get(name).cloned().unwrap_or_default())
    }

    fn create_system_group(&self, name: &str) -> io::Result<()> {
        self.update(|s| {
            s.check_names(&[name])?;
            if s.group_id(name).is_some() {
                return Err(already("group", name));
            }
            if s.net {
                s.record_argv(&argv_net_create_group(name)?);
                let sid = format!("S-1-5-21-1-2-3-{}", 1000 + s.sids.len());
                s.sids.insert(name.to_string(), sid);
            }
            if s.dscl {
                let (uids, gids) = s.taken_ids();
                let gid = pick_free_id(&uids, &gids)
                    .ok_or_else(|| io::Error::other("no free id in the macOS range"))?;
                for argv in argv_dscl_group(name, gid) {
                    s.record_argv(&argv);
                }
                s.groups.insert(name.to_string(), gid);
                return Ok(());
            }
            s.groups.insert(name.to_string(), own_gid());
            Ok(())
        })
    }

    fn create_system_user(&self, name: &str, group: &str) -> io::Result<()> {
        self.update(|s| {
            s.refuse_on_windows()?;
            s.check_names(&[name, group])?;
            if s.user(name).is_some() {
                return Err(already("user", name));
            }
            let gid = s.group_id(group).ok_or_else(|| missing("group", group))?;
            if s.dscl {
                let (uids, gids) = s.taken_ids();
                let uid = pick_user_id(gid, &uids, &gids)
                    .ok_or_else(|| io::Error::other("no free id in the macOS range"))?;
                for argv in argv_dscl_user(name, uid, gid) {
                    s.record_argv(&argv);
                }
                s.users.insert(
                    name.to_string(),
                    UserInfo {
                        uid,
                        gid,
                        home: PathBuf::from("/var/empty"),
                        shell: "/usr/bin/false".to_string(),
                    },
                );
                s.run.insert(
                    dscl_read_line(name),
                    CmdOutput {
                        status: 0,
                        stdout: fake_dscl_read(uid, gid),
                        stderr: String::new(),
                    },
                );
                return Ok(());
            }
            s.users.insert(
                name.to_string(),
                UserInfo {
                    uid: own_uid(),
                    gid,
                    home: PathBuf::from("/nonexistent"),
                    shell: "/usr/sbin/nologin".to_string(),
                },
            );
            Ok(())
        })
    }

    fn add_to_group(&self, user: &str, group: &str) -> io::Result<()> {
        self.update(|s| {
            s.check_names(&[user, group])?;
            s.user(user).ok_or_else(|| missing("user", user))?;
            s.group_id(group).ok_or_else(|| missing("group", group))?;
            if s.net {
                s.record_argv(&argv_net_add_member(user, group)?);
            }
            if s.dscl {
                s.record_argv(&argv_dseditgroup(true, user, group)?);
            }
            let m = s.members.entry(group.to_string()).or_default();
            if !m.iter().any(|u| u == user) {
                m.push(user.to_string());
            }
            Ok(())
        })
    }

    fn delete_user(&self, name: &str) -> io::Result<()> {
        self.update(|s| {
            s.refuse_on_windows()?;
            s.check_names(&[name])?;
            s.users.remove(name).ok_or_else(|| missing("user", name))?;
            if s.dscl {
                s.record_argv(&argv_dscl_delete_user(name)?);
                s.run.remove(&dscl_read_line(name));
            }
            for m in s.members.values_mut() {
                m.retain(|u| u != name);
            }
            Ok(())
        })
    }

    fn delete_group(&self, name: &str) -> io::Result<()> {
        self.update(|s| {
            s.check_names(&[name])?;
            s.groups
                .remove(name)
                .ok_or_else(|| missing("group", name))?;
            if s.net {
                s.record_argv(&argv_net_delete_group(name)?);
                s.sids.remove(name);
            }
            if s.dscl {
                s.record_argv(&argv_dscl_delete_group(name)?);
            }
            s.members.remove(name);
            Ok(())
        })
    }

    fn remove_from_group(&self, user: &str, group: &str) -> io::Result<()> {
        self.update(|s| {
            s.check_names(&[user, group])?;
            s.group_id(group).ok_or_else(|| missing("group", group))?;
            if s.net {
                s.record_argv(&argv_net_remove_member(user, group)?);
            }
            if s.dscl {
                s.record_argv(&argv_dseditgroup(false, user, group)?);
            }
            if let Some(m) = s.members.get_mut(group) {
                m.retain(|u| u != user);
            }
            Ok(())
        })
    }

    fn chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()> {
        // Like the real call: the path itself must exist (a symlink counts).
        std::fs::symlink_metadata(path)
            .map_err(|e| io::Error::new(e.kind(), format!("chown {}: {e}", path.display())))?;
        self.update(|s| {
            s.refuse_on_windows()?;
            if s.fail_chown.iter().any(|p| p == path) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("chown {}: fake failure", path.display()),
                ));
            }
            s.chowns.push(Chown {
                path: path.to_path_buf(),
                uid,
                gid,
            });
            Ok(())
        })
    }

    #[cfg(unix)]
    fn fchown(&self, fd: BorrowedFd<'_>, shown: &Path, uid: u32, gid: u32) -> io::Result<()> {
        // Like the real call: the descriptor must be open. Recorded under
        // `shown`, never applied.
        rustix::fs::fstat(fd).map_err(|e| {
            io::Error::new(
                io::Error::from(e).kind(),
                format!("chown {}: {e}", shown.display()),
            )
        })?;
        self.update(|s| {
            if s.fail_chown.iter().any(|p| p == shown) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("chown {}: fake failure", shown.display()),
                ));
            }
            s.chowns.push(Chown {
                path: shown.to_path_buf(),
                uid,
                gid,
            });
            Ok(())
        })?;
        // As XNU does, even for root: a chown clears the setuid and setgid
        // bits (only `fchown` callers, all macOS, reach this). So a mode set
        // before the chown is caught losing its setgid bit.
        let (_, mode, _) = crate::fsops::stat_owner_mode(&rustix::fs::fstat(fd)?);
        if mode & 0o6000 != 0 {
            rustix::fs::fchmod(fd, rustix::fs::Mode::from_raw_mode((mode & !0o6000) as _))?;
        }
        Ok(())
    }

    fn owner_uid(&self, path: &Path, on_disk: u32) -> u32 {
        self.read()
            .ok()
            .and_then(|s| {
                s.chowns
                    .iter()
                    .rev()
                    .find(|c| c.path == path)
                    .map(|c| c.uid)
            })
            .unwrap_or(on_disk)
    }

    fn policy_reload(
        &self,
        socket_dir: &Path,
        daemon_uid: u32,
        _wait: Duration,
    ) -> io::Result<ReloadAnswer> {
        let line = format!("ipc policy.reload {} {daemon_uid}", socket_dir.display());
        // The call is recorded even when it fails.
        let r = self.update(|s| {
            s.calls.push(line);
            Ok(match &s.policy_reload_error {
                Some(e) => Err(e.clone()),
                None => Ok(s.policy_reload.clone()),
            })
        })?;
        r.map_err(io::Error::other)
    }

    fn systemctl(&self, args: &[&str]) -> io::Result<CmdOutput> {
        let line = call_line("systemctl", args);
        self.update(|s| {
            let out = s.run.get(&line).cloned().unwrap_or_default();
            s.calls.push(line);
            Ok(out)
        })
    }

    fn systemd_version(&self) -> io::Result<u32> {
        Ok(self.read()?.systemd)
    }

    fn encrypt_credential(&self, name: &str, secret: &[u8], out: &Path) -> io::Result<()> {
        check_names(&[name])?;
        if !self.inside(out) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "fake host writes only below {}: {}",
                    self.root.display(),
                    out.display()
                ),
            ));
        }
        let line = format!("systemd-creds encrypt --name={name} - {}", out.display());
        let canned = self.update(|s| {
            let c = s.run.get(&line).cloned();
            s.calls.push(line.clone());
            Ok(c)
        })?;
        if let Some(c) = canned.filter(|c| c.status != 0) {
            return Err(io::Error::other(format!(
                "{line} failed (exit {}): {}",
                c.status,
                c.stderr.trim()
            )));
        }
        // Not the secret: a stand-in for the encrypted blob.
        let digest: String = Sha256::digest(secret)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let mut f = opts.open(out)?;
        writeln!(f, "saiife fake credential name={name} sha256={digest}")?;
        f.sync_all()
    }

    fn container(&self) -> Option<String> {
        self.read().ok()?.container
    }

    fn run(&self, program: &str, args: &[&str], _timeout: Duration) -> io::Result<CmdOutput> {
        let line = call_line(program, args);
        self.update(|s| {
            let out = s.run.get(&line).cloned().unwrap_or(CmdOutput {
                status: 1,
                stdout: String::new(),
                stderr: String::new(),
            });
            s.calls.push(line);
            Ok(out)
        })
    }

    fn launchctl(&self, args: &[&str]) -> io::Result<CmdOutput> {
        let line = call_line("launchctl", args);
        self.update(|s| {
            let out = s.run.get(&line).cloned().unwrap_or_default();
            s.calls.push(line);
            Ok(out)
        })
    }

    fn macos_version(&self) -> io::Result<(u32, u32)> {
        Ok(self.read()?.macos)
    }

    fn sip_enabled(&self) -> bool {
        // Not recorded in `calls`: doctor's read-only call lists stay as
        // they are. An unreadable state is "not enabled".
        self.read()
            .is_ok_and(|s| s.csrutil.as_ref().is_some_and(crate::sip::parse_status))
    }

    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        _timeout: Duration,
    ) -> io::Result<CmdOutput> {
        let line = call_line(program, args);
        self.update(|s| {
            let out = s.run.get(&line).cloned().unwrap_or(CmdOutput {
                status: 1,
                stdout: String::new(),
                stderr: String::new(),
            });
            // The length only: the input may be a secret.
            s.calls
                .push(format!("{line} <stdin {} bytes>", input.len()));
            Ok(out)
        })
    }

    fn set_sddl(&self, path: &Path, sddl: &str) -> io::Result<()> {
        self.fake_applies(path, sddl)?;
        refuse_like_windows(&self.root, path)?;
        self.update(|s| {
            s.calls.push(format!("set_sddl {} {sddl}", path.display()));
            s.sddl.insert(path.to_path_buf(), sddl.to_string());
            Ok(())
        })
    }

    fn get_sddl(&self, path: &Path) -> io::Result<String> {
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is a reparse point", path.display()),
            ));
        }
        self.update(|s| {
            s.calls.push(format!("get_sddl {}", path.display()));
            if s.sddl_denied.iter().any(|p| p == path) {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            s.sddl
                .get(path)
                .cloned()
                .ok_or_else(|| missing("descriptor of", &path.display().to_string()))
        })
    }

    fn create_dir_sddl(&self, path: &Path, sddl: &str) -> io::Result<()> {
        self.fake_applies(path, sddl)?;
        std::fs::create_dir(path)?;
        self.update(|s| {
            s.calls
                .push(format!("create_dir_sddl {} {sddl}", path.display()));
            s.sddl.insert(path.to_path_buf(), sddl.to_string());
            Ok(())
        })
    }

    fn lookup_sid(&self, name: &str) -> Option<String> {
        self.update(|s| {
            s.calls.push(format!("lookup_sid {name}"));
            Ok(s.sids.get(name).cloned())
        })
        .ok()?
    }

    fn reg_string(&self, key: &str, value: &str) -> Option<String> {
        self.update(|s| {
            s.calls.push(format!("reg_string {key} {value}"));
            Ok(
                match s.registry.get(&(key.to_string(), value.to_string())) {
                    Some(RegValue::Str(v)) => Some(v.clone()),
                    _ => None,
                },
            )
        })
        .ok()?
    }

    fn reg_dword(&self, key: &str, value: &str) -> Option<u32> {
        self.update(|s| {
            s.calls.push(format!("reg_dword {key} {value}"));
            Ok(
                match s.registry.get(&(key.to_string(), value.to_string())) {
                    Some(RegValue::Dword(v)) => Some(*v),
                    _ => None,
                },
            )
        })
        .ok()?
    }

    fn reg_value_present(&self, key: &str, value: &str) -> io::Result<bool> {
        self.update(|s| {
            s.calls.push(format!("reg_value_present {key} {value}"));
            match &s.reg_probe_error {
                Some(e) => Err(io::Error::other(e.clone())),
                None => Ok(s
                    .registry
                    .contains_key(&(key.to_string(), value.to_string()))),
            }
        })
    }

    fn windows_build(&self) -> io::Result<WinBuild> {
        self.update(|s| {
            s.calls.push("windows_build".to_string());
            Ok(s.build)
        })
    }

    fn service(&self, op: ServiceOp) -> io::Result<ServiceState> {
        use crate::layout::WIN_SERVICE;
        self.update(|s| {
            s.calls.push(match &op {
                ServiceOp::Query => "service query".to_string(),
                ServiceOp::Create(spec) => format!("service create {}", spec.fingerprint()),
                ServiceOp::Update(spec) => format!("service update {}", spec.fingerprint()),
                ServiceOp::Start => "service start".to_string(),
                ServiceOp::Stop { .. } => "service stop".to_string(),
                ServiceOp::Delete => "service delete".to_string(),
                ServiceOp::SetSddl(sddl) => format!("service sdset {sddl}"),
                ServiceOp::ParamChange => "service paramchange".to_string(),
            });
            if let (ServiceOp::Query, Some(e)) = (&op, &s.service_query_error) {
                return Err(io::Error::other(e.clone()));
            }
            let exists = s.services.contains_key(WIN_SERVICE);
            let gone = || missing("service", WIN_SERVICE);
            match op {
                ServiceOp::Query => {}
                ServiceOp::Create(spec) => {
                    if exists {
                        return Err(already("service", WIN_SERVICE));
                    }
                    s.services.insert(WIN_SERVICE.to_string(), spec);
                }
                ServiceOp::Update(spec) => {
                    if !exists {
                        return Err(gone());
                    }
                    s.services.insert(WIN_SERVICE.to_string(), spec);
                }
                ServiceOp::Start | ServiceOp::Stop { .. } | ServiceOp::ParamChange if !exists => {
                    return Err(gone());
                }
                ServiceOp::Start => s.service_running = true,
                ServiceOp::Stop { .. } if s.service_will_not_stop => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("{WIN_SERVICE} did not stop within 10 s"),
                    ));
                }
                ServiceOp::Stop { .. } => s.service_running = false,
                ServiceOp::ParamChange => {}
                ServiceOp::Delete => {
                    s.services.remove(WIN_SERVICE).ok_or_else(gone)?;
                    s.service_running = false;
                }
                ServiceOp::SetSddl(sddl) => {
                    s.services.get_mut(WIN_SERVICE).ok_or_else(gone)?.sddl = sddl;
                }
            }
            Ok(if !s.services.contains_key(WIN_SERVICE) {
                ServiceState::Missing
            } else if s.service_running {
                ServiceState::Running { pid: 4242 }
            } else {
                ServiceState::Stopped
            })
        })
    }

    fn elevated(&self) -> bool {
        let s = self.state();
        s.euid == 0 && !s.limited_token
    }

    fn lookup_local_group(&self, name: &str) -> io::Result<Option<String>> {
        self.update(|s| {
            s.calls.push(format!("lookup_local_group {name}"));
            if s.not_local_groups.iter().any(|n| n == name) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{name} is no local group"),
                ));
            }
            Ok(s.sids.get(name).cloned())
        })
    }

    fn hold_dir(&self, path: &Path) -> io::Result<Hold> {
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is a reparse point", path.display()),
            ));
        }
        self.update(|s| {
            s.calls.push(format!("hold {}", path.display()));
            Ok(())
        })?;
        Ok(Box::new(FakeDirHold {
            root: self.root.clone(),
            path: path.to_path_buf(),
        }))
    }

    fn lock_file(&self, path: &Path) -> io::Result<Option<Hold>> {
        // What the real open must get past first.
        saiife_win::open_rules::LOCK_FILE.check()?;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(_) => Ok(Some(Box::new(FakeLockHold(path.to_path_buf())))),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn claude_hklm_policy(&self) -> saiife_agents::claude::HklmPolicy {
        use saiife_agents::claude::{hklm_policy, HklmReadError};
        let s = self.state();
        hklm_policy(&|key, value| {
            match s.registry.get(&(key.to_string(), value.to_string())) {
                Some(RegValue::Str(v)) => Ok(Some(v.clone())),
                None => Ok(None),
                // A value of the wrong type: the real read fails too.
                Some(_) => Err(HklmReadError),
            }
        })
    }

    fn rename_file(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)?;
        self.update(|s| {
            if let Some(sddl) = s.sddl.remove(from) {
                s.sddl.insert(to.to_path_buf(), sddl);
            }
            Ok(())
        })
    }

    fn wait_for_pipe(&self, _wait: Duration) -> io::Result<()> {
        self.update(|s| {
            s.calls.push("wait_for_pipe".to_string());
            match &s.pipe_error {
                Some(e) => Err(io::Error::new(io::ErrorKind::TimedOut, e.clone())),
                None => Ok(()),
            }
        })
    }

    fn service_spec(&self) -> io::Result<Option<ServiceSpec>> {
        let s = self.state();
        if s.service_spec_denied {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        match s.service_spec_error {
            Some(e) => Err(io::Error::other(e)),
            None => Ok(s.services.get(crate::layout::WIN_SERVICE).cloned()),
        }
    }

    fn local_groups_of(&self, user: &str) -> io::Result<Vec<String>> {
        let s = self.state();
        if s.local_groups_denied {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        match s.local_groups_error {
            Some(e) => Err(io::Error::other(e)),
            None => Ok(s.local_groups.get(user).cloned().unwrap_or_default()),
        }
    }

    fn own_token(&self) -> io::Result<OwnToken> {
        let elevated = self.elevated();
        self.update(|s| {
            s.calls.push("own_token".to_string());
            let sid = s
                .own_sid
                .clone()
                .ok_or_else(|| io::Error::other("the token cannot be read"))?;
            Ok(OwnToken { sid, elevated })
        })
    }

    fn authenticode_status(&self, path: &Path) -> io::Result<i32> {
        self.update(|s| {
            s.calls.push(format!("authenticode {}", path.display()));
            s.authenticode
                .ok_or_else(|| io::Error::other("the trust provider did not answer"))
        })
    }

    fn daemon_status(
        &self,
        _wait: Duration,
    ) -> io::Result<serde_json::Map<String, serde_json::Value>> {
        self.state()
            .daemon_status
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "the daemon did not answer"))
    }
}

/// What the fake's [`Host::hold_dir`] returns: says so in `calls` when dropped.
struct FakeDirHold {
    root: PathBuf,
    path: PathBuf,
}

impl Drop for FakeDirHold {
    fn drop(&mut self) {
        let _ = FakeHost::unopened(&self.root).update(|s| {
            s.calls.push(format!("release {}", self.path.display()));
            Ok(())
        });
    }
}

/// What the fake's [`Host::lock_file`] returns: the file goes when dropped, as the real
/// one does when its handle closes.
struct FakeLockHold(PathBuf);

impl Drop for FakeLockHold {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl FakeHost {
    /// What the real calls refuse: a path outside the fake's tree, and a descriptor
    /// with no owner or no protection.
    fn fake_applies(&self, path: &Path, sddl: &str) -> io::Result<()> {
        if !self.inside(path) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "fake host writes only below {}: {}",
                    self.root.display(),
                    path.display()
                ),
            ));
        }
        saiife_win::sddl::check_settable(sddl)
            .map(|_| ())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }
}

#[cfg(test)]
mod windows_tests {
    use super::*;
    use crate::layout::Layout;
    use crate::winservice::ServiceSpec;

    fn fake() -> (tempfile::TempDir, FakeHost) {
        let dir = tempfile::tempdir().unwrap();
        let host = FakeHost::open(dir.path()).unwrap();
        (dir, host)
    }

    const SD: &str = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    #[test]
    fn fake_host_records_sddl_and_registry() {
        let (dir, host) = fake();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let made = root.join("made");
        host.create_dir_sddl(&made, SD).unwrap();
        assert!(made.is_dir());
        assert_eq!(host.get_sddl(&made).unwrap(), SD);
        assert!(host.create_dir_sddl(&made, SD).is_err());

        let other = "O:SYD:P(A;;FA;;;SY)";
        host.set_sddl(&made, other).unwrap();
        assert_eq!(host.get_sddl(&made).unwrap(), other);

        // As the real calls refuse them.
        assert!(host.set_sddl(&made, "D:P(A;;FA;;;SY)").is_err());
        assert!(host.set_sddl(&made, "O:BAD:(A;;FA;;;SY)").is_err());
        assert!(host.set_sddl(&root.join("missing"), SD).is_err());
        assert!(host.set_sddl(Path::new("/outside"), SD).is_err());
        assert!(host.get_sddl(&root.join("missing")).is_err());

        host.set(|s| {
            s.registry
                .insert(("K".into(), "dw".into()), RegValue::Dword(7));
            s.sids.insert("alice".into(), "S-1-5-21-9-9-9-1001".into());
        });
        assert_eq!(host.reg_dword("K", "dw"), Some(7));
        assert_eq!(host.reg_string("K", "dw"), None);
        assert_eq!(host.reg_dword("K", "none"), None);
        assert_eq!(
            host.lookup_sid("alice").as_deref(),
            Some("S-1-5-21-9-9-9-1001")
        );
        assert_eq!(host.lookup_sid("bob"), None);
        assert_eq!(
            host.windows_build().unwrap(),
            WinBuild {
                build: 26100,
                server: true
            }
        );

        let calls = host.state().calls;
        for line in [
            format!("create_dir_sddl {} {SD}", made.display()),
            format!("set_sddl {} {other}", made.display()),
            format!("get_sddl {}", made.display()),
            "reg_dword K dw".to_string(),
            "reg_string K dw".to_string(),
            "lookup_sid alice".to_string(),
            "windows_build".to_string(),
        ] {
            assert!(calls.contains(&line), "{line}: {calls:?}");
        }

        // All of it survives the state file, tuple keys included.
        let again = FakeHost::open(dir.path()).unwrap();
        assert_eq!(again.reg_dword("K", "dw"), Some(7));
        assert_eq!(again.get_sddl(&made).unwrap(), other);
    }

    /// The folders above ours, as a real machine prints them
    /// (`real_ancestors_pass_ancestor_ok` keeps reading them in CI). A refusal here would
    /// stop install on every stock machine.
    #[test]
    fn ancestor_ok_reads_the_printed_letters() {
        use crate::winacl::{ancestor_ok, protected_ok};
        use saiife_win::sddl::{parse, stock};
        for text in [stock::PROGRAM_DATA, stock::DRIVE_ROOT, stock::PROGRAM_FILES] {
            ancestor_ok(&parse(text).unwrap()).unwrap_or_else(|e| panic!("{text}: {e}"));
        }
        // Users may create entries there, so it is no fit for a path of ours.
        assert!(protected_ok(&parse(stock::PROGRAM_DATA).unwrap(), &[]).is_err());
        // What may not pass, in the same letters.
        for rights in ["DT", "SD", "WD", "WO", "GA", "GW"] {
            let text = format!("O:SYG:SYD:P(A;;FA;;;SY)(A;;{rights};;;BU)");
            assert!(ancestor_ok(&parse(&text).unwrap()).is_err(), "{rights}");
        }
    }

    #[test]
    fn net_localgroup_argv() {
        assert_eq!(
            argv_net_create_group("saiife-audit").unwrap(),
            [NET_EXE, "localgroup", "saiife-audit", "/add"]
        );
        assert_eq!(
            argv_net_delete_group("saiife-audit").unwrap(),
            [NET_EXE, "localgroup", "saiife-audit", "/delete"]
        );
        assert_eq!(
            argv_net_add_member(r"ACME\some user", "saiife-audit").unwrap(),
            [
                NET_EXE,
                "localgroup",
                "saiife-audit",
                r"ACME\some user",
                "/add"
            ]
        );
        assert_eq!(
            argv_net_remove_member("alice", "saiife-audit").unwrap(),
            [NET_EXE, "localgroup", "saiife-audit", "alice", "/delete"]
        );
        for bad in ["", "-x", "/delete", "a/b", "a\nb", "a\u{7f}"] {
            assert!(argv_net_create_group(bad).is_err(), "{bad:?}");
            assert!(argv_net_add_member(bad, "g").is_err(), "{bad:?}");
            assert!(argv_net_add_member("u", bad).is_err(), "{bad:?}");
        }
        for argv in [
            argv_net_create_group("g").unwrap(),
            argv_sc_sdset("saiifed", crate::layout::WIN_SERVICE_SDDL).unwrap(),
            argv_sc_paramchange("saiifed").unwrap(),
        ] {
            assert!(WIN_PROGRAMS.contains(&argv[0].as_str()), "{argv:?}");
        }
        assert!(argv_sc_sdset("saiifed", "not sddl").is_err());
    }

    /// A failing tool's text is localized, so an error never quotes it.
    #[test]
    fn check_exit_reads_the_code_only() {
        let argv = argv_net_create_group("g").unwrap();
        let out = |status: i32| CmdOutput {
            status,
            stdout: "Der Befehl ist fehlgeschlagen".into(),
            stderr: "Systemfehler 5".into(),
        };
        check_exit(&argv, &out(0)).unwrap();
        let text = check_exit(&argv, &out(2)).unwrap_err().to_string();
        assert!(text.contains("exit 2"), "{text}");
        assert!(
            !text.contains("Befehl") && !text.contains("Systemfehler"),
            "{text}"
        );
    }

    #[test]
    fn parse_win_build_reads_the_registry_values() {
        let s = |v: &str| Some(v.to_string());
        for (kind, server) in [
            ("Client", false),
            ("Server", true),
            ("Server Core", true),
            ("Nano Server", true),
        ] {
            assert_eq!(
                parse_win_build(s("22631"), s(kind)).unwrap(),
                WinBuild {
                    build: 22631,
                    server
                }
            );
        }
        assert!(parse_win_build(None, s("Client")).is_err());
        assert!(parse_win_build(s("22631"), None).is_err());
        assert!(parse_win_build(s("22631.1"), s("Client")).is_err());
        assert!(parse_win_build(s(""), s("Client")).is_err());
        assert!(parse_win_build(s("22631"), s("Something new")).is_err());
    }

    #[test]
    fn fake_net_mode_follows_windows() {
        let (dir, host) = fake();
        host.set(|s| s.net = true);
        host.create_system_group("saiife-audit").unwrap();
        let sid = host.lookup_sid("saiife-audit").unwrap();
        assert!(saiife_win::sid::valid_sid(&sid), "{sid}");
        host.add_to_group(r"ACME\some user", "saiife-audit")
            .unwrap();
        host.remove_from_group(r"ACME\some user", "saiife-audit")
            .unwrap();
        host.delete_group("saiife-audit").unwrap();
        assert_eq!(host.lookup_sid("saiife-audit"), None);
        let calls = host.state().calls;
        for line in [
            format!("{NET_EXE} localgroup saiife-audit /add"),
            format!(r"{NET_EXE} localgroup saiife-audit ACME\some user /add"),
            format!(r"{NET_EXE} localgroup saiife-audit ACME\some user /delete"),
            format!("{NET_EXE} localgroup saiife-audit /delete"),
        ] {
            assert!(calls.contains(&line), "{line}: {calls:?}");
        }
        for e in [
            host.create_system_user("u", "g").unwrap_err(),
            host.delete_user("u").unwrap_err(),
            host.chown(dir.path(), 1, 1).unwrap_err(),
        ] {
            assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        }
        assert!(host.create_system_group("/add").is_err());
    }

    #[test]
    fn fake_service_lifecycle() {
        let (dir, host) = fake();
        let spec = ServiceSpec::saiifed(&Layout::under(dir.path()));
        let wait = Duration::from_secs(1);
        assert_eq!(
            host.service(ServiceOp::Query).unwrap(),
            ServiceState::Missing
        );
        assert!(host.service(ServiceOp::Start).is_err());
        assert!(host.service(ServiceOp::Update(spec.clone())).is_err());
        assert!(host.service(ServiceOp::Delete).is_err());
        assert_eq!(
            host.service(ServiceOp::Create(spec.clone())).unwrap(),
            ServiceState::Stopped
        );
        assert!(host.service(ServiceOp::Create(spec.clone())).is_err());
        assert_eq!(
            host.service(ServiceOp::Start).unwrap(),
            ServiceState::Running { pid: 4242 }
        );
        host.service(ServiceOp::ParamChange).unwrap();
        host.service(ServiceOp::SetSddl("D:".into())).unwrap();
        assert_eq!(host.state().services["saiifed"].sddl, "D:");
        assert_eq!(
            host.service(ServiceOp::Stop { wait }).unwrap(),
            ServiceState::Stopped
        );
        assert_eq!(
            host.service(ServiceOp::Delete).unwrap(),
            ServiceState::Missing
        );
        let calls = host.state().calls;
        assert!(calls.contains(&format!("service create {}", spec.fingerprint())));
        assert!(calls.contains(&"service paramchange".to_string()));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn reload_answer_from_the_daemon_fields() {
        let m = |v: serde_json::Value| v.as_object().unwrap().clone();
        let a =
            ReloadAnswer::from_answer(&m(serde_json::json!({"result": "loaded", "hash": "h1"})));
        assert_eq!(
            a,
            ReloadAnswer {
                loaded: true,
                reason: String::new(),
                hash: Some("h1".into())
            }
        );
        let a = ReloadAnswer::from_answer(&m(
            serde_json::json!({"result": "rejected", "reason": "bad", "hash": "h0"}),
        ));
        assert!(!a.loaded);
        assert_eq!(a.reason, "bad");
        assert_eq!(a.hash.as_deref(), Some("h0"));
        let a = ReloadAnswer::from_answer(&m(serde_json::json!({})));
        assert!(!a.loaded);
        assert_eq!(a.reason, "no result in the answer");
    }

    /// A fake daemon on a socket in a temp dir: answers hello, then
    /// `policy.reload` with `answer`.
    #[cfg(target_os = "linux")]
    fn fake_daemon(
        dir: &Path,
        answer: serde_json::Value,
    ) -> std::thread::JoinHandle<serde_json::Map<String, serde_json::Value>> {
        use saiife_ipc::frame::{read_frame, write_frame};
        let l =
            std::os::unix::net::UnixListener::bind(dir.join(saiife_ipc::msg::SOCKET_NAME)).unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let h = read_frame(&mut s).unwrap();
            assert_eq!(h["op"], "hello");
            write_frame(
                &mut s,
                &serde_json::json!({"id": h["id"], "ok": true, "proto": 1}),
            )
            .unwrap();
            let req = read_frame(&mut s).unwrap();
            let mut a = answer.as_object().unwrap().clone();
            a.insert("id".into(), req["id"].clone());
            a.insert("ok".into(), true.into());
            write_frame(&mut s, &serde_json::Value::Object(a)).unwrap();
            req
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn policy_reload_over_the_socket() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let me = rustix::process::getuid().as_raw();
        let t = fake_daemon(
            d.path(),
            serde_json::json!({"result": "rejected", "reason": "scope conflict", "hash": "old"}),
        );
        let a = call_policy_reload(d.path(), me, Duration::from_secs(5)).unwrap();
        assert_eq!(t.join().unwrap()["op"], "policy.reload");
        assert!(!a.loaded);
        assert_eq!(a.reason, "scope conflict");
        assert_eq!(a.hash.as_deref(), Some("old"));
        fs::remove_file(d.path().join(saiife_ipc::msg::SOCKET_NAME)).unwrap();
        let t = fake_daemon(
            d.path(),
            serde_json::json!({"result": "loaded", "hash": "new"}),
        );
        let a = call_policy_reload(d.path(), me, Duration::from_secs(5)).unwrap();
        t.join().unwrap();
        assert!(a.loaded);
        assert_eq!(a.hash.as_deref(), Some("new"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn policy_reload_without_a_daemon_times_out() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let me = rustix::process::getuid().as_raw();
        let started = Instant::now();
        let e = call_policy_reload(d.path(), me, Duration::from_millis(600)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(e.to_string().contains("did not answer"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    fn own_ids() -> (u32, u32) {
        (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
    }

    #[test]
    fn fake_host_state_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert!(dir.path().join(".fakehost.json").is_file());
        h.set(|s| {
            s.systemd = 249;
            s.container = Some("podman".into());
        });
        h.create_system_group("saiife").unwrap();
        h.create_system_user("saiife", "saiife").unwrap();
        drop(h);
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.systemd_version().unwrap(), 249);
        assert_eq!(h.container().as_deref(), Some("podman"));
        let u = h.user("saiife").unwrap();
        assert_eq!(u.shell, "/usr/sbin/nologin");
        assert_eq!(u.home, PathBuf::from("/nonexistent"));
        assert!(h.group_id("saiife").is_some());
    }

    #[test]
    fn fake_host_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.systemd_version().unwrap(), 255);
        assert_eq!(h.container(), None);
        assert_eq!(h.euid(), rustix::process::geteuid().as_raw());
        let out = h
            .run("/usr/bin/sudo", &["-n", "true"], Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            out,
            CmdOutput {
                status: 1,
                stdout: String::new(),
                stderr: String::new()
            }
        );
    }

    #[test]
    fn fake_host_records_systemctl_calls() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.systemctl(&["daemon-reload"]).unwrap().status, 0);
        h.set(|s| {
            s.run.insert(
                "systemctl enable --now saiifed.service".into(),
                CmdOutput {
                    status: 1,
                    stdout: String::new(),
                    stderr: "boom".into(),
                },
            );
            s.run.insert(
                "/usr/bin/sudo -n true".into(),
                CmdOutput {
                    status: 0,
                    stdout: "ok\n".into(),
                    stderr: String::new(),
                },
            );
        });
        let out = h
            .systemctl(&["enable", "--now", "saiifed.service"])
            .unwrap();
        assert_eq!((out.status, out.stderr.as_str()), (1, "boom"));
        let out = h
            .run("/usr/bin/sudo", &["-n", "true"], Duration::from_secs(1))
            .unwrap();
        assert_eq!((out.status, out.stdout.as_str()), (0, "ok\n"));
        // Another process sees the same log.
        let again = FakeHost::open(dir.path()).unwrap();
        assert_eq!(
            again.state().calls,
            vec![
                "systemctl daemon-reload".to_string(),
                "systemctl enable --now saiifed.service".to_string(),
                "/usr/bin/sudo -n true".to_string(),
            ]
        );
    }

    #[test]
    fn fake_host_ids_default_to_own_uid() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        let (uid, gid) = own_ids();
        // Names saiife creates are absent until created.
        assert_eq!(h.user(DAEMON_USER), None);
        assert_eq!(h.group_id(DAEMON_GROUP), None);
        assert_eq!(h.group_id(AUDIT_GROUP), None);
        // Any other name resolves to the test user.
        let root = h.user("root").unwrap();
        assert_eq!((root.uid, root.gid), (uid, gid));
        assert_eq!(h.group_id("root"), Some(gid));
        assert_eq!(h.user("alice").unwrap().uid, uid);
        // Created names too.
        h.create_system_group(DAEMON_GROUP).unwrap();
        h.create_system_group(AUDIT_GROUP).unwrap();
        h.create_system_user(DAEMON_USER, DAEMON_GROUP).unwrap();
        h.add_to_group(DAEMON_USER, AUDIT_GROUP).unwrap();
        let u = h.user(DAEMON_USER).unwrap();
        assert_eq!((u.uid, u.gid), (uid, gid));
        assert_eq!(h.group_id(AUDIT_GROUP), Some(gid));
        assert_eq!(
            h.state().members[AUDIT_GROUP],
            vec![DAEMON_USER.to_string()]
        );
        // Tests can change them.
        h.set(|s| {
            s.users.get_mut("saiife").unwrap().uid = 1001;
            s.users.insert(
                "root".into(),
                UserInfo {
                    uid: uid + 1,
                    gid,
                    home: "/root".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        assert_eq!(h.user("saiife").unwrap().uid, 1001);
        assert_eq!(h.user("root").unwrap().uid, uid + 1);
        // Delete makes them absent again.
        h.delete_user(DAEMON_USER).unwrap();
        h.delete_group(AUDIT_GROUP).unwrap();
        assert_eq!(h.user(DAEMON_USER), None);
        assert_eq!(h.group_id(AUDIT_GROUP), None);
        // A second create of an existing name fails, like useradd.
        assert!(h.create_system_group(DAEMON_GROUP).is_err());
        // A user's primary group must exist (saiife-audit was deleted).
        assert!(h.create_system_user(DAEMON_USER, AUDIT_GROUP).is_err());
    }

    #[test]
    fn fake_chown_is_recorded_not_applied() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "x").unwrap();
        let before = fs::metadata(&f).unwrap();
        h.chown(&f, 0, 0).unwrap();
        let after = fs::metadata(&f).unwrap();
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
        assert_eq!(
            h.state().chowns,
            vec![Chown {
                path: f.clone(),
                uid: 0,
                gid: 0
            }]
        );
    }

    #[test]
    fn fake_encrypt_writes_under_root_only() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        // Spelled as `Layout::under` spells it: canonical (on macOS the temp
        // dir is below the /var -> /private/var symlink).
        let out = fs::canonicalize(dir.path()).unwrap().join("vault-key");
        h.encrypt_credential("vault-key", &[7u8; 32], &out).unwrap();
        let bytes = fs::read(&out).unwrap();
        assert!(!bytes.is_empty());
        assert!(
            !bytes.windows(32).any(|w| w == [7u8; 32]),
            "plain secret written"
        );
        assert!(h.state().calls[0].starts_with("systemd-creds encrypt --name=vault-key - "));
        let outside = tempfile::tempdir().unwrap();
        assert!(h
            .encrypt_credential("vault-key", b"k", &outside.path().join("k"))
            .is_err());
        assert!(!outside.path().join("k").exists());
    }

    #[test]
    fn host_kind_decision() {
        let tmp = Path::new("/home/u/t");
        assert_eq!(host_kind(Path::new("/"), 0), Ok(HostKind::Real));
        assert_eq!(host_kind(Path::new("/"), 1000), Ok(HostKind::Real));
        assert_eq!(host_kind(tmp, 1000), Ok(HostKind::Fake));
        let e = host_kind(tmp, 0).unwrap_err();
        assert!(e.contains("as root") && e.contains("/home/u/t"), "{e}");
    }

    #[test]
    fn host_for_refuses_an_unresolvable_root() {
        let dir = tempfile::tempdir().unwrap();
        let l = Layout::under(dir.path().join("missing/../../.."));
        assert!(host_for(&l).is_err());
    }

    #[test]
    fn names_follow_the_portable_pattern() {
        for ok in ["saiife", "saiife-audit", "_svc", "a", "u2", &"a".repeat(32)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "saiife-audit,docker",
            "0",
            "123",
            "Saiife",
            "-o",
            "",
            "a b",
            "a:b",
            "a/b",
            "1abc",
            &"a".repeat(33),
            "sa\u{e9}",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(argv_add_to_group("saiife", "saiife-audit,docker").is_err());
        assert!(argv_create_group("0").is_err());
    }

    #[test]
    fn fake_delete_validates_names() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        h.set(|s| {
            s.users.insert(
                "-r".into(),
                UserInfo {
                    uid: 1,
                    gid: 1,
                    home: "/".into(),
                    shell: "/bin/sh".into(),
                },
            );
            s.groups.insert("a,b".into(), 1);
        });
        assert_eq!(
            h.delete_user("-r").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            h.delete_group("a,b").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn container_detection_fails_closed() {
        let out = |status: i32, stdout: &str| -> io::Result<CmdOutput> {
            Ok(CmdOutput {
                status,
                stdout: stdout.into(),
                stderr: String::new(),
            })
        };
        assert_eq!(
            container_from(out(0, "docker\n"), true).as_deref(),
            Some("docker")
        );
        assert_eq!(container_from(out(1, "none\n"), true), None);
        let missing = || Err(io::Error::new(io::ErrorKind::NotFound, "x not found"));
        let timeout = || Err(io::Error::new(io::ErrorKind::TimedOut, "slow"));
        assert_eq!(
            container_from(missing(), true).as_deref(),
            Some(CONTAINER_UNKNOWN)
        );
        assert_eq!(
            container_from(timeout(), true).as_deref(),
            Some(CONTAINER_UNKNOWN)
        );
        assert_eq!(
            container_from(out(2, ""), true).as_deref(),
            Some(CONTAINER_UNKNOWN)
        );
        // Without systemd, the systemd check refuses anyway.
        assert_eq!(container_from(missing(), false), None);
    }

    #[test]
    fn host_for_picks_fake_under_a_root() {
        let dir = tempfile::tempdir().unwrap();
        let h = host_for(&Layout::under(dir.path())).unwrap();
        assert_eq!(h.systemd_version().unwrap(), 255);
        assert!(dir.path().join(".fakehost.json").is_file());
    }

    #[test]
    fn real_systemd_version_parses() {
        assert_eq!(
            parse_systemd_version("systemd 249 (249.11-0ubuntu3)\n+PAM +AUDIT -SELINUX\n"),
            Some(249)
        );
        assert_eq!(
            parse_systemd_version("systemd 255 (255.4-1ubuntu8)\n"),
            Some(255)
        );
        assert_eq!(parse_systemd_version("garbage"), None);
        assert_eq!(parse_systemd_version(""), None);
        assert_eq!(parse_systemd_version("systemd x (y)"), None);
    }

    #[test]
    fn real_argv_is_exact() {
        assert_eq!(
            argv_create_user("saiife", "saiife").unwrap(),
            [
                "/usr/sbin/useradd",
                "--system",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "--gid",
                "saiife",
                "saiife",
            ]
        );
        assert_eq!(
            argv_create_group("saiife-audit").unwrap(),
            ["/usr/sbin/groupadd", "--system", "saiife-audit"]
        );
        assert_eq!(
            argv_add_to_group("saiife", "saiife-audit").unwrap(),
            ["/usr/sbin/usermod", "-aG", "saiife-audit", "saiife"]
        );
        assert_eq!(
            argv_delete_user("saiife").unwrap(),
            ["/usr/sbin/userdel", "saiife"]
        );
        assert_eq!(
            argv_remove_from_group("saiife", "saiife-audit").unwrap(),
            ["/usr/bin/gpasswd", "-d", "saiife", "saiife-audit"]
        );
        assert!(argv_remove_from_group("saiife", "a,b").is_err());
        assert!(argv_remove_from_group("-r", "g").is_err());
        assert_eq!(
            argv_delete_group("saiife").unwrap(),
            ["/usr/sbin/groupdel", "saiife"]
        );
        assert_eq!(
            argv_encrypt("vault-key", Path::new("/etc/saiife/credstore/vault-key")).unwrap(),
            [
                "/usr/bin/systemd-creds",
                "encrypt",
                "--name=vault-key",
                "-",
                "/etc/saiife/credstore/vault-key",
            ]
        );
        assert_eq!(SYSTEMCTL, "/usr/bin/systemctl");
        assert_eq!(DETECT_VIRT, "/usr/bin/systemd-detect-virt");
        assert_eq!(GPASSWD, "/usr/bin/gpasswd");
        // Every argv this module builds starts with a listed program.
        let p = Path::new("/etc/saiife/credstore/vault-key");
        for argv in [
            argv_create_user("saiife", "saiife").unwrap(),
            argv_create_group("saiife").unwrap(),
            argv_add_to_group("saiife", "saiife-audit").unwrap(),
            argv_remove_from_group("saiife", "saiife-audit").unwrap(),
            argv_delete_user("saiife").unwrap(),
            argv_delete_group("saiife").unwrap(),
            argv_encrypt("vault-key", p).unwrap(),
        ] {
            assert!(PROGRAMS.contains(&argv[0].as_str()), "{argv:?}");
        }
        assert!(PROGRAMS.iter().all(|p| p.starts_with('/')));
    }

    #[test]
    fn real_argv_refuses_option_like_names() {
        assert!(argv_create_user("-o", "saiife").is_err());
        assert!(argv_create_user("saiife", "a b").is_err());
        assert!(argv_create_group("").is_err());
        assert!(argv_add_to_group("x:y", "g").is_err());
        assert!(argv_encrypt("--name", Path::new("/x")).is_err());
        assert!(argv_encrypt("vault-key", Path::new("relative")).is_err());
    }

    #[test]
    fn passwd_and_group_lines_parse() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nsaiife:x:998:997::/nonexistent:/usr/sbin/nologin\nbad\n";
        let u = find_passwd(passwd, "saiife").unwrap();
        assert_eq!(
            u,
            UserInfo {
                uid: 998,
                gid: 997,
                home: "/nonexistent".into(),
                shell: "/usr/sbin/nologin".into()
            }
        );
        assert_eq!(find_passwd(passwd, "nobody"), None);
        assert_eq!(
            find_group("root:x:0:\nsaiife-audit:x:996:saiife\n", "saiife-audit"),
            Some(996)
        );
        assert_eq!(find_group("root:x:0:\n", "saiife"), None);
        let group = "root:x:0:\nsaiife-audit:x:996:saiife,alice\nempty:x:5:\n";
        assert_eq!(
            find_group_members(group, "saiife-audit"),
            Some(vec!["saiife".to_string(), "alice".to_string()])
        );
        assert_eq!(find_group_members(group, "empty"), Some(vec![]));
        assert_eq!(find_group_members(group, "nogroup"), None);
    }

    #[test]
    fn fake_group_members_follow_add_to_group() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.group_members(AUDIT_GROUP), None);
        h.create_system_group(DAEMON_GROUP).unwrap();
        h.create_system_group(AUDIT_GROUP).unwrap();
        h.create_system_user(DAEMON_USER, DAEMON_GROUP).unwrap();
        assert_eq!(h.group_members(AUDIT_GROUP), Some(vec![]));
        h.add_to_group(DAEMON_USER, AUDIT_GROUP).unwrap();
        assert_eq!(
            h.group_members(AUDIT_GROUP),
            Some(vec![DAEMON_USER.to_string()])
        );
    }

    #[test]
    fn real_run_needs_an_absolute_program_and_names_a_missing_one() {
        let e = RealHost.run("ls", &[], Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = RealHost
            .run(
                "/nonexistent/saiife-no-such-program",
                &[],
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert!(
            e.to_string()
                .contains("/nonexistent/saiife-no-such-program"),
            "{e}"
        );
    }

    #[test]
    fn real_run_captures_output_and_times_out() {
        let out = RealHost
            .run(
                "/bin/sh",
                &["-c", "echo hi; echo err >&2; exit 3"],
                Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(
            out,
            CmdOutput {
                status: 3,
                stdout: "hi\n".into(),
                stderr: "err\n".into()
            }
        );
        let start = std::time::Instant::now();
        let e = RealHost
            .run("/bin/sh", &["-c", "sleep 5"], Duration::from_millis(200))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn primary_gid_users_parse_and_fake() {
        let passwd = "root:x:0:0::/root:/bin/bash\nsaiife:x:990:990::/nonexistent:/usr/sbin/nologin\nalice:x:1000:990::/home/alice:/bin/bash\nbad:x\n";
        assert_eq!(find_primary_gid_users(passwd, 990), ["saiife", "alice"]);
        assert!(find_primary_gid_users(passwd, 5).is_empty());
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        h.set(|s| {
            s.users.insert(
                "alice".into(),
                UserInfo {
                    uid: 1000,
                    gid: 990,
                    home: "/home/alice".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        assert_eq!(h.users_with_primary_gid(990).unwrap(), ["alice"]);
        assert!(h.users_with_primary_gid(991).unwrap().is_empty());
    }

    // ------------------------------------------------------------ macOS

    fn ids(v: impl IntoIterator<Item = u32>) -> BTreeSet<u32> {
        v.into_iter().collect()
    }

    #[test]
    fn sw_vers_parse() {
        assert_eq!(parse_sw_vers("15.1\n").unwrap(), (15, 1));
        assert_eq!(parse_sw_vers("26.0.1").unwrap(), (26, 0));
        assert_eq!(parse_sw_vers("15").unwrap(), (15, 0));
        for bad in ["x", "", "15.x", ".1", "-15.0"] {
            let e = parse_sw_vers(bad).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{bad}");
        }
    }

    #[test]
    fn pick_free_id_skips_users_and_groups() {
        assert_eq!(MACOS_ID_RANGE, 200..=400);
        assert_eq!(pick_free_id(&ids([]), &ids([])), Some(200));
        // A uid or a gid alone takes the id.
        assert_eq!(pick_free_id(&ids([200, 202]), &ids([201])), Some(203));
        assert_eq!(pick_free_id(&ids(200..=250), &ids(251..=300)), Some(301));
        // Ids outside the range do not matter.
        assert_eq!(pick_free_id(&ids([0, 1, 199, 501]), &ids([20])), Some(200));
        // The user takes the group's gid when no user has it...
        assert_eq!(pick_user_id(210, &ids([200]), &ids([210])), Some(210));
        // ...and a free id otherwise, or when the gid is outside the range.
        assert_eq!(pick_user_id(210, &ids([210]), &ids([200, 210])), Some(201));
        assert_eq!(pick_user_id(20, &ids([]), &ids([20])), Some(200));
    }

    #[test]
    fn pick_free_id_full_range_is_none() {
        assert_eq!(pick_free_id(&ids(200..=400), &ids([])), None);
        assert_eq!(pick_free_id(&ids([]), &ids(200..=400)), None);
        assert_eq!(pick_free_id(&ids(200..=300), &ids(301..=400)), None);
        assert_eq!(pick_user_id(500, &ids(200..=400), &ids([])), None);
        // One id left is found.
        assert_eq!(
            pick_free_id(&ids((200..=400).filter(|i| *i != 333)), &ids([])),
            Some(333)
        );
    }

    #[test]
    fn parse_dscl_ids() {
        let users = "_amavisd                 83\n_appleevents             55\nnobody                   -2\nroot                     0\njdoe                     501\n_saiife                  250\n\nbroken\n";
        assert_eq!(super::parse_dscl_ids(users), ids([0, 55, 83, 250, 501]));
        let groups = "_saiifeaudit\t251\nstaff\t20\nwheel\t0\n";
        assert_eq!(super::parse_dscl_ids(groups), ids([0, 20, 251]));
        assert!(super::parse_dscl_ids("").is_empty());
    }

    #[test]
    fn parse_dscl_search_reads_matching_users() {
        let out = "_saiife\t\tPrimaryGroupID = (\n    250\n)\nalice\t\tPrimaryGroupID = (\n    250\n)\nbob\t\tPrimaryGroupID = (\n    2500\n)\ncarol PrimaryGroupID = 250\n";
        assert_eq!(parse_dscl_search(out, 250), ["_saiife", "alice", "carol"]);
        assert_eq!(parse_dscl_search(out, 2500), ["bob"]);
        assert!(parse_dscl_search(out, 25).is_empty());
        assert!(parse_dscl_search("", 250).is_empty());
    }

    #[test]
    fn dscl_user_argv_is_hidden_with_false_shell() {
        let rec = |a: &[&str]| -> Vec<String> {
            [DSCL, "."]
                .iter()
                .chain(a.iter())
                .map(|s| s.to_string())
                .collect()
        };
        assert_eq!(
            argv_dscl_user("_saiife", 250, 251),
            vec![
                rec(&["-create", "/Users/_saiife"]),
                rec(&["-create", "/Users/_saiife", "UniqueID", "250"]),
                rec(&["-create", "/Users/_saiife", "PrimaryGroupID", "251"]),
                rec(&["-create", "/Users/_saiife", "UserShell", "/usr/bin/false"]),
                rec(&[
                    "-create",
                    "/Users/_saiife",
                    "NFSHomeDirectory",
                    "/var/empty"
                ]),
                rec(&["-create", "/Users/_saiife", "RealName", "saiife daemon"]),
                rec(&["-create", "/Users/_saiife", "Password", "*"]),
                rec(&["-create", "/Users/_saiife", "IsHidden", "1"]),
            ]
        );
        assert_eq!(
            argv_dscl_group("_saiifeaudit", 252),
            vec![
                rec(&["-create", "/Groups/_saiifeaudit"]),
                rec(&["-create", "/Groups/_saiifeaudit", "PrimaryGroupID", "252"]),
                rec(&[
                    "-create",
                    "/Groups/_saiifeaudit",
                    "RealName",
                    "_saiifeaudit"
                ]),
                rec(&["-create", "/Groups/_saiifeaudit", "Password", "*"]),
            ]
        );
        assert_eq!(
            argv_dseditgroup(true, "_saiife", "_saiifeaudit").unwrap(),
            [
                "/usr/sbin/dseditgroup",
                "-o",
                "edit",
                "-a",
                "_saiife",
                "-t",
                "user",
                "_saiifeaudit"
            ]
        );
        assert_eq!(
            argv_dseditgroup(false, "_saiife", "_saiifeaudit").unwrap()[3],
            "-d"
        );
        assert_eq!(
            argv_dscl_delete_user("_saiife").unwrap(),
            [DSCL, ".", "-delete", "/Users/_saiife"]
        );
        assert_eq!(
            argv_dscl_delete_group("_saiifeaudit").unwrap(),
            [DSCL, ".", "-delete", "/Groups/_saiifeaudit"]
        );
        assert!(argv_dseditgroup(true, "-a", "g").is_err());
        assert!(argv_dscl_delete_user("../x").is_err());
        assert!(argv_dscl_delete_group("a,b").is_err());
        // The macOS programs, all absolute and listed.
        assert_eq!(DSCL, "/usr/bin/dscl");
        assert_eq!(DSEDITGROUP, "/usr/sbin/dseditgroup");
        assert_eq!(LAUNCHCTL, "/bin/launchctl");
        assert_eq!(SW_VERS, "/usr/bin/sw_vers");
        assert_eq!(SECURITY, "/usr/bin/security");
        let mut all = argv_dscl_user("_saiife", 250, 250);
        all.extend(argv_dscl_group("_saiife", 250));
        all.push(argv_dseditgroup(true, "_saiife", "_saiifeaudit").unwrap());
        all.push(argv_dscl_delete_user("_saiife").unwrap());
        for argv in all {
            assert!(PROGRAMS.contains(&argv[0].as_str()), "{argv:?}");
        }
        for p in [LAUNCHCTL, SW_VERS, SECURITY] {
            assert!(PROGRAMS.contains(&p));
        }
    }

    #[test]
    fn fake_host_records_launchctl_and_run_input() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.macos_version().unwrap(), (15, 0));
        h.set(|s| s.macos = (26, 1));
        assert_eq!(h.macos_version().unwrap(), (26, 1));
        // launchctl answers 0 unless canned, as systemctl does.
        assert_eq!(
            h.launchctl(&["print", "system/com.saiife.saiifed"])
                .unwrap()
                .status,
            0
        );
        h.set(|s| {
            s.run.insert(
                "launchctl bootstrap system /x.plist".into(),
                CmdOutput {
                    status: 5,
                    stdout: String::new(),
                    stderr: "Bootstrap failed: 5".into(),
                },
            );
            s.run.insert(
                "/usr/bin/security authorizationdb write com.saiife.approve".into(),
                CmdOutput {
                    status: 0,
                    stdout: String::new(),
                    stderr: "YES (0)\n".into(),
                },
            );
        });
        let out = h.launchctl(&["bootstrap", "system", "/x.plist"]).unwrap();
        assert_eq!(
            (out.status, out.stderr.as_str()),
            (5, "Bootstrap failed: 5")
        );
        let secret = concat!("not-", "a-secret-", "plist-body");
        let out = h
            .run_input(
                SECURITY,
                &["authorizationdb", "write", "com.saiife.approve"],
                secret.as_bytes(),
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(out.status, 0);
        // Not canned: exits 1, as `run` does.
        let out = h
            .run_input(SECURITY, &["x"], b"", Duration::from_secs(1))
            .unwrap();
        assert_eq!(out.status, 1);
        let again = FakeHost::open(dir.path()).unwrap();
        assert_eq!(
            again.state().calls,
            vec![
                "launchctl print system/com.saiife.saiifed".to_string(),
                "launchctl bootstrap system /x.plist".to_string(),
                format!(
                    "/usr/bin/security authorizationdb write com.saiife.approve <stdin {} bytes>",
                    secret.len()
                ),
                "/usr/bin/security x <stdin 0 bytes>".to_string(),
            ]
        );
        // The input's bytes are nowhere in the state file.
        let state = fs::read_to_string(dir.path().join(".fakehost.json")).unwrap();
        assert!(!state.contains(secret));
    }

    #[test]
    fn macos_names_are_valid() {
        for n in [MACOS_DAEMON_USER, MACOS_DAEMON_GROUP, MACOS_AUDIT_GROUP] {
            assert!(valid_name(n), "{n}");
        }
        assert!(valid_name("_saiife") && valid_name("_saiifeaudit"));
        // The fake treats them as names install creates: absent until made.
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.user("_saiife"), None);
        assert_eq!(h.group_id("_saiife"), None);
        assert_eq!(h.group_id("_saiifeaudit"), None);
        h.create_system_group("_saiife").unwrap();
        h.create_system_user("_saiife", "_saiife").unwrap();
        assert!(h.user("_saiife").is_some());
    }

    #[test]
    fn real_run_input_writes_stdin() {
        let out = RealHost
            .run_input("/bin/cat", &[], b"abc", Duration::from_secs(5))
            .unwrap();
        assert_eq!((out.status, out.stdout.as_str()), (0, "abc"));
        let e = RealHost
            .run_input("cat", &[], b"abc", Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn old_fake_state_files_get_the_macos_default() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".fakehost.json"), r#"{"systemd": 250}"#).unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.macos_version().unwrap(), (15, 0));
        assert_eq!(h.systemd_version().unwrap(), 250);
    }

    // ------------------------------------------------ fix round 1 (macOS)

    fn out(status: i32, stdout: &str, stderr: &str) -> io::Result<CmdOutput> {
        Ok(CmdOutput {
            status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        })
    }

    const NOT_FOUND: &str = "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)";

    #[test]
    fn primary_gid_users_fail_closed() {
        let found = "alice\t\tPrimaryGroupID = (\n    250\n)\n";
        assert_eq!(
            primary_gid_users_from(out(0, found, ""), 250).unwrap(),
            ["alice"]
        );
        assert!(primary_gid_users_from(out(0, "", ""), 250)
            .unwrap()
            .is_empty());
        // A failed, timed-out or missing dscl is an error, never "no one".
        assert!(primary_gid_users_from(out(1, found, "boom"), 250).is_err());
        let timeout = Err(io::Error::new(io::ErrorKind::TimedOut, "slow"));
        assert_eq!(
            primary_gid_users_from(timeout, 250).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            argv_dscl_search_gid(250),
            [DSCL, ".", "-search", "/Users", "PrimaryGroupID", "250"]
        );
    }

    #[test]
    fn dscl_read_found_is_three_way() {
        assert!(dscl_read_found(out(0, "RecordName: _saiife\n", "")).unwrap());
        assert!(!dscl_read_found(out(56, "", NOT_FOUND)).unwrap());
        assert!(!dscl_read_found(out(56, "eDSRecordNotFound", "")).unwrap());
        // Any other failure cannot tell: an error.
        assert!(dscl_read_found(out(1, "", "eDSPermissionError")).is_err());
        assert!(dscl_read_found(Err(io::Error::new(io::ErrorKind::TimedOut, "t"))).is_err());
        assert_eq!(
            argv_dscl_read("/Users/_saiife"),
            [DSCL, ".", "-read", "/Users/_saiife"]
        );
    }

    /// Runs [`create_account`] with a scripted runner: `answer` gives each
    /// call's output by its argv. Returns the result, the calls made, and
    /// whether the steps were asked for.
    fn drive(
        any_node: bool,
        answer: impl Fn(&[String]) -> io::Result<CmdOutput>,
    ) -> (io::Result<()>, Vec<String>, bool) {
        let mut calls = Vec::new();
        let mut asked = false;
        let res = create_account(
            "/Users/_saiife",
            any_node,
            &mut |argv: &[String]| {
                calls.push(argv[1..].join(" "));
                answer(argv)
            },
            || {
                asked = true;
                Ok(argv_dscl_user("_saiife", 250, 250))
            },
        );
        (res, calls, asked)
    }

    fn is_read(argv: &[String]) -> bool {
        argv.get(2).map(String::as_str) == Some("-read")
    }

    #[test]
    fn existing_record_is_never_created_or_deleted() {
        let (res, calls, asked) = drive(false, |_| out(0, "RecordName: _saiife\n", ""));
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(calls, [". -read /Users/_saiife"]);
        assert!(!asked, "no id is picked for an existing record");
        assert!(!calls
            .iter()
            .any(|c| c.contains("-create") || c.contains("-delete")));
    }

    #[test]
    fn unreadable_or_foreign_record_is_refused_before_any_create() {
        // dscl -read failed in a way that is not "not found".
        let (res, calls, asked) = drive(false, |_| out(1, "", "eDSPermissionError"));
        assert!(res.is_err());
        assert_eq!(calls, [". -read /Users/_saiife"]);
        assert!(!asked);
        // Not local, but the directory service resolves the name.
        let (res, calls, asked) = drive(true, |_| out(56, "", NOT_FOUND));
        let e = res.unwrap_err();
        assert!(e.to_string().contains("other than the local one"), "{e}");
        assert_eq!(calls, [". -read /Users/_saiife"]);
        assert!(!asked);
    }

    #[test]
    fn create_account_rolls_back_only_its_own_record() {
        // All steps pass: read, then the eight creates, no delete.
        let (res, calls, asked) = drive(false, |a| {
            if is_read(a) {
                out(56, "", NOT_FOUND)
            } else {
                out(0, "", "")
            }
        });
        res.unwrap();
        assert!(asked);
        assert_eq!(calls.len(), 1 + 8);
        assert!(!calls.iter().any(|c| c.contains("-delete")));
        // The record was made, then a later step failed: deleted again.
        let (res, calls, _) = drive(false, |a| {
            if is_read(a) {
                out(56, "", NOT_FOUND)
            } else if a.iter().any(|w| w == "UserShell") {
                out(1, "", "boom")
            } else {
                out(0, "", "")
            }
        });
        assert!(res.is_err());
        assert_eq!(calls.last().unwrap(), ". -delete /Users/_saiife");
        // The first create failed: nothing of ours to delete.
        let (res, calls, _) = drive(false, |a| {
            if is_read(a) {
                out(56, "", NOT_FOUND)
            } else {
                out(1, "", "boom")
            }
        });
        assert!(res.is_err());
        assert_eq!(
            calls,
            [". -read /Users/_saiife", ". -create /Users/_saiife"]
        );
    }

    #[test]
    fn id_lists_need_root_and_wheel() {
        check_id_anchors(&ids([0, 250]), &ids([0, 20])).unwrap();
        for (u, g) in [
            (ids([]), ids([])),
            (ids([250]), ids([0])),
            (ids([0]), ids([20])),
        ] {
            let e = check_id_anchors(&u, &g).unwrap_err();
            assert!(
                e.to_string().contains("could not read the local uids/gids"),
                "{e}"
            );
        }
    }

    #[test]
    fn ids_taken_on_other_nodes_are_skipped() {
        let elsewhere = |id: u32| id == 200 || id == 201;
        assert_eq!(
            pick_free_id_avoiding(&ids([]), &ids([202]), &elsewhere),
            Some(203)
        );
        assert_eq!(pick_free_id_avoiding(&ids([]), &ids([]), &|_| true), None);
        // The group's gid is not reused as uid when another node has it.
        assert_eq!(
            pick_user_id_avoiding(201, &ids([0]), &ids([0, 201]), &elsewhere),
            Some(202)
        );
        assert_eq!(
            pick_user_id_avoiding(205, &ids([0]), &ids([0, 205]), &elsewhere),
            Some(205)
        );
    }

    #[test]
    fn group_members_flag_nested_and_guid_members() {
        let plain = "GroupMembership: _saiife alice\nGroupMembers: A-1 B-2\nPrimaryGroupID: 251\nRecordName: _saiifeaudit\n";
        assert_eq!(
            group_members_from(out(0, plain, "")).unwrap(),
            ["_saiife", "alice"]
        );
        let nested =
            "GroupMembership: _saiife\nGroupMembers: A-1\nNestedGroups: ABCD-EF\nRecordName: g\n";
        let m = group_members_from(out(0, nested, "")).unwrap();
        assert_eq!(m, ["_saiife", "<nested group ABCD-EF>"]);
        let guid_only = "GroupMembership: _saiife\nGroupMembers:\n A-1\n B-2\n C-3\n";
        let m = group_members_from(out(0, guid_only, "")).unwrap();
        assert_eq!(m, ["_saiife", "<2 member(s) by GUID without a name>"]);
        // None of the markers can be a user name.
        assert!(m.iter().skip(1).all(|n| !valid_name(n)));
        // Absent group; unreadable record (refused by "no other members").
        assert_eq!(group_members_from(out(56, "", NOT_FOUND)), None);
        let m = group_members_from(out(1, "", "eDSPermissionError")).unwrap();
        assert!(
            m.len() == 1 && m[0].starts_with("<members unreadable"),
            "{m:?}"
        );
        let m = group_members_from(Err(io::Error::new(io::ErrorKind::TimedOut, "t"))).unwrap();
        assert!(m[0].starts_with("<members unreadable"));
        // No members at all.
        assert_eq!(
            group_members_from(out(0, "RecordName: g\n", "")).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn dscl_attrs_parse() {
        let a = parse_dscl_attrs(
            "dsAttrTypeNative:foo: x\nGroupMembership: a b\nRealName:\n saiife audit\nbare line\n",
        );
        assert_eq!(a["GroupMembership"], ["a", "b"]);
        assert_eq!(a["RealName"], ["saiife", "audit"]);
        assert_eq!(a["dsAttrTypeNative:foo"], ["x"]);
        assert!(!a.contains_key("bare line"));
    }

    #[test]
    fn version_and_id_parts_are_plain_digits() {
        for bad in ["+15.0", "15.+1", " 15.0x", "15. 1", "１５.0"] {
            assert!(parse_sw_vers(bad).is_err(), "{bad}");
        }
        assert_eq!(super::parse_dscl_ids("a +5\nb 7\n"), ids([7]));
        assert!(parse_dscl_search("a PrimaryGroupID = +20\n", 20).is_empty());
    }

    #[test]
    fn real_run_input_large_input_meets_the_deadline() {
        // A program that never reads 1 MiB of input is still killed at the
        // deadline (the write is on its own thread).
        let big = vec![b'x'; 1 << 20];
        let start = std::time::Instant::now();
        let e = RealHost
            .run_input(
                "/bin/sh",
                &["-c", "sleep 5"],
                &big,
                Duration::from_millis(300),
            )
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
        // One that echoes it does not deadlock on its full output pipe.
        let out = RealHost
            .run_input("/bin/cat", &[], &big, Duration::from_secs(20))
            .unwrap();
        assert_eq!(out.status, 0);
        assert_eq!(out.stdout.len(), OUTPUT_CAP);
    }

    #[test]
    fn exec_with_removes_variables() {
        // env(1) prints its environment as given (a shell would add PATH).
        let env = |remove: &[&str]| {
            exec_with("/usr/bin/env", &[], None, Duration::from_secs(5), remove)
                .unwrap()
                .stdout
        };
        let has_path = |s: &str| s.lines().any(|l| l.starts_with("PATH="));
        assert!(has_path(&env(&[])), "the test runs with PATH set");
        assert!(!has_path(&env(&["PATH"])));
    }
}
