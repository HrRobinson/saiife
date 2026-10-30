//! `saiife system install` (spec §7): users and groups, the binary under
//! `/opt/saiife`, `/etc/saiife`, the vault key, the unit, the managed hooks,
//! `installed.toml`, then the daemon is started.
//!
//! Every step is idempotent. Whatever a step creates is recorded in
//! `installed.toml` before the next step runs, so a failure part-way leaves
//! an accurate list for `uninstall`.

use crate::authright;
use crate::default_config::default_config;
use crate::fsops;
use crate::host::{valid_name, Host, DSCL, SECURITY};
use crate::launchd;
use crate::layout::*;
use crate::polkit::polkit_present;
use crate::supported::{check_supported, Support};
use crate::unit::{unit_text, vault_key_mode};
use saiife_agents::{claude, codex, gemini, Agent, AgentError, Change};
use saiife_policy::installed::{
    read_installed, write_installed, FileKind, Installed, InstalledFile, ManagedAgent, Membership,
    VaultKeyMode, INSTALLED_VERSION,
};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub struct InstallOptions {
    pub config: Option<PathBuf>,
    pub agents: Vec<Agent>,
    pub approvers: Vec<String>,
    pub non_interactive: bool,
    /// Install a dynamic or debug-assertions build on the real system
    /// (the CI job `locked-linux` only; never for production).
    pub allow_test_build: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallReport {
    /// What this run created or changed (user, group and path names).
    pub changed: Vec<String>,
    /// What was already as it should be.
    pub unchanged: Vec<String>,
    pub started: bool,
    /// Said but not refused: a test build under `--root` or with
    /// `--allow-test-build`.
    pub warnings: Vec<String>,
    /// After a reload: the policy hash the daemon confirmed it enforces.
    pub policy_hash: Option<String>,
    /// After a reload: why the daemon is not known to enforce the new
    /// config (it rejected it, or did not answer). Installed, but the old
    /// policy may still be in force: the CLI exits 1.
    pub reload_problem: Option<String>,
}

/// The start of [`InstallReport::reload_problem`] (the Ansible role and
/// the docs match on it).
pub const RELOAD_NOT_TAKEN: &str = "the daemon did not take the new config";

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("needs root")]
    NotRoot,
    #[error("{0}")]
    Unsupported(String),
    #[error("{}: {detail}", path.display())]
    Refused { path: PathBuf, detail: String },
    #[error("{step}: {detail}")]
    Step { step: String, detail: String },
    /// macOS without System Integrity Protection ([`crate::sip`]).
    #[error("{}", crate::sip::SIP_REQUIRED)]
    SipRequired,
}

/// Shells that mean "no login" for an existing `saiife` user.
const NOLOGIN_SHELLS: &[&str] = &[
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
];

/// A managed writer and its fingerprint (Codex, Gemini CLI).
type InstallFn = fn(&Path) -> Result<Change, AgentError>;
type EntryFn = fn(&Path) -> Result<Option<String>, AgentError>;

/// How long a system install waits for the daemon's socket.
const SOCKET_WAIT: Duration = Duration::from_secs(10);
/// How long install waits for the daemon to confirm a reload.
const RELOAD_WAIT: Duration = Duration::from_secs(15);

/// How long a `security authorizationdb` or `dscl` call may take.
pub(crate) const MACOS_TOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// The shell of the macOS daemon user (spec §5.3).
const MACOS_FALSE_SHELL: &str = "/usr/bin/false";

/// macOS hands out uids and gids from 500 up to login accounts; a hidden
/// system account is below.
const MACOS_FIRST_LOGIN_ID: u32 = 500;

pub(crate) fn step(name: &str) -> impl Fn(io::Error) -> InstallError + '_ {
    move |e| InstallError::Step {
        step: name.to_string(),
        detail: e.to_string(),
    }
}

fn agent_step(name: &str) -> impl Fn(AgentError) -> InstallError + '_ {
    move |e| InstallError::Step {
        step: name.to_string(),
        detail: e.to_string(),
    }
}

pub(crate) fn refused(path: &Path, detail: impl Into<String>) -> InstallError {
    InstallError::Refused {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}

pub fn install(
    layout: &Layout,
    host: &dyn Host,
    opts: &InstallOptions,
    binary: &Path,
) -> Result<InstallReport, InstallError> {
    install_with(layout, host, opts, binary, crate::sip::seam_set())
}

/// [`install`] with the SIP test seam given ([`crate::sip::seam_set`]: a
/// release build always passes false).
pub(crate) fn install_with(
    layout: &Layout,
    host: &dyn Host,
    opts: &InstallOptions,
    binary: &Path,
    sip_seam: bool,
) -> Result<InstallReport, InstallError> {
    // 1. Root, then the supported-system check. Nothing runs before these.
    if layout.is_system() && host.euid() != 0 {
        return Err(InstallError::NotRoot);
    }
    let systemd = match check_supported(layout, host) {
        Support::Supported { systemd, .. } => systemd,
        Support::Refused(why) => return Err(InstallError::Unsupported(why)),
    };
    // macOS: SIP on, or the hardened runtime does not keep an injected
    // library out of the hook (A4). Refused before any change.
    let sip_warning = if layout.platform() == Platform::Macos {
        use crate::sip::{verdict, SipVerdict, SIP_BYPASSED};
        match verdict(host.sip_enabled(), sip_seam) {
            SipVerdict::Enabled => None,
            SipVerdict::Bypassed => Some(format!(
                "System Integrity Protection is not enabled {SIP_BYPASSED}: \
                 library injection (DYLD_INSERT_LIBRARIES) is not stopped"
            )),
            SipVerdict::Required => return Err(InstallError::SipRequired),
        }
    } else {
        None
    };

    // 2. Refusals, before anything is created.
    let previous =
        read_installed(&layout.at(INSTALLED)).map_err(|e| refused(&layout.at(INSTALLED), e))?;
    check_state_paths(layout, host)?;
    // After a plain uninstall, the copy in /etc/saiife says what an earlier
    // install created. It never relaxes a check: only the live
    // installed.toml exempts a user or gid install made itself.
    let restored = match previous {
        Some(_) => None,
        None => read_previous(layout, host),
    };
    let known = previous.as_ref().or(restored.as_ref());
    let mac = layout.platform() == Platform::Macos;
    if mac {
        check_macos_daemon_user(layout, host, previous.as_ref())?;
        check_group_for(
            host,
            previous.as_ref(),
            layout.daemon_group(),
            layout.daemon_user(),
            MACOS_FIRST_LOGIN_ID,
            &PathBuf::from(format!("/Local/Default/Groups/{}", layout.daemon_group())),
        )?;
    } else {
        check_daemon_user(host, previous.as_ref())?;
        check_daemon_group(host, previous.as_ref())?;
    }
    for a in &opts.approvers {
        let name = a.strip_prefix("group:").unwrap_or(a);
        if !valid_name(name) {
            return Err(refused(
                &layout.at(CONFIG),
                format!("approver {a:?} is not a user name or group:<name>"),
            ));
        }
    }
    let new_config = match &opts.config {
        // Checked with the drop-ins it will be loaded with: the live
        // policy.d, not the one beside the file.
        Some(p) => Some(validated_config(p, &layout.at(POLICY_D))?),
        None => None,
    };
    // The bytes checked are the bytes copied.
    let binary_bytes = std::fs::read(binary).map_err(|e| InstallError::Step {
        step: "binary".into(),
        detail: format!("{}: {e}", binary.display()),
    })?;
    let strict = layout.is_system() && !opts.allow_test_build;
    let warnings: Vec<String> = if mac {
        check_macho(binary, &binary_bytes, strict)?
    } else {
        check_binary(binary, &binary_bytes, strict)?
            .into_iter()
            .collect()
    };

    // An existing key decides its own mode (never rotated); a record is
    // not trusted for it. On macOS the daemon reads its own key file.
    let key_mode = if mac {
        check_macos_key(layout)?;
        VaultKeyMode::DaemonFile
    } else {
        match key_file_mode(layout)? {
            Some(m) => m,
            None => vault_key_mode(systemd),
        }
    };
    let rec = known.cloned().unwrap_or_else(|| Installed {
        version: INSTALLED_VERSION,
        saiife: env!("CARGO_PKG_VERSION").to_string(),
        installed_at: now(),
        systemd,
        vault_key: key_mode,
        users: Vec::new(),
        groups: Vec::new(),
        memberships: Vec::new(),
        dirs: Vec::new(),
        files: Vec::new(),
        agents: Vec::new(),
        auth_rights: Vec::new(),
    });
    // Polkit presence, decided once: the default `same_user`, the action
    // file and the warning all follow it.
    // An unsafe parent of the action dir (say a 0777 /usr/share) is not
    // a reason to abort: the action is skipped and approvals fall back to
    // a second account (`same_user = "deny"` for a new config).
    // On macOS the right is still registered, but a same-user approval is
    // always refused there: the config keeps `same_user = "deny"` and the
    // install always says so.
    let mut warnings = warnings;
    warnings.extend(sip_warning);
    let polkit = if mac {
        warnings.push(MAC_SAME_USER_OFF.to_string());
        false
    } else if !polkit_present(layout, host) {
        warnings.push(REAUTH_UNAVAILABLE.to_string());
        false
    } else if let Some(why) = polkit_dir_problem(layout, host) {
        warnings.push(format!(
            "polkit action not installed: {why}; approvals need a second account"
        ));
        false
    } else {
        true
    };
    let mut run = Run {
        layout,
        host,
        reauth: polkit,
        saved: previous,
        rec,
        report: InstallReport {
            warnings,
            ..InstallReport::default()
        },
    };
    run.rec.systemd = systemd;
    run.rec.vault_key = key_mode;
    run.rec.saiife = env!("CARGO_PKG_VERSION").to_string();

    // `/etc/saiife` first: installed.toml lives there.
    run.dir(ETC_DIR, 0o755, true)?;
    run.save()?;
    // installed.toml holds it now.
    fsops::remove_if_listed(&layout.at(PREVIOUS)).map_err(step("installed.toml"))?;

    // 3. Groups, the user, the audit-group membership.
    let member_added = run.users()?;
    // 4. The binary.
    let binary_changed = run.binary(&binary_bytes)?;
    // macOS: the authorization right, before config.toml (a new config's
    // `same_user` follows it).
    if mac {
        run.auth_right()?;
    }
    // 5. /etc/saiife, policy.d, config.toml.
    let config_changed = run.config(new_config.as_deref(), &opts.approvers)?;
    let unit_changed = if mac {
        // macOS: the state, run and log paths and the vault key (no
        // systemd makes them), then the launchd plist.
        run.macos_state()?;
        run.plist()?
    } else {
        // 5b. The polkit action, when polkit is there.
        run.polkit()?;
        // 6. The vault key.
        run.vault_key(key_mode)?;
        // 7. The unit.
        run.unit(key_mode, systemd)?
    };
    // 8. Managed hooks.
    let mut agents = opts.agents.clone();
    agents.sort();
    agents.dedup();
    if agents.is_empty() {
        run.report.warnings.push(NO_AGENTS.to_string());
    }
    let claude = agents.contains(&Agent::Claude);
    if mac && claude {
        let mdm = layout.at(CLAUDE_MDM_PROFILE);
        if std::fs::symlink_metadata(&mdm).is_ok() {
            run.report.warnings.push(format!(
                "{CLAUDE_MDM_PROFILE} exists: an MDM profile may also deliver Claude Code \
                 managed settings, and Claude Code may then ignore {}",
                layout.logical(CLAUDE_MANAGED_DIR)
            ));
        }
    }
    for a in agents {
        run.managed(a)?;
    }
    if claude {
        run.mcp_allowlist()?;
    } else {
        run.drop_stale_mcp()?;
    }
    run.save()?;
    // 9. Start (or restart) the daemon.
    // A running daemon picks up a new group membership only at start. A
    // new config.toml alone is a reload (SIGHUP, the unit's ExecReload; on
    // macOS, policy.reload over the socket).
    let restart = binary_changed || unit_changed || member_added;
    if mac {
        // launchd reads the plist only at bootstrap: a changed plist
        // reloads the job, anything else restarts it in place.
        run.start_macos(binary_changed || member_added, unit_changed, config_changed)?;
    } else {
        run.start(restart, config_changed)?;
    }
    // 10. Wait for the socket on the real machine.
    if layout.is_system() {
        let sock = layout.at(SOCKET);
        let deadline = Instant::now() + SOCKET_WAIT;
        while !sock.exists() {
            if Instant::now() >= deadline {
                return Err(InstallError::Step {
                    step: "start".into(),
                    detail: if mac {
                        format!(
                            "the daemon did not open {} within 10 s (see {DAEMON_LOG})",
                            layout.logical(SOCKET)
                        )
                    } else {
                        format!(
                            "the daemon did not open {SOCKET} within 10 s (see: journalctl -u saiifed)"
                        )
                    },
                });
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    run.report.started = true;
    Ok(run.report)
}

/// Why the binary `bytes` is unfit for locked mode (spec §9.2 A4): not a
/// static ELF, or a build with debug assertions. `None` for the static
/// release build.
fn binary_problem(bytes: &[u8]) -> Option<String> {
    let problems = match crate::binary::inspect(bytes) {
        Ok(info) => info.problems(),
        Err(e) => vec![format!("it is not a static ELF executable ({e})")],
    };
    (!problems.is_empty()).then(|| problems.join("; "))
}

/// `strict` (the real system without `--allow-test-build`): an unfit
/// binary is refused. Otherwise it is a warning.
fn check_binary(path: &Path, bytes: &[u8], strict: bool) -> Result<Option<String>, InstallError> {
    let Some(problem) = binary_problem(bytes) else {
        return Ok(None);
    };
    if strict {
        return Err(refused(
            path,
            format!(
                "{problem}; locked mode installs only the static release build \
                 (see docs/install.md)"
            ),
        ));
    }
    Ok(Some(format!("{}: {problem}", path.display())))
}

/// [`check_binary`] for macOS (spec §9.2 A4, plan 13 decision 13): a thin
/// 64-bit Mach-O, code-signed with the hardened runtime, release build.
/// An ad-hoc or CMS-less signature only warns. The flags are what the file
/// claims ([`crate::binary::inspect_macho`] verifies nothing), so a
/// `Signed` result is never taken as proof of who built it. Returns the
/// warnings.
fn check_macho(path: &Path, bytes: &[u8], strict: bool) -> Result<Vec<String>, InstallError> {
    let (problems, notes) = match crate::binary::inspect_macho(bytes) {
        Ok(info) => (info.problems(), info.warnings()),
        Err(e) => (
            vec![format!("it is not a thin 64-bit Mach-O executable ({e})")],
            Vec::new(),
        ),
    };
    let shown = path.display();
    let mut warnings: Vec<String> = notes.iter().map(|w| format!("{shown}: {w}")).collect();
    if problems.is_empty() {
        return Ok(warnings);
    }
    let problem = problems.join("; ");
    if strict {
        return Err(refused(
            path,
            format!(
                "{problem}; locked mode installs only the signed release build with the \
                 hardened runtime (see docs/install.md)"
            ),
        ));
    }
    warnings.insert(0, format!("{shown}: {problem}"));
    Ok(warnings)
}

/// An existing macOS vault key must be a regular file of 32 bytes; it is
/// never replaced.
fn check_macos_key(layout: &Layout) -> Result<(), InstallError> {
    let p = layout.at(VAULT_KEY);
    match fsops::lstat(&p).map_err(|e| refused(&p, e.to_string()))? {
        None => Ok(()),
        Some(m) if !m.is_file() => Err(refused(&p, "exists and is not a regular file")),
        Some(m) if m.len() != 32 => Err(refused(
            &p,
            format!(
                "exists with {} bytes, not a 32-byte key; saiife does not adopt it (move it away first)",
                m.len()
            ),
        )),
        Some(_) => Ok(()),
    }
}

/// True when `dscl . -read` output says `IsHidden: 1` (or `YES`), in
/// either of dscl's layouts ([`crate::host::parse_dscl_attrs`]). A real
/// Mac names it `dsAttrTypeNative:IsHidden` (it is no standard attribute;
/// seen on the macos-15 runners); exactly that prefix is accepted too.
pub(crate) fn dscl_is_hidden(out: &str) -> bool {
    let attrs = crate::host::parse_dscl_attrs(out);
    ["IsHidden", "dsAttrTypeNative:IsHidden"]
        .iter()
        .filter_map(|k| attrs.get(*k).and_then(|v| v.first()))
        .any(|v| matches!(v.as_str(), "1" | "YES" | "yes" | "true"))
}

/// An existing macOS daemon user must be a record of the local directory
/// (`dscl .`), never a directory-service account; a read that cannot tell
/// refuses (fail closed). Unless the live installed.toml says install
/// created it, it must also be hidden, have the shell `/usr/bin/false` and
/// a uid below 500. It is reused as it is, never created again.
fn check_macos_daemon_user(
    layout: &Layout,
    host: &dyn Host,
    previous: Option<&Installed>,
) -> Result<(), InstallError> {
    use crate::host::{argv_dscl_read, dscl_read_found};
    let name = layout.daemon_user();
    let Some(u) = host.user(name) else {
        return Ok(());
    };
    let shown = PathBuf::from(format!("/Local/Default/Users/{name}"));
    let argv = argv_dscl_read(&format!("/Users/{name}"));
    let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    let res = host.run(DSCL, &args, MACOS_TOOL_TIMEOUT);
    let stdout = res.as_ref().map(|o| o.stdout.clone()).unwrap_or_default();
    match dscl_read_found(res) {
        Ok(true) => {}
        Ok(false) => {
            return Err(refused(
                &shown,
                format!(
                    "a user {name} exists but is not in the local directory; \
                     saiife never adopts a directory-service account as its daemon user"
                ),
            ))
        }
        Err(e) => {
            return Err(refused(
                &shown,
                format!("the user {name} could not be read from the local directory: {e}"),
            ))
        }
    }
    if previous.is_some_and(|p| p.users.iter().any(|n| n == name)) {
        return Ok(());
    }
    let hidden = dscl_is_hidden(&stdout);
    if !hidden || u.shell != MACOS_FALSE_SHELL || u.uid >= MACOS_FIRST_LOGIN_ID {
        return Err(refused(
            &shown,
            format!(
                "a user {name} already exists with uid {}, shell {}{}; saiife adopts only a \
                 hidden system account (uid below {MACOS_FIRST_LOGIN_ID}, shell {MACOS_FALSE_SHELL})",
                u.uid,
                u.shell,
                if hidden { "" } else { " and not hidden" }
            ),
        ));
    }
    Ok(())
}

/// `logical` (a path as the platform names it) with a trusted system link
/// at its top resolved: on macOS `/var/x` is `/private/var/x` when `/var`
/// below the root is the link `private/var`, owned by root
/// ([`fsops::trusted_link_target`]). Any other path, and every path on
/// Linux, is returned as it is. For fd-relative walks that refuse every
/// symlink.
pub(crate) fn beneath_links(layout: &Layout, host: &dyn Host, logical: &Path) -> PathBuf {
    use std::os::unix::fs::MetadataExt;
    if layout.platform() != Platform::Macos {
        return logical.to_path_buf();
    }
    let mut parts = logical.components();
    let (Some(std::path::Component::RootDir), Some(std::path::Component::Normal(top))) =
        (parts.next(), parts.next())
    else {
        return logical.to_path_buf();
    };
    let link_logical = Path::new("/").join(top);
    let Ok(link) = layout.try_at(&link_logical) else {
        return logical.to_path_buf();
    };
    let root_uid = host.user("root").map(|u| u.uid);
    let trusted = std::fs::symlink_metadata(&link).is_ok_and(|m| {
        m.file_type().is_symlink()
            && Some(m.uid()) == root_uid
            && std::fs::read_link(&link)
                .is_ok_and(|t| fsops::trusted_link_target(&link_logical, &t))
    });
    if !trusted {
        return logical.to_path_buf();
    }
    Path::new("/private").join(top).join(parts.as_path())
}

/// The existing file `name` in the open directory `dir`, opened with
/// `O_NOFOLLOW` and checked on the descriptor: a regular file with one
/// link, owned by one of `allowed`, of `len` bytes when given. `None` when
/// it is missing. A symlink or a hard link (say to a root-owned file the
/// daemon user linked there) is refused, so root never chowns it.
fn open_daemon_file(
    dir: &OwnedFd,
    name: &std::ffi::OsStr,
    shown: &Path,
    len: Option<u64>,
    allowed: &[u32],
) -> Result<Option<OwnedFd>, InstallError> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    let bad = |e: rustix::io::Errno| refused(shown, io::Error::from(e).to_string());
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(bad(e)),
        Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Symlink => {
            return Err(refused(shown, "is a symlink; saiife does not follow it"))
        }
        Ok(_) => {}
    }
    let fd = match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::LOOP) => {
            return Err(refused(shown, "is a symlink; saiife does not follow it"))
        }
        Err(e) => return Err(bad(e)),
    };
    let st = rustix::fs::fstat(&fd).map_err(bad)?;
    check_daemon_file(shown, &st, len, allowed)?;
    Ok(Some(fd))
}

/// What [`open_daemon_file`] requires of the open file's `stat`.
#[allow(clippy::unnecessary_cast)] // st_nlink and st_size differ per OS
fn check_daemon_file(
    shown: &Path,
    st: &fsops::Stat,
    len: Option<u64>,
    allowed: &[u32],
) -> Result<(), InstallError> {
    use rustix::fs::FileType;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(refused(shown, "exists and is not a regular file"));
    }
    let links = st.st_nlink as u64;
    if links != 1 {
        return Err(refused(
            shown,
            format!(
                "has {links} hard links; saiife does not adopt a linked file (remove it first)"
            ),
        ));
    }
    let uid = st.st_uid as u32;
    if !allowed.contains(&uid) {
        return Err(refused(
            shown,
            format!(
                "exists and is owned by uid {uid}; saiife does not adopt it (move it away first)"
            ),
        ));
    }
    let size = st.st_size as u64;
    if let Some(want) = len.filter(|w| *w != size) {
        return Err(refused(
            shown,
            format!("exists with {size} bytes, not {want}; saiife does not adopt it (move it away first)"),
        ));
    }
    Ok(())
}

/// A new file `name` in the open `dir`: `O_CREAT|O_EXCL|O_NOFOLLOW` with
/// `mode`, so nothing planted there is opened.
fn create_daemon_file(
    dir: &OwnedFd,
    name: &std::ffi::OsStr,
    shown: &Path,
    mode: u32,
) -> Result<OwnedFd, InstallError> {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(mode as _),
    )
    .map_err(|e| refused(shown, io::Error::from(e).to_string()))
}

/// `fchmod` on the open file.
fn set_mode_fd(fd: &OwnedFd, shown: &Path, mode: u32) -> Result<(), InstallError> {
    rustix::fs::fchmod(fd, rustix::fs::Mode::from_raw_mode(mode as _))
        .map_err(|e| refused(shown, io::Error::from(e).to_string()))
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// An existing `saiife` user must be a system account without a login,
/// unless an earlier install created it.
fn check_daemon_user(host: &dyn Host, previous: Option<&Installed>) -> Result<(), InstallError> {
    let Some(u) = host.user(DAEMON_USER) else {
        return Ok(());
    };
    if previous.is_some_and(|p| p.users.iter().any(|n| n == DAEMON_USER)) {
        return Ok(());
    }
    if u.uid >= 1000 || !NOLOGIN_SHELLS.contains(&u.shell.as_str()) {
        return Err(refused(
            Path::new("/etc/passwd"),
            format!(
                "a user {DAEMON_USER} already exists with uid {} and shell {}; \
                 saiife never adopts a login account as its daemon user \
                 (it needs a system uid below 1000 and a nologin shell)",
                u.uid, u.shell
            ),
        ));
    }
    Ok(())
}

/// An existing `saiife` group must have no member but `saiife`, neither
/// listed in `/etc/group` nor by primary gid in `/etc/passwd`: on systemd
/// < 250 the plain vault key is readable by that group (§5.2). This always
/// runs. Its gid must also be a system gid (below 1000), unless the live
/// installed.toml says install created the group.
fn check_daemon_group(host: &dyn Host, live: Option<&Installed>) -> Result<(), InstallError> {
    check_group_for(
        host,
        live,
        DAEMON_GROUP,
        DAEMON_USER,
        1000,
        Path::new("/etc/group"),
    )
}

/// [`check_daemon_group`] for the daemon group `group` and user `user`,
/// with system gids below `first_regular`; refusals name `shown`.
fn check_group_for(
    host: &dyn Host,
    live: Option<&Installed>,
    group: &str,
    user: &str,
    first_regular: u32,
    shown: &Path,
) -> Result<(), InstallError> {
    let Some(gid) = host.group_id(group) else {
        return Ok(());
    };
    // A directory that cannot be asked refuses (fail closed).
    let primary = host.users_with_primary_gid(gid).map_err(|e| {
        refused(
            shown,
            format!("the members of the group {group} (gid {gid}) could not be read: {e}"),
        )
    })?;
    let mut others: Vec<String> = host
        .group_members(group)
        .unwrap_or_default()
        .into_iter()
        .chain(primary)
        .filter(|m| m != user)
        .collect();
    others.sort();
    others.dedup();
    let ours = live.is_some_and(|p| p.groups.iter().any(|n| n == group));
    if !others.is_empty() {
        return Err(refused(
            shown,
            format!(
                "the group {group} (gid {gid}) has members besides {user}: {}; \
                 they could read the vault key, so saiife does not use it \
                 (remove them from the group first)",
                others.join(", ")
            ),
        ));
    }
    if gid >= first_regular && !ours {
        return Err(refused(
            shown,
            format!(
                "a group {group} already exists with gid {gid}; saiife \
                 never adopts a regular group for its daemon (it needs a system \
                 gid below {first_regular})"
            ),
        ));
    }
    Ok(())
}

/// The vault-key mode of an existing key file: 32 raw bytes are a plain
/// key (`File`), anything else an encrypted credential. `None` when there
/// is no key.
fn key_file_mode(layout: &Layout) -> Result<Option<VaultKeyMode>, InstallError> {
    let p = layout.at(VAULT_KEY);
    match fsops::lstat(&p).map_err(|e| refused(&p, e.to_string()))? {
        None => Ok(None),
        Some(m) if !m.is_file() => Err(refused(&p, "exists and is not a regular file")),
        Some(m) if m.len() == 32 => Ok(Some(VaultKeyMode::File)),
        Some(_) => Ok(Some(VaultKeyMode::Credential)),
    }
}

/// Where a plain uninstall keeps a copy of installed.toml: root:root 0600
/// in the root-owned `/etc/saiife`, never in the daemon's state dir.
pub(crate) const PREVIOUS: &str = "/etc/saiife/installed.previous.toml";

/// Largest copy read.
const MAX_PREVIOUS: u64 = 1024 * 1024;

/// The copy a plain uninstall left, read through one `O_NOFOLLOW` open: it
/// must be a regular file of root's with mode 0600 (checked on that open
/// file), else it is ignored. It is trusted only for what install could
/// have created; anything else is dropped. It never relaxes a check and
/// never decides the vault-key mode (the key file does). Removed files
/// (binary, unit, managed configs) are not taken over; their `created`
/// flags are found again on the next write.
pub(crate) fn read_previous(layout: &Layout, host: &dyn Host) -> Option<Installed> {
    let mut i = read_previous_record(layout, host)?;
    let (user, group, audit) = (
        layout.daemon_user(),
        layout.daemon_group(),
        layout.audit_group(),
    );
    let mac = layout.platform() == Platform::Macos;
    i.users.retain(|u| u == user);
    i.groups.retain(|g| g == group || g == audit);
    i.memberships.retain(|m| m.user == user && m.group == audit);
    i.auth_rights.retain(|r| mac && r == authright::RIGHT);
    let l = |abs: &'static str| Path::new(layout.logical(abs));
    let unit_dir = l(UNIT).parent().unwrap_or(Path::new("/"));
    let mut known_dirs = vec![
        l(BIN_DIR),
        l(POLICY_D),
        unit_dir,
        l(CLAUDE_MANAGED_DIR),
        l(CODEX_DIR),
        l(GEMINI_DIR),
    ];
    // macOS has no credstore.
    if !mac {
        known_dirs.insert(2, l(CREDSTORE));
    }
    i.dirs
        .retain(|d| d != Path::new("/") && known_dirs.iter().any(|k| k.starts_with(d)));
    i.files.retain(|f| {
        (f.kind == FileKind::Config && f.path == l(CONFIG))
            || (f.kind == FileKind::VaultKey && f.path == l(VAULT_KEY))
    });
    for f in &mut i.files {
        if f.kind == FileKind::VaultKey {
            f.sha256 = None;
        }
    }
    i.agents.clear();
    Some(i)
}

/// The copy a plain uninstall left, whole, with the checks of
/// [`read_previous`] on the file (root's, 0600, a regular file opened
/// without following a symlink, at most 1 MiB) but none on its content.
/// For what it says about the admin's choices (the agents), never for
/// what install may take over.
pub(crate) fn read_previous_record(layout: &Layout, host: &dyn Host) -> Option<Installed> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let p = layout.at(PREVIOUS);
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(&p)
        .ok()?;
    let m = f.metadata().ok()?;
    let root_uid = host.user("root")?.uid;
    if !m.is_file() || m.uid() != root_uid || m.mode() & 0o7777 != 0o600 || m.len() > MAX_PREVIOUS {
        return None;
    }
    let mut text = String::new();
    f.take(MAX_PREVIOUS).read_to_string(&mut text).ok()?;
    let i: Installed = toml::from_str(&text).ok()?;
    (i.version == INSTALLED_VERSION).then_some(i)
}

/// A directory root writes into must be root's and not writable by group
/// or others (sticky dirs excepted), so no other user can swap what is
/// below it while install or uninstall works there.
pub(crate) fn check_trusted_dir(
    p: &Path,
    m: &std::fs::Metadata,
    root_uid: u32,
) -> Result<(), InstallError> {
    use std::os::unix::fs::MetadataExt;
    check_trusted_owner_mode(p, m.uid(), m.mode() & 0o7777, root_uid)
}

/// [`check_trusted_dir`] from an owner and permission bits.
pub(crate) fn check_trusted_owner_mode(
    p: &Path,
    uid: u32,
    mode: u32,
    root_uid: u32,
) -> Result<(), InstallError> {
    check_owner_mode_for(p, uid, mode, root_uid, "saiife does not write below it")
}

/// [`check_trusted_owner_mode`] with the consequence the refusal names
/// (`saiife does not ...`).
pub(crate) fn check_owner_mode_for(
    p: &Path,
    uid: u32,
    mode: u32,
    root_uid: u32,
    consequence: &str,
) -> Result<(), InstallError> {
    if uid != root_uid {
        return Err(refused(
            p,
            format!("exists and is owned by uid {uid}, not root; {consequence}"),
        ));
    }
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(refused(
            p,
            format!("mode {mode:04o} is writable by group or others; {consequence}"),
        ));
    }
    Ok(())
}

/// Why root may not write the polkit action below [`POLKIT_DIR`]: the first
/// existing dir on the way (from `/usr`) that is not a directory, not
/// root's or writable by group or others, as `<path> is ...`. Dirs that do
/// not exist yet would be created by install, so the walk stops there.
fn polkit_dir_problem(layout: &Layout, host: &dyn Host) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let root_uid = host.user("root").map(|u| u.uid)?;
    let mut logical = PathBuf::from("/");
    for comp in Path::new(POLKIT_DIR).components().skip(1) {
        logical.push(comp);
        let shown = logical.display();
        let Ok(p) = layout.try_at(&logical) else {
            return Some(format!("{shown} is outside the install root"));
        };
        let m = match fsops::lstat(&p) {
            Ok(None) => return None,
            Ok(Some(m)) => m,
            Err(e) => return Some(format!("{shown} cannot be read ({e})")),
        };
        if !m.is_dir() {
            return Some(format!("{shown} is not a directory"));
        }
        let mode = m.mode() & 0o7777;
        if m.uid() != root_uid {
            return Some(format!("{shown} is owned by uid {}, not root", m.uid()));
        }
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Some(format!("{shown} is writable by group or others"));
        }
    }
    None
}

/// An existing state dir, key dir or audit key must be the daemon user's,
/// with the spec modes. They are never adopted otherwise.
fn check_state_paths(layout: &Layout, host: &dyn Host) -> Result<(), InstallError> {
    use std::os::unix::fs::MetadataExt;
    let daemon_user = layout.daemon_user();
    let saiife_uid = host.user(daemon_user).map(|u| u.uid);
    // macOS: install itself makes the state and key dirs (as root, then
    // hands them over), so a root-owned one is what a crashed install left;
    // it is repaired, as `Run::owned_dir_at` does. A file must be the
    // daemon user's.
    let root_uid = host.user("root").map(|u| u.uid);
    let mac = layout.platform() == Platform::Macos;
    for (abs, want, is_dir) in [
        (STATE_DIR, 0o700, true),
        (KEYS_DIR, 0o700, true),
        (AUDIT_KEY, 0o600, false),
    ] {
        let p = layout.at(abs);
        let m = match fsops::lstat(&p) {
            Ok(None) => continue,
            Ok(Some(m)) => m,
            Err(e) => return Err(refused(&p, e.to_string())),
        };
        if m.is_dir() != is_dir || (!is_dir && !m.is_file()) {
            return Err(refused(
                &p,
                format!(
                    "exists but is not a {}; saiife does not adopt it",
                    if is_dir { "directory" } else { "regular file" }
                ),
            ));
        }
        let crashed = mac && is_dir && Some(m.uid()) == root_uid;
        if Some(m.uid()) != saiife_uid && !crashed {
            return Err(refused(
                &p,
                format!(
                    "exists and is owned by uid {}, not by the {daemon_user} user; \
                     saiife does not adopt it (move it away first)",
                    m.uid()
                ),
            ));
        }
        let mode = m.mode() & 0o7777;
        if mode != want {
            return Err(refused(
                &p,
                format!(
                    "exists with mode {mode:o}, not {want:o}; saiife does not adopt it \
                     (move it away first)"
                ),
            ));
        }
    }
    Ok(())
}

/// The `--config` file: it loads and checks (unknown keys, scopes) and says
/// `locked = true`. Returns its text.
fn validated_config(path: &Path, dropins: &Path) -> Result<String, InstallError> {
    let text = std::fs::read_to_string(path).map_err(|e| refused(path, e.to_string()))?;
    let loaded = saiife_policy::load_and_check_with(path, dropins, &saiife_policy::Getent)
        .map_err(|e| refused(path, e.to_string()))?;
    if !loaded.config.locked {
        return Err(refused(
            path,
            "it must say `locked = true` for system install",
        ));
    }
    // The text loaded is the text written: a file changed in between is refused.
    if std::fs::read_to_string(path).map_err(|e| refused(path, e.to_string()))? != text {
        return Err(refused(path, "it changed while it was being checked"));
    }
    Ok(text)
}

/// Root's group: `root` on Linux, `wheel` (gid 0) on macOS.
pub(crate) fn root_group(layout: &Layout) -> &'static str {
    match layout.platform() {
        Platform::Linux => "root",
        Platform::Macos => "wheel",
    }
}

/// One install run: the record so far and what was written last.
struct Run<'a> {
    layout: &'a Layout,
    host: &'a dyn Host,
    /// Re-authentication is available: [`polkit_present`] on Linux, decided
    /// once per run; the authorization right registered on macOS.
    reauth: bool,
    saved: Option<Installed>,
    rec: Installed,
    report: InstallReport,
}

impl Run<'_> {
    fn at(&self, abs: &str) -> PathBuf {
        self.layout.at(abs)
    }

    /// Writes installed.toml when the record changed (root:root 0644).
    fn save(&mut self) -> Result<(), InstallError> {
        if self.saved.as_ref() == Some(&self.rec) {
            return Ok(());
        }
        let p = self.at(INSTALLED);
        write_installed(&p, &self.rec).map_err(step("installed.toml"))?;
        self.chown_root(&p, "installed.toml")?;
        self.saved = Some(self.rec.clone());
        Ok(())
    }

    fn root_ids(&self) -> Result<(u32, u32), InstallError> {
        let group = root_group(self.layout);
        let uid = self.host.user("root").map(|u| u.uid);
        let gid = self.host.group_id(group);
        match (uid, gid) {
            (Some(u), Some(g)) => Ok((u, g)),
            _ => Err(InstallError::Step {
                step: "owners".into(),
                detail: if group == "root" {
                    "user or group root not found".to_string()
                } else {
                    format!("user root or group {group} not found")
                },
            }),
        }
    }

    fn chown_root(&self, p: &Path, step_name: &str) -> Result<(), InstallError> {
        let (u, g) = self.root_ids()?;
        self.host.chown(p, u, g).map_err(step(step_name))
    }

    fn changed(&mut self, what: impl Into<String>) {
        self.report.changed.push(what.into());
    }

    fn unchanged(&mut self, what: impl Into<String>) {
        self.report.unchanged.push(what.into());
    }

    /// Ensures the directory `abs` (and its missing ancestors, 0755) exists,
    /// root:root. Created ones are recorded. With `own` (saiife's own dirs)
    /// an existing `abs` also gets `mode` and root:root.
    ///
    /// `abs` is a path constant (or a parent of one) and is walked as the
    /// platform names it ([`Layout::logical`]). On macOS a root-owned
    /// `/etc` or `/var` link to `private/<name>` is passed through
    /// ([`fsops::trusted_link_target`]); every other symlink is refused.
    fn dir(&mut self, abs: &str, mode: u32, own: bool) -> Result<(), InstallError> {
        let mut logical = PathBuf::from("/");
        let target = Path::new(self.layout.logical(abs));
        for comp in target.components().skip(1) {
            logical.push(comp);
            let p = self
                .layout
                .try_at(&logical)
                .map_err(|e| refused(&logical, e.to_string()))?;
            let is_target = logical == target;
            if !is_target && self.trusted_link(&logical, &p)? {
                continue;
            }
            let m = if is_target { mode } else { 0o755 };
            let created = fsops::create_dir_mode(&p, m).map_err(|e| refused(&p, e.to_string()))?;
            if !created && !(is_target && own) {
                // Someone else's existing dir: root writes below it only
                // when no other user can change it.
                let (root_uid, _) = self.root_ids()?;
                let md = fsops::lstat(&p)
                    .map_err(|e| refused(&p, e.to_string()))?
                    .ok_or_else(|| refused(&p, "disappeared"))?;
                check_trusted_dir(&p, &md, root_uid)?;
            }
            if created {
                self.chown_root(&p, "dirs")?;
                if !self.rec.dirs.contains(&logical) {
                    self.rec.dirs.push(logical.clone());
                }
                self.changed(logical.display().to_string());
                self.save()?;
            } else if is_target && own {
                let before = fsops::mode_of(&p).map_err(step("dirs"))?;
                fsops::set_dir_mode(&p, mode).map_err(|e| refused(&p, e.to_string()))?;
                self.chown_root(&p, "dirs")?;
                if before != Some(mode) {
                    self.changed(format!("{} (mode {mode:o})", logical.display()));
                }
            }
        }
        Ok(())
    }

    /// macOS only: `p` (the logical `logical`) is a trusted system link
    /// owned by root, and the directory it points at is root's and not
    /// writable by group or others. Always false on Linux.
    fn trusted_link(&self, logical: &Path, p: &Path) -> Result<bool, InstallError> {
        use std::os::unix::fs::MetadataExt;
        if self.layout.platform() != Platform::Macos {
            return Ok(false);
        }
        let Ok(m) = std::fs::symlink_metadata(p) else {
            return Ok(false);
        };
        if !m.file_type().is_symlink() {
            return Ok(false);
        }
        let target = std::fs::read_link(p).map_err(|e| refused(p, e.to_string()))?;
        if !fsops::trusted_link_target(logical, &target) {
            return Ok(false);
        }
        let (root_uid, _) = self.root_ids()?;
        if m.uid() != root_uid {
            return Err(refused(
                p,
                format!(
                    "is a symlink owned by uid {}, not root; saiife does not write below it",
                    m.uid()
                ),
            ));
        }
        let dir = self
            .layout
            .try_at(&Path::new("/").join(&target))
            .map_err(|e| refused(p, e.to_string()))?;
        let md = fsops::lstat(&dir)
            .map_err(|e| refused(&dir, e.to_string()))?
            .ok_or_else(|| refused(&dir, "is missing (the target of a system link)"))?;
        if !md.is_dir() {
            return Err(refused(&dir, "is not a directory"));
        }
        check_trusted_dir(&dir, &md, root_uid)?;
        Ok(true)
    }

    /// True when the daemon user was just added to the audit group.
    fn users(&mut self) -> Result<bool, InstallError> {
        let (daemon_user, daemon_group, audit_group) = (
            self.layout.daemon_user(),
            self.layout.daemon_group(),
            self.layout.audit_group(),
        );
        for g in [daemon_group, audit_group] {
            if self.host.group_id(g).is_none() {
                self.host.create_system_group(g).map_err(step("users"))?;
                if !self.rec.groups.iter().any(|x| x == g) {
                    self.rec.groups.push(g.to_string());
                }
                self.changed(format!("group {g}"));
                self.save()?;
            }
        }
        if self.host.user(daemon_user).is_none() {
            self.host
                .create_system_user(daemon_user, daemon_group)
                .map_err(step("users"))?;
            if !self.rec.users.iter().any(|x| x == daemon_user) {
                self.rec.users.push(daemon_user.to_string());
            }
            self.changed(format!("user {daemon_user}"));
            self.save()?;
        }
        // The daemon regroups the audit dir at start: it must be a member.
        // Added and recorded only when it is not one yet, so uninstall
        // reverts only what install did.
        let member = self
            .host
            .group_members(audit_group)
            .is_some_and(|m| m.iter().any(|u| u == daemon_user));
        if !member {
            let m = Membership {
                user: daemon_user.to_string(),
                group: audit_group.to_string(),
            };
            if !self.rec.memberships.contains(&m) {
                self.rec.memberships.push(m);
            }
            // Recorded before it is made: a failure part-way is still listed.
            self.save()?;
            self.host
                .add_to_group(daemon_user, audit_group)
                .map_err(step("users"))?;
            self.changed(format!("{daemon_user} in group {audit_group}"));
        }
        Ok(!member)
    }

    /// Records (or refreshes) a file, by its platform path. `created`
    /// sticks from the first record.
    fn record_file(&mut self, abs: &str, kind: FileKind, sha256: Option<String>, created: bool) {
        let path = PathBuf::from(self.layout.logical(abs));
        match self.rec.files.iter_mut().find(|f| f.path == path) {
            Some(f) => {
                f.sha256 = sha256;
                f.kind = kind;
            }
            None => self.rec.files.push(InstalledFile {
                path,
                sha256,
                kind,
                created,
            }),
        }
    }

    /// Writes `bytes` to `abs` at `mode` unless it already holds them, then
    /// sets mode and root:root. True when written.
    fn file(
        &mut self,
        abs: &str,
        bytes: &[u8],
        mode: u32,
        kind: FileKind,
        step_name: &str,
    ) -> Result<bool, InstallError> {
        let p = self.at(abs);
        let current = fsops::sha256_file(&p).map_err(|e| refused(&p, e.to_string()))?;
        let want = fsops::sha256_hex(bytes);
        let write = current.as_deref() != Some(want.as_str());
        // Listed before it is written, so a failure part-way leaves it on
        // the list for uninstall (no digest until the write is done).
        self.record_file(abs, kind, None, current.is_none());
        self.save()?;
        let shown = self.layout.logical(abs).to_string();
        if write {
            fsops::write_file_atomic(&p, bytes, mode).map_err(step(step_name))?;
            self.changed(shown);
        } else {
            fsops::set_file_mode(&p, mode).map_err(step(step_name))?;
            self.unchanged(shown);
        }
        self.chown_root(&p, step_name)?;
        self.record_file(abs, kind, Some(want), current.is_none());
        self.save()?;
        Ok(write)
    }

    fn binary(&mut self, bytes: &[u8]) -> Result<bool, InstallError> {
        self.dir(OPT_DIR, 0o755, true)?;
        self.dir(BIN_DIR, 0o755, true)?;
        self.file(BINARY, bytes, 0o755, FileKind::Binary, "binary")
    }

    /// True when config.toml was written.
    fn config(&mut self, new: Option<&str>, approvers: &[String]) -> Result<bool, InstallError> {
        self.dir(ETC_DIR, 0o755, true)?;
        self.dir(POLICY_D, 0o755, true)?;
        let p = self.at(CONFIG);
        let text = match new {
            Some(t) => t.to_string(),
            None => match fsops::lstat(&p).map_err(|e| refused(&p, e.to_string()))? {
                // An existing config is kept as it is.
                Some(_) => {
                    let current = std::fs::read(&p).map_err(step("config"))?;
                    return self.file(CONFIG, &current, 0o644, FileKind::Config, "config");
                }
                None => default_config(self.layout, approvers, self.reauth),
            },
        };
        self.file(CONFIG, text.as_bytes(), 0o644, FileKind::Config, "config")
    }

    /// The polkit action file (root:root 0644), only when `pkcheck` exists.
    fn polkit(&mut self) -> Result<(), InstallError> {
        if !self.reauth {
            return Ok(());
        }
        self.dir(POLKIT_DIR, 0o755, false)?;
        self.file(
            POLKIT_ACTION,
            POLKIT_POLICY.as_bytes(),
            0o644,
            FileKind::Polkit,
            "polkit",
        )
        .map(|_| ())
    }

    fn vault_key(&mut self, mode: VaultKeyMode) -> Result<(), InstallError> {
        self.dir(CREDSTORE, 0o700, true)?;
        let p = self.at(VAULT_KEY);
        let exists = fsops::lstat(&p)
            .map_err(|e| refused(&p, e.to_string()))?
            .is_some();
        let (uid, root_gid) = self.root_ids()?;
        let (file_mode, gid) = match mode {
            VaultKeyMode::Credential => (0o600, root_gid),
            VaultKeyMode::File | VaultKeyMode::DaemonFile => (
                0o640,
                self.host
                    .group_id(DAEMON_GROUP)
                    .ok_or_else(|| InstallError::Step {
                        step: "vault-key".into(),
                        detail: format!("group {DAEMON_GROUP} not found"),
                    })?,
            ),
        };
        // Listed before it is made. Never with a digest: installed.toml is
        // world-readable.
        self.record_file(VAULT_KEY, FileKind::VaultKey, None, !exists);
        self.save()?;
        if !exists {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut key[..]).map_err(|e| InstallError::Step {
                step: "vault-key".into(),
                detail: e.to_string(),
            })?;
            match mode {
                VaultKeyMode::Credential => self
                    .host
                    .encrypt_credential("vault-key", &key[..], &p)
                    .map_err(step("vault-key"))?,
                VaultKeyMode::File | VaultKeyMode::DaemonFile => {
                    fsops::write_new_file(&p, &key[..], file_mode).map_err(step("vault-key"))?
                }
            }
            self.changed(VAULT_KEY);
        } else {
            self.unchanged(VAULT_KEY);
        }
        // Never rotated: an existing key only gets its mode and owner.
        fsops::set_file_mode(&p, file_mode).map_err(step("vault-key"))?;
        self.host.chown(&p, uid, gid).map_err(step("vault-key"))?;
        Ok(())
    }

    fn unit(&mut self, key_mode: VaultKeyMode, systemd: u32) -> Result<bool, InstallError> {
        // The unit follows the key on disk, not only the systemd version: a
        // plain key from before a systemd upgrade keeps `LoadCredential=`.
        let text = match key_mode {
            VaultKeyMode::File | VaultKeyMode::DaemonFile => unit_text(systemd.min(249)),
            VaultKeyMode::Credential => unit_text(systemd.max(250)),
        };
        let unit_dir = Path::new(UNIT)
            .parent()
            .and_then(Path::to_str)
            .unwrap_or("/");
        self.dir(unit_dir, 0o755, false)?;
        self.file(UNIT, text.as_bytes(), 0o644, FileKind::Unit, "unit")
    }

    fn managed(&mut self, a: Agent) -> Result<(), InstallError> {
        let (dir_abs, file_abs) = match a {
            Agent::Claude => (CLAUDE_MANAGED_DIR, CLAUDE_MANAGED),
            Agent::Codex => (CODEX_DIR, CODEX_REQUIREMENTS),
            Agent::Gemini => (GEMINI_DIR, GEMINI_SETTINGS),
        };
        self.dir(dir_abs, 0o755, false)?;
        let p = self.at(file_abs);
        let shown = self.layout.logical(file_abs);
        let existed = fsops::lstat(&p)
            .map_err(|e| refused(&p, e.to_string()))?
            .is_some();
        // Listed before it is written (empty digest until done), so a
        // failure part-way still leaves it for uninstall.
        self.record_agent(a, file_abs, String::new(), a == Agent::Claude, !existed);
        self.save()?;
        let (sha, whole) = match a {
            Agent::Claude => {
                let bytes = claude::managed_settings().as_bytes();
                let current = fsops::sha256_file(&p).map_err(|e| refused(&p, e.to_string()))?;
                let want = fsops::sha256_hex(bytes);
                if current.as_deref() != Some(want.as_str()) {
                    fsops::write_file_atomic(&p, bytes, 0o644).map_err(step("managed"))?;
                    self.changed(shown);
                } else {
                    self.unchanged(shown);
                }
                (want, true)
            }
            Agent::Codex | Agent::Gemini => {
                let (install, entry): (InstallFn, EntryFn) = if a == Agent::Codex {
                    (codex::install_managed, codex::managed_entry)
                } else {
                    (gemini::install_managed, gemini::managed_entry)
                };
                match install(&p).map_err(agent_step("managed"))? {
                    Change::Unchanged => self.unchanged(shown),
                    _ => self.changed(shown),
                }
                let sha = entry(&p).map_err(agent_step("managed"))?.ok_or_else(|| {
                    InstallError::Step {
                        step: "managed".into(),
                        detail: format!("{shown}: saiife's entry is missing after the write"),
                    }
                })?;
                (sha, false)
            }
        };
        fsops::set_file_mode(&p, 0o644).map_err(step("managed"))?;
        self.chown_root(&p, "managed")?;
        self.record_agent(a, file_abs, sha, whole, !existed);
        self.save()
    }

    /// A reinstall without Claude removes the drop-in an earlier run wrote,
    /// and its entry in installed.toml.
    fn drop_stale_mcp(&mut self) -> Result<(), InstallError> {
        let path = Path::new(self.layout.logical(CLAUDE_MCP));
        if !self.rec.files.iter().any(|f| f.path == path) {
            return Ok(());
        }
        let p = self.at(CLAUDE_MCP);
        if fsops::remove_if_listed(&p).map_err(step("managed"))? {
            self.changed(format!("removed {}", path.display()));
        }
        self.rec.files.retain(|f| f.path != path);
        self.save()
    }

    /// The Claude Code MCP allowlist drop-in, from `[guard.mcp]` in the
    /// config as it is now (so the hook and Claude Code agree). An
    /// unreadable config leaves only `saiife` allowed, and says so.
    fn mcp_allowlist(&mut self) -> Result<(), InstallError> {
        let allow = match saiife_policy::load_system(&self.at(CONFIG)) {
            Ok(l) => l.config.guard.mcp.allow_servers,
            Err(e) => {
                self.report.warnings.push(format!(
                    "{}: the config could not be read ({e}); only the saiife MCP server is allowed",
                    self.layout.logical(CLAUDE_MCP)
                ));
                Vec::new()
            }
        };
        let text = claude::managed_mcp_settings(&allow);
        self.file(
            CLAUDE_MCP,
            text.as_bytes(),
            0o644,
            FileKind::Managed,
            "managed",
        )?;
        Ok(())
    }

    /// Records (or refreshes) a managed agent. `created_file` sticks from
    /// the first record.
    fn record_agent(&mut self, a: Agent, file_abs: &str, sha: String, whole: bool, created: bool) {
        let path = PathBuf::from(self.layout.logical(file_abs));
        match self.rec.agents.iter_mut().find(|m| m.agent == a.name()) {
            Some(m) => {
                m.sha256 = sha;
                m.path = path;
                m.whole_file = whole;
            }
            None => self.rec.agents.push(ManagedAgent {
                agent: a.name().to_string(),
                path,
                sha256: sha,
                whole_file: whole,
                created_file: created,
            }),
        }
    }

    // ------------------------------------------------ macOS

    /// Registers the authorization right [`authright::RIGHT`] unless
    /// `authorizationdb read` shows it with the settings it needs. A
    /// failure warns. Either way a new config keeps `same_user = "deny"`
    /// on macOS, and approvals need a second account.
    fn auth_right(&mut self) -> Result<(), InstallError> {
        use authright::{read_args, read_ok, write_args, RIGHT, RIGHT_PLIST};
        let current = self
            .host
            .run(SECURITY, &read_args(), MACOS_TOOL_TIMEOUT)
            .ok()
            .filter(|o| o.status == 0);
        if current.is_some_and(|o| read_ok(&o.stdout).is_ok()) {
            self.reauth = true;
            self.unchanged(format!("auth right {RIGHT}"));
            return Ok(());
        }
        let listed = self.rec.auth_rights.iter().any(|r| r == RIGHT);
        // Listed before it is written: a failure part-way is still undone
        // by uninstall.
        if !listed {
            self.rec.auth_rights.push(RIGHT.to_string());
            self.save()?;
        }
        let out = self.host.run_input(
            SECURITY,
            &write_args(),
            RIGHT_PLIST.as_bytes(),
            MACOS_TOOL_TIMEOUT,
        );
        let why = match out {
            Ok(o) if o.status == 0 => {
                self.reauth = true;
                self.changed(format!("auth right {RIGHT}"));
                return Ok(());
            }
            Ok(o) => format!("exited {}: {}", o.status, o.stderr.trim()),
            Err(e) => e.to_string(),
        };
        if !listed {
            self.rec.auth_rights.retain(|r| r != RIGHT);
            self.save()?;
        }
        self.reauth = false;
        self.report.warnings.push(format!(
            "{SECURITY} authorizationdb write {RIGHT} failed ({why}); {REAUTH_UNAVAILABLE}"
        ));
        Ok(())
    }

    /// The ids of a user and a group that must exist by now.
    fn ids(&self, user: &str, group: &str) -> Result<(u32, u32), InstallError> {
        let uid = self.host.user(user).map(|u| u.uid);
        let gid = self.host.group_id(group);
        match (uid, gid) {
            (Some(u), Some(g)) => Ok((u, g)),
            _ => Err(InstallError::Step {
                step: "owners".into(),
                detail: format!("user {user} or group {group} not found"),
            }),
        }
    }

    /// The paths launchd does not make for the daemon (spec §5.3, plan 13
    /// decision 2): the state and key dirs, the vault key, the socket dir,
    /// the log and audit dirs and `daemon.log`. Not listed in
    /// installed.toml (`--purge` removes them, as on Linux).
    ///
    /// The state dir is the daemon user's to write, so everything below
    /// the root-owned `/var/db` and `/var/log` is made and changed
    /// fd-relative: each entry is opened with `O_NOFOLLOW` from its
    /// parent's descriptor, checked on that descriptor (type, owner, link
    /// count), and its mode and owner are set on it (`fchmod`, `fchown`),
    /// never by path. A symlink or hard link the daemon user planted is
    /// refused, never chowned.
    fn macos_state(&mut self) -> Result<(), InstallError> {
        let user = self.layout.daemon_user();
        let daemon = self.ids(user, self.layout.daemon_group())?;
        let audit = self.ids(user, self.layout.audit_group())?;
        let root = self.root_ids()?;
        let allowed = [root.0, daemon.0];
        let db = self.root_parent(STATE_DIR)?;
        let state = self.owned_dir_at(&db, STATE_DIR, 0o700, daemon, &allowed)?;
        let keys = self.owned_dir_at(&state, KEYS_DIR, 0o700, daemon, &allowed)?;
        self.macos_vault_key(&keys, daemon, &allowed)?;
        let db = self.root_parent(RUN_DIR)?;
        self.owned_dir_at(&db, RUN_DIR, 0o755, daemon, &allowed)?;
        let var_log = self.root_parent(LOG_DIR)?;
        let log = self.owned_dir_at(&var_log, LOG_DIR, 0o755, root, &[root.0])?;
        self.owned_dir_at(&log, AUDIT_DIR, 0o2750, audit, &allowed)?;
        self.daemon_log(&log, audit, &allowed)
    }

    /// The root-owned parent of `abs` (`/var/db`, `/var/log`), checked as
    /// [`Run::dir`] checks it, then opened fd-relative from the root (below
    /// the trusted `/var` link).
    fn root_parent(&mut self, abs: &'static str) -> Result<OwnedFd, InstallError> {
        let parent = Path::new(self.layout.logical(abs))
            .parent()
            .and_then(Path::to_str)
            .unwrap_or("/");
        self.dir(parent, 0o755, false)?;
        let real = beneath_links(self.layout, self.host, Path::new(parent));
        let rel = real.strip_prefix("/").unwrap_or(&real);
        let shown = self
            .layout
            .try_at(&real)
            .map_err(|e| refused(&real, e.to_string()))?;
        fsops::open_dir_beneath(self.layout.root(), rel)
            .map_err(|e| refused(&shown, e.to_string()))?
            .ok_or_else(|| refused(&shown, "disappeared"))
    }

    /// Ensures the directory `abs` in the open `parent` with `mode` and
    /// `owner`, fd-relative. An existing one must be a directory (never a
    /// symlink) owned by one of `allowed`; it gets `mode` and `owner`.
    /// Returns it, open.
    fn owned_dir_at(
        &mut self,
        parent: &OwnedFd,
        abs: &'static str,
        mode: u32,
        owner: (u32, u32),
        allowed: &[u32],
    ) -> Result<OwnedFd, InstallError> {
        use rustix::fs::{AtFlags, FileType, Mode, OFlags};
        let logical = self.layout.logical(abs);
        let name = Path::new(logical).file_name().unwrap_or_default();
        let p = self.at(abs);
        let bad = |e: rustix::io::Errno| refused(&p, io::Error::from(e).to_string());
        let created = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) if FileType::from_raw_mode(st.st_mode) != FileType::Directory => {
                return Err(refused(
                    &p,
                    "exists and is not a directory (or is a symlink)",
                ))
            }
            Ok(_) => false,
            Err(rustix::io::Errno::NOENT) => {
                rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)).map_err(bad)?;
                true
            }
            Err(e) => return Err(bad(e)),
        };
        let fd = rustix::fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(bad)?;
        let st = rustix::fs::fstat(&fd).map_err(bad)?;
        let (uid, before, is_dir) = fsops::stat_owner_mode(&st);
        if !is_dir {
            return Err(refused(&p, "is not a directory"));
        }
        // Checked on a fresh dir too: the one opened must be the one made.
        if !allowed.contains(&uid) {
            return Err(refused(
                &p,
                format!("exists and is owned by uid {uid}; saiife does not adopt it (move it away first)"),
            ));
        }
        // Owner first, then mode: XNU's chown clears the setgid bit (even
        // for root), so a chmod before it left the audit dir 0750, not
        // 2750 (seen on the macos-15 runners).
        self.host
            .fchown(fd.as_fd(), &p, owner.0, owner.1)
            .map_err(step("dirs"))?;
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(mode as _)).map_err(bad)?;
        if created {
            self.changed(logical);
        } else if before != mode {
            self.changed(format!("{logical} (mode {mode:o})"));
        }
        Ok(fd)
    }

    /// The macOS vault key in the open key dir: 32 random bytes, 0400,
    /// owned by the daemon user (the daemon reads it itself). Never
    /// rotated. A new key is made with `O_CREAT|O_EXCL|O_NOFOLLOW`; an
    /// existing one must be a regular file with one link, 32 bytes, owned
    /// by root or the daemon user. Mode and owner are set on the open file.
    fn macos_vault_key(
        &mut self,
        keys: &OwnedFd,
        owner: (u32, u32),
        allowed: &[u32],
    ) -> Result<(), InstallError> {
        use std::io::Write;
        let p = self.at(VAULT_KEY);
        let shown = self.layout.logical(VAULT_KEY);
        let name = Path::new(shown).file_name().unwrap_or_default();
        let existing = open_daemon_file(keys, name, &p, Some(32), allowed)?;
        // Listed before it is made, never with a digest.
        self.record_file(VAULT_KEY, FileKind::VaultKey, None, existing.is_none());
        self.save()?;
        let fd = match existing {
            Some(fd) => {
                self.unchanged(shown);
                fd
            }
            None => {
                let fd = create_daemon_file(keys, name, &p, 0o400)?;
                let mut key = Zeroizing::new([0u8; 32]);
                getrandom::fill(&mut key[..]).map_err(|e| InstallError::Step {
                    step: "vault-key".into(),
                    detail: e.to_string(),
                })?;
                let mut f = std::fs::File::from(fd);
                if let Err(e) = f.write_all(&key[..]).and_then(|_| f.sync_all()) {
                    // Never leave a short key behind (it would be adopted
                    // as is on the next run): unlinked fd-relative.
                    let _ = rustix::fs::unlinkat(keys, name, rustix::fs::AtFlags::empty());
                    return Err(step("vault-key")(e));
                }
                self.changed(shown);
                OwnedFd::from(f)
            }
        };
        set_mode_fd(&fd, &p, 0o400)?;
        self.host
            .fchown(fd.as_fd(), &p, owner.0, owner.1)
            .map_err(step("vault-key"))
    }

    /// `daemon.log` in the open log dir, the daemon's stderr (launchd opens
    /// it as root and would make it 0644 root otherwise). Checked and
    /// changed on the open file, as the vault key is.
    fn daemon_log(
        &mut self,
        log: &OwnedFd,
        owner: (u32, u32),
        allowed: &[u32],
    ) -> Result<(), InstallError> {
        let p = self.at(DAEMON_LOG);
        let name = Path::new(DAEMON_LOG).file_name().unwrap_or_default();
        let fd = match open_daemon_file(log, name, &p, None, allowed)? {
            Some(fd) => {
                let st = rustix::fs::fstat(&fd).map_err(|e| refused(&p, e.to_string()))?;
                if fsops::stat_owner_mode(&st).1 != 0o640 {
                    self.changed(format!("{DAEMON_LOG} (mode 640)"));
                }
                fd
            }
            None => {
                let fd = create_daemon_file(log, name, &p, 0o640)?;
                self.changed(DAEMON_LOG);
                fd
            }
        };
        set_mode_fd(&fd, &p, 0o640)?;
        self.host
            .fchown(fd.as_fd(), &p, owner.0, owner.1)
            .map_err(step("log"))
    }

    /// The launchd plist (root:wheel 0644). True when written.
    fn plist(&mut self) -> Result<bool, InstallError> {
        let plist_dir = Path::new(self.layout.logical(UNIT))
            .parent()
            .and_then(Path::to_str)
            .unwrap_or("/");
        self.dir(plist_dir, 0o755, false)?;
        self.file(
            UNIT,
            launchd::plist_text().as_bytes(),
            0o644,
            FileKind::Unit,
            "unit",
        )
    }

    /// Starts the daemon. A loaded job is restarted in place
    /// (`kickstart -k`) when the binary or a membership changed; when the
    /// plist changed it is reloaded (`bootout`, `enable`, `bootstrap`). A
    /// job not loaded is enabled and bootstrapped. A loaded job whose only
    /// change is `config_changed` is asked to load it (`policy.reload`
    /// over its socket, as on Linux after `systemctl reload`).
    fn start_macos(
        &mut self,
        changed: bool,
        plist_changed: bool,
        config_changed: bool,
    ) -> Result<(), InstallError> {
        let plist = self.at(UNIT).to_string_lossy().into_owned();
        let launchctl = |args: &[&str]| -> Result<(), InstallError> {
            let fail = |detail: String| InstallError::Step {
                step: "start".into(),
                detail: format!("{detail} (see {DAEMON_LOG})"),
            };
            let out = self.host.launchctl(args).map_err(|e| fail(e.to_string()))?;
            if out.status != 0 {
                let msg = out.stderr.trim();
                return Err(fail(if msg.is_empty() {
                    format!("launchctl {} exited {}", args.join(" "), out.status)
                } else {
                    msg.to_string()
                }));
            }
            Ok(())
        };
        let loaded = self
            .host
            .launchctl(&["print", launchd::SERVICE])
            .is_ok_and(|o| o.status == 0);
        if loaded && !plist_changed {
            if changed {
                launchctl(&["kickstart", "-k", launchd::SERVICE])?;
            } else if config_changed {
                self.confirm_reload();
            }
            return Ok(());
        }
        // A loaded job keeps the plist it was bootstrapped with: take it
        // out first. `enable` comes before `bootstrap`, so a job disabled
        // earlier is loaded at all.
        if loaded {
            launchctl(&["bootout", launchd::SERVICE])?;
        }
        launchctl(&["enable", launchd::SERVICE])?;
        launchctl(&["bootstrap", "system", &plist])
    }

    /// Starts the daemon, or restarts it when `changed` (binary, unit or
    /// membership). A running daemon whose only change is `config_changed`
    /// is reloaded instead.
    fn start(&mut self, changed: bool, config_changed: bool) -> Result<(), InstallError> {
        let fail = |detail: String| InstallError::Step {
            step: "start".into(),
            detail: format!("{detail} (see: journalctl -u saiifed)"),
        };
        let reload = self
            .host
            .systemctl(&["daemon-reload"])
            .map_err(|e| fail(e.to_string()))?;
        if reload.status != 0 {
            return Err(fail(reload.stderr.trim().to_string()));
        }
        let active = self
            .host
            .systemctl(&["is-active", UNIT_NAME])
            .is_ok_and(|o| o.status == 0 && o.stdout.trim() == "active");
        let reloading = !changed && config_changed && active;
        let args: &[&str] = if changed && active {
            &["restart", UNIT_NAME]
        } else if reloading {
            &["reload", UNIT_NAME]
        } else {
            &["enable", "--now", UNIT_NAME]
        };
        let out = self.host.systemctl(args).map_err(|e| fail(e.to_string()))?;
        if out.status != 0 {
            let msg = out.stderr.trim();
            return Err(fail(if msg.is_empty() {
                format!("systemctl {} exited {}", args.join(" "), out.status)
            } else {
                msg.to_string()
            }));
        }
        if reloading {
            self.confirm_reload();
        }
        Ok(())
    }

    /// `systemctl reload` only sends SIGHUP: the daemon may still reject
    /// the new config and keep the old policy. `policy.reload` loads it
    /// again and answers synchronously (it waits for the SIGHUP reload to
    /// finish), so its answer says what the daemon enforces now.
    fn confirm_reload(&mut self) {
        // The platform's daemon user and socket dir (`_saiife` and
        // `/var/db/saiife-run` on macOS: `at` maps RUN_DIR).
        let user = self.layout.daemon_user();
        let log = if self.layout.platform() == Platform::Macos {
            format!("see {DAEMON_LOG}")
        } else {
            "see: journalctl -u saiifed".to_string()
        };
        let why = match self.host.user(user) {
            None => format!("user {user} not found"),
            Some(u) => match self
                .host
                .policy_reload(&self.at(RUN_DIR), u.uid, RELOAD_WAIT)
            {
                Ok(a) if a.loaded => {
                    self.report.policy_hash = a.hash;
                    return;
                }
                Ok(a) => format!(
                    "it rejected the new config and keeps the old policy: {}",
                    a.reason
                ),
                Err(e) => format!("it did not confirm the reload: {e}"),
            },
        };
        self.report.reload_problem = Some(format!("{RELOAD_NOT_TAKEN} ({CONFIG}): {why} ({log})"));
    }
}

// Locked mode is Linux-only: on macOS `check_supported` refuses every
// install (spec §0 decision 8), so these tests run on Linux only.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use crate::host::{CmdOutput, FakeHost, UserInfo};
    use saiife_policy::installed::{read_installed, FileKind, Installed, VaultKeyMode};
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) struct Env {
        /// Keeps the root alive.
        pub _dir: tempfile::TempDir,
        pub src: tempfile::TempDir,
        pub layout: Layout,
        pub host: FakeHost,
        pub binary: PathBuf,
    }

    impl Env {
        pub fn at(&self, abs: &str) -> PathBuf {
            self.layout.at(abs)
        }
        pub fn installed(&self) -> Installed {
            read_installed(&self.at(INSTALLED)).unwrap().unwrap()
        }
        pub fn run(&self, opts: &InstallOptions) -> Result<InstallReport, InstallError> {
            install(&self.layout, &self.host, opts, &self.binary)
        }
        pub fn install(&self) -> InstallReport {
            self.run(&all_agents()).unwrap()
        }
        /// Every path below the root, relative, dirs included.
        pub fn tree(&self) -> BTreeSet<String> {
            fn walk(base: &Path, d: &Path, out: &mut BTreeSet<String>) {
                for e in fs::read_dir(d).unwrap() {
                    let p = e.unwrap().path();
                    out.insert(p.strip_prefix(base).unwrap().to_string_lossy().into_owned());
                    if p.symlink_metadata().unwrap().is_dir() {
                        walk(base, &p, out);
                    }
                }
            }
            let mut out = BTreeSet::new();
            walk(self.layout.root(), self.layout.root(), &mut out);
            out
        }
    }

    /// A stand-in `pkcheck` in the fake root (never run).
    pub(crate) fn add_pkcheck(e: &Env) {
        let p = e.at(PKCHECK);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        let d = e.at(crate::polkit::POLKITD_PATHS[0]);
        fs::create_dir_all(d.parent().unwrap()).unwrap();
        fs::write(&d, b"polkitd").unwrap();
    }

    #[test]
    fn polkit_needs_polkitd_and_a_sound_pkcheck() {
        let e = env(255);
        assert!(!polkit_present(&e.layout, &e.host));
        add_pkcheck(&e);
        assert!(polkit_present(&e.layout, &e.host));
        // Group-writable pkcheck.
        fs::set_permissions(e.at(PKCHECK), fs::Permissions::from_mode(0o775)).unwrap();
        assert!(!polkit_present(&e.layout, &e.host));
        fs::set_permissions(e.at(PKCHECK), fs::Permissions::from_mode(0o755)).unwrap();
        // Not root's.
        let uid = e.host.user("root").unwrap().uid;
        crate::testing::set_root_uid(&e.host, uid + 1);
        assert!(!polkit_present(&e.layout, &e.host));
        crate::testing::set_root_uid(&e.host, uid);
        // No polkitd.
        fs::remove_file(e.at(crate::polkit::POLKITD_PATHS[0])).unwrap();
        assert!(!polkit_present(&e.layout, &e.host));
    }

    #[test]
    fn pkcheck_without_polkitd_chooses_deny_and_warns() {
        let e = env(255);
        add_pkcheck(&e);
        fs::remove_file(e.at(crate::polkit::POLKITD_PATHS[0])).unwrap();
        let r = e.install();
        assert!(!e.at(POLKIT_ACTION).exists());
        assert!(r.warnings.iter().any(|w| w == REAUTH_UNAVAILABLE));
    }

    #[test]
    fn warns_on_every_path_without_polkit() {
        let e = env(255);
        e.install();
        // Existing config, second run.
        let r = e.install();
        assert!(r.warnings.iter().any(|w| w == REAUTH_UNAVAILABLE), "{r:?}");
        // --config: the admin's file is kept, the warning still shows.
        let cfg = e.src.path().join("c.toml");
        fs::write(&cfg, fs::read_to_string(e.at(CONFIG)).unwrap()).unwrap();
        let mut o = all_agents();
        o.config = Some(cfg);
        let r = e.run(&o).unwrap();
        assert!(r.warnings.iter().any(|w| w == REAUTH_UNAVAILABLE), "{r:?}");
    }

    #[test]
    fn install_writes_polkit_action_when_pkcheck_present() {
        let e = env(255);
        add_pkcheck(&e);
        let r = e.install();
        let p = e.at(POLKIT_ACTION);
        assert_eq!(fs::read_to_string(&p).unwrap(), POLKIT_POLICY);
        assert_eq!(mode(&p), 0o644);
        assert_eq!(chowned(&e.host, &p), vec![root_ids(&e.host)]);
        let rec = e.installed();
        let f = rec
            .files
            .iter()
            .find(|f| f.path == Path::new(POLKIT_ACTION))
            .unwrap();
        assert_eq!(f.kind, FileKind::Polkit);
        assert!(f.created);
        assert!(f.sha256.is_some());
        let cfg = fs::read_to_string(e.at(CONFIG)).unwrap();
        assert!(cfg.contains("same_user = \"reauth\"\n"), "{cfg}");
        assert!(!r.warnings.iter().any(|w| w == REAUTH_UNAVAILABLE));
        // Idempotent.
        let again = e.install();
        assert!(again.unchanged.iter().any(|u| u == POLKIT_ACTION));
    }

    /// A 0777 `/usr/share` (as on some CI runners) does not abort the
    /// install: the action is skipped, a new config says `deny`, and the
    /// warning says why.
    #[test]
    fn unsafe_polkit_parent_skips_the_action_and_warns() {
        let e = env(255);
        add_pkcheck(&e);
        let share = e.at("/usr/share");
        fs::create_dir_all(&share).unwrap();
        fs::set_permissions(&share, fs::Permissions::from_mode(0o777)).unwrap();
        let r = e.install();
        assert!(!e.at(POLKIT_ACTION).exists());
        assert!(!e.at("/usr/share/polkit-1").exists());
        assert!(!e
            .installed()
            .files
            .iter()
            .any(|f| f.kind == FileKind::Polkit));
        let cfg = fs::read_to_string(e.at(CONFIG)).unwrap();
        assert!(cfg.contains("# same_user = \"deny\"\n"), "{cfg}");
        assert!(
            r.warnings.iter().any(|w| w
                == "polkit action not installed: /usr/share is writable by group or others; approvals need a second account"),
            "{r:?}"
        );
        assert!(!r.warnings.iter().any(|w| w == REAUTH_UNAVAILABLE), "{r:?}");
        // A safe parent again: the action is written.
        fs::set_permissions(&share, fs::Permissions::from_mode(0o755)).unwrap();
        let r = e.install();
        assert!(e.at(POLKIT_ACTION).exists());
        assert!(
            !r.warnings.iter().any(|w| w.starts_with("polkit action")),
            "{r:?}"
        );
    }

    #[test]
    fn install_skips_and_sets_deny_without_pkcheck() {
        let e = env(255);
        let r = e.install();
        assert!(!e.at(POLKIT_ACTION).exists());
        assert!(!e
            .installed()
            .files
            .iter()
            .any(|f| f.kind == FileKind::Polkit));
        let cfg = fs::read_to_string(e.at(CONFIG)).unwrap();
        assert!(cfg.contains("# same_user = \"deny\"\n"), "{cfg}");
        assert!(r.warnings.iter().any(|w| w == REAUTH_UNAVAILABLE), "{r:?}");
    }

    #[test]
    fn action_file_never_auth_self_keep() {
        assert!(!POLKIT_POLICY.contains("auth_self_keep"));
        assert!(!POLKIT_POLICY.contains("auth_admin"));
        for k in ["allow_any", "allow_inactive", "allow_active"] {
            assert!(
                POLKIT_POLICY.contains(&format!("<{k}>auth_self</{k}>")),
                "{k}"
            );
        }
        assert!(POLKIT_POLICY.contains("<action id=\"com.saiife.approve\">"));
    }

    pub(crate) const UBUNTU_2404: &str =
        "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n";

    pub(crate) fn env(systemd: u32) -> Env {
        env_with(systemd, UBUNTU_2404)
    }

    pub(crate) fn env_with(systemd: u32, os_release: &str) -> Env {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        fs::write(dir.path().join("etc/os-release"), os_release).unwrap();
        fs::create_dir_all(dir.path().join("run/systemd/system")).unwrap();
        let layout = Layout::under(dir.path());
        let host = FakeHost::open(layout.root()).unwrap();
        host.set(|s| s.systemd = systemd);
        let src = tempfile::tempdir().unwrap();
        let binary = src.path().join("saiife");
        fs::write(&binary, crate::binary::fake_elf(None, 0, Some(false))).unwrap();
        Env {
            _dir: dir,
            src,
            layout,
            host,
            binary,
        }
    }

    pub(crate) fn all_agents() -> InstallOptions {
        InstallOptions {
            config: None,
            agents: Agent::ALL.to_vec(),
            approvers: Vec::new(),
            non_interactive: true,
            allow_test_build: false,
        }
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn root_ids(h: &FakeHost) -> (u32, u32) {
        (h.user("root").unwrap().uid, h.group_id("root").unwrap())
    }

    fn chowned(h: &FakeHost, p: &Path) -> Vec<(u32, u32)> {
        h.state()
            .chowns
            .iter()
            .filter(|c| c.path == p)
            .map(|c| (c.uid, c.gid))
            .collect()
    }

    const ROOT_OWNED: &[(&str, u32)] = &[
        ("/opt/saiife", 0o755),
        ("/opt/saiife/bin", 0o755),
        ("/opt/saiife/bin/saiife", 0o755),
        ("/etc/saiife", 0o755),
        ("/etc/saiife/policy.d", 0o755),
        ("/etc/saiife/config.toml", 0o644),
        ("/etc/saiife/installed.toml", 0o644),
        ("/etc/saiife/credstore", 0o700),
        ("/etc/saiife/credstore/vault-key", 0o600),
        ("/etc/systemd/system/saiifed.service", 0o644),
        ("/etc/claude-code/managed-settings.d", 0o755),
        ("/etc/claude-code/managed-settings.d/50-saiife.json", 0o644),
        (
            "/etc/claude-code/managed-settings.d/60-saiife-mcp.json",
            0o644,
        ),
        ("/etc/codex", 0o755),
        ("/etc/codex/requirements.toml", 0o644),
        ("/etc/gemini-cli", 0o755),
        ("/etc/gemini-cli/settings.json", 0o644),
    ];

    #[test]
    fn fresh_install_writes_every_path_with_spec_modes() {
        let e = env(255);
        let r = e.install();
        assert!(r.started);
        let root = root_ids(&e.host);
        for (abs, want) in ROOT_OWNED {
            let p = e.at(abs);
            assert!(p.exists(), "{abs} missing");
            assert_eq!(mode(&p), *want, "{abs} mode {:o}", mode(&p));
            let c = chowned(&e.host, &p);
            assert!(
                !c.is_empty() && c.iter().all(|x| *x == root),
                "{abs}: {c:?}"
            );
        }
        assert_eq!(
            fs::read(e.at(BINARY)).unwrap(),
            fs::read(&e.binary).unwrap()
        );
        // No pkcheck in the fake root: the only warning is about reauth.
        assert_eq!(r.warnings, [REAUTH_UNAVAILABLE], "{:?}", r.warnings);
        assert_eq!(
            fs::read_to_string(e.at(UNIT)).unwrap(),
            crate::unit_text(255)
        );
        assert_eq!(
            fs::read_to_string(e.at(CLAUDE_MANAGED)).unwrap(),
            saiife_agents::claude::managed_settings()
        );
        let cfg = fs::read_to_string(e.at(CONFIG)).unwrap();
        assert!(cfg.starts_with("version = 2\nlocked = true\n"));
        saiife_policy::load_system(&e.at(CONFIG)).unwrap();
        // systemd creates the state, run and log dirs.
        for abs in [STATE_DIR, RUN_DIR, LOG_DIR] {
            assert!(!e.at(abs).exists(), "{abs}");
        }
        // Users, groups and the audit-group membership.
        let s = e.host.state();
        assert!(s.users.contains_key(DAEMON_USER));
        assert!(s.groups.contains_key(DAEMON_GROUP) && s.groups.contains_key(AUDIT_GROUP));
        assert_eq!(s.members[AUDIT_GROUP], vec![DAEMON_USER.to_string()]);
        assert!(s.calls.contains(&"systemctl daemon-reload".to_string()));
        assert!(s
            .calls
            .contains(&"systemctl enable --now saiifed.service".to_string()));
        assert!(r
            .changed
            .iter()
            .any(|c| c.contains("/opt/saiife/bin/saiife")));
    }

    #[test]
    fn systemd_249_writes_plain_vault_key_and_load_credential() {
        let e = env(249);
        e.install();
        let vk = e.at(VAULT_KEY);
        assert_eq!(mode(&vk), 0o640);
        assert_eq!(fs::read(&vk).unwrap().len(), 32);
        let want = (
            e.host.user("root").unwrap().uid,
            e.host.group_id(DAEMON_GROUP).unwrap(),
        );
        assert_eq!(chowned(&e.host, &vk), vec![want]);
        let unit = fs::read_to_string(e.at(UNIT)).unwrap();
        assert!(unit.contains("\nLoadCredential=vault-key:"), "{unit}");
        assert!(!unit.contains("LoadCredentialEncrypted"));
        assert_eq!(e.installed().vault_key, VaultKeyMode::File);
        assert!(!e
            .host
            .state()
            .calls
            .iter()
            .any(|c| c.contains("systemd-creds")));
    }

    #[test]
    fn systemd_255_encrypts_vault_key() {
        let e = env(255);
        e.install();
        assert!(e
            .host
            .state()
            .calls
            .iter()
            .any(|c| c.starts_with("systemd-creds encrypt --name=vault-key")));
        assert_eq!(mode(&e.at(VAULT_KEY)), 0o600);
        assert_eq!(e.installed().vault_key, VaultKeyMode::Credential);
        assert!(fs::read_to_string(e.at(UNIT))
            .unwrap()
            .contains("\nLoadCredentialEncrypted=vault-key:"));
    }

    #[test]
    fn vault_key_is_never_rotated() {
        let e = env(249);
        e.install();
        let before = fs::read(e.at(VAULT_KEY)).unwrap();
        e.install();
        assert_eq!(fs::read(e.at(VAULT_KEY)).unwrap(), before);
    }

    #[test]
    fn installed_toml_lists_everything_with_fingerprints() {
        let e = env(255);
        e.install();
        let i = e.installed();
        assert_eq!(i.systemd, 255);
        assert_eq!(i.users, ["saiife"]);
        assert_eq!(i.groups, ["saiife", "saiife-audit"]);
        assert_eq!(i.memberships.len(), 1);
        assert_eq!(
            (
                i.memberships[0].user.as_str(),
                i.memberships[0].group.as_str()
            ),
            ("saiife", "saiife-audit")
        );
        let file = |k: FileKind| i.files.iter().find(|f| f.kind == k).unwrap().clone();
        for (k, abs) in [
            (FileKind::Binary, BINARY),
            (FileKind::Unit, UNIT),
            (FileKind::Config, CONFIG),
        ] {
            let f = file(k);
            assert_eq!(f.path, Path::new(abs));
            assert!(f.created);
            assert_eq!(
                f.sha256.unwrap(),
                crate::fsops::sha256_file(&e.at(abs)).unwrap().unwrap(),
                "{abs}"
            );
        }
        // The vault key is listed without a digest (installed.toml is 0644).
        let vk = file(FileKind::VaultKey);
        assert_eq!(vk.path, Path::new(VAULT_KEY));
        assert!(vk.created && vk.sha256.is_none());
        let key_sha = crate::fsops::sha256_file(&e.at(VAULT_KEY))
            .unwrap()
            .unwrap();
        assert!(!fs::read_to_string(e.at(INSTALLED))
            .unwrap()
            .contains(&key_sha));
        assert_eq!(i.agents.len(), 3);
        for a in &i.agents {
            let p = e.layout.try_at(&a.path).unwrap();
            let want = match a.agent.as_str() {
                "claude" => crate::fsops::sha256_file(&p).unwrap().unwrap(),
                "codex" => saiife_agents::codex::managed_entry(&p).unwrap().unwrap(),
                "gemini" => saiife_agents::gemini::managed_entry(&p).unwrap().unwrap(),
                o => panic!("{o}"),
            };
            assert_eq!(a.sha256, want, "{}", a.agent);
            assert!(a.created_file);
            assert_eq!(a.whole_file, a.agent == "claude");
        }
        // Dirs are logical paths, in creation order, parents first.
        let pos = |d: &str| i.dirs.iter().position(|x| x == Path::new(d)).unwrap();
        assert!(pos("/opt/saiife") < pos("/opt/saiife/bin"));
        assert!(pos("/etc/saiife") < pos("/etc/saiife/policy.d"));
        assert!(i
            .dirs
            .iter()
            .all(|d| d.is_absolute() && !d.starts_with(e.layout.root())));
    }

    #[test]
    fn second_install_is_unchanged_and_keeps_config() {
        let e = env(255);
        e.install();
        let edited = "version = 2\nlocked = true\n\n[guard]\nbudget_ms = 40\n";
        fs::write(e.at(CONFIG), edited).unwrap();
        let before = e.installed();
        e.host.set(|s| s.calls.clear());
        let r = e.install();
        assert!(r.changed.is_empty(), "{:?}", r.changed);
        assert!(r.started);
        assert_eq!(fs::read_to_string(e.at(CONFIG)).unwrap(), edited);
        let calls = e.host.state().calls;
        assert!(calls.contains(&"systemctl enable --now saiifed.service".to_string()));
        assert!(!calls.iter().any(|c| c.contains("restart")), "{calls:?}");
        let after = e.installed();
        assert_eq!(after.users, before.users);
        assert_eq!(after.dirs, before.dirs);
        assert!(after.files.iter().all(|f| f.created));
        assert!(after.agents.iter().all(|a| a.created_file));
    }

    #[test]
    fn install_writes_mcp_dropin_from_policy() {
        let e = env(255);
        e.install();
        // The default config lists no servers: only `saiife`.
        assert_eq!(
            fs::read_to_string(e.at(CLAUDE_MCP)).unwrap(),
            "{\n  \"allowedMcpServers\": [\n    {\n      \"serverCommand\": [\n        \"/opt/saiife/bin/saiife\",\n        \"mcp\"\n      ]\n    }\n  ]\n}\n"
        );
        let cfg =
            "version = 2\nlocked = true\n\n[guard.mcp]\nallow_servers = [\"github\", \"jira\"]\n";
        fs::write(e.at(CONFIG), cfg).unwrap();
        e.install();
        let v: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(e.at(CLAUDE_MCP)).unwrap()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"allowedMcpServers": [
                {"serverCommand": [BINARY, "mcp"]},
                {"serverName": "github"}, {"serverName": "jira"}
            ]})
        );
        let f = e
            .installed()
            .files
            .into_iter()
            .find(|f| f.path == Path::new(CLAUDE_MCP))
            .unwrap();
        assert_eq!(f.kind, FileKind::Managed);
        assert!(f.created);
        assert_eq!(
            f.sha256.unwrap(),
            crate::fsops::sha256_file(&e.at(CLAUDE_MCP))
                .unwrap()
                .unwrap()
        );
    }

    #[test]
    fn dropin_pins_saiife_by_command_not_name() {
        let e = env(255);
        e.install();
        let text = fs::read_to_string(e.at(CLAUDE_MCP)).unwrap();
        assert!(text.contains("\"serverCommand\""), "{text}");
        assert!(!text.contains("\"serverName\": \"saiife\""), "{text}");
    }

    #[test]
    fn reinstall_without_claude_removes_stale_dropin() {
        let e = env(255);
        e.install();
        assert!(e.at(CLAUDE_MCP).exists());
        let mut o = all_agents();
        o.agents = vec![Agent::Codex];
        e.run(&o).unwrap();
        assert!(!e.at(CLAUDE_MCP).exists());
        assert!(!e
            .installed()
            .files
            .iter()
            .any(|f| f.path == Path::new(CLAUDE_MCP)));
    }

    #[test]
    fn install_without_claude_writes_no_dropin() {
        let e = env(255);
        let mut o = all_agents();
        o.agents = vec![Agent::Codex, Agent::Gemini];
        e.run(&o).unwrap();
        assert!(!e.at(CLAUDE_MCP).exists());
        assert!(!e
            .installed()
            .files
            .iter()
            .any(|f| f.path == Path::new(CLAUDE_MCP)));
    }

    #[test]
    fn second_install_unchanged() {
        let e = env(255);
        e.install();
        let r = e.install();
        assert!(r.changed.is_empty(), "{:?}", r.changed);
        assert!(
            r.unchanged.iter().any(|u| u == CLAUDE_MCP),
            "{:?}",
            r.unchanged
        );
    }

    fn set_active(h: &FakeHost) {
        h.set(|s| {
            s.run.insert(
                "systemctl is-active saiifed.service".into(),
                CmdOutput {
                    status: 0,
                    stdout: "active\n".into(),
                    stderr: String::new(),
                },
            );
        });
    }

    #[test]
    fn binary_change_restarts() {
        let e = env(255);
        e.install();
        set_active(&e.host);
        // Same binary while active: no restart.
        e.host.set(|s| s.calls.clear());
        e.install();
        assert!(!e.host.state().calls.iter().any(|c| c.contains("restart")));
        let mut v2 = crate::binary::fake_elf(None, 0, Some(false));
        v2.extend_from_slice(b"v2");
        fs::write(&e.binary, &v2).unwrap();
        e.host.set(|s| s.calls.clear());
        let r = e.install();
        let calls = e.host.state().calls;
        assert!(
            calls.contains(&"systemctl restart saiifed.service".to_string()),
            "{calls:?}"
        );
        assert!(!calls.iter().any(|c| c.contains("enable --now")));
        assert_eq!(fs::read(e.at(BINARY)).unwrap(), v2);
        assert_eq!(r.changed, vec!["/opt/saiife/bin/saiife".to_string()]);
    }

    fn config_file(e: &Env, name: &str, budget: u32) -> InstallOptions {
        let p = e.src.path().join(name);
        fs::write(
            &p,
            format!("version = 2\nlocked = true\n\n[guard]\nbudget_ms = {budget}\n"),
        )
        .unwrap();
        let mut o = all_agents();
        o.config = Some(p);
        o
    }

    #[test]
    fn no_agents_warns() {
        let e = env(255);
        let mut o = all_agents();
        o.agents = Vec::new();
        let r = e.run(&o).unwrap();
        assert!(
            r.warnings.contains(&NO_AGENTS.to_string()),
            "{:?}",
            r.warnings
        );
        assert!(!e.at(CLAUDE_MANAGED).exists());
        let r = e.install();
        assert!(
            !r.warnings.contains(&NO_AGENTS.to_string()),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn config_change_reloads_running_daemon() {
        let e = env(255);
        e.run(&config_file(&e, "a.toml", 30)).unwrap();
        set_active(&e.host);
        e.host.set(|s| s.calls.clear());
        let r = e.run(&config_file(&e, "b.toml", 40)).unwrap();
        assert_eq!(r.changed, vec![CONFIG.to_string()]);
        let calls = e.host.state().calls;
        assert!(
            calls.contains(&"systemctl reload saiifed.service".to_string()),
            "{calls:?}"
        );
        assert!(!calls.iter().any(|c| c.contains("restart")), "{calls:?}");
        // The reload is confirmed over the socket, after the SIGHUP.
        let pos = |want: &str| calls.iter().position(|c| c.starts_with(want));
        let ipc = pos("ipc policy.reload ").expect("policy.reload call");
        assert!(pos("systemctl reload").unwrap() < ipc, "{calls:?}");
        assert!(
            calls[ipc].contains(&e.at(RUN_DIR).display().to_string()),
            "{calls:?}"
        );
        assert_eq!(r.policy_hash.as_deref(), Some("fake"));
        assert_eq!(r.reload_problem, None);
        // Not running: a new config is a plain start, never a reload.
        let e = env(255);
        e.run(&config_file(&e, "a.toml", 30)).unwrap();
        e.host.set(|s| s.calls.clear());
        e.run(&config_file(&e, "b.toml", 40)).unwrap();
        let calls = e.host.state().calls;
        assert!(
            !calls.iter().any(|c| c.contains("reload saiifed")),
            "{calls:?}"
        );
        assert!(
            calls.contains(&"systemctl enable --now saiifed.service".to_string()),
            "{calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("ipc policy.reload")),
            "{calls:?}"
        );
    }

    #[test]
    fn rejected_reload_is_reported() {
        let e = env(255);
        e.run(&config_file(&e, "a.toml", 30)).unwrap();
        set_active(&e.host);
        e.host.set(|s| {
            s.policy_reload = crate::host::ReloadAnswer {
                loaded: false,
                reason: "bad drop-in".into(),
                hash: Some("old".into()),
            }
        });
        let r = e.run(&config_file(&e, "b.toml", 40)).unwrap();
        let p = r.reload_problem.expect("a reload problem");
        assert!(p.starts_with(RELOAD_NOT_TAKEN), "{p}");
        assert!(p.contains("rejected the new config"), "{p}");
        assert!(p.contains("bad drop-in"), "{p}");
        assert_eq!(r.policy_hash, None);
        // Installed all the same: the new config is in place.
        assert!(fs::read_to_string(e.at(CONFIG)).unwrap().contains("40"));
    }

    #[test]
    fn unanswered_reload_is_reported() {
        let e = env(255);
        e.run(&config_file(&e, "a.toml", 30)).unwrap();
        set_active(&e.host);
        e.host
            .set(|s| s.policy_reload_error = Some("no answer within 15 s".into()));
        let r = e.run(&config_file(&e, "b.toml", 40)).unwrap();
        let p = r.reload_problem.expect("a reload problem");
        assert!(p.starts_with(RELOAD_NOT_TAKEN), "{p}");
        assert!(p.contains("did not confirm the reload: no answer"), "{p}");
        // A restart (binary changed) needs no confirmation: the daemon
        // starts on the new config or not at all.
        let e = env(255);
        e.run(&config_file(&e, "a.toml", 30)).unwrap();
        set_active(&e.host);
        e.host
            .set(|s| s.policy_reload_error = Some("unreachable".into()));
        let mut v2 = crate::binary::fake_elf(None, 0, Some(false));
        v2.extend_from_slice(b"v2");
        fs::write(&e.binary, &v2).unwrap();
        let r = e.run(&config_file(&e, "b.toml", 40)).unwrap();
        assert_eq!(r.reload_problem, None);
    }

    /// The config is checked with the drop-ins the daemon will load: the
    /// live policy.d, not one beside the source file.
    #[test]
    fn config_checked_against_the_live_policy_d() {
        let e = env(255);
        e.install();
        let bad = "this is = not toml [\n";
        fs::write(e.at(POLICY_D).join("50-bad.toml"), bad).unwrap();
        let err = e.run(&config_file(&e, "a.toml", 30)).unwrap_err();
        assert!(err.to_string().contains("50-bad.toml"), "{err}");
        fs::remove_file(e.at(POLICY_D).join("50-bad.toml")).unwrap();
        // A broken policy.d beside the source config is not what the
        // daemon loads: it does not matter.
        let side = e.src.path().join("policy.d");
        fs::create_dir_all(&side).unwrap();
        fs::write(side.join("50-bad.toml"), bad).unwrap();
        e.run(&config_file(&e, "a.toml", 30)).unwrap();
    }

    #[test]
    fn same_config_no_reload() {
        let e = env(255);
        e.run(&config_file(&e, "a.toml", 30)).unwrap();
        set_active(&e.host);
        e.host.set(|s| s.calls.clear());
        e.run(&config_file(&e, "a.toml", 30)).unwrap();
        // Without --config the current file is kept: no reload either.
        e.install();
        let calls = e.host.state().calls;
        assert!(
            !calls.iter().any(|c| c.contains("reload saiifed")),
            "{calls:?}"
        );
        assert!(!calls.iter().any(|c| c.contains("restart")), "{calls:?}");
    }

    #[test]
    fn binary_and_config_change_restarts_only() {
        let e = env(255);
        e.run(&config_file(&e, "a.toml", 30)).unwrap();
        set_active(&e.host);
        let mut v2 = crate::binary::fake_elf(None, 0, Some(false));
        v2.extend_from_slice(b"v2");
        fs::write(&e.binary, &v2).unwrap();
        e.host.set(|s| s.calls.clear());
        e.run(&config_file(&e, "b.toml", 40)).unwrap();
        let calls = e.host.state().calls;
        assert_eq!(
            calls
                .iter()
                .filter(|c| *c == "systemctl restart saiifed.service")
                .count(),
            1,
            "{calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.contains("reload saiifed")),
            "{calls:?}"
        );
    }

    /// The daemon regroups the audit dir at start: a membership added while
    /// it runs needs a restart to take effect.
    #[test]
    fn new_audit_membership_restarts() {
        let e = env(255);
        e.install();
        set_active(&e.host);
        e.host.set(|s| {
            s.members.remove(AUDIT_GROUP);
            s.calls.clear();
        });
        let r = e.install();
        assert!(
            r.changed
                .contains(&"saiife in group saiife-audit".to_string()),
            "{:?}",
            r.changed
        );
        let calls = e.host.state().calls;
        assert!(
            calls.contains(&"systemctl restart saiifed.service".to_string()),
            "{calls:?}"
        );
    }

    #[test]
    fn config_flag_validated() {
        let e = env(255);
        let bad = e.src.path().join("bad.toml");
        fs::write(&bad, "version = 2\nlocked = true\nsurprise = 1\n").unwrap();
        let mut o = all_agents();
        o.config = Some(bad.clone());
        match e.run(&o) {
            Err(InstallError::Refused { path, detail }) => {
                assert_eq!(path, bad);
                assert!(detail.contains("surprise"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        assert!(!e.at(ETC_DIR).exists() || fs::read_dir(e.at(ETC_DIR)).unwrap().count() == 0);
        // Not locked.
        let unlocked = e.src.path().join("unlocked.toml");
        fs::write(&unlocked, "version = 2\n").unwrap();
        o.config = Some(unlocked);
        assert!(matches!(e.run(&o), Err(InstallError::Refused { .. })));
        // A good one replaces the current file.
        let good = e.src.path().join("good.toml");
        let text = "version = 2\nlocked = true\n\n[guard]\nbudget_ms = 30\n";
        fs::write(&good, text).unwrap();
        o.config = Some(good);
        e.run(&o).unwrap();
        assert_eq!(fs::read_to_string(e.at(CONFIG)).unwrap(), text);
        assert_eq!(mode(&e.at(CONFIG)), 0o644);
    }

    #[test]
    fn approvers_are_checked_and_written() {
        let e = env(255);
        let mut o = all_agents();
        o.approvers = vec!["alice".into(), "group:ops".into()];
        e.run(&o).unwrap();
        let c = saiife_policy::load_system(&e.at(CONFIG)).unwrap().config;
        assert_eq!(c.approval.approvers, ["alice", "group:ops"]);
        let e = env(255);
        o.approvers = vec!["bad name\"".into()];
        assert!(matches!(e.run(&o), Err(InstallError::Refused { .. })));
    }

    #[test]
    fn existing_human_saiife_user_refused() {
        let e = env(255);
        e.host.set(|s| {
            s.users.insert(
                DAEMON_USER.into(),
                UserInfo {
                    uid: 1001,
                    gid: 1001,
                    home: "/home/saiife".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        let err = e.run(&all_agents()).unwrap_err();
        assert!(matches!(err, InstallError::Refused { .. }), "{err:?}");
        assert!(err.to_string().contains("1001"), "{err}");
        assert!(!e.at(ETC_DIR).exists());
        assert!(e.host.state().groups.is_empty());
    }

    #[test]
    fn existing_system_saiife_user_with_nologin_is_used() {
        let e = env(255);
        e.host.set(|s| {
            s.groups.insert(DAEMON_GROUP.into(), 990);
            s.users.insert(
                DAEMON_USER.into(),
                UserInfo {
                    uid: 990,
                    gid: 990,
                    home: "/nonexistent".into(),
                    shell: "/usr/sbin/nologin".into(),
                },
            );
        });
        e.install();
        let i = e.installed();
        assert!(i.users.is_empty());
        assert_eq!(i.groups, ["saiife-audit"]);
        // The group is new, so the membership is install's.
        assert_eq!(i.memberships.len(), 1);
    }

    /// A system `saiife` user that owns what the test user owns.
    fn system_saiife_user(h: &FakeHost) {
        h.set(|s| {
            s.users.insert(
                DAEMON_USER.into(),
                UserInfo {
                    uid: rustix::process::getuid().as_raw(),
                    gid: rustix::process::getgid().as_raw(),
                    home: "/nonexistent".into(),
                    shell: "/usr/sbin/nologin".into(),
                },
            );
        });
    }

    #[test]
    fn existing_state_dir_not_owned_by_saiife_refused() {
        let e = env(255);
        let st = e.at(STATE_DIR);
        fs::create_dir_all(&st).unwrap();
        fs::set_permissions(&st, fs::Permissions::from_mode(0o700)).unwrap();
        // No saiife user yet: nobody can own it as saiife.
        let err = e.run(&all_agents()).unwrap_err();
        assert!(err.to_string().contains("not by the saiife user"), "{err}");
        assert!(!e.at(ETC_DIR).exists());
    }

    #[test]
    fn existing_state_dir_wrong_mode_refused() {
        let e = env(255);
        system_saiife_user(&e.host);
        let st = e.at(STATE_DIR);
        fs::create_dir_all(&st).unwrap();
        fs::set_permissions(&st, fs::Permissions::from_mode(0o755)).unwrap();
        let err = e.run(&all_agents()).unwrap_err();
        match &err {
            InstallError::Refused { path, detail } => {
                assert_eq!(path, &st);
                assert!(detail.contains("755"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        assert!(!e.at(ETC_DIR).exists());
    }

    #[test]
    fn existing_key_dir_symlink_refused() {
        let e = env(255);
        fs::create_dir_all(e.at(STATE_DIR)).unwrap();
        fs::set_permissions(e.at(STATE_DIR), fs::Permissions::from_mode(0o700)).unwrap();
        // The state dir is owned by the test user, which the fake `saiife`
        // user resolves to.
        system_saiife_user(&e.host);
        std::os::unix::fs::symlink(e.src.path(), e.at(KEYS_DIR)).unwrap();
        assert!(matches!(
            e.run(&all_agents()),
            Err(InstallError::Refused { .. })
        ));
    }

    #[test]
    fn start_failure_still_writes_installed_and_exits_2() {
        let e = env(255);
        e.host.set(|s| {
            s.run.insert(
                "systemctl enable --now saiifed.service".into(),
                CmdOutput {
                    status: 1,
                    stdout: String::new(),
                    stderr: "Job for saiifed.service failed.\n".into(),
                },
            );
        });
        match e.run(&all_agents()) {
            Err(InstallError::Step { step, detail }) => {
                assert_eq!(step, "start");
                assert!(
                    detail.contains("Job for saiifed.service failed."),
                    "{detail}"
                );
                assert!(
                    detail.ends_with(" (see: journalctl -u saiifed)"),
                    "{detail}"
                );
            }
            other => panic!("{other:?}"),
        }
        let i = e.installed();
        assert_eq!(i.users, ["saiife"]);
        assert_eq!(i.groups, ["saiife", "saiife-audit"]);
        assert_eq!(i.files.len(), 5);
        assert_eq!(i.agents.len(), 3);
    }

    #[test]
    fn unsupported_writes_nothing() {
        let e = env_with(255, "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.0\n");
        match e.run(&all_agents()) {
            Err(InstallError::Unsupported(why)) => assert!(why.contains("Alpine"), "{why}"),
            other => panic!("{other:?}"),
        }
        let files: BTreeSet<String> = e
            .tree()
            .into_iter()
            .filter(|p| !e.layout.root().join(p).is_dir())
            .collect();
        assert_eq!(
            files,
            BTreeSet::from([".fakehost.json".to_string(), "etc/os-release".to_string()])
        );
        assert!(e.host.state().calls.is_empty());
    }

    #[test]
    fn only_named_agents_are_written_and_others_kept() {
        let e = env(255);
        let mut o = all_agents();
        o.agents = vec![Agent::Codex];
        e.run(&o).unwrap();
        assert!(e.at(CODEX_REQUIREMENTS).exists());
        assert!(!e.at(CLAUDE_MANAGED).exists());
        assert!(!e.at(GEMINI_SETTINGS).exists());
        o.agents = vec![Agent::Gemini];
        e.run(&o).unwrap();
        let names: Vec<String> = e.installed().agents.into_iter().map(|a| a.agent).collect();
        assert_eq!(names, ["codex", "gemini"]);
        assert!(e.at(CODEX_REQUIREMENTS).exists());
    }

    #[test]
    fn existing_codex_file_is_edited_not_replaced() {
        let e = env(255);
        fs::create_dir_all(e.at(CODEX_DIR)).unwrap();
        fs::write(e.at(CODEX_REQUIREMENTS), "[features]\nweb_search = true\n").unwrap();
        e.install();
        let text = fs::read_to_string(e.at(CODEX_REQUIREMENTS)).unwrap();
        assert!(text.contains("web_search = true"));
        let i = e.installed();
        let a = i.agents.iter().find(|a| a.agent == "codex").unwrap();
        assert!(!a.created_file && !a.whole_file);
        assert!(!i.dirs.contains(&PathBuf::from(CODEX_DIR)));
    }

    #[test]
    fn symlinked_managed_file_is_refused() {
        let e = env(255);
        fs::create_dir_all(e.at(GEMINI_DIR)).unwrap();
        let elsewhere = e.src.path().join("elsewhere.json");
        fs::write(&elsewhere, "{}").unwrap();
        std::os::unix::fs::symlink(&elsewhere, e.at(GEMINI_SETTINGS)).unwrap();
        assert!(e.run(&all_agents()).is_err());
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "{}");
    }

    #[test]
    fn missing_binary_is_a_step_error() {
        let e = env(255);
        fs::remove_file(&e.binary).unwrap();
        match e.run(&all_agents()) {
            Err(InstallError::Step { step, .. }) => assert_eq!(step, "binary"),
            other => panic!("{other:?}"),
        }
        // Read (and checked) before anything is created.
        assert!(!e.at(INSTALLED).exists());
        assert!(e.host.state().calls.is_empty());
    }

    // ------------------------------------------------ A4: the binary kind

    #[test]
    fn unfit_binary_is_refused_on_the_real_system() {
        let p = Path::new("/usr/local/bin/saiife");
        let dynamic = crate::binary::fake_elf(Some("/lib64/ld-linux-x86-64.so.2"), 1, Some(false));
        let debug = crate::binary::fake_elf(None, 0, Some(true));
        for (bytes, want) in [
            (
                &dynamic[..],
                "dynamically linked (interpreter /lib64/ld-linux-x86-64.so.2)",
            ),
            (&debug[..], "test build (debug assertions on"),
            (
                &b"#!/bin/sh\n"[..],
                "not a static ELF executable (not an ELF file)",
            ),
        ] {
            match check_binary(p, bytes, true) {
                Err(InstallError::Refused { path, detail }) => {
                    assert_eq!(path, p);
                    assert!(detail.contains(want), "{detail}");
                    assert!(detail.contains("static release build"), "{detail}");
                }
                other => panic!("{other:?}"),
            }
            // Not strict (`--root`, `--allow-test-build`): a warning.
            let w = check_binary(p, bytes, false).unwrap().unwrap();
            assert!(
                w.starts_with("/usr/local/bin/saiife: ") && w.contains(want),
                "{w}"
            );
        }
        let release = crate::binary::fake_elf(None, 0, Some(false));
        assert_eq!(check_binary(p, &release, true).unwrap(), None);
    }

    #[test]
    fn test_build_under_root_installs_with_a_warning() {
        let e = env(255);
        fs::write(
            &e.binary,
            crate::binary::fake_elf(Some("/lib64/ld-linux-x86-64.so.2"), 1, Some(true)),
        )
        .unwrap();
        let r = e.install();
        assert_eq!(r.warnings.len(), 2, "{:?}", r.warnings);
        assert_eq!(r.warnings[1], REAUTH_UNAVAILABLE);
        assert!(
            r.warnings[0].contains("dynamically linked"),
            "{:?}",
            r.warnings
        );
        assert!(r.warnings[0].contains("test build"), "{:?}", r.warnings);
        assert!(e.at(BINARY).is_file());
    }

    // ------------------------------------------------ fix round 1

    fn users_preexisting(h: &FakeHost, member: bool) {
        h.set(|s| {
            s.groups.insert(DAEMON_GROUP.into(), 990);
            s.groups.insert(AUDIT_GROUP.into(), 991);
            s.users.insert(
                DAEMON_USER.into(),
                UserInfo {
                    uid: 990,
                    gid: 990,
                    home: "/nonexistent".into(),
                    shell: "/usr/sbin/nologin".into(),
                },
            );
            if member {
                s.members
                    .insert(AUDIT_GROUP.into(), vec![DAEMON_USER.to_string()]);
            }
        });
    }

    #[test]
    fn new_membership_of_existing_user_and_group_is_recorded() {
        let e = env(255);
        users_preexisting(&e.host, false);
        let r = e.install();
        let i = e.installed();
        assert!(i.users.is_empty() && i.groups.is_empty());
        assert_eq!(i.memberships.len(), 1);
        assert!(r
            .changed
            .contains(&"saiife in group saiife-audit".to_string()));
        assert_eq!(
            e.host.group_members(AUDIT_GROUP).unwrap(),
            vec![DAEMON_USER.to_string()]
        );
    }

    #[test]
    fn existing_membership_is_not_recorded() {
        let e = env(255);
        users_preexisting(&e.host, true);
        e.install();
        assert!(e.installed().memberships.is_empty());
    }

    #[test]
    fn existing_shared_saiife_group_refused() {
        // A member besides saiife.
        let e = env(249);
        e.host.set(|s| {
            s.groups.insert(DAEMON_GROUP.into(), 990);
            s.members
                .insert(DAEMON_GROUP.into(), vec!["alice".to_string()]);
        });
        let err = e.run(&all_agents()).unwrap_err();
        assert!(matches!(err, InstallError::Refused { .. }), "{err:?}");
        assert!(err.to_string().contains("alice"), "{err}");
        assert!(!e.at(ETC_DIR).exists());
        // A non-system gid.
        let e = env(249);
        e.host.set(|s| {
            s.groups.insert(DAEMON_GROUP.into(), 1001);
        });
        let err = e.run(&all_agents()).unwrap_err();
        assert!(err.to_string().contains("1001"), "{err}");
        // A system group with only saiife in it is fine.
        let e = env(249);
        e.host.set(|s| {
            s.groups.insert(DAEMON_GROUP.into(), 990);
            s.members
                .insert(DAEMON_GROUP.into(), vec![DAEMON_USER.to_string()]);
        });
        e.install();
    }

    #[test]
    fn writable_existing_managed_dir_refused() {
        let e = env(255);
        fs::create_dir_all(e.at(CODEX_DIR)).unwrap();
        fs::set_permissions(e.at(CODEX_DIR), fs::Permissions::from_mode(0o777)).unwrap();
        match e.run(&all_agents()) {
            Err(InstallError::Refused { path, detail }) => {
                assert_eq!(path, e.at(CODEX_DIR));
                assert!(detail.contains("0777"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        assert!(!e.at(CODEX_REQUIREMENTS).exists());
        // Sticky is allowed.
        let e = env(255);
        fs::create_dir_all(e.at(GEMINI_DIR)).unwrap();
        fs::set_permissions(e.at(GEMINI_DIR), fs::Permissions::from_mode(0o1777)).unwrap();
        e.install();
    }

    #[test]
    fn existing_ancestor_not_owned_by_root_refused() {
        let e = env(255);
        // Root resolves to another uid: the test's own `etc` is not root's.
        e.host.set(|s| {
            s.users.insert(
                "root".into(),
                UserInfo {
                    uid: rustix::process::getuid().as_raw() + 1,
                    gid: 0,
                    home: "/root".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        match e.run(&all_agents()) {
            Err(InstallError::Refused { path, detail }) => {
                assert_eq!(path, e.at("/etc"));
                assert!(detail.contains("not root"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn failure_after_a_write_still_lists_the_file() {
        let e = env(255);
        let unit = e.at(UNIT);
        e.host.set(|s| s.fail_chown = vec![unit.clone()]);
        match e.run(&all_agents()) {
            Err(InstallError::Step { step, .. }) => assert_eq!(step, "unit"),
            other => panic!("{other:?}"),
        }
        assert!(unit.exists());
        let f = e
            .installed()
            .files
            .into_iter()
            .find(|f| f.kind == FileKind::Unit)
            .expect("the unit is listed");
        assert!(f.created);
        // The managed agent too.
        let e = env(255);
        let codex = e.at(CODEX_REQUIREMENTS);
        e.host.set(|s| s.fail_chown = vec![codex.clone()]);
        assert!(e.run(&all_agents()).is_err());
        assert!(codex.exists());
        let a = e
            .installed()
            .agents
            .into_iter()
            .find(|a| a.agent == "codex")
            .expect("codex is listed");
        assert!(a.created_file);
    }

    #[test]
    fn reinstall_after_uninstall_keeps_the_plain_key_mode() {
        // Ubuntu 22.04: systemd 249, a plain key.
        let e = env(249);
        e.install();
        assert_eq!(e.installed().vault_key, VaultKeyMode::File);
        let out = crate::uninstall::uninstall(
            &e.layout,
            &e.host,
            &crate::uninstall::UninstallOptions { purge: false },
        )
        .unwrap();
        assert!(
            out.iter().any(|l| l.contains("installed.previous.toml")),
            "{out:?}"
        );
        let copy = e.at(PREVIOUS);
        assert_eq!(mode(&copy), 0o600);
        assert!(!e.at(INSTALLED).exists());
        // Upgraded to 24.04: systemd 255. On a real host the user and
        // group install made have system ids (the fake gives them the test
        // user's, which the copy may not exempt).
        e.host.set(|s| {
            s.systemd = 255;
            s.users.get_mut(DAEMON_USER).unwrap().uid = 990;
            s.users.get_mut(DAEMON_USER).unwrap().gid = 990;
            s.groups.insert(DAEMON_GROUP.into(), 990);
        });
        e.install();
        let i = e.installed();
        assert_eq!(i.vault_key, VaultKeyMode::File);
        assert_eq!(i.users, ["saiife"]);
        assert_eq!(i.groups, ["saiife", "saiife-audit"]);
        let vk = i
            .files
            .iter()
            .find(|f| f.kind == FileKind::VaultKey)
            .unwrap();
        assert!(vk.created, "the key install made is still install's");
        let unit = fs::read_to_string(e.at(UNIT)).unwrap();
        assert!(unit.contains("\nLoadCredential=vault-key:"), "{unit}");
        assert!(!copy.exists(), "installed.toml holds it again");
    }

    #[test]
    fn previous_copy_not_owned_by_root_is_ignored() {
        let e = env(249);
        fs::create_dir_all(e.at(ETC_DIR)).unwrap();
        e.host.set(|s| {
            s.users.insert(
                "root".into(),
                UserInfo {
                    uid: rustix::process::getuid().as_raw() + 1,
                    gid: 0,
                    home: "/root".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        fs::write(e.at(PREVIOUS), "garbage").unwrap();
        fs::set_permissions(e.at(PREVIOUS), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_previous(&e.layout, &e.host).is_none());
    }

    #[test]
    fn previous_copy_is_limited_to_what_install_could_create() {
        let e = env(255);
        fs::create_dir_all(e.at(ETC_DIR)).unwrap();
        let mut i = Installed {
            version: saiife_policy::installed::INSTALLED_VERSION,
            saiife: "x".into(),
            installed_at: "x".into(),
            systemd: 249,
            vault_key: VaultKeyMode::File,
            users: vec!["saiife".into(), "alice".into()],
            groups: vec!["saiife".into(), "wheel".into()],
            memberships: vec![],
            dirs: vec!["/".into(), "/home".into(), "/opt/saiife".into()],
            files: vec![],
            agents: vec![],
            auth_rights: vec!["com.saiife.approve".into()],
        };
        i.memberships.push(saiife_policy::installed::Membership {
            user: "alice".into(),
            group: "wheel".into(),
        });
        saiife_policy::installed::write_installed(&e.at(PREVIOUS), &i).unwrap();
        fs::set_permissions(e.at(PREVIOUS), fs::Permissions::from_mode(0o600)).unwrap();
        let got = read_previous(&e.layout, &e.host).unwrap();
        assert_eq!(got.users, ["saiife"]);
        assert_eq!(got.groups, ["saiife"]);
        assert!(got.memberships.is_empty());
        assert_eq!(got.dirs, [PathBuf::from("/opt/saiife")]);
        // Rights are macOS's: never taken over from a Linux copy.
        assert!(got.auth_rights.is_empty());
    }

    #[test]
    fn doctor_files_installed_passes_after_install_and_sees_codex_tamper() {
        use crate::doctor::{run as doctor, DoctorOptions, Status};
        let e = env(255);
        e.install();
        let check = |e: &Env| {
            let r = doctor(
                &e.layout,
                &e.host,
                &saiife_policy::FixedDirectory::from_text("", ""),
                &DoctorOptions::default(),
            );
            r.checks
                .into_iter()
                .find(|c| c.id == "files.installed")
                .unwrap()
        };
        let c = check(&e);
        assert_eq!(c.status, Status::Pass, "{c:?}");
        let p = e.at(CODEX_REQUIREMENTS);
        let t = fs::read_to_string(&p)
            .unwrap()
            .replace("timeout = 10", "timeout = 1");
        fs::write(&p, t).unwrap();
        let c = check(&e);
        assert_eq!(c.status, Status::Fail, "{c:?}");
        assert!(c.detail.contains("changed since install"), "{c:?}");
    }

    // ------------------------------------------------ fix round 2

    /// A valid copy of `i` at `abs`, root's 0600 (root = the test user).
    fn write_copy(e: &Env, abs: &str, i: &Installed) {
        let p = e.at(abs);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        saiife_policy::installed::write_installed(&p, i).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn copy_record(mode: VaultKeyMode) -> Installed {
        Installed {
            version: saiife_policy::installed::INSTALLED_VERSION,
            saiife: "x".into(),
            installed_at: "x".into(),
            systemd: 249,
            vault_key: mode,
            users: vec!["saiife".into()],
            groups: vec!["saiife".into(), "saiife-audit".into()],
            memberships: vec![],
            dirs: vec![],
            files: vec![saiife_policy::installed::InstalledFile {
                path: VAULT_KEY.into(),
                sha256: Some("ab".repeat(32)),
                kind: FileKind::VaultKey,
                created: true,
            }],
            agents: vec![],
            auth_rights: vec![],
        }
    }

    #[test]
    fn existing_user_with_saiife_as_primary_group_refused() {
        let e = env(249);
        e.host.set(|s| {
            s.groups.insert(DAEMON_GROUP.into(), 990);
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
        let err = e.run(&all_agents()).unwrap_err();
        assert!(matches!(err, InstallError::Refused { .. }), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("alice") && msg.contains("vault key"), "{msg}");
        assert!(!msg.contains("  "), "no stray continuation spaces: {msg}");
        assert!(!e.at(ETC_DIR).exists());
    }

    #[test]
    fn copy_in_the_state_dir_is_ignored() {
        let e = env(255);
        // The old location, in the daemon user's state dir.
        let old = "/var/lib/saiife/installed.previous.toml";
        write_copy(&e, old, &copy_record(VaultKeyMode::File));
        assert!(!Path::new(PREVIOUS).starts_with(STATE_DIR));
        assert!(read_previous(&e.layout, &e.host).is_none());
    }

    #[test]
    fn tampered_copy_is_ignored() {
        // Wrong mode.
        let e = env(255);
        write_copy(&e, PREVIOUS, &copy_record(VaultKeyMode::File));
        assert!(read_previous(&e.layout, &e.host).is_some());
        fs::set_permissions(e.at(PREVIOUS), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_previous(&e.layout, &e.host).is_none());
        // A symlink to a good-looking copy.
        let e = env(255);
        write_copy(&e, "/etc/elsewhere.toml", &copy_record(VaultKeyMode::File));
        fs::create_dir_all(e.at(ETC_DIR)).unwrap();
        std::os::unix::fs::symlink(e.at("/etc/elsewhere.toml"), e.at(PREVIOUS)).unwrap();
        assert!(read_previous(&e.layout, &e.host).is_none());
    }

    #[test]
    fn copy_never_exempts_a_login_user() {
        let e = env(255);
        write_copy(&e, PREVIOUS, &copy_record(VaultKeyMode::Credential));
        e.host.set(|s| {
            s.users.insert(
                DAEMON_USER.into(),
                UserInfo {
                    uid: 1001,
                    gid: 1001,
                    home: "/home/saiife".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        let err = e.run(&all_agents()).unwrap_err();
        assert!(err.to_string().contains("1001"), "{err}");
    }

    #[test]
    fn copy_clears_the_vault_key_digest() {
        let e = env(255);
        write_copy(&e, PREVIOUS, &copy_record(VaultKeyMode::File));
        let i = read_previous(&e.layout, &e.host).unwrap();
        assert!(i.files.iter().all(|f| f.sha256.is_none()));
    }

    #[test]
    fn vault_key_mode_comes_from_the_key_file() {
        // The copy says Credential, the key on disk is 32 raw bytes.
        let e = env(255);
        write_copy(&e, PREVIOUS, &copy_record(VaultKeyMode::Credential));
        fs::create_dir_all(e.at(CREDSTORE)).unwrap();
        fs::write(e.at(VAULT_KEY), [7u8; 32]).unwrap();
        e.install();
        assert_eq!(e.installed().vault_key, VaultKeyMode::File);
        assert!(fs::read_to_string(e.at(UNIT))
            .unwrap()
            .contains("\nLoadCredential=vault-key:"));
        assert_eq!(fs::read(e.at(VAULT_KEY)).unwrap(), [7u8; 32]);
        // The copy says File, the key on disk is an encrypted credential.
        let e = env(249);
        write_copy(&e, PREVIOUS, &copy_record(VaultKeyMode::File));
        fs::create_dir_all(e.at(CREDSTORE)).unwrap();
        fs::write(e.at(VAULT_KEY), "an encrypted credential, not 32 bytes\n").unwrap();
        e.install();
        assert_eq!(e.installed().vault_key, VaultKeyMode::Credential);
        assert_eq!(mode(&e.at(VAULT_KEY)), 0o600);
    }
}

/// The macOS install, driven from any Unix with the macOS layout below a
/// temp root and the [`FakeHost`] acting as the local directory.
#[cfg(all(test, unix))]
pub(crate) mod macos_tests {
    use super::*;
    use crate::authright::{RIGHT, RIGHT_PLIST};
    use crate::binary::{fake_elf, fake_macho};
    use crate::host::{dscl_read_line, CmdOutput, FakeHost, UserInfo, MACOS_ID_RANGE};
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) struct MacEnv {
        /// Keeps the root alive.
        pub _dir: tempfile::TempDir,
        pub _src: tempfile::TempDir,
        pub layout: Layout,
        pub host: FakeHost,
        pub binary: PathBuf,
    }

    /// What the test root holds before install: `/etc` and `/var` as the
    /// links into `/private` a Mac has, and `/Library`'s dirs.
    pub(crate) const MAC_SETUP: &[&str] = &[
        ".fakehost.json",
        "Library",
        "Library/Application Support",
        "Library/LaunchDaemons",
        "etc",
        "private",
        "private/etc",
        "private/var",
        "private/var/db",
        "private/var/log",
        "var",
    ];

    pub(crate) fn ok(stdout: &str) -> CmdOutput {
        CmdOutput {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    pub(crate) fn exit(status: i32, stderr: &str) -> CmdOutput {
        CmdOutput {
            status,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    pub(crate) const PRINT: &str = "launchctl print system/com.saiife.saiifed";

    pub(crate) fn write_line() -> String {
        format!("{SECURITY} authorizationdb write {RIGHT}")
    }

    /// A signed release build with the hardened runtime.
    pub(crate) fn signed() -> Vec<u8> {
        fake_macho(Some((false, true, true)))
    }

    pub(crate) fn mac_env() -> MacEnv {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        for d in [
            "private/etc",
            "private/var/db",
            "private/var/log",
            "Library/LaunchDaemons",
            "Library/Application Support",
        ] {
            fs::create_dir_all(r.join(d)).unwrap();
        }
        for d in MAC_SETUP.iter().filter(|d| !matches!(**d, "etc" | "var")) {
            if r.join(d).is_dir() {
                fs::set_permissions(r.join(d), fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        std::os::unix::fs::symlink("private/etc", r.join("etc")).unwrap();
        std::os::unix::fs::symlink("private/var", r.join("var")).unwrap();
        let layout = Layout::under_for(r, Platform::Macos);
        let host = FakeHost::open(layout.root()).unwrap();
        host.set(|s| {
            s.dscl = true;
            // Not loaded yet; the right registers.
            s.run
                .insert(PRINT.into(), exit(113, "Could not find service"));
            s.run.insert(write_line(), ok(""));
        });
        let src = tempfile::tempdir().unwrap();
        let binary = src.path().join("saiife");
        fs::write(&binary, signed()).unwrap();
        MacEnv {
            _dir: dir,
            _src: src,
            layout,
            host,
            binary,
        }
    }

    pub(crate) fn opts() -> InstallOptions {
        InstallOptions {
            config: None,
            agents: Agent::ALL.to_vec(),
            approvers: Vec::new(),
            non_interactive: true,
            allow_test_build: false,
        }
    }

    impl MacEnv {
        /// A platform path (as recorded) below the root.
        pub fn at(&self, logical: &str) -> PathBuf {
            self.layout.try_at(Path::new(logical)).unwrap()
        }
        pub fn installed(&self) -> Installed {
            read_installed(&self.layout.at(INSTALLED)).unwrap().unwrap()
        }
        pub fn run(&self, o: &InstallOptions) -> Result<InstallReport, InstallError> {
            install(&self.layout, &self.host, o, &self.binary)
        }
        pub fn install(&self) -> InstallReport {
            self.run(&opts()).unwrap()
        }
        /// Every path below the root, relative (links are not followed).
        pub fn tree(&self) -> BTreeSet<String> {
            fn walk(base: &Path, d: &Path, out: &mut BTreeSet<String>) {
                for e in fs::read_dir(d).unwrap() {
                    let p = e.unwrap().path();
                    out.insert(p.strip_prefix(base).unwrap().to_string_lossy().into_owned());
                    if p.symlink_metadata().unwrap().is_dir() {
                        walk(base, &p, out);
                    }
                }
            }
            let mut out = BTreeSet::new();
            walk(self.layout.root(), self.layout.root(), &mut out);
            out
        }
        /// What a Mac shows after the first install: launchd has the job,
        /// the right reads back, and the chowns the fake records took
        /// effect (the daemon user owns what the test user owns).
        pub fn settle(&self) {
            self.host.set(|s| {
                s.run.remove(PRINT);
                s.run.insert(
                    format!("{SECURITY} authorizationdb read {RIGHT}"),
                    ok(RIGHT_PLIST),
                );
                s.users.get_mut(MACOS_DAEMON_USER).unwrap().uid =
                    rustix::process::getuid().as_raw();
                s.calls.clear();
            });
        }
        pub fn calls(&self) -> Vec<String> {
            self.host.state().calls
        }
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn chowned(h: &FakeHost, p: &Path) -> Vec<(u32, u32)> {
        h.state()
            .chowns
            .iter()
            .filter(|c| c.path == p)
            .map(|c| (c.uid, c.gid))
            .collect()
    }

    #[derive(Clone, Copy, Debug)]
    enum Own {
        Root,
        Daemon,
        Audit,
    }

    /// Every §5.3 path install makes, with its mode and owner.
    const SPEC: &[(&str, u32, Own)] = &[
        ("/opt", 0o755, Own::Root),
        ("/opt/saiife", 0o755, Own::Root),
        ("/opt/saiife/bin", 0o755, Own::Root),
        ("/opt/saiife/bin/saiife", 0o755, Own::Root),
        ("/etc/saiife", 0o755, Own::Root),
        ("/etc/saiife/policy.d", 0o755, Own::Root),
        ("/etc/saiife/config.toml", 0o644, Own::Root),
        ("/etc/saiife/installed.toml", 0o644, Own::Root),
        (
            "/Library/LaunchDaemons/com.saiife.saiifed.plist",
            0o644,
            Own::Root,
        ),
        (
            "/Library/Application Support/ClaudeCode/managed-settings.d",
            0o755,
            Own::Root,
        ),
        (
            "/Library/Application Support/ClaudeCode/managed-settings.d/50-saiife.json",
            0o644,
            Own::Root,
        ),
        (
            "/Library/Application Support/ClaudeCode/managed-settings.d/60-saiife-mcp.json",
            0o644,
            Own::Root,
        ),
        ("/Library/Application Support/GeminiCli", 0o755, Own::Root),
        (
            "/Library/Application Support/GeminiCli/settings.json",
            0o644,
            Own::Root,
        ),
        ("/etc/codex", 0o755, Own::Root),
        ("/etc/codex/requirements.toml", 0o644, Own::Root),
        ("/var/db/saiife", 0o700, Own::Daemon),
        ("/var/db/saiife/keys", 0o700, Own::Daemon),
        ("/var/db/saiife/keys/vault.key", 0o400, Own::Daemon),
        ("/var/db/saiife-run", 0o755, Own::Daemon),
        ("/var/log/saiife", 0o755, Own::Root),
        ("/var/log/saiife/audit", 0o2750, Own::Audit),
        ("/var/log/saiife/daemon.log", 0o640, Own::Audit),
    ];

    #[test]
    fn macos_fresh_install_writes_spec_paths_and_modes() {
        let e = mac_env();
        let r = e.install();
        assert!(r.started);
        assert_eq!(r.warnings, [MAC_SAME_USER_OFF], "{:?}", r.warnings);
        let h = &e.host;
        let root = (h.user("root").unwrap().uid, h.group_id("wheel").unwrap());
        let d = h.user("_saiife").unwrap();
        let daemon = (d.uid, h.group_id("_saiife").unwrap());
        let audit = (d.uid, h.group_id("_saiifeaudit").unwrap());
        for (abs, want, own) in SPEC {
            let p = e.at(abs);
            assert!(p.exists(), "{abs} missing");
            assert_eq!(mode(&p), *want, "{abs} mode {:o}", mode(&p));
            let owner = match own {
                Own::Root => root,
                Own::Daemon => daemon,
                Own::Audit => audit,
            };
            let c = chowned(h, &p);
            assert!(
                !c.is_empty() && c.iter().all(|x| *x == owner),
                "{abs} ({own:?}): {c:?}"
            );
        }
        // Through the /etc and /var links, into /private.
        assert!(e
            .layout
            .root()
            .join("private/var/db/saiife/keys/vault.key")
            .is_file());
        assert!(e
            .layout
            .root()
            .join("private/etc/saiife/config.toml")
            .is_file());
        assert_eq!(
            fs::read_to_string(e.at("/Library/LaunchDaemons/com.saiife.saiifed.plist")).unwrap(),
            launchd::plist_text()
        );
        assert_eq!(fs::read(e.at(BINARY)).unwrap(), signed());
        // Nothing of Linux's.
        for linux in [
            "/etc/saiife/credstore",
            "/etc/systemd",
            "/usr/share/polkit-1",
            "/var/lib/saiife",
            "/run",
        ] {
            assert!(!e.at(linux).exists(), "{linux}");
        }
        let calls = e.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("systemctl")),
            "{calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.contains("systemd-creds")),
            "{calls:?}"
        );
        let plist = e.layout.at(UNIT).display().to_string();
        assert!(
            calls.contains(&format!("launchctl bootstrap system {plist}")),
            "{calls:?}"
        );
        let i = e.installed();
        assert_eq!(i.systemd, 0);
        // Recorded as the platform names them.
        assert!(i.files.iter().any(|f| f.kind == FileKind::Unit
            && f.path == Path::new("/Library/LaunchDaemons/com.saiife.saiifed.plist")));
        assert!(i.dirs.contains(&PathBuf::from("/opt")));
        assert!(i
            .dirs
            .iter()
            .all(|d| d.is_absolute() && !d.starts_with(e.layout.root())));
    }

    /// BSD gives a new file its directory's gid: the audit dir's group must
    /// be the `_saiifeaudit` group install made, so the daemon's 0640 month
    /// files are readable by that group (and never `wheel`).
    #[test]
    fn macos_audit_dir_is_saiife_saiifeaudit() {
        let e = mac_env();
        e.install();
        let audit = e.layout.at(AUDIT_DIR);
        assert_eq!(audit, e.at("/var/log/saiife/audit"));
        let uid = e.host.user("_saiife").unwrap().uid;
        let gid = e.host.group_id("_saiifeaudit").unwrap();
        assert_ne!(gid, e.host.group_id("_saiife").unwrap());
        assert_ne!(Some(gid), e.host.group_id("wheel"));
        assert_eq!(chowned(&e.host, &audit), vec![(uid, gid)]);
        assert_eq!(mode(&audit), 0o2750);
        // The daemon log too.
        assert_eq!(chowned(&e.host, &e.layout.at(DAEMON_LOG)), vec![(uid, gid)]);
    }

    #[test]
    fn macos_install_creates_hidden_users_in_range() {
        let e = mac_env();
        e.install();
        let calls = e.calls();
        let pos = |line: &str| {
            calls
                .iter()
                .position(|c| c == line)
                .unwrap_or_else(|| panic!("{line}: {calls:?}"))
        };
        let g = pos("/usr/bin/dscl . -create /Groups/_saiife");
        let a = pos("/usr/bin/dscl . -create /Groups/_saiifeaudit");
        let u = pos("/usr/bin/dscl . -create /Users/_saiife");
        assert!(g < a && a < u, "groups first, then the user: {calls:?}");
        let uid_line = calls
            .iter()
            .find_map(|c| c.strip_prefix("/usr/bin/dscl . -create /Users/_saiife UniqueID "))
            .unwrap();
        let uid: u32 = uid_line.parse().unwrap();
        assert!(MACOS_ID_RANGE.contains(&uid), "{uid}");
        let gid = e.host.group_id("_saiife").unwrap();
        assert!(MACOS_ID_RANGE.contains(&gid));
        // One id, used as the gid too while it is free.
        assert_eq!(uid, gid);
        pos(&format!(
            "/usr/bin/dscl . -create /Users/_saiife PrimaryGroupID {gid}"
        ));
        pos("/usr/bin/dscl . -create /Users/_saiife IsHidden 1");
        pos("/usr/bin/dscl . -create /Users/_saiife UserShell /usr/bin/false");
        pos("/usr/sbin/dseditgroup -o edit -a _saiife -t user _saiifeaudit");
        let i = e.installed();
        assert_eq!(i.users, ["_saiife"]);
        assert_eq!(i.groups, ["_saiife", "_saiifeaudit"]);
        assert_eq!(i.memberships.len(), 1);
        let u = e.host.user("_saiife").unwrap();
        assert_eq!(u.shell, "/usr/bin/false");
        assert_eq!(u.home, PathBuf::from("/var/empty"));
    }

    #[test]
    fn macos_vault_key_0400_daemon_file_mode() {
        let e = mac_env();
        e.install();
        let p = e.at("/var/db/saiife/keys/vault.key");
        assert_eq!(fs::read(&p).unwrap().len(), 32);
        assert_eq!(mode(&p), 0o400);
        let d = e.host.user("_saiife").unwrap();
        assert_eq!(
            chowned(&e.host, &p),
            vec![(d.uid, e.host.group_id("_saiife").unwrap())]
        );
        let i = e.installed();
        assert_eq!(i.vault_key, VaultKeyMode::DaemonFile);
        let vk = i
            .files
            .iter()
            .find(|f| f.kind == FileKind::VaultKey)
            .unwrap();
        assert_eq!(vk.path, Path::new("/var/db/saiife/keys/vault.key"));
        assert!(vk.created && vk.sha256.is_none());
        assert!(fs::read_to_string(e.layout.at(INSTALLED))
            .unwrap()
            .contains("vault_key = \"daemon_file\""));
        assert!(!e.at(CREDSTORE).exists());
        // Never rotated.
        let before = fs::read(&p).unwrap();
        e.settle();
        e.install();
        assert_eq!(fs::read(&p).unwrap(), before);
        // A key of the wrong size is never adopted.
        let e = mac_env();
        fs::create_dir_all(e.at("/var/db/saiife/keys")).unwrap();
        fs::write(e.at("/var/db/saiife/keys/vault.key"), b"short").unwrap();
        let err = check_macos_key(&e.layout).unwrap_err();
        assert!(err.to_string().contains("not a 32-byte key"), "{err}");
        assert!(check_macos_key(&mac_env().layout).is_ok());
    }

    #[test]
    fn macos_install_registers_auth_right() {
        let e = mac_env();
        let r = e.install();
        let line = format!("{} <stdin {} bytes>", write_line(), RIGHT_PLIST.len());
        assert!(e.calls().contains(&line), "{:?}", e.calls());
        assert_eq!(e.installed().auth_rights, [RIGHT]);
        let cfg = fs::read_to_string(e.layout.at(CONFIG)).unwrap();
        // Same-user approval is off on macOS: the config keeps "deny".
        assert!(cfg.contains("# same_user = \"deny\"\n"), "{cfg}");
        assert!(!cfg.contains("same_user = \"reauth\""), "{cfg}");
        assert!(r.changed.contains(&format!("auth right {RIGHT}")), "{r:?}");
        assert!(!r.warnings.iter().any(|w| w.contains(REAUTH_UNAVAILABLE)));
        assert!(r.warnings.iter().any(|w| w == MAC_SAME_USER_OFF), "{r:?}");
        // Read back with its settings: not written again.
        e.settle();
        let r = e.install();
        assert!(!e.calls().iter().any(|c| c.starts_with(&write_line())));
        assert!(r.unchanged.contains(&format!("auth right {RIGHT}")));
        assert_eq!(e.installed().auth_rights, [RIGHT]);
        // A right weakened since (shared) is written again.
        e.host.set(|s| {
            s.run.insert(
                format!("{SECURITY} authorizationdb read {RIGHT}"),
                ok(&RIGHT_PLIST.replace(
                    "<key>shared</key>\n\t<false/>",
                    "<key>shared</key>\n\t<true/>",
                )),
            );
        });
        e.install();
        assert!(e.calls().iter().any(|c| c.starts_with(&write_line())));
    }

    #[test]
    fn macos_auth_right_failure_warns_and_denies() {
        let e = mac_env();
        e.host
            .set(|s| drop(s.run.insert(write_line(), exit(1, "boom"))));
        let r = e.install();
        let cfg = fs::read_to_string(e.layout.at(CONFIG)).unwrap();
        assert!(cfg.contains("# same_user = \"deny\"\n"), "{cfg}");
        assert!(!cfg.contains("same_user = \"reauth\""), "{cfg}");
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("authorizationdb write")
                    && w.contains("boom")
                    && w.ends_with(REAUTH_UNAVAILABLE)),
            "{:?}",
            r.warnings
        );
        assert!(e.installed().auth_rights.is_empty());
        assert!(r.warnings.iter().any(|w| w == MAC_SAME_USER_OFF), "{r:?}");
        assert!(r.started);
    }

    /// SIP not enabled (disabled, unknown, a custom configuration, a
    /// failing csrutil): refused before any change, with the exact reason.
    #[test]
    fn macos_install_refuses_without_sip_before_any_change() {
        let cases = [
            Some(ok("System Integrity Protection status: disabled.\n")),
            Some(ok("System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n\tKext Signing: enabled\n")),
            Some(CmdOutput {
                status: 1,
                stdout: String::new(),
                stderr: "csrutil: failed".into(),
            }),
            None,
        ];
        for c in cases {
            let e = mac_env();
            let before = e.tree();
            e.host.set(|s| s.csrutil = c.clone());
            match e.run(&opts()) {
                Err(InstallError::SipRequired) => {}
                other => panic!("{c:?}: {other:?}"),
            }
            assert_eq!(e.tree(), before, "{c:?}: install changed something");
            assert!(
                !e.calls().iter().any(|l| l.contains("dscl")),
                "{:?}",
                e.calls()
            );
        }
        assert_eq!(
            InstallError::SipRequired.to_string(),
            "locked mode on macOS needs System Integrity Protection: without it the hardened \
             runtime does not stop library injection (DYLD_INSERT_LIBRARIES). Enable SIP \
             (Recovery: csrutil enable) and run install again."
        );
    }

    /// The CI seam (debug builds only): install goes on, with a warning.
    #[test]
    fn macos_install_with_the_sip_seam_warns() {
        let e = mac_env();
        e.host
            .set(|s| s.csrutil = Some(ok("System Integrity Protection status: disabled.\n")));
        let r = install_with(&e.layout, &e.host, &opts(), &e.binary, true).unwrap();
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("(test build: SIP check bypassed)")),
            "{:?}",
            r.warnings
        );
        // SIP on: no warning.
        let e = mac_env();
        let r = install_with(&e.layout, &e.host, &opts(), &e.binary, true).unwrap();
        assert!(
            !r.warnings.iter().any(|w| w.contains("SIP")),
            "{:?}",
            r.warnings
        );
    }

    /// A new config.toml alone on a loaded job: no restart, and the daemon
    /// confirms it over its own socket dir (`/var/db/saiife-run`) as
    /// `_saiife`, never `/run/saiife`.
    #[test]
    fn macos_config_change_is_confirmed_over_the_macos_socket() {
        let e = mac_env();
        e.install();
        e.settle();
        let cfg = e._src.path().join("new.toml");
        fs::write(
            &cfg,
            "version = 2\nlocked = true\n\n[guard]\nbudget_ms = 40\n",
        )
        .unwrap();
        let mut o = opts();
        o.config = Some(cfg);
        let r = e.run(&o).unwrap();
        assert_eq!(r.changed, [CONFIG]);
        let calls = e.calls();
        assert!(!calls.iter().any(|c| c.contains("kickstart")), "{calls:?}");
        let uid = e.host.user(MACOS_DAEMON_USER).unwrap().uid;
        let want = format!("ipc policy.reload {} {uid}", e.layout.at(RUN_DIR).display());
        assert!(calls.contains(&want), "{calls:?}");
        assert!(want.contains("/var/db/saiife-run"), "{want}");
        assert_eq!(r.policy_hash.as_deref(), Some("fake"));
        // Not confirmed: the problem names the macOS log, not journalctl.
        e.host.set(|s| {
            s.calls.clear();
            s.policy_reload_error = Some("unreachable".into());
        });
        let cfg = e._src.path().join("newer.toml");
        fs::write(
            &cfg,
            "version = 2\nlocked = true\n\n[guard]\nbudget_ms = 45\n",
        )
        .unwrap();
        o.config = Some(cfg);
        let r = e.run(&o).unwrap();
        let p = r.reload_problem.expect("a reload problem");
        assert!(p.ends_with(&format!("(see {DAEMON_LOG})")), "{p}");
    }

    #[test]
    fn macos_start_bootstraps_then_kickstarts_on_change() {
        let e = mac_env();
        e.install();
        let plist = e.layout.at(UNIT).display().to_string();
        let calls = e.calls();
        let launch: Vec<&String> = calls
            .iter()
            .filter(|c| c.starts_with("launchctl"))
            .collect();
        assert_eq!(
            launch,
            [
                PRINT,
                "launchctl enable system/com.saiife.saiifed",
                &format!("launchctl bootstrap system {plist}"),
            ]
        );
        // Loaded, nothing changed: left alone.
        e.settle();
        e.install();
        let launch: Vec<String> = e
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("launchctl"))
            .collect();
        assert_eq!(launch, [PRINT]);
        // A new binary: restarted in place.
        let mut v2 = signed();
        v2.extend_from_slice(b"v2");
        fs::write(&e.binary, &v2).unwrap();
        e.host.set(|s| s.calls.clear());
        let r = e.install();
        let launch: Vec<String> = e
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("launchctl"))
            .collect();
        assert_eq!(
            launch,
            [PRINT, "launchctl kickstart -k system/com.saiife.saiifed"]
        );
        assert_eq!(r.changed, ["/opt/saiife/bin/saiife"]);
        // A changed plist: launchd reads it only at bootstrap, so the job
        // is reloaded.
        let plist_path = e.layout.at(UNIT);
        fs::write(&plist_path, "<plist/>").unwrap();
        e.host.set(|s| s.calls.clear());
        let r = e.install();
        let launch: Vec<String> = e
            .calls()
            .into_iter()
            .filter(|c| c.starts_with("launchctl"))
            .collect();
        let plist = plist_path.display().to_string();
        assert_eq!(
            launch,
            [
                PRINT.to_string(),
                "launchctl bootout system/com.saiife.saiifed".to_string(),
                "launchctl enable system/com.saiife.saiifed".to_string(),
                format!("launchctl bootstrap system {plist}"),
            ]
        );
        assert_eq!(
            r.changed,
            ["/Library/LaunchDaemons/com.saiife.saiifed.plist"]
        );
        assert_eq!(
            fs::read_to_string(&plist_path).unwrap(),
            launchd::plist_text()
        );
        // A failed bootstrap names the daemon log.
        let e = mac_env();
        let plist = e.layout.at(UNIT).display().to_string();
        e.host.set(|s| {
            s.run.insert(
                format!("launchctl bootstrap system {plist}"),
                exit(5, "Bootstrap failed: 5: Input/output error"),
            );
        });
        match e.run(&opts()) {
            Err(InstallError::Step { step, detail }) => {
                assert_eq!(step, "start");
                assert!(detail.contains("Bootstrap failed"), "{detail}");
                assert!(
                    detail.ends_with("(see /var/log/saiife/daemon.log)"),
                    "{detail}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn macos_second_install_unchanged() {
        let e = mac_env();
        e.install();
        let before = e.installed();
        e.settle();
        let r = e.install();
        assert!(r.changed.is_empty(), "{:?}", r.changed);
        assert!(r.started);
        let after = e.installed();
        assert_eq!(after.users, before.users);
        assert_eq!(after.dirs, before.dirs);
        assert_eq!(after.files, before.files);
        assert_eq!(after.auth_rights, before.auth_rights);
        assert!(!e.calls().iter().any(|c| c.contains("-create")));
    }

    fn preset_saiife(e: &MacEnv, uid: u32, shell: &str, read: CmdOutput) {
        e.host.set(|s| {
            s.groups.insert("_saiife".into(), uid);
            s.users.insert(
                "_saiife".into(),
                UserInfo {
                    uid,
                    gid: uid,
                    home: "/var/empty".into(),
                    shell: shell.into(),
                },
            );
            s.run.insert(dscl_read_line("_saiife"), read);
        });
    }

    #[test]
    #[allow(non_snake_case)] // the brief's names: `_saiife` is the user
    fn existing_login__saiife_refused() {
        // A login account (uid 501, a shell).
        let e = mac_env();
        preset_saiife(
            &e,
            501,
            "/bin/zsh",
            ok("UniqueID: 501\nUserShell: /bin/zsh\n"),
        );
        let err = e.run(&opts()).unwrap_err();
        assert!(matches!(err, InstallError::Refused { .. }), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("501") && msg.contains("/bin/zsh"), "{msg}");
        assert!(!e.layout.at(ETC_DIR).exists());
        assert!(!e.calls().iter().any(|c| c.contains("-create")));
        // Hidden with /usr/bin/false but a login-range uid.
        let e = mac_env();
        preset_saiife(&e, 502, "/usr/bin/false", ok("IsHidden: 1\n"));
        assert!(e.run(&opts()).unwrap_err().to_string().contains("502"));
        // Below 500 with the right shell, but not hidden.
        let e = mac_env();
        preset_saiife(&e, 250, "/usr/bin/false", ok("UniqueID: 250\n"));
        let msg = e.run(&opts()).unwrap_err().to_string();
        assert!(msg.contains("not hidden"), "{msg}");
    }

    /// On a real Mac, `RealHost::user` already hides a `_saiife` that only
    /// another directory node has, so install goes on to create it, and
    /// `host::create_account` refuses that ("exists in a directory node
    /// other than the local one"; tested in host.rs,
    /// `unreadable_or_foreign_record_is_refused_before_any_create`). The
    /// fake's `user` does not model nodes and returns the record: this
    /// covers the second line of defence, the local-node read here.
    #[test]
    #[allow(non_snake_case)] // the brief's names: `_saiife` is the user
    fn nonlocal__saiife_refused() {
        // A directory-service account: `dscl .` does not have it.
        let e = mac_env();
        preset_saiife(
            &e,
            250,
            "/usr/bin/false",
            exit(56, "<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)"),
        );
        let msg = e.run(&opts()).unwrap_err().to_string();
        assert!(msg.contains("not in the local directory"), "{msg}");
        assert!(!e.layout.at(ETC_DIR).exists());
    }

    #[test]
    #[allow(non_snake_case)] // the brief's names: `_saiife` is the user
    fn existing_hidden__saiife_reused() {
        let e = mac_env();
        preset_saiife(
            &e,
            250,
            "/usr/bin/false",
            ok("IsHidden:\n 1\nUniqueID: 250\nUserShell: /usr/bin/false\n"),
        );
        e.install();
        let i = e.installed();
        assert!(i.users.is_empty(), "{:?}", i.users);
        assert_eq!(i.groups, ["_saiifeaudit"]);
        assert_eq!(i.memberships.len(), 1);
        let calls = e.calls();
        assert!(!calls.iter().any(|c| c.contains("-create /Users/_saiife")));
        assert!(!calls
            .iter()
            .any(|c| c == "/usr/bin/dscl . -create /Groups/_saiife"));
        // The audit group got a free id, not the one the user has.
        let audit = e.host.group_id("_saiifeaudit").unwrap();
        assert_ne!(audit, 250);
        assert!(MACOS_ID_RANGE.contains(&audit));
        // A group with another member is not adopted.
        let e = mac_env();
        preset_saiife(&e, 250, "/usr/bin/false", ok("IsHidden: 1\n"));
        e.host
            .set(|s| drop(s.members.insert("_saiife".into(), vec!["alice".into()])));
        let msg = e.run(&opts()).unwrap_err().to_string();
        assert!(msg.contains("alice"), "{msg}");
    }

    #[test]
    fn dscl_is_hidden_reads_both_layouts() {
        assert!(dscl_is_hidden("IsHidden: 1\n"));
        assert!(dscl_is_hidden("Foo: x\nIsHidden:\n 1\n"));
        assert!(dscl_is_hidden("IsHidden: YES\n"));
        assert!(!dscl_is_hidden("IsHidden: 0\n"));
        assert!(!dscl_is_hidden("UniqueID: 250\n"));
        assert!(!dscl_is_hidden("NotIsHidden: 1\n"));
        // Other prefixes stay refused.
        assert!(!dscl_is_hidden("dsAttrTypeStandard:IsHidden: 1\n"));
        assert!(!dscl_is_hidden("dsAttrTypeNative:IsHidden: 0\n"));
    }

    /// `dscl . -read /Users/_saiife` on a macos-15 runner (locked-macos
    /// log), verbatim but for the GUID.
    #[test]
    fn dscl_is_hidden_reads_the_real_native_attribute() {
        let real = r#"dsAttrTypeNative:accountPolicyData:
 <?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>creationTime</key>
	<real>1793353472.3020391</real>
</dict>
</plist>

dsAttrTypeNative:IsHidden: 1
dsAttrTypeNative:record_daemon_version: 9054000
AppleMetaNodeLocation: /Local/Default
GeneratedUID: 00000000-0000-0000-0000-000000000000
NFSHomeDirectory: /var/empty
Password: *
PrimaryGroupID: 206
RealName:
 saiife daemon
RecordName: _saiife
RecordType: dsRecTypeStandard:Users
UniqueID: 206
UserShell: /usr/bin/false
"#;
        assert!(dscl_is_hidden(real));
        let attrs = crate::host::parse_dscl_attrs(real);
        assert_eq!(attrs["UniqueID"], ["206"]);
        assert_eq!(attrs["UserShell"], ["/usr/bin/false"]);
        assert_eq!(attrs["AppleMetaNodeLocation"], ["/Local/Default"]);
        assert!(!dscl_is_hidden(&real.replace("IsHidden: 1", "IsHidden: 0")));
    }

    #[test]
    fn macos_managed_paths() {
        let e = mac_env();
        e.install();
        let want = [
            (
                "claude",
                "/Library/Application Support/ClaudeCode/managed-settings.d/50-saiife.json",
            ),
            ("codex", "/etc/codex/requirements.toml"),
            (
                "gemini",
                "/Library/Application Support/GeminiCli/settings.json",
            ),
        ];
        let i = e.installed();
        for (agent, path) in want {
            let a = i.agents.iter().find(|a| a.agent == agent).unwrap();
            assert_eq!(a.path, Path::new(path), "{agent}");
            assert!(e.at(path).is_file(), "{path}");
            assert_eq!(
                e.layout.at(match agent {
                    "claude" => CLAUDE_MANAGED,
                    "codex" => CODEX_REQUIREMENTS,
                    _ => GEMINI_SETTINGS,
                }),
                e.at(path)
            );
        }
        assert_eq!(
            fs::read_to_string(e.at(path_of(CLAUDE_MANAGED))).unwrap(),
            saiife_agents::claude::managed_settings()
        );
        let mcp = i
            .files
            .iter()
            .find(|f| f.kind == FileKind::Managed)
            .unwrap();
        assert_eq!(
            mcp.path,
            Path::new(
                "/Library/Application Support/ClaudeCode/managed-settings.d/60-saiife-mcp.json"
            )
        );
        // The Linux paths are not written.
        for linux in ["/etc/claude-code", "/etc/gemini-cli"] {
            assert!(!e.at(linux).exists(), "{linux}");
        }
    }

    fn path_of(abs: &'static str) -> &'static str {
        Layout::under_for("/", Platform::Macos).logical(abs)
    }

    #[test]
    fn macos_install_warns_on_claude_mdm_profile() {
        let e = mac_env();
        let p = e.at(CLAUDE_MDM_PROFILE);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "<plist/>").unwrap();
        let r = e.install();
        assert!(
            r.warnings.iter().any(|w| w.starts_with(CLAUDE_MDM_PROFILE)
                && w.contains("/Library/Application Support/ClaudeCode/managed-settings.d")),
            "{:?}",
            r.warnings
        );
        // Without Claude Code it does not matter.
        let e = mac_env();
        let p = e.at(CLAUDE_MDM_PROFILE);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "<plist/>").unwrap();
        let mut o = opts();
        o.agents = vec![Agent::Codex];
        let r = e.run(&o).unwrap();
        assert_eq!(r.warnings, [MAC_SAME_USER_OFF], "{:?}", r.warnings);
        // No profile, no warning.
        let r = mac_env().install();
        assert_eq!(r.warnings, [MAC_SAME_USER_OFF], "{:?}", r.warnings);
    }

    #[test]
    fn macos_unfit_binary_refused_on_the_real_system() {
        let p = Path::new("/usr/local/bin/saiife");
        let unsigned = fake_macho(None);
        let no_runtime = fake_macho(Some((false, false, true)));
        let elf = fake_elf(None, 0, Some(false));
        for (bytes, want) in [
            (&unsigned[..], "it is not code-signed"),
            (&no_runtime[..], "without the hardened runtime"),
            (&elf[..], "not a thin 64-bit Mach-O executable"),
        ] {
            match check_macho(p, bytes, true) {
                Err(InstallError::Refused { path, detail }) => {
                    assert_eq!(path, p);
                    assert!(detail.contains(want), "{detail}");
                    assert!(detail.contains("hardened runtime"), "{detail}");
                }
                other => panic!("{want}: {other:?}"),
            }
            // Not strict (`--root`, `--allow-test-build`): a warning.
            let w = check_macho(p, bytes, false).unwrap();
            assert!(
                w[0].starts_with("/usr/local/bin/saiife: ") && w[0].contains(want),
                "{w:?}"
            );
        }
        // Ad-hoc (and CMS-less) signatures with the runtime only warn.
        let adhoc = fake_macho(Some((true, true, false)));
        let w = check_macho(p, &adhoc, true).unwrap();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("ad-hoc signature"), "{w:?}");
        let no_cms = fake_macho(Some((false, true, false)));
        let w = check_macho(p, &no_cms, true).unwrap();
        assert!(w[0].contains("no CMS signature"), "{w:?}");
        // A Developer ID build: nothing to say.
        assert!(check_macho(p, &signed(), true).unwrap().is_empty());
        // Through install: an unsigned build under the test root warns.
        let e = mac_env();
        fs::write(&e.binary, &unsigned).unwrap();
        let r = e.install();
        assert!(
            r.warnings.iter().any(|w| w.contains("not code-signed")),
            "{:?}",
            r.warnings
        );
    }

    #[test]
    fn macos_untrusted_links_refused() {
        // `/var` pointing anywhere but `private/var`.
        let e = mac_env();
        let r = e.layout.root();
        fs::remove_file(r.join("var")).unwrap();
        fs::create_dir_all(r.join("elsewhere/db")).unwrap();
        std::os::unix::fs::symlink("elsewhere", r.join("var")).unwrap();
        let err = e.run(&opts()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        // `/etc` as the right link, but not root's.
        let e = mac_env();
        crate::testing::set_root_uid(&e.host, rustix::process::getuid().as_raw() + 1);
        let err = e.run(&opts()).unwrap_err();
        assert!(err.to_string().contains("not root"), "{err}");
    }

    #[test]
    fn beneath_links_resolves_only_trusted_links() {
        let e = mac_env();
        let b = |p: &str| beneath_links(&e.layout, &e.host, Path::new(p));
        assert_eq!(b("/var/db/saiife"), PathBuf::from("/private/var/db/saiife"));
        assert_eq!(b("/etc/saiife"), PathBuf::from("/private/etc/saiife"));
        assert_eq!(b("/opt/saiife"), PathBuf::from("/opt/saiife"));
        // On Linux nothing is resolved.
        let l = Layout::under_for(e.layout.root(), Platform::Linux);
        assert_eq!(
            beneath_links(&l, &e.host, Path::new("/var/db")),
            PathBuf::from("/var/db")
        );
    }

    /// A root-owned file outside the tree, as /etc/sudoers would be.
    fn outside_file(e: &MacEnv, bytes: &[u8]) -> PathBuf {
        let p = e._src.path().join("sudoers");
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o440)).unwrap();
        p
    }

    fn untouched(e: &MacEnv, p: &Path) {
        assert_eq!(mode(p), 0o440, "{}", p.display());
        let s = e.host.state();
        assert!(
            !s.chowns.iter().any(|c| c.path == p),
            "{} was chowned",
            p.display()
        );
    }

    #[test]
    fn hard_linked_vault_key_refused() {
        let e = mac_env();
        e.install();
        e.settle();
        let key = e.at("/var/db/saiife/keys/vault.key");
        let target = outside_file(&e, &[9u8; 32]);
        fs::remove_file(&key).unwrap();
        fs::hard_link(&target, &key).unwrap();
        let chowns_before = e.host.state().chowns.len();
        match e.run(&opts()) {
            Err(InstallError::Refused { path, detail }) => {
                assert_eq!(path, key);
                assert!(detail.contains("2 hard links"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        untouched(&e, &target);
        // Nothing was chowned under the key's name either.
        let s = e.host.state();
        assert!(!s.chowns[chowns_before..].iter().any(|c| c.path == key));
    }

    #[test]
    fn symlinked_vault_key_refused() {
        let e = mac_env();
        e.install();
        e.settle();
        let key = e.at("/var/db/saiife/keys/vault.key");
        let target = outside_file(&e, &[9u8; 32]);
        fs::remove_file(&key).unwrap();
        std::os::unix::fs::symlink(&target, &key).unwrap();
        let err = e.run(&opts()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        untouched(&e, &target);
    }

    #[test]
    fn foreign_owned_daemon_file_refused() {
        let e = mac_env();
        e.install();
        let keys =
            fsops::open_dir_beneath(e.layout.root(), Path::new("private/var/db/saiife/keys"))
                .unwrap()
                .unwrap();
        let shown = e.at("/var/db/saiife/keys/vault.key");
        let name = std::ffi::OsStr::new("vault.key");
        let own = rustix::process::getuid().as_raw();
        // Owned by root or the daemon user: fine.
        assert!(open_daemon_file(&keys, name, &shown, Some(32), &[own])
            .unwrap()
            .is_some());
        // Anyone else's (the test user's file stands in for it).
        match open_daemon_file(&keys, name, &shown, Some(32), &[own + 1]) {
            Err(InstallError::Refused { detail, .. }) => {
                assert!(detail.contains(&format!("owned by uid {own}")), "{detail}")
            }
            other => panic!("{other:?}"),
        }
        // The wrong size.
        let err = open_daemon_file(&keys, name, &shown, Some(16), &[own]).unwrap_err();
        assert!(err.to_string().contains("not 16"), "{err}");
        // Missing: None, never created here.
        assert!(
            open_daemon_file(&keys, std::ffi::OsStr::new("nope"), &shown, None, &[own])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn linked_daemon_log_refused() {
        // A hard link.
        let e = mac_env();
        e.install();
        e.settle();
        let log = e.at(DAEMON_LOG);
        let target = outside_file(&e, b"");
        fs::remove_file(&log).unwrap();
        fs::hard_link(&target, &log).unwrap();
        let err = e.run(&opts()).unwrap_err();
        assert!(err.to_string().contains("hard links"), "{err}");
        untouched(&e, &target);
        // A symlink.
        let e = mac_env();
        e.install();
        e.settle();
        let log = e.at(DAEMON_LOG);
        let target = outside_file(&e, b"");
        fs::remove_file(&log).unwrap();
        std::os::unix::fs::symlink(&target, &log).unwrap();
        let err = e.run(&opts()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        untouched(&e, &target);
    }

    #[test]
    fn symlinked_state_dir_entry_refused() {
        // The daemon user swaps keys/ for a link to a root-owned dir.
        let e = mac_env();
        e.install();
        e.settle();
        let keys = e.at("/var/db/saiife/keys");
        let elsewhere = e._src.path().join("etc-like");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&keys).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &keys).unwrap();
        assert!(e.run(&opts()).is_err());
        assert_eq!(mode(&elsewhere), 0o755);
        assert!(!e.host.state().chowns.iter().any(|c| c.path == elsewhere));
    }

    /// A root-owned state dir is what a crashed install leaves: the
    /// pre-check and the fd-relative step agree, and it is handed over.
    #[test]
    fn macos_root_owned_state_dir_is_repaired() {
        let e = mac_env();
        let st = e.at("/var/db/saiife");
        fs::create_dir_all(st.join("keys")).unwrap();
        for d in [&st, &st.join("keys")] {
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        // The test user stands in for root here (the fake's root).
        let r = e.install();
        let d = e.host.user("_saiife").unwrap();
        let daemon = (d.uid, e.host.group_id("_saiife").unwrap());
        assert_eq!(chowned(&e.host, &st), vec![daemon]);
        assert_eq!(chowned(&e.host, &st.join("keys")), vec![daemon]);
        assert!(st.join("keys/vault.key").is_file(), "{r:?}");
        // Anyone else's is refused by both.
        let e = mac_env();
        let st = e.at("/var/db/saiife");
        fs::create_dir_all(&st).unwrap();
        fs::set_permissions(&st, fs::Permissions::from_mode(0o700)).unwrap();
        crate::testing::set_root_uid(&e.host, rustix::process::getuid().as_raw() + 1);
        let msg = e.run(&opts()).unwrap_err().to_string();
        assert!(msg.contains("not by the _saiife user"), "{msg}");
    }

    #[test]
    fn unreadable_local_record_refused() {
        let e = mac_env();
        preset_saiife(&e, 250, "/usr/bin/false", exit(1, "eDSPermissionError"));
        let msg = e.run(&opts()).unwrap_err().to_string();
        assert!(msg.contains("could not be read"), "{msg}");
        assert!(!e.layout.at(ETC_DIR).exists());
    }

    #[test]
    fn unreadable_primary_gid_members_refused() {
        let e = mac_env();
        preset_saiife(&e, 250, "/usr/bin/false", ok("IsHidden: 1\n"));
        e.host.set(|s| s.fail_primary_gid = vec![250]);
        let msg = e.run(&opts()).unwrap_err().to_string();
        assert!(msg.contains("could not be read"), "{msg}");
        assert!(msg.contains("_saiife"), "{msg}");
        assert!(!e.layout.at(ETC_DIR).exists());
    }
}
