//! `saiife system install` (spec §7): users and groups, the binary under
//! `/opt/saiife`, `/etc/saiife`, the vault key, the unit, the managed hooks,
//! `installed.toml`, then the daemon is started.
//!
//! Every step is idempotent. Whatever a step creates is recorded in
//! `installed.toml` before the next step runs, so a failure part-way leaves
//! an accurate list for `uninstall`.

use crate::default_config::default_config;
use crate::fsops;
use crate::host::{valid_name, Host};
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
}

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

fn refused(path: &Path, detail: impl Into<String>) -> InstallError {
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
    // 1. Root, then the supported-system check. Nothing runs before these.
    if layout.is_system() && host.euid() != 0 {
        return Err(InstallError::NotRoot);
    }
    let systemd = match check_supported(layout, host) {
        Support::Supported { systemd, .. } => systemd,
        Support::Refused(why) => return Err(InstallError::Unsupported(why)),
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
    check_daemon_user(host, previous.as_ref())?;
    check_daemon_group(host, previous.as_ref())?;
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
        Some(p) => Some(validated_config(p)?),
        None => None,
    };
    // The bytes checked are the bytes copied.
    let binary_bytes = std::fs::read(binary).map_err(|e| InstallError::Step {
        step: "binary".into(),
        detail: format!("{}: {e}", binary.display()),
    })?;
    let strict = layout.is_system() && !opts.allow_test_build;
    let warnings: Vec<String> = check_binary(binary, &binary_bytes, strict)?
        .into_iter()
        .collect();

    // An existing key decides its own mode (never rotated); a record is
    // not trusted for it.
    let key_mode = match key_file_mode(layout)? {
        Some(m) => m,
        None => vault_key_mode(systemd),
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
    });
    // Polkit presence, decided once: the default `same_user`, the action
    // file and the warning all follow it.
    // An unsafe parent of the action dir (say a 0777 /usr/share) is not
    // a reason to abort: the action is skipped and approvals fall back to
    // a second account (`same_user = "deny"` for a new config).
    let mut warnings = warnings;
    let polkit = if !polkit_present(layout, host) {
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
        polkit,
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
    // 5. /etc/saiife, policy.d, config.toml.
    run.config(new_config.as_deref(), &opts.approvers)?;
    // 5b. The polkit action, when polkit is there.
    run.polkit()?;
    // 6. The vault key.
    run.vault_key(key_mode)?;
    // 7. The unit.
    let unit_changed = run.unit(key_mode, systemd)?;
    // 8. Managed hooks.
    let mut agents = opts.agents.clone();
    agents.sort();
    agents.dedup();
    for a in agents {
        run.managed(a)?;
    }
    run.save()?;
    // 9. Start (or restart) the daemon.
    // A running daemon picks up a new group membership only at start.
    run.start(binary_changed || unit_changed || member_added)?;
    // 10. Wait for the socket on the real machine.
    if layout.is_system() {
        let sock = layout.at(SOCKET);
        let deadline = Instant::now() + SOCKET_WAIT;
        while !sock.exists() {
            if Instant::now() >= deadline {
                return Err(InstallError::Step {
                    step: "start".into(),
                    detail: format!(
                        "the daemon did not open {SOCKET} within 10 s (see: journalctl -u saiifed)"
                    ),
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
    let Some(gid) = host.group_id(DAEMON_GROUP) else {
        return Ok(());
    };
    let mut others: Vec<String> = host
        .group_members(DAEMON_GROUP)
        .unwrap_or_default()
        .into_iter()
        .chain(host.users_with_primary_gid(gid))
        .filter(|m| m != DAEMON_USER)
        .collect();
    others.sort();
    others.dedup();
    let ours = live.is_some_and(|p| p.groups.iter().any(|n| n == DAEMON_GROUP));
    if !others.is_empty() {
        return Err(refused(
            Path::new("/etc/group"),
            format!(
                "the group {DAEMON_GROUP} (gid {gid}) has members besides {DAEMON_USER}: {}; \
                 they could read the vault key, so saiife does not use it \
                 (remove them from the group first)",
                others.join(", ")
            ),
        ));
    }
    if gid >= 1000 && !ours {
        return Err(refused(
            Path::new("/etc/group"),
            format!(
                "a group {DAEMON_GROUP} already exists with gid {gid}; saiife \
                 never adopts a regular group for its daemon (it needs a system \
                 gid below 1000)"
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
    let mut i: Installed = toml::from_str(&text).ok()?;
    if i.version != INSTALLED_VERSION {
        return None;
    }
    i.users.retain(|u| u == DAEMON_USER);
    i.groups.retain(|g| g == DAEMON_GROUP || g == AUDIT_GROUP);
    i.memberships
        .retain(|m| m.user == DAEMON_USER && m.group == AUDIT_GROUP);
    let unit_dir = Path::new(UNIT).parent().unwrap_or(Path::new("/"));
    let known_dirs = [
        Path::new(BIN_DIR),
        Path::new(POLICY_D),
        Path::new(CREDSTORE),
        unit_dir,
        Path::new(CLAUDE_MANAGED_DIR),
        Path::new(CODEX_DIR),
        Path::new(GEMINI_DIR),
    ];
    i.dirs
        .retain(|d| d != Path::new("/") && known_dirs.iter().any(|k| k.starts_with(d)));
    i.files.retain(|f| {
        (f.kind == FileKind::Config && f.path == Path::new(CONFIG))
            || (f.kind == FileKind::VaultKey && f.path == Path::new(VAULT_KEY))
    });
    for f in &mut i.files {
        if f.kind == FileKind::VaultKey {
            f.sha256 = None;
        }
    }
    i.agents.clear();
    Some(i)
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
    if uid != root_uid {
        return Err(refused(
            p,
            format!("exists and is owned by uid {uid}, not root; saiife does not write below it"),
        ));
    }
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(refused(
            p,
            format!(
                "mode {mode:04o} is writable by group or others; saiife does not write below it"
            ),
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
    let saiife_uid = host.user(DAEMON_USER).map(|u| u.uid);
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
        if Some(m.uid()) != saiife_uid {
            return Err(refused(
                &p,
                format!(
                    "exists and is owned by uid {}, not by the {DAEMON_USER} user; \
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
fn validated_config(path: &Path) -> Result<String, InstallError> {
    let text = std::fs::read_to_string(path).map_err(|e| refused(path, e.to_string()))?;
    let loaded = saiife_policy::load_and_check(path, &saiife_policy::Getent)
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

/// One install run: the record so far and what was written last.
struct Run<'a> {
    layout: &'a Layout,
    host: &'a dyn Host,
    /// [`polkit_present`], decided once per run.
    polkit: bool,
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
        let uid = self.host.user("root").map(|u| u.uid);
        let gid = self.host.group_id("root");
        match (uid, gid) {
            (Some(u), Some(g)) => Ok((u, g)),
            _ => Err(InstallError::Step {
                step: "owners".into(),
                detail: "user or group root not found".into(),
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
    fn dir(&mut self, abs: &str, mode: u32, own: bool) -> Result<(), InstallError> {
        let mut logical = PathBuf::from("/");
        let target = Path::new(abs);
        for comp in target.components().skip(1) {
            logical.push(comp);
            let p = self
                .layout
                .try_at(&logical)
                .map_err(|e| refused(&logical, e.to_string()))?;
            let is_target = logical == target;
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

    /// True when the daemon user was just added to the audit group.
    fn users(&mut self) -> Result<bool, InstallError> {
        for g in [DAEMON_GROUP, AUDIT_GROUP] {
            if self.host.group_id(g).is_none() {
                self.host.create_system_group(g).map_err(step("users"))?;
                if !self.rec.groups.iter().any(|x| x == g) {
                    self.rec.groups.push(g.to_string());
                }
                self.changed(format!("group {g}"));
                self.save()?;
            }
        }
        if self.host.user(DAEMON_USER).is_none() {
            self.host
                .create_system_user(DAEMON_USER, DAEMON_GROUP)
                .map_err(step("users"))?;
            if !self.rec.users.iter().any(|x| x == DAEMON_USER) {
                self.rec.users.push(DAEMON_USER.to_string());
            }
            self.changed(format!("user {DAEMON_USER}"));
            self.save()?;
        }
        // The daemon regroups the audit dir at start: it must be a member.
        // Added and recorded only when it is not one yet, so uninstall
        // reverts only what install did.
        let member = self
            .host
            .group_members(AUDIT_GROUP)
            .is_some_and(|m| m.iter().any(|u| u == DAEMON_USER));
        if !member {
            let m = Membership {
                user: DAEMON_USER.to_string(),
                group: AUDIT_GROUP.to_string(),
            };
            if !self.rec.memberships.contains(&m) {
                self.rec.memberships.push(m);
            }
            // Recorded before it is made: a failure part-way is still listed.
            self.save()?;
            self.host
                .add_to_group(DAEMON_USER, AUDIT_GROUP)
                .map_err(step("users"))?;
            self.changed(format!("{DAEMON_USER} in group {AUDIT_GROUP}"));
        }
        Ok(!member)
    }

    /// Records (or refreshes) a file. `created` sticks from the first record.
    fn record_file(&mut self, abs: &str, kind: FileKind, sha256: Option<String>, created: bool) {
        let path = PathBuf::from(abs);
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
        if write {
            fsops::write_file_atomic(&p, bytes, mode).map_err(step(step_name))?;
            self.changed(abs);
        } else {
            fsops::set_file_mode(&p, mode).map_err(step(step_name))?;
            self.unchanged(abs);
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

    fn config(&mut self, new: Option<&str>, approvers: &[String]) -> Result<(), InstallError> {
        self.dir(ETC_DIR, 0o755, true)?;
        self.dir(POLICY_D, 0o755, true)?;
        let p = self.at(CONFIG);
        let text = match new {
            Some(t) => t.to_string(),
            None => match fsops::lstat(&p).map_err(|e| refused(&p, e.to_string()))? {
                // An existing config is kept as it is.
                Some(_) => {
                    let current = std::fs::read(&p).map_err(step("config"))?;
                    return self
                        .file(CONFIG, &current, 0o644, FileKind::Config, "config")
                        .map(|_| ());
                }
                None => default_config(self.layout, approvers, self.polkit),
            },
        };
        self.file(CONFIG, text.as_bytes(), 0o644, FileKind::Config, "config")
            .map(|_| ())
    }

    /// The polkit action file (root:root 0644), only when `pkcheck` exists.
    fn polkit(&mut self) -> Result<(), InstallError> {
        if !self.polkit {
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
            VaultKeyMode::File => (
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
                VaultKeyMode::File => {
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
            VaultKeyMode::File => unit_text(systemd.min(249)),
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
                    self.changed(file_abs);
                } else {
                    self.unchanged(file_abs);
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
                    Change::Unchanged => self.unchanged(file_abs),
                    _ => self.changed(file_abs),
                }
                let sha = entry(&p).map_err(agent_step("managed"))?.ok_or_else(|| {
                    InstallError::Step {
                        step: "managed".into(),
                        detail: format!("{file_abs}: saiife's entry is missing after the write"),
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

    /// Records (or refreshes) a managed agent. `created_file` sticks from
    /// the first record.
    fn record_agent(&mut self, a: Agent, file_abs: &str, sha: String, whole: bool, created: bool) {
        let path = PathBuf::from(file_abs);
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

    fn start(&mut self, changed: bool) -> Result<(), InstallError> {
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
        let args: &[&str] = if changed && active {
            &["restart", UNIT_NAME]
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
        Ok(())
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
        assert_eq!(i.files.len(), 4);
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
