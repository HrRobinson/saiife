//! `saiife system install` and `system uninstall` on Windows (plan 19b Task 7, W9, W10,
//! W14, W15, W20, W24, W26). Everything goes through [`Host`] and `std::fs`, so Linux
//! tests drive it against `Layout::under_for(tmp, Platform::Windows)`. Nothing here has
//! run on Windows outside CI's `locked-windows`.
//!
//! This runs elevated and writes protected files, so the order matters:
//!
//! - **Nothing is written before every check has passed**, for every path the run would
//!   create or write into ([`preflight`]). The one exception is an empty root, which the
//!   lock needs, and which goes again if the run ends with nothing in it ([`WinLock`]).
//! - **A new dir has its descriptor from its first moment** (`create_dir_sddl`). A dir
//!   that appears first is an error there, and is never taken over.
//! - **A new file gets its descriptor before it has its name**: it is written beside its
//!   target, the descriptor is set on that, then it is renamed in.
//! - **Every set checks the whole chain first** ([`Check::chain`]): a junction is refused,
//!   and so is an ancestor someone else controls. The real `set_sddl` also compares the
//!   handle's true path with the one it was given.
//! - **A dir another product made is never re-ACLed**: see [`Check::check_foreign`].

use crate::fleet::MAX_FLEET_FILE;
use crate::host::{valid_win_name, Hold, Host};
use crate::install::RELOAD_NOT_TAKEN;
use crate::install::{now, refused, step, InstallError, InstallOptions, InstallReport};
use crate::layout::*;
use crate::supported::{check_supported, Support};
use crate::winacl::{
    ancestor_ok, expected, protected_ok, refuse_reparse, service_may_write, set_sddl_tree,
};
use crate::winservice::{ServiceOp, ServiceSpec, ServiceState};
use saiife_agents::claude::{self, HklmPolicy};
use saiife_agents::{codex, gemini, Agent, AgentError, Change};
use saiife_policy::installed::{
    read_installed, write_installed, FileKind, Installed, InstalledFile, ManagedAgent,
    VaultKeyMode, INSTALLED_VERSION,
};
use saiife_win::sddl::{parse, Sd};
use saiife_win::sid::{service_sid, ADMINISTRATORS};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How long install waits for the service to stop, and for its pipe (W10).
const SERVICE_WAIT: Duration = Duration::from_secs(10);
/// How long install waits for the daemon to confirm a reload.
const RELOAD_WAIT: Duration = Duration::from_secs(15);
/// The vault key's length (W15).
const KEY_LEN: u64 = 32;
/// Largest copy of `installed.toml` read.
const MAX_PREVIOUS: u64 = 1024 * 1024;

/// Stands in for `<A>` where a row is only asked who may write, which `<A>` never
/// changes, or for a row that has no `<A>`. It never reaches a disk with an `<A>` in the
/// row: [`Run::row`] takes the real SID from the group.
const NO_AUDIT_SID: &str = ADMINISTRATORS;

/// A managed writer, its fingerprint and its remover (Codex, Gemini CLI).
type WriteFn = fn(&Path, bool) -> Result<Change, AgentError>;
type EntryFn = fn(&Path) -> Result<Option<String>, AgentError>;
type RemoveFn = fn(&Path) -> Result<Change, AgentError>;

fn io_refused(path: &Path, e: impl std::fmt::Display) -> InstallError {
    refused(path, e.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `path`'s metadata without following it. `None` when nothing is there. A reparse point
/// is an error.
fn plain_meta(path: &Path) -> io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            refuse_reparse(path, &m)?;
            Ok(Some(m))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// SHA-256 of the plain file at `path`. `None` when nothing is there.
fn sha256_file(path: &Path) -> io::Result<Option<String>> {
    match plain_meta(path)? {
        None => Ok(None),
        Some(m) if !m.is_file() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        )),
        Some(_) => Ok(Some(sha256_hex(&std::fs::read(path)?))),
    }
}

/// The parent of `C:\a\b`, as text: a Windows path means nothing to `Path` on Linux.
fn parent_of(logical: &str) -> &str {
    logical.rsplit_once('\\').map_or(logical, |(p, _)| p)
}

fn name_of(logical: &str) -> &str {
    logical.rsplit_once('\\').map_or(logical, |(_, n)| n)
}

/// `C:\ProgramData\saiife\log\daemon`: the layout has its file, not the dir.
fn daemon_log_dir(layout: &Layout) -> &'static str {
    parent_of(layout.logical(DAEMON_LOG))
}

/// Whether the logical path lies in `C:\ProgramData\saiife`, or is it.
fn in_tree(layout: &Layout, logical: &str) -> bool {
    let root = layout.logical(OPT_DIR);
    let lower = logical.to_ascii_lowercase();
    let root = root.to_ascii_lowercase();
    lower == root || lower.starts_with(&format!("{root}\\"))
}

/// The dirs one agent's managed file needs, outermost first, as the platform names them.
fn agent_dirs(layout: &Layout, a: Agent) -> Vec<&'static str> {
    match a {
        Agent::Claude => {
            let d = layout.logical(CLAUDE_MANAGED_DIR);
            vec![parent_of(d), d]
        }
        Agent::Codex => {
            let d = layout.logical(CODEX_DIR);
            vec![parent_of(d), d]
        }
        Agent::Gemini => vec![layout.logical(GEMINI_DIR)],
    }
}

fn agent_file(a: Agent) -> &'static str {
    match a {
        Agent::Claude => CLAUDE_MANAGED,
        Agent::Codex => CODEX_REQUIREMENTS,
        Agent::Gemini => GEMINI_SETTINGS,
    }
}

/// The dirs of the tree, outermost first, as the platform names them. Those in [`own_trees`]
/// get every entry below them set again on a reinstall; the others have a row of their own.
fn own_dirs(layout: &Layout) -> [&'static str; 9] {
    [
        layout.logical(OPT_DIR),
        layout.logical(BIN_DIR),
        layout.logical(ETC_DIR),
        layout.logical(POLICY_D),
        layout.logical(STATE_DIR),
        layout.logical(KEYS_DIR),
        layout.logical(LOG_DIR),
        layout.logical(AUDIT_DIR),
        daemon_log_dir(layout),
    ]
}

/// The trees whose rows cover everything below them.
fn own_trees(layout: &Layout) -> [&'static str; 4] {
    [
        layout.logical(ETC_DIR),
        layout.logical(STATE_DIR),
        layout.logical(AUDIT_DIR),
        daemon_log_dir(layout),
    ]
}

// ---------------------------------------------------------------- the checks

/// The W14 checks against one layout.
struct Check<'a> {
    layout: &'a Layout,
    host: &'a dyn Host,
}

impl Check<'_> {
    /// The real path of a path as the platform names it.
    fn at(&self, logical: &str) -> Result<PathBuf, InstallError> {
        self.layout
            .try_at(Path::new(logical))
            .map_err(|e| io_refused(Path::new(logical), e))
    }

    /// `real`'s descriptor, parsed. A reparse point is an error, from the host.
    fn read(&self, logical: &str, real: &Path) -> Result<Sd, InstallError> {
        let shown = Path::new(logical);
        let text = self
            .host
            .get_sddl(real)
            .map_err(|e| io_refused(shown, format!("cannot read its descriptor: {e}")))?;
        parse(&text).map_err(|e| io_refused(shown, format!("its descriptor {text}: {e}")))
    }

    /// `protected_ok` for a path of ours: `<S>` is allowed where the table grants it.
    fn own_ok(&self, logical: &str, sd: &Sd) -> Result<(), InstallError> {
        let shown = Path::new(logical);
        let real = self.at(logical)?;
        let row = expected(self.layout, &real, NO_AUDIT_SID).map_err(|e| io_refused(shown, e))?;
        let service = service_sid(WIN_SERVICE);
        let extra: &[&str] = if row.as_deref().is_some_and(service_may_write) {
            &[service.as_str()]
        } else {
            &[]
        };
        protected_ok(sd, extra)
            .map_err(|e| refused(shown, format!("{e}; saiife does not take over this path")))
    }

    /// Every ancestor of `logical`, top-down, before anything is set or created below it:
    /// no reparse point; above the tree, and in another product's dirs, `ancestor_ok`;
    /// inside the tree, `protected_ok` with `<S>` where its row grants it.
    ///
    /// Inside the tree `ancestor_ok` cannot be the test: `<S>` holds `FA` on `state` by
    /// the table, and that rule would refuse our own row. A service that abused it, by
    /// swapping in a junction, is caught by `set_sddl` comparing the handle's true path.
    ///
    /// A missing ancestor ends the walk: nothing is below it.
    fn chain(&self, logical: &str) -> Result<(), InstallError> {
        let mut at = logical;
        let mut up = Vec::new();
        while at.len() > 3 && at.contains('\\') {
            at = parent_of(at);
            // `C:` is `C:\`.
            let above = if at.len() == 2 {
                format!("{at}\\")
            } else {
                at.to_string()
            };
            up.push(above);
        }
        for ancestor in up.iter().rev() {
            let real = self.at(ancestor)?;
            let shown = Path::new(ancestor.as_str());
            let Some(meta) = plain_meta(&real).map_err(|e| io_refused(shown, e))? else {
                return Ok(());
            };
            if !meta.is_dir() {
                return Err(refused(shown, "is not a directory"));
            }
            let sd = self.read(ancestor, &real)?;
            if in_tree(self.layout, ancestor) {
                self.own_ok(ancestor, &sd)?;
            } else {
                ancestor_ok(&sd).map_err(|e| {
                    refused(shown, format!("{e}; saiife does not build below this path"))
                })?;
            }
        }
        Ok(())
    }

    /// An existing path of ours (`is_dir`: a directory, else a file), checked. `false`
    /// when it is missing.
    fn existing_own(&self, logical: &str, is_dir: bool) -> Result<bool, InstallError> {
        let real = self.at(logical)?;
        let shown = Path::new(logical);
        let Some(meta) = plain_meta(&real).map_err(|e| io_refused(shown, e))? else {
            return Ok(false);
        };
        if meta.is_dir() != is_dir {
            return Err(refused(
                shown,
                if is_dir {
                    "exists and is not a directory"
                } else {
                    "exists and is not a regular file"
                },
            ));
        }
        self.own_ok(logical, &self.read(logical, &real)?)?;
        Ok(true)
    }

    /// An existing dir another product may own, which saiife relies on and never re-ACLs.
    /// `false` when it is missing.
    ///
    /// W14 as written, for the dirs an agent reads its policy from (`ClaudeCode`,
    /// `managed-settings.d`, `Codex`, `gemini-cli`): they must pass `protected_ok`. Where
    /// Users can create entries, a user could plant a settings file before install, which
    /// install would merge and re-ACL, or one later, which the agent would read. Cost: an
    /// admin must correct such a dir's ACL first; a stock `C:\ProgramData` child inherits
    /// Users' right to create. It also closes the window on Codex and Gemini, which write
    /// the file before its row: what it inherits meanwhile lets no one else write.
    ///
    /// Only `C:\ProgramData\OpenAI` holds no policy of an agent. It passes on `ancestor_ok`,
    /// which allows Users to create entries, and a warning says so.
    fn check_foreign(
        &self,
        logical: &str,
        warnings: &mut Vec<String>,
    ) -> Result<bool, InstallError> {
        let real = self.at(logical)?;
        let shown = Path::new(logical);
        let Some(meta) = plain_meta(&real).map_err(|e| io_refused(shown, e))? else {
            return Ok(false);
        };
        if !meta.is_dir() {
            return Err(refused(shown, "exists and is not a directory"));
        }
        let sd = self.read(logical, &real)?;
        let no_takeover = "saiife does not write below it (move it away first)";
        ancestor_ok(&sd).map_err(|e| refused(shown, format!("{e}; {no_takeover}")))?;
        let strict = protected_ok(&sd, &[]);
        let holds_no_policy =
            logical.eq_ignore_ascii_case(parent_of(self.layout.logical(CODEX_DIR)));
        if holds_no_policy {
            if let Err(e) = strict {
                warnings.push(format!(
                    "{logical} belongs to another product and is left as it is: {e}"
                ));
            }
        } else {
            strict.map_err(|e| {
                refused(
                    shown,
                    format!(
                        "{e}: an agent reads its policy here, so a user could plant one; \
                         let only administrators write this dir, then run install again"
                    ),
                )
            })?;
        }
        Ok(true)
    }

    /// Whether install made this dir: it is listed and its descriptor can be set again.
    fn listed(known: Option<&Installed>, logical: &str) -> bool {
        known.is_some_and(|k| k.dirs.iter().any(|d| d == Path::new(logical)))
    }

    /// No reparse point anywhere below `logical`, read before anything is written. The
    /// walk that sets descriptors refuses one too, but by then it has begun.
    fn scan(&self, logical: &str) -> Result<(), InstallError> {
        fn walk(path: &Path, shown: &Path) -> Result<(), InstallError> {
            let meta = match plain_meta(path) {
                Ok(Some(m)) => m,
                Ok(None) => return Ok(()),
                Err(e) => return Err(io_refused(shown, e)),
            };
            if meta.is_dir() {
                let entries = std::fs::read_dir(path).map_err(|e| io_refused(shown, e))?;
                for entry in entries {
                    let entry = entry.map_err(|e| io_refused(shown, e))?;
                    walk(&entry.path(), shown)?;
                }
            }
            Ok(())
        }
        walk(&self.at(logical)?, Path::new(logical))
    }
}

/// W26, then the machine. An elevated administrator's token is asked for on the real
/// machine, from [`Host::elevated`], not `euid`: `euid` is 0 for a low-integrity or
/// restricted child of an elevated admin, which holds `Administrators` but cannot use it.
///
/// This is here and not in `check_supported`, where it was: whether the caller is elevated
/// says nothing about the machine. There it made doctor report an unsupported system from
/// any plain shell, read through `refusal_line`'s "Developer mode works as before", and
/// the daemon's virtual account could never have passed it. So: exit 2 with W26's text
/// from install and uninstall, and doctor decides for itself what a plain shell can check.
pub(crate) fn host_refusals(layout: &Layout, host: &dyn Host) -> Result<(), InstallError> {
    if layout.is_system() && !host.elevated() {
        return Err(InstallError::NotElevated);
    }
    match check_supported(layout, host) {
        Support::Supported { .. } => Ok(()),
        Support::Refused(why) => Err(InstallError::Unsupported(why)),
    }
}

/// Everything install would rely on, read only: each path it would create or write into.
/// On any refusal nothing has been written.
fn preflight(
    layout: &Layout,
    host: &dyn Host,
    agents: &[Agent],
    known: Option<&Installed>,
    warnings: &mut Vec<String>,
) -> Result<(), InstallError> {
    let check = Check { layout, host };
    check.chain(layout.logical(OPT_DIR))?;
    for dir in own_dirs(layout) {
        check.existing_own(dir, true)?;
    }
    for file in [BINARY, CONFIG, VAULT_KEY, INSTALLED, DAEMON_LOG] {
        check.existing_own(layout.logical(file), false)?;
    }
    for tree in own_trees(layout) {
        check.scan(tree)?;
    }
    for a in agents {
        let dirs = agent_dirs(layout, *a);
        check.chain(dirs[0])?;
        for dir in dirs {
            if Check::listed(known, dir) {
                check.existing_own(dir, true)?;
            } else {
                check.check_foreign(dir, warnings)?;
            }
        }
        check.existing_own(layout.logical(agent_file(*a)), false)?;
        if *a == Agent::Claude {
            check.existing_own(layout.logical(CLAUDE_MCP), false)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- the lock

/// Held for one install: the lock file (W9 gives it no path; see [`WIN_INSTALL_LOCK`]), and
/// the root when this lock made it. Dropped, it lets go, then takes away an empty root it
/// made, so a run refused after the lock leaves nothing behind.
struct WinLock {
    hold: Option<Hold>,
    made_root: Option<PathBuf>,
}

impl Drop for WinLock {
    fn drop(&mut self) {
        // Closes the lock file first, which deletes it. The root is removed only if
        // that leaves it empty: anything more means the run got further.
        self.hold.take();
        if let Some(root) = &self.made_root {
            let _ = std::fs::remove_dir(root);
        }
    }
}

/// Takes the install lock, with the host's refusals first. The lock is a file in the
/// root, not a path of its own, since Users may create entries in `C:\ProgramData` and
/// could plant one there. The root is created with its descriptor when it is missing, and
/// checked either way before the lock is opened inside it.
pub(crate) fn lock(layout: &Layout, host: &dyn Host, wait: Duration) -> Result<Hold, InstallError> {
    host_refusals(layout, host)?;
    take_lock(layout, host, wait)
}

fn take_lock(layout: &Layout, host: &dyn Host, wait: Duration) -> Result<Hold, InstallError> {
    let check = Check { layout, host };
    let root_shown = layout.logical(OPT_DIR);
    let root = check.at(root_shown)?;
    let lock_shown = Path::new(WIN_INSTALL_LOCK);
    let lock_path = check.at(WIN_INSTALL_LOCK)?;
    let row = expected(layout, &root, NO_AUDIT_SID)
        .map_err(|e| io_refused(Path::new(root_shown), e))?
        .ok_or_else(|| refused(Path::new(root_shown), "no row in the ACL table"))?;
    let start = Instant::now();
    let mut made_root = None;
    loop {
        check.chain(root_shown)?;
        // More than once only when the holder before this one took the root away.
        match host.create_dir_sddl(&root, &row) {
            Ok(()) => made_root = Some(root.clone()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_refused(Path::new(root_shown), e)),
        }
        // Whoever made it, it must be fit before anything is opened inside it.
        check.existing_own(root_shown, true)?;
        match host.lock_file(&lock_path) {
            Ok(Some(hold)) => {
                return Ok(Box::new(WinLock {
                    hold: Some(hold),
                    made_root,
                }))
            }
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_refused(lock_shown, format!("cannot lock: {e}"))),
        }
        if start.elapsed() >= wait {
            return Err(InstallError::Step {
                step: "lock".into(),
                detail: format!(
                    "another saiife system install or purge holds {WIN_INSTALL_LOCK}; gave up \
                     after {} s. Nothing was changed: run it again when that has finished",
                    wait.as_secs()
                ),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ---------------------------------------------------------------- the checks of the input

/// An unfit binary is refused when `strict`, else a warning: as on Linux. Returns the
/// warnings.
fn check_pe(path: &Path, bytes: &[u8], strict: bool) -> Result<Vec<String>, InstallError> {
    let shown = path.display();
    let (problems, notes) = match crate::binary::inspect_pe(bytes) {
        Ok(info) => (
            info.problems(crate::binary::PE_IMPORT_ALLOWLIST),
            info.warnings(),
        ),
        Err(e) => (vec![format!("it is not a PE executable ({e})")], Vec::new()),
    };
    let mut warnings: Vec<String> = notes.iter().map(|w| format!("{shown}: {w}")).collect();
    if problems.is_empty() {
        return Ok(warnings);
    }
    let problem = problems.join("; ");
    if strict {
        return Err(refused(
            path,
            format!("{problem}; locked mode installs only the release build (see docs/windows.md)"),
        ));
    }
    warnings.insert(0, format!("{shown}: {problem}"));
    Ok(warnings)
}

/// The `--config` file: it loads and checks, says `locked = true`, and did not change
/// while that went on. Returns its text.
fn validated_config(path: &Path, dropins: &Path) -> Result<String, InstallError> {
    let text = std::fs::read_to_string(path).map_err(|e| io_refused(path, e))?;
    #[cfg(windows)]
    let directory = saiife_policy::WinDirectory::system();
    #[cfg(not(windows))]
    let directory = saiife_policy::Getent;
    let loaded = saiife_policy::load_and_check_with(path, dropins, &directory)
        .map_err(|e| io_refused(path, e))?;
    if !loaded.config.locked {
        return Err(refused(
            path,
            "it must say `locked = true` for system install",
        ));
    }
    if std::fs::read_to_string(path).map_err(|e| io_refused(path, e))? != text {
        return Err(refused(path, "it changed while it was being checked"));
    }
    Ok(text)
}

/// `user`, `group:<name>` or `DOMAIN\user`, each name as `net.exe` would take it. An
/// approver goes into the config as text.
fn valid_approver(a: &str) -> bool {
    let plain = |n: &str| valid_win_name(n) && !n.contains(['\\', '"']);
    let name = a.strip_prefix("group:").unwrap_or(a);
    match name.split_once('\\') {
        Some((domain, user)) => plain(domain) && plain(user),
        None => plain(name),
    }
}

// ---------------------------------------------------------------- install

pub(crate) fn install(
    layout: &Layout,
    host: &dyn Host,
    opts: &InstallOptions,
    binary: &Path,
    began: &std::cell::Cell<bool>,
) -> Result<InstallReport, InstallError> {
    // The refusals again: the lock may have taken a while.
    host_refusals(layout, host)?;
    let installed_shown = Path::new(layout.logical(INSTALLED));
    let previous =
        read_installed(&layout.at(INSTALLED)).map_err(|e| refused(installed_shown, e))?;
    let restored = match previous {
        Some(_) => None,
        None => read_previous(layout, host),
    };
    let mut agents = opts.agents.clone();
    agents.sort();
    agents.dedup();
    let mut warnings = Vec::new();
    let known = previous.as_ref().or(restored.as_ref());
    preflight(layout, host, &agents, known, &mut warnings)?;

    // `audit_sid` must be a local group: the row hands it read access to the audit log.
    let audit_group = layout.audit_group();
    let group_shown = PathBuf::from(format!(r"local group {audit_group}"));
    host.lookup_local_group(audit_group)
        .map_err(|e| io_refused(&group_shown, e))?;

    for a in &opts.approvers {
        if !valid_approver(a) {
            return Err(refused(
                Path::new(layout.logical(CONFIG)),
                format!("approver {a:?} is not a user name, DOMAIN\\user or group:<name>"),
            ));
        }
    }
    let new_config = match &opts.config {
        Some(p) => Some(validated_config(p, &layout.at(POLICY_D))?),
        None => None,
    };
    // The bytes checked are the bytes copied.
    let binary_bytes = std::fs::read(binary).map_err(|e| InstallError::Step {
        step: "binary".into(),
        detail: format!("{}: {e}", binary.display()),
    })?;
    let strict = layout.is_system() && !opts.allow_test_build;
    warnings.extend(check_pe(binary, &binary_bytes, strict)?);
    check_existing_key(layout)?;
    if agents.is_empty() {
        warnings.push(NO_AGENTS.to_string());
    }
    warnings.push(crate::layout::WIN_SAME_USER_OFF.to_string());

    let rec = known.cloned().unwrap_or_else(|| Installed {
        version: INSTALLED_VERSION,
        saiife: env!("CARGO_PKG_VERSION").to_string(),
        installed_at: now(),
        // No systemd on Windows.
        systemd: 0,
        vault_key: VaultKeyMode::DaemonFile,
        users: Vec::new(),
        groups: Vec::new(),
        memberships: Vec::new(),
        dirs: Vec::new(),
        files: Vec::new(),
        agents: Vec::new(),
        auth_rights: Vec::new(),
    });
    began.set(true);
    let mut run = Run {
        layout,
        host,
        check: Check { layout, host },
        saved: previous,
        rec,
        audit_sid: String::new(),
        report: InstallReport {
            warnings,
            ..InstallReport::default()
        },
    };
    run.rec.saiife = env!("CARGO_PKG_VERSION").to_string();
    run.rec.systemd = 0;
    run.rec.vault_key = VaultKeyMode::DaemonFile;

    // 3. The audit group, whose SID is in the rows.
    run.audit_group()?;
    // 4. The tree. `etc` first: installed.toml lives there.
    run.tree_dir(layout.logical(OPT_DIR))?;
    run.tree_dir(layout.logical(ETC_DIR))?;
    run.save()?;
    remove_kept_copy(&run)?;
    run.tree_dir(layout.logical(POLICY_D))?;
    run.tree_dir(layout.logical(BIN_DIR))?;
    let binary_changed = run.binary(&binary_bytes)?;
    let config_changed = run.config(new_config.as_deref(), &opts.approvers)?;
    run.tree_dir(layout.logical(STATE_DIR))?;
    run.tree_dir(layout.logical(KEYS_DIR))?;
    run.vault_key()?;
    run.tree_dir(layout.logical(LOG_DIR))?;
    run.tree_dir(layout.logical(AUDIT_DIR))?;
    run.tree_dir(daemon_log_dir(layout))?;
    run.daemon_log()?;
    // 5. The managed files, then the HKLM policy.
    for a in &agents {
        run.managed(*a)?;
    }
    let claude_listed = agents.contains(&Agent::Claude);
    if claude_listed {
        run.mcp_allowlist()?;
        match run.host.claude_hklm_policy() {
            HklmPolicy::Overrides => {
                run.report.policy_failure = Some(claude::HKLM_OVERRIDES_TEXT.to_string());
            }
            HklmPolicy::WeakensHooks => {
                run.report.policy_failure = Some(claude::HKLM_WEAKENS_HOOKS_TEXT.to_string());
            }
            HklmPolicy::Absent | HklmPolicy::Merge => {}
        }
    } else {
        run.drop_stale_mcp()?;
    }
    run.save()?;
    // 6. The service, 7. its pipe.
    run.service(binary_changed, config_changed)?;
    run.host
        .wait_for_pipe(SERVICE_WAIT)
        .map_err(|e| InstallError::Step {
            step: "start".into(),
            detail: format!(
                "the daemon did not open {WIN_PIPE} within {} s: {e} (see {})",
                SERVICE_WAIT.as_secs(),
                layout.logical(DAEMON_LOG)
            ),
        })?;
    // 8. installed.toml holds all of it. The doctor is the CLI's.
    run.save()?;
    run.report.started = true;
    Ok(run.report)
}

/// An existing vault key is never replaced: it must be a regular file of 32 bytes.
fn check_existing_key(layout: &Layout) -> Result<(), InstallError> {
    let p = layout.at(VAULT_KEY);
    let shown = Path::new(layout.logical(VAULT_KEY));
    match plain_meta(&p).map_err(|e| io_refused(shown, e))? {
        None => Ok(()),
        Some(m) if !m.is_file() => Err(refused(shown, "exists and is not a regular file")),
        Some(m) if m.len() != KEY_LEN => Err(refused(
            shown,
            format!(
                "exists with {} bytes, not a 32-byte key; saiife does not adopt it (move it away first)",
                m.len()
            ),
        )),
        Some(_) => Ok(()),
    }
}

/// `replace` with what Windows does to a file that is running: it can be renamed but not
/// overwritten. So a refused rename moves the old file to `aside` and tries again. Hooks
/// and the daemon run `saiife.exe`, so this is the normal path for an upgrade.
fn replace_with(
    rename: &mut dyn FnMut(&Path, &Path) -> io::Result<()>,
    tmp: &Path,
    path: &Path,
    aside: &Path,
) -> io::Result<()> {
    match rename(tmp, path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            rename(path, aside)?;
            // With the second rename refused, the old file goes back: never no binary.
            rename(tmp, path).inspect_err(|_| {
                let _ = rename(aside, path);
            })
        }
        Err(e) => Err(e),
    }
}

/// The old binaries [`replace_with`] moved aside, in the dir of `binary`.
fn binaries_aside(binary: &Path) -> Vec<PathBuf> {
    let Some(dir) = binary.parent() else {
        return Vec::new();
    };
    let Some(prefix) = binary.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let prefix = format!("{prefix}.old.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .map(|e| e.path())
        .collect()
}

/// One install run: the record so far.
struct Run<'a> {
    layout: &'a Layout,
    host: &'a dyn Host,
    check: Check<'a>,
    saved: Option<Installed>,
    rec: Installed,
    audit_sid: String,
    report: InstallReport,
}

impl Run<'_> {
    fn at(&self, logical: &str) -> Result<PathBuf, InstallError> {
        self.check.at(logical)
    }

    /// The row for the path as the platform names it. Not in the table is a refusal: a
    /// path install writes must have one.
    fn row(&self, logical: &str) -> Result<String, InstallError> {
        let shown = Path::new(logical);
        expected(self.layout, &self.at(logical)?, &self.audit_sid)
            .map_err(|e| io_refused(shown, e))?
            .ok_or_else(|| refused(shown, "no row in the ACL table"))
    }

    /// Sets `row` on `real`, after checking the whole chain of `logical`.
    fn set(&self, logical: &str, real: &Path, row: &str) -> Result<(), InstallError> {
        self.check.chain(logical)?;
        self.host
            .set_sddl(real, row)
            .map_err(|e| io_refused(Path::new(logical), e))
    }

    fn save(&mut self) -> Result<(), InstallError> {
        if self.saved.as_ref() == Some(&self.rec) {
            return Ok(());
        }
        let logical = self.layout.logical(INSTALLED);
        let real = self.at(logical)?;
        self.check.chain(logical)?;
        write_installed(&real, &self.rec).map_err(step("installed.toml"))?;
        let row = self.row(logical)?;
        self.set(logical, &real, &row)?;
        self.saved = Some(self.rec.clone());
        Ok(())
    }

    fn changed(&mut self, what: impl Into<String>) {
        self.report.changed.push(what.into());
    }

    fn unchanged(&mut self, what: impl Into<String>) {
        self.report.unchanged.push(what.into());
    }

    /// The local group `saiife-audit`: looked up first, since `net.exe` exits 2 for a
    /// group that exists as for most other failures. Only a group install made is listed,
    /// so only that is ever deleted.
    fn audit_group(&mut self) -> Result<(), InstallError> {
        let name = self.layout.audit_group();
        let shown = PathBuf::from(format!("local group {name}"));
        let found = self
            .host
            .lookup_local_group(name)
            .map_err(|e| io_refused(&shown, e))?;
        let sid = match found {
            Some(sid) => sid,
            None => {
                if !self.rec.groups.iter().any(|g| g == name) {
                    self.rec.groups.push(name.to_string());
                }
                self.host.create_system_group(name).map_err(step("users"))?;
                self.changed(format!("group {name}"));
                self.host
                    .lookup_local_group(name)
                    .map_err(|e| io_refused(&shown, e))?
                    .ok_or_else(|| refused(&shown, "was made, and cannot be found"))?
            }
        };
        // A machine's own groups have this prefix; a well-known SID would hand the audit
        // log to everyone in it.
        if !sid.starts_with("S-1-5-21-") {
            return Err(refused(
                &shown,
                format!("{sid} is no group of this machine"),
            ));
        }
        self.audit_sid = sid;
        Ok(())
    }

    /// A dir of the tree: created with its descriptor when missing, and listed. An
    /// existing one is checked and set again, with all that is below it where its row
    /// covers that (a tree an older ACL left must not stay as it was).
    fn tree_dir(&mut self, logical: &str) -> Result<(), InstallError> {
        let shown = Path::new(logical);
        let real = self.at(logical)?;
        let row = self.row(logical)?;
        if self.check.existing_own(logical, true)? {
            if own_trees(self.layout).contains(&logical) {
                self.set_tree(logical, &real)?;
            } else if self.check.read(logical, &real)?
                != parse(&row).map_err(|e| refused(shown, e))?
            {
                // Otherwise it already reads as its row: the lock made the root with it,
                // and a dir below a tree was just walked.
                self.set(logical, &real, &row)?;
            }
            self.list_dir(logical);
            self.unchanged(logical);
            return Ok(());
        }
        self.check.chain(logical)?;
        self.host
            .create_dir_sddl(&real, &row)
            .map_err(|e| io_refused(shown, e))?;
        self.list_dir(logical);
        self.changed(logical);
        // Before `etc` exists there is nowhere to write it; the next save has it.
        if self.at(self.layout.logical(ETC_DIR))?.is_dir() {
            self.save()?;
        }
        Ok(())
    }

    fn list_dir(&mut self, logical: &str) {
        let p = PathBuf::from(logical);
        if !self.rec.dirs.contains(&p) {
            self.rec.dirs.push(p);
        }
    }

    /// Sets every entry from `logical` down, each by its own row, each with the chain
    /// checked first.
    fn set_tree(&mut self, logical: &str, real: &Path) -> Result<(), InstallError> {
        let (layout, check, audit) = (self.layout, &self.check, self.audit_sid.as_str());
        let as_io = |e: InstallError| io::Error::other(e.to_string());
        set_sddl_tree(
            self.host,
            real,
            &mut |path| {
                let shown = logical_of(layout, path)?;
                check.chain(&shown).map_err(as_io)
            },
            &mut |path, _| {
                expected(layout, path, audit)
                    .map_err(io::Error::other)?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("{}: no row in the ACL table", path.display()),
                        )
                    })
            },
        )
        .map_err(|e| io_refused(Path::new(logical), e))?;
        Ok(())
    }

    fn record_file(&mut self, logical: &str, kind: FileKind, sha256: Option<String>, new: bool) {
        let path = PathBuf::from(logical);
        match self.rec.files.iter_mut().find(|f| f.path == path) {
            Some(f) => {
                f.sha256 = sha256;
                f.kind = kind;
            }
            None => self.rec.files.push(InstalledFile {
                path,
                sha256,
                kind,
                created: new,
            }),
        }
    }

    /// `bytes` at `logical`, with its row, under its final name only once the row is on
    /// it. The row is set again if the file already holds them. True when written.
    fn write_file(&mut self, logical: &str, bytes: &[u8]) -> Result<bool, InstallError> {
        let shown = Path::new(logical);
        let real = self.at(logical)?;
        let row = self.row(logical)?;
        let want = sha256_hex(bytes);
        let current = sha256_file(&real).map_err(|e| io_refused(shown, e))?;
        if current.as_deref() == Some(want.as_str()) {
            self.set(logical, &real, &row)?;
            return Ok(false);
        }
        self.check.chain(logical)?;
        let pid = std::process::id();
        let tmp = real.with_file_name(format!("{}.new.{pid}", name_of(logical)));
        let aside = real.with_file_name(format!("{}.old.{pid}", name_of(logical)));
        let written = (|| -> Result<(), InstallError> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| io_refused(shown, e))?;
            f.write_all(bytes).map_err(|e| io_refused(shown, e))?;
            f.sync_all().map_err(|e| io_refused(shown, e))?;
            drop(f);
            self.set(logical, &tmp, &row)?;
            let host = self.host;
            replace_with(&mut |a, b| host.rename_file(a, b), &tmp, &real, &aside)
                .map_err(|e| io_refused(shown, e))
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written?;
        Ok(true)
    }

    /// Writes, records and reports a file. True when written.
    fn file(&mut self, abs: &str, bytes: &[u8], kind: FileKind) -> Result<bool, InstallError> {
        let logical = self.layout.logical(abs);
        let real = self.at(logical)?;
        let new = plain_meta(&real)
            .map_err(|e| io_refused(Path::new(logical), e))?
            .is_none();
        // Listed before it is written: a failure part-way is still on the list.
        self.record_file(logical, kind, None, new);
        self.save()?;
        let written = self.write_file(logical, bytes)?;
        if written {
            self.changed(logical);
        } else {
            self.unchanged(logical);
        }
        self.record_file(logical, kind, Some(sha256_hex(bytes)), new);
        self.save()?;
        Ok(written)
    }

    fn binary(&mut self, bytes: &[u8]) -> Result<bool, InstallError> {
        let written = self.file(BINARY, bytes, FileKind::Binary)?;
        // An earlier upgrade's old copies, once nothing runs them. One still running stays
        // for the next run.
        for old in binaries_aside(&self.layout.at(BINARY)) {
            let _ = std::fs::remove_file(old);
        }
        Ok(written)
    }

    fn config(&mut self, new: Option<&str>, approvers: &[String]) -> Result<bool, InstallError> {
        let logical = self.layout.logical(CONFIG);
        let real = self.at(logical)?;
        let text = match new {
            Some(t) => t.as_bytes().to_vec(),
            None => match plain_meta(&real).map_err(|e| io_refused(Path::new(logical), e))? {
                // An existing config is kept as it is.
                Some(_) => std::fs::read(&real).map_err(step("config"))?,
                // Same-user re-authentication is not said here: see plan 19b Task 9.
                None => crate::default_config::default_config(self.layout, approvers, false)
                    .into_bytes(),
            },
        };
        self.file(CONFIG, &text, FileKind::Config)
    }

    /// W15: 32 random bytes, never rotated. The descriptor goes on while the file is still
    /// empty, so the key is never readable through what it inherits from `state\keys`,
    /// where the service may write. Written through the handle that made the file.
    fn vault_key(&mut self) -> Result<(), InstallError> {
        let logical = self.layout.logical(VAULT_KEY);
        let shown = Path::new(logical);
        let real = self.at(logical)?;
        let row = self.row(logical)?;
        let exists = plain_meta(&real)
            .map_err(|e| io_refused(shown, e))?
            .is_some();
        // Listed before it is made. Never with a digest.
        self.record_file(logical, FileKind::VaultKey, None, !exists);
        self.save()?;
        if exists {
            self.set(logical, &real, &row)?;
            self.unchanged(logical);
            return Ok(());
        }
        self.check.chain(logical)?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&real)
            .map_err(|e| io_refused(shown, e))?;
        let filled = (|| -> Result<(), InstallError> {
            self.set(logical, &real, &row)?;
            let mut key = Zeroizing::new([0u8; KEY_LEN as usize]);
            getrandom::fill(&mut key[..]).map_err(|e| InstallError::Step {
                step: "vault-key".into(),
                detail: e.to_string(),
            })?;
            f.write_all(&key[..]).map_err(step("vault-key"))?;
            f.sync_all().map_err(step("vault-key"))
        })();
        drop(f);
        if let Err(e) = filled {
            // Never leave a short key behind: it would be refused on the next run.
            let _ = std::fs::remove_file(&real);
            return Err(e);
        }
        self.changed(logical);
        Ok(())
    }

    /// The daemon's log: there and with its row before the service first opens it.
    fn daemon_log(&mut self) -> Result<(), InstallError> {
        let logical = self.layout.logical(DAEMON_LOG);
        let shown = Path::new(logical);
        let real = self.at(logical)?;
        let row = self.row(logical)?;
        if plain_meta(&real)
            .map_err(|e| io_refused(shown, e))?
            .is_some()
        {
            // The walk of `log\daemon` set it already.
            return Ok(());
        }
        self.check.chain(logical)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&real)
            .map_err(|e| io_refused(shown, e))?;
        self.set(logical, &real, &row)?;
        self.changed(logical);
        Ok(())
    }

    /// The dirs of one agent's managed file. A missing one is made with its descriptor,
    /// and listed, and is ours from then on. One install listed earlier must still be fit
    /// and gets its descriptor again. Any other existing one belongs to another product:
    /// it must be fit to rely on ([`Check::check_foreign`]), and its descriptor stays.
    fn managed_dirs(&mut self, a: Agent) -> Result<(), InstallError> {
        for logical in agent_dirs(self.layout, a) {
            let shown = Path::new(logical);
            let real = self.at(logical)?;
            let row = self.row(logical)?;
            self.check.chain(logical)?;
            let listed = self.rec.dirs.iter().any(|d| d == shown);
            if listed && self.check.existing_own(logical, true)? {
                self.set(logical, &real, &row)?;
                continue;
            }
            let mut warnings = Vec::new();
            if self.check.check_foreign(logical, &mut warnings)? {
                // The preflight said it already.
                continue;
            }
            self.host
                .create_dir_sddl(&real, &row)
                .map_err(|e| io_refused(shown, e))?;
            self.list_dir(logical);
            self.changed(logical);
            self.save()?;
        }
        Ok(())
    }

    fn record_agent(&mut self, a: Agent, logical: &str, sha: String, whole: bool, new: bool) {
        let path = PathBuf::from(logical);
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
                created_file: new,
            }),
        }
    }

    /// One agent's managed file with its row.
    fn managed(&mut self, a: Agent) -> Result<(), InstallError> {
        self.managed_dirs(a)?;
        let logical = self.layout.logical(agent_file(a));
        // Again, right before the write: what the preflight read may have changed.
        self.check.existing_own(logical, false)?;
        let shown = Path::new(logical);
        let real = self.at(logical)?;
        let new = plain_meta(&real)
            .map_err(|e| io_refused(shown, e))?
            .is_none();
        let whole = a == Agent::Claude;
        // Listed before it is written (no digest until done).
        self.record_agent(a, logical, String::new(), whole, new);
        self.save()?;
        let managed_step = |e: AgentError| InstallError::Step {
            step: "managed".into(),
            detail: e.to_string(),
        };
        let sha = match a {
            Agent::Claude => {
                // Not `managed_settings()`, which says the Linux path on every OS.
                let text = claude::managed_settings_for(true);
                if self.write_file(logical, text.as_bytes())? {
                    self.changed(logical);
                } else {
                    self.unchanged(logical);
                }
                sha256_hex(text.as_bytes())
            }
            Agent::Codex | Agent::Gemini => {
                self.check.chain(logical)?;
                let (write, entry): (WriteFn, EntryFn) = if a == Agent::Codex {
                    (codex::install_managed_for, codex::managed_entry)
                } else {
                    (gemini::install_managed_for, gemini::managed_entry)
                };
                match write(&real, true).map_err(managed_step)? {
                    Change::Unchanged => self.unchanged(logical),
                    _ => self.changed(logical),
                }
                let row = self.row(logical)?;
                self.set(logical, &real, &row)?;
                entry(&real)
                    .map_err(managed_step)?
                    .ok_or_else(|| InstallError::Step {
                        step: "managed".into(),
                        detail: format!("{logical}: saiife's entry is missing after the write"),
                    })?
            }
        };
        self.record_agent(a, logical, sha, whole, new);
        self.save()
    }

    /// The Claude Code MCP drop-in, from the config as it is now.
    fn mcp_allowlist(&mut self) -> Result<(), InstallError> {
        let allow = match saiife_policy::load_system(&self.layout.at(CONFIG)) {
            Ok(l) => l.config.guard.mcp.allow_servers,
            Err(e) => {
                self.report.warnings.push(format!(
                    "{}: the config could not be read ({e}); only the saiife MCP server is allowed",
                    self.layout.logical(CLAUDE_MCP)
                ));
                Vec::new()
            }
        };
        let text = claude::managed_mcp_settings_for(true, &allow);
        self.file(CLAUDE_MCP, text.as_bytes(), FileKind::Managed)?;
        Ok(())
    }

    /// A reinstall without Claude removes the drop-in an earlier run wrote.
    fn drop_stale_mcp(&mut self) -> Result<(), InstallError> {
        let logical = self.layout.logical(CLAUDE_MCP);
        let path = Path::new(logical);
        if !self.rec.files.iter().any(|f| f.path == path) {
            return Ok(());
        }
        if remove_plain(&self.at(logical)?).map_err(step("managed"))? {
            self.changed(format!("removed {logical}"));
        }
        self.rec.files.retain(|f| f.path != path);
        self.save()
    }

    /// W10. `Query`; missing is `Create`, a different spec `Update`; `SetSddl`, always,
    /// since a drifted DACL has nothing else to put it right. Then: stopped is `Start`;
    /// running with a new binary or spec is `Stop` and `Start`; running with only a new
    /// config is `ParamChange` (plan 18 decision 5). No membership counts here: the
    /// virtual account's rights are its own SID in the rows.
    fn service(&mut self, binary_changed: bool, config_changed: bool) -> Result<(), InstallError> {
        let spec = ServiceSpec::saiifed(self.layout);
        let fingerprint = spec.fingerprint();
        let logical = WIN_SERVICE;
        let service_step = step("service");
        let recorded = self
            .rec
            .files
            .iter()
            .find(|f| f.kind == FileKind::Service)
            .and_then(|f| f.sha256.clone());
        let state = self.host.service(ServiceOp::Query).map_err(&service_step)?;
        // Listed before it is made. A service that was there is no reason to keep it on
        // uninstall, so `created` says nothing here.
        self.record_file(logical, FileKind::Service, recorded.clone(), true);
        self.save()?;
        let spec_changed = if state == ServiceState::Missing {
            self.host
                .service(ServiceOp::Create(spec.clone()))
                .map_err(&service_step)?;
            self.changed(format!("service {WIN_SERVICE}"));
            true
        } else if recorded.as_deref() != Some(fingerprint.as_str()) {
            self.host
                .service(ServiceOp::Update(spec.clone()))
                .map_err(&service_step)?;
            self.changed(format!("service {WIN_SERVICE} (updated)"));
            true
        } else {
            // The record says what install last wrote, not what's there now. An admin may
            // have changed it since, so it's set again; no restart for that alone.
            self.host
                .service(ServiceOp::Update(spec.clone()))
                .map_err(&service_step)?;
            self.unchanged(format!("service {WIN_SERVICE}"));
            false
        };
        self.host
            .service(ServiceOp::SetSddl(spec.sddl.clone()))
            .map_err(&service_step)?;
        self.record_file(logical, FileKind::Service, Some(fingerprint), true);
        self.save()?;

        let log = self.layout.logical(DAEMON_LOG);
        let start_step = |e: io::Error| InstallError::Step {
            step: "start".into(),
            detail: format!("{e} (see {log})"),
        };
        match settled_state(self.host, SERVICE_WAIT).map_err(start_step)? {
            ServiceState::Stopped => {
                self.host.service(ServiceOp::Start).map_err(start_step)?;
            }
            ServiceState::Running { .. } if binary_changed || spec_changed => {
                self.host
                    .service(ServiceOp::Stop { wait: SERVICE_WAIT })
                    .map_err(start_step)?;
                self.host.service(ServiceOp::Start).map_err(start_step)?;
            }
            ServiceState::Running { .. } if config_changed => {
                self.host
                    .service(ServiceOp::ParamChange)
                    .map_err(start_step)?;
                self.confirm_reload();
            }
            ServiceState::Running { .. } => {}
            other => {
                return Err(InstallError::Step {
                    step: "start".into(),
                    detail: format!("{WIN_SERVICE} is {other:?} (see {log})"),
                })
            }
        }
        Ok(())
    }

    /// `ParamChange` only asks: the daemon may still reject the new config and keep the
    /// old policy. `policy.reload` loads it again and answers.
    fn confirm_reload(&mut self) {
        let config = self.layout.logical(CONFIG);
        let log = self.layout.logical(DAEMON_LOG);
        let why = match self.host.policy_reload(self.layout.root(), 0, RELOAD_WAIT) {
            Ok(a) if a.loaded => {
                self.report.policy_hash = a.hash;
                return;
            }
            Ok(a) => format!(
                "it rejected the new config and keeps the old policy: {}",
                a.reason
            ),
            Err(e) => format!("it did not confirm the reload: {e}"),
        };
        self.report.reload_problem =
            Some(format!("{RELOAD_NOT_TAKEN} ({config}): {why} (see {log})"));
    }
}

/// The service's state once it is no longer starting or stopping, within `wait`. What is
/// still pending then comes back as it is, for the caller to refuse.
fn settled_state(host: &dyn Host, wait: Duration) -> io::Result<ServiceState> {
    let deadline = Instant::now() + wait;
    loop {
        let state = host.service(ServiceOp::Query)?;
        let pending = matches!(&state, ServiceState::Other(w) if w.ends_with("-pending"));
        if !pending || Instant::now() >= deadline {
            return Ok(state);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The path as the platform names it, from a real one of this layout.
fn logical_of(layout: &Layout, path: &Path) -> io::Result<String> {
    let (drive, names) = layout.windows_location(path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not plainly a path of this tree", path.display()),
        )
    })?;
    Ok(format!("{drive}:\\{}", names.join("\\")))
}

/// Removes the file at `path`, never what a link points to. `false` when nothing was there.
fn remove_plain(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a directory", path.display()),
        )),
        Ok(_) => std::fs::remove_file(path).map(|_| true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------- the kept copy

/// The kept copy's path: [`WIN_PREVIOUS`], and only if the dirs above it and the copy
/// itself are fit. `None` otherwise: a copy nobody can vouch for says nothing.
fn read_previous_record_checked(layout: &Layout, host: &dyn Host) -> Option<Installed> {
    let check = Check { layout, host };
    let real = check.at(WIN_PREVIOUS).ok()?;
    check.chain(WIN_PREVIOUS).ok()?;
    if !check.existing_own(WIN_PREVIOUS, false).ok()? {
        return None;
    }
    let f = std::fs::File::open(&real).ok()?;
    if f.metadata().ok()?.len() > MAX_PREVIOUS {
        return None;
    }
    let mut text = String::new();
    f.take(MAX_PREVIOUS).read_to_string(&mut text).ok()?;
    let i: Installed = toml::from_str(&text).ok()?;
    (i.version == INSTALLED_VERSION).then_some(i)
}

/// The copy a plain uninstall left, for what it says about the admin's choices.
pub(crate) fn read_previous_record(layout: &Layout, host: &dyn Host) -> Option<Installed> {
    read_previous_record_checked(layout, host)
}

/// The copy, trusted only for what install could have made: nothing else in it counts.
fn read_previous(layout: &Layout, host: &dyn Host) -> Option<Installed> {
    let mut i = read_previous_record_checked(layout, host)?;
    let audit = layout.audit_group();
    i.users.clear();
    i.memberships.clear();
    i.auth_rights.clear();
    i.groups.retain(|g| g == audit);
    let known = known_dirs(layout);
    i.dirs.retain(|d| known.iter().any(|k| d == Path::new(k)));
    let (config, key) = (layout.logical(CONFIG), layout.logical(VAULT_KEY));
    i.files.retain(|f| {
        (f.kind == FileKind::Config && f.path == Path::new(config))
            || (f.kind == FileKind::VaultKey && f.path == Path::new(key))
    });
    for f in &mut i.files {
        if f.kind == FileKind::VaultKey {
            f.sha256 = None;
        }
    }
    i.agents.clear();
    Some(i)
}

fn remove_kept_copy(run: &Run<'_>) -> Result<(), InstallError> {
    remove_plain(&run.at(WIN_PREVIOUS)?).map_err(step("installed.toml"))?;
    Ok(())
}

/// Every dir install can make: a doctored `installed.toml` names no other.
fn known_dirs(layout: &Layout) -> Vec<&'static str> {
    let mut all: Vec<&'static str> = own_dirs(layout).to_vec();
    for a in Agent::ALL {
        all.extend(agent_dirs(layout, a));
    }
    all
}

// ---------------------------------------------------------------- fleet

/// The fleet files: each dir down to `etc\fleet`, and each file, must pass `protected_ok`,
/// with every ancestor above the tree `ancestor_ok`. Missing dirs mean no fleet files.
pub(crate) fn fleet_files(
    layout: &Layout,
    host: &dyn Host,
) -> Result<crate::fleet::FleetFiles, InstallError> {
    host_refusals(layout, host)?;
    let check = Check { layout, host };
    let dir = layout.logical(FLEET_DIR);
    check.chain(dir)?;
    if !check.existing_own(dir, true)? {
        return Ok((None, None));
    }
    let read = |abs: &str| -> Result<Option<Vec<u8>>, InstallError> {
        let logical = layout.logical(abs);
        let shown = Path::new(logical);
        if !check.existing_own(logical, false)? {
            return Ok(None);
        }
        let f = std::fs::File::open(check.at(logical)?).map_err(|e| io_refused(shown, e))?;
        let too_large = || refused(shown, "is larger than 1 MiB; saiife does not use it");
        if f.metadata().map_err(|e| io_refused(shown, e))?.len() > MAX_FLEET_FILE {
            return Err(too_large());
        }
        let mut bytes = Vec::new();
        // Bounded even when the file grows after the size check.
        f.take(MAX_FLEET_FILE + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io_refused(shown, e))?;
        if bytes.len() as u64 > MAX_FLEET_FILE {
            return Err(too_large());
        }
        Ok(Some(bytes))
    };
    Ok((read(FLEET_CONFIG)?, read(FLEET_INSTALL)?))
}

// ---------------------------------------------------------------- the install log

/// The descriptor of [`WIN_INSTALL_LOG`]: the admins' alone to write, readable by users as
/// its dir is. The `log` row has no inheritable entries, so a file made there without one
/// gets its creator's default DACL. Under the MSI that is the custom action server's token,
/// which can grant its own service SID, and doctor's walk then fails the file.
const INSTALL_LOG_SDDL: &str = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";

/// Appends the doctor's text to [`WIN_INSTALL_LOG`] (W20). The file has no row in the
/// table, by ruling: only admin tools write it, in a dir only admins can write. It gets
/// [`INSTALL_LOG_SDDL`] before anything is written. A reparse point is refused.
pub(crate) fn append_install_log(
    layout: &Layout,
    host: &dyn Host,
    text: &str,
) -> Result<(), InstallError> {
    let shown = Path::new(WIN_INSTALL_LOG);
    let real = layout.try_at(shown).map_err(|e| io_refused(shown, e))?;
    plain_meta(&real).map_err(|e| io_refused(shown, e))?;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&real)
        .map_err(|e| io_refused(shown, e))?;
    host.set_sddl(&real, INSTALL_LOG_SDDL)
        .map_err(|e| io_refused(shown, e))?;
    f.write_all(text.as_bytes())
        .map_err(|e| io_refused(shown, e))
}

// ---------------------------------------------------------------- uninstall

/// A managed agent's file, when it is a path install knows how to write: a doctored
/// `installed.toml` cannot make this delete anything else.
fn known_agent_path(layout: &Layout, agent: &str, path: &Path) -> Option<Agent> {
    let a = Agent::from_name(agent)?;
    (path == Path::new(layout.logical(agent_file(a)))).then_some(a)
}

pub(crate) fn uninstall(
    layout: &Layout,
    host: &dyn Host,
    purge: bool,
) -> Result<Vec<String>, InstallError> {
    if layout.is_system() && !host.elevated() {
        return Err(InstallError::NotElevated);
    }
    let check = Check { layout, host };
    let root_shown = layout.logical(OPT_DIR);
    // Nothing there, nothing to lock: the lock would make the root.
    if plain_meta(&check.at(root_shown)?)
        .map_err(|e| io_refused(Path::new(root_shown), e))?
        .is_none()
    {
        return Ok(Vec::new());
    }
    check.chain(root_shown)?;
    check.existing_own(root_shown, true)?;
    // Never removes what a running install is writing, purge or not.
    let lock = take_lock(layout, host, crate::install::INSTALL_LOCK_WAIT)?;
    let installed_logical = layout.logical(INSTALLED);
    let installed_path = check.at(installed_logical)?;
    let listed =
        read_installed(&installed_path).map_err(|e| refused(Path::new(installed_logical), e))?;
    let rec = match listed {
        Some(r) => r,
        None if purge => match read_previous(layout, host) {
            Some(r) => r,
            None => return Ok(Vec::new()),
        },
        None => return Ok(Vec::new()),
    };

    // Every chain, before the service goes: a refusal must remove nothing at all.
    for a in &rec.agents {
        if let Some(known) = known_agent_path(layout, &a.agent, &a.path) {
            check.chain(layout.logical(agent_file(known)))?;
        }
    }
    check.chain(layout.logical(BINARY))?;
    if purge {
        for tree in [STATE_DIR, LOG_DIR, ETC_DIR] {
            check.existing_own(layout.logical(tree), true)?;
        }
    }

    let mut out = Vec::new();
    stop_and_delete_service(host, &mut out)?;

    // Managed files, only when they are still what install wrote.
    for a in rec.agents.iter().rev() {
        let shown = a.path.display();
        let Some(known) = known_agent_path(layout, &a.agent, &a.path) else {
            out.push(format!(
                "warning: unknown managed agent {:?} at {shown} in installed.toml; left as is",
                a.agent
            ));
            continue;
        };
        let logical = layout.logical(agent_file(known));
        let p = check.at(logical)?;
        remove_managed_file(known, &p, &a.sha256, a.created_file, logical, &mut out)?;
    }
    let mcp = layout.logical(CLAUDE_MCP);
    for f in rec
        .files
        .iter()
        .filter(|f| f.kind == FileKind::Managed && f.path == Path::new(mcp))
    {
        let p = check.at(mcp)?;
        let Some(sha) = sha256_file(&p).map_err(step("managed"))? else {
            continue;
        };
        if f.sha256.as_deref() == Some(sha.as_str()) {
            remove_plain(&p).map_err(step("managed"))?;
            out.push(format!("removed {mcp}"));
        } else {
            out.push(format!("warning: {mcp} changed since install; left as is"));
        }
    }

    // The binary. Running, it can only be renamed: see `replace_with`.
    let binary_logical = layout.logical(BINARY);
    let binary_real = check.at(binary_logical)?;
    if rec
        .files
        .iter()
        .any(|f| f.kind == FileKind::Binary && f.path == Path::new(binary_logical))
    {
        remove_binary(host, &binary_real, binary_logical, &mut out)?;
    }
    for old in binaries_aside(&binary_real) {
        let _ = std::fs::remove_file(old);
    }

    // Listed dirs out of the kept trees, if empty, innermost first.
    let known = known_dirs(layout);
    let kept = [
        layout.logical(OPT_DIR),
        layout.logical(ETC_DIR),
        layout.logical(POLICY_D),
        layout.logical(STATE_DIR),
        layout.logical(KEYS_DIR),
        layout.logical(LOG_DIR),
        layout.logical(AUDIT_DIR),
        daemon_log_dir(layout),
    ];
    for d in rec.dirs.iter().rev() {
        let Some(logical) = known.iter().copied().find(|k| d == Path::new(k)) else {
            out.push(format!(
                "warning: unknown dir {} in installed.toml; left as is",
                d.display()
            ));
            continue;
        };
        if kept.contains(&logical) {
            continue;
        }
        check.chain(logical)?;
        if remove_empty_dir(&check.at(logical)?).map_err(step("dirs"))? {
            out.push(format!("removed {logical}"));
        }
    }

    // A hook left behind names `bin\saiife.exe`: see `naming_the_binary`.
    let still_named = naming_the_binary(&check)?;

    if !purge {
        for logical in &still_named {
            out.push(format!(
                "warning: {logical} still names {} after uninstall, so the hook stays, and Claude \
                 then blocks every tool; remove saiife's hook from that file",
                layout.logical(BINARY)
            ));
        }
        keep_copy(&check, &installed_path, &mut out)?;
        if remove_plain(&installed_path).map_err(step("installed.toml"))? {
            out.push(format!("removed {installed_logical}"));
        }
        out.push(format!(
            "kept {} (config, policy.d), {} (vault key), {} and the {} group \
             (remove them with --purge)",
            layout.logical(ETC_DIR),
            layout.logical(STATE_DIR),
            layout.logical(LOG_DIR),
            layout.audit_group()
        ));
        return Ok(out);
    }

    // --purge: state, log and etc, then the group, only if install made it.
    for tree in [STATE_DIR, LOG_DIR, ETC_DIR] {
        let logical = layout.logical(tree);
        check.chain(logical)?;
        if check.existing_own(logical, true)? {
            // Does not follow a link: std removes the link itself.
            std::fs::remove_dir_all(check.at(logical)?)
                .map_err(|e| io_refused(Path::new(logical), e))?;
            out.push(format!("removed {logical}"));
        }
    }
    for g in rec.groups.iter().rev() {
        if g == layout.audit_group()
            && host
                .lookup_local_group(g)
                .map_err(|e| io_refused(Path::new(g.as_str()), e))?
                .is_some()
        {
            host.delete_group(g).map_err(step("users"))?;
            out.push(format!("deleted group {g}"));
        }
    }
    // Last, and only once the lock in it has gone.
    drop(lock);
    if !still_named.is_empty() {
        out.push(format!(
            "warning: kept {root_shown}: {} still name {}, and with the folder gone any user \
             could put a program there that the hook runs for every user; remove saiife's hook \
             from them, then run uninstall --purge again",
            still_named.join(", "),
            layout.logical(BINARY)
        ));
        return Ok(out);
    }
    if remove_empty_dir(&check.at(root_shown)?).map_err(step("dirs"))? {
        out.push(format!("removed {root_shown}"));
    }
    Ok(out)
}

/// The managed files still on disk that name W9's binary. A file changed since install stays,
/// and `read_previous` clears the list after a plain uninstall, so this reads the files.
fn naming_the_binary(check: &Check<'_>) -> Result<Vec<&'static str>, InstallError> {
    let mut found = Vec::new();
    for file in [
        CLAUDE_MANAGED,
        CLAUDE_MCP,
        CODEX_REQUIREMENTS,
        GEMINI_SETTINGS,
    ] {
        let logical = check.layout.logical(file);
        let real = check.at(logical)?;
        // One that can't be read might name it: a kept root costs little.
        let names = match std::fs::read_to_string(&real) {
            Ok(text) => text.contains(saiife_agents::WINDOWS_BINARY),
            Err(e) => e.kind() != io::ErrorKind::NotFound,
        };
        if names {
            found.push(logical);
        }
    }
    Ok(found)
}

/// `Stop` (10 s; if it still runs, nothing is removed, as `stopped_or_refuse` does on
/// Linux), then `Delete`. A service that is not there is fine.
fn stop_and_delete_service(host: &dyn Host, out: &mut Vec<String>) -> Result<(), InstallError> {
    let fail = |detail: String| InstallError::Step {
        step: "stop".into(),
        detail: format!("{detail}; the daemon may still run, so uninstall removed nothing"),
    };
    let state = host
        .service(ServiceOp::Query)
        .map_err(|e| fail(e.to_string()))?;
    if state == ServiceState::Missing {
        return Ok(());
    }
    if state != ServiceState::Stopped {
        host.service(ServiceOp::Stop { wait: SERVICE_WAIT })
            .map_err(|e| fail(e.to_string()))?;
    }
    host.service(ServiceOp::Delete)
        .map_err(|e| fail(e.to_string()))?;
    out.push(format!("removed service {WIN_SERVICE}"));
    Ok(())
}

/// One agent's managed file or entry, only if its fingerprint is still install's. Anything
/// else is somebody's later change: it stays, with a warning.
fn remove_managed_file(
    a: Agent,
    p: &Path,
    sha: &str,
    created_file: bool,
    logical: &str,
    out: &mut Vec<String>,
) -> Result<(), InstallError> {
    let managed_step = |e: AgentError| InstallError::Step {
        step: "managed".into(),
        detail: e.to_string(),
    };
    let changed = || format!("warning: {logical} changed since install; left as is");
    if a == Agent::Claude {
        match sha256_file(p).map_err(step("managed"))? {
            None => {}
            Some(now) if now == sha => {
                remove_plain(p).map_err(step("managed"))?;
                out.push(format!("removed {logical}"));
            }
            Some(_) => out.push(changed()),
        }
        return Ok(());
    }
    if plain_meta(p).map_err(step("managed"))?.is_none() {
        return Ok(());
    }
    let (entry, remove): (EntryFn, RemoveFn) = if a == Agent::Codex {
        (codex::managed_entry, codex::remove_managed)
    } else {
        (gemini::managed_entry, gemini::remove_managed)
    };
    match entry(p).map_err(managed_step)? {
        None => return Ok(()),
        Some(now) if now != sha => {
            out.push(changed());
            return Ok(());
        }
        Some(_) => {}
    }
    remove(p).map_err(managed_step)?;
    if created_file && crate::uninstall::is_empty_config(a.name(), p) {
        remove_plain(p).map_err(step("managed"))?;
        out.push(format!("removed {logical}"));
    } else {
        out.push(format!("removed saiife's entry from {logical}"));
    }
    Ok(())
}

/// The binary, which a hook may be running: moved aside then, and said so.
fn remove_binary(
    host: &dyn Host,
    real: &Path,
    logical: &str,
    out: &mut Vec<String>,
) -> Result<(), InstallError> {
    match remove_plain(real) {
        Ok(true) => out.push(format!("removed {logical}")),
        Ok(false) => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            let aside =
                real.with_file_name(format!("{}.old.{}", name_of(logical), std::process::id()));
            host.rename_file(real, &aside).map_err(step("files"))?;
            out.push(format!(
                "warning: {logical} is in use; moved aside, remove it after it exits"
            ));
        }
        Err(e) => return Err(step("files")(e)),
    }
    Ok(())
}

/// Removes an empty dir. `false` when it is missing or not empty.
fn remove_empty_dir(path: &Path) -> io::Result<bool> {
    match plain_meta(path)? {
        None => return Ok(false),
        Some(m) if !m.is_dir() => return Ok(false),
        Some(_) => {}
    }
    if std::fs::read_dir(path)?.next().is_some() {
        return Ok(false);
    }
    std::fs::remove_dir(path).map(|_| true)
}

/// A plain uninstall keeps `installed.toml` as [`WIN_PREVIOUS`], with its row, so a later
/// install or `--purge` knows what install made.
fn keep_copy(
    check: &Check<'_>,
    installed: &Path,
    out: &mut Vec<String>,
) -> Result<(), InstallError> {
    let Ok(bytes) = std::fs::read(installed) else {
        return Ok(());
    };
    let shown = Path::new(WIN_PREVIOUS);
    let real = check.at(WIN_PREVIOUS)?;
    // No `<A>` on an `etc` row.
    let row = expected(check.layout, &real, NO_AUDIT_SID)
        .map_err(|e| io_refused(shown, e))?
        .ok_or_else(|| refused(shown, "no row in the ACL table"))?;
    check.chain(WIN_PREVIOUS)?;
    let tmp = real.with_file_name(format!(
        "{}.new.{}",
        name_of(WIN_PREVIOUS),
        std::process::id()
    ));
    let written = (|| -> Result<(), InstallError> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(step("installed.toml"))?;
        f.write_all(&bytes).map_err(step("installed.toml"))?;
        f.sync_all().map_err(step("installed.toml"))?;
        drop(f);
        check
            .host
            .set_sddl(&tmp, &row)
            .map_err(|e| io_refused(shown, e))?;
        check
            .host
            .rename_file(&tmp, &real)
            .map_err(step("installed.toml"))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    out.push(format!(
        "kept a copy of {} as {WIN_PREVIOUS}",
        check.layout.logical(INSTALLED)
    ));
    Ok(())
}

// On Unix: these drive the Windows tree on a Unix filesystem, and plant Unix links.
#[cfg(all(test, unix))]
mod windows_tests {
    use super::*;
    use crate::binary::tests::{pe_fixture, PeFixture};
    use crate::host::{FakeHost, RegValue};
    use crate::install::{install_locked, lock_install, package_exit};
    use crate::uninstall::UninstallOptions;
    use crate::winacl::{actual_file_ok, actual_ok};
    use saiife_win::sddl::stock;
    use std::collections::BTreeSet;
    use std::fs;

    const USER: &str = "S-1-5-21-9-9-9-1001";

    struct Env {
        _dir: tempfile::TempDir,
        layout: Layout,
        host: FakeHost,
        binary: PathBuf,
    }

    fn release_pe() -> Vec<u8> {
        pe_fixture(PeFixture {
            signed: true,
            ..PeFixture::default()
        })
    }

    /// A stock, elevated Windows machine below a temp dir.
    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under_for(dir.path(), Platform::Windows);
        let host = FakeHost::open(layout.root()).unwrap();
        let root = layout.root().to_path_buf();
        for (p, sd) in [
            ("C", stock::DRIVE_ROOT),
            ("C/ProgramData", stock::PROGRAM_DATA),
            ("C/Program Files", stock::PROGRAM_FILES),
        ] {
            fs::create_dir_all(root.join(p)).unwrap();
            let real = root.join(p);
            host.set(|s| {
                s.sddl.insert(real.clone(), sd.to_string());
            });
        }
        host.set(|s| {
            s.euid = 0;
            s.net = true;
        });
        let binary = root.join("incoming.exe");
        fs::write(&binary, release_pe()).unwrap();
        Env {
            _dir: dir,
            layout,
            host,
            binary,
        }
    }

    impl Env {
        fn at(&self, logical: &str) -> PathBuf {
            self.layout.try_at(Path::new(logical)).unwrap()
        }

        fn opts(&self) -> InstallOptions {
            InstallOptions {
                config: None,
                agents: Agent::ALL.to_vec(),
                approvers: Vec::new(),
                non_interactive: true,
                allow_test_build: false,
            }
        }

        fn run_with(&self, o: &InstallOptions) -> Result<InstallReport, InstallError> {
            let lock = lock_install(&self.layout, &self.host)?;
            let began = std::cell::Cell::new(false);
            install_locked(&lock, &self.layout, &self.host, o, &self.binary, &began)
        }

        fn run(&self) -> Result<InstallReport, InstallError> {
            self.run_with(&self.opts())
        }

        fn audit_sid(&self) -> String {
            self.host.state().sids[WIN_AUDIT_GROUP].clone()
        }

        fn want(&self, logical: &str) -> String {
            expected(&self.layout, &self.at(logical), &self.audit_sid())
                .unwrap()
                .unwrap()
        }

        fn calls(&self) -> Vec<String> {
            self.host.state().calls
        }

        /// Every file and dir below the root, but for the fake's own and what the test
        /// made.
        fn tree(&self) -> BTreeSet<String> {
            fn walk(base: &Path, dir: &Path, out: &mut BTreeSet<String>) {
                for e in fs::read_dir(dir).unwrap() {
                    let p = e.unwrap().path();
                    out.insert(p.strip_prefix(base).unwrap().display().to_string());
                    if p.is_dir() {
                        walk(base, &p, out);
                    }
                }
            }
            let mut out = BTreeSet::new();
            walk(self.layout.root(), self.layout.root(), &mut out);
            out.remove(".fakehost.json");
            out.remove("incoming.exe");
            out
        }
    }

    const STOCK_TREE: [&str; 3] = ["C", "C/ProgramData", "C/Program Files"];

    fn stock_tree() -> BTreeSet<String> {
        STOCK_TREE.iter().map(|s| s.to_string()).collect()
    }

    /// A dir made by someone: its descriptor is on record.
    fn plant_dir(e: &Env, logical: &str, sddl: &str) {
        let p = e.at(logical);
        fs::create_dir_all(&p).unwrap();
        e.host.set(|s| {
            s.sddl.insert(p.clone(), sddl.to_string());
        });
    }

    /// A dir an admin has closed: only admins write, Users read.
    const ADMIN_CLOSED: &str =
        "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    const CLAUDE_MANAGED_WIN: &str =
        r"C:\Program Files\ClaudeCode\managed-settings.d\50-saiife.json";

    fn user_owned() -> String {
        format!("O:{USER}G:{USER}D:(A;OICI;FA;;;{USER})")
    }

    /// What an admin's installer leaves in `C:\ProgramData`: inherited, and Users may
    /// create entries.
    fn admin_made_inherited() -> String {
        stock::PROGRAM_DATA.to_string()
    }

    const ALL_FILES: [&str; 9] = [
        BINARY,
        CONFIG,
        INSTALLED,
        VAULT_KEY,
        DAEMON_LOG,
        CLAUDE_MANAGED,
        CLAUDE_MCP,
        CODEX_REQUIREMENTS,
        GEMINI_SETTINGS,
    ];

    #[test]
    fn windows_fresh_install_writes_spec_paths_and_acls() {
        let e = env();
        let r = e.run().unwrap();
        assert!(r.started);
        let host = e.host.state();
        for abs in ALL_FILES {
            let logical = e.layout.logical(abs);
            let real = e.at(logical);
            assert!(real.is_file(), "{logical}");
            let got = &host.sddl[&real];
            assert_eq!(got, &e.want(logical), "{logical}");
            actual_ok(&e.want(logical), &parse(got).unwrap()).unwrap();
        }
        for dir in own_dirs(&e.layout) {
            let real = e.at(dir);
            assert!(real.is_dir(), "{dir}");
            assert_eq!(host.sddl[&real], e.want(dir), "{dir}");
        }
        for a in Agent::ALL {
            for dir in agent_dirs(&e.layout, a) {
                assert_eq!(host.sddl[&e.at(dir)], e.want(dir), "{dir}");
            }
        }
        // The vault key is 32 bytes, and readable only by the service, by its row.
        let key = e.at(e.layout.logical(VAULT_KEY));
        assert_eq!(fs::metadata(&key).unwrap().len(), 32);
        // The managed files name the Windows binary, not Linux text.
        let claude = fs::read_to_string(e.at(e.layout.logical(CLAUDE_MANAGED))).unwrap();
        assert!(claude.contains(WIN_HOOK_BINARY), "{claude}");
        assert!(!claude.contains("/opt/saiife"), "{claude}");
        let mcp = fs::read_to_string(e.at(e.layout.logical(CLAUDE_MCP))).unwrap();
        assert!(mcp.contains(WIN_HOOK_BINARY), "{mcp}");
        let codex = fs::read_to_string(e.at(e.layout.logical(CODEX_REQUIREMENTS))).unwrap();
        assert!(codex.contains(WIN_HOOK_BINARY), "{codex}");
        // installed.toml says all of it.
        let rec = read_installed(&e.at(e.layout.logical(INSTALLED)))
            .unwrap()
            .unwrap();
        assert_eq!(rec.vault_key, VaultKeyMode::DaemonFile);
        assert!(rec.groups.iter().any(|g| g == WIN_AUDIT_GROUP));
        let service = rec
            .files
            .iter()
            .find(|f| f.kind == FileKind::Service)
            .unwrap();
        assert_eq!(
            service.sha256.as_deref(),
            Some(ServiceSpec::saiifed(&e.layout).fingerprint().as_str())
        );
        // The lock has gone with its handle.
        assert!(!e.at(WIN_INSTALL_LOCK).exists());
    }

    /// A file's row reads back without `OI` and `CI`, which `set_sddl` leaves to Windows:
    /// the row given is the row asked for, and `actual_file_ok` is for reading it back.
    #[test]
    fn file_rows_are_for_actual_file_ok() {
        let e = env();
        e.run().unwrap();
        let logical = e.layout.logical(BINARY);
        let want = e.want(logical);
        let mut sd = parse(&want).unwrap();
        for ace in &mut sd.aces {
            ace.flags.object_inherit = false;
            ace.flags.container_inherit = false;
        }
        actual_file_ok(&want, &sd).unwrap();
    }

    #[test]
    fn windows_dirs_created_with_descriptor() {
        let e = env();
        e.run().unwrap();
        let calls = e.calls();
        let mut dirs: Vec<&str> = own_dirs(&e.layout).to_vec();
        for a in Agent::ALL {
            dirs.extend(agent_dirs(&e.layout, a));
        }
        for dir in dirs {
            let real = e.at(dir).display().to_string();
            let made = format!("create_dir_sddl {real} ");
            assert_eq!(
                calls.iter().filter(|c| c.starts_with(&made)).count(),
                1,
                "{dir}: {calls:?}"
            );
            let set = format!("set_sddl {real} ");
            assert!(!calls.iter().any(|c| c.starts_with(&set)), "{dir}");
        }
    }

    /// Each file has its row before it has its name: the rename comes after the set, and
    /// no set is ever on a file a user could have reached through the final name.
    #[test]
    fn a_new_file_has_its_row_before_its_name() {
        let e = env();
        e.run().unwrap();
        let calls = e.calls();
        let real = e.at(e.layout.logical(BINARY)).display().to_string();
        assert!(
            calls
                .iter()
                .any(|c| c.starts_with(&format!("set_sddl {real}.new."))),
            "{calls:?}"
        );
        assert!(!calls
            .iter()
            .any(|c| c.starts_with(&format!("set_sddl {real} "))));
    }

    fn refused_at(err: InstallError) -> (PathBuf, String) {
        match err {
            InstallError::Refused { path, detail } => (path, detail),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn user_owned_programdata_saiife_refused() {
        let e = env();
        plant_dir(&e, r"C:\ProgramData\saiife", &user_owned());
        let before = e.tree();
        let (path, detail) = refused_at(e.run().unwrap_err());
        assert_eq!(path, Path::new(r"C:\ProgramData\saiife"));
        assert!(detail.contains(USER), "{detail}");
        assert_eq!(e.tree(), before, "nothing written");
        assert_eq!(e.host.state().services.len(), 0);
    }

    #[test]
    fn user_owned_codex_dir_refused() {
        let e = env();
        plant_dir(&e, r"C:\ProgramData\OpenAI", &admin_made_inherited());
        plant_dir(&e, r"C:\ProgramData\OpenAI\Codex", &user_owned());
        let before = e.tree();
        let (path, detail) = refused_at(e.run().unwrap_err());
        assert_eq!(path, Path::new(r"C:\ProgramData\OpenAI\Codex"));
        assert!(detail.contains("owned by"), "{detail}");
        // The empty root the lock needed went with the lock.
        assert_eq!(e.tree(), before, "nothing written");
    }

    /// A user-owned parent refuses too, and a run without that agent never looks.
    #[test]
    fn user_owned_openai_refused_only_when_codex_is_listed() {
        let e = env();
        plant_dir(&e, r"C:\ProgramData\OpenAI", &user_owned());
        let (path, _) = refused_at(e.run().unwrap_err());
        assert_eq!(path, Path::new(r"C:\ProgramData\OpenAI"));
        let mut o = e.opts();
        o.agents = vec![Agent::Claude, Agent::Gemini];
        e.run_with(&o).unwrap();
    }

    #[test]
    fn junction_in_chain_refused() {
        let e = env();
        let outside = e.layout.root().join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, e.at(r"C:\ProgramData\gemini-cli")).unwrap();
        let before = e.tree();
        let (path, detail) = refused_at(e.run().unwrap_err());
        assert_eq!(path, Path::new(r"C:\ProgramData\gemini-cli"));
        assert!(detail.contains("reparse point"), "{detail}");
        assert_eq!(e.tree(), before, "nothing written, nothing followed");

        // At the root of the tree, and above it.
        let e = env();
        let outside = e.layout.root().join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, e.at(r"C:\ProgramData\saiife")).unwrap();
        assert!(e.run().is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    }

    /// A link deep in a tree of ours is found before anything is written.
    #[test]
    fn junction_inside_the_tree_refused_before_anything_changes() {
        let e = env();
        e.run().unwrap();
        let outside = e.layout.root().join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, e.at(r"C:\ProgramData\saiife\state\planted")).unwrap();
        e.host.set(|s| s.calls.clear());
        let err = e.run().unwrap_err();
        assert!(err.to_string().contains("reparse point"), "{err}");
        assert!(
            !e.calls().iter().any(|c| c.starts_with("set_sddl")),
            "{:?}",
            e.calls()
        );
    }

    /// An ancestor that fails is refused, even when everything below it would pass.
    #[test]
    fn unfit_ancestor_refused() {
        let e = env();
        let p = e.at(r"C:\ProgramData");
        e.host.set(|s| {
            s.sddl
                .insert(p.clone(), "O:BAG:SYD:P(A;;FA;;;BU)".to_string());
        });
        let (path, detail) = refused_at(e.run().unwrap_err());
        assert_eq!(path, Path::new(r"C:\ProgramData"));
        assert!(detail.contains("may"), "{detail}");
    }

    /// The chain is read before every set, on a reinstall too: a descriptor that goes bad
    /// part-way stops the run there.
    #[test]
    fn every_set_reads_the_whole_chain_first() {
        let e = env();
        e.run().unwrap();
        e.host.set(|s| s.calls.clear());
        e.run().unwrap();
        let calls = e.calls();
        // Every chain starts at the drive.
        let drive = format!("get_sddl {}", e.at(r"C:\").display());
        for (i, c) in calls.iter().enumerate() {
            if c.starts_with("set_sddl") {
                assert!(
                    calls[..i].iter().rev().take(8).any(|x| *x == drive),
                    "{c} without its chain: {calls:?}"
                );
            }
        }
        assert!(calls.iter().any(|c| c.starts_with("set_sddl")));
    }

    #[test]
    fn own_previous_tree_accepted() {
        let e = env();
        e.run().unwrap();
        // As the service leaves its own files: owned by it, ACEs inherited.
        let state_file = e.at(r"C:\ProgramData\saiife\state\sessions.db");
        fs::write(&state_file, b"x").unwrap();
        let service = service_sid(WIN_SERVICE);
        e.host.set(|s| {
            s.sddl.insert(
                state_file.clone(),
                format!(
                    "O:{service}G:{service}D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;{service})"
                ),
            );
        });
        let r = e.run().unwrap();
        assert!(r.started);
        // Its row went on, and nothing else changed.
        assert_eq!(
            e.host.state().sddl[&state_file],
            e.want(r"C:\ProgramData\saiife\state\sessions.db")
        );
        assert!(r.changed.is_empty(), "{:?}", r.changed);
    }

    /// `<S>` may write only where its row says: not on `etc`, and never the vault key, which
    /// a drifted descriptor must not hand to a compromised daemon.
    #[test]
    fn a_service_write_off_its_rows_is_refused() {
        let s = service_sid(WIN_SERVICE);
        let granted = format!("O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{s})");
        for logical in [
            r"C:\ProgramData\saiife\etc",
            r"C:\ProgramData\saiife\state\keys\vault.key",
        ] {
            let e = env();
            e.run().unwrap();
            let p = e.at(logical);
            e.host.set(|st| {
                st.sddl.insert(p.clone(), granted.clone());
            });
            let (path, detail) = refused_at(e.run().unwrap_err());
            assert_eq!(path, Path::new(logical));
            assert!(detail.contains(&s), "{detail}");
        }
    }

    /// Another product's parents keep their descriptor, and what lets Users create entries
    /// there is said, not refused.
    #[test]
    fn foreign_parents_are_relied_on_and_never_re_acled() {
        let e = env();
        let (openai, gemini) = (r"C:\ProgramData\OpenAI", r"C:\ProgramData\gemini-cli");
        plant_dir(&e, openai, &admin_made_inherited());
        plant_dir(&e, gemini, ADMIN_CLOSED);
        plant_dir(&e, r"C:\Program Files\ClaudeCode", stock::PROGRAM_FILES);
        for _ in 0..2 {
            let r = e.run().unwrap();
            let s = e.host.state();
            assert_eq!(s.sddl[&e.at(openai)], admin_made_inherited());
            assert_eq!(s.sddl[&e.at(gemini)], ADMIN_CLOSED);
            assert_eq!(
                s.sddl[&e.at(r"C:\Program Files\ClaudeCode")],
                stock::PROGRAM_FILES
            );
            assert!(
                r.warnings.iter().any(|w| w.starts_with(openai)),
                "{:?}",
                r.warnings
            );
        }
        // Not listed, so uninstall leaves them.
        let rec = read_installed(&e.at(e.layout.logical(INSTALLED)))
            .unwrap()
            .unwrap();
        assert!(!rec.dirs.iter().any(|d| d == Path::new(openai)));
        // What is below them is ours and has its row.
        let codex = r"C:\ProgramData\OpenAI\Codex";
        assert_eq!(e.host.state().sddl[&e.at(codex)], e.want(codex));
    }

    /// Claude Code reads every file in `managed-settings.d`, so one Users may add to is a
    /// way around the hooks: `ancestor_ok` is not enough there.
    #[test]
    fn a_managed_settings_d_users_can_add_to_is_refused() {
        let e = env();
        plant_dir(&e, r"C:\Program Files\ClaudeCode", stock::PROGRAM_FILES);
        plant_dir(
            &e,
            r"C:\Program Files\ClaudeCode\managed-settings.d",
            &admin_made_inherited(),
        );
        let (path, detail) = refused_at(e.run().unwrap_err());
        assert_eq!(
            path,
            Path::new(r"C:\Program Files\ClaudeCode\managed-settings.d")
        );
        assert!(detail.contains("reads its policy here"), "{detail}");
    }

    /// A managed file a user planted, and the admin then closed the dir over it.
    #[test]
    fn a_planted_managed_file_is_refused() {
        let e = env();
        plant_dir(&e, r"C:\ProgramData\gemini-cli", ADMIN_CLOSED);
        let settings = r"C:\ProgramData\gemini-cli\settings.json";
        let p = e.at(settings);
        fs::write(&p, b"{}").unwrap();
        e.host.set(|s| {
            s.sddl.insert(p.clone(), user_owned());
        });
        let (path, _) = refused_at(e.run().unwrap_err());
        assert_eq!(path, Path::new(settings));
    }

    #[test]
    fn hard_link_in_a_tree_is_refused_not_followed() {
        let e = env();
        e.run().unwrap();
        let outside = e.layout.root().join("victim");
        fs::write(&outside, b"x").unwrap();
        let linked = e.at(r"C:\ProgramData\saiife\state\linked");
        fs::hard_link(&outside, &linked).unwrap();
        let err = e.run().unwrap_err();
        assert!(err.to_string().contains("hard link"), "{err}");
        assert!(!e.host.state().sddl.contains_key(&linked));
    }

    #[test]
    fn audit_group_must_be_a_local_group() {
        // Another kind of account by that name.
        let e = env();
        e.host
            .set(|s| s.not_local_groups = vec![WIN_AUDIT_GROUP.to_string()]);
        let before = e.tree();
        let (path, detail) = refused_at(e.run().unwrap_err());
        assert!(path.display().to_string().contains(WIN_AUDIT_GROUP));
        assert!(detail.contains("no local group"), "{detail}");
        assert_eq!(e.tree(), before);
        // A well-known SID by that name.
        let e = env();
        e.host.set(|s| {
            s.sids
                .insert(WIN_AUDIT_GROUP.to_string(), "S-1-1-0".to_string());
        });
        assert!(e.run().unwrap_err().to_string().contains("S-1-1-0"));
    }

    /// `net.exe` exits 2 for a group that exists, so it is looked up first and an existing
    /// one is used, unlisted, so purge leaves it.
    #[test]
    fn an_existing_group_is_used_and_not_listed() {
        let e = env();
        let sid = "S-1-5-21-7-7-7-1500".to_string();
        e.host.set(|s| {
            s.sids.insert(WIN_AUDIT_GROUP.to_string(), sid.clone());
        });
        e.run().unwrap();
        assert!(
            !e.calls().iter().any(|c| c.contains("/add")),
            "{:?}",
            e.calls()
        );
        assert!(e.want(e.layout.logical(AUDIT_DIR)).contains(&sid));
        let rec = read_installed(&e.at(e.layout.logical(INSTALLED)))
            .unwrap()
            .unwrap();
        assert!(rec.groups.is_empty());
        crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: true }).unwrap();
        assert!(!e.calls().iter().any(|c| c.contains("/delete")));
    }

    fn service_calls(calls: &[String]) -> Vec<String> {
        calls
            .iter()
            .filter(|c| c.starts_with("service ") && !c.starts_with("service query"))
            .map(|c| c.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
            .collect()
    }

    #[test]
    fn windows_service_created_then_unchanged_on_reinstall() {
        let e = env();
        e.run().unwrap();
        assert_eq!(
            service_calls(&e.calls()),
            ["service create", "service sdset", "service start"]
        );
        let state = e.host.state();
        let spec = &state.services[WIN_SERVICE];
        assert_eq!(spec.sddl, WIN_SERVICE_SDDL);
        assert_eq!(spec.binary, e.at(e.layout.logical(BINARY)));
        e.host.set(|s| s.calls.clear());
        let r = e.run().unwrap();
        assert_eq!(
            service_calls(&e.calls()),
            ["service update", "service sdset"]
        );
        assert!(r.changed.is_empty(), "{:?}", r.changed);
    }

    #[test]
    fn a_stopped_service_is_started_and_a_different_spec_updated() {
        let e = env();
        e.run().unwrap();
        e.host.set(|s| {
            s.service_running = false;
            s.calls.clear();
        });
        e.run().unwrap();
        assert_eq!(
            service_calls(&e.calls()),
            ["service update", "service sdset", "service start"]
        );
        // The record no longer says this spec.
        let p = e.at(e.layout.logical(INSTALLED));
        let mut rec = read_installed(&p).unwrap().unwrap();
        for f in &mut rec.files {
            if f.kind == FileKind::Service {
                f.sha256 = Some("older".to_string());
            }
        }
        write_installed(&p, &rec).unwrap();
        e.host.set(|s| s.calls.clear());
        e.run().unwrap();
        assert_eq!(
            service_calls(&e.calls()),
            [
                "service update",
                "service sdset",
                "service stop",
                "service start"
            ]
        );
    }

    #[test]
    fn windows_config_change_sends_paramchange() {
        let e = env();
        e.run().unwrap();
        let new = e.layout.root().join("new.toml");
        fs::write(&new, "version = 2\nlocked = true\n").unwrap();
        e.host.set(|s| s.calls.clear());
        let mut o = e.opts();
        o.config = Some(new);
        let r = e.run_with(&o).unwrap();
        assert_eq!(
            service_calls(&e.calls()),
            ["service update", "service sdset", "service paramchange"]
        );
        assert_eq!(r.policy_hash.as_deref(), Some("fake"));
        assert_eq!(r.exit_code(false), 0);
        // A rejected config is exit 1, as on Linux.
        let other = e.layout.root().join("other.toml");
        fs::write(&other, "version = 2\nlocked = true\n# again\n").unwrap();
        e.host.set(|s| {
            s.policy_reload.loaded = false;
            s.policy_reload.reason = "no".to_string();
        });
        o.config = Some(other);
        let r = e.run_with(&o).unwrap();
        assert!(r
            .reload_problem
            .as_deref()
            .unwrap()
            .contains("keeps the old"));
        assert_eq!(r.exit_code(false), 1);
    }

    #[test]
    fn windows_binary_change_restarts() {
        let e = env();
        e.run().unwrap();
        let mut newer = release_pe();
        newer.push(0);
        fs::write(&e.binary, &newer).unwrap();
        e.host.set(|s| s.calls.clear());
        let r = e.run().unwrap();
        assert_eq!(
            service_calls(&e.calls()),
            [
                "service update",
                "service sdset",
                "service stop",
                "service start"
            ]
        );
        assert_eq!(fs::read(e.at(e.layout.logical(BINARY))).unwrap(), newer);
        assert!(r.changed.iter().any(|c| c == e.layout.logical(BINARY)));
    }

    /// Windows will not overwrite a running file, but will rename it. A rename refused for
    /// anything else stays an error.
    #[test]
    fn a_running_file_is_moved_aside() {
        let mut steps = Vec::new();
        let mut refused_once = true;
        let (tmp, path, aside) = (Path::new("t"), Path::new("p"), Path::new("a"));
        replace_with(
            &mut |a, b| {
                steps.push((a.to_path_buf(), b.to_path_buf()));
                if std::mem::take(&mut refused_once) {
                    Err(io::Error::from(io::ErrorKind::PermissionDenied))
                } else {
                    Ok(())
                }
            },
            tmp,
            path,
            aside,
        )
        .unwrap();
        let pair = |a: &str, b: &str| (PathBuf::from(a), PathBuf::from(b));
        assert_eq!(steps, [pair("t", "p"), pair("p", "a"), pair("t", "p")]);
        let e = replace_with(
            &mut |_, _| Err(io::Error::from(io::ErrorKind::NotFound)),
            tmp,
            path,
            aside,
        );
        assert_eq!(e.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    /// The old file is aside and the new one won't go in: the old one comes back.
    #[test]
    fn a_failed_second_rename_puts_the_old_file_back() {
        let mut steps = Vec::new();
        let (tmp, path, aside) = (Path::new("t"), Path::new("p"), Path::new("a"));
        let mut n = 0;
        let e = replace_with(
            &mut |a, b| {
                steps.push((a.to_path_buf(), b.to_path_buf()));
                n += 1;
                match n {
                    1 | 3 => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
                    _ => Ok(()),
                }
            },
            tmp,
            path,
            aside,
        );
        assert_eq!(e.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let pair = |a: &str, b: &str| (PathBuf::from(a), PathBuf::from(b));
        assert_eq!(
            steps,
            [
                pair("t", "p"),
                pair("p", "a"),
                pair("t", "p"),
                pair("a", "p")
            ]
        );
    }

    /// W14 for the leaf dirs: a stock child of `C:\ProgramData`, where Users create entries,
    /// is refused before anything is written, and the refusal says what to do.
    #[test]
    fn a_policy_dir_users_can_add_to_is_refused() {
        for dir in [
            r"C:\ProgramData\OpenAI\Codex",
            r"C:\ProgramData\gemini-cli",
            r"C:\Program Files\ClaudeCode",
            r"C:\Program Files\ClaudeCode\managed-settings.d",
        ] {
            let e = env();
            // What's above it is fine, so this dir is what gets refused.
            let above = parent_of(dir);
            if above.ends_with("OpenAI") {
                plant_dir(&e, above, &admin_made_inherited());
            } else if above.ends_with("ClaudeCode") {
                plant_dir(&e, above, stock::PROGRAM_FILES);
            }
            plant_dir(&e, dir, &admin_made_inherited());
            let before = e.tree();
            let (path, detail) = refused_at(e.run().unwrap_err());
            assert_eq!(path, Path::new(dir));
            assert!(detail.contains("let only administrators write"), "{detail}");
            assert_eq!(e.tree(), before, "nothing written for {dir}");
        }
    }

    /// A file a user put there between the preflight and the write.
    #[test]
    fn a_file_planted_after_the_preflight_is_refused() {
        let e = env();
        e.run().unwrap();
        let settings = r"C:\ProgramData\gemini-cli\settings.json";
        e.host.set(|s| {
            s.sddl.insert(e.at(settings), user_owned());
        });
        let check = Check {
            layout: &e.layout,
            host: &e.host,
        };
        assert!(check.existing_own(settings, false).is_err());
    }

    /// W9's binary path stays named in a file that stays. Removing the root would let any user
    /// recreate `C:\ProgramData\saiife\bin\saiife.exe`, which the hook would run for everyone.
    #[test]
    fn purge_keeps_the_root_while_a_managed_file_names_the_binary() {
        let e = env();
        e.run().unwrap();
        let settings = e.at(CLAUDE_MANAGED_WIN);
        let text = fs::read_to_string(&settings).unwrap();
        fs::write(&settings, format!("{text}\n")).unwrap();
        let out =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: true })
                .unwrap();
        assert!(e.at(r"C:\ProgramData\saiife").is_dir(), "{out:?}");
        let said = out.join("\n");
        assert!(said.contains("kept C:\\ProgramData\\saiife"), "{said}");
        assert!(said.contains(CLAUDE_MANAGED_WIN), "{said}");
    }

    /// A plain uninstall, then a purge from the kept copy, whose agents are cleared: the file
    /// is what's read, not the list.
    #[test]
    fn purge_after_plain_uninstall_still_finds_a_changed_file() {
        let e = env();
        e.run().unwrap();
        let settings = e.at(CLAUDE_MANAGED_WIN);
        let text = fs::read_to_string(&settings).unwrap();
        fs::write(&settings, format!("{text}\n")).unwrap();
        let out =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: false })
                .unwrap();
        let said = out.join("\n");
        assert!(said.contains("the hook stays"), "{said}");
        assert!(said.contains("blocks every tool"), "{said}");
        crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: true }).unwrap();
        assert!(e.at(r"C:\ProgramData\saiife").is_dir());
    }

    /// With every hook gone, purge takes the root as before.
    #[test]
    fn purge_removes_the_root_when_nothing_names_the_binary() {
        let e = env();
        e.run().unwrap();
        crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: true }).unwrap();
        assert!(!e.at(r"C:\ProgramData\saiife").exists());
    }

    /// Plain uninstall can't race an install: it waits on the same lock, and gives up.
    #[test]
    fn plain_uninstall_takes_the_lock() {
        let e = env();
        e.run().unwrap();
        e.host.set(|s| s.calls.clear());
        let _held = e.host.lock_file(&e.at(WIN_INSTALL_LOCK)).unwrap().unwrap();
        let e2 =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: false });
        assert!(e2.is_err(), "{e2:?}");
        assert!(e.host.state().services.contains_key(WIN_SERVICE));
    }

    /// A service someone changed under the same record is set back on a reinstall.
    #[test]
    fn a_reinstall_sets_the_service_again() {
        let e = env();
        e.run().unwrap();
        e.host.set(|s| s.calls.clear());
        e.run().unwrap();
        let calls = e.calls();
        assert!(calls.iter().any(|c| c.contains("update")), "{calls:?}");
    }

    #[test]
    fn windows_hklm_overrides_exits_1() {
        let e = env();
        e.host.set(|s| {
            s.registry.insert(
                (CLAUDE_HKLM_KEY.to_string(), "Settings".to_string()),
                RegValue::Str(r#"{"permissions":{}}"#.to_string()),
            );
        });
        let r = e.run().unwrap();
        assert_eq!(
            r.policy_failure.as_deref(),
            Some(claude::HKLM_OVERRIDES_TEXT)
        );
        assert_eq!(r.exit_code(false), 1);
        // Installed all the same.
        assert!(r.started);
        // Merge passes; without Claude nobody asks.
        e.host.set(|s| {
            s.registry.insert(
                (CLAUDE_HKLM_KEY.to_string(), "Settings".to_string()),
                RegValue::Str(r#"{"managedSourcesBehavior":"merge"}"#.to_string()),
            );
        });
        assert_eq!(e.run().unwrap().policy_failure, None);
        let e = env();
        e.host.set(|s| {
            s.registry.insert(
                (CLAUDE_HKLM_KEY.to_string(), "Settings".to_string()),
                RegValue::Str(r#"{"permissions":{}}"#.to_string()),
            );
        });
        let mut o = e.opts();
        o.agents = vec![Agent::Codex];
        assert_eq!(e.run_with(&o).unwrap().policy_failure, None);
    }

    #[test]
    fn windows_unfit_binary_refused() {
        let p = Path::new("x.exe");
        for bad in [
            // No load flag: the agent could plant a DLL beside it.
            pe_fixture(PeFixture {
                flags: 0,
                ..PeFixture::default()
            }),
            // A debug marker.
            pe_fixture(PeFixture {
                marker: Some(true),
                ..PeFixture::default()
            }),
            b"not a PE".to_vec(),
        ] {
            let (path, _) = refused_at(check_pe(p, &bad, true).unwrap_err());
            assert_eq!(path, p);
            // Below a test root, or with --allow-test-build, it warns.
            assert!(!check_pe(p, &bad, false).unwrap().is_empty());
        }
    }

    #[test]
    fn windows_unsigned_binary_warns() {
        let p = Path::new("x.exe");
        let unsigned = pe_fixture(PeFixture {
            signed: false,
            ..PeFixture::default()
        });
        let w = check_pe(p, &unsigned, true).unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("not Authenticode-signed"), "{w:?}");
        assert!(check_pe(p, &release_pe(), true).unwrap().is_empty());
    }

    /// A missing pipe's text ends with the log, as W10 says.
    #[test]
    fn a_pipe_that_never_answers_names_the_log() {
        let e = env();
        e.host.set(|s| s.pipe_error = Some("no answer".to_string()));
        let err = e.run().unwrap_err().to_string();
        assert!(
            err.ends_with(r"(see C:\ProgramData\saiife\log\daemon\daemon.log)"),
            "{err}"
        );
    }

    #[test]
    fn windows_uninstall_removes_exactly_what_install_listed() {
        let e = env();
        e.run().unwrap();
        e.host.set(|s| s.calls.clear());
        let out =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: false })
                .unwrap();
        assert!(!e.host.state().services.contains_key(WIN_SERVICE));
        let kept: BTreeSet<String> = [
            "C/ProgramData/saiife",
            "C/ProgramData/saiife/etc",
            "C/ProgramData/saiife/etc/config.toml",
            "C/ProgramData/saiife/etc/installed.previous.toml",
            "C/ProgramData/saiife/etc/policy.d",
            "C/ProgramData/saiife/state",
            "C/ProgramData/saiife/state/keys",
            "C/ProgramData/saiife/state/keys/vault.key",
            "C/ProgramData/saiife/log",
            "C/ProgramData/saiife/log/audit",
            "C/ProgramData/saiife/log/daemon",
            "C/ProgramData/saiife/log/daemon/daemon.log",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain(stock_tree())
        .collect();
        assert_eq!(e.tree(), kept, "{out:?}");
        assert_eq!(
            e.calls().iter().filter(|c| c.contains("/delete")).count(),
            0
        );
        // A second run has nothing to do.
        let again =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: false })
                .unwrap();
        assert!(again.is_empty(), "{again:?}");
        // And a later install finds its way back.
        assert!(e.run().unwrap().started);
    }

    #[test]
    fn uninstall_keeps_a_managed_file_changed_since_install() {
        let e = env();
        e.run().unwrap();
        let claude = e.layout.logical(CLAUDE_MANAGED);
        fs::write(e.at(claude), b"{\"changed\":true}").unwrap();
        let out =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: false })
                .unwrap();
        assert!(e.at(claude).exists());
        assert!(
            out.iter()
                .any(|l| l.starts_with("warning:") && l.contains(claude)),
            "{out:?}"
        );
    }

    /// A doctored `installed.toml` cannot make uninstall delete anything else.
    #[test]
    fn a_doctored_list_deletes_nothing_else() {
        let e = env();
        e.run().unwrap();
        let p = e.at(e.layout.logical(INSTALLED));
        let mut rec = read_installed(&p).unwrap().unwrap();
        let victim = e.at(r"C:\ProgramData\victim");
        fs::create_dir(&victim).unwrap();
        rec.dirs.push(PathBuf::from(r"C:\ProgramData\victim"));
        rec.agents[0].path = PathBuf::from(r"C:\ProgramData\saiife\etc\config.toml");
        write_installed(&p, &rec).unwrap();
        let out =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: false })
                .unwrap();
        assert!(victim.is_dir(), "{out:?}");
        assert!(e.at(e.layout.logical(CONFIG)).exists(), "{out:?}");
    }

    #[test]
    fn windows_uninstall_refuses_when_service_will_not_stop() {
        let e = env();
        e.run().unwrap();
        e.host.set(|s| s.service_will_not_stop = true);
        let before = e.tree();
        let err =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: false })
                .unwrap_err()
                .to_string();
        assert!(err.contains("removed nothing"), "{err}");
        assert_eq!(e.tree(), before);
        assert!(e.host.state().services.contains_key(WIN_SERVICE));
    }

    #[test]
    fn windows_purge_deletes_group() {
        let e = env();
        e.run().unwrap();
        let out =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: true })
                .unwrap();
        assert!(
            out.iter()
                .any(|l| l == &format!("deleted group {WIN_AUDIT_GROUP}")),
            "{out:?}"
        );
        assert!(e
            .calls()
            .iter()
            .any(|c| c.contains(WIN_AUDIT_GROUP) && c.contains("/delete")));
        // Everything install made, and nothing else.
        assert_eq!(e.tree(), stock_tree(), "{out:?}");
    }

    /// Purge after a plain uninstall still finds what install made, in the kept copy.
    #[test]
    fn purge_after_plain_uninstall_uses_the_kept_copy() {
        let e = env();
        e.run().unwrap();
        crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: false })
            .unwrap();
        crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: true }).unwrap();
        assert_eq!(e.tree(), stock_tree());
    }

    #[test]
    fn a_tree_someone_else_controls_is_not_purged() {
        let e = env();
        e.run().unwrap();
        let state = e.at(e.layout.logical(STATE_DIR));
        e.host.set(|s| {
            s.sddl.insert(state.clone(), user_owned());
        });
        let err =
            crate::uninstall::uninstall(&e.layout, &e.host, &UninstallOptions { purge: true })
                .unwrap_err();
        assert!(err.to_string().contains("owned by"), "{err}");
        assert!(state.is_dir());
        assert!(e.host.state().services.contains_key(WIN_SERVICE));
    }

    /// W26: from a plain shell, and from a low-integrity or restricted child of an elevated
    /// admin, which `euid` alone would pass. Exit 2 with W26's text, not `NotRoot`, and no
    /// "not supported" around it.
    #[test]
    fn not_elevated_refused_with_w26_text() {
        for limited in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let host = FakeHost::open(dir.path()).unwrap();
            let layout = Layout::system_for(Platform::Windows);
            host.set(|s| {
                s.euid = if limited { 0 } else { 0x4000_1234 };
                s.limited_token = limited;
            });
            let err = lock_install(&layout, &host).unwrap_err();
            assert!(matches!(err, InstallError::NotElevated), "{err:?}");
            assert_eq!(
                err.to_string(),
                "run this from an elevated terminal (Run as administrator)"
            );
            let err =
                crate::uninstall::uninstall(&layout, &host, &UninstallOptions { purge: true })
                    .unwrap_err();
            assert!(matches!(err, InstallError::NotElevated), "{err:?}");
            let err = crate::fleet::fleet_options(&layout, &host).unwrap_err();
            assert!(matches!(err, InstallError::NotElevated), "{err:?}");
        }
    }

    #[test]
    fn a_held_lock_refuses_and_changes_nothing() {
        let e = env();
        let first = lock_install(&e.layout, &e.host).unwrap();
        let err = e.run().unwrap_err().to_string();
        assert!(err.starts_with("lock: another saiife"), "{err}");
        assert!(err.contains(WIN_INSTALL_LOCK), "{err}");
        drop(first);
        assert!(e.run().is_ok());
    }

    /// The lock never opens inside a root someone else made first.
    #[test]
    fn the_lock_checks_the_root_before_opening_inside_it() {
        let e = env();
        plant_dir(&e, r"C:\ProgramData\saiife", &user_owned());
        let (path, _) = refused_at(lock_install(&e.layout, &e.host).unwrap_err());
        assert_eq!(path, Path::new(r"C:\ProgramData\saiife"));
        assert!(!e.at(WIN_INSTALL_LOCK).exists());
    }

    #[test]
    fn fleet_files_must_be_protected() {
        let e = env();
        // No fleet dir: no files, and all agents.
        let o = crate::fleet::fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(o.agents, Agent::ALL);
        e.run().unwrap();
        let dir = r"C:\ProgramData\saiife\etc\fleet";
        let row = e.want(dir);
        plant_dir(&e, dir, &row);
        let (config, install) = (
            e.layout.logical(FLEET_CONFIG),
            e.layout.logical(FLEET_INSTALL),
        );
        fs::write(e.at(config), "version = 2\nlocked = true\n").unwrap();
        fs::write(e.at(install), "agents = [\"codex\"]\n").unwrap();
        e.host.set(|s| {
            s.sddl.insert(e.at(config), row.clone());
            s.sddl.insert(e.at(install), row.clone());
        });
        let o = crate::fleet::fleet_options(&e.layout, &e.host).unwrap();
        assert_eq!(o.agents, [Agent::Codex]);
        assert_eq!(o.config, Some(e.at(config)));
        // Refusals name the path as Windows does.
        e.host.set(|s| {
            s.sddl.insert(e.at(install), user_owned());
        });
        let (path, _) = refused_at(crate::fleet::fleet_options(&e.layout, &e.host).unwrap_err());
        assert_eq!(path, Path::new(install));
        // What a deployment tool leaves with no descriptors of its own: refused.
        e.host.set(|s| {
            s.sddl.insert(e.at(install), row.clone());
            s.sddl.insert(e.at(dir), admin_made_inherited());
        });
        let (path, _) = refused_at(crate::fleet::fleet_options(&e.layout, &e.host).unwrap_err());
        assert_eq!(path, Path::new(dir));
    }

    #[test]
    fn package_flag_maps_exit_1_to_0() {
        assert_eq!(package_exit(1, true), 0);
        assert_eq!(package_exit(0, true), 0);
        assert_eq!(package_exit(2, true), 2, "a failed install rolls back");
        assert_eq!(package_exit(1, false), 1);
        assert_eq!(package_exit(2, false), 2);
    }

    #[test]
    fn install_log_is_appended() {
        let e = env();
        e.run().unwrap();
        append_install_log(&e.layout, &e.host, "first\n").unwrap();
        append_install_log(&e.layout, &e.host, "second\n").unwrap();
        assert_eq!(
            fs::read_to_string(e.at(WIN_INSTALL_LOG)).unwrap(),
            "first\nsecond\n"
        );
    }

    #[test]
    fn approvers_must_be_names() {
        for good in ["alice", "group:ops", r"ACME\alice", "group:ACME\\ops"] {
            assert!(valid_approver(good), "{good}");
        }
        for bad in ["", "a\"b", "a\nb", r"a\b\c", "a/b", "group:", "-x"] {
            assert!(!valid_approver(bad), "{bad}");
        }
    }

    #[test]
    fn logical_paths_stay_windows_ones() {
        assert_eq!(parent_of(r"C:\a\b"), r"C:\a");
        assert_eq!(name_of(r"C:\a\b"), "b");
        let e = env();
        assert!(in_tree(&e.layout, r"C:\ProgramData\saiife"));
        assert!(in_tree(&e.layout, r"c:\programdata\SAIIFE\etc"));
        assert!(!in_tree(&e.layout, r"C:\ProgramData\saiife2"));
        assert!(!in_tree(&e.layout, r"C:\ProgramData"));
    }
}
