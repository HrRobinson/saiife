//! The system checks of `saiife doctor`: supported system, install record,
//! config, root-owned paths, installed files, owners and modes, the audit
//! key, the daemon, lock labels, MCP servers and host facts. Each check id
//! is fixed; fleet tools match on it.

use super::report::{Check, Status};
use super::Ctx;
use crate::layout::*;
use crate::supported::{check_supported, Support};
use saiife_agents::lock::{label, LockLabel};
use saiife_agents::Agent;
use saiife_audit::sign::{judge, Kind};
use saiife_policy::installed::{FileKind, Installed, VaultKeyMode};
use sha2::{Digest, Sha256};
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

const NOT_INSTALLED: &str = "locked mode is not installed: developer mode checks only";
const NOT_CHECKED: &str = "not checked (run as root)";
/// Largest file `files.installed` fingerprints (16 MiB), the binary
/// excepted ([`MAX_BINARY`]).
const MAX_FINGERPRINT: u64 = 16 * 1024 * 1024;
/// Largest binary `files.installed` fingerprints and `files.binary` reads
/// (256 MiB): a saiife build can outgrow 16 MiB.
const MAX_BINARY: u64 = 256 * 1024 * 1024;
/// The audit key seed length.
const KEY_LEN: u64 = 32;

pub fn checks(ctx: &Ctx) -> Vec<Check> {
    let mut out = vec![supported(ctx)];
    if !ctx.locked() {
        out.push(Check::new(
            "install.record",
            Status::Info,
            "install record",
            NOT_INSTALLED,
        ));
        return out;
    }
    out.push(install_record(ctx));
    out.push(config_valid(ctx));
    out.push(paths_owner(ctx));
    if let Some(i) = &ctx.installed {
        out.push(files_installed(ctx, i));
    }
    out.push(files_binary(ctx));
    out.push(files_modes(ctx));
    out.push(keys(ctx));
    out.push(audit_group(ctx));
    out.push(daemon_group(ctx));
    out.push(daemon_unit(ctx));
    out.push(daemon_health(ctx));
    if let Some(i) = &ctx.installed {
        out.extend(i.agents.iter().map(|a| agent_label(&a.agent)));
    }
    if let Ok(p) = &ctx.config {
        out.extend(p.config.guard.mcp.allow_servers.iter().map(|s| {
            Check::new(
                format!("mcp.{s}"),
                Status::Warn,
                format!("MCP server {s} bypasses saiife: its requests are not brokered or limited"),
                "",
            )
        }));
    }
    if let Some(i) = &ctx.installed {
        out.push(Check::new(
            "vault.key",
            Status::Info,
            "vault key",
            match i.vault_key {
                VaultKeyMode::Credential => "encrypted systemd credential",
                VaultKeyMode::File => "plain key file (systemd < 250)",
            },
        ));
    }
    out.push(peer_pidfd());
    out.push(Check::new(
        "reauth",
        Status::Info,
        "re-authentication",
        "not configured",
    ));
    out.push(Check::new(
        "forwarding",
        Status::Info,
        "audit forwarding",
        "not configured",
    ));
    out
}

// ------------------------------------------------------------ helpers

/// Offenders and paths the caller could not look at, for one check.
#[derive(Default)]
struct Tally {
    bad: Vec<String>,
    unchecked: Vec<String>,
}

impl Tally {
    fn bad(&mut self, what: String) {
        if !self.bad.contains(&what) {
            self.bad.push(what);
        }
    }

    /// Fail naming every offender; else Info when something could not be
    /// looked at; else Pass.
    fn check(self, id: &str, title: &str) -> Check {
        if !self.bad.is_empty() {
            Check::new(id, Status::Fail, title, self.bad.join("; "))
        } else if !self.unchecked.is_empty() {
            Check::new(
                id,
                Status::Info,
                title,
                format!("{NOT_CHECKED}: {}", self.unchecked.join(", ")),
            )
        } else {
            Check::new(id, Status::Pass, title, "")
        }
    }
}

enum Stat {
    Found(Metadata),
    Missing,
    /// Not visible to this caller; recorded in the tally.
    Skipped,
}

/// `lstat` of `path` (shown as `shown`). A permission error without root
/// is "not checked"; any other error is an offender.
fn lstat(ctx: &Ctx, shown: &str, path: &Path, t: &mut Tally) -> Stat {
    match fs::symlink_metadata(path) {
        Ok(m) => Stat::Found(m),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Stat::Missing,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            t.unchecked.push(shown.to_string());
            Stat::Skipped
        }
        Err(e) => {
            t.bad(format!("{shown}: cannot stat: {e}"));
            Stat::Skipped
        }
    }
}

/// A configured path: the §5.2 default lies under the layout's root; any
/// other value is taken as written (a test or `--root` config names its
/// own absolute paths).
fn configured(ctx: &Ctx, value: &Path, default: &str) -> PathBuf {
    if value == Path::new(default) {
        ctx.layout.at(default)
    } else {
        value.to_path_buf()
    }
}

fn socket_dir(ctx: &Ctx) -> (String, PathBuf) {
    match &ctx.config {
        Ok(p) => {
            let v = &p.config.daemon.socket_dir;
            (v.display().to_string(), configured(ctx, v, RUN_DIR))
        }
        Err(_) => (RUN_DIR.to_string(), ctx.layout.at(RUN_DIR)),
    }
}

fn audit_dir(ctx: &Ctx) -> (String, PathBuf) {
    match &ctx.config {
        Ok(p) => {
            let v = &p.config.audit.dir;
            (v.display().to_string(), configured(ctx, v, AUDIT_DIR))
        }
        Err(_) => (AUDIT_DIR.to_string(), ctx.layout.at(AUDIT_DIR)),
    }
}

fn kind_of(m: &Metadata) -> &'static str {
    let t = m.file_type();
    if t.is_symlink() {
        "a symlink"
    } else if t.is_dir() {
        "a directory"
    } else if t.is_file() {
        "a regular file"
    } else if t.is_socket() {
        "a socket"
    } else {
        "a special file"
    }
}

// ------------------------------------------------------------ checks

fn supported(ctx: &Ctx) -> Check {
    const TITLE: &str = "supported system";
    match check_supported(ctx.layout, ctx.host) {
        Support::Supported { distro, systemd } => Check::new(
            "system.supported",
            Status::Pass,
            TITLE,
            format!("{distro}, systemd {systemd}"),
        ),
        // Without locked mode installed, an unsupported machine is only a
        // fact: developer mode does not need it.
        Support::Refused(why) => Check::new(
            "system.supported",
            if ctx.locked() {
                Status::Fail
            } else {
                Status::Info
            },
            TITLE,
            format!("locked mode is not supported here: {why}"),
        ),
    }
}

fn install_record(ctx: &Ctx) -> Check {
    const TITLE: &str = "install record";
    match (&ctx.installed, &ctx.installed_error) {
        (_, Some(e)) => Check::new("install.record", Status::Fail, TITLE, e.clone()),
        (Some(i), None) => Check::new(
            "install.record",
            Status::Pass,
            TITLE,
            format!("saiife {}, installed {}", i.saiife, i.installed_at),
        ),
        (None, None) => Check::new("install.record", Status::Info, TITLE, NOT_INSTALLED),
    }
}

fn config_valid(ctx: &Ctx) -> Check {
    const TITLE: &str = "system config";
    match &ctx.config {
        Ok(p) if p.warnings.is_empty() => Check::new("config.valid", Status::Pass, TITLE, ""),
        Ok(p) => Check::new("config.valid", Status::Warn, TITLE, p.warnings.join("; ")),
        Err(e) => Check::new(
            "config.valid",
            Status::Fail,
            TITLE,
            format!("{e}. Every managed hook call is denied, and nothing is recorded"),
        ),
    }
}

/// §5.6 item 2: every directory from `/` down to the binary, and the
/// `/etc/saiife` files, owned by root and not writable by group or others.
fn paths_owner(ctx: &Ctx) -> Check {
    const ID: &str = "paths.owner";
    const TITLE: &str = "root-owned paths";
    let mut t = Tally::default();
    let Some(root) = ctx.host.user("root") else {
        t.bad("user root is not in /etc/passwd".into());
        return t.check(ID, TITLE);
    };
    // (shown, path under the root)
    let fixed = |p: &str| (p.to_string(), ctx.layout.at(p));
    let mut paths: Vec<(String, PathBuf)> = Path::new(BINARY)
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|p| fixed(&p.display().to_string()))
        .collect();
    paths.extend([ETC_DIR, CONFIG, POLICY_D].map(fixed));
    let policy_d = ctx.layout.at(POLICY_D);
    match fs::read_dir(&policy_d) {
        Ok(rd) => {
            let mut names = Vec::new();
            for e in rd {
                match e {
                    Ok(e) => names.push(e.file_name()),
                    Err(e) => t.bad(format!("{POLICY_D}: cannot list: {e}")),
                }
            }
            // Every drop-in the loader reads, whatever its name's encoding.
            names.retain(|n| Path::new(n).extension().is_some_and(|x| x == "toml"));
            names.sort();
            paths.extend(names.into_iter().map(|n| {
                let shown = format!("{POLICY_D}/{}", n.to_string_lossy());
                (shown, policy_d.join(n))
            }));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            t.unchecked.push(format!("{POLICY_D}/*.toml"))
        }
        Err(e) => t.bad(format!("{POLICY_D}: cannot list: {e}")),
    }
    paths.extend([INSTALLED, CREDSTORE].map(fixed));
    for (shown, at) in &paths {
        let Stat::Found(m) = lstat(ctx, shown, at, &mut t) else {
            // A missing path is reported by the checks that need it.
            continue;
        };
        if m.file_type().is_symlink() {
            t.bad(format!("{shown}: is a symlink"));
            continue;
        }
        if m.uid() != root.uid {
            t.bad(format!("{shown}: owned by uid {}, not root", m.uid()));
        }
        let perm = m.mode() & 0o7777;
        if perm & 0o022 != 0 {
            t.bad(format!(
                "{shown}: mode {perm:04o} is writable by group or others"
            ));
        }
    }
    t.check(ID, TITLE)
}

/// The regular file `path`, opened without following a symlink or
/// blocking on a FIFO, with its metadata.
fn open_regular(path: &Path) -> io::Result<(fs::File, Metadata)> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let f = fs::File::from(fd);
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok((f, md))
}

/// The SHA-256 of the regular file `path` (see [`open_regular`]) of at
/// most `max` bytes.
fn sha256_file(path: &Path, max: u64) -> io::Result<String> {
    let (f, md) = open_regular(path)?;
    let too_large = || io::Error::new(io::ErrorKind::InvalidData, "file too large to fingerprint");
    if md.len() > max {
        return Err(too_large());
    }
    let mut h = Sha256::new();
    // Bounded even when the file grows after the size check.
    if io::copy(&mut io::Read::take(f, max + 1), &mut h)? > max {
        return Err(too_large());
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Whether the file listed as `listed` still exists (and, when `want` is
/// given, still has that SHA-256; read up to `max` bytes).
fn verify_file(ctx: &Ctx, listed: &Path, want: Option<&str>, max: u64, t: &mut Tally) {
    let shown = listed.display().to_string();
    let at = match ctx.layout.try_at(listed) {
        Ok(p) => p,
        Err(e) => return t.bad(format!("{shown}: {e}")),
    };
    match lstat(ctx, &shown, &at, t) {
        Stat::Missing => return t.bad(format!("{shown}: missing")),
        Stat::Skipped => return,
        Stat::Found(m) if !m.is_file() => {
            return t.bad(format!("{shown}: is {}, not a regular file", kind_of(&m)))
        }
        Stat::Found(_) => {}
    }
    let Some(want) = want else { return };
    match sha256_file(&at, max) {
        Ok(got) if got == want => {}
        Ok(_) => t.bad(format!("{shown}: changed since install")),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            t.unchecked.push(shown)
        }
        Err(e) if e.kind() == io::ErrorKind::InvalidData => t.bad(format!("{shown}: {e}")),
        Err(e) => t.bad(format!("{shown}: cannot read: {e}")),
    }
}

/// The fingerprint of saiife's entry in a shared managed file (Codex,
/// Gemini CLI; §8.3), as `system install` recorded it.
fn entry_fingerprint(agent: &str, file: &Path) -> Result<Option<String>, String> {
    let r = match agent {
        "codex" => saiife_agents::codex::managed_entry(file),
        "gemini" => saiife_agents::gemini::managed_entry(file),
        other => return Err(format!("unknown managed agent {other:?}")),
    };
    r.map_err(|e| e.to_string())
}

/// The installed binary must be the static release build (spec §9.2 A4): a
/// dynamic one honours `LD_PRELOAD` from an environment the agent shapes, a
/// debug-assertions build the `SAIIFE_EVAL_FAULT` test seam.
fn files_binary(ctx: &Ctx) -> Check {
    use crate::binary::{inspect, Linking, Profile};
    const ID: &str = "files.binary";
    const TITLE: &str = "installed binary";
    let fail = |d: String| Check::new(ID, Status::Fail, TITLE, d);
    let read = open_regular(&ctx.layout.at(BINARY)).and_then(|(f, md)| {
        if md.len() > MAX_BINARY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
        }
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut io::Read::take(f, MAX_BINARY + 1), &mut bytes)?;
        if bytes.len() as u64 > MAX_BINARY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
        }
        Ok(bytes)
    });
    let bytes = match read {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            return Check::new(ID, Status::Info, TITLE, format!("{NOT_CHECKED}: {BINARY}"))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return fail(format!("{BINARY}: missing")),
        Err(e) => return fail(format!("{BINARY}: cannot read: {e}")),
    };
    let info = match inspect(&bytes) {
        Ok(i) => i,
        Err(e) => return fail(format!("{BINARY}: not a static ELF executable ({e})")),
    };
    if let Linking::Dynamic(why) = &info.linking {
        return fail(format!(
            "{BINARY}: dynamically linked ({why}); an agent can inject code into the \
             managed hook through LD_PRELOAD: install the static release build"
        ));
    }
    match info.profile {
        Profile::Release => Check::new(ID, Status::Pass, TITLE, "static release build"),
        Profile::DebugAssertions => Check::new(
            ID,
            Status::Warn,
            TITLE,
            format!(
                "test build installed: {BINARY} has debug assertions on (the \
                 SAIIFE_EVAL_FAULT test seam can hang the guard); install the release build"
            ),
        ),
        Profile::Unknown => Check::new(
            ID,
            Status::Warn,
            TITLE,
            format!("{BINARY}: no saiife build marker; its build is unknown"),
        ),
    }
}

fn files_installed(ctx: &Ctx, i: &Installed) -> Check {
    let mut t = Tally::default();
    for f in &i.files {
        // The admin edits the config; only its presence is checked here,
        // its content by `config.valid`. The vault key has no digest on
        // record (installed.toml is world-readable); `files.modes` checks
        // its owner and mode.
        let want = match f.kind {
            FileKind::Config | FileKind::VaultKey => None,
            _ => f.sha256.as_deref(),
        };
        let max = if f.kind == FileKind::Binary {
            MAX_BINARY
        } else {
            MAX_FINGERPRINT
        };
        verify_file(ctx, &f.path, want, max, &mut t);
    }
    for a in &i.agents {
        if a.whole_file {
            verify_file(ctx, &a.path, Some(&a.sha256), MAX_FINGERPRINT, &mut t);
            continue;
        }
        let shown = a.path.display().to_string();
        let at = match ctx.layout.try_at(&a.path) {
            Ok(p) => p,
            Err(e) => {
                t.bad(format!("{shown}: {e}"));
                continue;
            }
        };
        match entry_fingerprint(&a.agent, &at) {
            Ok(Some(got)) if got == a.sha256 => {}
            Ok(Some(_)) => t.bad(format!("{shown}: changed since install")),
            Ok(None) => t.bad(format!("{shown}: missing")),
            Err(e) => t.bad(format!("{shown}: {e}")),
        }
    }
    t.check("files.installed", "installed files")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ty {
    Dir,
    File,
    Socket,
}

struct Want {
    shown: String,
    at: PathBuf,
    user: &'static str,
    group: &'static str,
    mode: u32,
    ty: Ty,
    /// Made by the running daemon (systemd's `RuntimeDirectory=`): absent
    /// while it is stopped, which `daemon.health` reports.
    while_running: bool,
}

fn want(
    shown: &str,
    at: PathBuf,
    (user, group): (&'static str, &'static str),
    mode: u32,
    ty: Ty,
    while_running: bool,
) -> Want {
    Want {
        shown: shown.to_string(),
        at,
        user,
        group,
        mode,
        ty,
        while_running,
    }
}

/// The §5.2 owner, group and mode of the paths systemd, the daemon and
/// install make.
fn files_modes(ctx: &Ctx) -> Check {
    let mut t = Tally::default();
    let l = |p: &str| ctx.layout.at(p);
    let (audit_shown, audit_at) = audit_dir(ctx);
    let (sock_shown, sock_at) = socket_dir(ctx);
    let socket_shown = format!("{}/saiife.sock", sock_shown.trim_end_matches('/'));
    let socket_at = sock_at.join("saiife.sock");
    let daemon = (DAEMON_USER, DAEMON_GROUP);
    let root = ("root", "root");
    let mut wants = vec![
        want(STATE_DIR, l(STATE_DIR), daemon, 0o700, Ty::Dir, false),
        want(KEYS_DIR, l(KEYS_DIR), daemon, 0o700, Ty::Dir, false),
        want(AUDIT_KEY, l(AUDIT_KEY), daemon, 0o600, Ty::File, false),
        want(
            &audit_shown,
            audit_at,
            (DAEMON_USER, AUDIT_GROUP),
            0o2750,
            Ty::Dir,
            false,
        ),
        want(&sock_shown, sock_at, daemon, 0o755, Ty::Dir, true),
        want(&socket_shown, socket_at, daemon, 0o666, Ty::Socket, true),
    ];
    if let Some(i) = &ctx.installed {
        wants.push(match i.vault_key {
            VaultKeyMode::Credential => want(VAULT_KEY, l(VAULT_KEY), root, 0o600, Ty::File, false),
            VaultKeyMode::File => want(
                VAULT_KEY,
                l(VAULT_KEY),
                ("root", DAEMON_GROUP),
                0o640,
                Ty::File,
                false,
            ),
        });
    }
    wants.push(want(UNIT, l(UNIT), root, 0o644, Ty::File, false));

    for w in &wants {
        let m = match lstat(ctx, &w.shown, &w.at, &mut t) {
            Stat::Found(m) => m,
            Stat::Missing if w.while_running => continue,
            Stat::Missing => {
                t.bad(format!("{}: missing", w.shown));
                continue;
            }
            Stat::Skipped => continue,
        };
        let uid = ctx.host.user(w.user).map(|u| u.uid);
        let gid = ctx.host.group_id(w.group);
        let (Some(uid), Some(gid)) = (uid, gid) else {
            if uid.is_none() {
                t.bad(format!("user {} does not exist", w.user));
            }
            if gid.is_none() {
                t.bad(format!("group {} does not exist", w.group));
            }
            continue;
        };
        let ft = m.file_type();
        let ty_ok = match w.ty {
            Ty::Dir => ft.is_dir(),
            Ty::File => ft.is_file(),
            Ty::Socket => ft.is_socket(),
        };
        let perm = m.mode() & 0o7777;
        if !ty_ok || m.uid() != uid || m.gid() != gid || perm != w.mode {
            t.bad(format!(
                "{}: want {}:{} {:04o}, found {} uid {} gid {} mode {perm:04o}",
                w.shown,
                w.user,
                w.group,
                w.mode,
                kind_of(&m),
                m.uid(),
                m.gid(),
            ));
        }
    }
    t.check("files.modes", "file owners and modes")
}

/// The 9a follow-up: the key dir and key file the daemon signs with, by
/// the daemon's own start-up rules, plus the key's length.
fn keys(ctx: &Ctx) -> Check {
    const ID: &str = "keys";
    const TITLE: &str = "audit signing key";
    let mut t = Tally::default();
    let Some(owner) = ctx.host.user(DAEMON_USER).map(|u| u.uid) else {
        t.bad(format!("user {DAEMON_USER} does not exist"));
        return t.check(ID, TITLE);
    };
    let keys_at = ctx.layout.at(KEYS_DIR);
    match lstat(ctx, KEYS_DIR, &keys_at, &mut t) {
        Stat::Found(m) => {
            if let Err(e) = judge(&keys_at, Kind::KeyDir, m.uid(), m.mode(), owner) {
                t.bad(e.to_string());
                return t.check(ID, TITLE);
            }
        }
        Stat::Missing => {
            t.bad(format!("{KEYS_DIR}: missing"));
            return t.check(ID, TITLE);
        }
        Stat::Skipped => return t.check(ID, TITLE),
    }
    let key_at = ctx.layout.at(AUDIT_KEY);
    match lstat(ctx, AUDIT_KEY, &key_at, &mut t) {
        Stat::Found(m) => {
            if let Err(e) = judge(&key_at, Kind::KeyFile, m.uid(), m.mode(), owner) {
                t.bad(e.to_string());
            } else if m.len() != KEY_LEN {
                t.bad(format!(
                    "{AUDIT_KEY}: is {} bytes, must be {KEY_LEN} bytes",
                    m.len()
                ));
            }
        }
        Stat::Missing => t.bad(format!("{AUDIT_KEY}: missing")),
        Stat::Skipped => {}
    }
    t.check(ID, TITLE)
}

/// The daemon gives the audit dir to `saiife-audit` at start, which needs
/// the daemon user in that group.
fn audit_group(ctx: &Ctx) -> Check {
    const ID: &str = "daemon.audit_group";
    const TITLE: &str = "daemon user in saiife-audit";
    let fail = |d: String| Check::new(ID, Status::Fail, TITLE, d);
    let Some(user) = ctx.host.user(DAEMON_USER) else {
        return fail(format!("user {DAEMON_USER} does not exist"));
    };
    let (Some(gid), Some(members)) = (
        ctx.host.group_id(AUDIT_GROUP),
        ctx.host.group_members(AUDIT_GROUP),
    ) else {
        return fail(format!("group {AUDIT_GROUP} does not exist"));
    };
    if user.gid == gid || members.iter().any(|m| m == DAEMON_USER) {
        Check::new(ID, Status::Pass, TITLE, "")
    } else {
        fail(format!(
            "{DAEMON_USER} is not a member of {AUDIT_GROUP}: the daemon cannot give the audit log to {AUDIT_GROUP}"
        ))
    }
}

/// No user but the daemon's is in the `saiife` group, listed in
/// `/etc/group` or by primary gid: the plain vault key (systemd < 250) is
/// readable by that group (§5.2).
fn daemon_group(ctx: &Ctx) -> Check {
    const ID: &str = "daemon.group";
    const TITLE: &str = "saiife group holds only the daemon user";
    let Some(gid) = ctx.host.group_id(DAEMON_GROUP) else {
        return Check::new(
            ID,
            Status::Fail,
            TITLE,
            format!("group {DAEMON_GROUP} does not exist"),
        );
    };
    let mut others: Vec<String> = ctx
        .host
        .group_members(DAEMON_GROUP)
        .unwrap_or_default()
        .into_iter()
        .chain(ctx.host.users_with_primary_gid(gid))
        .filter(|u| u != DAEMON_USER)
        .collect();
    others.sort();
    others.dedup();
    if others.is_empty() {
        Check::new(ID, Status::Pass, TITLE, "")
    } else {
        Check::new(
            ID,
            Status::Fail,
            TITLE,
            format!(
                "{} in group {DAEMON_GROUP}: they can read what the daemon's group can, including a plain vault key",
                others.join(", ")
            ),
        )
    }
}

fn daemon_unit(ctx: &Ctx) -> Check {
    const TITLE: &str = "saiifed.service active";
    match ctx.host.systemctl(&["is-active", UNIT_NAME]) {
        Ok(out) if out.stdout.trim() == "active" => {
            Check::new("daemon.unit", Status::Pass, TITLE, "")
        }
        Ok(out) => {
            let state = out.stdout.trim();
            Check::new(
                "daemon.unit",
                Status::Fail,
                TITLE,
                format!(
                    "systemctl is-active {UNIT_NAME}: {}",
                    if state.is_empty() { "no answer" } else { state }
                ),
            )
        }
        Err(e) => Check::new("daemon.unit", Status::Fail, TITLE, e.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn daemon_health(ctx: &Ctx) -> Check {
    use saiife_ipc::client::Client;
    use saiife_ipc::msg::OP_STATUS;
    use serde_json::{Map, Value};
    use std::time::{Duration, Instant};
    const TITLE: &str = "daemon health";
    let fail = |d: String| Check::new("daemon.health", Status::Fail, TITLE, d);
    let user = match &ctx.config {
        Ok(p) => p.config.daemon.user.clone(),
        Err(_) => DAEMON_USER.to_string(),
    };
    let Some(uid) = ctx.host.user(&user).map(|u| u.uid) else {
        return fail(format!("daemon user {user} is not in /etc/passwd"));
    };
    let (_, dir) = socket_dir(ctx);
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = Client::connect(&dir, uid, deadline)
        .and_then(|mut c| c.call(OP_STATUS, Map::new(), deadline));
    let m = match status {
        Ok(m) => m,
        Err(e) => return fail(e.to_string()),
    };
    if m.get("policy_ok").and_then(Value::as_bool) != Some(true) {
        return fail("policy not loaded: connector calls are denied".into());
    }
    let show = |k: &str| match m.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => "none".to_string(),
        Some(v) => v.to_string(),
    };
    Check::new(
        "daemon.health",
        Status::Pass,
        TITLE,
        format!(
            "chain {}, head seq {}, last checkpoint seq {}",
            show("chain"),
            show("head_seq"),
            show("last_checkpoint_seq")
        ),
    )
}

#[cfg(not(target_os = "linux"))]
fn daemon_health(_ctx: &Ctx) -> Check {
    Check::new(
        "daemon.health",
        Status::Fail,
        "daemon health",
        crate::supported::NOT_LINUX,
    )
}

fn agent_label(name: &str) -> Check {
    let id = format!("agents.{name}.label");
    match Agent::from_name(name) {
        Some(a) => {
            let l = label(a);
            let title = format!("{} lock label", a.label());
            let status = if l == LockLabel::Lockable {
                Status::Pass
            } else {
                Status::Warn
            };
            Check::new(id, status, title, l.wording())
        }
        None => Check::new(
            id,
            Status::Warn,
            format!("{name} lock label"),
            "unknown agent",
        ),
    }
}

/// `SO_PEERPIDFD` arrived in Linux 6.5.
pub(crate) fn pidfd_release(release: &str) -> bool {
    let mut parts = release.split(['.', '-']);
    let mut num = || parts.next().and_then(|s| s.parse::<u32>().ok());
    match (num(), num()) {
        (Some(major), Some(minor)) => (major, minor) >= (6, 5),
        _ => false,
    }
}

fn peer_pidfd() -> Check {
    let uname = rustix::system::uname();
    let release = uname.release().to_string_lossy();
    let linux = cfg!(target_os = "linux");
    Check::new(
        "peer.pidfd",
        Status::Info,
        "peer identity",
        if linux && pidfd_release(&release) {
            "SO_PEERPIDFD available"
        } else {
            "SO_PEERCRED only"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::super::{run, DoctorOptions, Report, Status};
    use crate::host::{FakeHost, Host, UserInfo};
    use crate::layout::*;
    use crate::testing::fake_install;
    use saiife_policy::installed::{read_installed, write_installed, ManagedAgent, VaultKeyMode};
    use saiife_policy::FixedDirectory;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    struct T {
        _dir: TempDir,
        layout: Layout,
        host: FakeHost,
    }

    impl T {
        fn installed() -> T {
            let dir = tempfile::tempdir().unwrap();
            fake_install(dir.path());
            T::open(dir)
        }

        fn empty() -> T {
            T::open(tempfile::tempdir().unwrap())
        }

        fn open(dir: TempDir) -> T {
            let layout = Layout::under(dir.path());
            let host = FakeHost::open(dir.path()).unwrap();
            T {
                _dir: dir,
                layout,
                host,
            }
        }

        fn at(&self, p: &str) -> std::path::PathBuf {
            self.layout.at(p)
        }

        fn chmod(&self, p: &str, mode: u32) {
            fs::set_permissions(self.at(p), fs::Permissions::from_mode(mode)).unwrap();
        }

        fn doctor(&self) -> Report {
            run(
                &self.layout,
                &self.host,
                &FixedDirectory::from_text("", ""),
                &DoctorOptions::default(),
            )
        }

        fn edit_installed(&self, f: impl FnOnce(&mut saiife_policy::installed::Installed)) {
            let p = self.at(INSTALLED);
            let mut i = read_installed(&p).unwrap().unwrap();
            f(&mut i);
            write_installed(&p, &i).unwrap();
        }

        fn append_config(&self, text: &str) {
            let p = self.at(CONFIG);
            let mut c = fs::read_to_string(&p).unwrap();
            c.push_str(text);
            fs::write(&p, c).unwrap();
        }
    }

    fn get<'r>(r: &'r Report, id: &str) -> &'r super::Check {
        r.checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no check {id} in\n{}", r.to_text()))
    }

    fn assert_status(r: &Report, id: &str, s: Status) {
        let c = get(r, id);
        assert_eq!(c.status, s, "{id}: {c:?}\n{}", r.to_text());
    }

    // Linux only: on macOS `system.supported` fails (locked mode needs Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn fake_install_fails_only_daemon_checks() {
        let t = T::installed();
        let r = t.doctor();
        for id in [
            "system.supported",
            "install.record",
            "config.valid",
            "paths.owner",
            "files.installed",
            "files.binary",
            "files.modes",
            "keys",
            "daemon.audit_group",
            "daemon.group",
            "agents.claude.label",
        ] {
            assert_status(&r, id, Status::Pass);
        }
        assert_status(&r, "daemon.unit", Status::Fail);
        assert_status(&r, "daemon.health", Status::Fail);
        let fails: Vec<&str> = r
            .checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(fails, ["daemon.unit", "daemon.health"], "{}", r.to_text());
        for id in ["vault.key", "peer.pidfd", "reauth", "forwarding"] {
            assert_status(&r, id, Status::Info);
        }
        assert_eq!(get(&r, "reauth").detail, "not configured");
        assert_eq!(get(&r, "forwarding").detail, "not configured");
        assert!(!r.checks.iter().any(|c| c.id.starts_with("mcp.")));
        // Doctor asked systemd, through the host, and changed nothing.
        let calls = t.host.state().calls;
        assert_eq!(calls, ["systemctl is-active saiifed.service"]);
        assert!(t.host.state().chowns.is_empty());
    }

    #[test]
    fn invalid_config_fails_and_says_no_records() {
        let t = T::installed();
        t.append_config("bogus = 1\n");
        let r = t.doctor();
        assert_status(&r, "config.valid", Status::Fail);
        let d = &get(&r, "config.valid").detail;
        assert!(
            d.ends_with(". Every managed hook call is denied, and nothing is recorded"),
            "{d}"
        );
        assert!(d.contains("config.toml"), "{d}");
    }

    #[test]
    fn group_writable_etc_fails() {
        let t = T::installed();
        t.chmod(ETC_DIR, 0o775);
        let r = t.doctor();
        assert_status(&r, "paths.owner", Status::Fail);
        let d = &get(&r, "paths.owner").detail;
        assert!(d.contains("/etc/saiife"), "{d}");
        assert!(!d.contains("/opt/saiife"), "{d}");
    }

    #[test]
    fn group_writable_policy_drop_in_fails() {
        let t = T::installed();
        let p = t.at(POLICY_D).join("10-team.toml");
        fs::write(&p, "").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
        let r = t.doctor();
        assert_status(&r, "paths.owner", Status::Fail);
        assert!(get(&r, "paths.owner")
            .detail
            .contains("/etc/saiife/policy.d/10-team.toml"));
    }

    #[test]
    fn hostile_policy_drop_in_name_is_named_safely() {
        use std::os::unix::ffi::OsStrExt;
        let t = T::installed();
        let raw = std::ffi::OsStr::from_bytes(b"\x1b[31mevil\n\xff.toml");
        let p = t.at(POLICY_D).join(raw);
        fs::write(&p, "").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
        let r = t.doctor();
        assert_status(&r, "paths.owner", Status::Fail);
        assert!(get(&r, "paths.owner").detail.contains("evil"));
        let text = r.to_text();
        assert!(!text.contains('\x1b') && !text.contains("evil\n"), "{text}");
        let json = serde_json::to_string(&r.to_json()).unwrap();
        assert!(
            !json.contains('\x1b') && json.contains("\\u001b[31mevil\\n"),
            "{json}"
        );
    }

    #[test]
    fn unlistable_policy_dir_is_reported() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let t = T::installed();
        t.chmod(POLICY_D, 0o000);
        let r = t.doctor();
        t.chmod(POLICY_D, 0o755);
        // A dir its owner (here: "root") cannot list is not checked.
        let d = &get(&r, "paths.owner").detail;
        assert!(d.contains("/etc/saiife/policy.d/*.toml"), "{d}");
    }

    #[test]
    fn oversized_file_is_not_fingerprinted() {
        let t = T::installed();
        let f = fs::File::options().write(true).open(t.at(UNIT)).unwrap();
        f.set_len(super::MAX_FINGERPRINT + 1).unwrap();
        let f = fs::File::options().write(true).open(t.at(BINARY)).unwrap();
        f.set_len(super::MAX_BINARY + 1).unwrap();
        let r = t.doctor();
        assert_status(&r, "files.installed", Status::Fail);
        let d = &get(&r, "files.installed").detail;
        for p in [UNIT, BINARY] {
            assert!(
                d.contains(&format!("{p}: file too large to fingerprint")),
                "{d}"
            );
        }
    }

    /// A binary may be larger than the 16 MiB other files are held to.
    #[test]
    fn large_binary_is_fingerprinted() {
        let t = T::installed();
        let mut big = crate::binary::fake_elf(None, 0, Some(false));
        big.resize(super::MAX_FINGERPRINT as usize + 4096, 0x5a);
        put_binary(&t, &big);
        let r = t.doctor();
        assert_status(&r, "files.installed", Status::Pass);
        assert_status(&r, "files.binary", Status::Pass);
        // Still compared: one byte changed is a changed file.
        let mut f = fs::File::options().write(true).open(t.at(BINARY)).unwrap();
        std::io::Seek::seek(&mut f, std::io::SeekFrom::End(-1)).unwrap();
        std::io::Write::write_all(&mut f, b"x").unwrap();
        let d = get(&t.doctor(), "files.installed").detail.clone();
        assert!(
            d.contains(&format!("{BINARY}: changed since install")),
            "{d}"
        );
    }

    /// Replaces the installed binary (and its digest on record).
    fn put_binary(t: &T, bytes: &[u8]) {
        fs::write(t.at(BINARY), bytes).unwrap();
        let sha = crate::fsops::sha256_hex(bytes);
        t.edit_installed(|i| {
            for f in &mut i.files {
                if f.kind == saiife_policy::installed::FileKind::Binary {
                    f.sha256 = Some(sha.clone());
                }
            }
        });
    }

    #[test]
    fn dynamic_binary_fails() {
        let t = T::installed();
        put_binary(
            &t,
            &crate::binary::fake_elf(Some("/lib64/ld-linux-x86-64.so.2"), 3, Some(false)),
        );
        let r = t.doctor();
        assert_status(&r, "files.binary", Status::Fail);
        assert_status(&r, "files.installed", Status::Pass);
        let d = &get(&r, "files.binary").detail;
        assert!(
            d.contains("dynamically linked (interpreter /lib64/ld-linux-x86-64.so.2)")
                && d.contains("LD_PRELOAD"),
            "{d}"
        );
        // Without an interpreter, a needed library is just as dynamic.
        put_binary(&t, &crate::binary::fake_elf(None, 1, Some(false)));
        assert_status(&t.doctor(), "files.binary", Status::Fail);
    }

    #[test]
    fn debug_build_warns_test_build_installed() {
        let t = T::installed();
        put_binary(&t, &crate::binary::fake_elf(None, 0, Some(true)));
        let r = t.doctor();
        assert_status(&r, "files.binary", Status::Warn);
        assert!(
            get(&r, "files.binary")
                .detail
                .starts_with("test build installed"),
            "{}",
            r.to_text()
        );
    }

    #[test]
    fn non_elf_or_missing_binary_fails() {
        let t = T::installed();
        put_binary(&t, b"#!/bin/sh\nexit 0\n");
        let r = t.doctor();
        assert_status(&r, "files.binary", Status::Fail);
        assert!(get(&r, "files.binary").detail.contains("not an ELF file"));
        fs::remove_file(t.at(BINARY)).unwrap();
        let r = t.doctor();
        assert_eq!(get(&r, "files.binary").detail, format!("{BINARY}: missing"));
    }

    #[test]
    fn ancestor_owned_by_other_uid_fails() {
        let t = T::installed();
        let uid = rustix::process::getuid().as_raw() + 1;
        t.host.set(|s| {
            s.users.insert(
                "root".into(),
                UserInfo {
                    uid,
                    gid: 0,
                    home: "/root".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        let r = t.doctor();
        assert_status(&r, "paths.owner", Status::Fail);
        let d = &get(&r, "paths.owner").detail;
        for p in [
            "/opt/saiife/bin/saiife",
            "/opt/saiife/bin",
            "/opt",
            "/etc/saiife",
        ] {
            assert!(d.contains(&format!("{p}: owned by uid")), "{p}: {d}");
        }
    }

    #[test]
    fn changed_managed_file_fails() {
        let t = T::installed();
        fs::write(t.at(CLAUDE_MANAGED), "{}\n").unwrap();
        fs::remove_file(t.at(BINARY)).unwrap();
        let r = t.doctor();
        assert_status(&r, "files.installed", Status::Fail);
        let d = &get(&r, "files.installed").detail;
        assert!(
            d.contains(&format!("{CLAUDE_MANAGED}: changed since install")),
            "{d}"
        );
        assert!(d.contains(&format!("{BINARY}: missing")), "{d}");
    }

    #[test]
    fn edited_config_is_not_a_changed_file() {
        let t = T::installed();
        t.append_config("\n# an admin's note\n");
        let r = t.doctor();
        assert_status(&r, "files.installed", Status::Pass);
    }

    #[test]
    fn missing_unit_fails() {
        let t = T::installed();
        fs::remove_file(t.at(UNIT)).unwrap();
        let r = t.doctor();
        for id in ["files.installed", "files.modes"] {
            assert_status(&r, id, Status::Fail);
            let d = &get(&r, id).detail;
            assert!(d.contains(&format!("{UNIT}: missing")), "{id}: {d}");
        }
    }

    #[test]
    fn wrong_unit_mode_fails() {
        let t = T::installed();
        t.chmod(UNIT, 0o664);
        let r = t.doctor();
        assert_status(&r, "files.modes", Status::Fail);
        let d = &get(&r, "files.modes").detail;
        assert!(d.contains(&format!("{UNIT}: want root:root 0644")), "{d}");
    }

    #[test]
    fn key_dir_0750_fails() {
        let t = T::installed();
        t.chmod(KEYS_DIR, 0o750);
        let r = t.doctor();
        assert_status(&r, "keys", Status::Fail);
        let d = &get(&r, "keys").detail;
        assert!(d.contains("keys") && d.contains("0750"), "{d}");
        assert_status(&r, "files.modes", Status::Fail);
    }

    #[test]
    fn key_file_wrong_size_fails() {
        let t = T::installed();
        fs::write(t.at(AUDIT_KEY), [1u8; 31]).unwrap();
        let r = t.doctor();
        assert_status(&r, "keys", Status::Fail);
        let d = &get(&r, "keys").detail;
        assert!(d.contains("31 bytes, must be 32"), "{d}");
    }

    #[test]
    fn key_file_symlink_fails() {
        let t = T::installed();
        let real = t.at(KEYS_DIR).join("real");
        fs::rename(t.at(AUDIT_KEY), &real).unwrap();
        std::os::unix::fs::symlink(&real, t.at(AUDIT_KEY)).unwrap();
        let r = t.doctor();
        assert_status(&r, "keys", Status::Fail);
        assert!(get(&r, "keys").detail.contains("symlink"));
    }

    #[test]
    fn unreadable_key_dir_is_info_when_not_root() {
        if rustix::process::geteuid().is_root() {
            return; // root reads through the 0000 dir
        }
        let t = T::installed();
        t.chmod(STATE_DIR, 0o000);
        let r = t.doctor();
        t.chmod(STATE_DIR, 0o700);
        assert_status(&r, "keys", Status::Info);
        assert!(get(&r, "keys").detail.contains("not checked (run as root)"));
    }

    #[test]
    fn daemon_user_outside_audit_group_fails() {
        let t = T::installed();
        t.host.set(|s| {
            s.members.clear();
            s.users.get_mut(DAEMON_USER).unwrap().gid = 4_000_000;
        });
        let r = t.doctor();
        assert_status(&r, "daemon.audit_group", Status::Fail);
        assert!(get(&r, "daemon.audit_group")
            .detail
            .contains("saiife is not a member of saiife-audit"));
    }

    #[test]
    fn other_users_in_the_saiife_group_fail() {
        let t = T::installed();
        assert_status(&t.doctor(), "daemon.group", Status::Pass);
        // A user whose primary group is saiife.
        let gid = t.host.group_id(DAEMON_GROUP).unwrap();
        t.host.set(|s| {
            s.users.insert(
                "alice".into(),
                UserInfo {
                    uid: 1000,
                    gid,
                    home: "/home/alice".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        let r = t.doctor();
        assert_status(&r, "daemon.group", Status::Fail);
        assert!(get(&r, "daemon.group")
            .detail
            .starts_with("alice in group saiife"));
        // A listed member.
        let t = T::installed();
        t.host.set(|s| {
            s.members
                .insert(DAEMON_GROUP.into(), vec!["bob".to_string()]);
        });
        assert_status(&t.doctor(), "daemon.group", Status::Fail);
    }

    #[test]
    fn active_unit_passes() {
        let t = T::installed();
        t.host.set(|s| {
            s.run.insert(
                "systemctl is-active saiifed.service".into(),
                crate::host::CmdOutput {
                    status: 0,
                    stdout: "active\n".into(),
                    stderr: String::new(),
                },
            );
        });
        assert_status(&t.doctor(), "daemon.unit", Status::Pass);
    }

    #[test]
    fn unverified_agent_warns() {
        let t = T::installed();
        t.edit_installed(|i| {
            i.agents.push(ManagedAgent {
                agent: "codex".into(),
                path: CODEX_REQUIREMENTS.into(),
                sha256: "0".repeat(64),
                whole_file: false,
                created_file: true,
            })
        });
        let r = t.doctor();
        assert_status(&r, "agents.claude.label", Status::Pass);
        assert_status(&r, "agents.codex.label", Status::Warn);
        assert_eq!(get(&r, "agents.codex.label").detail, "unverified");
        assert_eq!(r.exit_code(), 2);
    }

    #[test]
    fn mcp_server_warns_with_exact_text() {
        let t = T::installed();
        t.append_config("\n[guard.mcp]\nallow_servers = [\"github\", \"jira\"]\n");
        let r = t.doctor();
        assert_status(&r, "config.valid", Status::Pass);
        for s in ["github", "jira"] {
            let c = get(&r, &format!("mcp.{s}"));
            assert_eq!(c.status, Status::Warn);
            assert_eq!(
                c.title,
                format!("MCP server {s} bypasses saiife: its requests are not brokered or limited")
            );
        }
    }

    #[test]
    fn not_installed_is_info_only() {
        let t = T::empty();
        let r = t.doctor();
        let ids: Vec<&str> = r.checks.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            ["system.supported", "install.record"],
            "{}",
            r.to_text()
        );
        let c = get(&r, "install.record");
        assert_eq!(c.status, Status::Info);
        assert_eq!(
            c.detail,
            "locked mode is not installed: developer mode checks only"
        );
        // An unsupported dev machine without locked mode is not a failure.
        assert_status(&r, "system.supported", Status::Info);
        assert_eq!(r.exit_code(), 0);
    }

    // Linux only: on macOS `system.supported` fails (locked mode needs Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_system_fails_when_installed() {
        let t = T::installed();
        fs::write(t.at("/etc/os-release"), "ID=alpine\nVERSION_ID=3.20\n").unwrap();
        let r = t.doctor();
        assert_status(&r, "system.supported", Status::Fail);
        assert!(get(&r, "system.supported").detail.contains("Alpine"));
    }

    #[test]
    fn bad_install_record_fails() {
        let t = T::installed();
        fs::write(t.at(INSTALLED), "version = 99\n").unwrap();
        let r = t.doctor();
        assert_status(&r, "install.record", Status::Fail);
    }

    #[test]
    fn vault_key_mode_reported() {
        let t = T::installed();
        let r = t.doctor();
        assert_eq!(get(&r, "vault.key").detail, "encrypted systemd credential");
        t.edit_installed(|i| {
            i.vault_key = VaultKeyMode::File;
            i.systemd = 249;
        });
        // root:saiife 0640 on systemd < 250; 0600 is now wrong.
        let r = t.doctor();
        assert_eq!(
            get(&r, "vault.key").detail,
            "plain key file (systemd < 250)"
        );
        assert_status(&r, "files.modes", Status::Fail);
        assert!(get(&r, "files.modes")
            .detail
            .contains(&format!("{VAULT_KEY}: want root:saiife 0640")));
        t.chmod(VAULT_KEY, 0o640);
        assert_status(&t.doctor(), "files.modes", Status::Pass);
    }

    #[test]
    fn audit_dir_without_setgid_fails() {
        let t = T::installed();
        t.chmod(AUDIT_DIR, 0o750);
        let r = t.doctor();
        assert_status(&r, "files.modes", Status::Fail);
        assert!(get(&r, "files.modes")
            .detail
            .contains("/var/log/saiife/audit: want saiife:saiife-audit 2750"));
    }

    #[test]
    fn pidfd_from_release() {
        assert!(super::pidfd_release("6.5.0-1-generic"));
        assert!(super::pidfd_release("7.2.4-arch1-2"));
        assert!(super::pidfd_release("6.10.3"));
        assert!(!super::pidfd_release("6.4.16"));
        assert!(!super::pidfd_release("5.15.0-91-generic"));
        assert!(!super::pidfd_release("junk"));
    }
}
