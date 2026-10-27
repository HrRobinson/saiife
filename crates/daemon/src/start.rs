//! Startup, the serve loop, reload and stop (spec §6.2).

use crate::ops::{check_services, Ctx, CtxInit, PolicyState, MODE, VERSION};
use crate::tokens::{self, Tokens};
use crate::vault::{self, VaultState};
use crate::writer::{self, pending_key_path, WriterConfig};
use crate::{gateway, notify, server, DaemonOptions};
use saiife_audit::sign::AuditKey;
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_broker::limits::Limiter;
use saiife_broker::pipeline::limit_event;
use saiife_broker::upstream::Upstream;
use saiife_ipc::msg::{GATEWAY_SOCKET_NAME, SOCKET_NAME};
use saiife_policy::{load_and_check, parse_duration, AuditCfg, DaemonCfg, Fsync, LoadedPolicy};
use serde_json::{json, Value};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};

/// Records re-verified at start (spec §6.2).
const STARTUP_CHECK_RECORDS: usize = 1000;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// The group that may read the audit log (spec §5.2).
const AUDIT_GROUP: &str = "saiife-audit";

/// A startup refusal: one line on stderr, exit 2.
struct Refuse(String);

impl<T: Into<String>> From<T> for Refuse {
    fn from(s: T) -> Self {
        Refuse(s.into())
    }
}

pub fn run(opts: DaemonOptions) -> ExitCode {
    match start(opts) {
        Ok(code) => code,
        Err(Refuse(msg)) => {
            eprintln!("saiife: {msg}");
            ExitCode::from(2)
        }
    }
}

/// What the daemon needs before the policy is checked, read leniently from
/// `config.toml` alone: a value that is missing or of the wrong type takes
/// its §8.1 default. A config that cannot be read or parsed gives all
/// defaults and `locked: None`.
struct Bootstrap {
    locked: Option<bool>,
    daemon: DaemonCfg,
    audit: AuditCfg,
}

fn read_bounded(path: &Path) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    let mut s = String::new();
    f.take(MAX_CONFIG_BYTES + 1).read_to_string(&mut s).ok()?;
    (s.len() as u64 <= MAX_CONFIG_BYTES).then_some(s)
}

fn bootstrap(path: &Path) -> Bootstrap {
    let mut b = Bootstrap {
        locked: None,
        daemon: DaemonCfg::default(),
        audit: AuditCfg::default(),
    };
    let Some(t) = read_bounded(path).and_then(|s| s.parse::<toml::Table>().ok()) else {
        return b;
    };
    b.locked = Some(
        t.get("locked")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false),
    );
    let get = |sect: &str, key: &str| t.get(sect)?.get(key).cloned();
    let s = |v: Option<toml::Value>| v.and_then(|v| v.as_str().map(str::to_string));
    let n = |v: Option<toml::Value>| {
        v.and_then(|v| v.as_integer())
            .and_then(|i| u64::try_from(i).ok())
    };
    if let Some(u) = s(get("daemon", "user")) {
        b.daemon.user = u;
    }
    if let Some(d) = s(get("daemon", "socket_dir")) {
        b.daemon.socket_dir = d.into();
    }
    if let Some(d) = s(get("audit", "dir")) {
        b.audit.dir = d.into();
    }
    if let Some(v) = n(get("audit", "checkpoint_every")) {
        b.audit.checkpoint_every = v;
    }
    if let Some(v) = s(get("audit", "checkpoint_interval")).and_then(|v| parse_duration(&v).ok()) {
        b.audit.checkpoint_interval = v;
    }
    if let Some(v) = n(get("audit", "min_free_mb")) {
        b.audit.min_free_mb = v;
    }
    match s(get("audit", "fsync")).as_deref() {
        Some("always") => b.audit.fsync = Fsync::Always,
        Some("checkpoint") => b.audit.fsync = Fsync::Checkpoint,
        _ => {}
    }
    b
}

fn start(opts: DaemonOptions) -> Result<ExitCode, Refuse> {
    // 1. Who and what may run.
    let euid = rustix::process::geteuid().as_raw();
    if euid == 0 {
        return Err("the daemon must run as the daemon user, not root".into());
    }
    let boot = bootstrap(&opts.config);
    let name = boot.daemon.user.clone();
    match opts.directory.user(&name) {
        Some(u) if u.uid == euid => {}
        Some(_) => {
            return Err(format!("the daemon runs as {name} per [daemon] user, not uid {euid}").into())
        }
        None => {
            return Err(format!(
                "the daemon runs as {name} per [daemon] user, and there is no such user (this is uid {euid})"
            )
            .into())
        }
    }
    if boot.locked == Some(false) {
        return Err(format!(
            "{}: the daemon serves a locked config only; set locked = true",
            opts.config.display()
        )
        .into());
    }

    // 2. No core dumps (the signing key is in memory).
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        eprintln!("saiife: warning: cannot turn off core dumps: {e}");
    }

    // 3. The policy; an invalid one still lets the daemon accept audit.
    let directory: Arc<dyn saiife_policy::Directory + Send + Sync> = Arc::from(opts.directory);
    // The services are checked against the connector catalog as part of
    // the policy: a broken one makes the whole policy invalid.
    let loaded = load_and_check(&opts.config, directory.as_ref())
        .map_err(|e| e.to_string())
        .and_then(|l| check_services(&l, &opts.config).map(|cat| (l, cat)));
    let (daemon_cfg, audit_cfg, policy, policy_err) = match &loaded {
        Ok((l, cat)) => (
            l.config.daemon.clone(),
            l.config.audit.clone(),
            PolicyState::from_loaded(l, &opts.catalog, cat.clone()),
            None,
        ),
        Err(e) => {
            eprintln!("saiife: warning: policy not loaded, accepting audit only: {e}");
            (
                boot.daemon.clone(),
                boot.audit.clone(),
                PolicyState {
                    hash: None,
                    ok: false,
                    min_free_mb: boot.audit.min_free_mb,
                    admin_groups: Vec::new(),
                    system: None,
                    gateway: None,
                },
                Some(e.clone()),
            )
        }
    };
    let gateway_cfg = match &loaded {
        Ok((l, _)) => l.config.gateway.clone(),
        Err(_) => saiife_policy::GatewayCfg::default(),
    };

    // 4. The signing key.
    let key_path = opts.state_dir.join("keys").join("audit.ed25519");
    let (key, _created) = AuditKey::load_or_create(&key_path).map_err(|e| e.to_string())?;
    let pending = pending_key_path(&key_path);
    if std::fs::symlink_metadata(&pending).is_ok() {
        eprintln!(
            "saiife: warning: {} is left from an interrupted key rotation; the key in {} stays in force",
            pending.display(),
            key_path.display()
        );
    }

    // 5. The chain: one writer, checked at start.
    let cw = ChainWriter::open(
        &audit_cfg.dir,
        WriterOptions {
            mode: MODE.into(),
            saiife: VERSION.into(),
            key: Some(key),
        },
    )
    .map_err(|e| format!("{}: {e}", audit_cfg.dir.display()))?;
    regroup_audit_dir(&audit_cfg.dir, directory.as_ref());
    let check = cw.startup_check(STARTUP_CHECK_RECORDS);
    let writer_cfg = WriterConfig {
        checkpoint_every: audit_cfg.checkpoint_every,
        checkpoint_interval: audit_cfg.checkpoint_interval,
        fsync: audit_cfg.fsync,
    };
    let (handle, join) = writer::spawn(cw, writer_cfg, check.last_checkpoint)
        .map_err(|e| format!("cannot start the audit writer: {e}"))?;

    // The vault: an unavailable one never stops the daemon (fail closed
    // for connectors, audit keeps working).
    let vault_path = opts.state_dir.join("vault").join("vault.bin");
    let vault = match &opts.credentials_dir {
        Some(d) => vault::open(&d.join("vault-key"), &vault_path),
        None => VaultState::Unavailable("no vault key".into()),
    };

    // Connector limits survive a restart: rebuilt from the last 24 h of
    // connector records (spec §6.9.2).
    let (limiter, rebuild_failed) = rebuild_limiter(&audit_cfg.dir);
    let rebuild_note = rebuild_failed.map(|f| {
        let (reason, fields) = f.note();
        eprintln!("saiife: warning: {reason}");
        ("limits_rebuild_failed", reason, fields)
    });
    let capped_note = (limiter.rebuild_dropped() > 0).then(|| {
        let dropped = limiter.rebuild_dropped();
        let reason = format!(
            "{dropped} connector record(s) of the last 24 h were left out of the limits: a (uid, service) bucket holds at most {} events, and the oldest went",
            saiife_broker::limits::BUCKET_CAP
        );
        eprintln!("saiife: warning: {reason}");
        let mut m = serde_json::Map::new();
        m.insert("dropped".into(), dropped.into());
        ("limits_rebuild_capped", reason, m)
    });
    // The upstream client: the native roots plus `<config dir>/ca`, which
    // must be root's (a CA there can impersonate any upstream). A refused
    // directory is a `ca_refused` record; the native roots stay. The tests
    // trust their loopback CA through that same directory (owner seam in
    // `trusted_owner`), so the daemon has no seam for roots or names.
    let ca_dir = opts.config.parent().unwrap_or(Path::new("/")).join("ca");
    let ca_refused = check_ca_dir(&ca_dir, trusted_owner()).err();
    if let Some(why) = &ca_refused {
        eprintln!("saiife: warning: extra CAs not used: {why}");
    }
    let ca = ca_refused.is_none().then_some(ca_dir.as_path());
    let upstream = Upstream::with_ca_dir(ca, gateway_cfg.upstream_timeout).map_err(|e| {
        eprintln!("saiife: warning: connector calls will fail: {e}");
        e.to_string()
    });
    // Import backups older than 7 days go at start (and daily in `serve`).
    let backup_dir = crate::import_backup::dir_in(&opts.state_dir);
    crate::import_backup::purge(&backup_dir, crate::import_backup::now());
    // The approval requests; pending ones past their expiry are expired at
    // start (and every 30 s in `serve`). A store that cannot be opened
    // keeps the daemon up and denies every `ask`.
    let approvals = crate::approvals::Store::open(&crate::approvals::dir_in(&opts.state_dir))
        .map_err(|e| {
            eprintln!("saiife: warning: approvals unavailable: {e}");
            e.to_string()
        });
    // Their `approval`/`expired` records go with the start records.
    let expired_at_start = match &approvals {
        Ok(store) => store.sweep(crate::import_backup::now()),
        Err(_) => Vec::new(),
    };
    // The gateway's bearer tokens; an unreadable file is no tokens and a
    // `tokens_reset` record.
    let (tokens, tokens_reset) =
        Tokens::open(tokens::path_in(&opts.state_dir), tokens::system_clock());
    if let Some(why) = &tokens_reset {
        eprintln!("saiife: warning: gateway tokens reset: {why}");
    }
    // Checked at load: loopback only. No valid policy, no listener.
    let tcp = gateway_cfg.tcp_addr().ok().flatten();

    let ctx = Arc::new(Ctx::new(CtxInit {
        writer: handle,
        writer_cfg,
        directory,
        own_uid: euid,
        own_user: name,
        audit_dir: audit_cfg.dir.clone(),
        socket_dir: daemon_cfg.socket_dir.clone(),
        key_path,
        config_path: opts.config.clone(),
        catalog: opts.catalog,
        policy,
        proc: Box::new(crate::sessions::RealProc::new("/proc")),
        vault,
        vault_path,
        limiter,
        upstream,
        backup_dir,
        tokens: Arc::new(tokens),
        approvals,
    }));
    ctx.tcp.lock().unwrap_or_else(|p| p.into_inner()).configured = gateway_cfg.tcp.clone();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the runtime: {e}"))?;
    let loaded_files = loaded.as_ref().ok().map(|(l, _)| files_json(l));
    let notes: Vec<_> = [("ca_refused", ca_refused), ("tokens_reset", tokens_reset)]
        .into_iter()
        .filter_map(|(e, r)| Some((e, r?, serde_json::Map::new())))
        .chain(rebuild_note)
        .chain(capped_note)
        .collect();
    let more = start_notes(&ctx, notes, &expired_at_start);
    let code = rt.block_on(serve(
        Arc::clone(&ctx),
        daemon_cfg.socket_dir.clone(),
        check,
        policy_err,
        loaded_files,
        more,
        tcp,
    ));
    rt.shutdown_timeout(Duration::from_secs(1));
    drop(ctx);
    let _ = join.join();
    Ok(code)
}

/// Give the audit dir to `saiife-audit` when that group exists, warning on
/// stderr (the journal) when that fails. Called at start and at every
/// reload: systemd's `LogsDirectory=` hands the dir (recursively) back to
/// the unit's `Group=saiife` before every command it spawns for the unit,
/// `ExecReload=` (`/bin/kill -HUP`) included, not only before `ExecStart=`.
/// `None` when there is no such group.
fn regroup_audit_dir(dir: &Path, directory: &dyn saiife_policy::Directory) -> Option<u32> {
    let g = directory.group(AUDIT_GROUP)?;
    match adopt_audit_group(dir, g.gid) {
        Ok(n) => Some(n),
        Err(e) => {
            eprintln!(
                "saiife: warning: cannot give {} to group {AUDIT_GROUP}: {e}",
                dir.display()
            );
            None
        }
    }
}

/// Give the audit dir and every regular `*.jsonl` in it to group `gid`
/// when the dir is in another group; the owner stays, and nothing is
/// followed through a symlink. Returns how many month files were changed.
///
/// systemd's `LogsDirectory=` gives the dir to the unit's `Group=saiife`
/// before every command it spawns for the unit (start and reload), and
/// §5.2 wants it in `saiife-audit` (readers of the log).
fn adopt_audit_group(dir: &Path, gid: u32) -> std::io::Result<u32> {
    use rustix::fs::{AtFlags, Gid, Mode, OFlags};
    use std::os::unix::fs::MetadataExt;
    let fd = rustix::fs::open(
        dir,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let fd = std::fs::File::from(fd);
    if fd.metadata()?.gid() == gid {
        return Ok(0);
    }
    let group = Some(Gid::from_raw(gid));
    rustix::fs::fchown(&fd, None, group)?;
    let mut changed = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        // `file_type` of a directory entry does not follow a symlink.
        if !entry.file_type()?.is_file() || !name.to_string_lossy().ends_with(".jsonl") {
            continue;
        }
        rustix::fs::chownat(&fd, &name, None, group, AtFlags::SYMLINK_NOFOLLOW)?;
        changed += 1;
    }
    Ok(changed)
}

/// Who must own `<config dir>/ca` and its files: root. A debug build (the
/// test suite) honours `SAIIFE_TEST_CA_OWNER=<uid>`, so tests running as a
/// normal user can use the directory; a release build has no such seam.
fn trusted_owner() -> u32 {
    #[cfg(debug_assertions)]
    if let Some(uid) = std::env::var("SAIIFE_TEST_CA_OWNER")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return uid;
    }
    0
}

/// The checks `load_local_with` makes on local manifests, for the CA
/// directory: owned by `owner`, not writable by group or others, no
/// symlinks, and every `*.pem` a regular file with the same owner and mode
/// rules. A missing directory is fine (no extra CAs).
fn check_ca_dir(dir: &Path, owner: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let err = |p: &Path, why: &str| format!("{}: {why}", p.display());
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(err(dir, &e.to_string())),
    };
    if !meta.is_dir() {
        return Err(err(dir, "not a directory (symlinks are not followed)"));
    }
    if meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return Err(err(dir, "must be owned by root and not writable by others"));
    }
    for e in std::fs::read_dir(dir).map_err(|e| err(dir, &e.to_string()))? {
        let e = e.map_err(|e| err(dir, &e.to_string()))?;
        let p = e.path();
        if p.extension().is_none_or(|x| x != "pem") {
            continue;
        }
        let m = std::fs::symlink_metadata(&p).map_err(|e| err(&p, &e.to_string()))?;
        if !m.file_type().is_file() {
            return Err(err(&p, "not a regular file (symlinks are not followed)"));
        }
        if m.uid() != owner || m.mode() & 0o022 != 0 {
            return Err(err(&p, "must be owned by root and not writable by others"));
        }
    }
    Ok(())
}

/// The limiter from the connector records of the last 24 h (the two newest
/// month files cover a month boundary).
fn rebuild_limiter(audit_dir: &Path) -> (Limiter, Option<RebuildFailed>) {
    rebuild_limiter_at(audit_dir, time::OffsetDateTime::now_utc())
}

/// What kept the limiter rebuild from reading every record of the window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RebuildFailed {
    dir_error: Option<String>,
    unreadable_files: usize,
    skipped_lines: usize,
}

impl RebuildFailed {
    /// A directory or a month file could not be read: whole stretches of
    /// the window may be missing, so the limits fail closed. Skipped lines
    /// alone (a torn line from a crash stays in the log for good) are only
    /// a warning: failing closed on them would deny every connector call
    /// for 24 h after each start.
    fn fatal(&self) -> bool {
        self.dir_error.is_some() || self.unreadable_files > 0
    }

    /// The `limits_rebuild_failed` record's reason and fields.
    fn note(&self) -> (String, serde_json::Map<String, Value>) {
        let reason = if self.fatal() {
            format!(
                "the connector limits could not be rebuilt from the audit log ({}{} unreadable file(s), {} skipped line(s)); connector calls are denied with limits_unavailable for 24 h or until a clean start",
                self.dir_error
                    .as_deref()
                    .map(|e| format!("directory: {e}; "))
                    .unwrap_or_default(),
                self.unreadable_files,
                self.skipped_lines
            )
        } else {
            format!(
                "the connector limits were rebuilt from the audit log with {} unreadable line(s) skipped; a call recorded on such a line is not counted (connector calls are not denied)",
                self.skipped_lines
            )
        };
        let mut m = serde_json::Map::new();
        m.insert("fatal".into(), self.fatal().into());
        m.insert("dir_error".into(), json!(self.dir_error));
        m.insert("unreadable_files".into(), self.unreadable_files.into());
        m.insert("skipped_lines".into(), self.skipped_lines.into());
        (reason, m)
    }
}

/// [`rebuild_limiter`] at `now`. A record dated after `now` (a clock that
/// went back, or an edited log) is dropped: it would hold a slot for longer
/// than its window. A directory or month file that could not be read fails
/// closed ([`Limiter::rebuild_incomplete`]); skipped lines are reported but
/// do not deny ([`RebuildFailed::fatal`]).
fn rebuild_limiter_at(
    audit_dir: &Path,
    now: time::OffsetDateTime,
) -> (Limiter, Option<RebuildFailed>) {
    let cutoff = now - time::Duration::days(1);
    let read = saiife_audit::store::read_recent(audit_dir, 2, |r| {
        r.timestamp().is_none_or(|t| t > cutoff)
    });
    let events = read
        .records
        .iter()
        .filter_map(limit_event)
        .filter(|e| e.at <= now);
    if read.dir_error.is_none() && read.unreadable_files == 0 && read.skipped_lines == 0 {
        return (Limiter::rebuild(events, now), None);
    }
    let failed = RebuildFailed {
        dir_error: read.dir_error.clone(),
        unreadable_files: read.unreadable_files,
        skipped_lines: read.skipped_lines,
    };
    let limiter = if failed.fatal() {
        Limiter::rebuild_incomplete(events, now)
    } else {
        Limiter::rebuild(events, now)
    };
    (limiter, Some(failed))
}

fn files_json(l: &LoadedPolicy) -> Value {
    Value::Array(
        l.files
            .iter()
            .map(|(name, sha)| json!({"name": name, "sha256": sha}))
            .collect(),
    )
}

/// `policy` record: `result` `loaded` (with `files`) or `rejected` (with
/// `reason`).
fn policy_record(
    ctx: &Ctx,
    result: &str,
    files: Option<Value>,
    reason: Option<String>,
) -> saiife_audit::Record {
    let mut r = ctx.record("policy", result);
    r.extra.insert("result".into(), result.into());
    if let Some(f) = files {
        r.extra.insert("files".into(), f);
    }
    r.reason = reason;
    r
}

/// Refuse a socket dir others could write to or that is not this user's
/// (or root's): the client trusts whatever socket is in it.
fn check_socket_dir(st: &rustix::fs::Stat, dir: &Path, uid: u32) -> Result<(), String> {
    if st.st_mode & 0o170000 != 0o040000 {
        return Err(format!("{}: not a directory", dir.display()));
    }
    if st.st_uid != uid && st.st_uid != 0 {
        return Err(format!(
            "{}: owned by uid {}, expected the daemon user (uid {uid}) or root",
            dir.display(),
            st.st_uid
        ));
    }
    if st.st_mode & 0o022 != 0 {
        return Err(format!("{}: writable by group or others", dir.display()));
    }
    Ok(())
}

/// The socket dir (created 0755 when missing; an existing one must be
/// this user's or root's and not group/other-writable) and a fresh socket
/// `name` in it (`saiife.sock`, `gateway.sock`), 0666. A stale socket is
/// removed only when it is a socket of this uid that nobody answers on;
/// anything else there is left alone. The dir is held open (`O_NOFOLLOW`)
/// and every later step works relative to it, without following a symlink
/// at `name`.
fn bind(socket_dir: &Path, name: &str, uid: u32) -> Result<(UnixListener, PathBuf), String> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    let at = |e: &dyn std::fmt::Display| format!("{}: {e}", socket_dir.display());
    match std::fs::symlink_metadata(socket_dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = socket_dir.parent() {
                std::fs::create_dir_all(parent).map_err(|e| at(&e))?;
            }
            std::fs::create_dir(socket_dir)
                .and_then(|()| {
                    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o755))
                })
                .map_err(|e| at(&e))?;
        }
        Err(e) => return Err(at(&e)),
    }
    let dirfd = rustix::fs::open(
        socket_dir,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| at(&e))?;
    check_socket_dir(
        &rustix::fs::fstat(&dirfd).map_err(|e| at(&e))?,
        socket_dir,
        uid,
    )?;

    let path = socket_dir.join(name);
    let at_sock = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    match rustix::fs::statat(&dirfd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if st.st_mode & 0o170000 == 0o140000 && st.st_uid == uid => {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Err(format!("another daemon is listening on {}", path.display()));
            }
            rustix::fs::unlinkat(&dirfd, name, AtFlags::empty()).map_err(|e| at_sock(&e))?;
        }
        Ok(_) => {
            return Err(format!(
                "{} exists and is not a socket of this daemon user; not removing it",
                path.display()
            ))
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(e) => return Err(at_sock(&e)),
    }
    let l = UnixListener::bind(&path).map_err(|e| at_sock(&e))?;
    chmod_socket(&dirfd, name, uid).map_err(|e| at_sock(&e))?;
    Ok((l, path))
}

/// `chmod 0666` on the socket just bound, never through a symlink: an
/// `O_PATH | O_NOFOLLOW` handle is checked to be this uid's socket and
/// changed through `/proc/self/fd`. Without `/proc`, `fchmodat` on the
/// checked name in the held dir, which only this uid or root can change.
fn chmod_socket(dirfd: &rustix::fd::OwnedFd, name: &str, uid: u32) -> std::io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::os::fd::AsRawFd;
    let mode = Mode::from_raw_mode(0o666);
    let fd = rustix::fs::openat(
        dirfd,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let st = rustix::fs::fstat(&fd)?;
    if st.st_mode & 0o170000 != 0o140000 || st.st_uid != uid {
        return Err(std::io::Error::other("not the socket this daemon bound"));
    }
    match rustix::fs::chmod(format!("/proc/self/fd/{}", fd.as_raw_fd()), mode) {
        Ok(()) => Ok(()),
        Err(_) => {
            let st = rustix::fs::statat(dirfd, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if st.st_mode & 0o170000 != 0o140000 || st.st_uid != uid {
                return Err(std::io::Error::other("not the socket this daemon bound"));
            }
            Ok(rustix::fs::chmodat(dirfd, name, mode, AtFlags::empty())?)
        }
    }
}

/// A periodic blocking job that runs at most once at a time.
#[derive(Default)]
struct OneAtATime {
    running: Option<tokio::task::JoinHandle<()>>,
}

impl OneAtATime {
    /// Start `job` on a blocking thread unless the previous one is still
    /// running (then `false`, and `job` is dropped). A finished previous
    /// job is awaited first (it is done: this does not wait).
    async fn start(&mut self, job: impl FnOnce() + Send + 'static) -> bool {
        if let Some(h) = self.running.take() {
            if !h.is_finished() {
                self.running = Some(h);
                return false;
            }
            if let Err(e) = h.await {
                eprintln!("saiife: warning: a background job failed: {e}");
            }
        }
        self.running = Some(tokio::task::spawn_blocking(job));
        true
    }
}

/// The start records after the vault's: one `daemon` record per note
/// `(event, reason, fields)` (`ca_refused`, `tokens_reset`,
/// `limits_rebuild_failed`, `limits_rebuild_capped`), then one
/// `approval`/`expired` record per request the start sweep expired.
fn start_notes(
    ctx: &Ctx,
    notes: Vec<(&'static str, String, serde_json::Map<String, Value>)>,
    expired: &[crate::approvals::Request],
) -> Vec<saiife_audit::Record> {
    let mut out = Vec::new();
    for (event, reason, fields) in notes {
        let mut r = ctx.event(event);
        r.reason = Some(reason);
        r.extra.extend(fields);
        out.push(r);
    }
    for r in expired {
        out.push(ctx.approval_record(r, "expired"));
    }
    out
}

async fn serve(
    ctx: Arc<Ctx>,
    socket_dir: PathBuf,
    check: saiife_audit::StartupCheck,
    policy_err: Option<String>,
    loaded_files: Option<Value>,
    // More start records, after the vault's ([`start_notes`]).
    more: Vec<saiife_audit::Record>,
    tcp: Option<std::net::SocketAddr>,
) -> ExitCode {
    let signals = (
        signal(SignalKind::hangup()),
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    );
    let (Ok(mut hup), Ok(mut term), Ok(mut int)) = signals else {
        eprintln!("saiife: cannot install signal handlers");
        return ExitCode::from(2);
    };

    // 6. The start records. The startup check is a bounded spot check that
    // trusts the line before its window: a warning and a field, not proof.
    let chain_check = match &check.recent {
        Ok(()) => "ok".to_string(),
        Err(d) => {
            eprintln!(
                "saiife: warning: audit chain check at start: {d}; continuing from the end of the log"
            );
            format!("broken: {d}")
        }
    };
    let mut start = ctx.event("start");
    start
        .extra
        .insert("previous_clean_stop".into(), check.last_clean_stop.into());
    start.extra.insert("chain_check".into(), chain_check.into());
    let mut first = vec![start];
    match policy_err {
        Some(reason) => {
            let mut r = ctx.event("policy_invalid");
            r.reason = Some(reason);
            first.push(r);
        }
        None => first.push(policy_record(&ctx, "loaded", loaded_files, None)),
    }
    if let VaultState::Unavailable(reason) = &*ctx.vault.lock() {
        eprintln!("saiife: warning: vault unavailable: {reason}");
        let mut r = ctx.event("vault_unavailable");
        r.reason = Some(reason.clone());
        first.push(r);
    }
    first.extend(more);
    for r in first {
        if let Err(e) = ctx.writer.append(r).await {
            eprintln!("saiife: cannot write to the audit log: {e}");
            let _ = ctx.writer.stop(None).await;
            return ExitCode::from(2);
        }
    }

    // 7. The sockets: control and the HTTP gateway (§8.8), side by side.
    let (listener, sock_path) = match bind(&socket_dir, SOCKET_NAME, ctx.own_uid) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("saiife: {e}");
            let _ = ctx.writer.stop(None).await;
            return ExitCode::from(2);
        }
    };
    let (gw_listener, gw_path) = match bind(&socket_dir, GATEWAY_SOCKET_NAME, ctx.own_uid) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("saiife: {e}");
            drop(listener);
            let _ = std::fs::remove_file(&sock_path);
            let _ = ctx.writer.stop(None).await;
            return ExitCode::from(2);
        }
    };
    let gateway = tokio::spawn(gateway::serve(gw_listener, Arc::clone(&ctx)));
    // The optional loopback TCP listener: a bind failure is a record and
    // no listener; the Unix sockets stay.
    let gateway_tcp = match tcp {
        Some(addr) => start_tcp(&ctx, addr).await,
        None => None,
    };

    // The notification delivery task; it holds only a weak reference.
    let _notifier = ctx.notifier.start(Arc::downgrade(&ctx));

    // 8. Ready.
    notify::ready();
    let mut writer_died = false;
    // `last_used` marks reach the vault file from here, on a blocking
    // thread, never from a connector request on the runtime thread.
    let mut vault_tick = tokio::time::interval(Duration::from_secs(60));
    vault_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut vault_flush = OneAtATime::default();
    let day = Duration::from_secs(24 * 3600);
    let mut purge_tick = tokio::time::interval_at(tokio::time::Instant::now() + day, day);
    let hour = Duration::from_secs(3600);
    let mut token_tick = tokio::time::interval_at(tokio::time::Instant::now() + hour, hour);
    let sweep_every = crate::approvals::SWEEP_EVERY;
    let mut sweep_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + sweep_every, sweep_every);
    sweep_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut sweep = OneAtATime::default();
    loop {
        tokio::select! {
            _ = vault_tick.tick() => {
                let c = Arc::clone(&ctx);
                // The file is written outside the vault's memory lock: a
                // connector call reading the vault never waits on it. One
                // flush at a time: on a hung disk the ticks are skipped
                // instead of piling up blocked threads.
                let started = vault_flush.start(move || {
                    if let Err(e) = c.vault.writer().flush_if_due(std::time::Instant::now()) {
                        eprintln!("saiife: warning: cannot write the vault's last_used marks: {e}");
                    }
                }).await;
                if !started {
                    eprintln!("saiife: warning: the vault's last flush is still running; skipping this one");
                }
            }
            _ = purge_tick.tick() => {
                let dir = ctx.backup_dir.clone();
                tokio::task::spawn_blocking(move || {
                    crate::import_backup::purge(&dir, crate::import_backup::now())
                });
            }
            _ = sweep_tick.tick() => {
                if ctx.approvals.is_ok() {
                    let c = Arc::clone(&ctx);
                    let rt = tokio::runtime::Handle::current();
                    // One sweep at a time, off the runtime thread; what it
                    // expired gets its `approval`/`expired` records back on
                    // the runtime.
                    sweep.start(move || {
                        if let Ok(store) = &c.approvals {
                            let gone = store.sweep(crate::import_backup::now());
                            if !gone.is_empty() {
                                rt.spawn(async move { c.record_expired(gone).await });
                            }
                        }
                    }).await;
                }
            }
            _ = token_tick.tick() => {
                let t = Arc::clone(&ctx.tokens);
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = t.purge() {
                        eprintln!("saiife: warning: cannot write the gateway tokens: {e}");
                    }
                });
            }
            r = listener.accept() => match r {
                Ok((s, _)) => {
                    tokio::spawn(server::connection(s, Arc::clone(&ctx)));
                }
                Err(e) => {
                    // EMFILE and friends: back off instead of spinning.
                    eprintln!("saiife: warning: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            _ = hup.recv() => reload(&ctx).await,
            // Outside a stop the writer never ends on its own: without it
            // every append fails, so exit and let the service manager
            // restart the daemon.
            _ = ctx.writer.exited() => {
                writer_died = true;
                break;
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }

    // No new connections; connector calls in flight (which a client that
    // went away no longer holds) finish and are recorded first, for at
    // most the upstream timeout.
    drop(listener);
    let _ = std::fs::remove_file(&sock_path);
    gateway.abort();
    let _ = gateway.await;
    if let Some(t) = gateway_tcp {
        t.abort();
        let _ = t.await;
    }
    let _ = std::fs::remove_file(&gw_path);
    if !writer_died {
        let limit = ctx
            .upstream
            .as_ref()
            .map(|u| u.timeout())
            .unwrap_or(Duration::from_secs(30));
        if !ctx.calls.wait_idle(limit).await {
            eprintln!(
                "saiife: warning: {} connector call(s) still in flight at stop",
                ctx.calls.count()
            );
        }
    }
    // Pending `last_used` marks go to disk before the stop record.
    let c = Arc::clone(&ctx);
    if let Ok(Err(e)) = tokio::task::spawn_blocking(move || c.vault.writer().flush()).await {
        eprintln!("saiife: warning: cannot write the vault at stop: {e}");
    }
    // Stop: the stop record and a checkpoint, synced.
    if writer_died {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr(),
            "saiife: the audit writer stopped unexpectedly; exiting so the daemon is restarted"
        );
        return ExitCode::from(1);
    }
    match ctx.writer.stop(Some(ctx.event("stop"))).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("saiife: stop: {e}");
            ExitCode::from(1)
        }
    }
}

/// Bind `addr` (loopback, checked at load) and serve the gateway on it.
/// The bound address (the real port for `:0`) goes into `status` and a
/// `gateway_tcp` record; a failure is a `gateway_tcp_failed` record.
async fn start_tcp(
    ctx: &Arc<Ctx>,
    addr: std::net::SocketAddr,
) -> Option<tokio::task::JoinHandle<()>> {
    let bound = tokio::net::TcpListener::bind(addr)
        .await
        .and_then(|l| l.local_addr().map(|a| (l, a)));
    let (rec, task) = match bound {
        Ok((l, a)) => {
            ctx.tcp.lock().unwrap_or_else(|p| p.into_inner()).bound = Some(a);
            let mut r = ctx.event("gateway_tcp");
            r.extra.insert("addr".into(), a.to_string().into());
            let task = tokio::spawn(gateway::serve_tcp(
                l,
                Arc::clone(ctx),
                gateway::Opts::default(),
            ));
            (r, Some(task))
        }
        Err(e) => {
            let reason = format!("cannot listen on {addr}: {e}");
            eprintln!("saiife: warning: gateway tcp: {reason}");
            let mut r = ctx.event("gateway_tcp_failed");
            r.reason = Some(reason);
            (r, None)
        }
    };
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiife: warning: cannot write the gateway_tcp record: {e}");
    }
    task
}

/// SIGHUP: load and check the policy again. A valid one replaces the old in
/// one step; an invalid one is refused and the old one stays. First the
/// audit dir goes back to `saiife-audit`: the `ExecReload=` command that
/// sent the signal was spawned with `LogsDirectory=`, which gave the dir
/// back to `saiife`.
async fn reload(ctx: &Arc<Ctx>) {
    let c = Arc::clone(ctx);
    let loaded = tokio::task::spawn_blocking(move || {
        regroup_audit_dir(&c.audit_dir, c.directory.as_ref());
        load_and_check(&c.config_path, c.directory.as_ref())
            .map_err(|e| e.to_string())
            .and_then(|l| check_services(&l, &c.config_path).map(|cat| (l, cat)))
    })
    .await
    .unwrap_or_else(|e| Err(format!("reload failed: {e}")));
    let mut recs = Vec::new();
    match loaded {
        Ok((l, cat)) => {
            let next = PolicyState::from_loaded(&l, &ctx.catalog, cat);
            *ctx.policy.lock().unwrap_or_else(|p| p.into_inner()) = next;
            recs.push(policy_record(ctx, "loaded", Some(files_json(&l)), None));
            let changed = restart_only_changes(ctx, &l);
            if !changed.is_empty() {
                let reason = format!(
                    "{}; these take effect only at a restart, the daemon keeps running as started",
                    changed.join("; ")
                );
                eprintln!("saiife: warning: {reason}");
                let mut w = ctx.event("reload_warning");
                w.reason = Some(reason);
                recs.push(w);
            }
        }
        Err(reason) => {
            eprintln!("saiife: warning: policy reload refused, keeping the old policy: {reason}");
            recs.push(policy_record(ctx, "rejected", None, Some(reason)));
        }
    }
    for rec in recs {
        if let Err(e) = ctx.writer.append(rec).await {
            eprintln!("saiife: warning: cannot write the policy record: {e}");
        }
    }
}

/// Settings a reload cannot apply: what the daemon would refuse to start
/// with, or paths it opened at start.
fn restart_only_changes(ctx: &Ctx, l: &LoadedPolicy) -> Vec<String> {
    let c = &l.config;
    let mut out = Vec::new();
    if !c.locked {
        out.push("the reloaded config lacks locked = true".to_string());
    }
    if c.daemon.user != ctx.own_user {
        out.push(format!(
            "[daemon] user changed from {} to {}",
            ctx.own_user, c.daemon.user
        ));
    }
    if c.daemon.socket_dir != ctx.socket_dir {
        out.push("[daemon] socket_dir changed".to_string());
    }
    if c.gateway.tcp != ctx.tcp.lock().unwrap_or_else(|p| p.into_inner()).configured {
        out.push("[gateway] tcp changed".to_string());
    }
    if c.audit.dir != ctx.audit_dir {
        out.push("[audit] dir changed".to_string());
    }
    let w = &ctx.writer_cfg;
    if c.audit.checkpoint_every != w.checkpoint_every {
        out.push("[audit] checkpoint_every changed".to_string());
    }
    if c.audit.checkpoint_interval != w.checkpoint_interval {
        out.push("[audit] checkpoint_interval changed".to_string());
    }
    if c.audit.fsync != w.fsync {
        out.push("[audit] fsync changed".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// The start and reload helper: no `saiife-audit` group, nothing to do;
    /// a group the dir is already in, nothing changed; a dir that cannot be
    /// regrouped (missing) is a warning, not a stop.
    #[test]
    fn regroup_audit_dir_looks_up_the_group() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("audit");
        std::fs::create_dir(&dir).unwrap();
        let primary = rustix::process::getgid().as_raw();
        rustix::fs::chown(&dir, None, Some(rustix::fs::Gid::from_raw(primary))).unwrap();
        let none = saiife_policy::FixedDirectory::from_text("", "");
        assert_eq!(regroup_audit_dir(&dir, &none), None);
        let with = saiife_policy::FixedDirectory::from_text(
            "",
            &format!("{AUDIT_GROUP}:x:{primary}:saiife\n"),
        );
        assert_eq!(regroup_audit_dir(&dir, &with), Some(0));
        assert_eq!(regroup_audit_dir(&d.path().join("missing"), &with), None);
    }

    fn connector_rec(at: time::OffsetDateTime) -> saiife_audit::Record {
        let mut r = saiife_audit::Record::at(
            saiife_audit::NewRecord {
                agent: "",
                project: "",
                session: None,
                tool: "api",
                input: "erp invoices.list",
                decision: saiife_audit::DecisionKind::Allow,
                pack: None,
                rule: None,
                reason: None,
                mode: "locked",
                policy: None,
                permission_mode: None,
            },
            "test",
            at,
        );
        r.kind = Some("connector".into());
        r.uid = Some(1001);
        r.extra.insert("service".into(), "erp".into());
        r.extra.insert("op_kind".into(), "read".into());
        r
    }

    fn one_per_minute_hit(lim: &Limiter, now: time::OffsetDateTime) -> bool {
        let k = saiife_broker::limits::Key {
            uid: 1001,
            service: "erp".into(),
            session: None,
        };
        let cfg = saiife_policy::LimitsCfg {
            requests_per_minute: Some(1),
            ..Default::default()
        };
        lim.check_and_commit(
            &k,
            saiife_broker::manifest::OpKind::Read,
            None,
            false,
            &cfg,
            now,
        )
        .is_err()
    }

    #[test]
    fn rebuild_counts_recent_records_and_drops_future_ones() {
        let d = tempfile::tempdir().unwrap();
        let now = time::OffsetDateTime::now_utc();
        // A record from the future (clock went back) is not a slot.
        saiife_audit::store::append(d.path(), &connector_rec(now + time::Duration::minutes(5)))
            .unwrap();
        assert!(!one_per_minute_hit(
            &rebuild_limiter_at(d.path(), now).0,
            now
        ));
        // A record 10 s old is.
        saiife_audit::store::append(d.path(), &connector_rec(now - time::Duration::seconds(10)))
            .unwrap();
        let (lim, failed) = rebuild_limiter_at(d.path(), now);
        assert!(one_per_minute_hit(&lim, now));
        assert_eq!(failed, None);
        assert!(!lim.unavailable(now));
    }

    #[tokio::test]
    async fn one_at_a_time_skips_while_the_last_job_runs() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut one = OneAtATime::default();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let runs = Arc::new(AtomicUsize::new(0));
        let r = Arc::clone(&runs);
        assert!(
            one.start(move || {
                r.fetch_add(1, Ordering::SeqCst);
                let _ = wait.recv();
            })
            .await
        );
        // A hung job: the next ticks start nothing.
        for _ in 0..3 {
            let r = Arc::clone(&runs);
            let started = one
                .start(move || {
                    r.fetch_add(1, Ordering::SeqCst);
                })
                .await;
            assert!(!started);
        }
        release.send(()).unwrap();
        let end = std::time::Instant::now() + Duration::from_secs(10);
        while !one.running.as_ref().unwrap().is_finished() {
            assert!(std::time::Instant::now() < end, "the job never ended");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Done: the next tick runs again.
        let r = Arc::clone(&runs);
        assert!(
            one.start(move || {
                r.fetch_add(1, Ordering::SeqCst);
            })
            .await
        );
        one.running.take().unwrap().await.unwrap();
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn rebuild_with_skipped_lines_warns_but_allows() {
        use std::io::Write;
        let d = tempfile::tempdir().unwrap();
        let now = time::OffsetDateTime::now_utc();
        saiife_audit::store::append(d.path(), &connector_rec(now - time::Duration::seconds(10)))
            .unwrap();
        // A line that is not a record: the window may hide a call.
        let month = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&month)
            .unwrap();
        // A torn middle line (a crash mid-write, terminated at the next
        // open), then a record after it.
        f.write_all(b"{not a record\n").unwrap();
        drop(f);
        saiife_audit::store::append(d.path(), &connector_rec(now - time::Duration::seconds(5)))
            .unwrap();
        let (lim, failed) = rebuild_limiter_at(d.path(), now);
        let failed = failed.expect("the rebuild must report the skipped line");
        assert_eq!(failed.skipped_lines, 1);
        assert_eq!(failed.unreadable_files, 0);
        assert!(!failed.fatal());
        let (reason, fields) = failed.note();
        assert!(!reason.contains("denied with"), "{reason}");
        assert_eq!(fields["fatal"], false);
        assert_eq!(fields["skipped_lines"], 1);
        // Not denied, and the readable records still count.
        assert!(!lim.unavailable(now));
        assert!(one_per_minute_hit(&lim, now));
    }

    #[test]
    fn rebuild_from_an_unreadable_log_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let now = time::OffsetDateTime::now_utc();
        saiife_audit::store::append(d.path(), &connector_rec(now - time::Duration::seconds(10)))
            .unwrap();
        let month = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .unwrap();
        // A month file that cannot be opened: the window may hide calls.
        std::fs::set_permissions(&month, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::File::open(&month).is_err();
        let (lim, failed) = rebuild_limiter_at(d.path(), now);
        std::fs::set_permissions(&month, std::fs::Permissions::from_mode(0o600)).unwrap();
        // (As root every file opens: nothing to check there.)
        if unreadable {
            let failed = failed.expect("the rebuild must report the unreadable file");
            assert_eq!(failed.unreadable_files, 1);
            assert!(failed.fatal());
            let (reason, fields) = failed.note();
            assert!(reason.contains("limits_unavailable"), "{reason}");
            assert_eq!(fields["fatal"], true);
            assert_eq!(fields["unreadable_files"], 1);
            // Denied for a full window, then known again.
            assert!(lim.unavailable(now));
            assert!(lim.unavailable(now + time::Duration::hours(23)));
            assert!(!lim.unavailable(now + time::Duration::hours(24)));
        }
        // An audit dir that cannot be listed fails closed too.
        let file = d.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let (lim, failed) = rebuild_limiter_at(&file, now);
        let failed = failed.unwrap();
        assert!(failed.dir_error.is_some());
        assert!(failed.fatal());
        assert!(lim.unavailable(now));
    }

    #[test]
    fn ca_dir_must_be_the_owners_and_hold_no_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let me = rustix::process::getuid().as_raw();
        let dir = d.path().join("ca");
        // Missing: no extra CAs, fine.
        check_ca_dir(&dir, me).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pem = dir.join("a.pem");
        std::fs::write(&pem, "x").unwrap();
        std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o644)).unwrap();
        check_ca_dir(&dir, me).unwrap();
        // Not root's (the production owner).
        assert!(check_ca_dir(&dir, 0).unwrap_err().contains("owned by root"));
        // A group-writable file.
        std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(check_ca_dir(&dir, me).is_err());
        std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o644)).unwrap();
        // A symlinked pem.
        std::os::unix::fs::symlink(&pem, dir.join("b.pem")).unwrap();
        assert!(check_ca_dir(&dir, me).unwrap_err().contains("symlink"));
        std::fs::remove_file(dir.join("b.pem")).unwrap();
        // A world-writable dir; a symlinked dir.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_ca_dir(&dir, me).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = d.path().join("ca-link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(check_ca_dir(&link, me).is_err());
    }

    #[test]
    fn adopt_audit_group_changes_dir_and_files() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("audit");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("2026-10.jsonl"), b"{}\n").unwrap();
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();
        let primary = rustix::process::getgid().as_raw();
        let gid = |p: &Path| std::fs::symlink_metadata(p).unwrap().gid();
        // The dir is already in the group: nothing to do.
        rustix::fs::chown(&dir, None, Some(rustix::fs::Gid::from_raw(primary))).unwrap();
        assert_eq!(adopt_audit_group(&dir, primary).unwrap(), 0);
        // Another group this user is in, when there is one: the dir and its
        // month files move to it, nothing else does. (CI asserts the real
        // saiife-audit change as root, Task 8.)
        // In a user namespace (the offline CI job runs under `unshare
        // --map-current-user`) the supplementary groups are unmapped and
        // show as the overflow gid (nogroup); chown to them fails. Only a
        // group a scratch file can really be given is used.
        let overflow: Option<u32> = std::fs::read_to_string("/proc/sys/kernel/overflowgid")
            .ok()
            .and_then(|t| t.trim().parse().ok());
        let probe = d.path().join("probe");
        std::fs::write(&probe, b"").unwrap();
        let usable = |g: u32| {
            Some(g) != overflow
                && rustix::fs::chown(&probe, None, Some(rustix::fs::Gid::from_raw(g))).is_ok()
        };
        let other = rustix::process::getgroups()
            .unwrap()
            .into_iter()
            .map(|g| g.as_raw())
            .find(|&g| g != primary && usable(g));
        let Some(other) = other else {
            eprintln!(
                "skipped the regroup part: no supplementary group this user can chown to \
                 (none, or unmapped in a user namespace)"
            );
            return;
        };
        assert_eq!(adopt_audit_group(&dir, other).unwrap(), 1);
        assert_eq!(gid(&dir), other);
        assert_eq!(gid(&dir.join("2026-10.jsonl")), other);
        assert_eq!(gid(&dir.join("notes.txt")), primary);
        assert_eq!(adopt_audit_group(&dir, other).unwrap(), 0);
    }
}
