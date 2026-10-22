//! Startup, the serve loop, reload and stop (spec §6.2).

use crate::ops::{Ctx, CtxInit, PolicyState, MODE, VERSION};
use crate::writer::{self, pending_key_path, WriterConfig};
use crate::{notify, server, DaemonOptions};
use saiife_audit::sign::AuditKey;
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_ipc::msg::SOCKET_NAME;
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
    let loaded = load_and_check(&opts.config, directory.as_ref());
    let (daemon_cfg, audit_cfg, policy, policy_err) = match &loaded {
        Ok(l) => (
            l.config.daemon.clone(),
            l.config.audit.clone(),
            PolicyState::from_loaded(l, &opts.catalog),
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
                },
                Some(e.to_string()),
            )
        }
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
    let check = cw.startup_check(STARTUP_CHECK_RECORDS);
    let writer_cfg = WriterConfig {
        checkpoint_every: audit_cfg.checkpoint_every,
        checkpoint_interval: audit_cfg.checkpoint_interval,
        fsync: audit_cfg.fsync,
    };
    let (handle, join) = writer::spawn(cw, writer_cfg, check.last_checkpoint)
        .map_err(|e| format!("cannot start the audit writer: {e}"))?;

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
    }));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the runtime: {e}"))?;
    let loaded_files = loaded.as_ref().ok().map(files_json);
    let code = rt.block_on(serve(
        Arc::clone(&ctx),
        daemon_cfg.socket_dir.clone(),
        check,
        policy_err,
        loaded_files,
    ));
    rt.shutdown_timeout(Duration::from_secs(1));
    drop(ctx);
    let _ = join.join();
    Ok(code)
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
/// this user's or root's and not group/other-writable) and a fresh
/// `saiife.sock`, 0666. A stale socket is removed only when it is a socket
/// of this uid that nobody answers on; anything else there is left alone.
/// The dir is held open (`O_NOFOLLOW`) and every later step works relative
/// to it, without following a symlink at `saiife.sock`.
fn bind(socket_dir: &Path, uid: u32) -> Result<(UnixListener, PathBuf), String> {
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

    let path = socket_dir.join(SOCKET_NAME);
    let at_sock = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    match rustix::fs::statat(&dirfd, SOCKET_NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) if st.st_mode & 0o170000 == 0o140000 && st.st_uid == uid => {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Err(format!("another daemon is listening on {}", path.display()));
            }
            rustix::fs::unlinkat(&dirfd, SOCKET_NAME, AtFlags::empty()).map_err(|e| at_sock(&e))?;
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
    chmod_socket(&dirfd, uid).map_err(|e| at_sock(&e))?;
    Ok((l, path))
}

/// `chmod 0666` on the socket just bound, never through a symlink: an
/// `O_PATH | O_NOFOLLOW` handle is checked to be this uid's socket and
/// changed through `/proc/self/fd`. Without `/proc`, `fchmodat` on the
/// checked name in the held dir, which only this uid or root can change.
fn chmod_socket(dirfd: &rustix::fd::OwnedFd, uid: u32) -> std::io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::os::fd::AsRawFd;
    let mode = Mode::from_raw_mode(0o666);
    let fd = rustix::fs::openat(
        dirfd,
        SOCKET_NAME,
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
            let st = rustix::fs::statat(dirfd, SOCKET_NAME, AtFlags::SYMLINK_NOFOLLOW)?;
            if st.st_mode & 0o170000 != 0o140000 || st.st_uid != uid {
                return Err(std::io::Error::other("not the socket this daemon bound"));
            }
            Ok(rustix::fs::chmodat(
                dirfd,
                SOCKET_NAME,
                mode,
                AtFlags::empty(),
            )?)
        }
    }
}

async fn serve(
    ctx: Arc<Ctx>,
    socket_dir: PathBuf,
    check: saiife_audit::StartupCheck,
    policy_err: Option<String>,
    loaded_files: Option<Value>,
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
    for r in first {
        if let Err(e) = ctx.writer.append(r).await {
            eprintln!("saiife: cannot write to the audit log: {e}");
            let _ = ctx.writer.stop(None).await;
            return ExitCode::from(2);
        }
    }

    // 7. The socket.
    let (listener, sock_path) = match bind(&socket_dir, ctx.own_uid) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("saiife: {e}");
            let _ = ctx.writer.stop(None).await;
            return ExitCode::from(2);
        }
    };

    // 8. Ready.
    notify::ready();
    let mut writer_died = false;
    loop {
        tokio::select! {
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

    // Stop: no new connections, the stop record and a checkpoint, synced.
    drop(listener);
    let _ = std::fs::remove_file(&sock_path);
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

/// SIGHUP: load and check the policy again. A valid one replaces the old in
/// one step; an invalid one is refused and the old one stays.
async fn reload(ctx: &Arc<Ctx>) {
    let c = Arc::clone(ctx);
    let loaded = tokio::task::spawn_blocking(move || {
        load_and_check(&c.config_path, c.directory.as_ref()).map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|e| Err(format!("reload failed: {e}")));
    let mut recs = Vec::new();
    match loaded {
        Ok(l) => {
            let next = PolicyState::from_loaded(&l, &ctx.catalog);
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
