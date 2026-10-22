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
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
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
    let (handle, join) = writer::spawn(
        cw,
        WriterConfig {
            checkpoint_every: audit_cfg.checkpoint_every,
            checkpoint_interval: audit_cfg.checkpoint_interval,
            fsync: audit_cfg.fsync,
        },
        check.last_checkpoint,
    )
    .map_err(|e| format!("cannot start the audit writer: {e}"))?;

    let ctx = Arc::new(Ctx::new(CtxInit {
        writer: handle,
        directory,
        own_uid: euid,
        own_user: name,
        audit_dir: audit_cfg.dir.clone(),
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

/// The socket dir (created 0755 when missing) and a fresh `saiife.sock`,
/// 0666. A stale socket is removed only when it is a socket of this uid
/// that nobody answers on.
fn bind(socket_dir: &Path, uid: u32) -> Result<(UnixListener, PathBuf), String> {
    match std::fs::symlink_metadata(socket_dir) {
        Ok(m) if m.file_type().is_dir() => {}
        Ok(_) => return Err(format!("{}: not a directory", socket_dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(socket_dir)
                .and_then(|()| {
                    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o755))
                })
                .map_err(|e| format!("{}: {e}", socket_dir.display()))?;
        }
        Err(e) => return Err(format!("{}: {e}", socket_dir.display())),
    }
    let path = socket_dir.join(SOCKET_NAME);
    match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_socket() && m.uid() == uid => {
            if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Err(format!("another daemon is listening on {}", path.display()));
            }
            std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(_) => {
            return Err(format!(
                "{} exists and is not a socket of this daemon user; not removing it",
                path.display()
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let l = UnixListener::bind(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((l, path))
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
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }

    // Stop: no new connections, the stop record and a checkpoint, synced.
    drop(listener);
    let _ = std::fs::remove_file(&sock_path);
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
    let rec = match loaded {
        Ok(l) => {
            let next = PolicyState::from_loaded(&l, &ctx.catalog);
            *ctx.policy.lock().unwrap_or_else(|p| p.into_inner()) = next;
            policy_record(ctx, "loaded", Some(files_json(&l)), None)
        }
        Err(reason) => {
            eprintln!("saiife: warning: policy reload refused, keeping the old policy: {reason}");
            policy_record(ctx, "rejected", None, Some(reason))
        }
    };
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiife: warning: cannot write the policy record: {e}");
    }
}
