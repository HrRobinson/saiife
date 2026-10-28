//! Startup, the serve loop, reload and stop (spec §6.2).

use crate::ops::{check_services_owned, Ctx, CtxInit, Mode, PolicyState, VERSION};
use crate::personal::{self, PersonalCfg};
use crate::tokens::{self, Tokens};
use crate::vault::{self, VaultState};
use crate::writer::{self, pending_key_path, WriterConfig};
use crate::{gateway, notify, server, DaemonMode, DaemonOptions};
use saiife_audit::sign::AuditKey;
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_broker::limits::Limiter;
use saiife_broker::pipeline::limit_event;
use saiife_broker::upstream::Upstream;
use saiife_broker::Catalog;
use saiife_ipc::msg::{GATEWAY_SOCKET_NAME, SOCKET_NAME};
use saiife_policy::PackInfo;
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
use saiife_system::layout::AUDIT_GROUP;

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

/// What only the personal broker has at start.
struct PersonalStart {
    cfg: PersonalCfg,
    /// The vault, read from the keychain before the runtime exists.
    vault: VaultState,
    /// The single-instance lock on the state dir, held until the end.
    lock: std::fs::File,
}

/// The lock file in the personal state dir that keeps a second broker of
/// the same user from starting (and from making a second vault key).
const PERSONAL_LOCK: &str = "broker.lock";

/// See [`crate::personal_preflight`].
pub(crate) fn personal_preflight(
    config: &Path,
    socket_dir: &Path,
    locked_marker: &Path,
) -> Result<(), String> {
    let euid = rustix::process::geteuid().as_raw();
    if euid == 0 {
        return Err("the personal broker runs as your own user, not root".into());
    }
    // Decision 10: a locked host wins.
    if std::fs::symlink_metadata(locked_marker).is_ok() {
        return Err(format!(
            "this host is in locked mode ({} exists): connectors go through the system daemon, not daemon --user",
            locked_marker.display()
        ));
    }
    let runtime = socket_dir
        .parent()
        .ok_or_else(|| format!("{}: no XDG_RUNTIME_DIR above it", socket_dir.display()))?;
    saiife_system::personal::check_runtime_dir(runtime, euid)?;
    if bootstrap(config).locked == Some(true) {
        return Err(format!(
            "{}: locked = true is a locked-mode config; the personal broker does not serve it",
            config.display()
        ));
    }
    Ok(())
}

/// A dir of the personal broker's own (state, audit): created 0700 when
/// missing; an existing one must be a real dir of this user that group
/// and others cannot use.
fn private_dir(dir: &Path, euid: u32) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let md = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !md.file_type().is_dir() {
        return Err(format!(
            "{}: not a directory (symlinks are not followed)",
            dir.display()
        ));
    }
    if md.uid() != euid {
        return Err(format!(
            "{}: owned by uid {}, not this user (uid {euid})",
            dir.display(),
            md.uid()
        ));
    }
    if md.mode() & 0o077 != 0 {
        return Err(format!(
            "{}: mode {:04o}, must be 0700; fix: chmod 700 {}",
            dir.display(),
            md.mode() & 0o7777,
            dir.display()
        ));
    }
    Ok(())
}

/// Take the personal broker's single-instance lock (`flock` on
/// `<state>/broker.lock`, never through a symlink). A lock another broker
/// holds refuses the start.
///
/// The lock is per state dir, not per user: two brokers started with
/// different `XDG_STATE_HOME` hold different locks but share the one
/// keychain item (`saiife`/`vault-key`). If both start with no key at once,
/// each may store its own and the last write wins; the other's vault is then
/// left under a key the keychain no longer holds. One broker per user is the
/// supported setup.
fn lock_state_dir(state_dir: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = state_dir.join(PERSONAL_LOCK);
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(f),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(format!(
            "another personal broker of this user is running (it holds {})",
            path.display()
        )),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The personal broker's start up to the vault (decision 11 and the
/// security order of Task 5): the refusals, the config, the state dir and
/// its lock, then the key from the keychain. The keychain is dropped here,
/// before any runtime exists.
#[allow(clippy::too_many_arguments)]
fn personal_start(
    config: &Path,
    state_dir: &Path,
    directory: &dyn saiife_policy::Directory,
    euid: u32,
    socket_dir: PathBuf,
    audit_dir: PathBuf,
    keychain: Box<dyn saiife_keychain::Keychain>,
    locked_marker: &Path,
) -> Result<PersonalStart, Refuse> {
    personal_preflight(config, &socket_dir, locked_marker)?;
    let own_user = directory
        .name_of(euid)
        .ok_or_else(|| format!("uid {euid} has no user name"))?;
    match personal::ensure_config(config) {
        Ok(true) => eprintln!("saiife: created {}", config.display()),
        Ok(false) => {}
        Err(e) => {
            let dir = config.parent().unwrap_or(Path::new("/"));
            let fix = if e.to_string().contains("mode 0700") {
                format!("; fix: chmod 700 {}", dir.display())
            } else {
                String::new()
            };
            return Err(format!("{}: {e}{fix}", config.display()).into());
        }
    }
    private_dir(state_dir, euid)?;
    // The lock before the keychain: two brokers starting at once must not
    // both find no key and each store a new one.
    let lock = lock_state_dir(state_dir)?;
    let vault = personal::open_vault(
        keychain.as_ref(),
        &state_dir.join("vault").join("vault.bin"),
    );
    // The Secret Service backend owns a runtime of its own: dropped here,
    // outside any runtime.
    drop(keychain);
    Ok(PersonalStart {
        cfg: PersonalCfg {
            own_user,
            own_uid: euid,
            socket_dir,
            audit_dir,
        },
        vault,
        lock,
    })
}

/// The one load path for start and reload: load and check the files, fit
/// them to personal mode (`personal`), check the `ask` rules and the
/// services, then the state in force.
pub(crate) fn load_policy(
    mode: Mode,
    config: &Path,
    dir: &dyn saiife_policy::Directory,
    catalog: &[PackInfo],
    personal: Option<&PersonalCfg>,
) -> Result<(LoadedPolicy, Catalog, PolicyState), String> {
    let mut l = load_and_check(config, dir).map_err(|e| e.to_string())?;
    let owner = match personal {
        Some(p) => {
            // A locked-mode config is never served by the personal broker:
            // refused at start, and a reload to one is rejected (the old
            // policy stays).
            if l.config.locked {
                return Err(format!(
                    "{}: locked = true is a locked-mode config; the personal broker does not serve it",
                    config.display()
                ));
            }
            let raw = read_bounded(config)
                .and_then(|s| s.parse::<toml::Table>().ok())
                .unwrap_or_default();
            for w in personal::apply(&mut l.config, &raw, p, dir) {
                eprintln!("saiife: warning: {w}");
            }
            p.own_uid
        }
        None => 0,
    };
    // Locked keeps main's order (services, then `[guard] ask`), so a
    // config with both errors reports the same one as before plan 16.
    let cat = if personal.is_none() {
        let cat = check_services_owned(&l, config, owner)?;
        check_ask(&l, catalog)?;
        cat
    } else {
        check_ask(&l, catalog)?;
        check_services_owned(&l, config, owner)?
    };
    let state = PolicyState::from_loaded_in(&l, catalog, cat.clone(), mode);
    Ok((l, cat, state))
}

/// The socket dir and socket modes: the locked daemon's dir is 0755 and
/// its sockets 0666 (the peer check decides); the personal broker's are
/// 0700 and 0600, owned by the user (root's is not accepted).
#[derive(Debug, Clone, Copy)]
struct SocketPerms {
    dir: u32,
    sock: u32,
    root_dir_ok: bool,
}

const SYSTEM_SOCKETS: SocketPerms = SocketPerms {
    dir: 0o755,
    sock: 0o666,
    root_dir_ok: true,
};
const PERSONAL_SOCKETS: SocketPerms = SocketPerms {
    dir: 0o700,
    sock: 0o600,
    root_dir_ok: false,
};

fn start(opts: DaemonOptions) -> Result<ExitCode, Refuse> {
    let DaemonOptions {
        config,
        state_dir,
        catalog,
        directory,
        credentials_dir,
        mode: daemon_mode,
    } = opts;
    // 1. Who and what may run.
    let euid = rustix::process::geteuid().as_raw();
    if euid == 0 {
        return Err(match daemon_mode {
            DaemonMode::System => "the daemon must run as the daemon user, not root",
            DaemonMode::Personal { .. } => "the personal broker runs as your own user, not root",
        }
        .into());
    }
    let boot = bootstrap(&config);
    let directory: Arc<dyn saiife_policy::Directory + Send + Sync> = Arc::from(directory);
    // 2. No core dumps (the signing key or the vault key is in memory).
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        eprintln!("saiife: warning: cannot turn off core dumps: {e}");
    }
    let (mode, personal) = match daemon_mode {
        DaemonMode::System => {
            let name = &boot.daemon.user;
            match directory.user(name) {
                Some(u) if u.uid == euid => {}
                Some(_) => {
                    return Err(format!(
                        "the daemon runs as {name} per [daemon] user, not uid {euid}"
                    )
                    .into())
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
                    config.display()
                )
                .into());
            }
            (Mode::Locked, None)
        }
        DaemonMode::Personal {
            socket_dir,
            audit_dir,
            keychain,
            locked_marker,
        } => (
            Mode::Personal,
            Some(personal_start(
                &config,
                &state_dir,
                directory.as_ref(),
                euid,
                socket_dir,
                audit_dir,
                keychain,
                &locked_marker,
            )?),
        ),
    };
    let pcfg = personal.as_ref().map(|p| p.cfg.clone());
    let name = match &pcfg {
        Some(p) => p.own_user.clone(),
        None => boot.daemon.user.clone(),
    };

    // 3. The policy; an invalid one still lets the daemon accept audit.
    // The services are checked against the connector catalog as part of
    // the policy: a broken one makes the whole policy invalid.
    let loaded = load_policy(mode, &config, directory.as_ref(), &catalog, pcfg.as_ref());
    let (mut daemon_cfg, mut audit_cfg, policy, policy_err) = match &loaded {
        Ok((l, _, state)) => (
            l.config.daemon.clone(),
            l.config.audit.clone(),
            state.clone(),
            None,
        ),
        Err(e) => {
            eprintln!("saiife: warning: policy not loaded, accepting audit only: {e}");
            (
                boot.daemon.clone(),
                boot.audit.clone(),
                PolicyState::invalid(boot.audit.min_free_mb),
                Some(e.clone()),
            )
        }
    };
    // The personal broker's paths are fixed (decision 2), whatever the
    // config says or whether it loaded.
    if let Some(p) = &pcfg {
        daemon_cfg.user = p.own_user.clone();
        daemon_cfg.socket_dir = p.socket_dir.clone();
        audit_cfg.dir = p.audit_dir.clone();
    }
    let gateway_cfg = match &loaded {
        Ok((l, _, _)) => l.config.gateway.clone(),
        Err(_) => saiife_policy::GatewayCfg::default(),
    };

    // 4. The signing key: none for the personal broker (§6.4.4: a key in
    // the user's own home proves nothing).
    let key_path = state_dir.join("keys").join("audit.ed25519");
    let key = match mode {
        Mode::Personal => None,
        Mode::Locked => {
            let (key, _created) = AuditKey::load_or_create(&key_path).map_err(|e| e.to_string())?;
            let pending = pending_key_path(&key_path);
            if std::fs::symlink_metadata(&pending).is_ok() {
                eprintln!(
                    "saiife: warning: {} is left from an interrupted key rotation; the key in {} stays in force",
                    pending.display(),
                    key_path.display()
                );
            }
            Some(key)
        }
    };

    // 5. The chain: one writer, checked at start.
    if mode == Mode::Personal {
        private_dir(&audit_cfg.dir, euid)?;
    }
    let cw = ChainWriter::open(
        &audit_cfg.dir,
        WriterOptions {
            mode: mode.as_str().into(),
            saiife: VERSION.into(),
            key,
        },
    )
    .map_err(|e| format!("{}: {e}", audit_cfg.dir.display()))?;
    if mode == Mode::Locked {
        regroup_audit_dir(&audit_cfg.dir, directory.as_ref());
    }
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
    let vault_path = state_dir.join("vault").join("vault.bin");
    let (vault, _personal_lock) = match personal {
        Some(p) => (p.vault, Some(p.lock)),
        None => (
            match &credentials_dir {
                Some(d) => vault::open(&d.join("vault-key"), &vault_path),
                None => VaultState::Unavailable("no vault key".into()),
            },
            None,
        ),
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
    let ca_dir = config.parent().unwrap_or(Path::new("/")).join("ca");
    let ca_refused = check_ca_dir(&ca_dir, crate::ops::trusted_owner_in(mode, euid)).err();
    if let Some(why) = &ca_refused {
        eprintln!("saiife: warning: extra CAs not used: {why}");
    }
    let ca = ca_refused.is_none().then_some(ca_dir.as_path());
    let upstream = Upstream::with_ca_dir(ca, gateway_cfg.upstream_timeout).map_err(|e| {
        eprintln!("saiife: warning: connector calls will fail: {e}");
        e.to_string()
    });
    // Import backups older than 7 days go at start (and daily in `serve`).
    let backup_dir = crate::import_backup::dir_in(&state_dir);
    crate::import_backup::purge(&backup_dir, crate::import_backup::now());
    // The approval requests; pending ones past their expiry are expired at
    // start (and every 30 s in `serve`). A store that cannot be opened
    // keeps the daemon up and denies every `ask`.
    let approvals =
        crate::approvals::Store::open(&crate::approvals::dir_in(&state_dir)).map_err(|e| {
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
    let (tokens, tokens_reset) = Tokens::open(tokens::path_in(&state_dir), tokens::system_clock());
    if let Some(why) = &tokens_reset {
        eprintln!("saiife: warning: gateway tokens reset: {why}");
    }
    // The lockdown flag; an unreadable file is `all` (fail closed) and a
    // `lockdown_unreadable` record.
    let (lockdown, lockdown_unreadable) =
        crate::lockdown::Store::open(crate::lockdown::path_in(&state_dir));
    if let Some(why) = &lockdown_unreadable {
        eprintln!("saiife: warning: {why}: lockdown is on for all hooks and connectors");
    }
    // The command grants; an unusable file is no grants (each command
    // needs approval again) and a `grants_unreadable` record.
    let (grants, grants_unreadable) = crate::grants::Grants::open(
        crate::grants::path_in(&state_dir),
        crate::import_backup::now(),
    );
    if let Some(why) = &grants_unreadable {
        eprintln!("saiife: warning: {why}: approved commands need approval again");
    }
    // Checked at load: loopback only. No valid policy, no listener.
    let tcp = gateway_cfg.tcp_addr().ok().flatten();

    let ctx = Arc::new(Ctx::new(CtxInit {
        writer: handle,
        writer_cfg,
        directory,
        mode,
        own_uid: euid,
        own_user: name,
        audit_dir: audit_cfg.dir.clone(),
        socket_dir: daemon_cfg.socket_dir.clone(),
        key_path,
        config_path: config.clone(),
        catalog,
        policy,
        proc: Box::new(crate::sessions::RealProc::new("/proc")),
        vault,
        vault_path,
        limiter,
        upstream,
        backup_dir,
        tokens: Arc::new(tokens),
        approvals,
        lockdown,
        grants,
    }));
    ctx.tcp.lock().unwrap_or_else(|p| p.into_inner()).configured = gateway_cfg.tcp.clone();

    // The forwarding workers start in `serve`, after the start records.
    {
        let weak = Arc::downgrade(&ctx);
        let host: std::sync::Weak<dyn crate::forwarder::Host> = weak.clone();
        ctx.forwarders.configure(crate::forwarder::Setup {
            audit_dir: audit_cfg.dir.clone(),
            state_dir: state_dir.clone(),
            appended: ctx.writer.appends(),
            clock: Arc::new(crate::forwarder::SystemClock::default()),
            host,
            make: Arc::new(move |name, cfg| crate::forwarder::transport_for(name, cfg, &weak)),
            send_timeout: crate::forwarder::BATCH_TIMEOUT,
        });
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the runtime: {e}"))?;
    let loaded_files = loaded.as_ref().ok().map(|(l, _, _)| files_json(l));
    let notes: Vec<_> = [
        ("ca_refused", ca_refused),
        ("tokens_reset", tokens_reset),
        ("lockdown_unreadable", lockdown_unreadable),
        ("grants_unreadable", grants_unreadable),
    ]
    .into_iter()
    .filter_map(|(e, r)| Some((e, r?, serde_json::Map::new())))
    .chain(rebuild_note)
    .chain(capped_note)
    .collect();
    let mut more = start_notes(&ctx, notes, &expired_at_start);
    // Requests approved but not sent when the daemon stopped become
    // `send_failed` (`interrupted`); none is sent again by itself.
    more.extend(crate::approval_ops::reconcile_interrupted(&ctx));
    let code = rt.block_on(serve(
        Arc::clone(&ctx),
        daemon_cfg.socket_dir.clone(),
        check,
        policy_err,
        loaded_files,
        more,
        tcp,
    ));
    // An oauth2 refresh in flight finishes first: its rotated refresh token
    // may be the only valid one, and it must reach the vault.
    if !rt.block_on(ctx.oauth.drain(crate::oauth::DRAIN)) {
        eprintln!("saiifed: warning: an oauth2 refresh was still running at shutdown");
    }
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

/// The checks `load_local_with` makes on local manifests, for the CA
/// directory: owned by `owner`, not writable by group or others, no
/// symlinks, and every `*.pem` a regular file with the same owner and mode
/// rules. A missing directory is fine (no extra CAs).
fn check_ca_dir(dir: &Path, owner: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let err = |p: &Path, why: &str| format!("{}: {why}", p.display());
    let who = if owner == 0 { "root" } else { "this user" };
    let owned = format!("must be owned by {who} and not writable by others");
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(err(dir, &e.to_string())),
    };
    if !meta.is_dir() {
        return Err(err(dir, "not a directory (symlinks are not followed)"));
    }
    if meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return Err(err(dir, &owned));
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
            return Err(err(&p, &owned));
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
/// The personal broker's dir must be its own (not root's) and closed to
/// group and others.
fn check_socket_dir(
    st: &rustix::fs::Stat,
    dir: &Path,
    uid: u32,
    perms: SocketPerms,
) -> Result<(), String> {
    if st.st_mode & 0o170000 != 0o040000 {
        return Err(format!("{}: not a directory", dir.display()));
    }
    if !perms.root_dir_ok {
        if st.st_uid != uid {
            return Err(format!(
                "{}: owned by uid {}, expected this user (uid {uid})",
                dir.display(),
                st.st_uid
            ));
        }
        if st.st_mode & 0o077 != 0 {
            return Err(format!(
                "{}: mode {:04o}, must be 0700; fix: chmod 700 {}",
                dir.display(),
                st.st_mode & 0o7777,
                dir.display()
            ));
        }
        return Ok(());
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

/// The socket dir (created `perms.dir` when missing: 0755, or 0700 for the
/// personal broker; an existing one is checked by [`check_socket_dir`]) and a fresh socket
/// `name` in it (`saiife.sock`, `gateway.sock`), `perms.sock` (0666 or 0600). A stale socket is
/// removed only when it is a socket of this uid that nobody answers on;
/// anything else there is left alone. The dir is held open (`O_NOFOLLOW`)
/// and every later step works relative to it, without following a symlink
/// at `name`.
fn bind(
    socket_dir: &Path,
    name: &str,
    uid: u32,
    perms: SocketPerms,
) -> Result<(UnixListener, PathBuf), String> {
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
                    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(perms.dir))
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
        perms,
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
    chmod_socket(&dirfd, name, uid, perms.sock).map_err(|e| at_sock(&e))?;
    Ok((l, path))
}

/// `chmod` (`sock_mode`) on the socket just bound, never through a symlink: an
/// `O_PATH | O_NOFOLLOW` handle is checked to be this uid's socket and
/// changed through `/proc/self/fd`. Without `/proc`, `fchmodat` on the
/// checked name in the held dir, which only this uid or root can change.
fn chmod_socket(
    dirfd: &rustix::fd::OwnedFd,
    name: &str,
    uid: u32,
    sock_mode: u32,
) -> std::io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use std::os::fd::AsRawFd;
    let mode = Mode::from_raw_mode(sock_mode);
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
    let perms = match ctx.mode {
        Mode::Locked => SYSTEM_SOCKETS,
        Mode::Personal => PERSONAL_SOCKETS,
    };
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
            ctx.notify_chain_break(d);
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
    let (listener, sock_path) = match bind(&socket_dir, SOCKET_NAME, ctx.own_uid, perms) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("saiife: {e}");
            let _ = ctx.writer.stop(None).await;
            return ExitCode::from(2);
        }
    };
    let (gw_listener, gw_path) = match bind(&socket_dir, GATEWAY_SOCKET_NAME, ctx.own_uid, perms) {
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
    // Audit forwarding, per the policy loaded at start (none while it is
    // invalid; a valid reload starts it).
    match ctx.policy().system {
        Some(sys) => ctx.forwarders.apply(&sys.audit.forward).await,
        None => eprintln!(
            "saiife: warning: audit forwarding is off until a valid policy loads ([audit.forward.*] is read from it)"
        ),
    }

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
            _ = hup.recv() => { let _ = reload(&ctx).await; }
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
    // The forwarders stop first: the stop record waits for the next start
    // (the cursors are on disk).
    ctx.forwarders.stop_all().await;
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

/// Every `[guard] ask` entry names a rule of an active pack; otherwise the
/// policy is invalid (named by its file).
fn check_ask(
    l: &saiife_policy::LoadedPolicy,
    catalog: &[saiife_policy::PackInfo],
) -> Result<(), String> {
    saiife_policy::check_guard_ask(&l.config, catalog).map_err(|e| {
        let file = l.files.first().map(|f| f.0.as_str()).unwrap_or("config");
        format!("{file}: {e}")
    })
}

/// SIGHUP: load and check the policy again. A valid one replaces the old in
/// one step; an invalid one is refused and the old one stays. First the
/// audit dir goes back to `saiife-audit`: the `ExecReload=` command that
/// sent the signal was spawned with `LogsDirectory=`, which gave the dir
/// back to `saiife`. One reload at a time (`ctx.reloads`): a second one,
/// from SIGHUP or `policy.reload`, waits for the first to finish.
pub(crate) async fn reload(ctx: &Arc<Ctx>) -> Result<(), String> {
    let _one_at_a_time = ctx.reloads.lock().await;
    let c = Arc::clone(ctx);
    let loaded = tokio::task::spawn_blocking(move || {
        let personal = (c.mode == Mode::Personal).then(|| PersonalCfg {
            own_user: c.own_user.clone(),
            own_uid: c.own_uid,
            socket_dir: c.socket_dir.clone(),
            audit_dir: c.audit_dir.clone(),
        });
        if c.mode == Mode::Locked {
            regroup_audit_dir(&c.audit_dir, c.directory.as_ref());
        }
        load_policy(
            c.mode,
            &c.config_path,
            c.directory.as_ref(),
            &c.catalog,
            personal.as_ref(),
        )
    })
    .await
    .unwrap_or_else(|e| Err(format!("reload failed: {e}")));
    let mut recs = Vec::new();
    let mut result = Ok(());
    match loaded {
        Ok((l, _, next)) => {
            *ctx.policy.lock().unwrap_or_else(|p| p.into_inner()) = next;
            ctx.forwarders.apply(&l.config.audit.forward).await;
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
            recs.push(policy_record(ctx, "rejected", None, Some(reason.clone())));
            result = Err(reason);
        }
    }
    for rec in recs {
        if let Err(e) = ctx.writer.append(rec).await {
            eprintln!("saiife: warning: cannot write the policy record: {e}");
        }
    }
    result
}

/// Settings a reload cannot apply: what the daemon would refuse to start
/// with, or paths it opened at start.
fn restart_only_changes(ctx: &Ctx, l: &LoadedPolicy) -> Vec<String> {
    let c = &l.config;
    let mut out = Vec::new();
    // (A personal reload with `locked = true` never gets here: `load_policy`
    // rejects it.)
    if ctx.mode == Mode::Locked && !c.locked {
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

    /// Locked mode checks the services before `[guard] ask` (as main did,
    /// at start and reload): a config that fails both names the service.
    #[test]
    fn locked_load_reports_services_before_ask() {
        let d = tempfile::tempdir().unwrap();
        let config = d.path().join("config.toml");
        std::fs::write(
            &config,
            "version = 2\nlocked = true\n\n[daemon]\nuser = \"saiife\"\n\n\
             [guard]\nask = [\"core.git/no-such-rule\"]\n\n\
             [services.erp]\nconnector = \"no-such-connector\"\n",
        )
        .unwrap();
        let dir = saiife_policy::FixedDirectory::from_text(
            "saiife:x:990:990::/:/usr/sbin/nologin\n",
            "saiife:x:990:\n",
        );
        let e = load_policy(Mode::Locked, &config, &dir, &[], None).unwrap_err();
        assert!(e.contains("no-such-connector"), "{e}");
        assert!(!e.contains("no-such-rule"), "{e}");
    }

    /// The personal broker's one load path (`load_policy` with a
    /// `PersonalCfg`) validates every environment against the connector
    /// catalog (plan 14's `check_catalog`, through `check_services_owned`)
    /// and builds one snapshot per environment (`GatewayPolicy::build`),
    /// deciding as developer mode.
    #[test]
    fn personal_config_envs_validated_via_load_policy() {
        let d = tempfile::tempdir().unwrap();
        let config = d.path().join("config.toml");
        let p = PersonalCfg {
            own_user: "me".into(),
            own_uid: rustix::process::getuid().as_raw(),
            socket_dir: d.path().join("run"),
            audit_dir: d.path().join("audit"),
        };
        let dir = saiife_policy::FixedDirectory::from_text("", "");
        let write = |staging_host: &str| {
            std::fs::write(
                &config,
                format!(
                    "version = 2\n\n[services.gl]\nconnector = \"gitlab\"\n\
                     secret = \"gl\"\nparams = {{ host = \"gitlab.example.com\" }}\n\
                     allow = [\"issues:read\"]\n\n\
                     [environments.staging]\n\
                     services.gl.params = {{ host = {staging_host:?} }}\n"
                ),
            )
            .unwrap();
        };
        // The base is fine; the environment's host is an IP literal, which
        // the gitlab manifest's host param refuses.
        write("127.0.0.1");
        let e = load_policy(Mode::Personal, &config, &dir, &[], Some(&p)).unwrap_err();
        assert!(e.contains("environment staging"), "{e}");
        // A valid one loads, with its own snapshot that decides as
        // developer mode.
        write("gitlab-staging.example.com");
        let (_, _, state) = load_policy(Mode::Personal, &config, &dir, &[], Some(&p)).unwrap();
        assert!(state.ok);
        let g = state.gateway.expect("connectors are served");
        assert_eq!(g.snap.mode, saiife_policy::Mode::Developer);
        let staging = g.snapshot_for(Some("staging"));
        assert_eq!(staging.env.as_deref(), Some("staging"));
        assert_eq!(staging.mode, saiife_policy::Mode::Developer);
        assert_eq!(
            staging.config.services["gl"].params["host"],
            "gitlab-staging.example.com"
        );
        assert_ne!(staging.hash, g.snap.hash);
        // The implicit personal scope covers the service in both.
        assert_eq!(staging.config.scope[0].users, ["me"]);
    }

    #[test]
    fn state_lock_is_single_instance() {
        let d = tempfile::tempdir().unwrap();
        let first = lock_state_dir(d.path()).unwrap();
        let e = lock_state_dir(d.path()).unwrap_err();
        assert!(e.contains("another personal broker"), "{e}");
        drop(first);
        lock_state_dir(d.path()).unwrap();
        // Never through a symlink.
        let other = tempfile::tempdir().unwrap();
        std::fs::remove_file(d.path().join(PERSONAL_LOCK)).unwrap();
        std::os::unix::fs::symlink(other.path().join("x"), d.path().join(PERSONAL_LOCK)).unwrap();
        assert!(lock_state_dir(d.path()).is_err());
        assert!(!other.path().join("x").exists());
    }

    #[test]
    fn private_dir_is_0700_and_names_the_fix() {
        let d = tempfile::tempdir().unwrap();
        let me = rustix::process::geteuid().as_raw();
        let p = d.path().join("a/b");
        private_dir(&p, me).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
        let e = private_dir(&p, me).unwrap_err();
        assert!(e.contains(&format!("chmod 700 {}", p.display())), "{e}");
        assert!(private_dir(&p, me.wrapping_add(1)).is_err());
    }

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
