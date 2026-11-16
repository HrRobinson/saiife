//! `ChVmm`: plan 34's `Vmm` over Cloud Hypervisor. Ported from the spike's
//! `vm.sh`: `ch_launch` (the API socket wait and the early-exit check),
//! `ch_stop` (power button, then `vmm.shutdown`, then a bound) and
//! `ch_restore` (a restored VM starts paused and is resumed).
//!
//! Locking: one `Mutex` (the run map), never held across an API call, a
//! wait, a launcher call or a hook call. A boot holds a `Starting` slot
//! while it works, so a second boot fails and a stop is applied after the
//! start. Each booted run has a reaper thread that owns the run's state
//! through an `Arc`, runs the stop ladder, and is the only caller of the
//! hooks' `after_off` for that run, once its exit is confirmed.
//!
//! Liveness comes only from `Launcher::exited` (S3, ruling R19): the VMM's
//! own API socket refines Running/Paused/Created once the launcher says the
//! process is alive, and never proves it dead. A snapshot is restored only
//! from its verified copy in the vault (`crate::snapshot::verify`, R20);
//! a restore is one-shot.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use saiife_boxes::template::ImageRef;
use saiife_boxes::vmm::{VmHandle, VmSpec, VmStatus, Vmm, VmmError};
use saiife_wire::source::BoxId;

use crate::ch::{Action, Api, ApiError, VmState};
use crate::disk::make_overlay;
use crate::launch::{self, write_spec, Boot, LaunchSpec, Launcher, MAX_SOCK_PATH};
use crate::layout::Layout;
use crate::paths::BoxPaths;
use crate::pins::CH_VERSION;
use crate::snapshot;
use crate::tools::Tools;

/// `ch_launch` waits this long for the API socket.
const SOCKET_WAIT: Duration = Duration::from_secs(10);
/// Pause, resume and the stop ladder's calls.
const CALL_TIMEOUT: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(50);
/// A restored VMM may bind its socket a moment before it listens.
const RESUME_RETRY: Duration = Duration::from_secs(1);
const LOG_TAIL_BYTES: u64 = 64 * 1024;
const LOG_TAIL_LINES: usize = 20;
const LOG_LINE_MAX: usize = 300;
/// At most this many entries of a box dir are looked at.
const MAX_DIR_ENTRIES: usize = 256;
/// `destroy` waits at most this long, for a boot in progress and for the
/// stop ladder together (R41: the trait's "about a second"). A VMM still
/// stopping fails the call with every file kept; the caller retries.
const DESTROY_WAIT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImage {
    /// `base-<sha256>`
    pub id: String,
    pub raw: PathBuf,
    pub sha256: String,
    pub virtual_gib: u64,
    pub boot: Boot,
}

pub trait ImageResolver: Send + Sync {
    fn resolve(&self, r: &ImageRef) -> Result<ResolvedImage, String>;
}

pub trait VmHooks: Send + Sync {
    /// Bind host listeners; an error fails the boot.
    fn before_boot(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String>;
    /// The VMM exited or was destroyed. Once per run.
    fn after_off(&self, id: &BoxId);
    /// A snapshot was not trusted; the box cold-boots instead.
    fn restore_refused(&self, _id: &BoxId, _why: &str) {}
}

/// The stop ladder: wait `power_s` after the power button, then
/// `shutdown_s` after `vmm.shutdown`, then force-stop and wait up to
/// `force_s` for the launcher to see the exit (a unit's StopUnit returns
/// once the job is queued; systemd's own TimeoutStopSec is 30 s).
#[derive(Debug, Clone, Copy)]
pub struct StopTimes {
    pub power_s: u64,
    pub shutdown_s: u64,
    pub force_s: u64,
}

impl Default for StopTimes {
    fn default() -> Self {
        StopTimes {
            power_s: 60,
            shutdown_s: 30,
            force_s: 35,
        }
    }
}

/// How often the force-stop wait asks the launcher.
const FORCE_POLL: Duration = Duration::from_millis(250);

pub struct ChVmmInit {
    pub layout: Layout,
    /// The daemon's record dirs (the box store's root, R37): `VmSpec.dir`
    /// must be `<records>/<id>`. Nothing VMM-side is ever written there.
    pub records: PathBuf,
    pub tools: Tools,
    pub images: Arc<dyn ImageResolver>,
    pub launcher: Arc<dyn Launcher>,
    pub hooks: Vec<Arc<dyn VmHooks>>,
    /// The uid the VMM runs as: the daemon's euid in personal mode, the
    /// saiife-box VMM user in locked mode. Snapshot files must be its.
    pub vmm_uid: u32,
    pub landlock: bool,
    pub stop: StopTimes,
}

/// One booted (or stopping) VMM, shared with its reaper.
struct Run {
    id: BoxId,
    paths: BoxPaths,
    /// Set by the reaper when it ends.
    done: AtomicBool,
    /// Set (before `done`) when the reaper saw the VMM exit.
    confirmed: AtomicBool,
}

impl Run {
    fn done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }
    /// The reaper ended and saw the exit: the VM is off.
    fn off(&self) -> bool {
        self.done() && self.confirmed.load(Ordering::SeqCst)
    }
}

struct Entry {
    run: Arc<Run>,
    stop_tx: Sender<()>,
    reaper: JoinHandle<()>,
}

enum Slot {
    /// A boot is in progress; `stop` asks for a stop once it has started.
    Starting {
        stop: bool,
    },
    Run(Entry),
}

pub struct ChVmm {
    inner: Arc<ChVmmInit>,
    runs: Mutex<BTreeMap<BoxId, Slot>>,
}

fn log(id: &BoxId, msg: &str) {
    eprintln!("saiife box {}: {}", id.as_str(), clean_line(msg));
}

/// Printable text only: control characters (escapes, CR) become `?`.
fn clean_line(s: &str) -> String {
    let mut o: String = s
        .chars()
        .take(LOG_LINE_MAX)
        .map(|c| match c {
            '\t' => ' ',
            c if c.is_control() => '?',
            c => c,
        })
        .collect();
    if s.chars().count() > LOG_LINE_MAX {
        o.push_str("...");
    }
    o
}

fn api_text(e: &ApiError) -> String {
    match e {
        ApiError::NoSocket => "the VMM API socket is not there (is the VM running?)".into(),
        ApiError::Timeout => "the VMM API did not answer in time".into(),
        ApiError::Http { status, body } => {
            format!("the VMM API refused: HTTP {status}: {}", clean_line(body))
        }
        ApiError::Bad(m) => format!("bad answer from the VMM API: {}", clean_line(m)),
    }
}

fn failed_api(e: ApiError) -> VmmError {
    VmmError::Failed(api_text(&e))
}

/// The last 20 lines of the last 64 KiB of `ch.log`, sanitized. The VMM
/// writes this file, so it is opened without following links or blocking
/// and read from the end, never whole.
fn log_tail(p: &Path) -> String {
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(p)
    else {
        return String::new();
    };
    let Ok(m) = f.metadata() else {
        return String::new();
    };
    if !m.file_type().is_file() {
        return String::new();
    }
    let start = m.len().saturating_sub(LOG_TAIL_BYTES);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    let _ = f.take(LOG_TAIL_BYTES).read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0); // a cut line
    }
    let from = lines.len().saturating_sub(LOG_TAIL_LINES);
    lines[from..]
        .iter()
        .map(|l| clean_line(l))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_socket(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_socket())
}

/// `api.sock`, `vsock.sock` and `vsock.sock_*` (CH binds without unlinking).
/// The box dir is VMM-writable: the listing is bounded.
fn remove_sockets(paths: &BoxPaths) {
    let _ = std::fs::remove_file(paths.api_sock());
    let _ = std::fs::remove_file(paths.vsock());
    let Ok(rd) = std::fs::read_dir(&paths.dir) else {
        return;
    };
    for e in rd.take(MAX_DIR_ENTRIES).flatten() {
        if e.file_name().as_bytes().starts_with(b"vsock.sock_") {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// `mem_mib` from the handle `create` made (daemon-stored, unlike vm.json).
fn handle_mem_mib(h: &VmHandle) -> Result<u64, VmmError> {
    serde_json::from_str::<serde_json::Value>(&h.data)
        .ok()
        .and_then(|v| v.get("mem_mib")?.as_u64())
        .ok_or_else(|| VmmError::Failed("the box handle has no mem_mib; recreate the box".into()))
}

/// Locked mode: the overlay the daemon just made is read and written by
/// the VMM user through the group (0660, I5). Set through an fd opened
/// without following links; only a regular file with one link is touched.
fn group_writable(p: &Path) -> Result<(), String> {
    use rustix::fs::{Mode, OFlags, CWD};
    let fd = rustix::fs::openat(
        CWD,
        p,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("{}: {e}", p.display()))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| e.to_string())?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile
        || st.st_nlink != 1
    {
        return Err(format!("{} is not a plain file", p.display()));
    }
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o660)).map_err(|e| e.to_string())
}

/// The API's state of a VMM the launcher says is alive. Never Off: only the
/// launcher's word ends a VMM (R19), so a live VMM that says Shutdown (after
/// `vm.shutdown`, or lying) is Running until it exits.
fn map_state(s: VmState) -> VmStatus {
    match s {
        VmState::Created => VmStatus::Created,
        VmState::Running | VmState::Shutdown => VmStatus::Running,
        VmState::Paused => VmStatus::Paused,
    }
}

impl ChVmmInit {
    fn paths(&self, id: &BoxId) -> BoxPaths {
        self.layout.box_paths(id)
    }

    /// Whether the VMM is gone, by the launcher's word only (`None`: no
    /// process of this box is known to any launcher).
    fn gone(&self, id: &BoxId) -> bool {
        !matches!(self.launcher.exited(id), Some(false))
    }

    fn wait_exit(&self, run: &Run, until: Instant) -> bool {
        self.wait_exit_every(run, until, POLL)
    }

    fn wait_exit_every(&self, run: &Run, until: Instant, step: Duration) -> bool {
        loop {
            if self.gone(&run.id) {
                return true;
            }
            let now = Instant::now();
            if now >= until {
                return false;
            }
            std::thread::sleep(step.min(until - now));
        }
    }

    /// A run whose reaper ended without seeing the exit: once the launcher
    /// says the VMM is gone, confirm it and run `after_off`, exactly once
    /// (the reaper is done, and the flag is taken by compare-exchange).
    fn settle(&self, run: &Run) {
        if !run.done() || run.off() || !self.gone(&run.id) {
            return;
        }
        if run
            .confirmed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            log(&run.id, "the VMM has stopped after all");
            self.after_off(&run.id);
            remove_sockets(&run.paths);
        }
    }

    /// The runtime dir of a box (R37): made when missing (personal 0700,
    /// locked 2770 so the VMM user's group gets in; setgid keeps the group);
    /// an existing one must be a real dir of this uid. Its root is made
    /// 0700 in personal mode; locked, `system install --boxes` made it.
    fn runtime_dir(&self, paths: &BoxPaths) -> Result<(), String> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        let dir = &paths.dir;
        let me = rustix::process::geteuid().as_raw();
        if !self.layout.locked {
            self.private_root()?;
        }
        match std::fs::symlink_metadata(dir) {
            Ok(m) if !m.file_type().is_dir() => {
                return Err(format!(
                    "the box runtime dir {} is not a directory (or is a symlink)",
                    dir.display()
                ));
            }
            Ok(m) if m.uid() != me => {
                return Err(format!(
                    "the box runtime dir {} is owned by uid {}, not {me}",
                    dir.display(),
                    m.uid()
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(dir)
                    .map_err(|e| format!("box runtime dir {}: {e}", dir.display()))?;
            }
            Err(e) => return Err(format!("box runtime dir {}: {e}", dir.display())),
        }
        if self.layout.locked {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o2770))
                .map_err(|e| format!("box runtime dir {}: {e}", dir.display()))?;
        }
        Ok(())
    }

    /// Personal mode: the runtime root (`<state>/box-run`) is made 0700 when
    /// missing, an existing one of this uid made 0700, a symlinked, non-dir
    /// or foreign one refused (M2).
    fn private_root(&self) -> Result<(), String> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        let root = &self.layout.boxes;
        let me = rustix::process::geteuid().as_raw();
        if std::fs::symlink_metadata(root).is_err() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(root)
                .map_err(|e| format!("box runtime root {}: {e}", root.display()))?;
        }
        let m = std::fs::symlink_metadata(root)
            .map_err(|e| format!("box runtime root {}: {e}", root.display()))?;
        if !m.file_type().is_dir() {
            return Err(format!(
                "the box runtime root {} is not a directory (or is a symlink)",
                root.display()
            ));
        }
        if m.uid() != me {
            return Err(format!(
                "the box runtime root {} is owned by uid {}, not {me}",
                root.display(),
                m.uid()
            ));
        }
        if m.mode() & 0o7777 != 0o700 {
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("box runtime root {}: {e}", root.display()))?;
        }
        Ok(())
    }

    /// After a confirmed exit: the runtime dir (by fd, never following a
    /// link) and the box's vault entries. A failure keeps the rest.
    fn remove_runtime(&self, id: &BoxId) -> Result<(), VmmError> {
        snapshot::remove_runtime_dir(&self.paths(id))
            .map_err(|e| VmmError::Failed(format!("the box runtime dir is kept: {e}")))?;
        snapshot::discard(&self.layout.vault, id).map_err(VmmError::Failed)?;
        crate::vault::remove_pid(&self.layout.vault, id);
        Ok(())
    }

    fn after_off(&self, id: &BoxId) {
        for h in &self.hooks {
            h.after_off(id);
        }
    }

    /// Status from the launcher's liveness, refined by the API while the
    /// process is alive. Gone or unknown: Off when `vm.json` is there (a
    /// created, never booted or exited box), else Gone.
    fn status_of(&self, id: &BoxId, paths: &BoxPaths) -> VmStatus {
        if self.gone(id) {
            return if std::fs::symlink_metadata(paths.vm_json()).is_ok() {
                VmStatus::Off
            } else {
                VmStatus::Gone
            };
        }
        match Api::new(paths.api_sock()).state() {
            Ok(s) => map_state(s),
            // alive but not answering: never Off
            Err(_) => VmStatus::Running,
        }
    }

    /// The stop ladder (`ch_stop`, without signals): power button, wait
    /// `power_s`; `vmm.shutdown`, wait `shutdown_s`; then `force_stop`.
    fn ladder(&self, run: &Run) {
        let api = Api::new(run.paths.api_sock());
        let t0 = Instant::now();
        match api.put(Action::PowerButton, None, CALL_TIMEOUT) {
            Ok(()) => {
                if self.wait_exit(run, t0 + Duration::from_secs(self.stop.power_s)) {
                    return;
                }
            }
            Err(e) => log(&run.id, &format!("power button: {}", api_text(&e))),
        }
        if self.gone(&run.id) {
            return;
        }
        let t1 = Instant::now();
        if let Err(e) = api.put(Action::ShutdownVmm, None, CALL_TIMEOUT) {
            log(&run.id, &format!("vmm.shutdown: {}", api_text(&e)));
        }
        if self.wait_exit(run, t1 + Duration::from_secs(self.stop.shutdown_s)) {
            return;
        }
        log(&run.id, "the VMM did not stop; force-stopping it");
        if let Err(e) = self.launcher.force_stop(&run.id) {
            log(&run.id, &format!("force stop: {e}"));
        }
        // A unit's stop job may still be running: wait for it, bounded.
        let until = Instant::now() + Duration::from_secs(self.stop.force_s);
        self.wait_exit_every(run, until, FORCE_POLL);
    }

    /// The reaper: watch for the exit (or a stop request), run the ladder,
    /// then, once the exit is confirmed, `after_off` and remove the sockets.
    /// An unconfirmed end leaves the run not off: `status` asks the API and
    /// a later `stop` runs the ladder again.
    fn reap(&self, run: &Run, rx: &Receiver<()>, stopping: bool) {
        if !stopping {
            loop {
                if self.gone(&run.id) {
                    break;
                }
                match rx.recv_timeout(POLL) {
                    Ok(()) => {
                        self.ladder(run);
                        break;
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    // the ChVmm is gone: keep watching for the exit
                    Err(RecvTimeoutError::Disconnected) => std::thread::sleep(POLL),
                }
            }
        } else {
            self.ladder(run);
        }
        if self.gone(&run.id) {
            self.after_off(&run.id);
            remove_sockets(&run.paths);
            run.confirmed.store(true, Ordering::SeqCst);
        } else {
            // `ChVmm::settle` confirms it later (status, stop, boot, destroy).
            log(&run.id, "the VMM did not stop; it may still be running");
        }
        run.done.store(true, Ordering::SeqCst);
    }

    /// Undo a failed boot after every hook's `before_boot` succeeded.
    fn unwind(&self, id: &BoxId, paths: &BoxPaths, started: bool) {
        if started {
            if let Err(e) = self.launcher.force_stop(id) {
                log(id, &format!("force stop: {e}"));
            }
        }
        self.after_off(id);
        remove_sockets(paths);
    }

    /// The snapshot to restore this boot from, if any (the VMM of the box is
    /// confirmed gone). Not trusted: discarded with its marker, noted to
    /// the hooks, and the box cold-boots.
    /// The spec of a boot, from daemon-held state only: the image and sizes
    /// in the handle's data (the box record's), the image as the store
    /// resolves it now (base, firmware or kernel and cmdline), the driver's
    /// Landlock setting, and the repo disk create handed to the runtime dir.
    /// `restore` is the caller's (from the vault marker).
    fn launch_spec(&self, h: &VmHandle, paths: &BoxPaths) -> Result<LaunchSpec, String> {
        let stale = || {
            "the box's VM record has no image, sizes or repo flag (made by an older saiife): \
             discard the box and spawn it again"
                .to_string()
        };
        let image = image_of_data(&h.data).ok_or_else(stale)?;
        let v: serde_json::Value = serde_json::from_str(&h.data).map_err(|_| stale())?;
        let mem_mib = v.get("mem_mib").and_then(serde_json::Value::as_u64);
        let vcpus = v
            .get("vcpus")
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        let repo = v.get("repo").and_then(serde_json::Value::as_bool);
        let (Some(mem_mib), Some(vcpus), Some(repo)) = (mem_mib, vcpus, repo) else {
            return Err(stale());
        };
        // the runtime dir is VMM-writable: its repo.img must be the one
        // create handed over, no more, no less (not followed: check_plain)
        let present = std::fs::symlink_metadata(paths.repo_disk()).is_ok();
        if present != repo {
            return Err(if repo {
                "the box's repo disk is missing from its runtime dir".into()
            } else {
                "a repo disk the box was not created with is in its runtime dir".into()
            });
        }
        let resolved = self.images.resolve(&ImageRef::Pinned(image.clone()))?;
        if resolved.id != image {
            return Err(format!(
                "the image store resolved {image} to {}",
                resolved.id
            ));
        }
        let spec = LaunchSpec {
            version: 1,
            id: h.id.clone(),
            vcpus,
            mem_mib,
            base: resolved.raw,
            repo,
            boot: resolved.boot,
            landlock: self.landlock,
            restore: None,
        };
        launch::check_limits(&spec)?;
        Ok(spec)
    }

    fn decide_restore(&self, id: &BoxId, paths: &BoxPaths, spec: &LaunchSpec) -> Option<PathBuf> {
        let vault = &self.layout.vault;
        let present = |p: &Path| std::fs::symlink_metadata(p).is_ok();
        if !present(&crate::vault::marker_path(vault, id))
            && !present(&crate::vault::snap_dir(vault, id))
        {
            return None;
        }
        let why = match snapshot::verify(vault, id, paths, spec) {
            Ok(dir) => return Some(dir),
            Err(why) => why,
        };
        log(id, &format!("not restoring the snapshot: {why}"));
        for h in &self.hooks {
            h.restore_refused(id, &clean_line(&why));
        }
        self.discard_snapshot(id);
        None
    }

    fn discard_snapshot(&self, id: &BoxId) {
        if let Err(e) = snapshot::discard(&self.layout.vault, id) {
            log(id, &e);
        }
    }
}

impl ChVmm {
    /// Tells the launcher the box's tier from the daemon's record (the
    /// handle) before it is asked anything about the box; locked, the tier
    /// names the unit, and a handle without one fails closed.
    fn bind(&self, h: &VmHandle) {
        self.inner
            .launcher
            .bind(&h.id, tier_of_data(&h.data).as_deref());
    }

    pub fn new(init: ChVmmInit) -> ChVmm {
        ChVmm {
            inner: Arc::new(init),
            runs: Mutex::new(BTreeMap::new()),
        }
    }

    fn runs(&self) -> std::sync::MutexGuard<'_, BTreeMap<BoxId, Slot>> {
        self.runs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `ChVmmInit::settle` for the box's done, unconfirmed run, if any
    /// (the hooks run outside the map lock).
    fn settle(&self, id: &BoxId) {
        let run = match self.runs().get(id) {
            Some(Slot::Run(e)) if e.run.done() && !e.run.off() => Arc::clone(&e.run),
            _ => return,
        };
        self.inner.settle(&run);
    }

    fn spawn_reaper(&self, id: &BoxId, paths: BoxPaths, stopping: bool) -> Result<Entry, VmmError> {
        let run = Arc::new(Run {
            id: id.clone(),
            paths,
            done: AtomicBool::new(false),
            confirmed: AtomicBool::new(false),
        });
        let (tx, rx) = mpsc::channel();
        let inner = Arc::clone(&self.inner);
        let r = Arc::clone(&run);
        let reaper = std::thread::Builder::new()
            .name(format!("vmm-reaper-{}", id.as_str()))
            .spawn(move || inner.reap(&r, &rx, stopping))
            .map_err(|e| VmmError::Failed(format!("cannot start the reaper thread: {e}")))?;
        Ok(Entry {
            run,
            stop_tx: tx,
            reaper,
        })
    }

    /// Hooks, restore decision, start, socket wait, resume. On an error
    /// everything it started is undone; the `Starting` slot is the caller's.
    fn boot_inner(&self, h: &VmHandle, paths: &BoxPaths) -> Result<(), VmmError> {
        let inner = &self.inner;
        let id = &h.id;
        if inner.launcher.exited(id) == Some(false) {
            return Err(VmmError::Failed(format!(
                "the VMM of this box is still running, or its liveness cannot be determined; \
                 if you are sure no VMM of this box runs, remove {}",
                crate::vault::pid_path(&inner.layout.vault, id).display()
            )));
        }
        // Never read back from vm.json: it is in the runtime dir, which the
        // VMM user can write (R37). The spec is rebuilt from the daemon's
        // own state and written fresh every boot.
        let mut spec = inner.launch_spec(h, paths).map_err(VmmError::Failed)?;
        // CH opens these by path and follows links (S4 sweep): serial.log is
        // replaced when it is not a plain file (unlink removes a link, not its
        // target); the disks hold the box's data, so they are refused.
        if launch::check_plain("serial.log", &paths.serial()).is_err() {
            let _ = std::fs::remove_file(paths.serial());
        }
        let mut disks = vec![(crate::paths::ROOT_DISK, paths.root_disk())];
        if spec.repo {
            disks.push((crate::paths::REPO_DISK, paths.repo_disk()));
        }
        for (name, p) in disks {
            launch::check_plain(name, &p).map_err(VmmError::Failed)?;
        }
        // `ch_launch`: stale sockets of an earlier VMM (CH binds without unlink)
        remove_sockets(paths);
        for (i, hook) in inner.hooks.iter().enumerate() {
            if let Err(e) = hook.before_boot(id, paths) {
                for earlier in &inner.hooks[..i] {
                    earlier.after_off(id);
                }
                return Err(VmmError::Failed(e));
            }
        }
        spec.restore = inner.decide_restore(id, paths, &spec);
        if let Err(e) = write_spec(&spec, paths) {
            inner.unwind(id, paths, false);
            return Err(VmmError::Failed(e));
        }
        if let Err(e) = inner.launcher.start(id, paths) {
            inner.unwind(id, paths, false);
            return Err(VmmError::Failed(e));
        }
        if spec.restore.is_some() {
            // One-shot: whatever happens next, this snapshot is used up.
            snapshot::remove_marker(&inner.layout.vault, id);
        }
        let deadline = Instant::now() + SOCKET_WAIT;
        while !is_socket(&paths.api_sock()) {
            if inner.launcher.exited(id) == Some(true) {
                inner.unwind(id, paths, true);
                let tail = log_tail(&paths.ch_log());
                let mut m = String::from("the VMM exited at start; see ch.log");
                if !tail.is_empty() {
                    m.push('\n');
                    m.push_str(&tail);
                }
                return Err(VmmError::Failed(m));
            }
            if Instant::now() >= deadline {
                inner.unwind(id, paths, true);
                return Err(VmmError::Failed(format!(
                    "the VMM API socket did not appear within {} s; see ch.log",
                    SOCKET_WAIT.as_secs()
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if spec.restore.is_some() {
            // `ch_restore`: the restored VM starts paused.
            let api = Api::new(paths.api_sock());
            let until = Instant::now() + RESUME_RETRY;
            let r = loop {
                match api.put(Action::Resume, None, CALL_TIMEOUT) {
                    Err(ApiError::NoSocket) if Instant::now() < until => {
                        std::thread::sleep(POLL);
                    }
                    other => break other,
                }
            };
            if let Err(e) = r {
                inner.unwind(id, paths, true);
                return Err(VmmError::Failed(format!(
                    "resume after restore: {}",
                    api_text(&e)
                )));
            }
            // Linux keeps files CH still has open; the snapshot is spent.
            inner.discard_snapshot(id);
        }
        Ok(())
    }

    /// Stop a VM this process has no live run for (a daemon restart, or a
    /// reaper that could not confirm the exit): through the API alone.
    fn stop_unknown(&self, h: &VmHandle) -> Result<(), VmmError> {
        let paths = self.inner.paths(&h.id);
        if matches!(
            self.inner.status_of(&h.id, &paths),
            VmStatus::Off | VmStatus::Gone
        ) {
            return Ok(());
        }
        self.restart_ladder(h, paths)
    }

    /// A stale run (none, or a reaper that ended without confirming the
    /// exit) gets a new reaper that runs the ladder at once.
    fn restart_ladder(&self, h: &VmHandle, paths: BoxPaths) -> Result<(), VmmError> {
        let mut g = self.runs();
        let stale = match g.get(&h.id) {
            None => true,
            Some(Slot::Run(e)) => e.run.done() && !e.run.off(),
            Some(Slot::Starting { .. }) => false,
        };
        if stale {
            let e = self.spawn_reaper(&h.id, paths, true)?;
            // the old reaper (if any) is done; dropping its handle detaches it
            g.insert(h.id.clone(), Slot::Run(e));
        }
        Ok(())
    }

    /// `destroy`'s stop of a VMM the launcher says is alive, without
    /// asking its API (a hung API would cost the call's timeout): a live
    /// reaper is told to stop, a stale run gets a new ladder.
    fn request_stop(&self, h: &VmHandle) -> Result<(), VmmError> {
        {
            let mut g = self.runs();
            match g.get_mut(&h.id) {
                Some(Slot::Starting { stop }) => {
                    *stop = true;
                    return Ok(());
                }
                Some(Slot::Run(e)) if !e.run.done() => {
                    let _ = e.stop_tx.send(());
                    return Ok(());
                }
                _ => {}
            }
        }
        self.restart_ladder(h, self.inner.paths(&h.id))
    }
}

/// The longest handle data [`image_of_data`] parses.
const MAX_HANDLE_DATA: usize = 4096;

/// `data["tier"]` of a handle's data (the box's size tier, recorded at
/// create), when the data is short JSON and the tier one of `TIERS`.
fn tier_of_data(data: &str) -> Option<String> {
    if data.len() > MAX_HANDLE_DATA {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(data).ok()?;
    let t = v.get("tier")?.as_str()?;
    saiife_boxes::template::tier_named(t).map(|t| t.name.to_string())
}

/// `data["image"]` of a handle's data, when the data is short JSON and the
/// image a valid id.
fn image_of_data(data: &str) -> Option<String> {
    if data.len() > MAX_HANDLE_DATA {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(data).ok()?;
    let id = v.get("image")?.as_str()?;
    crate::image::parse_image_id(id).ok()?;
    Some(id.to_string())
}

impl Vmm for ChVmm {
    /// `spec.dir` is the box's record dir (the store's, R37): checked, and
    /// a repo disk spawn placed there is moved to the runtime dir
    /// (`repo_handover`); everything the VMM touches goes to the runtime
    /// dir `<layout.boxes>/<id>`, made here.
    fn create(&self, spec: &VmSpec) -> Result<VmHandle, VmmError> {
        let inner = &self.inner;
        let want = inner.records.join(spec.id.as_str());
        if spec.dir != want {
            return Err(VmmError::Failed(format!(
                "the box record dir must be {}",
                want.display()
            )));
        }
        let paths = inner.paths(&spec.id);
        let n = paths.longest_socket().as_os_str().as_bytes().len();
        if n > MAX_SOCK_PATH {
            return Err(VmmError::Failed(format!(
                "the box dir is too long: a socket path would be {n} bytes, over {MAX_SOCK_PATH}"
            )));
        }
        inner.runtime_dir(&paths).map_err(VmmError::Failed)?;
        let image = inner
            .images
            .resolve(&spec.image)
            .map_err(VmmError::Failed)?;
        if spec.size.disk_gib < image.virtual_gib {
            return Err(VmmError::Failed(format!(
                "the box disk ({} GiB) is smaller than the base image ({} GiB)",
                spec.size.disk_gib, image.virtual_gib
            )));
        }
        let root = paths.root_disk();
        // A restart keeps the overlay (and the box's writes in it).
        if std::fs::symlink_metadata(&root).is_err() {
            make_overlay(&inner.tools, &image.raw, &root, spec.size.disk_gib)
                .map_err(|e| VmmError::Failed(format!("root disk: {e}")))?;
        }
        // Also for a kept overlay: an earlier create whose fchmod failed is
        // retried (R35). A link or a hard-linked file is refused.
        if inner.layout.locked {
            group_writable(&root).map_err(|e| VmmError::Failed(format!("root disk: {e}")))?;
        }
        // Spawn placed the repo disk in the record dir; the VMM opens it
        // from the runtime dir (R37, R40); base.json stays in the record.
        // The last step that can fail before the spec: a failed create
        // gives the disk back to the record, which a discard removes.
        // locked: the unit of the smallest tier that holds the box (its
        // MemoryMax= and CPUQuota= are the tier's, written by the installer)
        let tier = saiife_boxes::template::tier_for(spec.size.vcpus, spec.size.mem_mib)
            .ok_or_else(|| {
                VmmError::Failed(format!(
                    "no size tier holds {} vCPUs and {} MiB",
                    spec.size.vcpus, spec.size.mem_mib
                ))
            })?;
        let handover =
            crate::repo_handover::take_repo_disk(&spec.dir, &paths.dir, inner.layout.locked)
                .map_err(VmmError::Failed)?;
        // `restore` is decided at boot, from the marker (S1).
        let ls = LaunchSpec {
            version: 1,
            id: spec.id.clone(),
            vcpus: spec.size.vcpus,
            mem_mib: spec.size.mem_mib,
            base: image.raw.clone(),
            // what this create handed over, not what the VMM-writable
            // runtime dir holds: a repo.img found there is not the box's
            // (boot then refuses it)
            repo: handover.moved() != crate::repo_handover::Moved::Nothing,
            boot: image.boot.clone(),
            landlock: inner.landlock,
            restore: None,
        };
        if let Err(e) = write_spec(&ls, &paths) {
            handover.undo();
            return Err(VmmError::Failed(e));
        }
        handover.commit().map_err(VmmError::Failed)?;
        // The handle (kept in the daemon-only box record) holds what boot
        // rebuilds the spec from: the image, the admitted sizes. mem_mib also
        // bounds the snapshot copy (`snapshot::seal`). The VMM-writable
        // vm.json is never asked for any of it.
        let data = serde_json::json!({
            "launcher": inner.launcher.kind(),
            "image": image.id,
            "mem_mib": spec.size.mem_mib,
            "vcpus": spec.size.vcpus,
            "repo": ls.repo,
            "tier": tier.name,
        });
        let h = VmHandle {
            id: spec.id.clone(),
            driver: format!("ch-{CH_VERSION}"),
            data: data.to_string(),
        };
        self.bind(&h);
        Ok(h)
    }

    /// Runs the hooks, starts the VMM (restoring a trusted snapshot), waits
    /// for its API socket and returns; the guest's readiness arrives later.
    fn boot(&self, h: &VmHandle) -> Result<(), VmmError> {
        if tier_of_data(&h.data).is_none() {
            return Err(VmmError::Failed(
                "the box's VM record has no size tier (made by an older saiife): \
                 discard the box and spawn it again"
                    .into(),
            ));
        }
        self.bind(h);
        let paths = self.inner.paths(&h.id);
        // an earlier run that is gone by now gets its after_off first
        self.settle(&h.id);
        let old = {
            let mut g = self.runs();
            match g.get(&h.id) {
                Some(Slot::Starting { .. }) => {
                    return Err(VmmError::Failed("the VM is already booting".into()));
                }
                // a done run that could not confirm the exit: boot_inner asks the API
                Some(Slot::Run(e)) if !e.run.done() => {
                    return Err(VmmError::Failed("the VM is already running".into()));
                }
                _ => {}
            }
            g.insert(h.id.clone(), Slot::Starting { stop: false })
        };
        if let Some(Slot::Run(e)) = old {
            let _ = e.reaper.join(); // done: returns at once
        }
        let r = self.boot_inner(h, &paths).and_then(|()| {
            match self.spawn_reaper(&h.id, paths.clone(), false) {
                Ok(e) => Ok(e),
                Err(e) => {
                    self.inner.unwind(&h.id, &paths, true);
                    Err(e)
                }
            }
        });
        let mut g = self.runs();
        let stop = matches!(g.remove(&h.id), Some(Slot::Starting { stop: true }));
        let e = r?;
        if stop {
            let _ = e.stop_tx.send(());
        }
        g.insert(h.id.clone(), Slot::Run(e));
        Ok(())
    }

    fn pause(&self, h: &VmHandle) -> Result<(), VmmError> {
        Api::new(self.inner.paths(&h.id).api_sock())
            .put(Action::Pause, None, CALL_TIMEOUT)
            .map_err(failed_api)
    }

    fn resume(&self, h: &VmHandle) -> Result<(), VmmError> {
        Api::new(self.inner.paths(&h.id).api_sock())
            .put(Action::Resume, None, CALL_TIMEOUT)
            .map_err(failed_api)
    }

    /// Asks for the stop and returns; the reaper sends the power button and
    /// escalates (`StopTimes`). During a boot, the stop follows the start.
    fn stop(&self, h: &VmHandle) -> Result<(), VmmError> {
        self.bind(h);
        self.settle(&h.id);
        {
            let mut g = self.runs();
            match g.get_mut(&h.id) {
                Some(Slot::Starting { stop }) => {
                    *stop = true;
                    return Ok(());
                }
                Some(Slot::Run(e)) if !e.run.done() => {
                    let _ = e.stop_tx.send(());
                    return Ok(());
                }
                Some(Slot::Run(e)) if e.run.off() => return Ok(()),
                _ => {}
            }
        }
        self.stop_unknown(h)
    }

    /// The exception to the trait's one-second rule: CH writes the whole
    /// guest memory, bounded by `Api::snapshot`'s 120 s, plus one SHA-256
    /// pass over it. The box's marker and vault copy are removed first; the
    /// new snapshot is sealed into the vault (`snapshot::seal`) while the VM
    /// is still paused, so only a snapshot the daemon took is ever restored.
    fn snapshot(&self, h: &VmHandle, dest: &Path) -> Result<(), VmmError> {
        let inner = &self.inner;
        let paths = inner.paths(&h.id);
        // the manager's dest (the record dir's) is checked, never written:
        // the VMM writes into the runtime `snapshot/` (R37)
        let want = inner.records.join(h.id.as_str()).join("snapshot");
        if dest != want {
            return Err(VmmError::Failed(format!(
                "a snapshot goes to {} only",
                want.display()
            )));
        }
        let api = Api::new(paths.api_sock());
        match api.state() {
            Ok(VmState::Paused) => {}
            Ok(_) => return Err(VmmError::Failed("pause first".into())),
            Err(e) => return Err(failed_api(e)),
        }
        let mem_mib = handle_mem_mib(h)?;
        snapshot::discard(&inner.layout.vault, &h.id).map_err(VmmError::Failed)?;
        // emptied by fd, never removed: Landlock's rule is bound to the dir
        snapshot::clear_dir(&paths).map_err(VmmError::Failed)?;
        api.snapshot(&paths.snapshot_dir()).map_err(failed_api)?;
        snapshot::seal(&inner.layout.vault, &h.id, &paths, inner.vmm_uid, mem_mib)
            .map_err(VmmError::Failed)
    }

    fn status(&self, h: &VmHandle) -> VmStatus {
        self.bind(h);
        if matches!(self.runs().get(&h.id), Some(Slot::Starting { .. })) {
            return VmStatus::Running;
        }
        self.settle(&h.id);
        self.inner.status_of(&h.id, &self.inner.paths(&h.id))
    }

    /// The `image` this driver put in the handle's data at `create`: read
    /// from at most [`MAX_HANDLE_DATA`] bytes of JSON and only when it is a
    /// valid `base-<64 hex>` id.
    fn image_id(&self, h: &VmHandle) -> Option<String> {
        image_of_data(&h.data)
    }

    /// Bounded to about a second (`DESTROY_WAIT`, R41): asks for the stop
    /// when the VMM is alive (its reaper runs the ladder), waits briefly for
    /// the reaper and, only once the launcher says the VMM is gone, forgets
    /// the run and removes the runtime dir and the vault entries (R37). A
    /// VMM still booting or stopping fails it with `Failed` and keeps the
    /// run and every file (runtime dir, vault, pid record): nothing is
    /// removed under a live VMM. The manager's tick retries it.
    fn destroy(&self, h: &VmHandle) -> Result<(), VmmError> {
        self.bind(h);
        let until = Instant::now() + DESTROY_WAIT;
        while matches!(self.runs().get(&h.id), Some(Slot::Starting { .. })) {
            if Instant::now() >= until {
                return Err(VmmError::Failed("the VM is still booting".into()));
            }
            std::thread::sleep(POLL);
        }
        // an earlier run that is gone by now gets its after_off first
        self.settle(&h.id);
        if !self.inner.gone(&h.id) {
            self.request_stop(h)?;
        }
        loop {
            let run = match self.runs().get(&h.id) {
                Some(Slot::Run(e)) => Arc::clone(&e.run),
                Some(Slot::Starting { .. }) => {
                    return Err(VmmError::Failed("the VM is booting".into()));
                }
                None => break,
            };
            if run.done() {
                // gone by now: confirmed here, with its after_off
                self.inner.settle(&run);
                break;
            }
            if Instant::now() >= until {
                return Err(VmmError::Failed("the VMM is still stopping".into()));
            }
            std::thread::sleep(POLL);
        }
        let e = {
            let mut g = self.runs();
            match g.remove(&h.id) {
                Some(Slot::Run(e)) if e.run.off() => e,
                Some(other) => {
                    let done = matches!(&other, Slot::Run(e) if e.run.done());
                    g.insert(h.id.clone(), other);
                    return Err(VmmError::Failed(if done {
                        "the VMM did not stop; it may still be running".into()
                    } else {
                        "the VMM is still stopping".into()
                    }));
                }
                // no run: only the launcher's word lets the state go
                None if self.inner.gone(&h.id) => {
                    drop(g);
                    return self.inner.remove_runtime(&h.id);
                }
                None => return Err(VmmError::Failed("the VMM is still stopping".into())),
            }
        };
        let _ = e.reaper.join(); // done: returns at once
        self.inner.remove_runtime(&h.id)
    }
}
