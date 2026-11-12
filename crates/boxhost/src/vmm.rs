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
use crate::launch::{read_spec, write_spec, Boot, LaunchSpec, Launcher, MAX_SOCK_PATH};
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
/// `destroy` waits this long for a boot in progress.
const BOOT_WAIT: Duration = Duration::from_secs(15);

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
/// `shutdown_s` after `vmm.shutdown`, then force-stop.
#[derive(Debug, Clone, Copy)]
pub struct StopTimes {
    pub power_s: u64,
    pub shutdown_s: u64,
}

impl Default for StopTimes {
    fn default() -> Self {
        StopTimes {
            power_s: 60,
            shutdown_s: 30,
        }
    }
}

pub struct ChVmmInit {
    pub layout: Layout,
    pub tools: Tools,
    pub images: Arc<dyn ImageResolver>,
    pub launcher: Arc<dyn Launcher>,
    pub hooks: Vec<Arc<dyn VmHooks>>,
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

fn map_state(s: VmState) -> VmStatus {
    match s {
        VmState::Created => VmStatus::Created,
        VmState::Running => VmStatus::Running,
        VmState::Paused => VmStatus::Paused,
        VmState::Shutdown => VmStatus::Off,
    }
}

impl ChVmmInit {
    fn paths(&self, id: &BoxId) -> BoxPaths {
        BoxPaths::new(self.layout.boxes.join(id.as_str()))
    }

    /// Whether the VMM is gone, by the launcher's word only (`None`: no
    /// process of this box is known to any launcher).
    fn gone(&self, id: &BoxId) -> bool {
        !matches!(self.launcher.exited(id), Some(false))
    }

    fn wait_exit(&self, run: &Run, until: Instant) -> bool {
        loop {
            if self.gone(&run.id) {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(POLL);
        }
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
            return if paths.vm_json().exists() {
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
    pub fn new(init: ChVmmInit) -> ChVmm {
        ChVmm {
            inner: Arc::new(init),
            runs: Mutex::new(BTreeMap::new()),
        }
    }

    fn runs(&self) -> std::sync::MutexGuard<'_, BTreeMap<BoxId, Slot>> {
        self.runs.lock().unwrap_or_else(|e| e.into_inner())
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
            return Err(VmmError::Failed(
                "the VMM of this box is still running (or its liveness cannot be determined)"
                    .into(),
            ));
        }
        let mut spec = read_spec(paths).map_err(VmmError::Failed)?;
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
}

impl Vmm for ChVmm {
    fn create(&self, spec: &VmSpec) -> Result<VmHandle, VmmError> {
        let inner = &self.inner;
        let want = inner.layout.boxes.join(spec.id.as_str());
        if spec.dir != want {
            return Err(VmmError::Failed(format!(
                "the box dir must be {}",
                want.display()
            )));
        }
        let paths = BoxPaths::new(spec.dir.clone());
        let n = paths.longest_socket().as_os_str().as_bytes().len();
        if n > MAX_SOCK_PATH {
            return Err(VmmError::Failed(format!(
                "the box dir is too long: a socket path would be {n} bytes, over {MAX_SOCK_PATH}"
            )));
        }
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
        // `restore` is decided at boot, from the marker (S1).
        let ls = LaunchSpec {
            version: 1,
            id: spec.id.clone(),
            vcpus: spec.size.vcpus,
            mem_mib: spec.size.mem_mib,
            base: image.raw.clone(),
            repo: paths.repo_disk().exists(),
            boot: image.boot.clone(),
            landlock: inner.landlock,
            restore: None,
        };
        write_spec(&ls, &paths).map_err(VmmError::Failed)?;
        let data = serde_json::json!({
            "launcher": inner.launcher.kind(),
            "image": image.id,
        });
        Ok(VmHandle {
            id: spec.id.clone(),
            driver: format!("ch-{CH_VERSION}"),
            data: data.to_string(),
        })
    }

    /// Runs the hooks, starts the VMM (restoring a trusted snapshot), waits
    /// for its API socket and returns; the guest's readiness arrives later.
    fn boot(&self, h: &VmHandle) -> Result<(), VmmError> {
        let paths = self.inner.paths(&h.id);
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
        if dest != paths.snapshot_dir() {
            return Err(VmmError::Failed(format!(
                "a snapshot goes to {} only",
                paths.snapshot_dir().display()
            )));
        }
        let api = Api::new(paths.api_sock());
        match api.state() {
            Ok(VmState::Paused) => {}
            Ok(_) => return Err(VmmError::Failed("pause first".into())),
            Err(e) => return Err(failed_api(e)),
        }
        snapshot::discard(&inner.layout.vault, &h.id).map_err(VmmError::Failed)?;
        match std::fs::remove_dir_all(dest) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(VmmError::Failed(format!("remove the old snapshot: {e}"))),
        }
        api.snapshot(dest).map_err(failed_api)?;
        snapshot::seal(&inner.layout.vault, &h.id, &paths).map_err(VmmError::Failed)
    }

    fn status(&self, h: &VmHandle) -> VmStatus {
        if matches!(self.runs().get(&h.id), Some(Slot::Starting { .. })) {
            return VmStatus::Running;
        }
        self.inner.status_of(&h.id, &self.inner.paths(&h.id))
    }

    /// Stops the VM if needed, waits for its reaper (at most
    /// `power_s + shutdown_s + 5` s) and forgets the run. Never deletes
    /// files. Fails, keeping the run, when the exit was not confirmed: the
    /// store must not remove the dir under a live VMM.
    fn destroy(&self, h: &VmHandle) -> Result<(), VmmError> {
        let until = Instant::now() + BOOT_WAIT;
        while matches!(self.runs().get(&h.id), Some(Slot::Starting { .. })) {
            if Instant::now() >= until {
                return Err(VmmError::Failed("the VM is still booting".into()));
            }
            std::thread::sleep(POLL);
        }
        if !matches!(self.status(h), VmStatus::Off | VmStatus::Gone) {
            self.stop(h)?;
        }
        let e = {
            let mut g = self.runs();
            match g.remove(&h.id) {
                Some(Slot::Run(e)) => e,
                Some(other) => {
                    g.insert(h.id.clone(), other);
                    return Err(VmmError::Failed("the VM is booting".into()));
                }
                None => return Ok(()),
            }
        };
        let s = self.inner.stop;
        let until = Instant::now() + Duration::from_secs(s.power_s + s.shutdown_s + 5);
        while !e.run.done() {
            if Instant::now() >= until {
                log(&h.id, "the VMM has not stopped yet");
                self.runs().entry(h.id.clone()).or_insert(Slot::Run(e));
                return Err(VmmError::Failed("the VMM has not stopped yet".into()));
            }
            std::thread::sleep(POLL);
        }
        if !e.run.off()
            && !matches!(
                self.inner.status_of(&h.id, &e.run.paths),
                VmStatus::Off | VmStatus::Gone
            )
        {
            self.runs().entry(h.id.clone()).or_insert(Slot::Run(e));
            return Err(VmmError::Failed(
                "the VMM did not stop; it may still be running".into(),
            ));
        }
        let _ = e.reaper.join();
        Ok(())
    }
}
