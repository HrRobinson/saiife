//! `ChVmm`: plan 34's `Vmm` over Cloud Hypervisor. Ported from the spike's
//! `vm.sh`: `ch_launch` (the API socket wait and the early-exit check),
//! `ch_stop` (power button, then `vmm.shutdown`, then a bound) and
//! `ch_restore` (a restored VM starts paused and is resumed).
//!
//! Locking: one `Mutex` (the run map), never held across an API call, a
//! wait, a launcher call or a hook call. Each booted run has a reaper thread
//! that owns the run's state through an `Arc`, runs the stop ladder, and is
//! the only caller of the hooks' `after_off` for that run.

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
    /// Set by the reaper after `after_off`.
    done: AtomicBool,
}

struct Entry {
    run: Arc<Run>,
    stop_tx: Sender<()>,
    reaper: JoinHandle<()>,
}

pub struct ChVmm {
    inner: Arc<ChVmmInit>,
    runs: Mutex<BTreeMap<BoxId, Entry>>,
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
fn remove_sockets(paths: &BoxPaths) {
    let _ = std::fs::remove_file(paths.api_sock());
    let _ = std::fs::remove_file(paths.vsock());
    let Ok(rd) = std::fs::read_dir(&paths.dir) else {
        return;
    };
    for e in rd.flatten() {
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

    /// Whether the VMM has exited: the launcher's word for its own process,
    /// else (no process of ours) the API socket refusing.
    fn exited(&self, id: &BoxId, paths: &BoxPaths) -> bool {
        match self.launcher.exited(id) {
            Some(x) => x,
            None => matches!(Api::new(paths.api_sock()).ping(), Err(ApiError::NoSocket)),
        }
    }

    fn wait_exit(&self, run: &Run, until: Instant) -> bool {
        loop {
            if self.exited(&run.id, &run.paths) {
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

    /// Status of a VM with no run in this process (e.g. after a daemon
    /// restart): ask the API. `vm.json` tells a known box from a gone one.
    fn status_unknown(&self, paths: &BoxPaths) -> VmStatus {
        match Api::new(paths.api_sock()).state() {
            Ok(s) => map_state(s),
            Err(ApiError::NoSocket) => {
                if paths.vm_json().exists() {
                    VmStatus::Off
                } else {
                    VmStatus::Gone
                }
            }
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
        if self.exited(&run.id, &run.paths) {
            return;
        }
        let t1 = Instant::now();
        match api.put(Action::ShutdownVmm, None, CALL_TIMEOUT) {
            Ok(()) => {
                if self.wait_exit(run, t1 + Duration::from_secs(self.stop.shutdown_s)) {
                    return;
                }
            }
            Err(e) => {
                log(&run.id, &format!("vmm.shutdown: {}", api_text(&e)));
                if self.wait_exit(run, t1 + Duration::from_secs(self.stop.shutdown_s)) {
                    return;
                }
            }
        }
        log(&run.id, "the VMM did not stop; force-stopping it");
        if let Err(e) = self.launcher.force_stop(&run.id) {
            log(&run.id, &format!("force stop: {e}"));
        }
    }

    /// The reaper: watch for the exit (or a stop request), run the ladder,
    /// then `after_off` once and remove the sockets.
    fn reap(&self, run: &Run, rx: &Receiver<()>, stopping: bool) {
        if !stopping {
            loop {
                if self.exited(&run.id, &run.paths) {
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
        let off = self.exited(&run.id, &run.paths);
        self.after_off(&run.id);
        if off {
            remove_sockets(&run.paths);
        } else {
            log(
                &run.id,
                "the VMM may still be running; its sockets are kept",
            );
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
}

impl ChVmm {
    pub fn new(init: ChVmmInit) -> ChVmm {
        ChVmm {
            inner: Arc::new(init),
            runs: Mutex::new(BTreeMap::new()),
        }
    }

    fn runs(&self) -> std::sync::MutexGuard<'_, BTreeMap<BoxId, Entry>> {
        self.runs.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn run_of(&self, id: &BoxId) -> Option<Arc<Run>> {
        self.runs().get(id).map(|e| Arc::clone(&e.run))
    }

    fn spawn_reaper(&self, id: &BoxId, paths: BoxPaths, stopping: bool) -> Result<Entry, VmmError> {
        let run = Arc::new(Run {
            id: id.clone(),
            paths,
            done: AtomicBool::new(false),
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

    fn boot_inner(
        &self,
        h: &VmHandle,
        paths: &BoxPaths,
        spec: &LaunchSpec,
    ) -> Result<(), VmmError> {
        let inner = &self.inner;
        let id = &h.id;
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
        if let Err(e) = inner.launcher.start(id, paths) {
            inner.unwind(id, paths, false);
            return Err(VmmError::Failed(e));
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
        if spec.restore {
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
        let ls = LaunchSpec {
            version: 1,
            id: spec.id.clone(),
            vcpus: spec.size.vcpus,
            mem_mib: spec.size.mem_mib,
            base: image.raw.clone(),
            repo: paths.repo_disk().exists(),
            boot: image.boot.clone(),
            landlock: inner.landlock,
            restore: paths.snapshot_dir().join("config.json").exists(),
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

    /// Runs the hooks, starts the VMM, waits for its API socket (resuming a
    /// restored VM) and returns; the guest's readiness arrives later.
    fn boot(&self, h: &VmHandle) -> Result<(), VmmError> {
        let paths = self.inner.paths(&h.id);
        let old = {
            let mut g = self.runs();
            match g.get(&h.id) {
                Some(e) if !e.run.done.load(Ordering::SeqCst) => {
                    return Err(VmmError::Failed("the VM is already running".into()));
                }
                _ => g.remove(&h.id),
            }
        };
        if let Some(e) = old {
            let _ = e.reaper.join(); // done: returns at once
        }
        if matches!(
            self.inner.status_unknown(&paths),
            VmStatus::Running | VmStatus::Paused | VmStatus::Created
        ) {
            return Err(VmmError::Failed("the VM is already running".into()));
        }
        let spec = read_spec(&paths).map_err(VmmError::Failed)?;
        self.boot_inner(h, &paths, &spec)?;
        match self.spawn_reaper(&h.id, paths.clone(), false) {
            Ok(e) => {
                self.runs().insert(h.id.clone(), e);
                Ok(())
            }
            Err(e) => {
                self.inner.unwind(&h.id, &paths, true);
                Err(e)
            }
        }
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
    /// escalates (`StopTimes`).
    fn stop(&self, h: &VmHandle) -> Result<(), VmmError> {
        {
            let g = self.runs();
            if let Some(e) = g.get(&h.id) {
                if !e.run.done.load(Ordering::SeqCst) {
                    let _ = e.stop_tx.send(());
                }
                return Ok(());
            }
        }
        // Not ours (a daemon restart): stop it through the API alone.
        let paths = self.inner.paths(&h.id);
        if matches!(
            self.inner.status_unknown(&paths),
            VmStatus::Off | VmStatus::Gone
        ) {
            return Ok(());
        }
        let mut g = self.runs();
        if !g.contains_key(&h.id) {
            let e = self.spawn_reaper(&h.id, paths, true)?;
            g.insert(h.id.clone(), e);
        }
        Ok(())
    }

    /// The exception to the trait's one-second rule: CH writes the whole
    /// guest memory, bounded by `Api::snapshot`'s 120 s.
    fn snapshot(&self, h: &VmHandle, dest: &Path) -> Result<(), VmmError> {
        let paths = self.inner.paths(&h.id);
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
        match std::fs::remove_dir_all(dest) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(VmmError::Failed(format!("remove the old snapshot: {e}"))),
        }
        api.snapshot(dest).map_err(failed_api)
    }

    fn status(&self, h: &VmHandle) -> VmStatus {
        let Some(run) = self.run_of(&h.id) else {
            return self.inner.status_unknown(&self.inner.paths(&h.id));
        };
        if run.done.load(Ordering::SeqCst) || self.inner.launcher.exited(&h.id) == Some(true) {
            return VmStatus::Off;
        }
        match Api::new(run.paths.api_sock()).state() {
            Ok(s) => map_state(s),
            Err(ApiError::NoSocket | ApiError::Timeout) => {
                if self.inner.exited(&run.id, &run.paths) {
                    VmStatus::Off
                } else {
                    VmStatus::Running
                }
            }
            Err(_) => VmStatus::Running,
        }
    }

    /// Stops the VM if needed, waits for its reaper (at most
    /// `power_s + shutdown_s + 5` s) and forgets the run. Never deletes files.
    fn destroy(&self, h: &VmHandle) -> Result<(), VmmError> {
        if !matches!(self.status(h), VmStatus::Off | VmStatus::Gone) {
            self.stop(h)?;
        }
        let Some(e) = self.runs().remove(&h.id) else {
            return Ok(());
        };
        let s = self.inner.stop;
        let until = Instant::now() + Duration::from_secs(s.power_s + s.shutdown_s + 5);
        while !e.run.done.load(Ordering::SeqCst) {
            if Instant::now() >= until {
                log(&h.id, "the reaper did not finish; leaving it running");
                return Ok(());
            }
            std::thread::sleep(POLL);
        }
        let _ = e.reaper.join();
        Ok(())
    }
}
