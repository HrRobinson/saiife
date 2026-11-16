//! The `box.*` ops on the control socket (plan 34, Task 8) over the box
//! manager of `saiife-boxes`, and its 5 s tick.
//!
//! [`build`] gives the manager: on the fake VM in a `fake-vmm` build with
//! `SAIIFE_BOX_FAKE_VMM=1` (tests), else on Linux in a `boxes` build the
//! Cloud Hypervisor driver once the box preflight passed (plan 35; `boxes`
//! is off by default and in every release until plan 41, R38). Without a manager every
//! op answers `unavailable`, with the failed check's detail when there is
//! one.
//!
//! Each op checks its arguments (`BoxId::parse`, `check_text`) before the
//! manager is called, and every manager call runs in `spawn_blocking` (the
//! manager holds its lock across VMM and guest calls). A peer that is not the
//! box's owner, root or an `[admin] groups` member gets `not_found` for it,
//! the answer of a missing id (B8). Under lockdown `all`, the ops that give a
//! box power (spawn, resume, revise, steer) are refused with a deny record;
//! the ones that take it away stay allowed, and the tick admits no queued
//! box and sends no prompt a `Ready` held (R30). Every change is a `box` record
//! with `extra = {action, box, template, from, to, via}` and `session =
//! "box-<id>"`.
//!
//! Real boxes (plan 38) have the guest channel as the manager's guest: its
//! events reach the manager through [`start_event_forwarder`] (`via:
//! "guest"`), a box restored from its kept snapshot runs without a `Ready`
//! once the channel says it is back (`via: "restore"`, R14), and a box the
//! boot timeout ends keeps its guest's last error (R2).

use crate::ops::{Conn, Ctx, Mode};
use saiife_audit::{DecisionKind, Record};
use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::guest::GuestEvent;
use saiife_boxes::manager::{Change, Manager, SpawnArgs, MAX_REPO_BYTES};
use saiife_boxes::source::{info, LandBook, ManagerSource};
use saiife_boxes::store::BoxRecord;
use saiife_boxes::template::{TemplateWarning, Trust};
use saiife_boxes::{BoxError, BoxId, BoxState};
use saiife_broker::pipeline::LockScope;
use saiife_ipc::msg::{
    err, err_with, ok, ErrorCode, Request, OP_BOX_DIFF, OP_BOX_DISCARD, OP_BOX_DONE, OP_BOX_GC,
    OP_BOX_LIST, OP_BOX_PAUSE, OP_BOX_REORDER, OP_BOX_RESUME, OP_BOX_REVISE, OP_BOX_SPAWN,
    OP_BOX_STEER, OP_BOX_STOP, OP_BOX_TEMPLATES, OP_BOX_TERM_READ,
};
use saiife_ipc::peer::PeerCred;
use saiife_wire::source::{check_text, BoxSource, Start, MAX_STEER_BYTES, MAX_TASK_BYTES};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The daemon's tick of the box manager.
pub const TICK_SECS: u64 = 5;
/// The answer of every box op when there is no manager.
pub const UNAVAILABLE: &str = "boxes are not available in this version";
/// Why a Linux build without the `boxes` feature has no boxes (R38).
pub const NOT_ENABLED: &str = "boxes are not enabled in this build";
/// Set to `1` (in a `fake-vmm` build) to run boxes on the fake VM.
pub const FAKE_ENV: &str = "SAIIFE_BOX_FAKE_VMM";
/// With [`FAKE_ENV`] (a `fake-vmm` build only): `<n>` pins the host to
/// exactly `n` default boxes, so a test never depends on the machine's RAM.
pub const FAKE_SLOTS_ENV: &str = "SAIIFE_BOX_FAKE_SLOTS";
/// Why the tick paused a box when the boxes filesystem ran low.
pub const DISK_LOW_WHY: &str = "paused: the host disk is almost full";
/// With [`FAKE_ENV`] (a `fake-vmm` build only): a JSON array of terminal
/// frames (at most 64 KiB) the fake guest serves for box `b1` (the CLI tests
/// cannot reach the daemon's `FakeGuest`).
#[cfg(feature = "fake-vmm")]
pub const FAKE_TERMINAL_ENV: &str = "SAIIFE_BOX_FAKE_TERMINAL";
/// The most bytes of [`FAKE_TERMINAL_ENV`] parsed.
#[cfg(feature = "fake-vmm")]
const FAKE_TERMINAL_MAX: usize = 64 * 1024;
/// The stderr line of a daemon whose boxes run on the fake VM.
pub const FAKE_NOTICE: &str = "saiifed: boxes use a fake VM (test build)";
/// What a `box.spawn` was passed (plan 37): the repo disk and its base
/// manifest. Descriptors pass on unix only.
#[cfg(unix)]
type Passed = Vec<std::os::fd::OwnedFd>;
#[cfg(not(unix))]
type Passed = Vec<()>;

/// The longest template name and `repo_dir` taken.
const MAX_TEMPLATE_BYTES: usize = 64;
const MAX_REPO_DIR_BYTES: usize = 4096;

/// The ops [`handle`] serves.
pub const OPS: &[&str] = &[
    OP_BOX_SPAWN,
    OP_BOX_LIST,
    OP_BOX_TEMPLATES,
    OP_BOX_PAUSE,
    OP_BOX_STOP,
    OP_BOX_DISCARD,
    OP_BOX_DONE,
    OP_BOX_RESUME,
    OP_BOX_REVISE,
    OP_BOX_STEER,
    OP_BOX_REORDER,
    OP_BOX_GC,
    OP_BOX_DIFF,
    OP_BOX_TERM_READ,
    // The base images (plan 36): `crate::box_images`.
    saiife_ipc::msg::OP_BOX_IMAGE_LS,
    saiife_ipc::msg::OP_BOX_IMAGE_IMPORT,
    saiife_ipc::msg::OP_BOX_IMAGE_DEFAULT,
    saiife_ipc::msg::OP_BOX_IMAGE_RM,
    // Land and push (plan 39): `crate::box_land::handle`.
    saiife_ipc::msg::OP_BOX_LAND_BEGIN,
    saiife_ipc::msg::OP_BOX_LAND,
    saiife_ipc::msg::OP_BOX_LAND_REJECT,
    saiife_ipc::msg::OP_BOX_LAND_FETCH,
    saiife_ipc::msg::OP_BOX_LAND_APPLIED,
    saiife_ipc::msg::OP_BOX_PUSH_BEGIN,
    saiife_ipc::msg::OP_BOX_PUSH,
    saiife_ipc::msg::OP_BOX_PUSH_DONE,
];

/// The ops of [`OPS`] the land book serves (plan 39).
const LAND_OPS: &[&str] = &[
    saiife_ipc::msg::OP_BOX_LAND_BEGIN,
    saiife_ipc::msg::OP_BOX_LAND,
    saiife_ipc::msg::OP_BOX_LAND_REJECT,
    saiife_ipc::msg::OP_BOX_LAND_FETCH,
    saiife_ipc::msg::OP_BOX_LAND_APPLIED,
    saiife_ipc::msg::OP_BOX_PUSH_BEGIN,
    saiife_ipc::msg::OP_BOX_PUSH,
    saiife_ipc::msg::OP_BOX_PUSH_DONE,
];

/// `<state_dir>/boxes`: the box records, the daemon's own in both modes
/// (R37). The VMM's runtime dirs are `saiife_boxhost::layout::Layout.boxes`.
pub fn dir_in(state_dir: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        saiife_boxhost::layout::boxes_in(state_dir)
    }
    // No boxes off Unix (no box host crate there); the same path.
    #[cfg(not(unix))]
    {
        state_dir.join("boxes")
    }
}

/// Where spawn moves a box's repo disk and base manifest: the box's record
/// dir under the store root ([`saiife_boxhost::layout::record_disk_place`],
/// R37/R40). The real driver hands the disk on to its runtime dir at
/// create; the manifest stays. `None` off Unix, where a box takes no repo
/// disk.
pub fn disk_place() -> Option<saiife_boxes::manager::DiskPlacer> {
    #[cfg(unix)]
    {
        Some(Arc::new(|root: &Path, id: &BoxId| {
            saiife_boxhost::layout::record_disk_place(root, id)
        }))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Where box templates come from (B11). Locked: `<dir of config_path>/templates.d`,
/// root's files only. Personal: `$XDG_CONFIG_HOME/saiife/templates.d` (an absolute
/// `XDG_CONFIG_HOME`, else `$HOME/.config`), the user's own files only; with
/// neither, beside `config_path`. Never a project directory.
pub fn templates_dir(
    mode: &Mode,
    config_path: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> (PathBuf, Trust) {
    let beside_config = || {
        config_path
            .parent()
            .unwrap_or(Path::new("/"))
            .join("templates.d")
    };
    match mode {
        Mode::Locked => (beside_config(), Trust::RootOwned),
        Mode::Personal => {
            let abs = |k: &str| {
                env(k)
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
                    .filter(|p| p.is_absolute())
            };
            let dir = abs("XDG_CONFIG_HOME")
                .or_else(|| abs("HOME").map(|h| h.join(".config")))
                .map(|c| c.join("saiife").join("templates.d"))
                .unwrap_or_else(beside_config);
            (dir, Trust::OwnedBy(crate::fsx::process_uid()))
        }
    }
}

/// A live sample of the host for admission. Linux: `/proc/meminfo`
/// (`MemTotal`, `MemAvailable`), `available_parallelism`, `statvfs` of the
/// boxes dir (its nearest existing ancestor) and the CPU use since the last
/// sample (`/proc/stat`; `None` on the first). Anything unreadable is 0, so
/// nothing fits rather than too much. Elsewhere: nothing fits.
#[cfg(target_os = "linux")]
pub fn host_facts(boxes_dir: &Path, prev_cpu: &Mutex<Option<(u64, u64)>>) -> HostFacts {
    let mem = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mib = |name: &str| meminfo_kib(&mem, name).map_or(0, |k| k / 1024);
    let threads = std::thread::available_parallelism()
        .map_or(0, |n| u32::try_from(n.get()).unwrap_or(u32::MAX));
    let disk_free_mib = boxes_dir
        .ancestors()
        .find(|p| p.exists())
        .and_then(|p| rustix::fs::statvfs(p).ok())
        .map_or(0, |st| {
            st.f_bavail.saturating_mul(st.f_frsize) / (1024 * 1024)
        });
    let now = std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| cpu_times(&s));
    let cpu_pct = {
        let mut prev = prev_cpu.lock().unwrap_or_else(|p| p.into_inner());
        let pct = match (*prev, now) {
            (Some(a), Some(b)) => cpu_pct(a, b),
            _ => None,
        };
        if now.is_some() {
            *prev = now;
        }
        pct
    };
    HostFacts {
        mem_total_mib: mib("MemTotal"),
        mem_avail_mib: mib("MemAvailable"),
        threads,
        disk_free_mib,
        cpu_pct,
    }
}

/// Not Linux: no host facts, so nothing fits.
#[cfg(not(target_os = "linux"))]
pub fn host_facts(boxes_dir: &Path, prev_cpu: &Mutex<Option<(u64, u64)>>) -> HostFacts {
    let _ = (boxes_dir, prev_cpu);
    HostFacts::default()
}

/// `name:   123 kB` of `/proc/meminfo`, in KiB.
#[cfg(any(target_os = "linux", test))]
fn meminfo_kib(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let rest = l.strip_prefix(name)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

/// `(total, idle)` jiffies of the `cpu` line of `/proc/stat` (idle counts
/// iowait).
#[cfg(any(target_os = "linux", test))]
fn cpu_times(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|x| x.parse().ok())
        .collect::<Option<_>>()?;
    if v.len() < 4 {
        return None;
    }
    let idle = v[3].saturating_add(v.get(4).copied().unwrap_or(0));
    Some((v.iter().fold(0u64, |a, x| a.saturating_add(*x)), idle))
}

/// The busy share between two samples, 0..=100.
#[cfg(any(target_os = "linux", test))]
fn cpu_pct(a: (u64, u64), b: (u64, u64)) -> Option<u8> {
    let total = b.0.checked_sub(a.0)?;
    let idle = b.1.checked_sub(a.1)?;
    if total == 0 {
        return None;
    }
    let busy = total.saturating_sub(idle);
    u8::try_from(busy.saturating_mul(100) / total).ok()
}

/// What [`build`] made: the manager, the start warnings (store, recovery,
/// templates) for stderr, the template warnings `box.templates` shows, the
/// recovery's state changes, which the daemon records with its start
/// records ([`change_records`], R29), and the link the driver's audit hook
/// writes through once the context exists ([`AuditLink::attach`]).
pub struct Built {
    pub manager: Arc<Manager>,
    pub warnings: Vec<String>,
    pub template_warnings: Vec<TemplateWarning>,
    pub changes: Vec<Change>,
    pub audit: Arc<AuditLink>,
    /// The manager runs on the fake VM (a `fake-vmm` test build).
    pub fake: bool,
    /// Where the boxes' disks are, for `box.list`'s `disk_mib`: the
    /// driver's runtime root (`Layout.boxes`, R37) on the real path, the
    /// record root on the fake VM.
    pub disk_root: PathBuf,
    /// Real boxes only: what is wired once the daemon context exists (the
    /// box gateway's hook, the guest event forwarder). Call it with the
    /// context and the daemon's runtime before any box can boot.
    pub on_ctx: Option<OnCtx>,
}

/// The box image store's dirs (plan 36) when this build and mode have
/// boxes, whether or not the box manager came up: an import is how a host
/// without a default image gets one. Records: `box_images::paths_for`
/// (the daemon's own); images: the box layout's (`box_vmm::layout_for`,
/// which honours the debug-only `SAIIFE_TEST_BOX_ROOT`), so the preflight,
/// the driver and the image ops agree. The fake VM has no VMM user: its
/// image store stays under the state dir in both modes (records
/// `<state>/image-records`, images `<state>/images`), as its boxes do, so a
/// locked test daemon never touches the host's install. `None` without
/// boxes.
pub fn image_paths(
    state_dir: &Path,
    mode: &Mode,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Option<crate::box_images::ImagePaths> {
    #[cfg(feature = "fake-vmm")]
    if env(FAKE_ENV).as_deref() == Some(std::ffi::OsStr::new("1")) {
        return Some(crate::box_images::paths_for(state_dir, &Mode::Personal));
    }
    #[cfg(all(target_os = "linux", feature = "boxes"))]
    {
        let layout = crate::box_vmm::layout_for(state_dir, mode, env).ok()?;
        Some(crate::box_images::ImagePaths {
            records: crate::box_images::paths_for(state_dir, mode).records,
            images: layout.images,
        })
    }
    #[cfg(not(all(target_os = "linux", feature = "boxes")))]
    {
        let _ = (state_dir, mode, env);
        None
    }
}

/// See [`Built::on_ctx`].
pub type OnCtx = Box<dyn FnOnce(&Arc<Ctx>, &tokio::runtime::Handle) + Send>;

/// The box manager, or why boxes are unavailable (`Ok(Err(why))`): (1) a
/// `fake-vmm` build with `SAIIFE_BOX_FAKE_VMM=1` runs on the fake VM;
/// (2) otherwise, on Linux, the real driver once the preflight
/// (`saiife_boxhost::preflight`) passed, whose first failure is the why;
/// (3) elsewhere [`UNAVAILABLE`]. `Err` when the box state cannot be opened.
///
/// Locked mode talks to the system bus, which needs the daemon's runtime
/// driven by another thread: call this on a `spawn_blocking` thread.
pub fn build(
    state_dir: &Path,
    mode: &Mode,
    config_path: &Path,
) -> Result<Result<Built, String>, String> {
    build_with(state_dir, mode, config_path, &|k| std::env::var_os(k))
}

/// [`build`] with the environment as a function (tests).
pub fn build_with(
    state_dir: &Path,
    mode: &Mode,
    config_path: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Result<Built, String>, String> {
    #[cfg(feature = "fake-vmm")]
    if env(FAKE_ENV).as_deref() == Some(std::ffi::OsStr::new("1")) {
        return build_fake(state_dir, mode, config_path, env).map(Ok);
    }
    build_real(state_dir, mode, config_path, env)
}

/// The preflight, then `ChVmm` (personal: a child of the daemon; locked:
/// the `saiife-box-<tier>@` unit) with the guest channel ([`VsockGuest`], plan 38)
/// as the manager's guest and, as VMM hooks, the audit hook, the box
/// gateway (filled late by [`Built::on_ctx`]: it needs the daemon context;
/// until then every boot fails) and the guest channel. Only in a build with
/// the `boxes` feature (R38).
///
/// [`VsockGuest`]: saiife_boxhost::guest::VsockGuest
#[cfg(all(target_os = "linux", feature = "boxes"))]
fn build_real(
    state_dir: &Path,
    mode: &Mode,
    config_path: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Result<Built, String>, String> {
    use crate::box_setup::{cast_path, packs_dir, LateHooks, TemplateSetup};
    use saiife_boxes::store::Store;
    use saiife_boxhost::guest::VsockGuest;
    use saiife_boxhost::preflight;
    use saiife_boxhost::vmm::VmHooks;

    let layout = match crate::box_vmm::layout_for(state_dir, mode, env) {
        Ok(l) => l,
        Err(why) => return Ok(Err(why)),
    };
    let tools = saiife_boxhost::tools::Tools::system(&layout.vmm).with_env(env);
    // the image store's daemon-only half (plan 36 R24); its disks are
    // `layout.images`
    let image_records = crate::box_images::paths_for(state_dir, mode).records;
    let checks = preflight::checks(
        &layout,
        &image_records,
        &tools,
        &crate::box_vmm::kvm_path(env),
        saiife_system::sandbox::landlock_abi(),
    );
    if let Err(why) = preflight::ready(&checks) {
        return Ok(Err(why));
    }
    let vmm_uid = match crate::box_vmm::vmm_uid(&layout, mode) {
        Ok(u) => u,
        Err(why) => return Ok(Err(why)),
    };
    // records in the daemon's own state dir, runtime dirs in the layout
    // (R37): nothing the VMM can write is ever read as a record, and the
    // terminal recording goes beside the record (R15)
    let records = dir_in(state_dir);
    let cast_store = Store::open(records.clone()).map_err(|e| e.to_string())?;
    let setups = TemplateSetup::new(packs_dir(config_path));
    let guest = VsockGuest::with_cast_path(
        setups.clone(),
        *mode == Mode::Locked,
        vmm_uid,
        cast_path(cast_store),
    );
    let audit = Arc::new(AuditLink::default());
    let gateway = LateHooks::new();
    let hooks: Vec<Arc<dyn VmHooks>> = vec![
        Arc::new(crate::box_vmm::AuditHooks::new(Arc::clone(&audit))),
        gateway.clone(),
        guest.clone(),
    ];
    let vmm =
        match crate::box_vmm::real_vmm_with(&layout, &records, &image_records, mode, hooks, env) {
            Ok(v) => v,
            Err(why) => return Ok(Err(why)),
        };
    let store = Store::open(records).map_err(|e| e.to_string())?;
    // the disks are in the runtime dirs
    let root = layout.boxes.clone();
    let prev = Mutex::new(None);
    let disk_root = root.clone();
    let mut built = open_manager(
        store,
        vmm,
        guest.clone(),
        Arc::new(move || host_facts(&root, &prev)),
        (mode, config_path, env),
        (audit, false, disk_root),
    )?;
    setups.attach(&built.manager);
    built.on_ctx = Some(Box::new(move |ctx, rt| {
        use crate::box_gateway::{GatewayConfig, GatewayHooks, SystemResolve};
        let hooks = GatewayHooks::new(
            Arc::clone(ctx),
            rt.clone(),
            Arc::new(SystemResolve::new()),
            GatewayConfig::default(),
        );
        gateway.fill(hooks);
        let _in_rt = rt.enter();
        start_event_forwarder(Arc::clone(ctx), guest);
    }));
    Ok(Ok(built))
}

/// Without real boxes: plan 34's answer; on Linux it says the build has
/// them off (R38: `boxes` is off until plan 41 ships).
#[cfg(not(all(target_os = "linux", feature = "boxes")))]
fn build_real(
    state_dir: &Path,
    mode: &Mode,
    config_path: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Result<Built, String>, String> {
    let _ = (state_dir, mode, config_path, env);
    if cfg!(target_os = "linux") {
        Ok(Err(format!("{UNAVAILABLE} ({NOT_ENABLED})")))
    } else {
        Ok(Err(UNAVAILABLE.into()))
    }
}

/// The environment as a function.
type EnvFn<'a> = &'a dyn Fn(&str) -> Option<OsString>;

/// The manager over `store` and `vmm`, with the mode's templates.
#[cfg_attr(
    not(any(all(target_os = "linux", feature = "boxes"), feature = "fake-vmm")),
    allow(dead_code)
)]
fn open_manager(
    store: saiife_boxes::store::Store,
    vmm: Arc<dyn saiife_boxes::vmm::Vmm>,
    guest: Arc<dyn saiife_boxes::guest::GuestLink>,
    host: saiife_boxes::manager::HostProbe,
    (mode, config_path, env): (&Mode, &Path, EnvFn<'_>),
    (audit, fake, disk_root): (Arc<AuditLink>, bool, PathBuf),
) -> Result<Built, String> {
    use saiife_boxes::manager::ManagerInit;

    let (tdir, trust) = templates_dir(mode, config_path, env);
    let (templates, template_warnings) = saiife_boxes::template::load_dir(&tdir, trust);
    let opened = Manager::open(ManagerInit {
        store,
        vmm,
        guest,
        templates,
        host,
        clock: Arc::new(unix_now),
        disk_place: disk_place(),
    })
    .map_err(|e| e.to_string())?;
    let mut warnings = opened.warnings;
    warnings.extend(
        template_warnings
            .iter()
            .map(|w| format!("template {}: {}", w.file.display(), w.reason)),
    );
    Ok(Built {
        manager: Arc::new(opened.manager),
        warnings,
        template_warnings,
        changes: opened.changes,
        audit,
        fake,
        disk_root,
        on_ctx: None,
    })
}

/// Plan 34's fake VM and guest. The fake VM has no VMM user, so its boxes
/// stay under `<state>/boxes` in both modes (as before plan 35).
#[cfg(feature = "fake-vmm")]
fn build_fake(
    state_dir: &Path,
    mode: &Mode,
    config_path: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Built, String> {
    use saiife_boxes::guest::fake::FakeGuest;
    use saiife_boxes::store::Store;
    use saiife_boxes::vmm::fake::FakeVmm;

    let root = dir_in(state_dir);
    let store = Store::open(root.clone()).map_err(|e| e.to_string())?;
    let disk_root = root.clone();
    let prev = Mutex::new(None);
    let pinned = env(FAKE_SLOTS_ENV)
        .and_then(|v| v.to_str().and_then(|s| s.parse::<u64>().ok()))
        .map(fake_host);
    let guest = Arc::new(FakeGuest::new());
    if let Some(frames) = env(FAKE_TERMINAL_ENV)
        .and_then(|v| v.to_str().map(str::to_string))
        .filter(|s| s.len() <= FAKE_TERMINAL_MAX)
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        if let Ok(b1) = saiife_wire::source::BoxId::parse("b1") {
            guest.set_terminal(&b1, frames);
        }
    }
    open_manager(
        store,
        Arc::new(FakeVmm::new()),
        guest,
        Arc::new(move || match &pinned {
            Some(h) => *h,
            None => host_facts(&root, &prev),
        }),
        (mode, config_path, env),
        (Arc::new(AuditLink::default()), true, disk_root),
    )
}

/// Where the driver's audit hook writes (R36): the daemon context, attached
/// once it exists. Never takes the box manager's lock and never asks the
/// manager anything (it runs inside the manager's VMM calls): the record is
/// made from the box id alone and written by a runtime task.
///
/// Before [`AuditLink::attach`] there is no context: a `restore_refused`
/// during `Manager::open`'s recovery (which runs inside [`build`], before
/// the daemon context exists) is only a stderr line, never an audit record
/// (M-3). `Manager::open` boots nothing, so a refusal at a restoring boot
/// comes after the attach and is recorded.
#[derive(Default)]
pub struct AuditLink {
    ctx: Mutex<std::sync::Weak<Ctx>>,
}

impl AuditLink {
    pub fn attach(&self, ctx: &Arc<Ctx>) {
        *self.ctx.lock().unwrap_or_else(|p| p.into_inner()) = Arc::downgrade(ctx);
    }

    /// A `box` record `restore_refused` (`via: "vmm"`, `reason` = why,
    /// sanitized). Called from a runtime's blocking thread (every manager
    /// call is); without a context or a runtime it is a stderr line.
    pub fn restore_refused(&self, id: &BoxId, why: &str) {
        let why = saiife_audit::text::sanitize(why);
        let ctx = self.ctx.lock().unwrap_or_else(|p| p.into_inner()).upgrade();
        let (Some(ctx), Ok(rt)) = (ctx, tokio::runtime::Handle::try_current()) else {
            eprintln!(
                "saiifed: boxes: {}: snapshot not restored: {why}",
                id.as_str()
            );
            return;
        };
        let mut rec = box_rec(&ctx, "restore_refused", Some(id), None, None, None, "vmm");
        rec.reason = Some(why);
        rt.spawn(async move {
            if let Err(e) = ctx.writer.append(rec).await {
                eprintln!("saiifed: warning: cannot write a box record: {e}");
            }
        });
    }
}

/// A host that holds exactly `n` default boxes (`SAIIFE_BOX_FAKE_SLOTS`).
#[cfg(feature = "fake-vmm")]
pub fn fake_host(n: u64) -> HostFacts {
    let mem = 8192
        + n.saturating_mul(capacity::charge_mib(
            &saiife_boxes::template::Size::default(),
        ));
    HostFacts {
        mem_total_mib: mem,
        mem_avail_mib: mem,
        threads: 12,
        disk_free_mib: 1024 * 1024,
        cpu_pct: None,
    }
}

#[cfg_attr(
    not(any(all(target_os = "linux", feature = "boxes"), feature = "fake-vmm")),
    allow(dead_code)
)]
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Run the manager's tick every [`TICK_SECS`] and record its changes. The
/// task holds the context weakly and ends with it. No manager, no task.
pub fn start_tick(ctx: Arc<Ctx>) {
    if ctx.box_manager.is_none() {
        return;
    }
    let weak = Arc::downgrade(&ctx);
    drop(ctx);
    tokio::spawn(async move {
        let every = Duration::from_secs(TICK_SECS);
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(ctx) = weak.upgrade() else { break };
            tick_once(&ctx).await;
            #[cfg(feature = "fake-vmm")]
            fake_ready(&ctx).await;
        }
    });
}

/// The fake VM "boots" at once: its guest says `Ready` for every box that
/// is Starting, at the next tick (there is no guest process to say it). Test
/// builds only; the CLI tests need a Running box. Each goes through
/// [`guest_event`], so lockdown holds the prompt here too.
#[cfg(feature = "fake-vmm")]
async fn fake_ready(ctx: &Ctx) {
    let Some(mgr) = ctx.box_manager.clone() else {
        return;
    };
    let starting = tokio::task::spawn_blocking(move || {
        mgr.list()
            .into_iter()
            // a fake-vmm build that runs the real driver has no fake guest
            .filter(|r| r.vm.as_ref().is_some_and(|h| h.driver == "fake"))
            .filter(|r| r.state == BoxState::Starting)
            .map(|r| r.id)
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    for id in starting {
        let _ = guest_event(ctx, id, GuestEvent::Ready).await;
    }
}

/// Where the forwarder reads guest events from: the guest channel
/// (`saiife_boxhost::guest::VsockGuest`) of real boxes, a stub in tests.
pub trait GuestEvents: Send + Sync + 'static {
    /// Waits up to `timeout` for events, then returns all queued ones.
    fn recv_events(&self, timeout: Duration) -> Vec<(BoxId, GuestEvent)>;
}

/// The forwarder's wait for events per round.
pub const FORWARD_WAIT: Duration = Duration::from_secs(1);
/// What a box's error says when its agent exited before it was ready.
pub const EXITED_WHILE_STARTING: &str = "the agent exited before it was ready";
/// Guest-derived text kept in a box's error, in bytes.
pub const MAX_GUEST_NOTE: usize = 512;

/// Real boxes: forward the guest channel's events to the manager, each
/// through [`guest_event`]'s rules (lockdown holds a `Ready`'s prompt, R30),
/// one `box` record (`via: "guest"`) per change. The wait runs on the
/// blocking pool; the task holds the context weakly and ends with it (or
/// with the runtime). Never beside the fake VM's `fake_ready`: the fake
/// path has no guest channel. No manager, no task.
pub fn start_event_forwarder(ctx: Arc<Ctx>, guest: Arc<dyn GuestEvents>) {
    if ctx.box_manager.is_none() {
        return;
    }
    let weak = Arc::downgrade(&ctx);
    drop(ctx);
    tokio::spawn(async move {
        loop {
            let g = Arc::clone(&guest);
            let events =
                match tokio::task::spawn_blocking(move || g.recv_events(FORWARD_WAIT)).await {
                    Ok(events) => events,
                    // the runtime is shutting down
                    Err(e) if e.is_cancelled() => {
                        eprintln!(
                        "saiifed: boxes: the guest event forwarder ended: the daemon is stopping"
                    );
                        break;
                    }
                    // a panic in the wait: one line, a pause, and on (a dead
                    // forwarder would leave every box starting until the boot
                    // timeout destroys it)
                    Err(e) => {
                        eprintln!("saiifed: boxes: the guest event wait failed ({e}); going on");
                        tokio::time::sleep(FORWARD_WAIT).await;
                        Vec::new()
                    }
                };
            let Some(ctx) = weak.upgrade() else {
                eprintln!("saiifed: boxes: the guest event forwarder ended: the daemon is gone");
                break;
            };
            for (id, ev) in events {
                forward(&ctx, id, ev).await;
            }
        }
    });
}

/// One guest event. A stale one (the box moved on or is gone) is dropped.
/// An `Exited` while the box is still starting (its agent died before it was
/// ready) stops the box instead of leaving it to the boot timeout, which
/// would destroy its VM. Since ruling R22 a fresh guest init is set up again,
/// so this is a safety net, not the cold-boot path.
async fn forward(ctx: &Ctx, id: BoxId, ev: GuestEvent) {
    match guest_event_via(ctx, id.clone(), ev, "guest").await {
        Ok(_) => {}
        Err(BoxError::WrongState {
            state: BoxState::Starting,
        }) if ev == GuestEvent::Exited => exited_while_starting(ctx, id).await,
        Err(BoxError::WrongState { .. } | BoxError::NotFound) => {}
        Err(e) => eprintln!(
            "saiifed: boxes: {}: a guest event was not taken: {e}",
            id.as_str()
        ),
    }
}

/// A starting box whose agent exited: stopped (Done, its disks kept), with
/// [`EXITED_WHILE_STARTING`] in its error and a `box` record (`via: "guest"`).
async fn exited_while_starting(ctx: &Ctx, id: BoxId) {
    let Some(mgr) = ctx.box_manager.clone() else {
        return;
    };
    let done = blocking(move || {
        // one manager step: no promotion or requeue can come in between
        let Some(c) =
            mgr.stop_if_starting(&id, EXITED_WHILE_STARTING, "agent exited while starting")?
        else {
            return Ok(None);
        };
        let template = mgr.get(&id).ok().map(|r| r.template);
        Ok(Some((c, template)))
    })
    .await;
    match done {
        Ok(Some(c)) => write_tick_records(ctx, "tick", None, vec![c], "guest").await,
        Ok(None) => {}
        Err(e) => eprintln!("saiifed: boxes: a box whose agent exited was not stopped: {e}"),
    }
}

/// Guest-derived text for a box's error: `guest: <text>`, cleaned and cut
/// to [`MAX_GUEST_NOTE`] bytes.
fn guest_note(text: &str) -> String {
    let mut t = saiife_audit::text::sanitize(text);
    if t.len() > MAX_GUEST_NOTE {
        let mut n = MAX_GUEST_NOTE;
        while !t.is_char_boundary(n) {
            n -= 1;
        }
        t.truncate(n);
    }
    format!("guest: {t}")
}

/// R14: a box booted from its kept snapshot gets no `Ready` (its guest was
/// set up before and says hello `set_up: true`). Once the guest channel
/// says it is back with its agent alive, such a starting box runs, through
/// [`guest_event`] (`via: "restore"`): its held prompt goes out unless
/// lockdown holds it. Returns how many boxes moved.
async fn promote_restored(ctx: &Ctx) -> usize {
    let Some(mgr) = ctx.box_manager.clone() else {
        return 0;
    };
    let ids = tokio::task::spawn_blocking(move || {
        let g = mgr.guest();
        mgr.list()
            .into_iter()
            .filter(|r| r.state == BoxState::Starting && r.vm_on && r.keep)
            .map(|r| r.id)
            .filter(|id| g.restored(id))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    let mut n = 0;
    for id in ids {
        if let Ok(Some(_)) = guest_event_via(ctx, id, GuestEvent::Ready, "restore").await {
            n += 1;
        }
    }
    n
}

/// What a box op answers without a manager: the failed preflight's detail,
/// else [`UNAVAILABLE`].
fn unavailable(ctx: &Ctx) -> &str {
    ctx.box_unavailable.as_deref().unwrap_or(UNAVAILABLE)
}

/// Lockdown `all`: the scheduler gives no box power (R30).
fn locked_all(ctx: &Ctx) -> bool {
    ctx.lockdown
        .get()
        .is_some_and(|l| l.scope == LockScope::All)
}

/// One event from a box's guest, and its `box` record (`via: "tick"`) when
/// it is a state change. Under lockdown `all` a `Ready` keeps the box's
/// pending prompt unsent; the first tick after lockdown lifts sends it
/// (R30). Every guest event the daemon takes comes through here.
pub async fn guest_event(ctx: &Ctx, id: BoxId, ev: GuestEvent) -> Result<Option<Change>, BoxError> {
    guest_event_via(ctx, id, ev, "tick").await
}

/// [`guest_event`] with the record's `via` (`"guest"` from the guest
/// channel, `"restore"` for a restored box).
pub async fn guest_event_via(
    ctx: &Ctx,
    id: BoxId,
    ev: GuestEvent,
    via: &'static str,
) -> Result<Option<Change>, BoxError> {
    let Some(mgr) = ctx.box_manager.clone() else {
        return Err(BoxError::Unavailable(unavailable(ctx).into()));
    };
    let prompt = !locked_all(ctx);
    let (c, template) = blocking(move || {
        let c = mgr.guest_event_with(&id, ev, prompt)?;
        let template = mgr.get(&id).ok().map(|r| r.template);
        Ok((c, template))
    })
    .await?;
    if let Some(c) = &c {
        write_tick_records(ctx, "tick", None, vec![(c.clone(), template)], via).await;
        refresh_done(ctx, std::slice::from_ref(c));
    }
    Ok(c)
}

/// One tick: the manager's tick off the runtime thread, then one `box`
/// record (`via: "tick"`) per change. Returns the number of changes. Under
/// lockdown `all` the tick only takes power away: no admission, and no
/// held prompt is sent (R30).
pub async fn tick_once(ctx: &Ctx) -> usize {
    let Some(mgr) = ctx.box_manager.clone() else {
        return 0;
    };
    let admit = !locked_all(ctx);
    let done = tokio::task::spawn_blocking(move || {
        // The floor first: the free-space read and the pauses hold no lock
        // while the host is probed; a box newly Running is paused (and
        // recorded) once, a box already Paused is not touched again.
        let low = floor_pauses(&mgr);
        let changes = mgr.tick_with(admit);
        // R2: a box the boot timeout ended keeps why its guest failed
        // (a refused hello, a failed setup), cleaned and capped.
        let guest = mgr.guest();
        let timed_out = saiife_boxes::manager::WHY_BOOT_TIMED_OUT;
        for c in changes.iter().filter(|c| c.why == timed_out) {
            if let Some(e) = guest.last_error(&c.id) {
                if let Err(e) = mgr.note_error(&c.id, &guest_note(&e)) {
                    eprintln!("saiifed: boxes: {}: {e}", c.id.as_str());
                }
            }
        }
        let changes = changes
            .into_iter()
            .map(|c| {
                let template = mgr.get(&c.id).ok().map(|r| r.template);
                (c, template)
            })
            .collect::<Vec<_>>();
        (low, changes)
    })
    .await;
    let (low, changes) = match done {
        Ok(c) => c,
        Err(e) => {
            eprintln!("saiifed: boxes: the tick did not finish: {e}");
            return 0;
        }
    };
    let n = low.len() + changes.len();
    let moved: Vec<Change> = changes.iter().map(|(c, _)| c.clone()).collect();
    write_tick_records(ctx, "disk_low", Some(DISK_LOW_WHY), low, "tick").await;
    write_tick_records(ctx, "tick", None, changes, "tick").await;
    refresh_done(ctx, &moved);
    n + promote_restored(ctx).await
}

/// Below the disk floor: pause every `Running` box with [`DISK_LOW_WHY`].
fn floor_pauses(mgr: &Manager) -> Vec<(Change, Option<String>)> {
    if !capacity::below_floor(&mgr.host_facts()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for r in mgr.list() {
        if r.state != BoxState::Running {
            continue;
        }
        match mgr.pause_for(&r.id, DISK_LOW_WHY) {
            Ok(c) => out.push((c, Some(r.template))),
            Err(e) => eprintln!(
                "saiifed: boxes: cannot pause {} on low disk: {e}",
                r.id.as_str()
            ),
        }
    }
    out
}

/// The daemon's own `box` records (`action` "tick", or "disk_low" for the
/// floor's pauses; `via` = who moved the box: `"tick"`, `"guest"`,
/// `"restore"`; `reason` = why, or `reason` when given), one per change,
/// each with the box's template when it is still known.
async fn write_tick_records(
    ctx: &Ctx,
    action: &str,
    reason: Option<&str>,
    changes: Vec<(Change, Option<String>)>,
    via: &str,
) {
    for (c, template) in changes {
        let mut rec = tick_record(ctx, action, &c, template.as_deref(), via);
        if let Some(r) = reason {
            rec.reason = Some(r.to_string());
        }
        if let Err(e) = ctx.writer.append(rec).await {
            eprintln!("saiifed: warning: cannot write a box tick record: {e}");
        }
    }
}

/// One daemon-made change as its `box` record.
fn tick_record(ctx: &Ctx, action: &str, c: &Change, template: Option<&str>, via: &str) -> Record {
    let mut rec = box_rec(
        ctx,
        action,
        Some(&c.id),
        template,
        Some(c.from),
        Some(c.to),
        via,
    );
    rec.reason = Some(c.why.to_string());
    // A queue head admitted here: the base image its VM was created from.
    if let Some(i) = &c.image {
        rec.extra.insert("image".into(), i.as_str().into());
    }
    rec
}

/// The records of the restart recovery's changes ([`Built::changes`]): the
/// same `box` records as the tick's (R29). The daemon writes them with its
/// start records, once the audit writer exists.
pub fn change_records(ctx: &Ctx, changes: &[Change]) -> Vec<Record> {
    changes
        .iter()
        .map(|c| {
            let template = ctx
                .box_manager
                .as_ref()
                .and_then(|m| m.get(&c.id).ok())
                .map(|r| r.template);
            tick_record(ctx, "tick", c, template.as_deref(), "tick")
        })
        .collect()
}

fn state_value(s: BoxState) -> Value {
    serde_json::to_value(s).unwrap_or(Value::Null)
}

/// A `box` record of `action`. The caller sets the peer.
pub(crate) fn box_rec(
    ctx: &Ctx,
    action: &str,
    id: Option<&BoxId>,
    template: Option<&str>,
    from: Option<BoxState>,
    to: Option<BoxState>,
    via: &str,
) -> Record {
    let input = match id {
        Some(i) => format!("{action} {}", i.as_str()),
        None => action.to_string(),
    };
    let mut r = ctx.record("box", &input);
    r.session = id.map(|i| format!("box-{}", i.as_str()));
    let x = &mut r.extra;
    x.insert("action".into(), action.into());
    x.insert("box".into(), id.map_or(Value::Null, |i| i.as_str().into()));
    x.insert("template".into(), template.map_or(Value::Null, Value::from));
    x.insert("from".into(), from.map_or(Value::Null, state_value));
    x.insert("to".into(), to.map_or(Value::Null, state_value));
    x.insert("via".into(), via.into());
    r
}

/// The answer to a refused op: `bad_request` with `rule` for not found,
/// wrong state and invalid; `busy`; `unavailable`.
pub(crate) fn refusal(id: u64, e: &BoxError) -> Value {
    let code = match e {
        BoxError::NotFound | BoxError::WrongState { .. } | BoxError::Invalid(_) => {
            ErrorCode::BadRequest
        }
        BoxError::Busy => ErrorCode::Busy,
        BoxError::Unavailable(_) => ErrorCode::Unavailable,
    };
    let msg = match e {
        BoxError::Busy => "busy: no room for the box now, or boxes are waiting in the queue".into(),
        other => other.to_string(),
    };
    let mut m = Map::new();
    m.insert("rule".into(), e.rule().into());
    err_with(id, code, &msg, m)
}

fn invalid(why: &str) -> BoxError {
    BoxError::Invalid(why.into())
}

fn arg_id(args: &Map<String, Value>) -> Result<BoxId, BoxError> {
    match args.get("box") {
        Some(Value::String(s)) => BoxId::parse(s),
        _ => Err(invalid("box must be a box id")),
    }
}

/// A required text argument, checked with `check_text`.
fn arg_text(args: &Map<String, Value>, name: &str, max: usize) -> Result<String, BoxError> {
    match args.get(name) {
        Some(Value::String(s)) => {
            check_text(s, max)?;
            Ok(s.clone())
        }
        _ => Err(BoxError::Invalid(format!("{name} must be a string"))),
    }
}

fn arg_bool(args: &Map<String, Value>, name: &str) -> Result<bool, BoxError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(BoxError::Invalid(format!("{name} must be true or false"))),
    }
}

/// One op with its arguments checked.
enum Op {
    Spawn(SpawnArgs),
    List {
        all: bool,
    },
    Templates,
    Pause(BoxId),
    Stop(BoxId, bool),
    /// `force`: even with an approved land not applied.
    Discard(BoxId, bool),
    Done(BoxId),
    Resume(BoxId),
    Revise(BoxId, String),
    Steer(BoxId, String),
    Reorder(Vec<BoxId>),
    Gc,
    /// `refresh`: export again rather than answer the cached review.
    Diff(BoxId, bool),
    TermRead(BoxId, Option<u64>),
}

impl Op {
    /// `disk`: a repo disk was passed, whose manifest names the repo, so
    /// `box.spawn` may leave `repo` out.
    fn parse(op: &str, a: &Map<String, Value>, uid: u32, disk: bool) -> Result<Op, BoxError> {
        Ok(match op {
            OP_BOX_SPAWN => {
                let task = match a.get("task") {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) if s.is_empty() => String::new(),
                    Some(Value::String(s)) => {
                        check_text(s, MAX_TASK_BYTES)?;
                        s.clone()
                    }
                    Some(_) => return Err(invalid("task must be a string")),
                };
                let repo_dir = match a.get("repo_dir") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => {
                        check_text(s, MAX_REPO_DIR_BYTES)?;
                        Some(s.clone())
                    }
                    Some(_) => return Err(invalid("repo_dir must be a string")),
                };
                let start = match a.get("start") {
                    None | Some(Value::Null) => Start::Queue,
                    Some(Value::String(s)) if s == "queue" => Start::Queue,
                    Some(Value::String(s)) if s == "now" => Start::Now,
                    Some(_) => return Err(invalid("start is \"now\" or \"queue\"")),
                };
                let repo = match a.get("repo") {
                    None | Some(Value::Null) if disk => String::new(),
                    _ => arg_text(a, "repo", MAX_REPO_BYTES)?,
                };
                Op::Spawn(SpawnArgs {
                    template: arg_text(a, "template", MAX_TEMPLATE_BYTES)?,
                    repo,
                    repo_dir,
                    task,
                    start,
                    owner_uid: uid,
                    repo_image: None,
                    base_manifest: None,
                })
            }
            OP_BOX_LIST => Op::List {
                all: arg_bool(a, "all")?,
            },
            OP_BOX_TEMPLATES => Op::Templates,
            OP_BOX_PAUSE => Op::Pause(arg_id(a)?),
            OP_BOX_STOP => Op::Stop(arg_id(a)?, arg_bool(a, "keep")?),
            OP_BOX_DISCARD => Op::Discard(arg_id(a)?, arg_bool(a, "force")?),
            OP_BOX_DONE => Op::Done(arg_id(a)?),
            OP_BOX_RESUME => Op::Resume(arg_id(a)?),
            OP_BOX_REVISE => Op::Revise(arg_id(a)?, arg_text(a, "comment", MAX_STEER_BYTES)?),
            OP_BOX_STEER => Op::Steer(arg_id(a)?, arg_text(a, "msg", MAX_STEER_BYTES)?),
            OP_BOX_REORDER => {
                let Some(Value::Array(v)) = a.get("ids") else {
                    return Err(invalid("ids must be a list of box ids"));
                };
                let ids = v
                    .iter()
                    .map(|x| match x {
                        Value::String(s) => BoxId::parse(s),
                        _ => Err(invalid("ids must be a list of box ids")),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Op::Reorder(ids)
            }
            OP_BOX_GC => Op::Gc,
            OP_BOX_DIFF => Op::Diff(arg_id(a)?, arg_bool(a, "refresh")?),
            OP_BOX_TERM_READ => {
                let after = match a.get("after") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(
                        v.as_u64()
                            .ok_or_else(|| invalid("after must be a number"))?,
                    ),
                };
                Op::TermRead(arg_id(a)?, after)
            }
            _ => return Err(invalid("not a box op")),
        })
    }

    /// The ops that give a box power, refused under lockdown `all`.
    fn grants_power(&self) -> bool {
        matches!(
            self,
            Op::Spawn(_) | Op::Resume(_) | Op::Revise(..) | Op::Steer(..)
        )
    }

    /// The box a per-box op is about.
    fn target(&self) -> Option<&BoxId> {
        match self {
            Op::Pause(i)
            | Op::Stop(i, _)
            | Op::Discard(i, _)
            | Op::Done(i)
            | Op::Resume(i)
            | Op::Revise(i, _)
            | Op::Steer(i, _)
            | Op::Diff(i, _)
            | Op::TermRead(i, _) => Some(i),
            _ => None,
        }
    }
}

/// A manager call off the runtime thread.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, BoxError> + Send + 'static,
) -> Result<T, BoxError> {
    tokio::task::spawn_blocking(f).await.unwrap_or_else(|e| {
        Err(BoxError::Unavailable(format!(
            "the box manager did not finish: {e}"
        )))
    })
}

/// `{name: t}`. Answers nest what carries an `id`: the answer's own `id`
/// is the request's.
fn under<T: Serialize>(name: &str, t: &T) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(name.into(), serde_json::to_value(t).unwrap_or(Value::Null));
    m
}

fn obj<T: Serialize>(t: &T) -> Map<String, Value> {
    match serde_json::to_value(t) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

/// Allocated MiB (rounded up) of a box's disks; lstat only, no lock held.
#[cfg(unix)]
fn disk_mib(root: &Path, id: &BoxId) -> u64 {
    saiife_boxhost::disk::usage(&saiife_boxhost::paths::BoxPaths::of(root, id))
        .total()
        .div_ceil(1 << 20)
}

#[cfg(not(unix))]
fn disk_mib(root: &Path, id: &BoxId) -> u64 {
    let _ = (root, id);
    0
}

/// The context's land book (plan 39), if one is attached.
type Book = Option<Arc<dyn LandBook>>;

fn book(ctx: &Ctx) -> Book {
    #[cfg(unix)]
    {
        ctx.box_lands
            .get()
            .map(|l| Arc::clone(l) as Arc<dyn LandBook>)
    }
    #[cfg(not(unix))]
    {
        let _ = ctx;
        None
    }
}

/// The box source over `mgr` as `scope` sees it, with the land book when
/// there is one: every `ManagerSource` of the daemon is made here.
fn source(mgr: &Arc<Manager>, scope: Option<u32>, book: &Book) -> ManagerSource {
    let src = ManagerSource::new(Arc::clone(mgr), scope);
    match book {
        Some(b) => src.with_lands(Arc::clone(b)),
        None => src,
    }
}

/// Attach the land book (plan 39) over the context's box manager, reaching
/// each box's guest through `guest` and its files through `layout`. Once
/// per context; `None` without a manager or when one is attached already.
/// The daemon's start calls it once boxes run on a real VMM (plan 35); a
/// test calls it with its own guest.
#[cfg(unix)]
pub fn attach_lands(
    ctx: &Arc<Ctx>,
    guest: Arc<saiife_boxhost::guest::VsockGuest>,
    layout: saiife_boxhost::layout::Layout,
) -> Option<Arc<crate::box_land::Lands>> {
    let mgr = ctx.box_manager.clone()?;
    let lands = crate::box_land::Lands::new(Arc::clone(ctx), mgr, guest, layout);
    ctx.box_lands.set(Arc::clone(&lands)).ok()?;
    Some(lands)
}

/// A box that just became `Done` gets its review now, before an idle stop
/// can turn its VM off (plan 39). Each refresh runs off the runtime and is
/// not waited for (an export may take up to two minutes); a refused export
/// is recorded by the book.
fn refresh_done(ctx: &Ctx, changes: &[Change]) {
    #[cfg(unix)]
    {
        let Some(lands) = ctx.box_lands.get() else {
            return;
        };
        for c in changes {
            if c.to != BoxState::Done || c.from == BoxState::Done {
                continue;
            }
            let (l, id) = (Arc::clone(lands), c.id.clone());
            tokio::task::spawn_blocking(move || match l.refresh(&id) {
                Ok(_) => {}
                // An idle stop or a stop: the VM is off already.
                Err(BoxError::Unavailable(m)) if m == crate::box_land::vm_off(&id) => {}
                Err(e) => eprintln!("saiifed: boxes: no review of {}: {e}", id.as_str()),
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (ctx, changes);
}

/// `{box: BoxInfo}`: box `r` as `scope` sees it (queue positions among
/// that owner's boxes; `None`: the whole queue).
fn info_of(
    mgr: &Arc<Manager>,
    r: &BoxRecord,
    scope: Option<u32>,
    book: &Book,
) -> Map<String, Value> {
    let src = source(mgr, scope, book);
    let i = src
        .list()
        .into_iter()
        .find(|b| b.id == r.id)
        .unwrap_or_else(|| info(r, None));
    under("box", &i)
}

/// What the caller may see and do, once per op.
struct Caller {
    peer: PeerCred,
    /// Root or an `[admin] groups` member.
    privileged: bool,
}

impl Caller {
    fn may_see(&self, r: &BoxRecord) -> bool {
        self.privileged || r.owner_uid == self.peer.uid
    }

    /// Queue positions: among the caller's own boxes, or the whole queue for
    /// someone else's.
    fn scope_for(&self, r: &BoxRecord) -> Option<u32> {
        (r.owner_uid == self.peer.uid).then_some(self.peer.uid)
    }
}

/// Every op in [`OPS`].
pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    // The descriptors a `box.fds` passed are this op's: an op in
    // `msg::FD_OPS` (`box.spawn`, `box.image.import`) takes them, any other
    // box op closes them now. Every refusal below closes them too.
    #[cfg(unix)]
    let mut passed: Passed = conn.take_fds();
    #[cfg(not(unix))]
    let mut passed: Passed = Vec::new();
    if !saiife_ipc::msg::FD_OPS.contains(&req.op.as_str()) {
        passed.clear();
    }
    // The base images (plan 36) need the image store, not the manager: a
    // host whose preflight failed for want of a default image imports one
    // here (`ctx.box_images` is set whenever this build and mode have boxes).
    if crate::box_images::OPS.contains(&req.op.as_str()) {
        if ctx.box_images.is_none() {
            return err(id, ErrorCode::Unavailable, unavailable(ctx));
        }
        #[cfg(unix)]
        return crate::box_images::handle(ctx, ctx.box_manager.as_ref(), &conn.peer, req, passed)
            .await;
        #[cfg(not(unix))]
        {
            drop(passed);
            return err(id, ErrorCode::Unavailable, UNAVAILABLE);
        }
    }
    let Some(mgr) = ctx.box_manager.clone() else {
        return err(id, ErrorCode::Unavailable, unavailable(ctx));
    };
    // Land and push (plan 39): the land book's own ops.
    if LAND_OPS.contains(&req.op.as_str()) {
        #[cfg(unix)]
        return crate::box_land::handle(ctx, conn, req).await;
        #[cfg(not(unix))]
        return err(id, ErrorCode::Unavailable, UNAVAILABLE);
    }
    let peer = conn.peer.clone();
    let action = req.op.strip_prefix("box.").unwrap_or(&req.op).to_string();
    let op = match Op::parse(&req.op, &req.args, peer.uid, !passed.is_empty()) {
        Ok(op) => op,
        Err(e) => return refusal(id, &e),
    };
    let user = ctx.peer_name(&peer).await;
    let with_peer = |mut r: Record| {
        r.uid = Some(peer.uid);
        r.sid = peer.sid.clone();
        r.user = user.clone();
        r
    };

    // Lockdown `all` refuses what gives a box power; the record says so.
    if op.grants_power() {
        if let Some(l) = ctx.lockdown.get().filter(|l| l.scope == LockScope::All) {
            let template = match &op {
                Op::Spawn(a) => Some(a.template.as_str()),
                _ => None,
            };
            let mut rec = with_peer(box_rec(
                ctx,
                &action,
                op.target(),
                template,
                None,
                None,
                "cli",
            ));
            let why = crate::lockdown::message(&l);
            rec.decision = DecisionKind::Deny;
            rec.rule = Some("lockdown".into());
            rec.reason = Some(why.clone());
            if let Err(e) = ctx.writer.append(rec).await {
                eprintln!("saiifed: warning: cannot write a box record: {e}");
            }
            let mut m = Map::new();
            m.insert("rule".into(), "lockdown".into());
            return err_with(id, ErrorCode::Lockdown, &why, m);
        }
    }

    let privileged = (peer.sid.is_none() && peer.uid == 0) || ctx.peer_is_admin(&peer).await;
    let caller = Arc::new(Caller {
        peer: peer.clone(),
        privileged,
    });

    // The owner check (B8): someone else's box is a missing one.
    let before = match op.target() {
        Some(target) => {
            let (m, t, c) = (Arc::clone(&mgr), target.clone(), Arc::clone(&caller));
            match blocking(move || {
                let r = m.get(&t)?;
                if c.may_see(&r) {
                    Ok(r)
                } else {
                    Err(BoxError::NotFound)
                }
            })
            .await
            {
                Ok(r) => Some(r),
                Err(e) => return refusal(id, &e),
            }
        }
        None => None,
    };

    let done = run(ctx, &mgr, &caller, op, before, passed).await;
    let (answer, rec) = match done {
        Ok(x) => x,
        Err(e) => return refusal(id, &e),
    };
    if let Some(rec) = rec {
        if let Err(e) = ctx.writer.append(with_peer(rec)).await {
            return err(
                id,
                ErrorCode::Unrecorded,
                &format!("box.{action} is done, but its record could not be written: {e}"),
            );
        }
    }
    ok(id, answer)
}

/// The answer and the record (if the op writes one) of a checked op.
type Done = (Map<String, Value>, Option<Record>);

/// A manager call that changes one box.
type Step = Box<dyn FnOnce(&Manager) -> Result<Change, BoxError> + Send>;

/// The repo disk a `box.spawn` was passed, taken in (`crate::box_repo`)
/// and named in `args`, with the repo's name from its manifest. `None`
/// when nothing was passed. A refused disk is `Invalid` (`bad_request`);
/// a disk the daemon failed to take in (I/O) is `Unavailable`.
#[cfg(unix)]
fn take_disk(
    root: &Path,
    passed: Passed,
    args: &mut SpawnArgs,
) -> Result<Option<PathBuf>, BoxError> {
    if passed.is_empty() {
        return Ok(None);
    }
    use crate::box_repo::IntakeError;
    let (image, manifest, parsed) = crate::box_repo::intake(root, passed).map_err(|e| match e {
        IntakeError::Refused(m) => BoxError::Invalid(m),
        IntakeError::Failed(m) => BoxError::Unavailable(m),
    })?;
    args.repo = parsed.repo;
    args.repo_image = Some(image.clone());
    args.base_manifest = Some(manifest);
    Ok(Some(image))
}

#[cfg(not(unix))]
fn take_disk(
    root: &Path,
    passed: Passed,
    args: &mut SpawnArgs,
) -> Result<Option<PathBuf>, BoxError> {
    let _ = (root, passed, args);
    Ok(None)
}

/// What [`take_disk`] left in `.incoming`, once the spawn is over.
fn discard_disk(root: &Path, image: Option<&Path>) {
    #[cfg(unix)]
    if let Some(i) = image {
        crate::box_repo::discard(root, i);
    }
    #[cfg(not(unix))]
    let _ = (root, image);
}

/// One op, past its argument, lockdown and owner checks. `before` is the
/// target box as the owner check read it; `passed`, a spawn's repo disk.
async fn run(
    ctx: &Ctx,
    mgr: &Arc<Manager>,
    caller: &Arc<Caller>,
    op: Op,
    before: Option<BoxRecord>,
    passed: Passed,
) -> Result<Done, BoxError> {
    let m = Arc::clone(mgr);
    let c = Arc::clone(caller);
    let uid = caller.peer.uid;
    let lands = book(ctx);
    // A per-box change: the manager call, then the box as it is now.
    let change = |action: &'static str, f: Step| {
        let (m, c) = (Arc::clone(mgr), Arc::clone(caller));
        let before = before.clone();
        let lands = lands.clone();
        async move {
            let b = before.ok_or(BoxError::NotFound)?;
            let (ch, answer) = blocking(move || {
                let ch = f(&m)?;
                let answer = match m.get(&ch.id) {
                    Ok(r) => info_of(&m, &r, c.scope_for(&r), &lands),
                    Err(_) => under("box", &json!({"id": ch.id.as_str()})),
                };
                Ok((ch, answer))
            })
            .await?;
            let rec = box_rec(
                ctx,
                action,
                Some(&ch.id),
                Some(&b.template),
                Some(ch.from),
                Some(ch.to),
                "cli",
            );
            Ok::<Done, BoxError>((answer, Some(rec)))
        }
    };
    match op {
        Op::Spawn(mut args) => {
            let lands = lands.clone();
            let (r, answer, others) = blocking(move || {
                // The copy runs here, off the runtime and outside every
                // lock; the manager moves it into the box dir.
                let root = m.root().to_path_buf();
                let staged = take_disk(&root, passed, &mut args)?;
                let spawned = m.spawn_changes(&args);
                discard_disk(&root, staged.as_deref());
                let (r, changes) = spawned?;
                let answer = info_of(&m, &r, Some(r.owner_uid), &lands);
                // Earlier queue heads this spawn's admission pass moved
                // (possibly other owners' boxes): the tick never sees them.
                // The new box's own admission is covered by the spawn
                // record's `to`.
                let others = changes
                    .into_iter()
                    .filter(|c| c.id != r.id)
                    .map(|c| {
                        let template = m.get(&c.id).ok().map(|b| b.template);
                        (c, template)
                    })
                    .collect::<Vec<_>>();
                Ok((r, answer, others))
            })
            .await?;
            write_tick_records(ctx, "tick", None, others, "tick").await;
            let mut rec = box_rec(
                ctx,
                "spawn",
                Some(&r.id),
                Some(&r.template),
                None,
                Some(r.state),
                "cli",
            );
            if r.state == BoxState::Discarded {
                rec.reason = r.error.clone();
            }
            // Admitted at its own spawn: the base image its VM was created
            // from (plan 36).
            if let Some(i) = &r.image {
                rec.extra.insert("image".into(), i.as_str().into());
            }
            Ok((answer, Some(rec)))
        }
        Op::List { all } => {
            let scope = (!(all && caller.privileged)).then_some(uid);
            let disk_root = ctx.box_disk_root.clone();
            blocking(move || {
                let boxes = source(&m, scope, &lands).list();
                // Usage is read from the box dirs after every manager lock
                // is released (the lists above are snapshots); the disks are
                // in the driver's runtime dirs (R37).
                let root = disk_root.unwrap_or_else(|| m.root().to_path_buf());
                let (host, committed) = m.capacity();
                let (total, free) = capacity::slots(&host, &committed);
                let mut a = Map::new();
                // Each entry is the `BoxInfo` plus, for a box that failed, its
                // record's `error` (the wire type has no such field; this
                // answer is the control socket's own).
                let errors: std::collections::HashMap<BoxId, String> = m
                    .list()
                    .into_iter()
                    .filter_map(|r| r.error.filter(|e| !e.is_empty()).map(|e| (r.id, e)))
                    .collect();
                let boxes: Vec<Value> = boxes
                    .into_iter()
                    .map(|b| {
                        let err = errors.get(&b.id).cloned();
                        let disk = disk_mib(&root, &b.id);
                        let mut v = serde_json::to_value(b).unwrap_or_default();
                        if let Value::Object(o) = &mut v {
                            if let Some(e) = err {
                                o.insert("error".into(), e.into());
                            }
                            o.insert("disk_mib".into(), disk.into());
                        }
                        v
                    })
                    .collect();
                a.insert("boxes".into(), Value::Array(boxes));
                a.insert("slots_total".into(), total.into());
                a.insert("slots_free".into(), free.into());
                Ok((a, None))
            })
            .await
        }
        Op::Templates => {
            let warnings: Vec<Value> = ctx
                .box_template_warnings
                .iter()
                .map(|w| json!({"file": w.file.display().to_string(), "reason": w.reason}))
                .collect();
            blocking(move || {
                let t: Vec<_> = m.templates().iter().map(|t| t.wire()).collect();
                let mut a = Map::new();
                a.insert(
                    "templates".into(),
                    serde_json::to_value(t).unwrap_or_default(),
                );
                a.insert("warnings".into(), Value::Array(warnings));
                Ok((a, None))
            })
            .await
        }
        Op::Pause(i) => change("pause", Box::new(move |m| m.pause(&i))).await,
        Op::Stop(i, keep) => change("stop", Box::new(move |m| m.stop(&i, keep))).await,
        Op::Done(i) => {
            let id = i.clone();
            let done = change("done", Box::new(move |m| m.done(&i))).await?;
            let moved = Change {
                id,
                from: BoxState::Running,
                to: BoxState::Done,
                why: "done",
                image: None,
            };
            refresh_done(ctx, &[moved]);
            Ok(done)
        }
        Op::Resume(i) => change("resume", Box::new(move |m| m.resume(&i))).await,
        Op::Revise(i, text) => change("revise", Box::new(move |m| m.revise(&i, &text))).await,
        Op::Discard(i, force) => {
            let gone = i.clone();
            // An approved land not applied yet keeps the box (L4), unless
            // forced; a land record that cannot be read counts as one.
            let book = lands.clone();
            let (_, rec) = change(
                "discard",
                Box::new(move |m| match &book {
                    // Checked and discarded under the book's box lock.
                    Some(b) => {
                        let mut done = None;
                        b.discard_with(&i, force, &mut || {
                            done = Some(m.discard(&i)?);
                            Ok(())
                        })?;
                        done.ok_or(BoxError::NotFound)
                    }
                    None => m.discard(&i),
                }),
            )
            .await?;
            // its run is stopped: the guest channel drops its last screen
            blocking(move || {
                m.guest().forget(&gone);
                Ok(())
            })
            .await?;
            let b = before.ok_or(BoxError::NotFound)?;
            let mut rec = rec;
            if force {
                if let Some(r) = rec.as_mut() {
                    r.extra.insert("force".into(), true.into());
                }
            }
            Ok((under("box", &json!({"id": b.id.as_str()})), rec))
        }
        Op::Steer(i, msg) => {
            let b = before.ok_or(BoxError::NotFound)?;
            blocking(move || m.say(&i, &msg)).await?;
            let rec = box_rec(
                ctx,
                "steer",
                Some(&b.id),
                Some(&b.template),
                Some(b.state),
                Some(b.state),
                "cli",
            );
            Ok((Map::new(), Some(rec)))
        }
        Op::Reorder(ids) => {
            let ids2 = ids.clone();
            blocking(move || {
                // An admin listing the whole queue orders it; anyone else
                // (or an admin listing only their own) orders their own
                // boxes among the places they hold.
                let mut want = ids2.clone();
                want.sort();
                let mut all = m.queue();
                all.sort();
                if c.privileged && want == all {
                    m.reorder(&ids2)
                } else {
                    source(&m, Some(c.peer.uid), &lands).reorder(&ids2)
                }
            })
            .await?;
            let mut rec = box_rec(ctx, "reorder", None, None, None, None, "cli");
            rec.extra.insert(
                "ids".into(),
                ids.iter().map(|i| i.as_str()).collect::<Vec<_>>().into(),
            );
            Ok((Map::new(), Some(rec)))
        }
        Op::Gc => {
            // gc goes on past a box it cannot remove (R31): the answer and
            // the record list every id removed, plus the first error.
            let (removed, error) = blocking(move || {
                let forget = |removed: &[BoxId]| {
                    let g = m.guest();
                    for i in removed {
                        g.forget(i);
                    }
                };
                if c.privileged {
                    let g = m.gc();
                    forget(&g.removed);
                    return Ok((g.removed, g.error));
                }
                // Only the caller's own discarded boxes; orphan dirs have no
                // owner, so they wait for an admin.
                let mine: Vec<BoxId> = m
                    .list()
                    .into_iter()
                    .filter(|r| r.state == BoxState::Discarded && r.owner_uid == c.peer.uid)
                    .map(|r| r.id)
                    .collect();
                let mut removed = Vec::new();
                let mut error = None;
                for i in mine {
                    if let Err(e) = m.discard(&i) {
                        error.get_or_insert_with(|| e.to_string());
                    }
                    if matches!(m.get(&i), Err(BoxError::NotFound)) {
                        removed.push(i);
                    }
                }
                forget(&removed);
                Ok((removed, error))
            })
            .await?;
            let ids: Vec<&str> = removed.iter().map(|i| i.as_str()).collect();
            let mut rec = box_rec(ctx, "gc", None, None, None, None, "cli");
            rec.extra.insert("removed".into(), ids.clone().into());
            rec.reason = error.clone();
            let mut a = Map::new();
            a.insert("removed".into(), ids.into());
            if let Some(e) = error {
                a.insert("error".into(), e.into());
            }
            Ok((a, Some(rec)))
        }
        Op::Diff(i, refresh) => {
            // With the land book: the review too (plan 39), the cached one
            // unless `refresh`.
            #[cfg(unix)]
            if let Some(l) = ctx.box_lands.get().cloned() {
                return blocking(move || {
                    let r = match (refresh, l.latest(&i)) {
                        (false, Some(r)) => r,
                        _ => l.refresh(&i)?,
                    };
                    Ok((crate::box_land::diff_answer(&r), None))
                })
                .await;
            }
            let _ = refresh;
            blocking(move || {
                let d = source(&m, None, &lands).diff(&i)?;
                Ok((under("diff", &d), None))
            })
            .await
        }
        Op::TermRead(i, after) => {
            blocking(move || {
                let b = source(&m, None, &lands).terminal(&i, after)?;
                Ok((obj(&b), None))
            })
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every build (with or without `fake-vmm`): no fake flag and no VMM in
    /// the personal layout is a reason, not a manager, and nothing is made.
    #[test]
    fn no_vmm_is_a_reason_naming_the_fetch() {
        let tmp = tempfile::tempdir_in(
            std::env::var_os("SAIIFE_TEST_TMP")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir),
        )
        .unwrap();
        let state = tmp.path().join("state");
        let data = tmp.path().join("data");
        let env = |k: &str| -> Option<OsString> {
            match k {
                "XDG_DATA_HOME" => Some(data.clone().into_os_string()),
                "HOME" => Some(tmp.path().join("home").into_os_string()),
                "SAIIFE_TEST_KVM" => Some(tmp.path().join("kvm").into_os_string()),
                _ => None,
            }
        };
        let why = build_with(&state, &Mode::Personal, &state.join("config.toml"), &env)
            .unwrap()
            .err()
            .expect("unavailable");
        if cfg!(all(target_os = "linux", feature = "boxes")) {
            assert!(why.contains("saiife box vmm fetch"), "{why}");
        } else if cfg!(target_os = "linux") {
            assert!(why.contains(NOT_ENABLED), "{why}");
        } else {
            assert_eq!(why, UNAVAILABLE);
        }
        assert!(!state.exists() && !data.exists());
    }

    #[test]
    fn meminfo_fields() {
        let t = "MemTotal:       32768000 kB\nMemFree:  1 kB\nMemAvailable:   16384000 kB\n";
        assert_eq!(meminfo_kib(t, "MemTotal"), Some(32_768_000));
        assert_eq!(meminfo_kib(t, "MemAvailable"), Some(16_384_000));
        assert_eq!(meminfo_kib(t, "Mem"), None);
        assert_eq!(meminfo_kib("", "MemTotal"), None);
    }

    #[test]
    fn cpu_delta() {
        let a = cpu_times("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\n").unwrap();
        assert_eq!(a, (1000, 800));
        let b = cpu_times("cpu  200 0 200 1300 300 0 0 0 0 0\n").unwrap();
        assert_eq!(cpu_pct(a, b), Some(20));
        assert_eq!(cpu_pct(a, a), None);
        assert_eq!(cpu_pct(b, a), None, "a counter that went back");
        assert_eq!(cpu_times("intr 1 2\n"), None);
    }

    #[test]
    fn personal_templates_dir_ignores_relative_xdg() {
        let env = |k: &str| -> Option<OsString> {
            match k {
                "XDG_CONFIG_HOME" => Some("rel/dir".into()),
                "HOME" => Some("/home/u".into()),
                _ => None,
            }
        };
        let (d, _) = templates_dir(&Mode::Personal, Path::new("/c/config.toml"), &env);
        assert_eq!(d, Path::new("/home/u/.config/saiife/templates.d"));
        let none = |_: &str| -> Option<OsString> { None };
        let (d, _) = templates_dir(&Mode::Personal, Path::new("/c/config.toml"), &none);
        assert_eq!(d, Path::new("/c/templates.d"));
    }
}
