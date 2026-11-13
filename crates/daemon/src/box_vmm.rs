//! The real box driver (plan 35, Task 7): `ChVmm` over the pinned Cloud
//! Hypervisor, as a child of the daemon (`saiife __box-vmm`, personal mode)
//! or as the `saiife-box@<id>.service` unit (locked mode), always with
//! Landlock on. [`crate::box_ops::build`] calls [`real_vmm`] only after the
//! preflight passed.
//!
//! Locking: the hooks run inside `ChVmm` calls, which the box manager makes
//! under its own lock. [`AuditHooks`] never takes that lock (nor asks the
//! manager anything): it builds its record from the box id alone and hands
//! it to the audit writer on a runtime task.

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;

use saiife_boxes::vmm::Vmm;
use saiife_boxhost::image::Store as ImageStore;
use saiife_boxhost::launch::{ChildLauncher, Launcher, UnitLauncher};
use saiife_boxhost::layout::Layout;
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::tools::Tools;
use saiife_boxhost::vmm::{ChVmm, ChVmmInit, StopTimes, VmHooks};
use saiife_wire::source::BoxId;

use crate::box_ops::AuditLink;
use crate::ops::Mode;

/// The user every locked VMM runs as (`system install --boxes` makes it).
pub const BOX_USER: &str = "saiife-box";
/// Debug builds only (like `SAIIFE_TOOL_*`): an absolute dir the locked
/// layout is re-rooted under, so tests never read the host's
/// `/var/lib/saiife-box` or `/opt/saiife` (M1). Release builds ignore it.
pub const TEST_BOX_ROOT_ENV: &str = "SAIIFE_TEST_BOX_ROOT";
/// The device a personal VMM opens.
pub const KVM: &str = "/dev/kvm";
/// Debug builds only (the V9 rule, as [`TEST_BOX_ROOT_ENV`]): an absolute
/// file the personal preflight probes instead of [`KVM`], so tests never
/// touch the host's `/dev/kvm` (M-2). Release builds ignore it.
pub const TEST_KVM_ENV: &str = "SAIIFE_TEST_KVM";

/// The device the personal preflight probes: [`KVM`], or in a debug build
/// the absolute path in [`TEST_KVM_ENV`].
pub fn kvm_path(env: &dyn Fn(&str) -> Option<OsString>) -> std::path::PathBuf {
    env(TEST_KVM_ENV)
        .map(std::path::PathBuf::from)
        .filter(|p| cfg!(debug_assertions) && p.is_absolute())
        .unwrap_or_else(|| std::path::PathBuf::from(KVM))
}

/// The debug-only test root for the locked layout (M1): `None` when unset
/// (or in a release build). Set, it must be absolute and must not resolve
/// to `/` or into the real locked roots: such a value is an error, never
/// the real layout, so a test never reaches the host's install or the
/// system bus (M-4).
fn test_box_root(
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Option<std::path::PathBuf>, String> {
    use std::path::{Component, PathBuf};
    if !cfg!(debug_assertions) {
        return Ok(None);
    }
    let Some(raw) = env(TEST_BOX_ROOT_ENV) else {
        return Ok(None);
    };
    let raw = PathBuf::from(raw);
    let bad = || {
        Err(format!(
            "{TEST_BOX_ROOT_ENV}={} is not a test root (absolute, not / or the real box dirs)",
            raw.display()
        ))
    };
    if !raw.is_absolute() {
        return bad();
    }
    // `..` and `.` resolved by hand (the dir may not exist yet); an existing
    // one through its links too
    let mut lexical = PathBuf::from("/");
    for c in raw.components() {
        match c {
            Component::Normal(n) => lexical.push(n),
            Component::ParentDir => {
                lexical.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    let resolved = std::fs::canonicalize(&lexical).unwrap_or(lexical);
    let real = Layout::locked();
    let real_roots = [Path::new("/var/lib/saiife-box"), Path::new("/opt/saiife")];
    if resolved == Path::new("/")
        || real_roots.iter().any(|r| resolved.starts_with(r))
        || Layout::locked_under(&resolved) == real
    {
        return bad();
    }
    Ok(Some(resolved))
}

/// The box layout of this daemon: [`Layout::locked`], or the personal one
/// under `state_dir` and the XDG data home (as `saiife box vmm fetch` and
/// `saiife __box-vmm` find it). Its `boxes` are the VMM's runtime dirs; the
/// records stay in [`crate::box_ops::dir_in`] (R37).
pub fn layout_for(
    state_dir: &Path,
    mode: &Mode,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Layout, String> {
    match mode {
        Mode::Locked => Ok(match test_box_root(env)? {
            Some(root) => Layout::locked_under(&root),
            None => Layout::locked(),
        }),
        Mode::Personal => {
            let abs = |k: &str| {
                env(k)
                    .map(std::path::PathBuf::from)
                    .filter(|p| p.is_absolute())
            };
            let data_home = abs("XDG_DATA_HOME")
                .or_else(|| abs("HOME").map(|h| h.join(".local/share")))
                .ok_or("boxes need your data dir, and HOME is not set")?;
            Ok(Layout::personal(state_dir, &data_home))
        }
    }
}

/// The uid the box VMMs run as, which must own each box's `vsock.sock`
/// (R19; [`real_vmm`] and the guest channel both use it). Personal: the
/// daemon's own euid. Locked: the [`BOX_USER`] user, failing closed when it
/// is missing; a re-rooted (test) locked layout is refused first, so it
/// never reaches the system bus (M1).
pub fn vmm_uid(layout: &Layout, mode: &Mode) -> Result<u32, String> {
    match mode {
        Mode::Personal => Ok(rustix::process::geteuid().as_raw()),
        Mode::Locked => {
            if layout != &Layout::locked() {
                return Err("a locked test layout never reaches the system bus".into());
            }
            // Fail closed: snapshot files are checked against this uid.
            saiife_ipc::client::system_uid(BOX_USER).ok_or_else(|| {
                format!(
                    "the {BOX_USER} user is missing: run \"sudo saiife system install --boxes\""
                )
            })
        }
    }
}

/// `ChVmm` for `layout` and the box store's `records` root (R37): the
/// pinned tools of its VMM dir, the image store (manifests in
/// `image_records`, disks in `layout.images`, firmware `<vmm>/CLOUDHV.fd`), the mode's launcher and VMM uid, the hooks,
/// Landlock on (R23) and the default stop ladder.
pub fn real_vmm(
    layout: &Layout,
    records: &Path,
    image_records: &Path,
    mode: &Mode,
    hooks: Vec<Arc<dyn VmHooks>>,
) -> Result<Arc<dyn Vmm>, String> {
    real_vmm_with(layout, records, image_records, mode, hooks, &|k| {
        std::env::var_os(k)
    })
}

/// [`real_vmm`] with the environment as a function (the debug-only
/// `SAIIFE_TOOL_*` overrides read it).
pub fn real_vmm_with(
    layout: &Layout,
    records: &Path,
    image_records: &Path,
    mode: &Mode,
    hooks: Vec<Arc<dyn VmHooks>>,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Arc<dyn Vmm>, String> {
    let tools = Tools::system(&layout.vmm).with_env(env);
    // the image store split (plan 36 R24): manifests in the daemon-only
    // `image_records` (`box_images::paths_for`), disks in `layout.images`
    let images = ImageStore::open(image_records.to_path_buf(), layout.images.clone())?
        .with_firmware(layout.vmm.join("CLOUDHV.fd"));
    saiife_boxhost::vault::ensure(&layout.vault)?;
    let vmm_uid = vmm_uid(layout, mode)?;
    let launcher: Arc<dyn Launcher> = match mode {
        Mode::Personal => {
            let exe = std::env::current_exe()
                .map_err(|e| format!("boxes cannot find the saiife binary: {e}"))?;
            Arc::new(ChildLauncher::helper(exe, layout.vault.clone()))
        }
        Mode::Locked => {
            let bus = crate::box_unit::SystemdBus::connect_blocking()
                .map_err(|e| format!("boxes need the system bus: {e}"))?;
            Arc::new(UnitLauncher::new(Arc::new(bus)))
        }
    };
    Ok(Arc::new(ChVmm::new(ChVmmInit {
        layout: layout.clone(),
        records: records.to_path_buf(),
        tools,
        images: Arc::new(images),
        launcher,
        hooks,
        vmm_uid,
        landlock: true,
        stop: StopTimes::default(),
    })))
}

/// The daemon's own hooks (R36): a snapshot the driver did not trust is a
/// `box` record (`action: "restore_refused"`). Nothing else: no listener
/// to bind, nothing to undo. Plans 38 and 40 add their own hooks.
pub struct AuditHooks {
    link: Arc<AuditLink>,
}

impl AuditHooks {
    pub fn new(link: Arc<AuditLink>) -> AuditHooks {
        AuditHooks { link }
    }
}

impl VmHooks for AuditHooks {
    fn before_boot(&self, _id: &BoxId, _paths: &BoxPaths) -> Result<(), String> {
        Ok(())
    }

    fn after_off(&self, _id: &BoxId) {}

    fn restore_refused(&self, id: &BoxId, why: &str) {
        self.link.restore_refused(id, why);
    }
}
