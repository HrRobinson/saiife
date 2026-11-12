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
        Mode::Locked => Ok(
            match env(TEST_BOX_ROOT_ENV)
                .map(std::path::PathBuf::from)
                .filter(|p| cfg!(debug_assertions) && p.is_absolute())
            {
                Some(root) => Layout::locked_under(&root),
                None => Layout::locked(),
            },
        ),
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

/// `ChVmm` for `layout` and the box store's `records` root (R37): the
/// pinned tools of its VMM dir, the image store (firmware
/// `<vmm>/CLOUDHV.fd`), the mode's launcher and VMM uid, the hooks,
/// Landlock on (R23) and the default stop ladder.
pub fn real_vmm(
    layout: &Layout,
    records: &Path,
    mode: &Mode,
    hooks: Vec<Arc<dyn VmHooks>>,
) -> Result<Arc<dyn Vmm>, String> {
    real_vmm_with(layout, records, mode, hooks, &|k| std::env::var_os(k))
}

/// [`real_vmm`] with the environment as a function (the debug-only
/// `SAIIFE_TOOL_*` overrides read it).
pub fn real_vmm_with(
    layout: &Layout,
    records: &Path,
    mode: &Mode,
    hooks: Vec<Arc<dyn VmHooks>>,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Arc<dyn Vmm>, String> {
    let tools = Tools::system(&layout.vmm).with_env(env);
    let images =
        ImageStore::open(layout.images.clone())?.with_firmware(layout.vmm.join("CLOUDHV.fd"));
    saiife_boxhost::vault::ensure(&layout.vault)?;
    let (launcher, vmm_uid): (Arc<dyn Launcher>, u32) = match mode {
        Mode::Personal => {
            let exe = std::env::current_exe()
                .map_err(|e| format!("boxes cannot find the saiife binary: {e}"))?;
            (
                Arc::new(ChildLauncher::helper(exe, layout.vault.clone())),
                rustix::process::geteuid().as_raw(),
            )
        }
        Mode::Locked => {
            // A re-rooted (test) layout never reaches the system bus (M1).
            if layout != &Layout::locked() {
                return Err("a locked test layout never reaches the system bus".into());
            }
            // Fail closed: snapshot files are checked against this uid.
            let uid = saiife_ipc::client::system_uid(BOX_USER).ok_or_else(|| {
                format!(
                    "the {BOX_USER} user is missing: run \"sudo saiife system install --boxes\""
                )
            })?;
            let bus = crate::box_unit::SystemdBus::connect_blocking()
                .map_err(|e| format!("boxes need the system bus: {e}"))?;
            (Arc::new(UnitLauncher::new(Arc::new(bus))), uid)
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
