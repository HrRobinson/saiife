//! A fake VMM (feature `fake`): a state machine in a mutex, with a call log.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use saiife_wire::source::BoxId;

use super::{VmHandle, VmSpec, VmStatus, Vmm, VmmError};

/// The repo disk the fake looks for in the box dir. Test support only: the
/// real name is `saiife_boxhost::paths::REPO_DISK`, which this crate cannot
/// use; the daemon's repo-disk spawn test (`saw_repo_disk` after a placement
/// through `BoxPaths`) fails if the two drift apart.
const REPO_DISK_NAME: &str = "repo.img";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmOp {
    Create,
    Boot,
    Pause,
    Resume,
    Stop,
    Snapshot,
    Destroy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmCall {
    pub op: VmOp,
    pub id: BoxId,
}

#[derive(Default)]
struct State {
    status: HashMap<BoxId, VmStatus>,
    /// Whether `<dir>/repo.img` was there when `create` ran.
    repo_disk: HashMap<BoxId, bool>,
    fail: Vec<(VmOp, String)>,
    /// Boxes whose VMM never confirms its exit: every `destroy` errs.
    wedged: HashSet<BoxId>,
    calls: Vec<VmCall>,
    /// What `image_id` answers for every handle.
    image: Option<String>,
    /// The `data` of every handle `create` makes.
    data: String,
}

#[derive(Default)]
pub struct FakeVmm {
    state: Mutex<State>,
}

impl FakeVmm {
    pub fn new() -> FakeVmm {
        FakeVmm::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The next call of `op` errs `Failed(msg)`.
    pub fn fail_next(&self, op: VmOp, msg: &str) {
        self.lock().fail.push((op, msg.to_string()));
    }

    /// While `on`, every `destroy` of `id` errs like a VMM that never
    /// confirms its exit (it is still logged).
    pub fn wedge(&self, id: &BoxId, on: bool) {
        let mut s = self.lock();
        if on {
            s.wedged.insert(id.clone());
        } else {
            s.wedged.remove(id);
        }
    }

    /// Force a status, e.g. `Gone` to simulate a crash.
    pub fn set_status(&self, id: &BoxId, s: VmStatus) {
        self.lock().status.insert(id.clone(), s);
    }

    /// Whether the box's repo disk was in its dir at `create` (`None`: no
    /// create yet).
    pub fn saw_repo_disk(&self, id: &BoxId) -> Option<bool> {
        self.lock().repo_disk.get(id).copied()
    }

    /// What `image_id` answers from now on (`None`: no image, like a
    /// driver that cannot say).
    pub fn set_image(&self, image: Option<&str>) {
        self.lock().image = image.map(str::to_string);
    }

    /// The opaque `data` of the handles `create` makes from now on.
    pub fn set_handle_data(&self, data: &str) {
        self.lock().data = data.to_string();
    }

    pub fn calls(&self) -> Vec<VmCall> {
        self.lock().calls.clone()
    }

    /// Log the call and consume a queued failure for it.
    fn enter(&self, op: VmOp, id: &BoxId) -> Result<MutexGuard<'_, State>, VmmError> {
        let mut s = self.lock();
        s.calls.push(VmCall { op, id: id.clone() });
        if let Some(i) = s.fail.iter().position(|(o, _)| *o == op) {
            let (_, msg) = s.fail.remove(i);
            return Err(VmmError::Failed(msg));
        }
        Ok(s)
    }

    fn transition(
        &self,
        op: VmOp,
        h: &VmHandle,
        from: VmStatus,
        to: VmStatus,
        what: &str,
    ) -> Result<(), VmmError> {
        let mut s = self.enter(op, &h.id)?;
        let cur = s.status.get(&h.id).copied().unwrap_or(VmStatus::Gone);
        if cur != from {
            return Err(VmmError::Failed(format!(
                "cannot {what}: the VM is {cur:?}"
            )));
        }
        s.status.insert(h.id.clone(), to);
        Ok(())
    }
}

impl Vmm for FakeVmm {
    fn create(&self, spec: &VmSpec) -> Result<VmHandle, VmmError> {
        let disk = spec.dir.join(REPO_DISK_NAME).is_file();
        let mut s = self.enter(VmOp::Create, &spec.id)?;
        s.repo_disk.insert(spec.id.clone(), disk);
        s.status.insert(spec.id.clone(), VmStatus::Created);
        Ok(VmHandle {
            id: spec.id.clone(),
            driver: "fake".into(),
            data: s.data.clone(),
        })
    }

    fn boot(&self, h: &VmHandle) -> Result<(), VmmError> {
        let mut s = self.enter(VmOp::Boot, &h.id)?;
        match s.status.get(&h.id).copied().unwrap_or(VmStatus::Gone) {
            VmStatus::Created | VmStatus::Off => {
                s.status.insert(h.id.clone(), VmStatus::Running);
                Ok(())
            }
            cur => Err(VmmError::Failed(format!("cannot boot: the VM is {cur:?}"))),
        }
    }

    fn pause(&self, h: &VmHandle) -> Result<(), VmmError> {
        self.transition(VmOp::Pause, h, VmStatus::Running, VmStatus::Paused, "pause")
    }

    fn resume(&self, h: &VmHandle) -> Result<(), VmmError> {
        self.transition(
            VmOp::Resume,
            h,
            VmStatus::Paused,
            VmStatus::Running,
            "resume",
        )
    }

    fn stop(&self, h: &VmHandle) -> Result<(), VmmError> {
        let mut s = self.enter(VmOp::Stop, &h.id)?;
        match s.status.get(&h.id).copied().unwrap_or(VmStatus::Gone) {
            VmStatus::Gone | VmStatus::Off => {}
            _ => {
                s.status.insert(h.id.clone(), VmStatus::Off);
            }
        }
        Ok(())
    }

    fn snapshot(&self, h: &VmHandle, dest: &Path) -> Result<(), VmmError> {
        let s = self.enter(VmOp::Snapshot, &h.id)?;
        let cur = s.status.get(&h.id).copied().unwrap_or(VmStatus::Gone);
        if cur != VmStatus::Paused {
            return Err(VmmError::Failed(format!(
                "cannot snapshot: the VM is {cur:?}, not Paused"
            )));
        }
        std::fs::create_dir_all(dest).map_err(|e| VmmError::Failed(e.to_string()))?;
        std::fs::write(dest.join("snapshot.fake"), b"fake snapshot\n")
            .map_err(|e| VmmError::Failed(e.to_string()))
    }

    fn status(&self, h: &VmHandle) -> VmStatus {
        self.lock()
            .status
            .get(&h.id)
            .copied()
            .unwrap_or(VmStatus::Gone)
    }

    fn destroy(&self, h: &VmHandle) -> Result<(), VmmError> {
        let mut s = self.enter(VmOp::Destroy, &h.id)?;
        if s.wedged.contains(&h.id) {
            return Err(VmmError::Failed("the VMM is still stopping".into()));
        }
        s.status.insert(h.id.clone(), VmStatus::Gone);
        Ok(())
    }

    fn image_id(&self, _h: &VmHandle) -> Option<String> {
        self.lock().image.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{ImageRef, Size};
    use crate::vmm::{VmSpec, VmStatus, Vmm, VmmError};
    use saiife_wire::source::BoxId;

    fn spec(id: &str, dir: &std::path::Path) -> VmSpec {
        VmSpec {
            id: BoxId::parse(id).unwrap(),
            size: Size {
                vcpus: 2,
                mem_mib: 4096,
                mem_max_mib: 8192,
                disk_gib: 30,
            },
            image: ImageRef::Default,
            agent: crate::template::AgentKind::ClaudeCode,
            dir: dir.to_path_buf(),
        }
    }

    #[test]
    fn fake_vmm_lifecycle() {
        let d = tempfile::tempdir().unwrap();
        let v = FakeVmm::new();
        let h = v.create(&spec("b1", d.path())).unwrap();
        assert_eq!(h.id.as_str(), "b1");
        assert_eq!(v.status(&h), VmStatus::Created);
        v.boot(&h).unwrap();
        assert_eq!(v.status(&h), VmStatus::Running);
        v.pause(&h).unwrap();
        assert_eq!(v.status(&h), VmStatus::Paused);
        v.resume(&h).unwrap();
        assert_eq!(v.status(&h), VmStatus::Running);
        v.stop(&h).unwrap();
        assert_eq!(v.status(&h), VmStatus::Off);
        v.stop(&h).unwrap();
        v.destroy(&h).unwrap();
        assert_eq!(v.status(&h), VmStatus::Gone);
        v.destroy(&h).unwrap();
        let ops: Vec<VmOp> = v.calls().into_iter().map(|c| c.op).collect();
        assert_eq!(ops[0], VmOp::Create);
        assert_eq!(ops[1], VmOp::Boot);
        assert!(ops.contains(&VmOp::Destroy));
    }

    #[test]
    fn fake_vmm_pause_needs_running() {
        let d = tempfile::tempdir().unwrap();
        let v = FakeVmm::new();
        let h = v.create(&spec("b1", d.path())).unwrap();
        assert!(matches!(v.pause(&h), Err(VmmError::Failed(_))));
        v.boot(&h).unwrap();
        v.pause(&h).unwrap();
        assert!(matches!(v.pause(&h), Err(VmmError::Failed(_))));
        assert!(matches!(v.resume(&h), Ok(())));
        assert!(matches!(v.resume(&h), Err(VmmError::Failed(_))));
    }

    #[test]
    fn fail_next_fails_once() {
        let d = tempfile::tempdir().unwrap();
        let v = FakeVmm::new();
        let h = v.create(&spec("b1", d.path())).unwrap();
        v.fail_next(VmOp::Boot, "no kvm");
        assert_eq!(v.boot(&h), Err(VmmError::Failed("no kvm".into())));
        assert_eq!(v.status(&h), VmStatus::Created);
        v.boot(&h).unwrap();
        assert_eq!(v.status(&h), VmStatus::Running);
    }

    #[test]
    fn set_status_gone() {
        let d = tempfile::tempdir().unwrap();
        let v = FakeVmm::new();
        let h = v.create(&spec("b1", d.path())).unwrap();
        v.boot(&h).unwrap();
        v.set_status(&h.id, VmStatus::Gone);
        assert_eq!(v.status(&h), VmStatus::Gone);
        let unknown = BoxId::parse("b9").unwrap();
        v.set_status(&unknown, VmStatus::Running);
        assert_eq!(
            v.status(&crate::store::VmHandle {
                id: unknown,
                driver: "fake".into(),
                data: String::new()
            }),
            VmStatus::Running
        );
    }

    #[test]
    fn image_id_is_settable() {
        let d = tempfile::tempdir().unwrap();
        let v = FakeVmm::new();
        let h = v.create(&spec("b1", d.path())).unwrap();
        assert_eq!(v.image_id(&h), None);
        let img = format!("base-{}", "a".repeat(64));
        v.set_image(Some(&img));
        v.set_handle_data("not json {");
        assert_eq!(v.image_id(&h).as_deref(), Some(img.as_str()));
        assert_eq!(v.create(&spec("b2", d.path())).unwrap().data, "not json {");
    }

    #[test]
    fn snapshot_writes_into_dest() {
        let d = tempfile::tempdir().unwrap();
        let dest = d.path().join("snap");
        let v = FakeVmm::new();
        let h = v.create(&spec("b1", d.path())).unwrap();
        v.boot(&h).unwrap();
        assert!(v.snapshot(&h, &dest).is_err(), "needs a paused VM");
        v.pause(&h).unwrap();
        v.snapshot(&h, &dest).unwrap();
        assert!(dest.join("snapshot.fake").is_file());
    }
}
