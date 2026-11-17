//! The VMM seam: the driver the manager boots, pauses and snapshots boxes with.

use std::path::{Path, PathBuf};

use saiife_wire::source::BoxId;

use crate::template::{ImageRef, Size};

pub use crate::store::VmHandle;

#[cfg(feature = "fake")]
pub mod fake;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmSpec {
    pub id: BoxId,
    pub size: Size,
    pub image: ImageRef,
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmStatus {
    Created,
    Running,
    Paused,
    Off,
    Gone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmmError {
    Unavailable(String),
    Failed(String),
}

/// The VM driver. Every method returns within about a second: `boot`
/// starts the VM and returns; readiness arrives later as `GuestEvent::Ready`.
/// `stop` and `destroy` are idempotent (Ok on an Off or Gone VM). `status`
/// never errs for a VM it does not know: that is `Gone`.
pub trait Vmm: Send + Sync {
    fn create(&self, spec: &VmSpec) -> Result<VmHandle, VmmError>;
    fn boot(&self, h: &VmHandle) -> Result<(), VmmError>;
    fn pause(&self, h: &VmHandle) -> Result<(), VmmError>;
    fn resume(&self, h: &VmHandle) -> Result<(), VmmError>;
    fn stop(&self, h: &VmHandle) -> Result<(), VmmError>;
    /// The VM must be paused.
    fn snapshot(&self, h: &VmHandle, dest: &Path) -> Result<(), VmmError>;
    fn status(&self, h: &VmHandle) -> VmStatus;
    /// Frees VMM resources; the store removes the dir. Bounded like every
    /// other call: a VM still booting or stopping is not waited out, the
    /// call fails and keeps its state, and the manager's tick retries it
    /// (R41).
    fn destroy(&self, h: &VmHandle) -> Result<(), VmmError>;
    /// The base image id (`base-<sha256>`) the VM of `h` was created
    /// from, as the driver itself recorded it; `None` when it cannot say.
    /// The manager learns the image here and never reads `h.data` (plan 36).
    fn image_id(&self, h: &VmHandle) -> Option<String> {
        let _ = h;
        None
    }
}
