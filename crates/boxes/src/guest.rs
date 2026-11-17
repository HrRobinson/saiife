//! The guest seam: the `saiife-guest/1` channel to a running box.

use saiife_wire::source::{BoxError, BoxId, DiffSummary, TermBatch};

#[cfg(feature = "fake")]
pub mod fake;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestEvent {
    Ready,
    Activity,
    TurnFinished,
    Exited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestError {
    Unavailable(String),
    NotConnected,
}

/// The `saiife-guest/1` channel (later plan). Prompt types text + Enter into the agent's PTY.
pub trait GuestLink: Send + Sync {
    fn prompt(&self, id: &BoxId, text: &str) -> Result<(), GuestError>;
    fn terminal(&self, id: &BoxId, after: Option<u64>) -> Result<TermBatch, GuestError>;
    /// The box's diff without a land book. A [`crate::source::ManagerSource`]
    /// given one ([`crate::source::ManagerSource::with_lands`], plan 39)
    /// never calls this: the daemon's book exports, validates and renders
    /// the diff itself.
    fn diff(&self, id: &BoxId) -> Result<DiffSummary, GuestError>;

    /// The last refused hello or failed setup of the box's current run
    /// (guest-derived text: the caller sanitizes and caps it before keeping
    /// it). The daemon copies it into a box's error at the boot timeout.
    fn last_error(&self, _id: &BoxId) -> Option<String> {
        None
    }

    /// The box's guest came back already set up (a restored snapshot: its
    /// hello said `set_up: true` on this run) and its agent has not exited.
    /// Advisory, like `Ready`: the daemon only acts on it for a box that
    /// booted from a kept snapshot.
    fn restored(&self, _id: &BoxId) -> bool {
        false
    }

    /// Drop what is kept for a box that is gone (its last screen, its last
    /// error). Nothing for a box whose run is still on.
    fn forget(&self, _id: &BoxId) {}
}

/// The guest channel before its plan lands: every call is unavailable.
pub struct NoGuest;

fn not_built() -> GuestError {
    GuestError::Unavailable("the guest channel is not built yet".into())
}

impl GuestLink for NoGuest {
    fn prompt(&self, _id: &BoxId, _text: &str) -> Result<(), GuestError> {
        Err(not_built())
    }
    fn terminal(&self, _id: &BoxId, _after: Option<u64>) -> Result<TermBatch, GuestError> {
        Err(not_built())
    }
    fn diff(&self, _id: &BoxId) -> Result<DiffSummary, GuestError> {
        Err(not_built())
    }
}

impl From<GuestError> for BoxError {
    fn from(e: GuestError) -> BoxError {
        match e {
            GuestError::Unavailable(m) => BoxError::Unavailable(m),
            GuestError::NotConnected => BoxError::Unavailable("the box is not connected".into()),
        }
    }
}
