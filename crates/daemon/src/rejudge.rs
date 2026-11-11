//! The service's own judgment of a co-signed call (plan 21): the interface the
//! co-signer calls, and the values it is bound by. The pool behind it lives in
//! the CLI (`saiife::rejudge`, a blocking type), which passes it in
//! `DaemonOptions.rejudge`; the co-signer calls it on `spawn_blocking`.
//!
//! The judgment is lexical (`FsView::Lexical`): it makes no file system call,
//! so the service never reads the agent user's files. It is made with the
//! asking user's path variables (from the account record, never from an
//! environment the agent set) and the system policy's packs for that user's
//! scope, without the project config (which only adds packs in locked mode).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use bytes::Bytes;

use crate::hooks::Principal;

/// Warm workers the pool keeps, in all.
pub const REJUDGE_POOL: usize = 4;
/// Requests one worker serves before it is replaced.
pub const REJUDGE_MAX_USES: u32 = 500;
/// The longest one request may take, as the hook's `WORKER_TIMEOUT`. The
/// co-signer also keeps it inside `COSIGN_WAIT` from the request's arrival.
pub const REJUDGE_TIMEOUT: Duration = Duration::from_secs(3);
/// Requests of one principal judged at once: one user never holds every
/// worker, so another user's calls are still judged. More than one, so the
/// parallel sessions of one user are not judged one at a time (a burst of
/// 8 calls waited 32 ms at p95 with 1 worker each, 10 ms with 3:
/// `saiife::rejudge` `measure_bursts`).
pub const REJUDGE_PER_PRINCIPAL: usize = 3;
/// Requests waiting for a worker, in all. One more is `Failed` at once. At
/// least the co-signer's `MAX_INFLIGHT`, so this never refuses a request
/// the co-signer let in; it bounds the pool on its own.
pub const REJUDGE_MAX_WAITING: usize = 32;

/// One co-signed call to judge.
#[derive(Debug, Clone)]
pub struct RejudgeRequest {
    /// The request body exactly as Claude Code sent it.
    pub payload: Bytes,
    /// Who asks: the uid (Linux, macOS) or the SID (Windows) of the hook
    /// connection that bound the call's key.
    pub principal: Principal,
    /// Windows: that connection's token groups. Empty elsewhere.
    pub groups: Vec<String>,
    /// No answer after this is `Failed`.
    pub deadline: Instant,
    /// Set once the co-signed request that asked is gone (answered, timed
    /// out, or its connection closed): the pool checks it before it builds
    /// the worker's request and while it waits for a worker, so no judgment
    /// is started or kept waiting for a request nobody reads.
    pub cancel: Cancel,
}

/// A request's cancel flag ([`RejudgeRequest::cancel`]). Clones share it.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Cancel {
        Cancel::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The service's judgment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejudgeAnswer {
    Allow,
    Deny {
        /// The guard's reason.
        reason: String,
        pack: Option<String>,
        rule: Option<String>,
        /// The command, or the paths one per line.
        input: String,
        /// Only `[guard] ask` rules deny it: an approved grant may allow it.
        askable: bool,
    },
    /// No judgment: a worker that crashed, hung, answered badly or could not
    /// be started, a policy that cannot be resolved, or a call the guard
    /// cannot judge. The co-signer denies.
    Failed(String),
}

/// The service's judgment of one call. Blocking: it waits for a worker and
/// its answer, never past `req.deadline`.
pub trait Rejudge: Send + Sync {
    fn judge(&self, req: RejudgeRequest) -> RejudgeAnswer;
    /// Workers started and not yet ended (`status.cosign.rejudge.workers`).
    fn workers(&self) -> usize {
        0
    }
}

/// A closure as a [`Rejudge`] (tests, and fakes in the co-signer's tests).
impl<F> Rejudge for F
where
    F: Fn(RejudgeRequest) -> RejudgeAnswer + Send + Sync,
{
    fn judge(&self, req: RejudgeRequest) -> RejudgeAnswer {
        self(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One principal never holds every worker.
    const _: () = assert!(REJUDGE_PER_PRINCIPAL < REJUDGE_POOL);
    // The queue never refuses a request the co-signer let in: every
    // request in flight there may wait here.
    const _: () = assert!(REJUDGE_MAX_WAITING >= crate::cosign::MAX_INFLIGHT);

    #[test]
    fn the_fixed_values() {
        assert_eq!(REJUDGE_POOL, 4);
        assert_eq!(REJUDGE_PER_PRINCIPAL, 3);
        assert_eq!(REJUDGE_MAX_WAITING, 32);
        assert_eq!(REJUDGE_MAX_USES, 500);
        assert_eq!(REJUDGE_TIMEOUT, Duration::from_secs(3));
        assert!(REJUDGE_TIMEOUT < crate::cosign::COSIGN_WAIT);
    }

    #[test]
    fn a_closure_is_a_rejudge() {
        let r: Arc<dyn Rejudge> = Arc::new(|req: RejudgeRequest| match req.principal {
            Principal::Uid(0) => RejudgeAnswer::Failed("root".into()),
            _ => RejudgeAnswer::Allow,
        });
        let req = |p| RejudgeRequest {
            payload: Bytes::from_static(b"{}"),
            principal: p,
            groups: Vec::new(),
            deadline: Instant::now() + REJUDGE_TIMEOUT,
            cancel: Cancel::new(),
        };
        assert_eq!(r.judge(req(Principal::Uid(1000))), RejudgeAnswer::Allow);
        assert!(matches!(
            r.judge(req(Principal::Uid(0))),
            RejudgeAnswer::Failed(_)
        ));
    }

    #[test]
    fn cancel_is_shared_by_clones() {
        let c = Cancel::new();
        let d = c.clone();
        assert!(!d.is_cancelled());
        c.cancel();
        assert!(d.is_cancelled());
    }
}
