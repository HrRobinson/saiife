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

use std::time::{Duration, Instant};

pub use bytes::Bytes;

use crate::hooks::Principal;

/// Warm workers the pool keeps, in all.
pub const REJUDGE_POOL: usize = 2;
/// Requests one worker serves before it is replaced.
pub const REJUDGE_MAX_USES: u32 = 500;
/// The longest one request may take, as the hook's `WORKER_TIMEOUT`. The
/// co-signer also keeps it inside `COSIGN_WAIT` from the request's arrival.
pub const REJUDGE_TIMEOUT: Duration = Duration::from_secs(3);
/// Requests of one principal judged at once: one user never holds every
/// worker, so another user's calls are still judged.
pub const REJUDGE_PER_PRINCIPAL: usize = 1;
/// Requests waiting for a worker, in all. One more is `Failed` at once.
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
    use std::sync::Arc;

    // One principal never holds every worker.
    const _: () = assert!(REJUDGE_PER_PRINCIPAL < REJUDGE_POOL);

    #[test]
    fn the_fixed_values() {
        assert_eq!(REJUDGE_POOL, 2);
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
        };
        assert_eq!(r.judge(req(Principal::Uid(1000))), RejudgeAnswer::Allow);
        assert!(matches!(
            r.judge(req(Principal::Uid(0))),
            RejudgeAnswer::Failed(_)
        ));
    }
}
