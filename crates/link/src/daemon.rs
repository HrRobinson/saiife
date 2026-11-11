//! The client of `link.sock`: one blocking `saiife_ipc` connection per call,
//! made inside `spawn_blocking`. The daemon decides everything; this only
//! relays and keeps the daemon's refusal (`error`, `rule`, `message`).
//!
//! The daemon's per-uid budget (connections, in-flight requests, rate) is
//! shared with the user's hooks and CLI, so the whole link (hub sessions
//! and the local server together) makes at most [`MAX_DAEMON_CALLS`] calls
//! at once. A call's permit is held inside its blocking closure: a call
//! whose caller was dropped (a session the hub closed) still counts until
//! the daemon answers or the call times out.

#[cfg(unix)]
use saiife_ipc::client::{Client, ClientError};
#[cfg(unix)]
use saiife_ipc::msg::LINK_SOCKET_NAME;
use serde_json::{Map, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(unix)]
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

#[cfg(unix)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(unix)]
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Daemon calls in flight at once, link-wide: well under the daemon's
/// per-uid caps (32 connections, 64 requests in flight).
pub const MAX_DAEMON_CALLS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// No daemon answered in time, or the exchange broke.
    Unreachable(String),
    /// The daemon answered `ok: false`.
    Refused {
        error: String,
        rule: Option<String>,
        message: String,
    },
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::Unreachable(m) => write!(f, "daemon unreachable: {m}"),
            LinkError::Refused { error, message, .. } => {
                write!(f, "daemon refused ({error}): {message}")
            }
        }
    }
}

impl std::error::Error for LinkError {}

/// One daemon; clones share the call permits.
#[derive(Clone)]
pub struct Daemon {
    socket_dir: PathBuf,
    uid: u32,
    calls: Arc<Calls>,
}

/// The link-wide call budget.
struct Calls {
    permits: Arc<Semaphore>,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

impl Daemon {
    pub fn new(socket_dir: PathBuf, uid: u32) -> Daemon {
        Daemon {
            socket_dir,
            uid,
            calls: Arc::new(Calls {
                permits: Arc::new(Semaphore::new(MAX_DAEMON_CALLS)),
                in_flight: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
            }),
        }
    }

    /// The most calls that were ever in flight at once (tests,
    /// diagnostics); never above [`MAX_DAEMON_CALLS`].
    pub fn peak_calls(&self) -> usize {
        self.calls.peak.load(Ordering::SeqCst)
    }

    /// One call; waits for a permit first.
    pub async fn call(
        &self,
        op: &'static str,
        args: Map<String, Value>,
    ) -> Result<Map<String, Value>, LinkError> {
        let permit = Arc::clone(&self.calls.permits)
            .acquire_owned()
            .await
            .map_err(|_| LinkError::Unreachable("the link is stopping".into()))?;
        let me = self.clone();
        tokio::task::spawn_blocking(move || {
            // Held until the blocking call ends, even if the caller's task
            // was aborted meanwhile.
            let _permit = permit;
            let c = &me.calls;
            let now = c.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            c.peak.fetch_max(now, Ordering::SeqCst);
            let r = me.call_blocking(op, args);
            c.in_flight.fetch_sub(1, Ordering::SeqCst);
            r
        })
        .await
        .map_err(|e| LinkError::Unreachable(format!("call task: {e}")))?
    }

    #[cfg(unix)]
    fn call_blocking(
        &self,
        op: &str,
        args: Map<String, Value>,
    ) -> Result<Map<String, Value>, LinkError> {
        let unreachable = |e: ClientError| LinkError::Unreachable(e.to_string());
        let mut c = Client::connect_named(
            &self.socket_dir,
            LINK_SOCKET_NAME,
            self.uid,
            Instant::now() + CONNECT_TIMEOUT,
        )
        .map_err(unreachable)?;
        // `call_answer` hands back an `ok: false` answer whole, so `rule` survives.
        let ans = c
            .call_answer(op, args, Instant::now() + CALL_TIMEOUT)
            .map_err(unreachable)?;
        if ans.get("ok").and_then(Value::as_bool) == Some(false) {
            let s = |k: &str| ans.get(k).and_then(Value::as_str).map(str::to_string);
            return Err(LinkError::Refused {
                error: s("error").unwrap_or_default(),
                rule: s("rule"),
                message: s("message").unwrap_or_default(),
            });
        }
        Ok(ans)
    }

    #[cfg(not(unix))]
    fn call_blocking(
        &self,
        _op: &str,
        _args: Map<String, Value>,
    ) -> Result<Map<String, Value>, LinkError> {
        let _ = (&self.socket_dir, self.uid);
        Err(LinkError::Unreachable(crate::WINDOWS_MSG.into()))
    }
}
