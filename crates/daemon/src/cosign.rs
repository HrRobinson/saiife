//! The Claude Code co-signer (plan 20): a small HTTP/1.1 listener on
//! `127.0.0.1:7433` that the managed drop-in's second `PreToolUse` hook
//! (`type: "http"`, `onFailure: "block"`) posts each call to.
//!
//! It never answers `allow` (decision D3). For a call the command hook has
//! recorded as allowed (same session, tool call id and input hash, and the
//! same principal) **and** that the service's own judgment of the body
//! allows too (plan 21: [`crate::rejudge`], lexical, as the binding hook's
//! principal), it answers `200` with an empty body: no opinion, so the
//! command hook's verdict and Claude Code's own prompts stand. A service
//! deny of only `[guard] ask` rules passes when the binding connection used
//! up a grant for exactly the body's command. Anything else is `200` with a
//! `permissionDecision: "deny"` body: a service deny is one `rejudge_denied`
//! record per call, a failed or late judgment a `rejudge_failed` one. Claude Code runs the
//! two hooks in parallel, so the co-signer waits for the verdict, at most
//! [`COSIGN_WAIT`] from the request's arrival.
//!
//! No token: the answer only ever takes away. A browser request (it carries
//! `Origin`), a wrong content type, a wrong path and a flood each get a
//! refusal that blocks only that request (`onFailure: "block"`). Where the
//! asker's uid is known (Linux, macOS), each uid has its own share of the
//! connection and in-flight caps, so one user's flood leaves room for
//! another's calls; on Windows each asking pid has its own share, and its
//! `cosign_denied` records fold per pid and carry `asker_pid`. The global
//! caps stay as the backstop.

use crate::hooks::{Bound, Principal, Waited};
use crate::ops::{Ctx, VERSION};
use crate::rejudge::{Rejudge, RejudgeAnswer, RejudgeRequest, REJUDGE_TIMEOUT};
use bytes::Bytes;
use http::header::{HeaderValue, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use saiife_audit::{DecisionKind, NewRecord, Record};
use saiife_ipc::hookkey::{hook_key_value, HookKey};
use saiifeguard::payload::{classify_value, ToolCall};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

mod win;

/// The one route.
pub const COSIGN_PATH: &str = "/v1/cosign/claude";
/// How long a request waits for the command hook's verdict, from its
/// arrival. Under the drop-in's `"timeout": 10`.
pub const COSIGN_WAIT: Duration = Duration::from_secs(8);
/// The body cap: a single tool call whose payload is larger (a `Write` of a
/// file over 16 MiB) is denied. Recorded payloads are far smaller (the
/// largest fixture, an `Edit`, is 325 bytes); at the global in-flight cap
/// the bodies stay under 256 MiB.
pub const MAX_BODY: usize = 16 * 1024 * 1024;
/// Requests in flight; one more is answered `503`.
pub const MAX_INFLIGHT: usize = 16;
/// Requests in flight from one uid, where the uid is known; on Windows,
/// from one pid ([`Asker::Process`]).
pub const MAX_INFLIGHT_PER_UID: usize = 8;
/// Open connections; one more is closed at once.
pub const MAX_CONNS: usize = 64;
/// Open connections from one uid, where the uid is known; on Windows, from
/// one pid.
pub const MAX_CONNS_PER_UID: usize = 32;
/// The longest session id a `cosign_denied` record keeps, in bytes
/// (`hook.bind`'s own limit).
pub const MAX_RECORDED_SESSION: usize = crate::sessions::MAX_SESSION_ID;
/// The longest tool name a `cosign_denied` record keeps, in bytes
/// (`hook.bind`'s own limit).
pub const MAX_RECORDED_TOOL: usize = 64;
/// The longest re-judge error a `rejudge_failed` record keeps, in bytes.
const MAX_RECORDED_ERROR: usize = 256;
/// At most one `cosign_denied` record per reason, asker and session this
/// often; the next one carries `suppressed`.
pub const FOLD_EVERY: Duration = Duration::from_secs(10);
/// The fold windows kept at once. When they are all live, a new session
/// folds with the others of its reason and asker.
const MAX_FOLD_KEYS: usize = 256;
/// The fold windows one pid asker (Windows) may hold. A pid is cheap to
/// come by (another process), so past this its sessions fold together.
const MAX_FOLD_KEYS_PER_PID: usize = 16;
/// Debug builds only: `SAIIFE_TEST_COSIGN_ADDR=<addr>` binds the co-signer
/// there instead of [`saiife_system::layout::COSIGN_ADDR`], and `off` binds
/// none. The test suite runs many system daemons at once; release builds
/// never read it.
pub const ADDR_SEAM: &str = "SAIIFE_TEST_COSIGN_ADDR";

/// The co-signer's timeouts and caps; the tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Opts {
    /// The body cap ([`MAX_BODY`]).
    pub max_body: usize,
    pub wait: Duration,
    pub max_inflight: usize,
    /// Per uid, or per pid on Windows ([`MAX_INFLIGHT_PER_UID`]).
    pub max_inflight_per_uid: usize,
    pub max_conns: usize,
    /// Per uid, or per pid on Windows ([`MAX_CONNS_PER_UID`]).
    pub max_conns_per_uid: usize,
    pub header_read_timeout: Duration,
    pub body_read_timeout: Duration,
    /// A whole connection, write included: a client that does not read its
    /// answer cannot keep its slot.
    pub conn_limit: Duration,
    /// Tests only: the uid of a client by its address, in place of
    /// `/proc/net/tcp` (`None` is a client that cannot be identified).
    #[doc(hidden)]
    pub peer_uid: Option<fn(SocketAddr) -> Option<u32>>,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            max_body: MAX_BODY,
            wait: COSIGN_WAIT,
            max_inflight: MAX_INFLIGHT,
            max_inflight_per_uid: MAX_INFLIGHT_PER_UID,
            max_conns: MAX_CONNS,
            max_conns_per_uid: MAX_CONNS_PER_UID,
            header_read_timeout: Duration::from_secs(5),
            body_read_timeout: Duration::from_secs(10),
            conn_limit: Duration::from_secs(30),
            peer_uid: None,
        }
    }
}

/// How a failed bind is tried again: after `first`, then twice as long
/// each time, up to `max`, for the daemon's whole life.
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    pub first: Duration,
    pub max: Duration,
}

impl Default for Retry {
    fn default() -> Retry {
        Retry {
            first: Duration::from_millis(250),
            max: Duration::from_secs(5),
        }
    }
}

/// Why the co-signer denies a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CosignDeny {
    NoReport,
    NoVerdict,
    Denied,
    NotCosignable,
    TooLarge,
    BadJson,
    /// The service's own judgment of the call denies it (plan 21).
    Rejudged,
    /// The service could not judge the call: no pool, a worker that failed
    /// or timed out, or a full pool.
    RejudgeFailed,
}

impl CosignDeny {
    pub fn text(self) -> &'static str {
        match self {
            CosignDeny::NoReport => "no saiife hook reported a verdict for this call",
            CosignDeny::NoVerdict => "the saiife hook ended without a verdict",
            CosignDeny::Denied => "saiife denied this call",
            CosignDeny::NotCosignable => "the call has no session or tool use id",
            CosignDeny::TooLarge => "the payload is too large",
            CosignDeny::BadJson => "the payload is not JSON",
            CosignDeny::Rejudged => "the saiife service's own judgment denies this call",
            CosignDeny::RejudgeFailed => "the saiife service could not judge this call",
        }
    }
}

/// The longest guard reason a [`CosignDeny::Rejudged`] answer carries, in
/// characters.
pub const MAX_REJUDGED_REASON: usize = 200;

/// The deny body, byte for byte as the spec fixes it.
pub fn deny_body(why: CosignDeny) -> String {
    deny_body_text(why.text())
}

/// The [`CosignDeny::Rejudged`] body: its text, then the guard's `reason`
/// cut to [`MAX_REJUDGED_REASON`] characters.
pub fn rejudged_body(reason: &str) -> String {
    let reason: String = reason.chars().take(MAX_REJUDGED_REASON).collect();
    deny_body_text(&format!("{}: {reason}", CosignDeny::Rejudged.text()))
}

fn deny_body_text(text: &str) -> String {
    // A JSON string: a guard reason may hold quotes or backslashes.
    let text = Value::String(format!("saiife: BLOCKED (fail closed): {text}")).to_string();
    format!(
        "{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":{text}}}}}"
    )
}

/// The co-signer's place in `status`, and its record folding.
#[derive(Default)]
pub struct CosignState {
    /// The address bound; `None` before the start, in personal mode, or
    /// while the bind fails.
    pub addr: Option<SocketAddr>,
    /// Why the bind fails (the latest try), until a retry binds it.
    pub error: Option<String>,
    /// How the asker is found, when that worked at the start on a
    /// connection to itself: `"proc_net"` (Linux), `"pcblist"` (macOS),
    /// `"tcp_table"` (Windows).
    /// `None`: not checked yet, or it failed (every call is denied).
    pub asker: Option<&'static str>,
    /// The service's own judgment of each call (plan 21), set by the
    /// system daemon's start. `None`: every co-signed call is denied
    /// ([`CosignDeny::RejudgeFailed`]).
    pub rejudge: Option<Arc<dyn Rejudge>>,
    /// `rejudge_denied` records since the start, and the `ts` of the last.
    pub rejudge_denied: (u64, Option<String>),
    fold: Folder,
}

impl std::fmt::Debug for CosignState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CosignState")
            .field("addr", &self.addr)
            .field("error", &self.error)
            .field("asker", &self.asker)
            .field("rejudge", &self.rejudge.as_ref().map(|r| r.workers()))
            .field("rejudge_denied", &self.rejudge_denied)
            .finish_non_exhaustive()
    }
}

/// `status.cosign.rejudge.error` when the daemon has no re-judge pool.
pub const NO_REJUDGE: &str = "the re-judge pool did not start";

impl CosignState {
    pub fn status(&self) -> serde_json::Value {
        json!({
            "addr": self.addr.map(|a| a.to_string()),
            "error": self.error,
            "asker": self.asker,
            "rejudge": self.rejudge_status(),
        })
    }

    /// `status.cosign.rejudge`: `{"workers": n, "state": "ready" |
    /// "unavailable", "error": null | why}`.
    pub fn rejudge_status(&self) -> serde_json::Value {
        match &self.rejudge {
            Some(r) => json!({"workers": r.workers(), "state": "ready", "error": null}),
            None => json!({"workers": 0, "state": "unavailable", "error": NO_REJUDGE}),
        }
    }

    /// `status.hooks_rejudge_denied`.
    pub fn rejudge_denied_status(&self) -> serde_json::Value {
        let (n, last) = &self.rejudge_denied;
        json!({"since_start": n, "last_ts": last})
    }
}

/// What one fold window is for: a reason, who asked (a principal, or on
/// Windows a pid), and the call's session when the payload names one. So a
/// flood of decoys folds only with itself, never over another asker's or
/// another session's record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FoldKey {
    why: CosignDeny,
    principal: Option<Principal>,
    pid: Option<u32>,
    session: Option<String>,
}

/// One `cosign_denied` record per [`FoldKey`] per [`FOLD_EVERY`], with at
/// most [`MAX_FOLD_KEYS`] windows (and [`MAX_FOLD_KEYS_PER_PID`] per pid)
/// that carry a session.
#[derive(Debug, Default)]
struct Folder {
    /// The start of each window, and the records held back in it.
    windows: HashMap<FoldKey, (Instant, u64)>,
}

impl Folder {
    /// `Some(suppressed)` when a record for `key` is written now, with the
    /// count held back in the window before; `None` when it is held back.
    fn admit(&mut self, key: FoldKey, now: Instant) -> Option<u64> {
        let live = |start: &Instant| now.saturating_duration_since(*start) < FOLD_EVERY;
        let key = self.place(key, now);
        match self.windows.get_mut(&key) {
            Some((start, held)) if live(start) => {
                *held += 1;
                None
            }
            Some((start, held)) => {
                let n = *held;
                *start = now;
                *held = 0;
                Some(n)
            }
            None => {
                self.windows.insert(key, (now, 0));
                Some(0)
            }
        }
    }

    /// The window `key` folds into. Ended windows go first (with any count
    /// they held back) when a cap is reached. Past [`MAX_FOLD_KEYS_PER_PID`]
    /// a pid's sessions fold together; when every window is live, a session
    /// folds with its reason and asker, and a pid asker's into the one
    /// pid-less window of its reason, so new pids add no windows.
    fn place(&mut self, key: FoldKey, now: Instant) -> FoldKey {
        if self.windows.contains_key(&key) {
            return key;
        }
        let live = |start: &Instant| now.saturating_duration_since(*start) < FOLD_EVERY;
        let mut key = key;
        if let Some(pid) = key.pid {
            let of_pid = |w: &HashMap<FoldKey, (Instant, u64)>| {
                w.keys().filter(|k| k.pid == Some(pid)).count()
            };
            if of_pid(&self.windows) >= MAX_FOLD_KEYS_PER_PID {
                self.windows.retain(|_, (start, _)| live(start));
                if of_pid(&self.windows) >= MAX_FOLD_KEYS_PER_PID {
                    key.session = None;
                    if self.windows.contains_key(&key) {
                        return key;
                    }
                }
            }
        }
        if self.windows.len() >= MAX_FOLD_KEYS {
            self.windows.retain(|_, (start, _)| live(start));
        }
        if self.windows.len() < MAX_FOLD_KEYS {
            return key;
        }
        key.session = None;
        if key.pid.is_some() && !self.windows.contains_key(&key) {
            key.pid = None;
        }
        key
    }
}

/// Where the daemon binds the co-signer: the fixed address for the system
/// daemon, none for the personal broker. `test_pipe`: a Windows test daemon
/// (debug builds' test seam), which binds a free port instead.
pub fn target(system: bool, test_pipe: bool) -> Option<SocketAddr> {
    if !system {
        return None;
    }
    #[cfg(debug_assertions)]
    if let Some(v) = std::env::var_os(ADDR_SEAM) {
        let v = v.to_string_lossy();
        return if v == "off" { None } else { v.parse().ok() };
    }
    if test_pipe {
        return Some(SocketAddr::from(([127, 0, 0, 1], 0)));
    }
    saiife_system::layout::COSIGN_ADDR.parse().ok()
}

/// A listener on `addr` that is ours alone (D6). On Linux and macOS
/// `SO_REUSEADDR` is on: it lets the daemon bind again over the last
/// daemon's connections in `TIME_WAIT` after a restart, and it does not let
/// a second socket listen on the same address there. On Windows, where it
/// would, `SO_EXCLUSIVEADDRUSE` is on and `SO_REUSEADDR` off (a bind over
/// `TIME_WAIT` fails there; [`start_cosign`] retries it). For a fixed port
/// the bound address is checked.
pub fn bind_cosign(addr: SocketAddr) -> io::Result<TcpListener> {
    let sock = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        saiife_win::ffi::net::exclusive_addr_use(sock.as_raw_socket())?;
        sock.set_reuseaddr(false)?;
    }
    #[cfg(not(windows))]
    sock.set_reuseaddr(true)?;
    sock.bind(addr)?;
    let l = sock.listen(64)?;
    let bound = l.local_addr()?;
    if addr.port() != 0 && bound != addr {
        return Err(io::Error::other(format!(
            "bound {bound}, not {addr}: the listener is not the co-signer's"
        )));
    }
    Ok(l)
}

/// [`start_cosign_with`] with the default caps and retry.
pub async fn start_cosign(ctx: &Arc<Ctx>, addr: SocketAddr) -> tokio::task::JoinHandle<()> {
    start_cosign_with(ctx, addr, Opts::default(), Retry::default()).await
}

/// Bind `addr` and serve the co-signer on it, in the returned task. A
/// failed bind does not stop the daemon: it is one `daemon` record with
/// `event: "cosign_bind_failed"`, a log line, and `status.cosign.error`
/// for as long as it lasts; the task tries the bind again per `retry` for
/// the daemon's whole life. Claude Code blocks every call
/// (`onFailure: "block"`) until a try binds it.
pub async fn start_cosign_with(
    ctx: &Arc<Ctx>,
    addr: SocketAddr,
    opts: Opts,
    retry: Retry,
) -> tokio::task::JoinHandle<()> {
    let source = tokio::task::spawn_blocking(asker_source)
        .await
        .ok()
        .flatten();
    ctx.cosign.lock().unwrap_or_else(|p| p.into_inner()).asker = source;
    let e = match bind_cosign(addr) {
        Ok(l) => {
            set_bound(ctx, &l);
            return tokio::spawn(serve_cosign_with(l, Arc::clone(ctx), opts));
        }
        Err(e) => e,
    };
    let reason = e.to_string();
    eprintln!(
        "saiife: warning: co-signer {addr} is not available: {reason}; Claude Code calls are blocked until it is (trying again)"
    );
    set_error(ctx, reason.clone());
    let mut r = ctx.event("cosign_bind_failed");
    r.reason = Some(reason);
    r.extra.insert("addr".into(), addr.to_string().into());
    if let Err(e) = ctx.writer.append(r).await {
        eprintln!("saiife: warning: cannot write the cosign_bind_failed record: {e}");
    }
    let ctx = Arc::clone(ctx);
    tokio::spawn(async move {
        let mut pause = retry.first;
        loop {
            tokio::time::sleep(pause).await;
            pause = (pause * 2).min(retry.max);
            match bind_cosign(addr) {
                Ok(l) => {
                    set_bound(&ctx, &l);
                    eprintln!("saiife: co-signer {addr} is listening now");
                    return serve_cosign_with(l, ctx, opts).await;
                }
                Err(e) => set_error(&ctx, e.to_string()),
            }
        }
    })
}

fn set_bound(ctx: &Ctx, l: &TcpListener) {
    let mut st = ctx.cosign.lock().unwrap_or_else(|p| p.into_inner());
    st.addr = l.local_addr().ok();
    st.error = None;
}

fn set_error(ctx: &Ctx, reason: String) {
    let mut st = ctx.cosign.lock().unwrap_or_else(|p| p.into_inner());
    st.addr = None;
    st.error = Some(reason);
}

/// Serve `listener` until the task is dropped.
pub async fn serve_cosign(listener: TcpListener, ctx: Arc<Ctx>) {
    serve_cosign_with(listener, ctx, Opts::default()).await
}

/// The caps shared by the connections of one listener.
#[derive(Clone)]
struct Limits {
    inflight: Arc<Semaphore>,
    per_asker: Arc<PerAsker>,
}

/// [`serve_cosign`] with `opts`.
pub async fn serve_cosign_with(listener: TcpListener, ctx: Arc<Ctx>, opts: Opts) {
    let lim = Limits {
        inflight: Arc::new(Semaphore::new(opts.max_inflight)),
        per_asker: Arc::default(),
    };
    let conns = Arc::new(Semaphore::new(opts.max_conns));
    loop {
        match listener.accept().await {
            Ok((s, peer)) => {
                // Bound to loopback; nothing else is served.
                if !peer.ip().is_loopback() {
                    continue;
                }
                let Ok(slot) = Arc::clone(&conns).try_acquire_owned() else {
                    continue;
                };
                let (ctx, lim) = (Arc::clone(&ctx), lim.clone());
                tokio::spawn(async move {
                    let _slot = slot;
                    let _ =
                        tokio::time::timeout(opts.conn_limit, connection(s, peer, ctx, lim, opts))
                            .await;
                });
            }
            Err(e) => {
                eprintln!("saiife: warning: co-signer accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// One connection: who asks (before any of the body is read), that
/// asker's connection slot, then the one request.
async fn connection(s: TcpStream, peer: SocketAddr, ctx: Arc<Ctx>, lim: Limits, opts: Opts) {
    let who = asker(opts, s.local_addr().ok(), peer).await;
    let _asker_slot = match who.cap_key() {
        Some(k) => match lim.per_asker.take(k, Slot::Conn, opts.max_conns_per_uid) {
            Some(g) => Some(g),
            None => return,
        },
        None => None,
    };
    let svc = service_fn(move |req| {
        let (ctx, lim, who) = (Arc::clone(&ctx), lim.clone(), who.clone());
        async move { Ok::<_, Infallible>(handle(&ctx, &lim, opts, req, who).await) }
    });
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .keep_alive(false)
        .max_buf_size(64 * 1024)
        .header_read_timeout(opts.header_read_timeout)
        .serve_connection(TokioIo::new(s), svc)
        .await;
}

/// Whose share of the caps a connection takes: a uid's, or on Windows a
/// pid's (security review of task 4, finding 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CapKey {
    Uid(u32),
    Pid(u32),
}

/// The connections and requests in flight per uid or pid.
#[derive(Debug, Default)]
struct PerAsker {
    counts: Mutex<HashMap<CapKey, [usize; 2]>>,
}

#[derive(Debug, Clone, Copy)]
enum Slot {
    Conn = 0,
    Inflight = 1,
}

/// A held [`PerAsker`] slot, given back on drop.
struct AskerSlot {
    table: Arc<PerAsker>,
    key: CapKey,
    slot: Slot,
}

impl PerAsker {
    fn take(self: &Arc<Self>, key: CapKey, slot: Slot, max: usize) -> Option<AskerSlot> {
        let mut m = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let c = m.entry(key).or_default();
        if c[slot as usize] >= max {
            if *c == [0, 0] {
                m.remove(&key);
            }
            return None;
        }
        c[slot as usize] += 1;
        Some(AskerSlot {
            table: Arc::clone(self),
            key,
            slot,
        })
    }
}

impl Drop for AskerSlot {
    fn drop(&mut self) {
        let mut m = self.table.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = m.get_mut(&self.key) {
            c[self.slot as usize] = c[self.slot as usize].saturating_sub(1);
            if *c == [0, 0] {
                m.remove(&self.key);
            }
        }
    }
}

type Resp = Response<Full<Bytes>>;

fn plain(status: StatusCode, text: &'static str) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from_static(text.as_bytes())));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    r.headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    r
}

/// `200`, no body: no opinion.
fn no_opinion() -> Resp {
    let mut r = Response::new(Full::new(Bytes::new()));
    r.headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    r
}

fn deny(why: CosignDeny) -> Resp {
    deny_with(deny_body(why))
}

fn deny_with(body: String) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(body)));
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r.headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    r
}

/// `application/json`, with or without parameters, in any case.
fn is_json(h: &http::HeaderMap) -> bool {
    h.get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
}

/// Who asks: on Linux the uid of the client's socket, from `/proc/net`; on
/// macOS from `net.inet.tcp.pcblist_n` (`asker_macos`); on Windows the pid
/// that owns it ([`Asker::Process`]). Elsewhere a TCP peer is not identified
/// (W13), and every principal's verdict counts.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Asker {
    Known(Principal),
    /// Windows: the pid that owns the client's socket (`GetExtendedTcpTable`).
    /// The service cannot read that process's token (plan 21, D2), so the
    /// principal is the binding hook connection's, and the binder must run
    /// under this pid ([`crate::hooks::ASKER_MAX_DEPTH`]).
    Process(u32),
    Unscoped,
    /// The socket could not be found: denied.
    Unknown,
}

impl Asker {
    /// The share of the caps this asker takes: its uid, or (Windows) its
    /// pid. An asker that is not identified takes the global caps only.
    fn cap_key(&self) -> Option<CapKey> {
        match self {
            Asker::Known(Principal::Uid(u)) => Some(CapKey::Uid(*u)),
            Asker::Process(pid) => Some(CapKey::Pid(*pid)),
            _ => None,
        }
    }

    /// The pid of an [`Asker::Process`].
    fn pid(&self) -> Option<u32> {
        match self {
            Asker::Process(pid) => Some(*pid),
            _ => None,
        }
    }

    fn principal(&self) -> Option<&Principal> {
        match self {
            Asker::Known(p) => Some(p),
            _ => None,
        }
    }
}

async fn asker(opts: Opts, local: Option<SocketAddr>, peer: SocketAddr) -> Asker {
    let known = |uid: Option<u32>| uid.map_or(Asker::Unknown, |u| Asker::Known(Principal::Uid(u)));
    if let Some(f) = opts.peer_uid {
        let _ = local;
        return known(f(peer));
    }
    if cfg!(windows) {
        return win::asker(local, peer).await;
    }
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Asker::Unscoped;
    }
    let Some(local) = local else {
        return Asker::Unknown;
    };
    known(
        tokio::task::spawn_blocking(move || socket_uid(local, peer))
            .await
            .ok()
            .flatten(),
    )
}

/// The uid that owns the client end of a connection the co-signer
/// accepted (`local` its own end, `peer` the client's).
#[cfg(not(target_os = "macos"))]
fn socket_uid(local: SocketAddr, peer: SocketAddr) -> Option<u32> {
    crate::mcp_gateway::tcp_peer_socket(local, peer).map(|(uid, _)| uid)
}

#[cfg(target_os = "macos")]
fn socket_uid(local: SocketAddr, peer: SocketAddr) -> Option<u32> {
    asker_macos::socket_uid(local, peer)
}

/// Who asks, on macOS (plan 21, Task 5): the `so_uid` of the client's
/// socket in `net.inet.tcp.pcblist_n`, a private kernel layout (D4) that
/// `saiife_darwin` reads and parses strictly. A layout it does not know,
/// a failed read, or no matching socket is no uid: the asker is
/// `Asker::Unknown`, and the call is denied.
#[cfg(target_os = "macos")]
pub mod asker_macos {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The `status.cosign.asker` name of this source.
    pub const SOURCE: &str = "pcblist";

    /// One warning per daemon for a read or layout failure; every call
    /// it hits is denied all the same.
    static WARNED: AtomicBool = AtomicBool::new(false);

    pub(super) fn socket_uid(local: SocketAddr, peer: SocketAddr) -> Option<u32> {
        match saiife_darwin::tcp_peer_uid_checked(local, peer) {
            Ok(uid) => uid,
            Err(e) => {
                if !WARNED.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "saiife: warning: the co-signer cannot tell who asks ({e}); Claude Code calls are blocked"
                    );
                }
                None
            }
        }
    }
}

/// How this system finds the asker, when that works on a connection the
/// daemon makes to itself; `None` when it does not (or there is none here).
fn asker_source() -> Option<&'static str> {
    if cfg!(windows) {
        let me = std::process::id();
        return self_connection(|local, peer| win::owner_pid(local, peer) == Some(me))
            .then_some("tcp_table");
    }
    if cfg!(target_os = "linux") {
        return self_connection(|local, peer| {
            crate::mcp_gateway::tcp_peer_socket(local, peer).is_some()
        })
        .then_some("proc_net");
    }
    if cfg!(target_os = "macos") {
        return macos_source();
    }
    None
}

/// macOS: [`asker_macos::SOURCE`] when the pcb list shows the daemon's own
/// uid on a connection to itself.
#[cfg(target_os = "macos")]
fn macos_source() -> Option<&'static str> {
    let me = saiife_darwin::proc_info(std::process::id())?.uid;
    self_connection(|local, peer| asker_macos::socket_uid(local, peer) == Some(me))
        .then_some(asker_macos::SOURCE)
}

#[cfg(not(target_os = "macos"))]
fn macos_source() -> Option<&'static str> {
    None
}

/// `check(local, peer)` on a loopback connection of this process to itself,
/// as the co-signer sees one it accepted.
fn self_connection(check: impl FnOnce(SocketAddr, SocketAddr) -> bool) -> bool {
    let Ok(l) = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)) else {
        return false;
    };
    let Ok(local) = l.local_addr() else {
        return false;
    };
    let Ok(_client) = std::net::TcpStream::connect(local) else {
        return false;
    };
    match l.accept() {
        Ok((_server, peer)) => check(local, peer),
        Err(_) => false,
    }
}

async fn handle(
    ctx: &Arc<Ctx>,
    lim: &Limits,
    opts: Opts,
    req: Request<Incoming>,
    who: Asker,
) -> Resp {
    let arrival = Instant::now();
    if req.method() != Method::POST || req.uri().path() != COSIGN_PATH {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    // A browser's request (a local web page) carries `Origin`.
    if req.headers().contains_key(ORIGIN) {
        return plain(StatusCode::FORBIDDEN, "forbidden\n");
    }
    if !is_json(req.headers()) {
        return plain(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "the body must be application/json\n",
        );
    }
    // No verdict can be this asker's: denied before the body is read.
    if who == Asker::Unknown {
        return denied(ctx, CosignDeny::NoReport, &who, None).await;
    }
    let _asker_permit = match who.cap_key() {
        Some(k) => match lim
            .per_asker
            .take(k, Slot::Inflight, opts.max_inflight_per_uid)
        {
            Some(g) => Some(g),
            None => return plain(StatusCode::SERVICE_UNAVAILABLE, "busy\n"),
        },
        None => None,
    };
    let Ok(_permit) = Arc::clone(&lim.inflight).try_acquire_owned() else {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "busy\n");
    };
    let body = match read_body(req, opts).await {
        Ok(b) => b,
        Err(why) => return denied(ctx, why, &who, None).await,
    };
    judge_body(ctx, opts, arrival, body, &who).await
}

/// What the co-signer keeps of a request body, parsed once: the call's
/// key, its tool, and its input as the guard would show it.
#[derive(Debug)]
struct Call {
    key: HookKey,
    tool: Option<String>,
    input: String,
    /// A shell call's command, as the hook hashes it for a grant
    /// (`raw_sha256`).
    command: Option<String>,
    /// Claude Code's `cwd`: a grant's project root must hold it.
    cwd: Option<String>,
}

/// The one parse of a body.
fn parse(body: &[u8]) -> Result<Call, CosignDeny> {
    let v: Value = serde_json::from_slice(body).map_err(|_| CosignDeny::BadJson)?;
    let key = hook_key_value("claude", &v).map_err(|_| CosignDeny::BadJson)?;
    let tool = ["tool_name", "toolName"]
        .into_iter()
        .find_map(|f| v.get(f).and_then(Value::as_str))
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    let (input, command) = match classify_value(&v, Some("claude"), cfg!(windows)) {
        Ok(ToolCall::Shell { command, .. }) => (command.clone(), Some(command)),
        Ok(ToolCall::File { paths, .. }) => (paths.join(" "), None),
        Ok(ToolCall::Other { .. }) | Err(_) => (String::new(), None),
    };
    Ok(Call {
        key,
        tool,
        input,
        command,
        cwd: v.get("cwd").and_then(Value::as_str).map(str::to_string),
    })
}

/// The answer for a request body that arrived at `arrival`. The body is
/// parsed on a blocking thread, never on a runtime worker; the request's
/// in-flight slot bounds how many parses run at once.
async fn judge_body(
    ctx: &Arc<Ctx>,
    opts: Opts,
    arrival: Instant,
    body: Bytes,
    who: &Asker,
) -> Resp {
    let parsed = body.clone();
    let call = match tokio::task::spawn_blocking(move || parse(&parsed)).await {
        Ok(Ok(c)) => c,
        Ok(Err(why)) => return denied(ctx, why, who, None).await,
        Err(_) => return denied(ctx, CosignDeny::BadJson, who, None).await,
    };
    judge(ctx, opts, arrival, &call, body, who).await
}

/// The answer for `call` (whose body is `body`), asked by `who`. Both
/// must agree (plan 21): the hook's recorded verdict, and the service's
/// own judgment of `body`. Where the asker's principal is known (Linux,
/// macOS) that judgment starts at once, beside the wait; elsewhere it
/// starts once the wait names the binder.
async fn judge(
    ctx: &Arc<Ctx>,
    opts: Opts,
    arrival: Instant,
    call: &Call,
    body: Bytes,
    who: &Asker,
) -> Resp {
    if !call.key.cosignable() {
        return denied(ctx, CosignDeny::NotCosignable, who, Some(call)).await;
    }
    let (principal, asker_pid) = match who {
        Asker::Known(p) => (Some(p), None),
        Asker::Process(pid) => (None, Some(*pid)),
        Asker::Unscoped => (None, None),
        Asker::Unknown => return denied(ctx, CosignDeny::NoReport, who, Some(call)).await,
    };
    let until = arrival + opts.wait;
    let early =
        principal.map(|p| Rejudging::start(ctx, body.clone(), p.clone(), Vec::new(), until));
    let bound = match ctx.hooks.wait(&call.key, principal, asker_pid, until).await {
        Waited::Allow(b) => b,
        // The guard record says why. A judgment still running is dropped.
        Waited::Deny => return deny(CosignDeny::Denied),
        Waited::NoVerdict => return denied(ctx, CosignDeny::NoVerdict, who, Some(call)).await,
        Waited::Timeout | Waited::Foreign => {
            return denied(ctx, CosignDeny::NoReport, who, Some(call)).await
        }
    };
    let rejudging = match early {
        Some(r) => r,
        None => Rejudging::start(
            ctx,
            body,
            bound.principal.clone(),
            bound.groups.clone(),
            until,
        ),
    };
    match rejudging.answer().await {
        RejudgeAnswer::Allow => no_opinion(),
        RejudgeAnswer::Deny { askable: true, .. } if granted(&bound, call) => no_opinion(),
        RejudgeAnswer::Deny {
            reason,
            pack,
            rule,
            input,
            ..
        } => {
            let d = Disagreed {
                reason: &reason,
                pack: pack.as_deref(),
                rule: rule.as_deref(),
                input: &input,
            };
            rejudge_denied(ctx, &bound, call, d).await;
            deny_with(rejudged_body(&reason))
        }
        RejudgeAnswer::Failed(e) => {
            record_as(ctx, CosignDeny::RejudgeFailed, who, Some(call), Some(&e)).await;
            deny(CosignDeny::RejudgeFailed)
        }
    }
}

/// Whether the binding connection used up a grant for exactly this call:
/// only that lets an `ask` deny of the service pass. The grant key is
/// computed again from the co-signed body's own fields, as `grant.consume`
/// computes it (`grants::grant_key`: the binder's principal, the agent, the
/// grant's project root, the body's tool, and its command and the
/// command's SHA-256), and must be the key used up. The body's `cwd` must
/// be that project root or lie below it.
fn granted(bound: &Bound, call: &Call) -> bool {
    use sha2::{Digest, Sha256};
    let (Some(grant), Some(command), Some(tool), Some(cwd)) =
        (&bound.grant, &call.command, &call.tool, &call.cwd)
    else {
        return false;
    };
    if !crate::approval_ops::within_project(cwd, &grant.project) {
        return false;
    }
    let raw: [u8; 32] = Sha256::digest(command.as_bytes()).into();
    let key = match &bound.principal {
        Principal::Uid(uid) => {
            crate::grants::grant_key(*uid, "claude", &grant.project, tool, command, &raw)
        }
        Principal::Sid(sid) => {
            crate::grants::grant_key_for_sid(sid, "claude", &grant.project, tool, command, &raw)
        }
    };
    crate::grants::hex(&key).eq_ignore_ascii_case(&grant.key)
}

/// The service's own judgment of one call, on a blocking thread.
enum Rejudging {
    Running {
        task: tokio::task::JoinHandle<RejudgeAnswer>,
        deadline: Instant,
    },
    /// No pool: nothing to run.
    Done(RejudgeAnswer),
}

impl Rejudging {
    /// Start judging `body` as `principal`; it must answer by `until` (the
    /// co-sign wait) and within [`REJUDGE_TIMEOUT`] from now.
    fn start(
        ctx: &Ctx,
        body: Bytes,
        principal: Principal,
        groups: Vec<String>,
        until: Instant,
    ) -> Rejudging {
        let pool = ctx
            .cosign
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .rejudge
            .clone();
        let Some(pool) = pool else {
            return Rejudging::Done(RejudgeAnswer::Failed(NO_REJUDGE.into()));
        };
        let deadline = until.min(Instant::now() + REJUDGE_TIMEOUT);
        let req = RejudgeRequest {
            payload: body,
            principal,
            groups,
            deadline: deadline.into_std(),
        };
        Rejudging::Running {
            task: tokio::task::spawn_blocking(move || pool.judge(req)),
            deadline,
        }
    }

    /// The answer, or `Failed` past the deadline or on a panic.
    async fn answer(self) -> RejudgeAnswer {
        match self {
            Rejudging::Done(a) => a,
            Rejudging::Running { task, deadline } => {
                match tokio::time::timeout_at(deadline, task).await {
                    Ok(Ok(a)) => a,
                    Ok(Err(_)) => RejudgeAnswer::Failed("the re-judge panicked".into()),
                    Err(_) => RejudgeAnswer::Failed("the re-judge timed out".into()),
                }
            }
        }
    }
}

/// The body, at most `opts.max_body`: a larger `Content-Length` or more
/// bytes is [`CosignDeny::TooLarge`]; a body that does not arrive in time
/// or cannot be read is [`CosignDeny::BadJson`].
async fn read_body(req: Request<Incoming>, opts: Opts) -> Result<Bytes, CosignDeny> {
    let (parts, body) = req.into_parts();
    let declared = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|n| n > opts.max_body as u64) {
        return Err(CosignDeny::TooLarge);
    }
    match tokio::time::timeout(
        opts.body_read_timeout,
        Limited::new(body, opts.max_body).collect(),
    )
    .await
    {
        Ok(Ok(c)) => Ok(c.to_bytes()),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => Err(CosignDeny::TooLarge),
        Ok(Err(_)) | Err(_) => Err(CosignDeny::BadJson),
    }
}

/// The deny answer for `why`, with its `cosign_denied` record (folded).
async fn denied(ctx: &Arc<Ctx>, why: CosignDeny, who: &Asker, call: Option<&Call>) -> Resp {
    record(ctx, why, who, call).await;
    deny(why)
}

/// What the service's own judgment said of a call the hook allowed.
struct Disagreed<'a> {
    reason: &'a str,
    pack: Option<&'a str>,
    rule: Option<&'a str>,
    input: &'a str,
}

/// The `rejudge_denied` record of a call the hook allowed and the
/// service's own judgment denied: one per call, never folded (owner
/// ruling 4), unless the audit volume is below its floor. It is counted
/// in `status.hooks_rejudge_denied` either way.
async fn rejudge_denied(ctx: &Arc<Ctx>, bound: &Bound, call: &Call, d: Disagreed<'_>) {
    let ts = crate::ops::now_ts();
    {
        let mut st = ctx.cosign.lock().unwrap_or_else(|p| p.into_inner());
        st.rejudge_denied.0 += 1;
        st.rejudge_denied.1 = Some(ts.clone());
    }
    let p = ctx.policy();
    let free = crate::disk::free_mb(&ctx.audit_dir).unwrap_or(0);
    if crate::disk::disk_gate(free, p.min_free_mb, false).is_err() {
        return;
    }
    let session = call
        .key
        .session
        .as_deref()
        .map(|s| capped(s, MAX_RECORDED_SESSION));
    let tool = call
        .tool
        .as_deref()
        .map(|t| capped(t, MAX_RECORDED_TOOL))
        .unwrap_or_default();
    let input = if d.input.is_empty() {
        call.input.as_str()
    } else {
        d.input
    };
    let mut r = Record::new(
        NewRecord {
            agent: "claude",
            project: "",
            session: session.as_deref(),
            tool: &tool,
            input,
            decision: DecisionKind::Deny,
            pack: d.pack,
            rule: d.rule,
            reason: Some(d.reason),
            mode: ctx.mode.as_str(),
            policy: p.hash.as_deref(),
            permission_mode: None,
        },
        VERSION,
    );
    r.ts = ts;
    r.kind = Some("hook".into());
    match &bound.principal {
        Principal::Uid(u) => r.uid = Some(*u),
        Principal::Sid(s) => r.sid = Some(s.clone()),
    }
    let x = &mut r.extra;
    x.insert("event".into(), "rejudge_denied".into());
    x.insert("hook_pid".into(), bound.pid.into());
    x.insert(
        "tool_use_id".into(),
        json!(call
            .key
            .tool_use_id
            .as_deref()
            .map(crate::hooks::recorded_id)),
    );
    if let Err(e) = ctx.writer.append(r).await {
        eprintln!("saiife: warning: cannot write a rejudge_denied record: {e}");
    }
}

/// `s` masked and cut to at most `max` bytes on a character boundary.
fn capped(s: &str, max: usize) -> String {
    saiife_audit::mask::mask_cut(s, max)
}

/// The `cosign_denied` record of a deny, unless [`FOLD_EVERY`] holds it
/// back, or the audit volume is below its floor (a TCP peer is never the
/// daemon itself). The session and the input are the asker's own words:
/// they are kept only when the asker is identified, and every string is
/// capped as `hook.bind` caps it.
async fn record(ctx: &Arc<Ctx>, why: CosignDeny, who: &Asker, call: Option<&Call>) {
    record_as(ctx, why, who, call, None).await
}

/// [`record`], and for [`CosignDeny::RejudgeFailed`] a `rejudge_failed`
/// record (folded the same way) whose `error` says what failed.
async fn record_as(
    ctx: &Arc<Ctx>,
    why: CosignDeny,
    who: &Asker,
    call: Option<&Call>,
    error: Option<&str>,
) {
    let session = call
        .and_then(|c| c.key.session.as_deref())
        .map(|s| capped(s, MAX_RECORDED_SESSION));
    let fold = FoldKey {
        why,
        principal: who.principal().cloned(),
        pid: who.pid(),
        session: session.clone(),
    };
    let suppressed = {
        let mut st = ctx.cosign.lock().unwrap_or_else(|p| p.into_inner());
        match st.fold.admit(fold, Instant::now()) {
            Some(n) => n,
            None => return,
        }
    };
    let p = ctx.policy();
    let free = crate::disk::free_mb(&ctx.audit_dir).unwrap_or(0);
    if crate::disk::disk_gate(free, p.min_free_mb, false).is_err() {
        return;
    }
    let identified = matches!(who, Asker::Known(_));
    let session = session.filter(|_| identified);
    let input = call
        .filter(|_| identified)
        .map(|c| c.input.as_str())
        .unwrap_or("");
    let tool = call
        .and_then(|c| c.tool.as_deref())
        .map(|t| capped(t, MAX_RECORDED_TOOL))
        .unwrap_or_default();
    let mut r = Record::new(
        NewRecord {
            agent: "claude",
            project: "",
            session: session.as_deref(),
            tool: &tool,
            input,
            decision: DecisionKind::ErrorDenied,
            pack: None,
            rule: None,
            reason: Some(why.text()),
            mode: ctx.mode.as_str(),
            policy: p.hash.as_deref(),
            permission_mode: None,
        },
        VERSION,
    );
    r.kind = Some("hook".into());
    let x = &mut r.extra;
    let event = match why {
        CosignDeny::RejudgeFailed => "rejudge_failed",
        _ => "cosign_denied",
    };
    x.insert("event".into(), event.into());
    if let Some(e) = error {
        x.insert("error".into(), capped(e, MAX_RECORDED_ERROR).into());
    }
    // The call by its id only: no hash of the input (see `hooks::Verdict`).
    x.insert(
        "tool_use_id".into(),
        json!(call
            .and_then(|c| c.key.tool_use_id.as_deref())
            .map(crate::hooks::recorded_id)),
    );
    // A pid asker (Windows) is no principal, but its pid tells floods apart.
    if let Some(pid) = who.pid() {
        x.insert("asker_pid".into(), pid.into());
    }
    if suppressed > 0 {
        x.insert("suppressed".into(), suppressed.into());
    }
    if let Err(e) = ctx.writer.append(r).await {
        eprintln!("saiife: warning: cannot write a {event} record: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_body_is_byte_for_byte() {
        assert_eq!(
            deny_body(CosignDeny::Denied),
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"saiife: BLOCKED (fail closed): saiife denied this call"}}"#
        );
        for d in [
            CosignDeny::NoReport,
            CosignDeny::NoVerdict,
            CosignDeny::Denied,
            CosignDeny::NotCosignable,
            CosignDeny::TooLarge,
            CosignDeny::BadJson,
            CosignDeny::Rejudged,
            CosignDeny::RejudgeFailed,
        ] {
            let v: serde_json::Value = serde_json::from_str(&deny_body(d)).unwrap();
            assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
            assert!(!d.text().contains('"') && !d.text().contains('\\'));
        }
        assert_eq!(
            deny_body(CosignDeny::RejudgeFailed),
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"saiife: BLOCKED (fail closed): the saiife service could not judge this call"}}"#
        );
    }

    /// The guard's reason, escaped and cut to 200 characters.
    #[test]
    fn rejudged_body_carries_the_reason() {
        let b = rejudged_body(r#"a "quoted" \ reason"#);
        assert_eq!(
            b,
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"saiife: BLOCKED (fail closed): the saiife service's own judgment denies this call: a \"quoted\" \\ reason"}}"#
        );
        let long = "é".repeat(300);
        let v: Value = serde_json::from_str(&rejudged_body(&long)).unwrap();
        let why = v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(why.ends_with(&"é".repeat(MAX_REJUDGED_REASON)));
        assert!(!why.ends_with(&"é".repeat(MAX_REJUDGED_REASON + 1)));
    }

    #[test]
    fn fixed_values() {
        assert_eq!(COSIGN_WAIT, Duration::from_secs(8));
        assert_eq!(MAX_INFLIGHT, 16);
        assert_eq!(MAX_INFLIGHT_PER_UID, 8);
        assert_eq!(MAX_CONNS_PER_UID, 32);
        assert_eq!(Opts::default().max_body, 16 * 1024 * 1024);
        assert_eq!(MAX_RECORDED_SESSION, 128);
        assert_eq!(MAX_RECORDED_TOOL, 64);
        assert_eq!(COSIGN_PATH, "/v1/cosign/claude");
        assert_eq!(saiife_system::layout::COSIGN_ADDR, "127.0.0.1:7433");
    }

    /// Every recorded Claude Code payload is far under the body cap.
    #[test]
    fn claude_fixtures_are_far_under_the_cap() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../cli/tests/fixtures/claude");
        let mut largest = 0;
        for e in std::fs::read_dir(dir).unwrap() {
            let len = e.unwrap().metadata().unwrap().len();
            largest = largest.max(len);
        }
        assert!(largest > 0);
        assert!(
            largest * 1000 < MAX_BODY as u64,
            "largest fixture {largest} bytes"
        );
    }

    #[test]
    fn json_content_types() {
        let h = |v: &str| {
            let mut m = http::HeaderMap::new();
            m.insert(CONTENT_TYPE, HeaderValue::from_str(v).unwrap());
            m
        };
        assert!(is_json(&h("application/json")));
        assert!(is_json(&h("Application/JSON; charset=utf-8")));
        assert!(!is_json(&h("text/plain")));
        assert!(!is_json(&h("application/jsonx")));
        assert!(!is_json(&http::HeaderMap::new()));
    }

    #[test]
    fn personal_mode_does_not_bind() {
        assert_eq!(target(false, false), None);
        assert_eq!(target(false, true), None);
    }

    fn fk(why: CosignDeny, uid: Option<u32>, session: Option<&str>) -> FoldKey {
        FoldKey {
            why,
            principal: uid.map(Principal::Uid),
            pid: None,
            session: session.map(str::to_string),
        }
    }

    /// A fold key of a pid asker (Windows).
    fn fp(why: CosignDeny, pid: u32, session: &str) -> FoldKey {
        FoldKey {
            pid: Some(pid),
            ..fk(why, None, Some(session))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fold_windows_are_bounded_per_pid() {
        let mut f = Folder::default();
        let t0 = Instant::now();
        let why = CosignDeny::NoReport;
        for n in 0..MAX_FOLD_KEYS_PER_PID {
            assert_eq!(f.admit(fp(why, 7, &format!("s-{n}")), t0), Some(0));
        }
        // Past its share, the pid's new sessions fold together.
        assert_eq!(f.admit(fp(why, 7, "new-1"), t0), Some(0));
        assert_eq!(f.admit(fp(why, 7, "new-2"), t0), None);
        assert_eq!(f.windows.len(), MAX_FOLD_KEYS_PER_PID + 1);
        // Another pid, and a pid-less asker with the same session, have their own.
        assert_eq!(f.admit(fp(why, 8, "new-1"), t0), Some(0));
        assert_eq!(f.admit(fk(why, None, Some("new-1")), t0), Some(0));
        // Once the windows end, the pid has room again.
        assert_eq!(f.admit(fp(why, 7, "new-3"), t0 + FOLD_EVERY), Some(0));
    }

    #[tokio::test(start_paused = true)]
    async fn many_pids_add_no_windows_when_all_are_live() {
        let mut f = Folder::default();
        let t0 = Instant::now();
        let why = CosignDeny::NoReport;
        for n in 0..MAX_FOLD_KEYS {
            let k = fk(why, Some(1), Some(&format!("s-{n}")));
            assert_eq!(f.admit(k, t0), Some(0));
        }
        // Every window is live: new pids share one pid-less window.
        assert_eq!(f.admit(fp(why, 100, "a"), t0), Some(0));
        for pid in 101..1000 {
            assert_eq!(f.admit(fp(why, pid, "a"), t0), None, "{pid}");
        }
        assert_eq!(f.windows.len(), MAX_FOLD_KEYS + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn folding_one_record_per_key_per_window() {
        let mut f = Folder::default();
        let t0 = Instant::now();
        let k = fk(CosignDeny::NoReport, Some(1000), Some("c-1"));
        assert_eq!(f.admit(k.clone(), t0), Some(0));
        for i in 1..20 {
            let at = t0 + Duration::from_millis(i * 400);
            assert_eq!(f.admit(k.clone(), at), None);
        }
        // Another reason, another session, another asker: each its own window.
        assert_eq!(
            f.admit(fk(CosignDeny::BadJson, Some(1000), Some("c-1")), t0),
            Some(0)
        );
        assert_eq!(
            f.admit(fk(CosignDeny::NoReport, Some(1000), Some("c-2")), t0),
            Some(0)
        );
        assert_eq!(
            f.admit(fk(CosignDeny::NoReport, Some(1001), Some("c-1")), t0),
            Some(0)
        );
        assert_eq!(
            f.admit(fk(CosignDeny::NoReport, None, Some("c-1")), t0),
            Some(0)
        );
        assert_eq!(
            f.admit(k.clone(), t0 + FOLD_EVERY),
            Some(19),
            "the next one carries the count"
        );
        assert_eq!(f.admit(k, t0 + FOLD_EVERY * 3), Some(0));
    }

    #[tokio::test(start_paused = true)]
    async fn fold_windows_are_bounded() {
        let mut f = Folder::default();
        let t0 = Instant::now();
        for n in 0..MAX_FOLD_KEYS {
            let s = format!("s-{n}");
            assert_eq!(
                f.admit(fk(CosignDeny::NoReport, Some(1), Some(&s)), t0),
                Some(0)
            );
        }
        // All live: new sessions fold with their reason and asker.
        assert_eq!(
            f.admit(fk(CosignDeny::NoReport, Some(1), Some("new-1")), t0),
            Some(0)
        );
        assert_eq!(
            f.admit(fk(CosignDeny::NoReport, Some(1), Some("new-2")), t0),
            None
        );
        // Another asker still has a window of its own.
        assert_eq!(
            f.admit(fk(CosignDeny::NoReport, Some(2), Some("new-1")), t0),
            Some(0)
        );
        assert!(f.windows.len() <= MAX_FOLD_KEYS + 2);
        // Once the windows end, they make room again.
        let later = t0 + FOLD_EVERY;
        assert_eq!(
            f.admit(fk(CosignDeny::NoReport, Some(1), Some("new-3")), later),
            Some(0)
        );
        assert!(f.windows.len() <= 2, "{}", f.windows.len());
    }

    #[test]
    fn per_uid_slots_are_given_back() {
        let t = Arc::new(PerAsker::default());
        let u = CapKey::Uid;
        let a: Vec<_> = (0..3)
            .map(|_| t.take(u(1), Slot::Inflight, 3).unwrap())
            .collect();
        assert!(t.take(u(1), Slot::Inflight, 3).is_none());
        assert!(t.take(u(2), Slot::Inflight, 3).is_some(), "another uid");
        let p = t.take(CapKey::Pid(1), Slot::Inflight, 3);
        assert!(p.is_some(), "a pid is not the uid");
        drop(p);
        let c = t.take(u(1), Slot::Conn, 3).unwrap();
        drop(a);
        assert!(t.take(u(1), Slot::Inflight, 3).is_some());
        drop(c);
        assert!(t.counts.lock().unwrap().is_empty());
        assert!(t.take(u(9), Slot::Conn, 0).is_none());
        assert!(t.counts.lock().unwrap().is_empty());
    }

    /// A pid asker (Windows) has its own share of the caps; an asker that
    /// is not identified has none.
    #[test]
    fn pid_askers_take_their_own_share() {
        assert_eq!(Asker::Process(77).cap_key(), Some(CapKey::Pid(77)));
        let me = Asker::Known(Principal::Uid(4242));
        assert_eq!(me.cap_key(), Some(CapKey::Uid(4242)));
        assert_eq!(Asker::Unscoped.cap_key(), None);
        assert_eq!(Asker::Unknown.cap_key(), None);
        let t = Arc::new(PerAsker::default());
        let max = MAX_CONNS_PER_UID;
        let held: Vec<_> = (0..max)
            .map(|_| t.take(CapKey::Pid(77), Slot::Conn, max).unwrap())
            .collect();
        assert!(t.take(CapKey::Pid(77), Slot::Conn, max).is_none());
        assert!(t.take(CapKey::Pid(78), Slot::Conn, max).is_some());
        drop(held);
        assert!(t.counts.lock().unwrap().is_empty());
    }

    #[test]
    fn parse_once_keeps_key_tool_and_input() {
        let c = parse(payload("toolu_1", "ls -la").as_bytes()).unwrap();
        assert_eq!(
            c.key,
            saiife_ipc::hookkey::hook_key("claude", &payload("toolu_1", "ls -la")).unwrap()
        );
        assert_eq!(c.tool.as_deref(), Some("Bash"));
        assert_eq!(c.input, "ls -la");
        assert_eq!(parse(b"{not json").unwrap_err(), CosignDeny::BadJson);
        assert_eq!(parse(b"[1]").unwrap_err(), CosignDeny::BadJson);
        assert_eq!(parse(b"\xff").unwrap_err(), CosignDeny::BadJson);
    }

    fn payload(tool_use_id: &str, command: &str) -> String {
        payload_in("c-1", "Bash", tool_use_id, command)
    }

    fn payload_in(session: &str, tool: &str, tool_use_id: &str, command: &str) -> String {
        json!({
            "session_id": session,
            "tool_use_id": tool_use_id,
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": {"command": command},
        })
        .to_string()
    }

    #[cfg(unix)]
    fn cosign_records(dir: &std::path::Path) -> Vec<Record> {
        saiife_audit::store::read_all(&dir.join("audit"))
            .records
            .into_iter()
            .filter(|r| r.extra.get("event").and_then(|e| e.as_str()) == Some("cosign_denied"))
            .collect()
    }

    #[cfg(unix)]
    async fn body_of(r: Resp) -> String {
        let b = r.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(b.to_vec()).unwrap()
    }

    /// Wait (on the real clock) for the writer thread to show `n` records.
    #[cfg(unix)]
    fn wait_records(dir: &std::path::Path, n: usize) -> Vec<Record> {
        let end = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let got = cosign_records(dir);
            if got.len() >= n || std::time::Instant::now() > end {
                return got;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    const ME: Asker = Asker::Known(Principal::Uid(4242));

    #[cfg(unix)]
    async fn ask(ctx: &Arc<Ctx>, start: Instant, body: String, who: &Asker) -> Resp {
        judge_body(ctx, Opts::default(), start, Bytes::from(body), who).await
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn no_hook_at_all_denies_at_the_cap() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        let start = Instant::now();
        let r = ask(&ctx, start, payload("toolu_1", "ls -la"), &ME).await;
        assert_eq!(start.elapsed(), COSIGN_WAIT);
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_of(r).await, deny_body(CosignDeny::NoReport));
        let got = wait_records(t.path(), 1);
        assert_eq!(got.len(), 1);
        let rec = &got[0];
        assert_eq!(rec.kind(), "hook");
        assert_eq!(rec.decision, DecisionKind::ErrorDenied);
        assert_eq!(rec.agent, "claude");
        assert_eq!(rec.tool, "Bash");
        assert_eq!(rec.input, "ls -la");
        assert_eq!(rec.session.as_deref(), Some("c-1"));
        assert_eq!(rec.reason.as_deref(), Some(CosignDeny::NoReport.text()));
        assert_eq!(rec.uid, None);
        assert_eq!(rec.extra["tool_use_id"], "toolu_1");
        assert!(
            !rec.extra.contains_key("input_sha256"),
            "no plain input hash"
        );
        assert!(!rec.extra.contains_key("suppressed"));
    }

    /// An asker that is not identified (macOS, Windows) has its session
    /// and input left out of the record.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn unidentified_asker_records_no_session_or_input() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        let r = ask(
            &ctx,
            Instant::now(),
            payload("toolu_1", "ls -la"),
            &Asker::Unscoped,
        )
        .await;
        assert_eq!(body_of(r).await, deny_body(CosignDeny::NoReport));
        let r = ask(
            &ctx,
            Instant::now(),
            // Another session: not folded with the first.
            payload_in("c-2", "Bash", "toolu_2", "ls"),
            &Asker::Unknown,
        )
        .await;
        assert_eq!(body_of(r).await, deny_body(CosignDeny::NoReport));
        let got = wait_records(t.path(), 2);
        assert_eq!(got.len(), 2);
        for rec in &got {
            assert_eq!(rec.session, None, "{rec:?}");
            assert_eq!(rec.input, "", "{rec:?}");
            assert_eq!(rec.tool, "Bash");
        }
        assert_eq!(got[0].extra["tool_use_id"], "toolu_1");
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn recorded_session_and_tool_are_capped() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        let session = "s".repeat(300);
        let tool = format!("{}é", "t".repeat(63));
        let r = ask(
            &ctx,
            Instant::now(),
            payload_in(&session, &tool, "toolu_1", "ls"),
            &ME,
        )
        .await;
        assert_eq!(body_of(r).await, deny_body(CosignDeny::NoReport));
        let got = wait_records(t.path(), 1);
        assert_eq!(
            got[0].session.as_deref(),
            Some(&session[..MAX_RECORDED_SESSION])
        );
        assert_eq!(got[0].tool, "t".repeat(63), "cut on a character boundary");
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn cosign_denied_records_are_folded() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        let start = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for n in 0..20 {
            let ctx = Arc::clone(&ctx);
            set.spawn(async move {
                let r = ask(
                    &ctx,
                    start,
                    payload(&format!("toolu_{n}"), "ls"),
                    &Asker::Unscoped,
                )
                .await;
                body_of(r).await
            });
        }
        while let Some(a) = set.join_next().await {
            assert_eq!(a.unwrap(), deny_body(CosignDeny::NoReport));
        }
        assert_eq!(start.elapsed(), COSIGN_WAIT, "all at once");
        assert_eq!(wait_records(t.path(), 1).len(), 1);
        tokio::time::sleep(FOLD_EVERY).await;
        ask(
            &ctx,
            Instant::now(),
            payload("toolu_late", "ls"),
            &Asker::Unscoped,
        )
        .await;
        let got = wait_records(t.path(), 2);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].extra["suppressed"], 19);
    }

    /// A flood of decoys does not hide another session's or another
    /// asker's record in the same window.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn a_decoy_does_not_hide_another_call() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        let decoy = Asker::Known(Principal::Uid(5000));
        let start = Instant::now();
        for n in 0..5 {
            let p = payload_in("decoy", "Bash", &format!("toolu_d{n}"), "ls");
            ask(&ctx, start, p, &decoy).await;
        }
        assert_eq!(wait_records(t.path(), 1).len(), 1);
        // The real call: same reason, the victim's own session and uid.
        let real = payload_in("victim", "Bash", "toolu_real", "rm -rf /");
        ask(&ctx, Instant::now(), real, &ME).await;
        // The same session from the decoy's uid does not fold with it either.
        let same = payload_in("victim", "Bash", "toolu_same", "ls");
        ask(&ctx, Instant::now(), same, &decoy).await;
        let got = wait_records(t.path(), 3);
        assert_eq!(got.len(), 3, "{got:?}");
        assert_eq!(got[1].extra["tool_use_id"], "toolu_real");
        assert_eq!(got[1].input, "rm -rf /");
        assert_eq!(got[2].extra["tool_use_id"], "toolu_same");
        // On macOS and Windows (no asker), the session alone parts them.
        let a = payload_in("u-1", "Bash", "toolu_u1", "ls");
        let b = payload_in("u-2", "Bash", "toolu_u2", "ls");
        ask(&ctx, Instant::now(), a, &Asker::Unscoped).await;
        ask(&ctx, Instant::now(), b, &Asker::Unscoped).await;
        assert_eq!(wait_records(t.path(), 5).len(), 5);
    }

    #[cfg(unix)]
    const BINDER_SID: &str = "S-1-5-21-1-2-3-1001";
    #[cfg(unix)]
    const BINDER_GROUP: &str = "S-1-5-32-545";

    /// A hook connection of `pid`, as a Windows pipe client: begins, binds
    /// `body`'s key and records `decision`.
    #[cfg(unix)]
    fn hook_says(ctx: &Ctx, conn: u64, pid: u32, body: &str, decision: DecisionKind) {
        use crate::hooks::{ConnId, Verdict};
        let peer = saiife_ipc::peer::PeerCred {
            uid: 4242,
            gid: 4242,
            pid,
            sid: Some(BINDER_SID.into()),
            group_sids: vec![BINDER_GROUP.into()],
        };
        let key = parse(body.as_bytes()).unwrap().key;
        assert!(ctx
            .hooks
            .begin(ConnId(conn), &peer, "claude", Some("PreToolUse")));
        assert!(ctx.hooks.bind(ConnId(conn), key.clone()));
        ctx.hooks
            .verdict(ConnId(conn), &Verdict::for_key(&key, decision));
    }

    /// Claude Code (100) under 50 under 10, its shell (200), the hook (777);
    /// another branch (900).
    #[cfg(unix)]
    fn fake_tree() -> crate::hooks::Tree {
        use saiife_win::proc::ProcEntry;
        let e = |pid, ppid| ProcEntry {
            pid,
            ppid,
            exe: format!("p{pid}.exe"),
            created: None,
            session: None,
        };
        let t = vec![
            e(10, 4),
            e(50, 10),
            e(100, 50),
            e(200, 100),
            e(777, 200),
            e(900, 50),
        ];
        Arc::new(move || Ok(t.clone()))
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn foreign_tree_is_denied() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        ctx.hooks.set_tree(fake_tree());
        let body = payload("toolu_1", "ls");
        hook_says(&ctx, 1, 777, &body, DecisionKind::Allow);
        // Another branch, and an ancestor 4 steps up: the hook is not theirs.
        for asker in [900, 10, 777, 4] {
            let start = Instant::now();
            let r = ask(&ctx, start, body.clone(), &Asker::Process(asker)).await;
            assert!(start.elapsed() < Duration::from_secs(1), "at once");
            assert_eq!(body_of(r).await, deny_body(CosignDeny::NoReport), "{asker}");
        }
        let got = wait_records(t.path(), 4);
        assert_eq!(got.len(), 4, "one window per pid: {got:?}");
        for (rec, pid) in got.iter().zip([900, 10, 777, 4]) {
            assert_eq!(rec.reason.as_deref(), Some(CosignDeny::NoReport.text()));
            assert_eq!(rec.extra["asker_pid"], pid);
            // The asker is a pid, not a principal: no session or input kept.
            assert_eq!(rec.session, None);
            assert_eq!(rec.input, "");
        }
        // A process table that cannot be read ties nothing.
        ctx.hooks
            .set_tree(Arc::new(|| Err(io::Error::other("no table"))));
        let r = ask(&ctx, Instant::now(), body.clone(), &Asker::Process(100)).await;
        assert_eq!(body_of(r).await, deny_body(CosignDeny::NoReport));
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn hook_under_the_asker_counts() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        ctx.hooks.set_tree(fake_tree());
        let asked = allow_all(&ctx);
        let allowed = payload("toolu_1", "ls");
        hook_says(&ctx, 1, 777, &allowed, DecisionKind::Allow);
        // Claude Code, 2 steps up; its parent, 3 steps up (the depth cap).
        for asker in [100, 50] {
            let r = ask(
                &ctx,
                Instant::now(),
                allowed.clone(),
                &Asker::Process(asker),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
            assert_eq!(body_of(r).await, "", "{asker}");
        }
        let denied = payload("toolu_2", "rm -rf /");
        hook_says(&ctx, 2, 777, &denied, DecisionKind::Deny);
        let r = ask(&ctx, Instant::now(), denied, &Asker::Process(100)).await;
        assert_eq!(body_of(r).await, deny_body(CosignDeny::Denied));
        // The request may come before the bind: it waits, then ties.
        let later = payload("toolu_3", "ls");
        let ctx2 = Arc::clone(&ctx);
        let l2 = later.clone();
        let w = tokio::spawn(async move {
            body_of(ask(&ctx2, Instant::now(), l2, &Asker::Process(100)).await).await
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        hook_says(&ctx, 3, 777, &later, DecisionKind::Allow);
        assert_eq!(w.await.unwrap(), "");
        // A pid asker is judged once the wait names the binder, as the
        // binder's SID and groups; the hook's deny needs no judgment.
        let asked = asked.lock().unwrap();
        assert_eq!(asked.len(), 3);
        for req in asked.iter() {
            assert_eq!(req.principal, Principal::Sid(BINDER_SID.into()));
            assert_eq!(req.groups, [BINDER_GROUP]);
        }
    }

    /// A re-judge that allows every call, keeping what it was asked.
    #[cfg(unix)]
    fn allow_all(ctx: &Ctx) -> Arc<Mutex<Vec<RejudgeRequest>>> {
        let asked: Arc<Mutex<Vec<RejudgeRequest>>> = Arc::default();
        let a = Arc::clone(&asked);
        ctx.cosign.lock().unwrap().rejudge = Some(Arc::new(move |req: RejudgeRequest| {
            a.lock().unwrap().push(req);
            RejudgeAnswer::Allow
        }));
        asked
    }

    /// Windows: a forged allow under the asker is still judged, as the
    /// binder, and denied; its record names the binder's SID and pid.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn pid_asker_forged_allow_is_rejudged_as_the_binder() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        ctx.hooks.set_tree(fake_tree());
        ctx.cosign.lock().unwrap().rejudge =
            Some(Arc::new(|_: RejudgeRequest| RejudgeAnswer::Deny {
                reason: "reads a secret".into(),
                pack: Some("core.secrets".into()),
                rule: Some("ssh-key".into()),
                input: "type secrets.env".into(),
                askable: false,
            }));
        let body = payload("toolu_1", "type secrets.env");
        hook_says(&ctx, 1, 777, &body, DecisionKind::Allow);
        let r = ask(&ctx, Instant::now(), body, &Asker::Process(100)).await;
        assert_eq!(body_of(r).await, rejudged_body("reads a secret"));
        let end = std::time::Instant::now() + Duration::from_secs(10);
        let got = loop {
            let got: Vec<Record> = saiife_audit::store::read_all(&t.path().join("audit"))
                .records
                .into_iter()
                .filter(|r| r.extra.get("event").and_then(Value::as_str) == Some("rejudge_denied"))
                .collect();
            if !got.is_empty() || std::time::Instant::now() > end {
                break got;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].sid.as_deref(), Some(BINDER_SID));
        assert_eq!(got[0].uid, None);
        assert_eq!(got[0].extra["hook_pid"], 777);
        assert_eq!(got[0].pack.as_deref(), Some("core.secrets"));
    }

    /// Security review of task 4, finding 2: a pid asker (Windows) folds
    /// with its own pid only, and its record names that pid.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn process_askers_fold_apart_and_record_their_pid() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        ctx.hooks.set_tree(fake_tree());
        let start = Instant::now();
        // The same session and reason from two pids: neither hides the other.
        for (n, pid) in [(1, 900), (2, 901), (3, 900)] {
            let p = payload(&format!("toolu_{n}"), "ls");
            let r = ask(&ctx, start, p, &Asker::Process(pid)).await;
            assert_eq!(body_of(r).await, deny_body(CosignDeny::NoReport));
        }
        let got = wait_records(t.path(), 2);
        assert_eq!(got.len(), 2, "{got:?}");
        let pids: Vec<_> = got.iter().map(|r| r.extra["asker_pid"].clone()).collect();
        assert_eq!(pids, [json!(900), json!(901)]);
        // Still no principal: no session or input kept.
        assert!(got
            .iter()
            .all(|r| r.session.is_none() && r.input.is_empty()));
        // A uid asker's record has no asker pid.
        ask(&ctx, Instant::now(), payload("toolu_9", "ls"), &ME).await;
        let got = wait_records(t.path(), 3);
        assert!(!got[2].extra.contains_key("asker_pid"), "{:?}", got[2]);
    }

    #[test]
    fn self_connection_sees_both_ends() {
        let mut seen = None;
        assert!(self_connection(|local, peer| {
            seen = Some((local, peer));
            true
        }));
        let (local, peer) = seen.unwrap();
        assert!(local.ip().is_loopback() && peer.ip().is_loopback());
        assert_ne!(local.port(), peer.port());
        assert!(!self_connection(|_, _| false));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn asker_source_on_linux_is_proc_net() {
        assert_eq!(asker_source(), Some("proc_net"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn asker_source_on_macos_is_pcblist() {
        assert_eq!(asker_source(), Some(asker_macos::SOURCE));
    }

    #[cfg(windows)]
    #[test]
    fn asker_source_on_windows_is_tcp_table() {
        assert_eq!(asker_source(), Some("tcp_table"));
    }

    #[cfg(windows)]
    #[test]
    fn exclusive_addr_blocks_a_second_bind() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let l = bind_cosign("127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = l.local_addr().unwrap();
            assert!(std::net::TcpListener::bind(addr).is_err());
            let s = socket2_like_reuse_bind(addr);
            assert!(s.is_err(), "SO_REUSEADDR does not get past it");
        });
    }

    /// A second bind with `SO_REUSEADDR` on, as a squatter would try.
    #[cfg(windows)]
    fn socket2_like_reuse_bind(addr: SocketAddr) -> io::Result<()> {
        let s = TcpSocket::new_v4()?;
        s.set_reuseaddr(true)?;
        s.bind(addr)
    }
}
