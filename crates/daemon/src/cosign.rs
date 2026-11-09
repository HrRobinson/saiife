//! The Claude Code co-signer (plan 20): a small HTTP/1.1 listener on
//! `127.0.0.1:7433` that the managed drop-in's second `PreToolUse` hook
//! (`type: "http"`, `onFailure: "block"`) posts each call to.
//!
//! It never answers `allow` (decision D3). For a call the command hook has
//! recorded as allowed (same session, tool call id and input hash, and the
//! same principal) it answers `200` with an empty body: no opinion, so the
//! command hook's verdict and Claude Code's own prompts stand. Anything else
//! is `200` with a `permissionDecision: "deny"` body. Claude Code runs the
//! two hooks in parallel, so the co-signer waits for the verdict, at most
//! [`COSIGN_WAIT`] from the request's arrival.
//!
//! No token: the answer only ever takes away. A browser request (it carries
//! `Origin`), a wrong content type, a wrong path and a flood each get a
//! refusal that blocks only that request (`onFailure: "block"`). Where the
//! asker's uid is known (Linux, macOS), each uid has its own share of the
//! connection and in-flight caps, so one user's flood leaves room for
//! another's calls; the global caps stay as the backstop.

use crate::hooks::{Principal, Waited};
use crate::ops::{Ctx, VERSION};
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
/// Requests in flight from one uid, where the uid is known.
pub const MAX_INFLIGHT_PER_UID: usize = 8;
/// Open connections; one more is closed at once.
pub const MAX_CONNS: usize = 64;
/// Open connections from one uid, where the uid is known.
pub const MAX_CONNS_PER_UID: usize = 32;
/// The longest session id a `cosign_denied` record keeps, in bytes
/// (`hook.bind`'s own limit).
pub const MAX_RECORDED_SESSION: usize = crate::sessions::MAX_SESSION_ID;
/// The longest tool name a `cosign_denied` record keeps, in bytes
/// (`hook.bind`'s own limit).
pub const MAX_RECORDED_TOOL: usize = 64;
/// At most one `cosign_denied` record per reason, asker and session this
/// often; the next one carries `suppressed`.
pub const FOLD_EVERY: Duration = Duration::from_secs(10);
/// The fold windows kept at once. When they are all live, a new session
/// folds with the others of its reason and asker.
const MAX_FOLD_KEYS: usize = 256;
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
    pub max_inflight_per_uid: usize,
    pub max_conns: usize,
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
        }
    }
}

/// The deny body, byte for byte as the spec fixes it.
pub fn deny_body(why: CosignDeny) -> String {
    format!(
        "{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"saiife: BLOCKED (fail closed): {}\"}}}}",
        why.text()
    )
}

/// The co-signer's place in `status`, and its record folding.
#[derive(Debug, Default)]
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
    fold: Folder,
}

impl CosignState {
    pub fn status(&self) -> serde_json::Value {
        json!({"addr": self.addr.map(|a| a.to_string()), "error": self.error, "asker": self.asker})
    }
}

/// What one fold window is for: a reason, who asked, and the call's
/// session when the payload names one. So a flood of decoys folds only
/// with itself, never over another asker's or another session's record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FoldKey {
    why: CosignDeny,
    principal: Option<Principal>,
    session: Option<String>,
}

/// One `cosign_denied` record per [`FoldKey`] per [`FOLD_EVERY`], with at
/// most [`MAX_FOLD_KEYS`] windows.
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
        let key = if self.windows.contains_key(&key) || self.windows.len() < MAX_FOLD_KEYS {
            key
        } else {
            // Ended windows go (with any count they held back); if every
            // window is live, the session folds with its reason and asker.
            self.windows.retain(|_, (start, _)| live(start));
            if self.windows.len() < MAX_FOLD_KEYS {
                key
            } else {
                FoldKey {
                    session: None,
                    ..key
                }
            }
        };
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
    per_uid: Arc<PerUid>,
}

/// [`serve_cosign`] with `opts`.
pub async fn serve_cosign_with(listener: TcpListener, ctx: Arc<Ctx>, opts: Opts) {
    let lim = Limits {
        inflight: Arc::new(Semaphore::new(opts.max_inflight)),
        per_uid: Arc::default(),
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
    let _uid_slot = match who.uid() {
        Some(uid) => match lim.per_uid.take(uid, Slot::Conn, opts.max_conns_per_uid) {
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

/// The connections and requests in flight per uid.
#[derive(Debug, Default)]
struct PerUid {
    counts: Mutex<HashMap<u32, [usize; 2]>>,
}

#[derive(Debug, Clone, Copy)]
enum Slot {
    Conn = 0,
    Inflight = 1,
}

/// A held [`PerUid`] slot, given back on drop.
struct UidSlot {
    table: Arc<PerUid>,
    uid: u32,
    slot: Slot,
}

impl PerUid {
    fn take(self: &Arc<Self>, uid: u32, slot: Slot, max: usize) -> Option<UidSlot> {
        let mut m = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let c = m.entry(uid).or_default();
        if c[slot as usize] >= max {
            if *c == [0, 0] {
                m.remove(&uid);
            }
            return None;
        }
        c[slot as usize] += 1;
        Some(UidSlot {
            table: Arc::clone(self),
            uid,
            slot,
        })
    }
}

impl Drop for UidSlot {
    fn drop(&mut self) {
        let mut m = self.table.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = m.get_mut(&self.uid) {
            c[self.slot as usize] = c[self.slot as usize].saturating_sub(1);
            if *c == [0, 0] {
                m.remove(&self.uid);
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
    let mut r = Response::new(Full::new(Bytes::from(deny_body(why))));
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
    fn uid(&self) -> Option<u32> {
        match self {
            Asker::Known(Principal::Uid(u)) => Some(*u),
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
    let _uid_permit = match who.uid() {
        Some(uid) => match lim
            .per_uid
            .take(uid, Slot::Inflight, opts.max_inflight_per_uid)
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
    let input = match classify_value(&v, Some("claude"), cfg!(windows)) {
        Ok(ToolCall::Shell { command, .. }) => command,
        Ok(ToolCall::File { paths, .. }) => paths.join(" "),
        Ok(ToolCall::Other { .. }) | Err(_) => String::new(),
    };
    Ok(Call { key, tool, input })
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
    let call = match tokio::task::spawn_blocking(move || parse(&body)).await {
        Ok(Ok(c)) => c,
        Ok(Err(why)) => return denied(ctx, why, who, None).await,
        Err(_) => return denied(ctx, CosignDeny::BadJson, who, None).await,
    };
    judge(ctx, opts, arrival, &call, who).await
}

/// The answer for `call`, asked by `who`.
async fn judge(ctx: &Arc<Ctx>, opts: Opts, arrival: Instant, call: &Call, who: &Asker) -> Resp {
    if !call.key.cosignable() {
        return denied(ctx, CosignDeny::NotCosignable, who, Some(call)).await;
    }
    let (principal, asker_pid) = match who {
        Asker::Known(p) => (Some(p), None),
        Asker::Process(pid) => (None, Some(*pid)),
        Asker::Unscoped => (None, None),
        Asker::Unknown => return denied(ctx, CosignDeny::NoReport, who, Some(call)).await,
    };
    match ctx
        .hooks
        .wait(&call.key, principal, asker_pid, arrival + opts.wait)
        .await
    {
        Waited::Allow => no_opinion(),
        // The guard record says why.
        Waited::Deny => deny(CosignDeny::Denied),
        Waited::NoVerdict => denied(ctx, CosignDeny::NoVerdict, who, Some(call)).await,
        Waited::Timeout | Waited::Foreign => {
            denied(ctx, CosignDeny::NoReport, who, Some(call)).await
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
    let session = call
        .and_then(|c| c.key.session.as_deref())
        .map(|s| capped(s, MAX_RECORDED_SESSION));
    let fold = FoldKey {
        why,
        principal: who.principal().cloned(),
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
    x.insert("event".into(), "cosign_denied".into());
    // The call by its id only: no hash of the input (see `hooks::Verdict`).
    x.insert(
        "tool_use_id".into(),
        json!(call
            .and_then(|c| c.key.tool_use_id.as_deref())
            .map(crate::hooks::recorded_id)),
    );
    if suppressed > 0 {
        x.insert("suppressed".into(), suppressed.into());
    }
    if let Err(e) = ctx.writer.append(r).await {
        eprintln!("saiife: warning: cannot write a cosign_denied record: {e}");
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
        ] {
            let v: serde_json::Value = serde_json::from_str(&deny_body(d)).unwrap();
            assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
            assert!(!d.text().contains('"') && !d.text().contains('\\'));
        }
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
            session: session.map(str::to_string),
        }
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
        let t = Arc::new(PerUid::default());
        let a: Vec<_> = (0..3)
            .map(|_| t.take(1, Slot::Inflight, 3).unwrap())
            .collect();
        assert!(t.take(1, Slot::Inflight, 3).is_none());
        assert!(t.take(2, Slot::Inflight, 3).is_some(), "another uid");
        let c = t.take(1, Slot::Conn, 3).unwrap();
        drop(a);
        assert!(t.take(1, Slot::Inflight, 3).is_some());
        drop(c);
        assert!(t.counts.lock().unwrap().is_empty());
        assert!(t.take(9, Slot::Conn, 0).is_none());
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

    /// A hook connection of `pid`, as a Windows pipe client: begins, binds
    /// `body`'s key and records `decision`.
    #[cfg(unix)]
    fn hook_says(ctx: &Ctx, conn: u64, pid: u32, body: &str, decision: DecisionKind) {
        use crate::hooks::{ConnId, Verdict};
        let peer = saiife_ipc::peer::PeerCred {
            uid: 4242,
            gid: 4242,
            pid,
            sid: Some("S-1-5-21-1-2-3-1001".into()),
            group_sids: Vec::new(),
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
        let got = wait_records(t.path(), 1);
        assert_eq!(got.len(), 1, "folded per reason: {got:?}");
        assert_eq!(got[0].reason.as_deref(), Some(CosignDeny::NoReport.text()));
        // The asker is a pid, not a principal: no session or input kept.
        assert_eq!(got[0].session, None);
        assert_eq!(got[0].input, "");
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
