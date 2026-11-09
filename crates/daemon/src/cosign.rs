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
//! refusal that blocks only that request (`onFailure: "block"`).

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
use saiife_ipc::hookkey::{hook_key_bounded, HookKey, KeyError, HOOK_KEY_MAX_BYTES};
use saiifeguard::payload::{classify_for, context_from_hook_json_bounded, ToolCall};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::Semaphore;
use tokio::time::Instant;

/// The one route.
pub const COSIGN_PATH: &str = "/v1/cosign/claude";
/// How long a request waits for the command hook's verdict, from its
/// arrival. Under the drop-in's `"timeout": 10`.
pub const COSIGN_WAIT: Duration = Duration::from_secs(8);
/// Requests in flight; one more is answered `503`.
pub const MAX_INFLIGHT: usize = 16;
/// Open connections; one more is closed at once.
pub const MAX_CONNS: usize = 64;
/// At most one `cosign_denied` record per [`CosignDeny`] value this often;
/// the next one carries `suppressed`.
pub const FOLD_EVERY: Duration = Duration::from_secs(10);
/// Debug builds only: `SAIIFE_TEST_COSIGN_ADDR=<addr>` binds the co-signer
/// there instead of [`saiife_system::layout::COSIGN_ADDR`], and `off` binds
/// none. The test suite runs many system daemons at once; release builds
/// never read it.
pub const ADDR_SEAM: &str = "SAIIFE_TEST_COSIGN_ADDR";

/// The co-signer's timeouts and caps; the tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Opts {
    /// The body cap (`PARSE_MAX_BYTES`, 64 MiB).
    pub max_body: usize,
    pub wait: Duration,
    pub max_inflight: usize,
    pub header_read_timeout: Duration,
    pub body_read_timeout: Duration,
    /// A whole connection, write included: a client that does not read its
    /// answer cannot keep its slot.
    pub conn_limit: Duration,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            max_body: HOOK_KEY_MAX_BYTES,
            wait: COSIGN_WAIT,
            max_inflight: MAX_INFLIGHT,
            header_read_timeout: Duration::from_secs(5),
            body_read_timeout: Duration::from_secs(10),
            conn_limit: Duration::from_secs(30),
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
    /// after a failed bind.
    pub addr: Option<SocketAddr>,
    /// Why the bind failed.
    pub error: Option<String>,
    fold: Folder,
}

impl CosignState {
    pub fn status(&self) -> serde_json::Value {
        json!({"addr": self.addr.map(|a| a.to_string()), "error": self.error})
    }
}

/// One `cosign_denied` record per [`CosignDeny`] per [`FOLD_EVERY`].
#[derive(Debug, Default)]
struct Folder {
    /// The start of the current window, and the records held back in it.
    windows: HashMap<CosignDeny, (Instant, u64)>,
}

impl Folder {
    /// `Some(suppressed)` when a record for `why` is written now, with the
    /// count held back in the window before; `None` when it is held back.
    fn admit(&mut self, why: CosignDeny, now: Instant) -> Option<u64> {
        match self.windows.get_mut(&why) {
            Some((start, held)) if now.saturating_duration_since(*start) < FOLD_EVERY => {
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
                self.windows.insert(why, (now, 0));
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

/// A listener on `addr` that is ours alone: `SO_REUSEADDR` off, and on
/// Windows `SO_EXCLUSIVEADDRUSE`, so no other process can bind the same
/// address beside it (D6). For a fixed port the bound address is checked.
pub fn bind_cosign(addr: SocketAddr) -> io::Result<TcpListener> {
    let sock = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        saiife_win::ffi::net::exclusive_addr_use(sock.as_raw_socket())?;
    }
    sock.set_reuseaddr(false)?;
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

/// Bind `addr` and serve the co-signer on it. A failure does not stop the
/// daemon: it is a `daemon` record with `event: "cosign_bind_failed"`, a
/// log line, and `status.cosign.error`. Claude Code then blocks every call
/// (`onFailure: "block"`) until a restart binds it.
pub async fn start_cosign(ctx: &Arc<Ctx>, addr: SocketAddr) -> Option<tokio::task::JoinHandle<()>> {
    match bind_cosign(addr) {
        Ok(l) => {
            let bound = l.local_addr().ok();
            {
                let mut st = ctx.cosign.lock().unwrap_or_else(|p| p.into_inner());
                st.addr = bound;
                st.error = None;
            }
            Some(tokio::spawn(serve_cosign(l, Arc::clone(ctx))))
        }
        Err(e) => {
            let reason = e.to_string();
            eprintln!(
                "saiife: warning: co-signer {addr} is not available: {reason}; Claude Code calls are blocked until it is"
            );
            {
                let mut st = ctx.cosign.lock().unwrap_or_else(|p| p.into_inner());
                st.addr = None;
                st.error = Some(reason.clone());
            }
            let mut r = ctx.event("cosign_bind_failed");
            r.reason = Some(reason);
            r.extra.insert("addr".into(), addr.to_string().into());
            if let Err(e) = ctx.writer.append(r).await {
                eprintln!("saiife: warning: cannot write the cosign_bind_failed record: {e}");
            }
            None
        }
    }
}

/// Serve `listener` until the task is dropped.
pub async fn serve_cosign(listener: TcpListener, ctx: Arc<Ctx>) {
    serve_cosign_with(listener, ctx, Opts::default()).await
}

/// [`serve_cosign`] with `opts`.
pub async fn serve_cosign_with(listener: TcpListener, ctx: Arc<Ctx>, opts: Opts) {
    let inflight = Arc::new(Semaphore::new(opts.max_inflight));
    let conns = Arc::new(Semaphore::new(MAX_CONNS));
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
                let local = s.local_addr().ok();
                let (ctx, inflight) = (Arc::clone(&ctx), Arc::clone(&inflight));
                tokio::spawn(async move {
                    let _slot = slot;
                    let svc = service_fn(move |req| {
                        let (ctx, inflight) = (Arc::clone(&ctx), Arc::clone(&inflight));
                        async move {
                            Ok::<_, Infallible>(
                                handle(&ctx, &inflight, opts, req, local, peer).await,
                            )
                        }
                    });
                    let conn = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .keep_alive(false)
                        .max_buf_size(64 * 1024)
                        .header_read_timeout(opts.header_read_timeout)
                        .serve_connection(TokioIo::new(s), svc);
                    let _ = tokio::time::timeout(opts.conn_limit, conn).await;
                });
            }
            Err(e) => {
                eprintln!("saiife: warning: co-signer accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
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

/// Who asks: on Linux the uid of the client's socket, from `/proc/net`.
/// Elsewhere a TCP peer is not identified (W13; no `/proc` on macOS), and
/// every principal's verdict counts.
enum Asker {
    Known(Principal),
    Unscoped,
    /// The socket could not be found: denied.
    Unknown,
}

async fn asker(local: Option<SocketAddr>, peer: SocketAddr) -> Asker {
    if !cfg!(target_os = "linux") {
        let _ = (local, peer);
        return Asker::Unscoped;
    }
    let Some(local) = local else {
        return Asker::Unknown;
    };
    tokio::task::spawn_blocking(move || crate::mcp_gateway::tcp_peer_socket(local, peer))
        .await
        .ok()
        .flatten()
        .map_or(Asker::Unknown, |(uid, _)| Asker::Known(Principal::Uid(uid)))
}

async fn handle(
    ctx: &Arc<Ctx>,
    inflight: &Arc<Semaphore>,
    opts: Opts,
    req: Request<Incoming>,
    local: Option<SocketAddr>,
    peer: SocketAddr,
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
    let Ok(_permit) = Arc::clone(inflight).try_acquire_owned() else {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "busy\n");
    };
    let body = match read_body(req, opts).await {
        Ok(b) => b,
        Err(why) => return denied(ctx, why, None, None).await,
    };
    judge(ctx, opts, arrival, &body, || asker(local, peer)).await
}

/// The answer for a request body that arrived at `arrival`; `who` finds
/// the asking principal, once the body names a call.
async fn judge<F, Fut>(ctx: &Arc<Ctx>, opts: Opts, arrival: Instant, body: &[u8], who: F) -> Resp
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Asker>,
{
    let Ok(text) = std::str::from_utf8(body) else {
        return denied(ctx, CosignDeny::BadJson, None, None).await;
    };
    let key = match hook_key_bounded("claude", text, opts.max_body) {
        Ok(k) => k,
        Err(KeyError::TooLarge) => return denied(ctx, CosignDeny::TooLarge, None, None).await,
        Err(KeyError::Json(_)) => return denied(ctx, CosignDeny::BadJson, None, None).await,
    };
    if !key.cosignable() {
        return denied(ctx, CosignDeny::NotCosignable, Some(&key), Some(text)).await;
    }
    let principal = match who().await {
        Asker::Known(p) => Some(p),
        Asker::Unscoped => None,
        Asker::Unknown => {
            return denied(ctx, CosignDeny::NoReport, Some(&key), Some(text)).await;
        }
    };
    match ctx
        .hooks
        .wait(&key, principal.as_ref(), arrival + opts.wait)
        .await
    {
        Waited::Allow => no_opinion(),
        // The guard record says why.
        Waited::Deny => deny(CosignDeny::Denied),
        Waited::NoVerdict => denied(ctx, CosignDeny::NoVerdict, Some(&key), Some(text)).await,
        Waited::Timeout | Waited::Foreign => {
            denied(ctx, CosignDeny::NoReport, Some(&key), Some(text)).await
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
async fn denied(
    ctx: &Arc<Ctx>,
    why: CosignDeny,
    key: Option<&HookKey>,
    payload: Option<&str>,
) -> Resp {
    record(ctx, why, key, payload).await;
    deny(why)
}

/// What the guard would show as the call's input: the command, or the
/// paths of a file tool.
fn shown_input(payload: &str) -> String {
    match classify_for(payload, HOOK_KEY_MAX_BYTES, Some("claude"), cfg!(windows)) {
        Ok(ToolCall::Shell { command, .. }) => command,
        Ok(ToolCall::File { paths, .. }) => paths.join(" "),
        Ok(ToolCall::Other { .. }) | Err(_) => String::new(),
    }
}

/// The `cosign_denied` record of a deny, unless [`FOLD_EVERY`] holds it
/// back, or the audit volume is below its floor (a TCP peer is never the
/// daemon itself).
async fn record(ctx: &Arc<Ctx>, why: CosignDeny, key: Option<&HookKey>, payload: Option<&str>) {
    let suppressed = {
        let mut st = ctx.cosign.lock().unwrap_or_else(|p| p.into_inner());
        match st.fold.admit(why, Instant::now()) {
            Some(n) => n,
            None => return,
        }
    };
    let p = ctx.policy();
    let free = crate::disk::free_mb(&ctx.audit_dir).unwrap_or(0);
    if crate::disk::disk_gate(free, p.min_free_mb, false).is_err() {
        return;
    }
    let hc = payload
        .map(|t| context_from_hook_json_bounded(t, HOOK_KEY_MAX_BYTES))
        .unwrap_or_default();
    let input = payload.map(shown_input).unwrap_or_default();
    let mut r = Record::new(
        NewRecord {
            agent: "claude",
            project: "",
            session: key.and_then(|k| k.session.as_deref()),
            tool: hc.tool.as_deref().unwrap_or(""),
            input: &input,
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
    x.insert(
        "tool_use_id".into(),
        json!(key.and_then(|k| k.tool_use_id.as_deref())),
    );
    x.insert(
        "input_sha256".into(),
        json!(key.map(|k| k.input_sha256.as_str())),
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
        assert_eq!(Opts::default().max_body, 64 * 1024 * 1024);
        assert_eq!(COSIGN_PATH, "/v1/cosign/claude");
        assert_eq!(saiife_system::layout::COSIGN_ADDR, "127.0.0.1:7433");
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

    #[tokio::test(start_paused = true)]
    async fn folding_one_record_per_reason_per_window() {
        let mut f = Folder::default();
        let t0 = Instant::now();
        assert_eq!(f.admit(CosignDeny::NoReport, t0), Some(0));
        for i in 1..20 {
            let at = t0 + Duration::from_millis(i * 400);
            assert_eq!(f.admit(CosignDeny::NoReport, at), None);
        }
        // Another reason has its own window.
        assert_eq!(f.admit(CosignDeny::BadJson, t0), Some(0));
        assert_eq!(
            f.admit(CosignDeny::NoReport, t0 + FOLD_EVERY),
            Some(19),
            "the next one carries the count"
        );
        assert_eq!(f.admit(CosignDeny::NoReport, t0 + FOLD_EVERY * 3), Some(0));
    }

    #[cfg(unix)]
    fn payload(tool_use_id: &str, command: &str) -> String {
        json!({
            "session_id": "c-1",
            "tool_use_id": tool_use_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
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
    #[tokio::test(start_paused = true)]
    async fn no_hook_at_all_denies_at_the_cap() {
        let t = tempfile::tempdir().unwrap();
        let (ctx, _join) = crate::ops::test_ctx(t.path(), crate::ops::Mode::Locked, 0);
        let start = Instant::now();
        let body = payload("toolu_1", "ls -la");
        let r = judge(&ctx, Opts::default(), start, body.as_bytes(), || async {
            Asker::Unscoped
        })
        .await;
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
        assert_eq!(rec.extra["input_sha256"].as_str().map(str::len), Some(64));
        assert!(!rec.extra.contains_key("suppressed"));
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
                let b = payload(&format!("toolu_{n}"), "ls");
                let r = judge(&ctx, Opts::default(), start, b.as_bytes(), || async {
                    Asker::Unscoped
                })
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
        let late = payload("toolu_late", "ls");
        judge(
            &ctx,
            Opts::default(),
            Instant::now(),
            late.as_bytes(),
            || async { Asker::Unscoped },
        )
        .await;
        let got = wait_records(t.path(), 2);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].extra["suppressed"], 19);
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
