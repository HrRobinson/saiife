//! The HTTP/1.1 connector gateway on `gateway.sock` (spec §8.8): SDKs and
//! `curl --unix-socket` reach the connectors through the same pipeline as
//! `saiife api`. The request is turned into `api.call` arguments, checked by
//! the same parser, and run by [`api_ops::execute`]: one `connector`
//! record per request that reaches the pipeline, with `via = "http"`.
//!
//! On `gateway.sock` identity is the peer uid of the socket and nothing
//! else: `Authorization`, `Forwarded` and `X-Forwarded-*` are never read
//! for it, and agent credentials never go upstream.
//!
//! The optional loopback TCP listener (`[gateway] tcp`, spec §6.3) has no
//! peer uid: there identity is the bearer token of `saiife api token` and
//! nothing else. `Authorization: Bearer <token>` is required on every
//! request and consumed before the pipeline; everything after that is the
//! same code path as the Unix socket.

use crate::api_ops::{self, Caller, Refused};
use crate::limits::{ConnSlot, InFlight};
use crate::ops::{Ctx, GatewayRefusal, Notice, UNKNOWN_UID};
use base64::Engine as _;
use bytes::Bytes;
use http::header::{
    HeaderName, HeaderValue, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER,
    TRANSFER_ENCODING,
};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use saiife_broker::pipeline::{strict_json, Outcome, Via};
use saiife_ipc::peer::{peer_cred, PeerCred};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

/// The read buffer of a connection, which bounds the request head.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
/// A request body over this is refused with 413 as soon as it is seen.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// The request head (from the accept: also an idle connection) must be
/// in within this, or the connection is closed.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// The body must be in within this of the head (408).
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// A write to the client must make progress within this, or the
/// connection is closed.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Authenticated connections on the TCP listener, all uids together (each
/// uid's connections also count against its 32).
pub const MAX_TCP_CONNS: usize = 64;
/// TCP connections that have not shown a valid token yet; apart from the
/// 64, so idle strangers cannot lock token holders out.
pub const MAX_TCP_PRE_AUTH: usize = 16;
/// A TCP connection's request head must be in within this.
pub const PRE_AUTH_HEADER_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a refused connection gets to take its answer.
const REFUSE_WRITE_TIMEOUT: Duration = Duration::from_millis(100);

/// Request headers never passed to the pipeline: identity and credentials
/// (the pipeline drops `Authorization`, `Cookie` and `Host` again), proxy
/// headers, and this hop's framing.
const DROPPED: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "forwarded",
    "x-real-ip",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "content-length",
    "expect",
];

/// Percent-encoding of `X-Saiife-Next` keys and values (unreserved stays).
const NEXT_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The gateway's timeouts and TCP caps; the tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Opts {
    pub header_read_timeout: Duration,
    pub body_read_timeout: Duration,
    pub write_timeout: Duration,
    /// The head timeout of a TCP connection (not yet authenticated).
    pub pre_auth_header_timeout: Duration,
    pub tcp_max_conns: usize,
    pub tcp_max_pre_auth: usize,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            header_read_timeout: HEADER_READ_TIMEOUT,
            body_read_timeout: BODY_READ_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
            pre_auth_header_timeout: PRE_AUTH_HEADER_TIMEOUT,
            tcp_max_conns: MAX_TCP_CONNS,
            tcp_max_pre_auth: MAX_TCP_PRE_AUTH,
        }
    }
}

/// Serve `listener` until the task is dropped.
pub async fn serve(listener: UnixListener, ctx: Arc<Ctx>) {
    serve_with(listener, ctx, Opts::default()).await
}

/// [`serve`] with other timeouts.
pub async fn serve_with(listener: UnixListener, ctx: Arc<Ctx>, opts: Opts) {
    loop {
        match listener.accept().await {
            Ok((s, _)) => {
                tokio::spawn(connection(s, Arc::clone(&ctx), opts));
            }
            Err(e) => {
                // EMFILE and friends: back off instead of spinning.
                eprintln!("saiife: warning: gateway accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Where a connection came from, which says where its identity comes from.
#[derive(Clone)]
enum Source {
    /// `gateway.sock`: the peer's uid, from the kernel.
    Unix(PeerCred),
    /// The loopback TCP listener: no peer uid; the bearer token decides.
    Tcp(Arc<TcpConn>),
}

/// One TCP connection and the caps it holds: its pre-auth place until its
/// token is verified, then a permit of the main cap and its uid's slot,
/// both until the connection closes.
struct TcpConn {
    peer: SocketAddr,
    /// The listener's port, for the `Host` check.
    port: u16,
    main: Arc<Semaphore>,
    pre_auth: Mutex<Option<PreAuth>>,
    authed: Mutex<Option<(OwnedSemaphorePermit, ConnSlot)>>,
}

/// The answer to a connection refused at accept.
async fn refuse_busy<S: AsyncWrite + Unpin>(mut s: S) {
    let body = r#"{"error":"busy","reason":"too many open connections"}"#;
    let raw = format!(
        "HTTP/1.1 429 Too Many Requests\r\ncontent-type: application/json\r\nretry-after: 1\r\nx-saiife-outcome: saiife\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(REFUSE_WRITE_TIMEOUT, s.write_all(raw.as_bytes())).await;
}

async fn connection(s: tokio::net::UnixStream, ctx: Arc<Ctx>, opts: Opts) {
    let Ok(peer) = peer_cred(&s) else {
        return;
    };
    // The control socket's open-connection caps, shared: idle HTTP
    // connections count against the same 32 per uid.
    let _slot = match ctx.conns.try_open(peer.uid) {
        Ok(slot) => slot,
        Err(_) => {
            ctx.notice(peer.uid, Notice::Connections);
            refuse_busy(s).await;
            return;
        }
    };
    serve_conn(s, Source::Unix(peer), ctx, opts).await;
}

/// The TCP connections that have not shown a valid token yet, by accept
/// order, each with the signal that closes it.
type PreAuthSet = Arc<Mutex<BTreeMap<u64, Arc<Notify>>>>;

/// A connection's place in the pre-auth set; leaving it (a verified token,
/// or the connection's end) removes it.
struct PreAuth {
    id: u64,
    set: PreAuthSet,
}

impl Drop for PreAuth {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.id);
    }
}

/// Serve the loopback TCP listener until the task is dropped. A new
/// connection is pre-auth: at most 16 of those are open (a 17th closes the
/// oldest, so idle strangers cannot lock a token holder out), and each has
/// 2 s for its request head. Once its token is verified it leaves that
/// set for the main cap of 64 and its uid's connection slots.
pub async fn serve_tcp(listener: TcpListener, ctx: Arc<Ctx>, opts: Opts) {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let pre: PreAuthSet = Arc::new(Mutex::new(BTreeMap::new()));
    let main = Arc::new(Semaphore::new(opts.tcp_max_conns));
    let mut next_id = 0u64;
    loop {
        match listener.accept().await {
            Ok((s, addr)) => {
                // The listener is bound to loopback; nothing else is
                // served.
                if !addr.ip().is_loopback() {
                    continue;
                }
                next_id += 1;
                let close = Arc::new(Notify::new());
                {
                    let mut set = pre.lock().unwrap_or_else(|p| p.into_inner());
                    while set.len() >= opts.tcp_max_pre_auth.max(1) {
                        if let Some((_, oldest)) = set.pop_first() {
                            oldest.notify_one();
                        }
                    }
                    set.insert(next_id, Arc::clone(&close));
                }
                let conn = Arc::new(TcpConn {
                    peer: addr,
                    port,
                    main: Arc::clone(&main),
                    pre_auth: Mutex::new(Some(PreAuth {
                        id: next_id,
                        set: Arc::clone(&pre),
                    })),
                    authed: Mutex::new(None),
                });
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    tokio::select! {
                        _ = serve_conn(s, Source::Tcp(conn), ctx, opts) => {}
                        // Evicted while still pre-auth.
                        _ = close.notified() => {}
                    }
                });
            }
            Err(e) => {
                eprintln!("saiife: warning: gateway tcp accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// One HTTP/1.1 request on `s`, whichever listener it came from.
async fn serve_conn<S>(s: S, source: Source, ctx: Arc<Ctx>, opts: Opts)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let header_timeout = match source {
        Source::Unix(_) => opts.header_read_timeout,
        Source::Tcp(_) => opts.pre_auth_header_timeout,
    };
    let io = Guarded::new(s, opts.write_timeout);
    let line = Arc::clone(&io.line);
    let svc = service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        let raw = raw_target(&line);
        let source = source.clone();
        async move { Ok::<_, Infallible>(admit(&ctx, source, req, raw, opts).await) }
    });
    // One request per connection: the first line of the stream is then
    // the request line, read as sent (see [`Guarded`]).
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .keep_alive(false)
        .max_buf_size(MAX_HEAD_BYTES)
        .max_header_size(MAX_HEAD_BYTES)
        .header_read_timeout(header_timeout)
        .serve_connection(TokioIo::new(io), svc)
        .await;
}

/// The request line as it came off the socket, before the HTTP parser.
#[derive(Default)]
struct FirstLine {
    bytes: Vec<u8>,
    done: bool,
}

impl FirstLine {
    fn feed(&mut self, mut b: &[u8]) {
        if self.done {
            return;
        }
        if self.bytes.is_empty() {
            // Empty lines before the request line are allowed (RFC 9112 2.2).
            let skip = b.iter().take_while(|c| matches!(c, b'\r' | b'\n')).count();
            b = &b[skip..];
        }
        match b.iter().position(|c| *c == b'\n') {
            Some(i) => {
                self.bytes.extend_from_slice(&b[..i]);
                self.done = true;
            }
            None => self.bytes.extend_from_slice(b),
        }
        if self.bytes.len() > MAX_HEAD_BYTES {
            // The parser refuses it anyway; keep nothing of it.
            self.bytes.clear();
            self.done = true;
        }
    }
}

/// The request target of the captured request line, `None` if there is no
/// complete one.
fn raw_target(line: &Mutex<FirstLine>) -> Option<String> {
    let l = line.lock().unwrap_or_else(|p| p.into_inner());
    if !l.done {
        return None;
    }
    let s = std::str::from_utf8(&l.bytes).ok()?;
    let mut it = s.trim_end_matches('\r').split(' ');
    let (_method, target) = (it.next()?, it.next()?);
    Some(target.to_string())
}

/// The connection's stream: records the request line (`http::Uri` drops a
/// fragment and so cannot be trusted to show the target as sent), and
/// closes the connection when a write makes no progress within the write
/// timeout. A client that sends and never reads cannot hold its slot, and
/// the shared connection total, for longer than that.
struct Guarded<S> {
    inner: S,
    write_timeout: Duration,
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
    line: Arc<Mutex<FirstLine>>,
}

impl<S> Guarded<S> {
    fn new(inner: S, write_timeout: Duration) -> Guarded<S> {
        Guarded {
            inner,
            write_timeout,
            stalled: None,
            line: Arc::new(Mutex::new(FirstLine::default())),
        }
    }

    /// `r` from a write-side poll: progress clears the deadline; pending
    /// arms it, and a deadline that passed is a `TimedOut` error.
    fn deadline<T>(&mut self, cx: &mut Context<'_>, r: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match r {
            Poll::Ready(r) => {
                self.stalled = None;
                Poll::Ready(r)
            }
            Poll::Pending => {
                let t = self.write_timeout;
                let sleep = self
                    .stalled
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(t)));
                match sleep.as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the client does not read its answer",
                    ))),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = r {
            self.line
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .feed(&buf.filled()[before..]);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.deadline(cx, r)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.deadline(cx, r)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_flush(cx);
        self.deadline(cx, r)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.deadline(cx, r)
    }
}

type Resp = Response<Full<Bytes>>;

fn json_resp(status: StatusCode, v: Value) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(v.to_string())));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

fn error(status: StatusCode, error: &str, message: &str) -> Resp {
    json_resp(status, json!({"error": error, "message": message}))
}

const OUTCOME: &str = "x-saiife-outcome";

/// The per-uid request caps of the control socket, shared. Every answer on
/// `/v1/proxy` says who gave its status: `X-Saiife-Outcome: upstream` for
/// a passed-through upstream answer, `saiife` for anything saiife decided.
async fn admit(
    ctx: &Arc<Ctx>,
    source: Source,
    req: Request<Incoming>,
    raw: Option<String>,
    opts: Opts,
) -> Resp {
    let proxy = raw.as_deref().is_some_and(|t| t.starts_with("/v1/proxy/"));
    let mut r = admit_inner(ctx, source, req, raw, opts).await;
    if proxy {
        r.headers_mut()
            .entry(OUTCOME)
            .or_insert(HeaderValue::from_static("saiife"));
    }
    r
}

/// The token of the one `Authorization: Bearer <token>` header; `None`
/// for none, several, or another scheme.
fn bearer(headers: &http::HeaderMap) -> Option<Zeroizing<String>> {
    let mut all = headers.get_all(AUTHORIZATION).iter();
    let (Some(v), None) = (all.next(), all.next()) else {
        return None;
    };
    let v = v.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| Zeroizing::new(token.to_string()))
}

/// 401 `{"error":"token"}`: a missing, expired or unknown token.
fn unauthorized() -> Resp {
    let mut r = json_resp(StatusCode::UNAUTHORIZED, json!({"error": "token"}));
    r.headers_mut().insert(
        http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer"),
    );
    r
}

/// A TCP request a browser could have sent: an `Origin` header, or a
/// `Host` other than this listener's loopback name and port (DNS
/// rebinding).
fn browser_like(h: &http::HeaderMap, port: u16) -> bool {
    if h.contains_key(http::header::ORIGIN) {
        return true;
    }
    let mut all = h.get_all(http::header::HOST).iter();
    let (Some(v), None) = (all.next(), all.next()) else {
        return true;
    };
    let Ok(v) = v.to_str() else {
        return true;
    };
    let v = v.to_ascii_lowercase();
    ![
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
        format!("localhost:{port}"),
    ]
    .contains(&v)
}

fn busy(message: &str) -> Resp {
    let mut r = error(StatusCode::TOO_MANY_REQUESTS, "busy", message);
    r.headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    r
}

async fn admit_inner(
    ctx: &Arc<Ctx>,
    source: Source,
    mut req: Request<Incoming>,
    raw: Option<String>,
    opts: Opts,
) -> Resp {
    // The identity. On TCP: no browser, a valid token, then the
    // connection moves from the pre-auth cap to the main cap and its
    // uid's slots (held until it closes).
    let caller = match source {
        Source::Unix(peer) => Caller::Unix(peer),
        Source::Tcp(conn) => {
            if browser_like(req.headers(), conn.port) {
                ctx.notice(UNKNOWN_UID, Notice::Gateway(GatewayRefusal::Origin));
                return json_resp(StatusCode::FORBIDDEN, json!({"error": "origin"}));
            }
            let uid = bearer(req.headers()).and_then(|t| ctx.tokens.verify(&t));
            let Some(uid) = uid else {
                ctx.notice(UNKNOWN_UID, Notice::Gateway(GatewayRefusal::Token));
                return unauthorized();
            };
            let Ok(main) = Arc::clone(&conn.main).try_acquire_owned() else {
                return busy("too many open connections");
            };
            let slot = match ctx.conns.try_open(uid) {
                Ok(slot) => slot,
                Err(_) => {
                    ctx.notice(uid, Notice::Connections);
                    return busy("too many open connections");
                }
            };
            *conn.authed.lock().unwrap_or_else(|p| p.into_inner()) = Some((main, slot));
            drop(
                conn.pre_auth
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take(),
            );
            Caller::Token {
                uid,
                addr: conn.peer,
            }
        }
    };
    // Consumed here: the token (or, on the Unix socket, an agent's own
    // credential) never reaches the pipeline.
    req.headers_mut().remove(AUTHORIZATION);
    let uid = caller.uid();
    match ctx.limits.try_begin(uid, Instant::now()) {
        Ok(in_flight) => route(ctx, &caller, req, raw, opts, in_flight).await,
        Err(_) => {
            ctx.notice(uid, Notice::Requests);
            busy("too many requests from this uid")
        }
    }
}

/// Which route a request took, for the shape of a done answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Api,
    Proxy,
}

async fn route(
    ctx: &Arc<Ctx>,
    caller: &Caller,
    req: Request<Incoming>,
    raw: Option<String>,
    opts: Opts,
    in_flight: InFlight,
) -> Resp {
    let uid = caller.uid();
    match classify(req.method(), req.uri(), raw.as_deref()) {
        Target::BadRequest(m) => refused(
            ctx,
            uid,
            GatewayRefusal::BadRequest,
            error(StatusCode::BAD_REQUEST, "bad_request", m),
        ),
        Target::Services => {
            let services = api_ops::services_for(ctx, uid, &BTreeMap::new()).await;
            json_resp(StatusCode::OK, json!({"services": services}))
        }
        Target::MethodNotAllowed(allow) => {
            refused(ctx, uid, GatewayRefusal::Method, method_not_allowed(allow))
        }
        Target::Api { service, op } => {
            let body = match read_body(req, opts).await {
                Ok((_, b)) => b,
                Err(r) => return body_refused(ctx, uid, *r),
            };
            match api_args(&service, &op, &body) {
                Ok(args) => call(ctx, caller, args, Route::Api, in_flight).await,
                Err(m) => refused(
                    ctx,
                    uid,
                    GatewayRefusal::BadRequest,
                    error(StatusCode::BAD_REQUEST, "bad_request", m),
                ),
            }
        }
        Target::Proxy { service, upstream } => {
            let method = req.method().as_str().to_string();
            let (parts, body) = match read_body(req, opts).await {
                Ok(x) => x,
                Err(r) => return body_refused(ctx, uid, *r),
            };
            let args = proxy_args(&service, &method, &upstream, &parts.headers, &body);
            call(ctx, caller, args, Route::Proxy, in_flight).await
        }
        Target::Request(id) => request_result(ctx, uid, id).await,
        Target::NotFound => not_found(),
    }
}

/// `r`, a refusal before the pipeline: no `connector` record, only a
/// `gateway_refused` notice (at most one per uid and kind a minute).
fn refused(ctx: &Ctx, uid: u32, why: GatewayRefusal, r: Resp) -> Resp {
    ctx.notice(uid, Notice::Gateway(why));
    r
}

/// [`refused`] for a body [`read_body`] would not take.
fn body_refused(ctx: &Ctx, uid: u32, r: Resp) -> Resp {
    let why = if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
        GatewayRefusal::TooLarge
    } else {
        GatewayRefusal::BadRequest
    };
    refused(ctx, uid, why, r)
}

/// Where a request goes, decided from its method and target alone (no IO).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    BadRequest(&'static str),
    Services,
    MethodNotAllowed(&'static str),
    Api {
        service: String,
        op: String,
    },
    Proxy {
        service: String,
        upstream: String,
    },
    /// `GET /v1/requests/{id}`.
    Request(u64),
    NotFound,
}

/// The pure routing decision. `raw` is the request target exactly as
/// received, from the request line itself ([`Guarded`]): no dot-segment
/// removal, no percent-decoding, and a fragment (which `http::Uri` would
/// silently cut) is refused. The pipeline's own checks run on that.
pub fn classify(method: &Method, uri: &http::Uri, raw: Option<&str>) -> Target {
    let Some(target) = raw else {
        return Target::BadRequest("no request line");
    };
    if !target.starts_with('/') {
        return Target::BadRequest("the request target must be origin-form (/v1/...)");
    }
    if target.contains('#') {
        return Target::BadRequest("the request target holds a fragment (#)");
    }
    // What the parser made of it must be the same bytes.
    if uri.path_and_query().map(|pq| pq.as_str()) != Some(target) {
        return Target::BadRequest("the request target cannot be read as sent");
    }
    let path = target.split('?').next().unwrap_or("");
    if path == "/v1/services" {
        if method != Method::GET {
            return Target::MethodNotAllowed("GET");
        }
        return Target::Services;
    }
    if let Some(rest) = path.strip_prefix("/v1/api/") {
        if method != Method::POST {
            return Target::MethodNotAllowed("POST");
        }
        let Some((service, op)) = rest
            .split_once('/')
            .filter(|(s, o)| !s.is_empty() && !o.is_empty() && !o.contains('/'))
        else {
            return Target::NotFound;
        };
        return Target::Api {
            service: service.to_string(),
            op: op.to_string(),
        };
    }
    if let Some(rest) = target.strip_prefix("/v1/proxy/") {
        // `{service}` up to the first `/` or `?`; the rest, with its query,
        // is the upstream path, untouched.
        let cut = rest.find(['/', '?']).unwrap_or(rest.len());
        let (service, upstream) = rest.split_at(cut);
        if service.is_empty() {
            return Target::NotFound;
        }
        let upstream = if upstream.starts_with('/') {
            upstream.to_string()
        } else {
            format!("/{upstream}")
        };
        return Target::Proxy {
            service: service.to_string(),
            upstream,
        };
    }
    if let Some(id) = path.strip_prefix("/v1/requests/") {
        if method != Method::GET {
            return Target::MethodNotAllowed("GET");
        }
        // Canonical decimal ids only, as the store names its files.
        return match id.parse::<u64>() {
            Ok(n) if n > 0 && !id.starts_with('0') && id.bytes().all(|b| b.is_ascii_digit()) => {
                Target::Request(n)
            }
            _ => Target::NotFound,
        };
    }
    Target::NotFound
}

fn not_found() -> Resp {
    error(
        StatusCode::NOT_FOUND,
        "not_found",
        "routes: GET /v1/services, POST /v1/api/{service}/{operation}, ANY /v1/proxy/{service}/{path}, GET /v1/requests/{id}",
    )
}

fn method_not_allowed(allow: &'static str) -> Resp {
    let mut r = error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", allow);
    r.headers_mut()
        .insert(http::header::ALLOW, HeaderValue::from_static(allow));
    r
}

/// The body, at most [`MAX_BODY_BYTES`]: refused with 413 as soon as a
/// `Content-Length` or the bytes read so far say it is larger, and with
/// 408 when it does not arrive within the body timeout. A refused body is
/// not drained: the connection closes.
async fn read_body(
    req: Request<Incoming>,
    opts: Opts,
) -> Result<(http::request::Parts, Bytes), Box<Resp>> {
    let (parts, body) = req.into_parts();
    let too_large = || {
        let mut r = error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "the request body is over 1 MiB",
        );
        r.headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
        r
    };
    // With a Transfer-Encoding the length is not the Content-Length; the
    // cap below applies either way.
    if !parts.headers.contains_key(TRANSFER_ENCODING) {
        if let Some(n) = parts.headers.get(CONTENT_LENGTH) {
            match n.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok()) {
                Some(n) if n > MAX_BODY_BYTES as u64 => return Err(Box::new(too_large())),
                Some(_) => {}
                None => {
                    let mut r = error(
                        StatusCode::BAD_REQUEST,
                        "bad_request",
                        "the Content-Length is not a number",
                    );
                    r.headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("close"));
                    return Err(Box::new(r));
                }
            }
        }
    }
    match tokio::time::timeout(
        opts.body_read_timeout,
        Limited::new(body, MAX_BODY_BYTES).collect(),
    )
    .await
    {
        Ok(Ok(c)) => Ok((parts, c.to_bytes())),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => Err(Box::new(too_large())),
        Ok(Err(_)) => Err(Box::new(error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the request body could not be read",
        ))),
        Err(_) => {
            let mut r = error(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "the request body did not arrive in time",
            );
            r.headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
            Err(Box::new(r))
        }
    }
}

fn b64(b: &[u8]) -> Value {
    base64::engine::general_purpose::STANDARD.encode(b).into()
}

/// `POST /v1/api/{service}/{operation}` with `{"params", "body", "wait"}`
/// (all optional; an empty body is `{}`) as `api.call` arguments.
fn api_args(service: &str, op: &str, body: &[u8]) -> Result<Map<String, Value>, &'static str> {
    let mut req = if body.iter().all(u8::is_ascii_whitespace) {
        Map::new()
    } else {
        match strict_json(body) {
            Some(Value::Object(m)) => m,
            _ => return Err(r#"the body must be a JSON object {"params", "body", "wait"}"#),
        }
    };
    if req
        .keys()
        .any(|k| !matches!(k.as_str(), "params" | "body" | "wait"))
    {
        return Err(r#"the body takes only "params", "body" and "wait""#);
    }
    // `wait` is accepted and ignored (decision 3): the gateway answers 202
    // at once, and the client polls `GET /v1/requests/{id}`.
    if !matches!(
        req.get("wait"),
        None | Some(Value::Null) | Some(Value::String(_))
    ) {
        return Err(r#""wait" must be a duration like "10m""#);
    }
    let mut args = Map::new();
    args.insert("service".into(), service.into());
    args.insert("operation".into(), op.into());
    if let Some(p) = req.remove("params") {
        args.insert("params".into(), p);
    }
    match req.remove("body") {
        None | Some(Value::Null) => {}
        Some(v) => {
            let bytes = serde_json::to_vec(&v).map_err(|_| "the body cannot be serialized")?;
            args.insert("body_b64".into(), b64(&bytes));
        }
    }
    Ok(args)
}

/// `ANY /v1/proxy/{service}/{path}` as `api.call` arguments: the method,
/// the raw path and query, the agent's headers (less [`DROPPED`] and
/// `X-Forwarded-*`) and the body.
fn proxy_args(
    service: &str,
    method: &str,
    path: &str,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Map<String, Value> {
    let pass = |n: &HeaderName| {
        let n = n.as_str();
        !DROPPED.contains(&n) && !n.starts_with("x-forwarded-") && !n.starts_with("x-saiife-")
    };
    let hs: Vec<Value> = headers
        .iter()
        .filter(|(n, _)| pass(n))
        .filter_map(|(n, v)| Some(json!([n.as_str(), v.to_str().ok()?])))
        .collect();
    let mut args = Map::new();
    args.insert("service".into(), service.into());
    args.insert("operation".into(), json!({"method": method, "path": path}));
    args.insert("headers".into(), Value::Array(hs));
    if !body.is_empty() {
        args.insert("body_b64".into(), b64(body));
    }
    args
}

async fn call(
    ctx: &Arc<Ctx>,
    caller: &Caller,
    args: Map<String, Value>,
    route: Route,
    in_flight: InFlight,
) -> Resp {
    let (_, _, mut call) = match api_ops::parse_call(&args) {
        Ok(x) => x,
        Err(m) => {
            return refused(
                ctx,
                caller.uid(),
                GatewayRefusal::BadRequest,
                error(StatusCode::BAD_REQUEST, "bad_request", m),
            )
        }
    };
    call.via = Via::Http;
    // A task of its own: hyper drops this future when the client goes away,
    // and a call that may have reached the upstream must still finish,
    // count against the limits and be recorded. It keeps the uid's
    // in-flight slot until it ends: a client that walks away does not get
    // the slot back while its call still runs.
    let task = {
        let ctx = Arc::clone(ctx);
        let caller = *caller;
        tokio::spawn(async move {
            let _in_flight = in_flight;
            api_ops::execute(&ctx, &caller, call).await
        })
    };
    let Ok(done) = task.await else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "the call did not complete",
        );
    };
    match done {
        Ok(outcome) => respond(outcome, route),
        Err(Refused::LowDisk(_)) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            api_ops::LOW_DISK,
        ),
        Err(Refused::Unrecorded(m)) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &m),
    }
}

/// `next` (decision 8) as `k=v` pairs joined by `&`, percent-encoded.
fn next_header(next: &BTreeMap<String, String>) -> Option<HeaderValue> {
    let kv: Vec<String> = next
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                utf8_percent_encode(k, NEXT_SET),
                utf8_percent_encode(v, NEXT_SET)
            )
        })
        .collect();
    HeaderValue::from_str(&kv.join("&")).ok()
}

/// §8.8: 200 done (the upstream status in `X-Saiife-Upstream-Status` for
/// `/v1/api`, passed through for `/v1/proxy`), 403 denied, 429 limit, 502
/// upstream failure or a response withheld after it was sent.
fn respond(outcome: Outcome, route: Route) -> Resp {
    match outcome {
        Outcome::Done { finished, next } => {
            let status = match route {
                Route::Api => StatusCode::OK,
                // A 1xx is not a final answer: never pass one through.
                Route::Proxy => match StatusCode::from_u16(finished.status) {
                    Ok(s) if s.as_u16() >= 200 => s,
                    _ => {
                        return error(
                            StatusCode::BAD_GATEWAY,
                            "upstream_failed",
                            "the upstream answered with an informational status",
                        )
                    }
                },
            };
            let mut r = Response::new(Full::new(finished.body));
            *r.status_mut() = status;
            let h = r.headers_mut();
            match route {
                // The allowlisted upstream headers, masked.
                Route::Proxy => {
                    h.extend(finished.headers);
                    h.insert(OUTCOME, HeaderValue::from_static("upstream"));
                }
                Route::Api => {
                    if let Some(ct) = finished.headers.get(CONTENT_TYPE) {
                        h.insert(CONTENT_TYPE, ct.clone());
                    }
                    h.insert(
                        "x-saiife-upstream-status",
                        HeaderValue::from(finished.status),
                    );
                    if let Some(v) = next.as_ref().and_then(next_header) {
                        h.insert("x-saiife-next", v);
                    }
                }
            }
            if finished.truncated {
                h.insert("x-saiife-truncated", HeaderValue::from_static("true"));
            }
            r
        }
        o @ Outcome::Denied { .. } if o.is_post_send_deny() => {
            let Outcome::Denied { rule } = o else {
                unreachable!()
            };
            json_resp(
                StatusCode::BAD_GATEWAY,
                json!({"error": "withheld", "rule": rule}),
            )
        }
        Outcome::Denied { rule } => json_resp(
            StatusCode::FORBIDDEN,
            json!({"error": "denied", "rule": rule}),
        ),
        Outcome::Limited { limit } => json_resp(
            StatusCode::TOO_MANY_REQUESTS,
            json!({"error": "limit", "limit": limit}),
        ),
        Outcome::UpstreamFailed { reason } => json_resp(
            StatusCode::BAD_GATEWAY,
            json!({"error": "upstream_failed", "reason": reason}),
        ),
        Outcome::Pending { id } => json_resp(StatusCode::ACCEPTED, json!({"pending": id})),
    }
}

/// `GET /v1/requests/{id}` (spec §8.8, decision 4): the requester only. 200
/// with the result body and `X-Saiife-Upstream-Status` once it was sent,
/// 202 while it waits, 404 for an unknown id or another uid's request, 410
/// once it was rejected, expired or failed to send.
async fn request_result(ctx: &Arc<Ctx>, uid: u32, id: u64) -> Resp {
    use crate::approval_ops::ResultView;
    use crate::approvals::{state_name, State};
    let view = match crate::approval_ops::result_for(ctx, uid, id).await {
        Ok(v) => v,
        Err(()) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "approvals are unavailable",
            )
        }
    };
    let pick = |mut b: Value, from: Option<&Value>, keys: &[&str]| {
        for k in keys {
            if let Some(v) = from.and_then(|r| r.get(*k)).filter(|v| !v.is_null()) {
                b[*k] = v.clone();
            }
        }
        b
    };
    match view {
        ResultView::Unknown => error(
            StatusCode::NOT_FOUND,
            "not_found",
            &format!("no request #{id} (or not yours)"),
        ),
        ResultView::Waiting(s) => json_resp(
            StatusCode::ACCEPTED,
            json!({"pending": id, "state": state_name(s)}),
        ),
        ResultView::Done {
            state: State::Sent,
            result: Some(r),
        } if r.get("ok") == Some(&Value::Bool(true)) => sent_response(&r),
        // Sent, but the answer was withheld (as for a direct call: 502).
        ResultView::Done {
            state: State::Sent,
            result: Some(r),
        } => json_resp(
            StatusCode::BAD_GATEWAY,
            pick(
                json!({"error": "withheld"}),
                Some(&r),
                &["rule", "reason", "message"],
            ),
        ),
        ResultView::Done {
            state: State::Sent,
            result: None,
        } => json_resp(
            StatusCode::GONE,
            json!({"state": "sent", "message": "the result is kept for 24 h and is gone"}),
        ),
        ResultView::Done { state, result } => json_resp(
            StatusCode::GONE,
            pick(
                json!({"state": state_name(state)}),
                result.as_ref(),
                &["rule", "limit", "reason", "message"],
            ),
        ),
    }
}

/// The stored `api.call` answer of a send, as `/v1/api` would answer.
fn sent_response(r: &Value) -> Resp {
    let body = r
        .get("body_b64")
        .and_then(Value::as_str)
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
        .unwrap_or_default();
    let status = r.get("status").and_then(Value::as_u64).unwrap_or(0);
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    let content_type = r
        .get("headers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|p| {
            let p = p.as_array()?;
            if p.first()?.as_str()? == "content-type" {
                p.get(1)?.as_str()
            } else {
                None
            }
        });
    if let Some(ct) = content_type.and_then(|c| HeaderValue::from_str(c).ok()) {
        h.insert(CONTENT_TYPE, ct);
    }
    h.insert("x-saiife-upstream-status", HeaderValue::from(status));
    if r.get("truncated") == Some(&Value::Bool(true)) {
        h.insert("x-saiife-truncated", HeaderValue::from_static("true"));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_args_maps_the_body() {
        let a = api_args(
            "shop",
            "orders.list",
            br#"{"params":{"status":"open","limit":5},"body":{"a":1},"wait":"10m"}"#,
        )
        .unwrap();
        assert_eq!(a["service"], "shop");
        assert_eq!(a["operation"], "orders.list");
        assert_eq!(a["params"]["limit"], 5);
        assert_eq!(a["body_b64"], b64(br#"{"a":1}"#));
        let (_, _, c) = api_ops::parse_call(&a).unwrap();
        assert_eq!(c.params["limit"], "5");
        assert!(api_args("s", "o", b"").unwrap().get("params").is_none());
        assert!(api_args("s", "o", b"[]").is_err());
        assert!(api_args("s", "o", br#"{"params":{},"params":{}}"#).is_err());
        assert!(api_args("s", "o", br#"{"extra":1}"#).is_err());
        assert!(api_args("s", "o", br#"{"wait":5}"#).is_err());
    }

    #[test]
    fn proxy_args_drop_identity_and_hop_headers() {
        let mut h = http::HeaderMap::new();
        for (k, v) in [
            ("authorization", "Bearer agent"),
            ("cookie", "c=1"),
            ("host", "saiife"),
            ("x-forwarded-user", "root"),
            ("forwarded", "for=x"),
            ("content-length", "3"),
            ("accept", "application/json"),
        ] {
            h.insert(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        let a = proxy_args("shop", "GET", "/orders.json", &h, b"");
        assert_eq!(a["headers"], json!([["accept", "application/json"]]));
        assert!(a.get("body_b64").is_none());
    }

    #[test]
    fn next_header_is_kv_percent_encoded() {
        let n: BTreeMap<String, String> = [
            ("since_id".to_string(), "42".to_string()),
            ("status".to_string(), "a b&c".to_string()),
        ]
        .into();
        assert_eq!(next_header(&n).unwrap(), "since_id=42&status=a%20b%26c");
    }
}
