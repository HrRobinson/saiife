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
use crate::ops::{Ctx, Notice};
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
use tokio::sync::Semaphore;
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
/// Open connections on the TCP listener, all uids together (each uid's
/// connections also count against its 32).
pub const MAX_TCP_CONNS: usize = 64;
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

/// The gateway's timeouts; the tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Opts {
    pub header_read_timeout: Duration,
    pub body_read_timeout: Duration,
    pub write_timeout: Duration,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            header_read_timeout: HEADER_READ_TIMEOUT,
            body_read_timeout: BODY_READ_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
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
#[derive(Debug, Clone, Copy)]
enum Source {
    /// `gateway.sock`: the peer's uid, from the kernel.
    Unix(PeerCred),
    /// The loopback TCP listener: no peer uid; the bearer token decides.
    Tcp(SocketAddr),
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

/// Serve the loopback TCP listener until the task is dropped. At most
/// [`MAX_TCP_CONNS`] connections are open at once; each request then
/// takes a connection slot of its token's uid.
pub async fn serve_tcp(listener: TcpListener, ctx: Arc<Ctx>, opts: Opts) {
    let cap = Arc::new(Semaphore::new(MAX_TCP_CONNS));
    loop {
        match listener.accept().await {
            Ok((s, addr)) => {
                // The listener is bound to loopback; nothing else is
                // served.
                if !addr.ip().is_loopback() {
                    continue;
                }
                match Arc::clone(&cap).try_acquire_owned() {
                    Ok(permit) => {
                        let ctx = Arc::clone(&ctx);
                        tokio::spawn(async move {
                            let _permit = permit;
                            serve_conn(s, Source::Tcp(addr), ctx, opts).await;
                        });
                    }
                    Err(_) => {
                        tokio::spawn(refuse_busy(s));
                    }
                }
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
    let io = Guarded::new(s, opts.write_timeout);
    let line = Arc::clone(&io.line);
    let svc = service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        let raw = raw_target(&line);
        async move { Ok::<_, Infallible>(admit(&ctx, source, req, raw, opts).await) }
    });
    // One request per connection: the first line of the stream is then
    // the request line, read as sent (see [`Guarded`]).
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .keep_alive(false)
        .max_buf_size(MAX_HEAD_BYTES)
        .max_header_size(MAX_HEAD_BYTES)
        .header_read_timeout(opts.header_read_timeout)
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
    // The identity, and on TCP the token uid's connection slot for this
    // request (the connection carries one request).
    let (caller, _slot) = match source {
        Source::Unix(peer) => (Caller::Unix(peer), None),
        Source::Tcp(addr) => {
            let uid = bearer(req.headers()).and_then(|t| ctx.tokens.verify(&t));
            let Some(uid) = uid else {
                return unauthorized();
            };
            match ctx.conns.try_open(uid) {
                Ok(slot) => (Caller::Token { uid, addr }, Some(slot)),
                Err(_) => {
                    ctx.notice(uid, Notice::Connections);
                    return busy("too many open connections");
                }
            }
        }
    };
    // Consumed here: the token (or, on the Unix socket, an agent's own
    // credential) never reaches the pipeline.
    req.headers_mut().remove(AUTHORIZATION);
    let uid = caller.uid();
    match ctx.limits.try_begin(uid, Instant::now()) {
        Ok(_in_flight) => route(ctx, &caller, req, raw, opts).await,
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
) -> Resp {
    // The request target exactly as received, from the request line itself
    // ([`Guarded`]): no dot-segment removal, no percent-decoding, and a
    // fragment (which `http::Uri` would silently cut) is refused. The
    // pipeline's own checks run on that.
    let Some(target) = raw else {
        return error(StatusCode::BAD_REQUEST, "bad_request", "no request line");
    };
    if !target.starts_with('/') {
        return error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the request target must be origin-form (/v1/...)",
        );
    }
    if target.contains('#') {
        return error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the request target holds a fragment (#)",
        );
    }
    // What the parser made of it must be the same bytes.
    if req.uri().path_and_query().map(|pq| pq.as_str()) != Some(target.as_str()) {
        return error(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "the request target cannot be read as sent",
        );
    }
    let path = target.split('?').next().unwrap_or("");
    if path == "/v1/services" {
        if req.method() != Method::GET {
            return method_not_allowed("GET");
        }
        let services = api_ops::services_for(ctx, caller.uid(), &BTreeMap::new()).await;
        return json_resp(StatusCode::OK, json!({"services": services}));
    }
    if let Some(rest) = path.strip_prefix("/v1/api/") {
        if req.method() != Method::POST {
            return method_not_allowed("POST");
        }
        let Some((service, op)) = rest
            .split_once('/')
            .filter(|(s, o)| !s.is_empty() && !o.is_empty() && !o.contains('/'))
        else {
            return not_found();
        };
        let (service, op) = (service.to_string(), op.to_string());
        let body = match read_body(req, opts).await {
            Ok((_, b)) => b,
            Err(r) => return *r,
        };
        return match api_args(&service, &op, &body) {
            Ok(args) => call(ctx, caller, args, Route::Api).await,
            Err(m) => error(StatusCode::BAD_REQUEST, "bad_request", m),
        };
    }
    if let Some(rest) = target.strip_prefix("/v1/proxy/") {
        // `{service}` up to the first `/` or `?`; the rest, with its query,
        // is the upstream path, untouched.
        let cut = rest.find(['/', '?']).unwrap_or(rest.len());
        let (service, upstream) = rest.split_at(cut);
        if service.is_empty() {
            return not_found();
        }
        let upstream = if upstream.starts_with('/') {
            upstream.to_string()
        } else {
            format!("/{upstream}")
        };
        let service = service.to_string();
        let method = req.method().as_str().to_string();
        let (parts, body) = match read_body(req, opts).await {
            Ok(x) => x,
            Err(r) => return *r,
        };
        let args = proxy_args(&service, &method, &upstream, &parts.headers, &body);
        return call(ctx, caller, args, Route::Proxy).await;
    }
    if path.starts_with("/v1/requests/") {
        return json_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "approvals come in plan 11"}),
        );
    }
    not_found()
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
    // `wait` is accepted and ignored until plan 11, as in `api.call`.
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

async fn call(ctx: &Arc<Ctx>, caller: &Caller, args: Map<String, Value>, route: Route) -> Resp {
    let (_, _, mut call) = match api_ops::parse_call(&args) {
        Ok(x) => x,
        Err(m) => return error(StatusCode::BAD_REQUEST, "bad_request", m),
    };
    call.via = Via::Http;
    match api_ops::execute(ctx, caller, call).await {
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
    }
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
