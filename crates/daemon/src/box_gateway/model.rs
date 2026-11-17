//! The model forwarder on a box's `vsock.sock_5002` (plan 40, Task 2; plan
//! 42 Task 3; spec §7.4, §7.9): an HTTP/1.1 server that streams each
//! request to its route's one fixed upstream (`api.anthropic.com`,
//! `api.openai.com` or `generativelanguage.googleapis.com`, port 443; see
//! [`super::routes`]) after swapping the box's placeholder for the real
//! credential from the vault. The route comes from the box's template,
//! read per request; the box never picks it.
//!
//! The guest is untrusted. A request passes only when it is `GET` or
//! `POST`, has an origin-form target, asks for no upgrade, has a plain path
//! (plan 42 D4; on Google, no `key` query parameter), is one of its
//! route's exact (method, path, query) shapes (ruling R12), and carries this box's own placeholder (checked in constant
//! time) in exactly its credential's header: `x-api-key` for an Anthropic
//! API key, `authorization: Bearer` for an Anthropic subscription or an
//! OpenAI key, `x-goog-api-key` for a Google key. The placeholder anywhere
//! else in the headers or the target is refused, and every provider's
//! credential headers the box sent are always removed before the real one
//! is added (C5). A box whose template asks for subscription login gets a
//! fixed `403` while the owner's terms check is open (C4,
//! `SUBSCRIPTION_LOGIN_CLEARED`), whatever it sends. Bodies, the target and
//! the other headers are passed through untouched. Error answers are fixed
//! text: they never quote a header, the placeholder or the key.
//!
//! Bounds: the box's connection limit and new-connection bucket (as the
//! egress port), hyper's request head limits and a head deadline, a capped
//! request body (`413`), a connect deadline, and an idle timer reset by
//! every frame either way. Responses stream frame by frame and are never
//! buffered; a cut stream (idle, lockdown, box off, upstream error) ends
//! with an error, never a clean end. Every request that reaches the
//! upstream step writes one `model` record when its response ends (C6);
//! refusals write `model_denied`, rate-limited like `egress_denied`. Bodies
//! and query strings are never recorded.

use super::egress::{answer, idle_watch, lockdown_watch, ms_since};
use super::routes::{self, Route};
use super::{lock, stopped, BoxRun, GatewayShared, Slot};
use crate::vault::{Kind, VaultState};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, CONNECTION, CONTENT_TYPE, HOST, SET_COOKIE, UPGRADE};
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::{TokioIo, TokioTimer};
use saiife_audit::DecisionKind;
use saiife_boxes::template::{Login, ModelCred, Provider, SUBSCRIPTION_GATED};
use saiife_boxes::BoxId;
use saiife_broker::upstream::Resolver;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

/// The Anthropic route's host (plan 40's name; every route's host is
/// fixed, the box cannot choose another, R5).
pub const MODEL_HOST: &str = routes::ANTHROPIC.host;
/// The model port, on every route.
pub const MODEL_PORT: u16 = 443;
/// The Anthropic route's first vault service (C8; plan 42 D6).
pub const MODEL_SERVICE: &str = routes::ANTHROPIC.services[0];

/// The answer to a request without this box's placeholder in the right
/// header (fixed text).
pub const NOT_VALID: &str = "this box's model credential is not valid";
/// C7.
pub const LOCKDOWN_MSG: &str = "lockdown is on";
/// A path off the route's allow-list (plan 42 D4; fixed text, never the
/// path).
pub const NOT_FORWARDED: &str = "this path is not forwarded to the model service";
/// A path trick (plan 42 D4).
pub const NOT_PLAIN: &str = "the request path is not plain";
/// A `key` query parameter on the Google route (plan 42 D4).
pub const QUERY_KEY: &str = "the key query parameter is not forwarded";

/// Request headers per request (hyper answers `431` above).
const MAX_HEADERS: usize = 100;
/// The request head's bytes (hyper answers `431` above).
const MAX_HEAD_BYTES: usize = 32 * 1024;
/// hyper's read buffer for one box connection.
const MAX_BUF: usize = 64 * 1024;
/// The upstream's response head.
const MAX_RESPONSE_HEAD_BYTES: usize = 64 * 1024;
/// The recorded path is cut to this many bytes.
const RECORD_PATH_MAX: usize = 256;
/// The denied-record key's host for the model port: never a DNS name, so
/// it cannot share a key with an egress refusal.
const DENIED_KEY: &str = ":model";
/// The denied-record keys of one box's refused (method, path) pairs start
/// with this; at most [`MAX_PATH_KEYS`] of them live per window (R12), then
/// the refusals share [`DENIED_KEY`].
const PATH_KEY_PREFIX: &str = ":model ";
const MAX_PATH_KEYS: usize = 64;

/// C5's limits. Tests shorten them; the upstream is fixed in every build.
#[derive(Debug, Clone)]
pub struct ModelConfig {
    /// The largest request body; more is `413`.
    pub body_max: u64,
    /// Resolving, connecting and the TLS handshake to the upstream.
    pub connect_secs: u64,
    /// No byte either way for this long ends the request.
    pub idle_secs: u64,
    /// The deadline for each request head (and for an idle keep-alive
    /// connection's next one).
    pub head_secs: u64,
}

impl Default for ModelConfig {
    fn default() -> ModelConfig {
        ModelConfig {
            body_max: 32 * 1024 * 1024,
            connect_secs: 10,
            idle_secs: 300,
            head_secs: 30,
        }
    }
}

// ---------------------------------------------------------------- headers

/// Hop-by-hop headers (RFC 9110 §7.6.1, plus the legacy ones proxies drop).
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Request headers that carry any provider's credential, steer billing to
/// another project, or say who the client is; the box's are always removed
/// (C5, plan 42 D4). Then only the route's own header is set.
const REQUEST_REMOVED: [&str; 10] = [
    "x-api-key",
    "authorization",
    "cookie",
    "proxy-authorization",
    "forwarded",
    "host",
    "x-goog-api-key",
    "openai-organization",
    "openai-project",
    "x-goog-user-project",
];

fn remove_hop_by_hop(h: &mut HeaderMap) {
    let listed: Vec<HeaderName> = h
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
        .collect();
    for n in listed {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(n);
    }
}

/// C5's removals, then `host` set to the route's host and the
/// credential's one header with `real` (marked sensitive). Nothing else is
/// changed: never the target or the body. An empty value or one that is
/// not a valid header value is an error (fixed text).
pub fn rewrite_request(
    req: &mut http::request::Parts,
    cred: ModelCred,
    real: &str,
) -> Result<(), &'static str> {
    if real.is_empty() || real.trim() != real {
        return Err("the credential is not a usable token");
    }
    let (name, bearer) = routes::cred_header(cred);
    let host = routes::route(routes::provider_of(cred)).host;
    let value = if bearer {
        Zeroizing::new(format!("Bearer {real}"))
    } else {
        Zeroizing::new(real.to_string())
    };
    let mut value =
        HeaderValue::from_str(&value).map_err(|_| "the credential is not a usable token")?;
    value.set_sensitive(true);
    let h = &mut req.headers;
    remove_hop_by_hop(h);
    for n in REQUEST_REMOVED {
        h.remove(n);
    }
    let forwarded: Vec<HeaderName> = h
        .keys()
        .filter(|k| k.as_str().starts_with("x-forwarded-"))
        .cloned()
        .collect();
    for n in forwarded {
        h.remove(n);
    }
    h.insert(HOST, HeaderValue::from_static(host));
    h.insert(name, value);
    Ok(())
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether `expected` is in `target` as sent or once percent-decoded.
fn in_target(target: &[u8], expected: &[u8]) -> bool {
    contains(target, expected) || contains(&routes::percent_decode(target), expected)
}

/// Whether the request carries `expected` (this box's placeholder) in
/// exactly the credential's header, once, and nowhere else in its headers
/// or its target (path and query, also percent-decoded; plan 42 D4). The
/// error is for the record's reason only; the box always gets
/// [`NOT_VALID`].
pub fn check_credential(
    parts: &http::request::Parts,
    cred: ModelCred,
    expected: &str,
) -> Result<(), &'static str> {
    if expected.is_empty() {
        return Err("no placeholder");
    }
    let (name, bearer) = routes::cred_header(cred);
    let mut values = parts.headers.get_all(&name).iter();
    let (Some(v), None) = (values.next(), values.next()) else {
        return Err("not exactly one credential header");
    };
    let got = v.as_bytes();
    let token = if bearer {
        const BEARER: &[u8] = b"bearer ";
        if got.len() < BEARER.len() || !got[..BEARER.len()].eq_ignore_ascii_case(BEARER) {
            return Err("not a bearer token");
        }
        &got[BEARER.len()..]
    } else {
        got
    };
    if !saiife_boxhost::placeholder::placeholder_matches(expected, token) {
        return Err("not this box's placeholder");
    }
    let elsewhere = parts
        .headers
        .iter()
        .any(|(k, v)| *k != name && contains(v.as_bytes(), expected.as_bytes()));
    if elsewhere {
        return Err("the placeholder in another header");
    }
    let target = parts.uri.path_and_query().map_or("", |p| p.as_str());
    if in_target(target.as_bytes(), expected.as_bytes()) {
        return Err("the placeholder in the target");
    }
    Ok(())
}

/// C5's response removals: hop-by-hop headers and `set-cookie`.
pub fn clean_response(parts: &mut http::response::Parts) {
    remove_hop_by_hop(&mut parts.headers);
    parts.headers.remove(SET_COOKIE);
}

// ---------------------------------------------------------------- bodies

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ResBody = UnsyncBoxBody<Bytes, BoxError>;

/// One request's counts; `last` is ms since `t0` of the last frame either
/// way (the idle timer).
struct Counters {
    t0: Instant,
    up: AtomicU64,
    down: AtomicU64,
    last: AtomicU64,
    /// The request body passed the cap.
    over: AtomicBool,
}

impl Counters {
    fn new() -> Counters {
        Counters {
            t0: Instant::now(),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            last: AtomicU64::new(0),
            over: AtomicBool::new(false),
        }
    }

    fn stamp(&self) {
        self.last.store(ms_since(self.t0), Ordering::Relaxed);
    }
}

/// The box's request body on its way up: counted, capped, the idle timer
/// reset per frame. Trailers are dropped.
struct UpBody {
    inner: Incoming,
    c: Arc<Counters>,
    cap: u64,
}

impl Body for UpBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        loop {
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                None => return Poll::Ready(None),
                Some(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
                Some(Ok(f)) => {
                    let Ok(d) = f.into_data() else { continue };
                    let n = d.len() as u64;
                    let total = this.c.up.fetch_add(n, Ordering::Relaxed).saturating_add(n);
                    if total > this.cap {
                        this.c.over.store(true, Ordering::SeqCst);
                        return Poll::Ready(Some(Err("the request body is too large".into())));
                    }
                    this.c.stamp();
                    return Poll::Ready(Some(Ok(Frame::data(d))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The response body on its way down, fed frame by frame by the pump task
/// (one frame in flight). A cut stream ends with an error, so the box never
/// takes it for a complete answer.
struct DownBody {
    rx: mpsc::Receiver<Bytes>,
    cut: Arc<AtomicBool>,
}

impl Body for DownBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match ready!(self.rx.poll_recv(cx)) {
            Some(d) => Poll::Ready(Some(Ok(Frame::data(d)))),
            None if self.cut.load(Ordering::SeqCst) => {
                Poll::Ready(Some(Err("the model response was cut".into())))
            }
            None => Poll::Ready(None),
        }
    }
}

fn plain(code: StatusCode, msg: &str) -> Response<ResBody> {
    let body = Full::new(Bytes::from(format!("{msg}\n")))
        .map_err(|never: Infallible| match never {})
        .boxed_unsync();
    let mut r = Response::new(body);
    *r.status_mut() = code;
    let h = r.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(CONNECTION, HeaderValue::from_static("close"));
    r
}

// ---------------------------------------------------------------- refusals

/// A refused request: its answer, its `model_denied` reason and, for
/// `path_not_allowed`, the recorded method and path.
struct Deny {
    code: StatusCode,
    msg: String,
    reason: &'static str,
    request: Option<(String, String)>,
}

impl Deny {
    fn new(code: StatusCode, msg: impl Into<String>, reason: &'static str) -> Deny {
        Deny {
            code,
            msg: msg.into(),
            reason,
            request: None,
        }
    }
}

/// Write the `model_denied` record of `reason` (with the method and path
/// when given) unless its key wrote one in the last 60 s. A refused
/// (method, path) pair is its own key, so each distinct one is recorded,
/// up to [`MAX_PATH_KEYS`] per box per window (R12).
async fn model_deny(
    gw: Arc<GatewayShared>,
    id: BoxId,
    reason: &'static str,
    request: Option<(String, String)>,
) {
    let now = (gw.clock)();
    let suppressed = {
        let mut denied = lock(&gw.denied);
        let host = match &request {
            Some((m, p)) => {
                let k = format!("{PATH_KEY_PREFIX}{m} {p}");
                let known = denied
                    .0
                    .contains_key(&(id.clone(), Some(k.clone()), reason));
                if known || denied.live_with_prefix(&id, PATH_KEY_PREFIX, now) < MAX_PATH_KEYS {
                    k
                } else {
                    DENIED_KEY.to_string()
                }
            }
            None => DENIED_KEY.to_string(),
        };
        denied.admit((id.clone(), Some(host), reason), now)
    };
    let Some(suppressed) = suppressed else {
        return;
    };
    let Some(ctx) = gw.ctx() else { return };
    let mut rec = ctx.record("model_denied", "-");
    rec.decision = DecisionKind::Deny;
    rec.reason = Some(reason.to_string());
    rec.session = Some(format!("box-{}", id.as_str()));
    let x = &mut rec.extra;
    x.insert("box".into(), id.as_str().into());
    if let Some((m, p)) = request {
        x.insert("method".into(), m.into());
        x.insert("path".into(), p.into());
    }
    if suppressed > 0 {
        x.insert("suppressed".into(), suppressed.into());
    }
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiifed: warning: cannot write a model_denied record: {e}");
    }
}

// ---------------------------------------------------------------- the box

/// What a request needs from the box's record and template.
struct BoxInfo {
    session: String,
    login: Login,
    cred: ModelCred,
    provider: Provider,
    credential: String,
    placeholder: Option<String>,
}

/// The box's record, its template's login, credential kind, provider and
/// credential name, and its placeholder, read on the blocking pool (the manager's lock and the
/// placeholder file are never touched on the runtime thread).
async fn box_info(gw: &GatewayShared, id: &BoxId) -> Result<BoxInfo, Deny> {
    let unknown = || {
        Deny::new(
            StatusCode::FORBIDDEN,
            "this box is not known",
            "unknown_box",
        )
    };
    let Some(ctx) = gw.ctx() else {
        return Err(Deny::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "saiife is stopping",
            "stopping",
        ));
    };
    let Some(mgr) = ctx.box_manager.clone() else {
        return Err(unknown());
    };
    drop(ctx);
    let id = id.clone();
    tokio::task::spawn_blocking(move || {
        let r = mgr.get(&id).ok()?;
        let t = mgr.templates().into_iter().find(|t| t.name == r.template)?;
        let record = saiife_boxhost::paths::RecordPaths::of(mgr.root(), &id);
        // A bad or unreadable file, or one made for another agent or login
        // (plan 42 D3), is as good as none: nothing passes.
        let placeholder = saiife_boxhost::placeholder::read_placeholder(&record, t.model_cred())
            .ok()
            .flatten();
        Some(BoxInfo {
            session: r.session,
            login: t.login,
            cred: t.model_cred(),
            provider: t.agent.provider(),
            credential: t.credential,
            placeholder,
        })
    })
    .await
    .ok()
    .flatten()
    .ok_or_else(unknown)
}

/// The vault value of `name` for `route` (C8, plan 42 D6): a token secret
/// that allows any of the route's services; a refusal names the first.
/// Read per request, so a rotated key applies at once; the lock is held for
/// the lookup only.
fn vault_value(gw: &GatewayShared, name: &str, route: &Route) -> Result<Zeroizing<String>, Deny> {
    let service = route.services[0];
    let Some(ctx) = gw.ctx() else {
        return Err(Deny::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "saiife is stopping",
            "stopping",
        ));
    };
    let missing = |reason| {
        Deny::new(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "the vault has no secret {name} for {service}: \
                 saiife secret add {name} --kind token --service {service}"
            ),
            reason,
        )
    };
    let mut g = ctx.vault.lock();
    let VaultState::Ready(v) = &mut *g else {
        return Err(Deny::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "the vault is not available",
            "vault_unavailable",
        ));
    };
    let Some(e) = v.get(name) else {
        return Err(missing("secret_missing"));
    };
    if !e
        .allowed_services
        .iter()
        .any(|s| route.services.contains(&s.as_str()))
    {
        return Err(missing("secret_not_allowed"));
    }
    let token = match (e.kind, e.fields.get("token")) {
        (Kind::Token, Some(t)) => t.clone(),
        _ => return Err(missing("secret_wrong_kind")),
    };
    // In memory only, as api.call does.
    v.touch(name, &crate::ops::now_ts());
    Ok(token)
}

// ---------------------------------------------------------------- upstream

/// Aborts the task when dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One TLS connection to an upstream host; it ends with the box
/// connection, and is reused only for the same host.
struct UpConn {
    host: &'static str,
    sender: SendRequest<UpBody>,
    _task: AbortOnDrop,
}

/// Why the upstream step failed.
enum Fail {
    NoUpstream,
    Busy,
    Unreachable,
    Private,
    ConnectTimeout,
    /// The exchange failed after the request went out.
    Send,
    Idle,
    Lockdown,
    Stopped,
    TooLarge,
}

impl Fail {
    fn answer(&self) -> (StatusCode, &'static str, &'static str) {
        use StatusCode as S;
        match self {
            Fail::NoUpstream => (
                S::SERVICE_UNAVAILABLE,
                "the model service is not configured",
                "no_upstream",
            ),
            Fail::Busy => (
                S::SERVICE_UNAVAILABLE,
                "too many name lookups in progress",
                "lookup_busy",
            ),
            Fail::Unreachable => (
                S::BAD_GATEWAY,
                "the model service could not be reached",
                "unreachable",
            ),
            Fail::Private => (
                S::BAD_GATEWAY,
                "the model service resolved to a private address",
                "private_address",
            ),
            Fail::ConnectTimeout => (
                S::GATEWAY_TIMEOUT,
                "the model service did not answer in time",
                "connect_timeout",
            ),
            Fail::Send => (
                S::BAD_GATEWAY,
                "the model service closed the connection",
                "upstream_error",
            ),
            Fail::Idle => (
                S::GATEWAY_TIMEOUT,
                "the model service did not answer in time",
                "idle",
            ),
            Fail::Lockdown => (S::SERVICE_UNAVAILABLE, LOCKDOWN_MSG, "lockdown"),
            Fail::Stopped => (S::SERVICE_UNAVAILABLE, "the box is stopping", "stopped"),
            Fail::TooLarge => (
                S::PAYLOAD_TOO_LARGE,
                "the request body is too large",
                "body_too_large",
            ),
        }
    }
}

/// The address to connect to for resolver answer `a`: port
/// [`MODEL_PORT`], by construction in release builds. Only a debug build
/// whose gateway has the loopback test flag keeps a loopback answer's port
/// (the tests' loopback upstream).
fn upstream_addr(test_loopback: bool, a: SocketAddr) -> SocketAddr {
    if cfg!(debug_assertions) && test_loopback && a.ip().is_loopback() {
        a
    } else {
        SocketAddr::new(a.ip(), MODEL_PORT)
    }
}

/// One box connection: its run, and its upstream connection once made
/// (reused for the keep-alive requests on it).
struct ConnState {
    run: Arc<BoxRun>,
    gw: Arc<GatewayShared>,
    upstream: Mutex<Option<UpConn>>,
    client: Mutex<Option<(tokio_rustls::TlsConnector, Arc<dyn Resolver>)>>,
}

impl ConnState {
    /// The pinned TLS client pieces of the daemon's upstream client (its
    /// roots; ALPN `http/1.1`) and its resolver.
    fn client(&self) -> Result<(tokio_rustls::TlsConnector, Arc<dyn Resolver>), Fail> {
        if let Some(c) = lock(&self.client).as_ref() {
            return Ok(c.clone());
        }
        let ctx = self.gw.ctx().ok_or(Fail::Stopped)?;
        let up = ctx.upstream.as_ref().map_err(|_| Fail::NoUpstream)?;
        let c = (up.tls_connector_with_alpn(&[b"http/1.1"]), up.resolver());
        *lock(&self.client) = Some(c.clone());
        Ok(c)
    }

    /// A new connection to the route's fixed `host`, within the connect
    /// deadline: the lookup (on the blocking pool, holding the box's and
    /// the gateway's lookup permits until it really ends), every answer an
    /// allowed address, TCP, TLS for `host`, the HTTP/1.1 handshake. The
    /// port is always [`MODEL_PORT`], whatever the resolver answers
    /// ([`upstream_addr`]).
    async fn connect(&self, host: &'static str) -> Result<UpConn, Fail> {
        let (tls, resolver) = self.client()?;
        let gw = &self.gw;
        let mine = Arc::clone(&self.run.lookups)
            .try_acquire_owned()
            .map_err(|_| Fail::Busy)?;
        let all = Arc::clone(&gw.lookups)
            .try_acquire_owned()
            .map_err(|_| Fail::Busy)?;
        let work = async move {
            let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
                let _permits = (mine, all);
                resolver.resolve(host, MODEL_PORT)
            })
            .await
            .map_err(|_| Fail::Unreachable)?
            .map_err(|_| Fail::Unreachable)?
            .into_iter()
            .take(super::MAX_ANSWERS)
            .map(|a| upstream_addr(gw.allow_loopback, a))
            .collect();
            if addrs.is_empty() {
                return Err(Fail::Unreachable);
            }
            if !addrs.iter().all(|a| gw.address_ok(&a.ip())) {
                return Err(Fail::Private);
            }
            let mut tcp = None;
            for a in addrs {
                if let Ok(s) = TcpStream::connect(a).await {
                    tcp = Some(s);
                    break;
                }
            }
            let tcp = tcp.ok_or(Fail::Unreachable)?;
            let _ = tcp.set_nodelay(true);
            let name =
                rustls::pki_types::ServerName::try_from(host).map_err(|_| Fail::Unreachable)?;
            let tls = tls
                .connect(name, tcp)
                .await
                .map_err(|_| Fail::Unreachable)?;
            let (sender, conn) = hyper::client::conn::http1::Builder::new()
                .max_headers(MAX_HEADERS)
                .max_header_size(MAX_RESPONSE_HEAD_BYTES)
                .handshake(TokioIo::new(tls))
                .await
                .map_err(|_| Fail::Unreachable)?;
            let task = tokio::spawn(async move {
                let _ = conn.await;
            });
            Ok(UpConn {
                host,
                sender,
                _task: AbortOnDrop(task),
            })
        };
        tokio::time::timeout(Duration::from_secs(gw.model.connect_secs), work)
            .await
            .map_err(|_| Fail::ConnectTimeout)?
    }

    /// The kept connection when it is to `host` and can take a request,
    /// else a new one.
    async fn ready_conn(&self, host: &'static str) -> Result<UpConn, Fail> {
        let kept = lock(&self.upstream).take();
        if let Some(mut u) = kept {
            if u.host == host && !u.sender.is_closed() {
                let wait = Duration::from_secs(self.gw.model.connect_secs);
                if let Ok(Ok(())) = tokio::time::timeout(wait, u.sender.ready()).await {
                    return Ok(u);
                }
            }
        }
        self.connect(host).await
    }

    /// Send `req` to `host`; a kept connection that turns out closed before the
    /// request was written is replaced once (the request comes back
    /// unsent, so it is never sent twice).
    async fn exchange(
        &self,
        req: Request<UpBody>,
        host: &'static str,
    ) -> Result<Response<Incoming>, Fail> {
        let mut u = self.ready_conn(host).await?;
        let r = match u.sender.try_send_request(req).await {
            Ok(r) => r,
            Err(mut e) => {
                let Some(req) = e.take_message() else {
                    return Err(Fail::Send);
                };
                u = self.connect(host).await?;
                u.sender.send_request(req).await.map_err(|_| Fail::Send)?
            }
        };
        *lock(&self.upstream) = Some(u);
        Ok(r)
    }
}

// ---------------------------------------------------------------- records

/// What a `model` record says about its request.
struct RecInfo {
    id: BoxId,
    session: String,
    method: String,
    path: String,
    login: Login,
    provider: Provider,
}

fn login_name(l: Login) -> &'static str {
    match l {
        Login::ApiKey => "api-key",
        Login::Subscription => "subscription",
    }
}

/// The path without its query, cut to [`RECORD_PATH_MAX`] bytes.
fn record_path(p: &str) -> String {
    let mut end = p.len().min(RECORD_PATH_MAX);
    while !p.is_char_boundary(end) {
        end -= 1;
    }
    p[..end].to_string()
}

/// The path recorded for `path_not_allowed`: no query, the box's
/// placeholder never written (as sent or percent-encoded), cut to
/// [`RECORD_PATH_MAX`] bytes.
fn denied_path(path: &str, placeholder: Option<&str>) -> String {
    let Some(ph) = placeholder.filter(|p| !p.is_empty()) else {
        return record_path(path);
    };
    let shown = path.replace(ph, "[placeholder]");
    if in_target(shown.as_bytes(), ph.as_bytes()) {
        return "[a path holding the box placeholder]".to_string();
    }
    record_path(&shown)
}

async fn model_record(gw: &GatewayShared, r: &RecInfo, status: u16, c: &Counters, outcome: &str) {
    let Some(ctx) = gw.ctx() else {
        eprintln!("saiifed: boxes: a model record was not written: saiife is stopping");
        return;
    };
    let mut rec = ctx.record("model", &format!("{} {}", r.method, r.path));
    rec.session = Some(r.session.clone());
    let x = &mut rec.extra;
    x.insert("box".into(), r.id.as_str().into());
    x.insert("method".into(), r.method.clone().into());
    x.insert("path".into(), r.path.clone().into());
    x.insert("status".into(), status.into());
    x.insert("bytes_up".into(), c.up.load(Ordering::Relaxed).into());
    x.insert("bytes_down".into(), c.down.load(Ordering::Relaxed).into());
    x.insert("ms".into(), ms_since(c.t0).into());
    x.insert("provider".into(), r.provider.name().into());
    x.insert("login".into(), login_name(r.login).into());
    // R3: the real credential never enters the box.
    x.insert("credential".into(), "gateway".into());
    x.insert("outcome".into(), outcome.into());
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiifed: warning: cannot write a model record: {e}");
    }
}

// ---------------------------------------------------------------- serving

/// Stream `body` to the box frame by frame until it ends, the idle timer
/// fires, lockdown is on, the box goes off or the box stops reading; then
/// write the request's `model` record.
fn pump(st: &ConnState, body: Incoming, c: Arc<Counters>, rec: RecInfo, status: u16) -> DownBody {
    let (tx, rx) = mpsc::channel::<Bytes>(1);
    let cut = Arc::new(AtomicBool::new(false));
    let cut_set = Arc::clone(&cut);
    let gw = Arc::clone(&st.gw);
    let mut stop = st.run.stop.subscribe();
    tokio::spawn(async move {
        let mut body = body;
        let idle = Duration::from_secs(gw.model.idle_secs);
        let outcome = {
            let idle_w = idle_watch(&c.last, c.t0, idle);
            let lock_w = lockdown_watch(&gw);
            let stop_w = stopped(&mut stop);
            tokio::pin!(idle_w, lock_w, stop_w);
            loop {
                // Biased, the body first: once hyper has sent the whole
                // content-length body to the box it drops the receiver,
                // and a finished response must be recorded as `done`, not
                // `client_closed` (plan 42 R13). A receiver dropped before
                // the body ended is still `client_closed`.
                let frame = tokio::select! {
                    biased;
                    f = body.frame() => f,
                    () = &mut idle_w => break "idle",
                    () = &mut lock_w => break "lockdown",
                    () = &mut stop_w => break "stopped",
                    () = tx.closed() => {
                        break if body.is_end_stream() { "done" } else { "client_closed" };
                    }
                };
                let data = match frame {
                    None => break "done",
                    Some(Err(_)) => break "upstream_error",
                    Some(Ok(f)) => match f.into_data() {
                        Ok(d) => d,
                        // Trailers are not passed on.
                        Err(_) => continue,
                    },
                };
                c.down.fetch_add(data.len() as u64, Ordering::Relaxed);
                c.stamp();
                tokio::select! {
                    r = tx.send(data) => if r.is_err() { break "client_closed" },
                    () = &mut idle_w => break "idle",
                    () = &mut lock_w => break "lockdown",
                    () = &mut stop_w => break "stopped",
                }
                c.stamp();
            }
        };
        if outcome != "done" {
            cut_set.store(true, Ordering::SeqCst);
        }
        drop(tx);
        drop(body);
        model_record(&gw, &rec, status, &c, outcome).await;
    });
    DownBody { rx, cut }
}

/// One request: every check, the swap, the upstream, the streamed answer.
async fn forward(st: &Arc<ConnState>, req: Request<Incoming>) -> Result<Response<ResBody>, Deny> {
    let gw = &st.gw;
    if gw.locked() {
        return Err(Deny::new(
            StatusCode::SERVICE_UNAVAILABLE,
            LOCKDOWN_MSG,
            "lockdown",
        ));
    }
    let (mut parts, body) = req.into_parts();
    if parts.method != Method::GET && parts.method != Method::POST {
        return Err(Deny::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "only GET and POST are forwarded",
            "method",
        ));
    }
    let origin_form = parts.uri.scheme().is_none()
        && parts.uri.authority().is_none()
        && parts.uri.path().starts_with('/');
    if !origin_form {
        return Err(Deny::new(
            StatusCode::BAD_REQUEST,
            "only origin-form targets (/path) are forwarded",
            "target",
        ));
    }
    if parts.headers.contains_key(UPGRADE) {
        return Err(Deny::new(
            StatusCode::BAD_REQUEST,
            "upgrades are not forwarded",
            "upgrade",
        ));
    }
    let info = box_info(gw, &st.run.id).await?;
    // C4 holds here too: a template edited to subscription after spawn
    // gets nothing forwarded until the owner's terms check.
    if info.login == Login::Subscription && !gw.subscription_cleared {
        return Err(Deny::new(
            StatusCode::FORBIDDEN,
            SUBSCRIPTION_GATED,
            "subscription_gated",
        ));
    }
    let not_valid = |reason| Deny::new(StatusCode::UNAUTHORIZED, NOT_VALID, reason);
    // The route is the template's; the credential kind must belong to it
    // (both come from the template, so this only fails closed).
    if routes::provider_of(info.cred) != info.provider {
        return Err(not_valid("no_placeholder"));
    }
    let route = routes::route(info.provider);
    let path = parts.uri.path();
    if !routes::path_plain(path) {
        return Err(Deny::new(StatusCode::BAD_REQUEST, NOT_PLAIN, "path"));
    }
    if route.provider == Provider::Google && parts.uri.query().is_some_and(routes::query_has_key) {
        return Err(Deny::new(StatusCode::BAD_REQUEST, QUERY_KEY, "query_key"));
    }
    if !routes::allowed(route, &parts.method, path, parts.uri.query()) {
        let mut d = Deny::new(StatusCode::FORBIDDEN, NOT_FORWARDED, "path_not_allowed");
        d.request = Some((
            parts.method.to_string(),
            denied_path(path, info.placeholder.as_deref()),
        ));
        return Err(d);
    }
    let Some(expected) = info.placeholder.as_deref() else {
        return Err(not_valid("no_placeholder"));
    };
    check_credential(&parts, info.cred, expected).map_err(|_| not_valid("bad_credential"))?;
    let cap = gw.model.body_max;
    if body.size_hint().lower() > cap {
        return Err(Deny::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the request body is too large",
            "body_too_large",
        ));
    }
    let real = vault_value(gw, &info.credential, route)?;
    rewrite_request(&mut parts, info.cred, &real).map_err(|_| {
        Deny::new(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "the vault secret {} is not a usable token for {}",
                info.credential, route.services[0]
            ),
            "secret_invalid",
        )
    })?;
    drop(real);
    parts.version = Version::HTTP_11;
    let rec = RecInfo {
        id: st.run.id.clone(),
        session: info.session,
        method: parts.method.to_string(),
        path: record_path(parts.uri.path()),
        login: info.login,
        provider: route.provider,
    };
    let c = Arc::new(Counters::new());
    let req = Request::from_parts(
        parts,
        UpBody {
            inner: body,
            c: Arc::clone(&c),
            cap,
        },
    );
    let idle = Duration::from_secs(gw.model.idle_secs);
    let mut stop = st.run.stop.subscribe();
    let got = tokio::select! {
        r = st.exchange(req, route.host) => r,
        () = idle_watch(&c.last, c.t0, idle) => Err(Fail::Idle),
        () = lockdown_watch(gw) => Err(Fail::Lockdown),
        () = stopped(&mut stop) => Err(Fail::Stopped),
    };
    let got = got.map_err(|f| {
        if c.over.load(Ordering::SeqCst) {
            Fail::TooLarge
        } else {
            f
        }
    });
    let resp = match got {
        Ok(r) => r,
        Err(Fail::TooLarge) => {
            let (code, msg, reason) = Fail::TooLarge.answer();
            return Err(Deny::new(code, msg, reason));
        }
        Err(f) => {
            // Dropped: a request cut half way never leaves a connection
            // for the next one.
            lock(&st.upstream).take();
            let (code, msg, outcome) = f.answer();
            model_record(gw, &rec, code.as_u16(), &c, outcome).await;
            return Ok(plain(code, msg));
        }
    };
    c.stamp();
    let (mut rparts, rbody) = resp.into_parts();
    clean_response(&mut rparts);
    let status = rparts.status.as_u16();
    let down = pump(st, rbody, c, rec, status);
    Ok(Response::from_parts(rparts, down.boxed_unsync()))
}

/// Serve one guest connection on the model port of box `id` (nothing when
/// the box has no gateway run).
pub async fn serve(stream: UnixStream, id: BoxId, gw: Arc<GatewayShared>) {
    let Some(run) = gw.run(&id) else {
        return;
    };
    serve_run(stream, run, gw).await;
}

pub(crate) async fn serve_run(mut stream: UnixStream, run: Arc<BoxRun>, gw: Arc<GatewayShared>) {
    let mut stop = run.stop.subscribe();
    if *stop.borrow_and_update() {
        return;
    }
    // The box's new-connection bucket, then its connection limit, as on
    // the egress port (counted with the box's other connections).
    let slot = if run.take_token((gw.clock)(), &gw.limits) {
        Slot::take(&run, gw.limits.tunnels).ok_or((
            "too many open connections from this box",
            "too_many_tunnels",
        ))
    } else {
        Err(("too many new connections from this box", "rate_limited"))
    };
    let _slot = match slot {
        Ok(s) => s,
        Err((msg, reason)) => {
            answer(&mut stream, 429, msg).await;
            drop(stream);
            model_deny(Arc::clone(&gw), run.id.clone(), reason, None).await;
            return;
        }
    };
    let st = Arc::new(ConnState {
        run: Arc::clone(&run),
        gw: Arc::clone(&gw),
        upstream: Mutex::new(None),
        client: Mutex::new(None),
    });
    let svc = hyper::service::service_fn(move |req| {
        let st = Arc::clone(&st);
        async move {
            let resp = match forward(&st, req).await {
                Ok(r) => r,
                Err(d) => {
                    tokio::spawn(model_deny(
                        Arc::clone(&st.gw),
                        st.run.id.clone(),
                        d.reason,
                        d.request,
                    ));
                    plain(d.code, &d.msg)
                }
            };
            Ok::<_, Infallible>(resp)
        }
    });
    let mut b = hyper::server::conn::http1::Builder::new();
    b.timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(gw.model.head_secs))
        .max_headers(MAX_HEADERS)
        .max_header_size(MAX_HEAD_BYTES)
        .max_buf_size(MAX_BUF)
        .keep_alive(true);
    let conn = b.serve_connection(TokioIo::new(stream), svc);
    tokio::select! {
        _ = conn => {}
        () = stopped(&mut stop) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PH: &str = concat!("sk-", "ant-", "api03-", "saiife", "0123");
    const REAL: &str = concat!("sk-", "ant-", "api03-", "real", "4567");

    fn parts(headers: &[(&str, &str)]) -> http::request::Parts {
        let mut b = Request::builder().method("POST").uri("/v1/messages?x=1");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn names(h: &HeaderMap) -> Vec<String> {
        let mut v: Vec<String> = h
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap()))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn rewrite_request_is_pinned() {
        let mut p = parts(&[
            ("x-api-key", PH),
            ("authorization", "Bearer box"),
            ("cookie", "a=b"),
            ("proxy-authorization", "Basic x"),
            ("forwarded", "for=1.2.3.4"),
            ("x-forwarded-for", "1.2.3.4"),
            ("x-forwarded-proto", "http"),
            ("host", "evil.test"),
            ("connection", "keep-alive, x-hop"),
            ("x-hop", "1"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("trailer", "x"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "h2c"),
            ("proxy-connection", "keep-alive"),
            ("anthropic-version", "2023-06-01"),
            ("anthropic-beta", "a,b"),
            ("content-type", "application/json"),
            ("content-length", "12"),
            ("user-agent", "claude-cli"),
        ]);
        rewrite_request(&mut p, ModelCred::AnthropicApiKey, REAL).unwrap();
        assert_eq!(
            names(&p.headers),
            vec![
                "anthropic-beta: a,b".to_string(),
                "anthropic-version: 2023-06-01".into(),
                "content-length: 12".into(),
                "content-type: application/json".into(),
                "host: api.anthropic.com".into(),
                "user-agent: claude-cli".into(),
                format!("x-api-key: {REAL}"),
            ]
        );
        assert!(p.headers["x-api-key"].is_sensitive());
        // The target and method are untouched.
        assert_eq!(p.uri, "/v1/messages?x=1");
        assert_eq!(p.method, Method::POST);

        let mut p = parts(&[("authorization", "Bearer box"), ("x-api-key", PH)]);
        rewrite_request(&mut p, ModelCred::AnthropicSubscription, REAL).unwrap();
        assert_eq!(
            names(&p.headers),
            vec![
                format!("authorization: Bearer {REAL}"),
                "host: api.anthropic.com".into(),
            ]
        );
        assert!(p.headers["authorization"].is_sensitive());

        for bad in ["", " x", "x\r\nevil: 1", "x\n"] {
            let mut p = parts(&[("x-api-key", PH)]);
            assert!(rewrite_request(&mut p, ModelCred::AnthropicApiKey, bad).is_err());
            // Nothing changed on an error.
            assert_eq!(p.headers["x-api-key"], PH);
        }
    }

    #[test]
    fn check_credential_rules() {
        let ok = |h: &[(&str, &str)], l| check_credential(&parts(h), l, PH).is_ok();
        let bearer = format!("Bearer {PH}");
        assert!(ok(&[("x-api-key", PH)], ModelCred::AnthropicApiKey));
        assert!(ok(
            &[("x-api-key", PH), ("authorization", "Bearer x")],
            ModelCred::AnthropicApiKey
        ));
        assert!(!ok(&[], ModelCred::AnthropicApiKey));
        assert!(!ok(
            &[("authorization", &bearer)],
            ModelCred::AnthropicApiKey
        ));
        assert!(!ok(
            &[("x-api-key", PH), ("x-api-key", PH)],
            ModelCred::AnthropicApiKey
        ));
        assert!(!ok(
            &[("x-api-key", PH), ("x-other", &bearer)],
            ModelCred::AnthropicApiKey
        ));
        assert!(!ok(
            &[("x-api-key", &format!("{PH} "))],
            ModelCred::AnthropicApiKey
        ));
        assert!(ok(
            &[("authorization", &bearer)],
            ModelCred::AnthropicSubscription
        ));
        assert!(ok(
            &[("authorization", &format!("bearer {PH}"))],
            ModelCred::AnthropicSubscription
        ));
        assert!(!ok(
            &[("authorization", PH)],
            ModelCred::AnthropicSubscription
        ));
        assert!(!ok(&[("x-api-key", PH)], ModelCred::AnthropicSubscription));
        assert!(!ok(
            &[("authorization", &bearer), ("x-api-key", PH)],
            ModelCred::AnthropicSubscription
        ));
        assert!(
            check_credential(&parts(&[("x-api-key", "")]), ModelCred::AnthropicApiKey, "").is_err()
        );
    }

    #[test]
    fn clean_response_strips() {
        let r = Response::builder()
            .header("set-cookie", "a=b")
            .header("connection", "close, x-hop")
            .header("x-hop", "1")
            .header("transfer-encoding", "chunked")
            .header("content-type", "text/event-stream")
            .header("request-id", "req_1")
            .body(())
            .unwrap();
        let (mut p, ()) = r.into_parts();
        clean_response(&mut p);
        assert_eq!(
            names(&p.headers),
            vec![
                "content-type: text/event-stream".to_string(),
                "request-id: req_1".into(),
            ]
        );
    }

    #[test]
    fn upstream_port_is_fixed() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(upstream_addr(false, a("1.2.3.4:8443")), a("1.2.3.4:443"));
        assert_eq!(
            upstream_addr(false, a("127.0.0.1:8443")),
            a("127.0.0.1:443")
        );
        // The test flag keeps only a loopback answer's port, in debug builds.
        assert_eq!(upstream_addr(true, a("10.0.0.1:8443")), a("10.0.0.1:443"));
        let want = if cfg!(debug_assertions) { 8443 } else { 443 };
        assert_eq!(upstream_addr(true, a("127.0.0.1:8443")).port(), want);
    }

    #[test]
    fn denied_path_hides_the_placeholder() {
        assert_eq!(denied_path("/v1/files", Some(PH)), "/v1/files");
        assert_eq!(denied_path("/v1/files", None), "/v1/files");
        assert_eq!(
            denied_path(&format!("/v1/files/{PH}/x"), Some(PH)),
            "/v1/files/[placeholder]/x"
        );
        let enc = format!("/v1/files/%{:02X}{}", PH.as_bytes()[0], &PH[1..]);
        let shown = denied_path(&enc, Some(PH));
        assert!(!shown.contains(&PH[1..]), "{shown}");
        let long = format!("/{}{PH}", "a".repeat(250));
        assert!(!denied_path(&long, Some(PH)).contains(&PH[..6]));
    }

    #[test]
    fn record_path_is_cut() {
        assert_eq!(record_path("/v1/messages"), "/v1/messages");
        let long = format!("/{}", "é".repeat(300));
        let cut = record_path(&long);
        assert!(cut.len() <= RECORD_PATH_MAX);
        assert!(long.starts_with(&cut));
    }
}
