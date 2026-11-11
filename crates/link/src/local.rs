//! The localhost HTTP server for the browser UI (plan 29, Task 7).
//!
//! Security rests on four checks made before any routing: the peer is
//! loopback, `Host` is exactly `localhost:<port>` (DNS rebinding, and the
//! WebAuthn RP ID is always `localhost`), a POST carries exactly
//! `Origin: http://localhost:<port>` and a JSON content type, and the body
//! is capped while it is read. Every answer carries the CSP and friends.
//! This module never looks inside a frame's `body`: the daemon decides.

use crate::assets::{etag, Asset, ASSETS};
use crate::{Daemon, LinkError};
use bytes::Bytes;
use http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use saiife_ipc::msg::{OP_WORKSPACE_FRAME, OP_WORKSPACE_HELLO, OP_WORKSPACE_PAIR_FINISH};
use serde_json::{json, Map, Value};
use std::convert::Infallible;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;

/// Largest POST body the UI may send.
pub const MAX_REQUEST_BYTES: usize = 96 * 1024;

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Largest request head (request line and headers).
const MAX_HEAD_BYTES: usize = 16 * 1024;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Time a POST body may take to arrive (a trickling client gets a 408).
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Open connections at once; one over the cap is closed unanswered.
pub const MAX_CONNS: usize = 64;

/// The server's limits; the tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Opts {
    pub body_read_timeout: Duration,
    pub max_conns: usize,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts {
            body_read_timeout: BODY_READ_TIMEOUT,
            max_conns: MAX_CONNS,
        }
    }
}

/// Serves the UI on `listener` (bound on 127.0.0.1 only), one task per
/// connection. It never returns: an accept error is retried after 50 ms,
/// and the caller ends it by dropping the future.
pub async fn serve(listener: tokio::net::TcpListener, daemon: Daemon, port: u16) {
    serve_with(listener, daemon, port, Opts::default()).await
}

/// [`serve`] with explicit limits.
pub async fn serve_with(listener: tokio::net::TcpListener, daemon: Daemon, port: u16, opts: Opts) {
    let slots = Arc::new(Semaphore::new(opts.max_conns));
    loop {
        match listener.accept().await {
            Ok((s, addr)) => {
                // Bound on loopback; anything else is closed unanswered.
                if !addr.ip().is_loopback() {
                    continue;
                }
                // Over the cap: closed unanswered, so a flood of idle
                // connections cannot starve the ones in use.
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    continue;
                };
                let daemon = daemon.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let svc = service_fn(move |req| {
                        let daemon = daemon.clone();
                        async move { Ok::<_, Infallible>(handle(req, &daemon, port, opts).await) }
                    });
                    let _ = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .max_buf_size(MAX_HEAD_BYTES)
                        .max_header_size(MAX_HEAD_BYTES)
                        .header_read_timeout(HEADER_READ_TIMEOUT)
                        .serve_connection(TokioIo::new(s), svc)
                        .await;
                });
            }
            Err(e) => {
                eprintln!("saiife: warning: workspace accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

type Resp = Response<Full<Bytes>>;

async fn handle(req: Request<Incoming>, daemon: &Daemon, port: u16, opts: Opts) -> Resp {
    let mut resp = route(req, daemon, port, opts).await;
    let h = resp.headers_mut();
    for (k, v) in [
        ("content-security-policy", CSP),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
    ] {
        h.insert(k, HeaderValue::from_static(v));
    }
    resp
}

/// The value of a header that must occur exactly once and be text.
fn single(h: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    let mut it = h.get_all(name).iter();
    let v = it.next()?;
    if it.next().is_some() {
        return None;
    }
    v.to_str().ok()
}

fn json_resp(status: StatusCode, v: &Value) -> Resp {
    let mut r = Response::new(Full::new(Bytes::from(v.to_string())));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn json_error(status: StatusCode, msg: &str) -> Resp {
    json_resp(status, &json!({"ok": false, "error": msg}))
}

async fn route(req: Request<Incoming>, daemon: &Daemon, port: u16, opts: Opts) -> Resp {
    if single(req.headers(), header::HOST) != Some(format!("localhost:{port}").as_str()) {
        return json_error(StatusCode::FORBIDDEN, "bad_host");
    }
    let path = req.uri().path().to_string();
    match (req.method(), path.as_str()) {
        (&Method::GET, "/api/hello") => {
            let r = daemon.call(OP_WORKSPACE_HELLO, Map::new()).await;
            answer(r.map(|mut m| {
                m.remove("id");
                Value::Object(m)
            }))
        }
        (&Method::POST, "/api/frame") => post(req, daemon, port, opts, Post::Frame).await,
        (&Method::POST, "/api/pair") => post(req, daemon, port, opts, Post::Pair).await,
        (&Method::GET, p) => static_file(p, req.headers()),
        _ => json_error(StatusCode::NOT_FOUND, "not_found"),
    }
}

/// A daemon result as the UI reads it: success as is, a refusal as `200`
/// with its `rule`, an unreachable daemon as `503`.
fn answer(r: Result<Value, LinkError>) -> Resp {
    match r {
        Ok(v) => json_resp(StatusCode::OK, &v),
        Err(LinkError::Refused {
            error,
            rule,
            message,
        }) => json_resp(
            StatusCode::OK,
            &json!({"ok": false, "error": error, "rule": rule, "message": message}),
        ),
        Err(LinkError::Unreachable(_)) => json_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({
                "ok": false,
                "error": "unreachable",
                "message": "the saiife daemon is not reachable",
            }),
        ),
    }
}

/// ETags are computed once per asset (the table is static).
fn cached_etag(a: &Asset) -> String {
    static TAGS: OnceLock<Vec<String>> = OnceLock::new();
    let tags = TAGS.get_or_init(|| ASSETS.iter().map(etag).collect());
    match ASSETS.iter().position(|x| x.path == a.path) {
        Some(i) => tags[i].clone(),
        None => etag(a),
    }
}

fn static_file(path: &str, req_headers: &HeaderMap) -> Resp {
    let path = if path == "/" { "/index.html" } else { path };
    let Some(a) = ASSETS.iter().find(|a| a.path == path) else {
        return json_error(StatusCode::NOT_FOUND, "not_found");
    };
    let tag = cached_etag(a);
    let fresh = req_headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().trim_start_matches("W/"))
        .any(|t| t == tag || t == "*");
    asset_resp(a, &tag, fresh)
}

fn asset_resp(a: &Asset, tag: &str, not_modified: bool) -> Resp {
    let body = if not_modified {
        Bytes::new()
    } else {
        Bytes::from_static(a.bytes)
    };
    let mut r = Response::new(Full::new(body));
    if not_modified {
        *r.status_mut() = StatusCode::NOT_MODIFIED;
    }
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(a.mime));
    if let Ok(v) = HeaderValue::from_str(tag) {
        h.insert(header::ETAG, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    r
}

#[derive(Clone, Copy)]
enum Post {
    Frame,
    Pair,
}

fn is_json_type(v: &str) -> bool {
    let v = v.trim().to_ascii_lowercase();
    let rest = match v.strip_prefix("application/json") {
        Some(r) => r,
        None => return false,
    };
    let rest = rest.trim();
    rest.is_empty() || rest.strip_prefix(';').map(str::trim) == Some("charset=utf-8")
}

async fn post(req: Request<Incoming>, daemon: &Daemon, port: u16, opts: Opts, kind: Post) -> Resp {
    let h = req.headers();
    if single(h, header::ORIGIN) != Some(format!("http://localhost:{port}").as_str()) {
        return json_error(StatusCode::FORBIDDEN, "bad_origin");
    }
    if !single(h, header::CONTENT_TYPE).is_some_and(is_json_type) {
        return json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
    }
    // A declared length over the cap is refused before any byte is read.
    let declared = single(h, header::CONTENT_LENGTH).and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_REQUEST_BYTES) {
        return json_error(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    }
    let read = Limited::new(req.into_body(), MAX_REQUEST_BYTES).collect();
    let body = match tokio::time::timeout(opts.body_read_timeout, read).await {
        Err(_) => return json_error(StatusCode::REQUEST_TIMEOUT, "body_timeout"),
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(e))
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some() =>
        {
            return json_error(StatusCode::PAYLOAD_TOO_LARGE, "too_large");
        }
        Ok(Err(_)) => return json_error(StatusCode::BAD_REQUEST, "bad_request"),
    };
    let Ok(Value::Object(mut obj)) = serde_json::from_slice::<Value>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "bad_request");
    };
    match kind {
        Post::Frame => {
            if !keys_ok(&obj, &["body", "sig"], &["touch"]) {
                return json_error(StatusCode::BAD_REQUEST, "bad_request");
            }
            obj.insert("via".into(), "local".into());
            let r = daemon.call(OP_WORKSPACE_FRAME, obj).await;
            answer(r.map(|m| json!({"ok": true, "result": m.get("result").cloned()})))
        }
        Post::Pair => {
            if !keys_ok(&obj, &["pair_id", "device_pub", "label", "proof"], &[]) {
                return json_error(StatusCode::BAD_REQUEST, "bad_request");
            }
            let r = daemon.call(OP_WORKSPACE_PAIR_FINISH, obj).await;
            answer(r.map(
                |m| json!({"device_id": m.get("device_id"), "short_code": m.get("short_code")}),
            ))
        }
    }
}

/// Every `required` key present as a string and no key beyond `required`
/// and `optional` (whose value is passed on untouched).
fn keys_ok(obj: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    required
        .iter()
        .all(|k| obj.get(*k).is_some_and(Value::is_string))
        && obj
            .keys()
            .all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str()))
}
