//! The pipeline (§6.7.1 steps 3–12) with a fake `Env` and the `test-echo`
//! manifest over a loopback TLS upstream. Nothing leaves 127.0.0.1.

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::limits::Limiter;
use saiife_broker::manifest::{AuthSpec, Manifest};
use saiife_broker::pipeline::{
    limit_event, record, run, Call, Env, OpRef, Outcome, PolicySnapshot, Pools, Via,
};
use saiife_broker::request::AuthMaterial;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::Catalog;
use saiife_policy::{Mode, PolicyError, Scope, ServiceOverlay, SystemConfig};
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const TOKEN: &str = "echo-token-7f3a9c";

struct Mock {
    hits: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<(String, http::HeaderMap, Bytes)>>>,
}

struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if host.ends_with(".echo.test") {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

async fn answer(
    req: Request<Incoming>,
    hits: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<(String, http::HeaderMap, Bytes)>>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    hits.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let token = parts
        .headers
        .get("x-echo-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    seen.lock()
        .unwrap()
        .push((parts.uri.to_string(), parts.headers.clone(), body));
    let json = |status: u16, b: String| {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header(
                "link",
                "<https://acme.echo.test/api/orders.json?since_id=42&page_info=x>; rel=\"next\"",
            )
            .header("set-cookie", "s=1")
            .body(Full::new(Bytes::from(b)))
            .unwrap()
    };
    let resp = match parts.uri.path() {
        "/api/orders.json" => json(
            200,
            format!(r#"{{"orders":[{{"id":1}}],"echo":"{token}"}}"#),
        ),
        "/api/orders/404" => json(404, r#"{"errors":"Not Found"}"#.into()),
        "/api/files/gz" => Response::builder()
            .header("content-encoding", "gzip")
            .body(Full::new(Bytes::from_static(b"\x1f\x8b....")))
            .unwrap(),
        "/api/files/text" => Response::builder()
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from_static(b"plain text")))
            .unwrap(),
        _ => json(404, "{}".into()),
    };
    Ok(resp)
}

async fn mock() -> (Mock, Upstream) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["acme.echo.test".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    let leaf_der: CertificateDer<'static> = leaf.der().clone();
    let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf_der], PrivateKeyDer::Pkcs8(key))
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (h2, s2) = (hits.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let (h, s) = (h2.clone(), s2.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req| answer(req, h.clone(), s.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let up = Upstream::with_roots(roots, Arc::new(Loopback(port)), Duration::from_secs(5));
    (Mock { hits, seen }, up)
}

/// The fake daemon side.
struct FakeEnv {
    scope: Result<Option<Scope>, &'static str>,
    secret: Result<&'static str, &'static str>,
    pools: Pools,
}

impl FakeEnv {
    fn ok() -> FakeEnv {
        FakeEnv {
            scope: Ok(Some(Scope {
                name: "shop-agents".into(),
                users: vec!["agent".into()],
                projects: vec![],
                services: vec!["shop".into()],
                env: Some("prod".into()),
            })),
            secret: Ok(TOKEN),
            pools: Pools::new(),
        }
    }
}

impl Env for FakeEnv {
    fn scope(&self, user: &str) -> Result<Option<Scope>, PolicyError> {
        match &self.scope {
            Ok(s) => Ok(s.clone()),
            Err(_) => Err(PolicyError::ScopeConflict {
                user: user.into(),
                scopes: vec!["a".into(), "b".into()],
            }),
        }
    }
    fn secret(
        &self,
        _name: &str,
        _service: &str,
        auth: &[AuthSpec],
    ) -> Result<AuthMaterial, &'static str> {
        let v = self.secret?;
        let fields = [("token".to_string(), Zeroizing::new(v.to_string()))].into();
        Ok(AuthMaterial::from_spec(&auth[0], fields))
    }
    fn secret_values(&self, _name: &str) -> Option<Vec<Zeroizing<String>>> {
        // Masking values come from the vault even when the service may not
        // use the secret.
        Some(vec![Zeroizing::new(TOKEN.to_string())])
    }
    fn pool(&self, service: &str) -> Arc<Semaphore> {
        self.pools.get(service)
    }
}

fn refunds_allowed() -> PolicySnapshot {
    let mut snap = snapshot("");
    let s = snap.config.services.get_mut("shop").unwrap();
    s.ask = vec![];
    s.allow = vec!["refunds:write".into()];
    snap
}

#[tokio::test]
async fn denied_call_params_masked_with_the_service_secret() {
    let (_m, up) = mock().await;
    let mut env = FakeEnv::ok();
    env.scope = Ok(None);
    let snap = snapshot("");
    let c = call("files.get", &[("name", TOKEN)]);
    let (o, tr) = run(&c, &snap, &catalog(), &Limiter::new(), &env, &up).await;
    assert_eq!(rule(&o), "no_scope");
    let r = serde_json::to_string(&record(&c, &snap, &tr, &o, "", "0.2.0")).unwrap();
    assert!(!r.contains(TOKEN), "{r}");
    assert!(r.contains("[MASKED]"), "{r}");
}

#[tokio::test]
async fn duplicate_key_in_json_body_is_bad_body() {
    let (m, up) = mock().await;
    let mut c = call("refunds.create", &[("order_id", "7")]);
    c.body = Some(Bytes::from_static(
        br#"{"refund":{"currency":"EUR","transactions":[{"amount":"1.00","amount":"900.00"}]}}"#,
    ));
    let o = go(&c, &refunds_allowed(), &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "bad_body");
    c.body = Some(Bytes::from_static(b"{not json"));
    let o = go(&c, &refunds_allowed(), &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "bad_body");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn json_body_sent_canonical_with_json_content_type() {
    let (m, up) = mock().await;
    let mut c = call("refunds.create", &[("order_id", "7")]);
    c.body = Some(Bytes::from_static(
        b"{ \"refund\" : { \"currency\":\"EUR\",\n \"transactions\":[{\"amount\":\"5.00\"}]}}",
    ));
    c.headers = vec![("Content-Type".into(), "text/plain".into())];
    let (o, tr) = run(
        &c,
        &refunds_allowed(),
        &catalog(),
        &Limiter::new(),
        &FakeEnv::ok(),
        &up,
    )
    .await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    assert_eq!(tr.amount, Some((500, "EUR".to_string())));
    let seen = m.seen.lock().unwrap();
    let (_, headers, body) = &seen[0];
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(
        &body[..],
        br#"{"refund":{"currency":"EUR","transactions":[{"amount":"5.00"}]}}"#
    );
}

fn snapshot(extra: &str) -> PolicySnapshot {
    let text = format!(
        r#"version = 2
locked = true
[services.shop]
connector = "test-echo"
secret = "echo-tok"
params = {{ shop = "acme" }}
allow = ["orders:read", "files:read"]
ask = ["refunds:write"]
{extra}
"#
    );
    let config: SystemConfig = toml::from_str(&text).unwrap();
    PolicySnapshot {
        config,
        hash: "sha256:test".into(),
        mode: Mode::Locked,
    }
}

fn catalog() -> Catalog {
    let m = Manifest::parse(include_str!("../connectors/test-echo.toml")).unwrap();
    Catalog::new(&[], vec![m])
}

fn call(op: &str, params: &[(&str, &str)]) -> Call {
    Call {
        uid: 1001,
        user: "agent".into(),
        session: Some("sess-1".into()),
        project: "/srv/shop".into(),
        service: "shop".into(),
        op: OpRef::Named(op.into()),
        params: params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: None,
        headers: vec![],
        overlay: None,
        via: Via::Cli,
    }
}

async fn go(
    c: &Call,
    snap: &PolicySnapshot,
    env: &FakeEnv,
    up: &Upstream,
    lim: &Limiter,
) -> Outcome {
    run(c, snap, &catalog(), lim, env, up).await.0
}

fn rule(o: &Outcome) -> &str {
    match o {
        Outcome::Denied { rule } => rule,
        other => panic!("expected a deny, got {other:?}"),
    }
}

#[tokio::test]
async fn no_scope_denied_no_upstream_call() {
    let (m, up) = mock().await;
    let mut env = FakeEnv::ok();
    env.scope = Ok(None);
    let o = go(
        &call("orders.list", &[]),
        &snapshot(""),
        &env,
        &up,
        &Limiter::new(),
    )
    .await;
    assert_eq!(rule(&o), "no_scope");
    // A scope that does not list the service is no_scope too.
    let mut env = FakeEnv::ok();
    if let Ok(Some(s)) = &mut env.scope {
        s.services = vec!["other".into()];
    }
    let o = go(
        &call("orders.list", &[]),
        &snapshot(""),
        &env,
        &up,
        &Limiter::new(),
    )
    .await;
    assert_eq!(rule(&o), "no_scope");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn scope_conflict_denied() {
    let (m, up) = mock().await;
    let mut env = FakeEnv::ok();
    env.scope = Err("conflict");
    let o = go(
        &call("orders.list", &[]),
        &snapshot(""),
        &env,
        &up,
        &Limiter::new(),
    )
    .await;
    assert_eq!(rule(&o), "scope_conflict");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unknown_operation_denied() {
    let (m, up) = mock().await;
    let env = FakeEnv::ok();
    let o = go(
        &call("orders.nuke", &[]),
        &snapshot(""),
        &env,
        &up,
        &Limiter::new(),
    )
    .await;
    assert_eq!(rule(&o), "unknown_operation");
    let mut c = call("x", &[]);
    c.op = OpRef::Proxy {
        method: "GET".into(),
        path: "/nothing/here".into(),
    };
    let o = go(&c, &snapshot(""), &env, &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "unknown_operation");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn default_deny_denied() {
    let (m, up) = mock().await;
    let mut snap = snapshot("");
    snap.config.services.get_mut("shop").unwrap().allow = vec!["files:read".into()];
    let o = go(
        &call("orders.list", &[]),
        &snap,
        &FakeEnv::ok(),
        &up,
        &Limiter::new(),
    )
    .await;
    assert_eq!(rule(&o), "default_deny");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ask_denied_until_plan_11() {
    let (m, up) = mock().await;
    let mut c = call("refunds.create", &[("order_id", "7")]);
    c.body = Some(Bytes::from_static(
        br#"{"refund":{"currency":"EUR","transactions":[{"amount":"5.00"}]}}"#,
    ));
    let o = go(&c, &snapshot(""), &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "approval_not_available");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn project_overlay_tightens_and_cannot_widen() {
    let (m, up) = mock().await;
    let mut c = call("orders.list", &[]);
    c.overlay = Some(ServiceOverlay {
        deny: vec!["orders:*".into()],
        ..ServiceOverlay::default()
    });
    let o = go(&c, &snapshot(""), &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "deny:orders:*");
    let mut snap = snapshot("");
    snap.config.services.get_mut("shop").unwrap().allow = vec![];
    c.overlay = Some(ServiceOverlay {
        allow: vec!["orders:read".into()],
        ..ServiceOverlay::default()
    });
    let o = go(&c, &snap, &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "default_deny");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn amount_missing_is_bad_amount() {
    let (m, up) = mock().await;
    let mut snap = snapshot("");
    snap.config.services.get_mut("shop").unwrap().ask = vec![];
    snap.config.services.get_mut("shop").unwrap().allow = vec!["refunds:write".into()];
    let mut c = call("refunds.create", &[("order_id", "7")]);
    c.body = Some(Bytes::from_static(br#"{"refund":{}}"#));
    let o = go(&c, &snap, &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "bad_amount");
    c.body = None;
    let o = go(&c, &snap, &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "bad_amount");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn secret_not_allowed_for_service() {
    let (m, up) = mock().await;
    let mut env = FakeEnv::ok();
    env.secret = Err("secret_not_allowed_for_service");
    let lim = Limiter::new();
    let snap = snapshot("[services.shop.limits]\nrequests_per_minute = 1\n");
    let o = go(&call("orders.list", &[]), &snap, &env, &up, &lim).await;
    assert_eq!(rule(&o), "secret_not_allowed_for_service");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
    // Nothing was sent, so nothing was counted.
    let o = go(&call("orders.list", &[]), &snap, &FakeEnv::ok(), &up, &lim).await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
}

#[tokio::test]
async fn limit_reached() {
    let (m, up) = mock().await;
    let lim = Limiter::new();
    let snap = snapshot("[services.shop.limits]\nrequests_per_minute = 2\n");
    for _ in 0..2 {
        let o = go(&call("orders.list", &[]), &snap, &FakeEnv::ok(), &up, &lim).await;
        assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    }
    let o = go(&call("orders.list", &[]), &snap, &FakeEnv::ok(), &up, &lim).await;
    assert!(
        matches!(
            o,
            Outcome::Limited {
                limit: "requests_per_minute"
            }
        ),
        "{o:?}"
    );
    assert_eq!(m.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn response_value_masked_and_next_page() {
    let (m, up) = mock().await;
    let o = go(
        &call("orders.list", &[("status", "open")]),
        &snapshot(""),
        &FakeEnv::ok(),
        &up,
        &Limiter::new(),
    )
    .await;
    let Outcome::Done { finished, next } = o else {
        panic!("{o:?}")
    };
    assert_eq!(finished.status, 200);
    let body = String::from_utf8(finished.body.to_vec()).unwrap();
    assert!(!body.contains(TOKEN), "{body}");
    assert!(body.contains("[MASKED]"), "{body}");
    assert!(finished.headers.get("set-cookie").is_none());
    // Only the operation's own query parameters come from the link.
    let next = next.unwrap();
    assert_eq!(next.get("since_id").map(String::as_str), Some("42"));
    assert!(!next.contains_key("page_info"));
    // The upstream got the vault token, identity encoding and the query.
    let seen = m.seen.lock().unwrap();
    let (uri, headers, _) = &seen[0];
    assert_eq!(uri, "/api/orders.json?status=open");
    assert_eq!(headers["x-echo-token"], TOKEN);
    assert_eq!(headers["accept-encoding"], "identity");
}

#[tokio::test]
async fn upstream_404_is_done_with_status() {
    let (_m, up) = mock().await;
    let o = go(
        &call("orders.get", &[("order_id", "404")]),
        &snapshot(""),
        &FakeEnv::ok(),
        &up,
        &Limiter::new(),
    )
    .await;
    let Outcome::Done { finished, .. } = o else {
        panic!("{o:?}")
    };
    assert_eq!(finished.status, 404);
}

#[tokio::test]
async fn proxy_captures_validated_like_params() {
    let (m, up) = mock().await;
    let mut c = call("x", &[]);
    c.op = OpRef::Proxy {
        method: "GET".into(),
        path: "/orders/abc".into(),
    };
    let o = go(&c, &snapshot(""), &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "bad_param");
    c.op = OpRef::Proxy {
        method: "GET".into(),
        path: "/orders/%2e%2e".into(),
    };
    let o = go(&c, &snapshot(""), &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "bad_path");
    c.op = OpRef::Proxy {
        method: "GET".into(),
        path: "/orders.json?status=bogus".into(),
    };
    let o = go(&c, &snapshot(""), &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "bad_param");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
    c.op = OpRef::Proxy {
        method: "GET".into(),
        path: "/orders.json?status=open".into(),
    };
    let o = go(&c, &snapshot(""), &FakeEnv::ok(), &up, &Limiter::new()).await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
}

#[tokio::test]
async fn compressed_response_refused() {
    let (_m, up) = mock().await;
    let o = go(
        &call("files.get", &[("name", "gz")]),
        &snapshot(""),
        &FakeEnv::ok(),
        &up,
        &Limiter::new(),
    )
    .await;
    match o {
        Outcome::UpstreamFailed { reason } => assert!(reason.contains("compressed"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn redact_non_json_withheld() {
    let (_m, up) = mock().await;
    let snap = snapshot("[services.shop.redact]\nfields = [\"customer.email\"]\n");
    let o = go(
        &call("files.get", &[("name", "text")]),
        &snap,
        &FakeEnv::ok(),
        &up,
        &Limiter::new(),
    )
    .await;
    assert_eq!(rule(&o), "redact_non_json");
    assert!(o.is_post_send_deny());
}

/// Every §8.5 connector key, plus `op_kind` and `amount`.
#[tokio::test]
async fn connector_record_fields_exact() {
    let (_m, up) = mock().await;
    let snap = snapshot("");
    let c = call("orders.list", &[("status", "open"), ("limit", "50")]);
    let (o, tr) = run(&c, &snap, &catalog(), &Limiter::new(), &FakeEnv::ok(), &up).await;
    let r = record(&c, &snap, &tr, &o, "claude", "0.2.0");
    let v = serde_json::to_value(&r).unwrap();
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    let mut want = vec![
        "v",
        "ts",
        "kind",
        "uid",
        "user",
        "mode",
        "policy",
        "agent",
        "project",
        "session",
        "tool",
        "input",
        "decision",
        "pack",
        "rule",
        "reason",
        "saiife",
        "service",
        "operation",
        "capability",
        "env",
        "params",
        "body_sha256",
        "body_bytes",
        "status",
        "resp_bytes",
        "duration_ms",
        "secret",
        "limit",
        "via",
        "op_kind",
        "amount",
    ];
    want.sort();
    assert_eq!(keys, want);
    assert_eq!(v["kind"], "connector");
    assert_eq!(v["tool"], "api");
    assert_eq!(v["input"], "shop orders.list limit=50 status=open");
    assert_eq!(v["decision"], "allow");
    assert_eq!(v["capability"], "orders:read");
    assert_eq!(v["env"], "prod");
    assert_eq!(
        v["params"],
        serde_json::json!({"status":"open","limit":"50"})
    );
    assert_eq!(v["body_sha256"], serde_json::Value::Null);
    assert_eq!(v["body_bytes"], 0);
    assert_eq!(v["status"], 200);
    assert_eq!(v["secret"], "echo-tok");
    assert_eq!(v["limit"], serde_json::Value::Null);
    assert_eq!(v["via"], "cli");
    assert_eq!(v["op_kind"], "read");
    assert_eq!(v["policy"], "sha256:test");
    assert_eq!(v["session"], "sess-1");
    assert!(!v.to_string().contains(TOKEN));
    // A sent request is a limiter event; a denied one is not.
    let ev = limit_event(&r).unwrap();
    assert_eq!((ev.key.uid, ev.key.service.as_str()), (1001, "shop"));
    let c2 = call("orders.nuke", &[]);
    let (o2, tr2) = run(&c2, &snap, &catalog(), &Limiter::new(), &FakeEnv::ok(), &up).await;
    assert!(limit_event(&record(&c2, &snap, &tr2, &o2, "", "0.2.0")).is_none());
}

#[tokio::test]
async fn param_echoing_the_token_is_masked_in_the_record() {
    let (_m, up) = mock().await;
    let snap = snapshot("");
    let c = call("files.get", &[("name", TOKEN)]);
    let (o, tr) = run(&c, &snap, &catalog(), &Limiter::new(), &FakeEnv::ok(), &up).await;
    let r = serde_json::to_string(&record(&c, &snap, &tr, &o, "", "0.2.0")).unwrap();
    assert!(!r.contains(TOKEN), "{r}");
}

/// The docs' outbound webhook: a fixed-URL POST with path `/`.
#[test]
fn webhook_operation_builds_the_fixed_url() {
    let svc: saiife_policy::ServiceCfg = toml::from_str(
        r#"connector = "http"
base_url = "https://hooks.example.com/services/T000/B000"
auth = { kind = "bearer" }
[[operation]]
id = "send"
capability = "hook:write"
kind = "write"
method = "POST"
path = "/"
body = "json"
"#,
    )
    .unwrap();
    let m = saiife_broker::manifest::from_http_service("deploy-hook", &svc).unwrap();
    let fields = [("token".to_string(), Zeroizing::new("tok-1234".to_string()))].into();
    let auth = AuthMaterial::from_spec(&m.auth[0], fields);
    let b = saiife_broker::request::build(
        &m,
        &m.operation[0],
        &Default::default(),
        &Default::default(),
        &[],
        Some(Bytes::from_static(b"{}")),
        &auth,
    )
    .unwrap();
    assert_eq!(
        b.uri.to_string(),
        "https://hooks.example.com/services/T000/B000/"
    );
}
