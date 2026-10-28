//! WooCommerce refunds through the whole pipeline against a loopback TLS mock
//! (plan 14, Task 11 fix round). Nothing leaves 127.0.0.1.

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::limits::Limiter;
use saiife_broker::manifest::{builtin, AuthSpec};
use saiife_broker::pipeline::{
    record, run, ApprovalFuture, Call, Env, Lockdown, OpRef, Outcome, PendingCall, PolicySnapshot,
    Pools, Via,
};
use saiife_broker::request::AuthMaterial;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::Catalog;
use saiife_policy::{Mode, PolicyError, Scope};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

// Built at runtime: no key-shaped literal in the source.
fn ck() -> String {
    ["ck", "consumer", "e2e1"].join("_")
}
fn cs() -> String {
    ["cs", "secret", "e2e2"].join("_")
}

type Seen = Arc<Mutex<Vec<(String, HeaderMap, Bytes)>>>;

struct Loopback(u16);

impl Resolver for Loopback {
    fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        if host == "shop.acme.test" {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, self.0))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

async fn answer(
    req: Request<Incoming>,
    hits: Arc<AtomicUsize>,
    seen: Seen,
) -> Result<Response<Full<Bytes>>, Infallible> {
    hits.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    seen.lock()
        .unwrap()
        .push((parts.uri.to_string(), parts.headers.clone(), body));
    Ok(Response::builder()
        .status(201)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(
            r#"{"id":726,"amount":"10.00","reason":"Wrong size","refunded_by":1}"#,
        )))
        .unwrap())
}

async fn mock() -> (Arc<AtomicUsize>, Seen, Upstream) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["shop.acme.test".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let hits = Arc::new(AtomicUsize::new(0));
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
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
    let up = Upstream::with_roots(roots, Arc::new(Loopback(port)), Duration::from_secs(2));
    (hits, seen, up)
}

struct FakeEnv {
    pools: Pools,
}

impl Env for FakeEnv {
    fn lockdown(&self) -> Option<Lockdown> {
        None
    }
    fn scope(&self, _user: &str) -> Result<Option<Scope>, PolicyError> {
        Ok(Some(Scope {
            name: "shop-agents".into(),
            users: vec!["agent".into()],
            projects: vec![],
            services: vec!["woo".into()],
            env: None,
        }))
    }
    fn secret(
        &self,
        _name: &str,
        _service: &str,
        auth: &[AuthSpec],
    ) -> Result<AuthMaterial, &'static str> {
        Ok(AuthMaterial::from_spec(
            &auth[0],
            BTreeMap::from([
                ("username".to_string(), Zeroizing::new(ck())),
                ("password".to_string(), Zeroizing::new(cs())),
            ]),
        ))
    }
    fn secret_values(&self, _name: &str) -> Option<Vec<Zeroizing<String>>> {
        Some(vec![Zeroizing::new(ck()), Zeroizing::new(cs())])
    }
    fn pool(&self, service: &str) -> Arc<Semaphore> {
        self.pools.get(service)
    }
    fn create_approval<'a>(&'a self, _p: &'a PendingCall) -> ApprovalFuture<'a> {
        Box::pin(async { Err("approvals_unavailable".to_string()) })
    }
}

fn snapshot() -> PolicySnapshot {
    let config = toml::from_str(
        r#"version = 2
locked = true
[services.woo]
connector = "woocommerce"
secret = "woo-prod"
params = { host = "shop.acme.test", currency = "EUR" }
allow = ["orders:read", "refunds:write"]
"#,
    )
    .unwrap();
    PolicySnapshot {
        config,
        hash: "sha256:test".into(),
        mode: Mode::Locked,
        env: None,
    }
}

fn call(op: &str, params: &[(&str, &str)], body: Option<&str>) -> Call {
    Call {
        uid: 1001,
        user: "agent".into(),
        session: Some("sess-1".into()),
        project: "/srv/shop".into(),
        service: "woo".into(),
        op: OpRef::Named(op.into()),
        params: params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: body.map(|b| Bytes::from(b.to_string())),
        headers: vec![("Authorization".into(), "Bearer agent-guess".into())],
        overlay: None,
        via: Via::Cli,
    }
}

/// The outcome, and everything printable about the call: its audit record,
/// the outcome and the call's `Debug`.
async fn go(c: &Call, up: &Upstream) -> (Outcome, String) {
    let snap = snapshot();
    let cat = Catalog::new(builtin(), Vec::new());
    let env = FakeEnv {
        pools: Pools::new(),
    };
    let (o, tr) = run(c, &snap, &cat, &Limiter::new(), &env, Some(up)).await;
    let out = format!(
        "{}\n{o:?}\n{c:?}",
        serde_json::to_string(&record(c, &snap, &tr, &o, "", "0.2.0")).unwrap()
    );
    (o, out)
}

fn deny_rule(o: &Outcome) -> &str {
    match o {
        Outcome::Denied { rule } => rule,
        other => panic!("expected a deny, got {other:?}"),
    }
}

#[tokio::test]
async fn refund_end_to_end() {
    let (hits, seen, up) = mock().await;
    let mut printed = String::new();

    // No amount: denied bad_amount, nothing sent.
    for params in [
        vec![("order_id", "727")],
        vec![("order_id", "727"), ("reason", "no amount")],
    ] {
        let (o, out) = go(&call("refunds.create", &params, None), &up).await;
        assert_eq!(deny_rule(&o), "bad_amount");
        printed.push_str(&out);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // A raw agent body is refused: the body is built from params.
    let raw = r#"{"amount":"5.00","line_items":[{"id":1,"refund_total":"5.00"}],"meta_data":[]}"#;
    let (o, out) = go(
        &call("refunds.create", &[("order_id", "727")], Some(raw)),
        &up,
    )
    .await;
    assert!(matches!(o, Outcome::Denied { .. }), "{o:?}");
    printed.push_str(&out);
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // A normal refund reaches the mock with the Basic header.
    let (o, out) = go(
        &call(
            "refunds.create",
            &[
                ("order_id", "727"),
                ("amount", "10.00"),
                ("reason", "Wrong size"),
            ],
            None,
        ),
        &up,
    )
    .await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    printed.push_str(&out);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let pair = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", ck(), cs()));
    {
        let seen = seen.lock().unwrap();
        let (uri, headers, body) = &seen[0];
        assert!(uri.ends_with("/wp-json/wc/v3/orders/727/refunds"), "{uri}");
        assert_eq!(headers["authorization"], format!("Basic {pair}").as_str());
        let sent: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(
            sent,
            json!({"amount": "10.00", "reason": "Wrong size", "api_refund": false})
        );
    }

    // Neither the consumer key, the secret nor the Basic pair was printed.
    for needle in [ck(), cs(), pair] {
        assert!(!printed.contains(&needle), "leaked {needle}");
    }
}
