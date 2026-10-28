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
    limit_event, record, run, send_approved, ApprovalFuture, Call, Env, OpRef, Outcome,
    PendingCall, PolicySnapshot, Pools, Via,
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
        if host.ends_with(".echo.test") || host == "acme.myshopify.com" || host == "api.github.com"
        {
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
    let leaf = CertificateParams::new(vec![
        "acme.echo.test".to_string(),
        "acme.myshopify.com".to_string(),
        "api.github.com".to_string(),
    ])
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
    let up = Upstream::with_roots(roots, Arc::new(Loopback(port)), Duration::from_secs(2));
    (Mock { hits, seen }, up)
}

/// The fake daemon side.
struct FakeEnv {
    scope: Result<Option<Scope>, &'static str>,
    secret: Result<&'static str, &'static str>,
    pools: Pools,
    /// Replaces the per-service pool (a full or closed one).
    pool: Option<Arc<Semaphore>>,
    /// Every request step 8 stored; ids from 42.
    approvals: Mutex<Vec<PendingCall>>,
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
            pool: None,
            approvals: Mutex::new(Vec::new()),
        }
    }
}

impl Env for FakeEnv {
    fn lockdown(&self) -> Option<saiife_broker::pipeline::Lockdown> {
        None
    }
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
        self.pool.clone().unwrap_or_else(|| self.pools.get(service))
    }
    fn create_approval<'a>(&'a self, p: &'a PendingCall) -> ApprovalFuture<'a> {
        Box::pin(async move {
            let mut a = self.approvals.lock().unwrap();
            a.push(p.clone());
            Ok(41 + a.len() as u64)
        })
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
    let (o, tr) = run(&c, &snap, &catalog(), &Limiter::new(), &env, Some(&up)).await;
    assert_eq!(rule(&o), "no_scope");
    let r = serde_json::to_string(&record(&c, &snap, &tr, &o, "", "0.2.0")).unwrap();
    assert!(!r.contains(TOKEN), "{r}");
    assert!(r.contains("[MASKED]"), "{r}");
}

#[tokio::test]
async fn capability_qualifier_and_project_masked_in_the_record() {
    let (_m, up) = mock().await;
    // `files.get` with a qualifier filled from the agent's `name`.
    let text = include_str!("../connectors/test-echo.toml").replace(
        "path_params = { name = \"string\" }",
        "path_params = { name = \"string\" }\nqualifier = \"file={name}\"",
    );
    let cat = Catalog::new(&[], vec![Manifest::parse(&text).unwrap()]);
    let mut env = FakeEnv::ok();
    env.secret = Err("secret_missing");
    let snap = snapshot("");
    let mut c = call("files.get", &[("name", TOKEN)]);
    c.project = format!("/srv/{TOKEN}");
    let (o, tr) = run(&c, &snap, &cat, &Limiter::new(), &env, Some(&up)).await;
    assert_eq!(rule(&o), "secret_missing");
    assert_eq!(tr.capability.as_deref(), Some("files:read:file=[MASKED]"));
    let r = serde_json::to_string(&record(&c, &snap, &tr, &o, "", "0.2.0")).unwrap();
    assert!(!r.contains(TOKEN), "{r}");
    assert!(r.contains("/srv/[MASKED]"), "{r}");
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
        Some(&up),
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
        env: None,
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
    run(c, snap, &catalog(), lim, env, Some(up)).await.0
}

fn rule(o: &Outcome) -> &str {
    match o {
        Outcome::Denied { rule } => rule,
        other => panic!("expected a deny, got {other:?}"),
    }
}

#[tokio::test]
async fn incomplete_limiter_rebuild_denies_limits_unavailable() {
    let (m, up) = mock().await;
    let now = time::OffsetDateTime::now_utc();
    let lim = Limiter::rebuild_incomplete(std::iter::empty(), now);
    let o = go(
        &call("orders.list", &[]),
        &snapshot(""),
        &FakeEnv::ok(),
        &up,
        &lim,
    )
    .await;
    assert_eq!(rule(&o), "limits_unavailable");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
    // A full window later the limiter knows every event that counts.
    let old = Limiter::rebuild_incomplete(std::iter::empty(), now - time::Duration::days(1));
    let o = go(
        &call("orders.list", &[]),
        &snapshot(""),
        &FakeEnv::ok(),
        &up,
        &old,
    )
    .await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
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

fn refund_call(params: &[(&str, &str)]) -> Call {
    let mut c = call("refunds.create", params);
    // A duplicate-free body with spacing: what is stored is the canonical form.
    c.body = Some(Bytes::from_static(
        br#"{ "refund": {"currency":"EUR","transactions":[{"amount":"5.00"}]} }"#,
    ));
    c
}

#[tokio::test]
async fn ask_creates_pending_no_upstream_call() {
    let (m, up) = mock().await;
    let env = FakeEnv::ok();
    let snap = snapshot("");
    let c = refund_call(&[("order_id", "7")]);
    let (o, tr) = run(&c, &snap, &catalog(), &Limiter::new(), &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Pending { id: 42 }), "{o:?}");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
    let stored = env.approvals.lock().unwrap().pop().unwrap();
    assert_eq!(stored.stored.operation, "refunds.create");
    assert_eq!(stored.stored.uid, 1001);
    assert_eq!(stored.stored.via, "cli");
    assert_eq!(stored.capability.as_deref(), Some("refunds:write"));
    assert_eq!(stored.params.get()["order_id"], "7");
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD
        .decode(stored.stored.body_b64.as_deref().unwrap())
        .unwrap();
    assert_eq!(
        &body[..],
        br#"{"refund":{"currency":"EUR","transactions":[{"amount":"5.00"}]}}"#
    );
    // The connector record says ask, with the request's id.
    let r = serde_json::to_value(record(&c, &snap, &tr, &o, "", "0.2.0")).unwrap();
    assert_eq!(r["decision"], "ask");
    assert_eq!(r["approval"], 42);

    // The display copy is masked with the service's vault values.
    let mut c2 = call("files.get", &[("name", TOKEN)]);
    c2.project = format!("/srv/{TOKEN}");
    let mut snap2 = snapshot("");
    snap2.config.services.get_mut("shop").unwrap().ask = vec!["files:read".into()];
    snap2.config.services.get_mut("shop").unwrap().allow = vec![];
    let (o, _) = run(&c2, &snap2, &catalog(), &Limiter::new(), &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    let p = env.approvals.lock().unwrap().pop().unwrap();
    assert_eq!(p.params.get()["name"], "[MASKED]");
    assert_eq!(p.project, "/srv/[MASKED]");
    // The stored request keeps the exact value (it is sealed).
    assert_eq!(p.stored.params["name"], TOKEN);
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pending_display_shows_what_will_be_sent_masked() {
    let (m, up) = mock().await;
    let env = FakeEnv::ok();
    let mut c = call("refunds.create", &[("order_id", "7")]);
    // The padding attack: a large key that sorts first in the canonical
    // JSON must not push the fields that matter out of the display.
    let raw = format!(
        r#"{{"refund":{{"currency":"EUR","note":"plain","transactions":[{{"amount":"5.00"}}]}},"aaa":"{}"}}"#,
        "y".repeat(200_000)
    );
    c.body = Some(Bytes::from(raw.clone()));
    c.headers = vec![("X-Trace".into(), format!("t-{TOKEN}"))];
    let (o, tr) = run(
        &c,
        &snapshot(""),
        &catalog(),
        &Limiter::new(),
        &env,
        Some(&up),
    )
    .await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    let p = env.approvals.lock().unwrap().pop().unwrap();
    assert_eq!(p.amount, Some((500, "EUR".to_string())));
    assert_eq!(p.body_sha256, tr.body_sha256);
    let shown = p.body_display.unwrap();
    assert!(shown.contains(r#""note":"plain""#), "{shown}");
    // The whole body, in the canonical key order (whichever serde_json
    // gives in this build): the padding and every field after it.
    assert!(shown.contains(r#""aaa":"yyy"#));
    assert!(shown.contains(r#""transactions":[{"amount":"5.00"}]"#));
    assert!(!p.body_truncated);
    assert!(shown.len() > 200_000);
    assert_eq!(
        p.headers,
        vec![("X-Trace".to_string(), "t-[MASKED]".to_string())]
    );
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

/// A body the masker would change cannot be shown as it will be sent, so
/// it cannot be approved: a v1 pattern's `\S+` would swallow the JSON
/// after it (here the amount), and a vault value would be hidden.
#[tokio::test]
async fn ask_with_masked_body_refused_masked_content() {
    let (m, up) = mock().await;
    let env = FakeEnv::ok();
    let snap = snapshot("");
    for body in [
        r#"{"refund":{"currency":"EUR","note":"API_TOKEN=x","transactions":[{"amount":"5.00"}]}}"#
            .to_string(),
        format!(
            r#"{{"refund":{{"currency":"EUR","note":"{TOKEN}","transactions":[{{"amount":"5.00"}}]}}}}"#
        ),
    ] {
        let mut c = call("refunds.create", &[("order_id", "7")]);
        c.body = Some(Bytes::from(body));
        let (o, tr) = run(&c, &snap, &catalog(), &Limiter::new(), &env, Some(&up)).await;
        assert_eq!(rule(&o), "masked_content");
        let r = serde_json::to_value(record(&c, &snap, &tr, &o, "", "0.2.0")).unwrap();
        assert_eq!(r["decision"], "deny");
        assert_eq!(r["rule"], "masked_content");
        assert_eq!(
            r["reason"],
            "cannot be approved: the request contains masked content"
        );
        assert!(!r.to_string().contains(TOKEN));
    }
    // No request was created, nothing was sent.
    assert!(env.approvals.lock().unwrap().is_empty());
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);

    // A plain body is still approvable.
    let c = refund_call(&[("order_id", "7")]);
    let (o, _) = run(&c, &snap, &catalog(), &Limiter::new(), &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    assert_eq!(env.approvals.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn ask_over_limit_denied_at_creation() {
    let (m, up) = mock().await;
    let env = FakeEnv::ok();
    let snap = snapshot("[services.shop.limits]\nwrites_per_hour = 1\n");
    let lim = Limiter::new();
    let c = refund_call(&[("order_id", "7")]);
    // Asking reserves nothing: two requests can wait at once.
    for _ in 0..2 {
        let o = go(&c, &snap, &env, &up, &lim).await;
        assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    }
    let stored: Vec<_> = env
        .approvals
        .lock()
        .unwrap()
        .iter()
        .map(|p| p.stored.clone())
        .collect();
    // One write sent (allowed elsewhere) fills the hour.
    let (call, o, _) = send_approved(&stored[0], &snap, &catalog(), &lim, &env, Some(&up)).await;
    assert_eq!(call.via, Via::Approval);
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    assert_eq!(m.hits.load(Ordering::SeqCst), 1);
    // A request that could never be sent now is denied with its limit.
    let o = go(&c, &snap, &env, &up, &lim).await;
    assert!(
        matches!(
            o,
            Outcome::Limited {
                limit: "writes_per_hour"
            }
        ),
        "{o:?}"
    );
    assert_eq!(env.approvals.lock().unwrap().len(), 2);
    // At send the limit is checked for real: the second waits in vain.
    let (_, o, tr) = send_approved(&stored[1], &snap, &catalog(), &lim, &env, Some(&up)).await;
    assert!(
        matches!(
            o,
            Outcome::Limited {
                limit: "writes_per_hour"
            }
        ),
        "{o:?}"
    );
    assert!(!tr.sent);
    assert_eq!(m.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn approved_request_rechecked_against_the_policy_now() {
    let (m, up) = mock().await;
    let env = FakeEnv::ok();
    let lim = Limiter::new();
    let o = go(
        &refund_call(&[("order_id", "7")]),
        &snapshot(""),
        &env,
        &up,
        &lim,
    )
    .await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    let stored = env.approvals.lock().unwrap()[0].stored.clone();
    // Now denied: `policy_changed`, nothing sent.
    let mut now_deny = snapshot("");
    now_deny.config.services.get_mut("shop").unwrap().deny = vec!["refunds:*".into()];
    let (_, o, _) = send_approved(&stored, &now_deny, &catalog(), &lim, &env, Some(&up)).await;
    assert_eq!(rule(&o), "policy_changed");
    // Out of scope now: `policy_changed` too.
    let mut no_scope = FakeEnv::ok();
    no_scope.scope = Ok(None);
    let (_, o, _) = send_approved(
        &stored,
        &snapshot(""),
        &catalog(),
        &lim,
        &no_scope,
        Some(&up),
    )
    .await;
    assert_eq!(rule(&o), "policy_changed");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
    // Still `ask` (or now `allow`): sent, the stored body exactly.
    let (_, o, tr) = send_approved(&stored, &snapshot(""), &catalog(), &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    assert!(tr.sent);
    let seen = m.seen.lock().unwrap();
    assert_eq!(
        &seen[0].2[..],
        br#"{"refund":{"currency":"EUR","transactions":[{"amount":"5.00"}]}}"#
    );
}

/// The sealed request carries the hash of the body the approver saw; at
/// send the bytes about to go upstream must match it. A canonicalization
/// that changed between the ask and the send (the seam: stored bytes that
/// no longer canonicalize to the approved hash) is `body_changed`, and
/// nothing is sent.
#[tokio::test]
async fn approved_body_must_hash_to_what_was_shown() {
    use base64::Engine as _;
    let (m, up) = mock().await;
    let env = FakeEnv::ok();
    let lim = Limiter::new();
    let o = go(
        &refund_call(&[("order_id", "7")]),
        &snapshot(""),
        &env,
        &up,
        &lim,
    )
    .await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    let p = env.approvals.lock().unwrap()[0].clone();
    // The sealed copy holds the same hash the approver is shown.
    assert!(p.stored.body_sha256.is_some());
    assert_eq!(p.stored.body_sha256, p.body_sha256);

    // Same canonical bytes, other spelling: still the approved body.
    let mut spaced = p.stored.clone();
    spaced.body_b64 = Some(
        base64::engine::general_purpose::STANDARD
            .encode(br#"{ "refund" : {"currency":"EUR", "transactions":[{"amount":"5.00"}]} }"#),
    );
    // A canonicalizer that now writes other bytes for the stored body.
    let mut other = p.stored.clone();
    other.body_b64 = Some(
        base64::engine::general_purpose::STANDARD
            .encode(br#"{"refund":{"currency":"EUR","transactions":[{"amount":"500.00"}]}}"#),
    );
    let (_, o, tr) = send_approved(&other, &snapshot(""), &catalog(), &lim, &env, Some(&up)).await;
    assert_eq!(rule(&o), "body_changed");
    assert!(!tr.sent);
    // No hash on record but a body: not sent either (fail closed).
    let mut unhashed = p.stored.clone();
    unhashed.body_sha256 = None;
    let (_, o, _) =
        send_approved(&unhashed, &snapshot(""), &catalog(), &lim, &env, Some(&up)).await;
    assert_eq!(rule(&o), "body_changed");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);

    let (_, o, tr) = send_approved(&spaced, &snapshot(""), &catalog(), &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    assert!(tr.sent);
    assert_eq!(tr.body_sha256, p.body_sha256);
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
    let mut snap = snapshot("");
    snap.env = Some("prod".into());
    let c = call("orders.list", &[("status", "open"), ("limit", "50")]);
    let (o, tr) = run(
        &c,
        &snap,
        &catalog(),
        &Limiter::new(),
        &FakeEnv::ok(),
        Some(&up),
    )
    .await;
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
    let (o2, tr2) = run(
        &c2,
        &snap,
        &catalog(),
        &Limiter::new(),
        &FakeEnv::ok(),
        Some(&up),
    )
    .await;
    assert!(limit_event(&record(&c2, &snap, &tr2, &o2, "", "0.2.0")).is_none());
}

#[tokio::test]
async fn param_echoing_the_token_is_masked_in_the_record() {
    let (_m, up) = mock().await;
    let snap = snapshot("");
    let c = call("files.get", &[("name", TOKEN)]);
    let (o, tr) = run(
        &c,
        &snap,
        &catalog(),
        &Limiter::new(),
        &FakeEnv::ok(),
        Some(&up),
    )
    .await;
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

/// Fix round 1, I1: no upstream client still runs steps 3–8 first.
#[tokio::test]
async fn no_upstream_client_denies_after_the_earlier_steps() {
    let (m, _up) = mock().await;
    let snap = snapshot("");
    let mut env = FakeEnv::ok();
    env.scope = Ok(None);
    let c = call("orders.list", &[]);
    let (o, _) = run(&c, &snap, &catalog(), &Limiter::new(), &env, None).await;
    assert_eq!(rule(&o), "no_scope");
    let (o, tr) = run(&c, &snap, &catalog(), &Limiter::new(), &FakeEnv::ok(), None).await;
    assert_eq!(rule(&o), "upstream_unavailable");
    let v = serde_json::to_value(record(&c, &snap, &tr, &o, "", "0.2.0")).unwrap();
    assert_eq!(v["decision"], "deny");
    assert_eq!(v["capability"], "orders:read");
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

/// M1: the agent's operation id and proxy request are masked in the record.
#[tokio::test]
async fn operation_and_proxy_path_masked_in_the_record() {
    let (_m, up) = mock().await;
    let snap = snapshot("");
    let c = call(&format!("x{TOKEN}"), &[]);
    let (o, tr) = run(
        &c,
        &snap,
        &catalog(),
        &Limiter::new(),
        &FakeEnv::ok(),
        Some(&up),
    )
    .await;
    assert_eq!(rule(&o), "unknown_operation");
    let r = serde_json::to_string(&record(&c, &snap, &tr, &o, "", "0.2.0")).unwrap();
    assert!(!r.contains(TOKEN), "{r}");
    let mut c = call("x", &[]);
    c.op = OpRef::Proxy {
        method: "GET".into(),
        path: format!("/nothing/{TOKEN}"),
    };
    let (o, tr) = run(
        &c,
        &snap,
        &catalog(),
        &Limiter::new(),
        &FakeEnv::ok(),
        Some(&up),
    )
    .await;
    assert_eq!(rule(&o), "unknown_operation");
    let v = serde_json::to_value(record(&c, &snap, &tr, &o, "", "0.2.0")).unwrap();
    assert!(!v.to_string().contains(TOKEN), "{v}");
    assert_eq!(v["input"], "shop GET /nothing/[MASKED]");
}

/// M2: the body hash and size are of the canonical bytes sent.
#[tokio::test]
async fn body_hash_is_of_the_bytes_sent() {
    use sha2::Digest as _;
    let (m, up) = mock().await;
    let mut c = call("refunds.create", &[("order_id", "7")]);
    c.body = Some(Bytes::from_static(
        b"{ \"refund\" : { \"currency\":\"EUR\", \"transactions\":[{\"amount\":\"5.00\"}]}}",
    ));
    let (o, tr) = run(
        &c,
        &refunds_allowed(),
        &catalog(),
        &Limiter::new(),
        &FakeEnv::ok(),
        Some(&up),
    )
    .await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    let seen = m.seen.lock().unwrap();
    let sent = &seen[0].2;
    assert_eq!(tr.body_bytes, sent.len());
    let hex: String = sha2::Sha256::digest(sent)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(tr.body_sha256.as_deref(), Some(hex.as_str()));
}

/// M4 and M5: a full pool is the `concurrency` limit after a bounded wait;
/// a closed one fails closed. Nothing is sent either way.
#[tokio::test]
async fn full_pool_is_a_limit_and_closed_pool_fails_closed() {
    let (m, up) = mock().await;
    let mut env = FakeEnv::ok();
    env.pool = Some(Arc::new(Semaphore::new(0)));
    let started = std::time::Instant::now();
    let o = go(
        &call("orders.list", &[]),
        &snapshot(""),
        &env,
        &up,
        &Limiter::new(),
    )
    .await;
    assert!(
        matches!(
            o,
            Outcome::Limited {
                limit: "concurrency"
            }
        ),
        "{o:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(4));
    let closed = Arc::new(Semaphore::new(1));
    closed.close();
    env.pool = Some(closed);
    let c = call("orders.list", &[]);
    let snap = snapshot("");
    let (o, tr) = run(&c, &snap, &catalog(), &Limiter::new(), &env, Some(&up)).await;
    // A deny: nothing was sent, so the record does not count at a rebuild.
    assert_eq!(rule(&o), "upstream_unavailable");
    assert!(!tr.sent);
    let r = record(&c, &snap, &tr, &o, "", "0.2.0");
    assert_eq!(
        serde_json::to_value(&r).unwrap()["decision"],
        serde_json::json!("deny")
    );
    assert!(saiife_broker::pipeline::limit_event(&r).is_none());
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}

// ------------------------------------------------- built-in connectors

fn builtin_catalog() -> Catalog {
    Catalog::new(saiife_broker::builtin(), vec![])
}

fn snap_of(text: &str) -> PolicySnapshot {
    PolicySnapshot {
        config: toml::from_str(&format!("version = 2\nlocked = true\n{text}")).unwrap(),
        hash: "sha256:test".into(),
        mode: Mode::Locked,
        env: None,
    }
}

fn env_for(service: &str) -> FakeEnv {
    let mut env = FakeEnv::ok();
    if let Ok(Some(s)) = &mut env.scope {
        s.services = vec![service.into()];
    }
    env
}

fn named_call(service: &str, op: &str, params: &[(&str, &str)], body: Option<&str>) -> Call {
    let mut c = call(op, params);
    c.service = service.into();
    c.body = body.map(|b| Bytes::from(b.to_string()));
    c
}

/// Shopify refunds under `amount_per_day = 500 EUR`: 200 and 250 go
/// through, the next 100 would make 550 and is denied before sending.
#[tokio::test]
async fn refund_amount_cap_end_to_end() {
    let (m, up) = mock().await;
    let snap = snap_of(
        r#"[services.shop]
connector = "shopify"
secret = "shop-tok"
params = { shop = "acme" }
allow = ["refunds:write"]
[services.shop.limits]
amount_per_day = { max = 500, currency = "EUR" }
"#,
    );
    let (cat, lim, env) = (builtin_catalog(), Limiter::new(), env_for("shop"));
    let refund = |amount: &str| {
        named_call(
            "shop",
            "refunds.create",
            &[("order_id", "450789469")],
            Some(&format!(
                r#"{{"refund":{{"currency":"EUR","transactions":[{{"amount":"{amount}"}}]}}}}"#
            )),
        )
    };
    for a in ["200.00", "250.00"] {
        let (o, tr) = run(&refund(a), &snap, &cat, &lim, &env, Some(&up)).await;
        assert!(matches!(o, Outcome::Done { .. }), "{a}: {o:?}");
        assert!(tr.sent);
    }
    let (o, tr) = run(&refund("100.00"), &snap, &cat, &lim, &env, Some(&up)).await;
    assert!(
        matches!(
            o,
            Outcome::Limited {
                limit: "amount_per_day"
            }
        ),
        "{o:?}"
    );
    assert_eq!(tr.amount, Some((10_000, "EUR".to_string())));
    assert_eq!(m.hits.load(Ordering::SeqCst), 2);
    let seen = m.seen.lock().unwrap();
    assert_eq!(
        seen[0].0,
        "/admin/api/2026-07/orders/450789469/refunds.json"
    );
    assert_eq!(seen[0].1["x-shopify-access-token"], TOKEN);
}

/// GitHub `issues:write:repo=acme/*`: the qualifier from the manifest is
/// filled from the path parameters and decides the call.
#[tokio::test]
async fn qualifier_policy_end_to_end() {
    let (m, up) = mock().await;
    let snap = snap_of(
        r#"[services.gh]
connector = "github"
secret = "gh-tok"
allow = ["issues:write:repo=acme/*"]
"#,
    );
    let (cat, lim, env) = (builtin_catalog(), Limiter::new(), env_for("gh"));
    let issue = |owner: &str| {
        named_call(
            "gh",
            "issues.create",
            &[("owner", owner), ("repo", "web")],
            Some(r#"{"title":"t"}"#),
        )
    };
    let (o, tr) = run(&issue("acme"), &snap, &cat, &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    assert_eq!(tr.capability.as_deref(), Some("issues:write:repo=acme/web"));
    let (o, tr) = run(&issue("other"), &snap, &cat, &lim, &env, Some(&up)).await;
    assert_eq!(rule(&o), "default_deny");
    assert_eq!(
        tr.capability.as_deref(),
        Some("issues:write:repo=other/web")
    );
    assert_eq!(m.hits.load(Ordering::SeqCst), 1);
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen[0].0, "/repos/acme/web/issues");
    assert_eq!(seen[0].1["authorization"], format!("Bearer {TOKEN}"));
}

/// `saiife policy test` (`judge`) and the real pipeline reach the same
/// verdict and deny rule for the same call.
#[tokio::test]
async fn judge_and_pipeline_agree() {
    use saiife_broker::judge::judge;
    use saiife_policy::decide::Verdict;
    let (_m, up) = mock().await;
    let extra = "deny = [\"files:read\"]\n[[services.shop.rule]]\ncapability = \"orders:read\"\nwhen = { order_id = \"9\" }\naction = \"ask\"";
    let snap = snapshot(extra);
    let cat = catalog();
    let scope = FakeEnv::ok().scope.unwrap().unwrap();
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("orders.list", vec![]),
        ("orders.get", vec![("order_id", "5")]),
        ("orders.get", vec![("order_id", "9")]),
        ("orders.get", vec![("order_id", "abc")]),
        ("orders.get", vec![]),
        ("files.get", vec![("name", "x")]),
        ("orders.list", vec![("bogus", "1")]),
    ];
    for (op, params) in cases {
        let c = call(op, &params);
        let o = go(&c, &snap, &FakeEnv::ok(), &up, &Limiter::new()).await;
        let want = match o {
            Outcome::Done { .. } => Verdict::Allow,
            Outcome::Pending { .. } => Verdict::Ask,
            Outcome::Denied { rule } => Verdict::Deny { rule },
            other => panic!("{op}: {other:?}"),
        };
        let got = judge(&snap.config, &cat, Ok(Some(&scope)), "shop", op, &c.params).unwrap();
        assert_eq!(got, want, "{op} {params:?}");
    }
    // No scope.
    let mut env = FakeEnv::ok();
    env.scope = Ok(None);
    let c = call("orders.list", &[]);
    let o = go(&c, &snap, &env, &up, &Limiter::new()).await;
    assert_eq!(rule(&o), "no_scope");
    let got = judge(
        &snap.config,
        &cat,
        Ok(None),
        "shop",
        "orders.list",
        &c.params,
    )
    .unwrap();
    assert_eq!(
        got,
        Verdict::Deny {
            rule: "no_scope".into()
        }
    );
}

/// A form connector on the loopback host: a built refund body (with an
/// amount from the admin's currency) and a raw form body.
fn form_manifest(source: &str) -> Manifest {
    Manifest::parse(&format!(
        r#"
id = "test-form"
version = 1
title = "Test form"
base_url = "https://{{shop}}.echo.test/api"
hosts = ["*.echo.test"]
auth = [{{ kind = "header", name = "X-Echo-Token", secret_field = "token" }}]

[params.shop]
type = "string"
pattern = "^[a-z0-9-]+$"
required = true

[params.currency]
type = "string"

[[operation]]
id = "refunds.create"
capability = "refunds:write"
kind = "write"
method = "POST"
path = "/refunds"
body = "form"
body_params = {{ charge = "string", amount = "int:1.." }}
body_const = {{ "metadata.source" = "{source}" }}
amount = {{ field = "amount", currency_param = "currency", unit = "minor" }}

[[operation]]
id = "charges.create"
capability = "charges:write"
kind = "write"
method = "POST"
path = "/charges"
body = "form"
"#
    ))
    .unwrap()
}

fn form_snap() -> PolicySnapshot {
    snap_of(
        r#"[services.pay]
connector = "test-form"
secret = "pay-tok"
params = { shop = "acme", currency = "EUR" }
ask = ["refunds:write", "charges:write"]
"#,
    )
}

fn form_catalog(source: &str) -> Catalog {
    Catalog::new(&[], vec![form_manifest(source)])
}

#[tokio::test]
async fn approved_form_and_built_bodies_are_sent() {
    let (m, up) = mock().await;
    let (snap, cat, lim, env) = (
        form_snap(),
        form_catalog("saiife"),
        Limiter::new(),
        env_for("pay"),
    );
    // A built body: nothing of the agent's is stored, the params rebuild it.
    let c = named_call(
        "pay",
        "refunds.create",
        &[("charge", "ch_1"), ("amount", "1250")],
        None,
    );
    let (o, _) = run(&c, &snap, &cat, &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    let p = env.approvals.lock().unwrap()[0].clone();
    assert_eq!(p.stored.body_b64, None);
    assert_eq!(p.amount, Some((1250, "EUR".to_string())));
    assert_eq!(
        p.body_display.as_deref(),
        Some("amount=1250&charge=ch_1&metadata%5Bsource%5D=saiife")
    );
    let (_, o, tr) = send_approved(&p.stored, &snap, &cat, &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    assert!(tr.sent);
    assert_eq!(tr.body_sha256, p.body_sha256);
    {
        let seen = m.seen.lock().unwrap();
        let (_, h, body) = seen.last().unwrap();
        assert_eq!(
            &body[..],
            b"amount=1250&charge=ch_1&metadata%5Bsource%5D=saiife"
        );
        assert_eq!(
            h.get("content-type").unwrap(),
            "application/x-www-form-urlencoded"
        );
    }
    // A raw agent body on a form op: stored as canonical JSON, sent encoded.
    let c = named_call(
        "pay",
        "charges.create",
        &[],
        Some(r#"{ "b": 2, "a": {"x": "y"} }"#),
    );
    let (o, _) = run(&c, &snap, &cat, &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    let p = env.approvals.lock().unwrap()[1].clone();
    assert!(p.stored.body_b64.is_some());
    let (_, o, tr) = send_approved(&p.stored, &snap, &cat, &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Done { .. }), "{o:?}");
    assert_eq!(tr.body_sha256, p.body_sha256);
    let seen = m.seen.lock().unwrap();
    assert_eq!(&seen.last().unwrap().2[..], b"a%5Bx%5D=y&b=2");
    assert_eq!(m.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn manifest_change_between_ask_and_send_is_body_changed() {
    let (m, up) = mock().await;
    let (snap, lim, env) = (form_snap(), Limiter::new(), env_for("pay"));
    let c = named_call(
        "pay",
        "refunds.create",
        &[("charge", "ch_1"), ("amount", "1250")],
        None,
    );
    let (o, _) = run(&c, &snap, &form_catalog("saiife"), &lim, &env, Some(&up)).await;
    assert!(matches!(o, Outcome::Pending { .. }), "{o:?}");
    let p = env.approvals.lock().unwrap()[0].clone();
    // The admin changed a body constant before the approval was sent: the
    // rebuilt bytes are not what the approver saw.
    let changed = form_catalog("other");
    let (_, o, tr) = send_approved(&p.stored, &snap, &changed, &lim, &env, Some(&up)).await;
    assert_eq!(rule(&o), "body_changed");
    assert!(!tr.sent);
    assert_eq!(m.hits.load(Ordering::SeqCst), 0);
}
