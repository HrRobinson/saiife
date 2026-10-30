//! The notifier end to end against loopback mocks: a TLS webhook (hyper), an
//! SMTP server speaking just enough protocol (implicit TLS, STARTTLS, and a
//! plain one that must be refused) and local command targets. Certificates
//! come from `rcgen`; nothing leaves 127.0.0.1.
#![cfg(unix)]

use base64::Engine as _;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_audit::{DecisionKind, NewRecord, Record};
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_daemon::notifier::{Env, Notifier, NotifyEvent, Secret};
use saiife_daemon::vault::Kind;
use saiife_policy::{Event, NotifyCfg};
use serde_json::Value;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const HOOK_HOST: &str = "hooks.example.test";
const MAIL_HOST: &str = "mail.example.test";
const HOOK_SECRET: &str = "SECRETPATHTOKEN9";
const SMTP_PASS: &str = "hunter2-smtp-pw";

struct Loopback;

impl Resolver for Loopback {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if host == HOOK_HOST || host == MAIL_HOST {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

struct Pki {
    ca: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

fn pki() -> Pki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![HOOK_HOST.to_string(), MAIL_HOST.to_string()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    Pki {
        ca: ca.der().clone(),
        leaf: leaf.der().clone(),
        key: PrivatePkcs8KeyDer::from(key.serialize_der()),
    }
}

/// `alpn` is what the server accepts; a client offering anything else (and
/// offering some) is refused with a `no_application_protocol` alert.
fn acceptor(p: &Pki, alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![p.leaf.clone()],
        PrivateKeyDer::Pkcs8(p.key.clone_key()),
    )
    .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

// ------------------------------------------------------------------ env

type Plain = (Kind, BTreeMap<String, String>);

struct TestEnv {
    cfg: Mutex<NotifyCfg>,
    secrets: Mutex<BTreeMap<String, Plain>>,
    up: Upstream,
    records: Mutex<Vec<Record>>,
}

impl Env for TestEnv {
    fn cfg(&self) -> NotifyCfg {
        self.cfg.lock().unwrap().clone()
    }
    fn secret(&self, name: &str) -> Option<Secret> {
        let g = self.secrets.lock().unwrap();
        let (kind, f) = g.get(name)?;
        Some(Secret {
            kind: *kind,
            fields: f
                .iter()
                .map(|(k, v)| (k.clone(), Zeroizing::new(v.clone())))
                .collect(),
        })
    }
    fn upstream(&self) -> Result<&Upstream, String> {
        Ok(&self.up)
    }
    fn new_record(&self, input: &str) -> Record {
        let mut r = Record::new(
            NewRecord {
                agent: "",
                project: "",
                session: None,
                tool: "notify",
                input,
                decision: DecisionKind::Allow,
                pack: None,
                rule: None,
                reason: None,
                mode: "locked",
                policy: None,
                permission_mode: None,
            },
            "test",
        );
        r.kind = Some("notify".into());
        r
    }
    fn append(&self, rec: Record) {
        self.records.lock().unwrap().push(rec);
    }
}

struct World {
    env: Arc<TestEnv>,
    pki: Pki,
}

fn world(cfg_toml: impl FnOnce(&Pki) -> String, p: Pki) -> World {
    let mut roots = RootCertStore::empty();
    roots.add(p.ca.clone()).unwrap();
    let up = Upstream::with_roots(roots, Arc::new(Loopback), Duration::from_secs(10));
    let cfg: NotifyCfg = toml::from_str::<toml::Table>(&cfg_toml(&p))
        .map(|t| t.try_into().unwrap())
        .unwrap();
    cfg.validate().unwrap();
    let mut secrets = BTreeMap::new();
    secrets.insert(
        "smtp-login".to_string(),
        (
            Kind::Basic,
            BTreeMap::from([
                ("username".to_string(), "mailer".to_string()),
                ("password".to_string(), SMTP_PASS.to_string()),
            ]),
        ),
    );
    World {
        env: Arc::new(TestEnv {
            cfg: Mutex::new(cfg),
            secrets: Mutex::new(secrets),
            up,
            records: Mutex::new(Vec::new()),
        }),
        pki: p,
    }
}

impl World {
    fn add_secret(&self, name: &str, kind: Kind, k: &str, v: &str) {
        self.env.secrets.lock().unwrap().insert(
            name.into(),
            (kind, BTreeMap::from([(k.to_string(), v.to_string())])),
        );
    }

    fn records(&self) -> Vec<Value> {
        self.env
            .records
            .lock()
            .unwrap()
            .iter()
            .map(|r| serde_json::to_value(r).unwrap())
            .collect()
    }

    /// Waits until `n` records satisfy `f`.
    async fn wait(&self, n: usize, f: impl Fn(&Value) -> bool) -> Vec<Value> {
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            let got: Vec<Value> = self.records().into_iter().filter(|r| f(r)).collect();
            if got.len() >= n || Instant::now() > end {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn result_is(r: &Value, res: &str) -> bool {
    r["kind"] == "notify" && r["result"] == res
}

fn ev(event: Event, id: u64, summary: &str) -> NotifyEvent {
    NotifyEvent {
        event,
        id: Some(id),
        service: Some("shop".into()),
        operation: Some("orders.refund".into()),
        uid: Some(1001),
        host: "box1".into(),
        summary: summary.into(),
        reason: None,
    }
}

// -------------------------------------------------------------- webhook

#[derive(Default)]
struct Hook {
    /// (path, content-type, body)
    seen: Mutex<Vec<(String, String, String)>>,
}

async fn hook_handle(
    req: Request<Incoming>,
    port: u16,
    h: Arc<Hook>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let path = parts.uri.path().to_string();
    h.seen.lock().unwrap().push((
        path.clone(),
        parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        String::from_utf8_lossy(&body).into_owned(),
    ));
    let resp = match path.as_str() {
        "/redirect" => Response::builder()
            .status(307)
            .header("location", format!("https://{HOOK_HOST}:{port}/elsewhere"))
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/slow" => {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Response::new(Full::new(Bytes::new()))
        }
        "/four" => Response::builder()
            .status(404)
            .body(Full::new(Bytes::new()))
            .unwrap(),
        "/five" => Response::builder()
            .status(503)
            .body(Full::new(Bytes::new()))
            .unwrap(),
        _ => Response::new(Full::new(Bytes::from_static(b"ok"))),
    };
    Ok(resp)
}

async fn hook_server(p: &Pki) -> (u16, Arc<Hook>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acc = acceptor(p, &[b"http/1.1"]);
    let hook = Arc::new(Hook::default());
    let h2 = hook.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acc, h) = (acc.clone(), h2.clone());
            tokio::spawn(async move {
                let Ok(tls) = acc.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |r| hook_handle(r, port, h.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, hook)
}

fn webhook_world(port_of: u16, path: &str, p: Pki) -> World {
    world(
        |_| {
            format!(
                "[targets.ops]\ntype = \"webhook\"\nurl_secret = \"hook-url\"\n\
                 [targets.direct]\ntype = \"webhook\"\nurl = \"https://{HOOK_HOST}:{port_of}{path}/direct\"\n"
            )
        },
        p,
    )
}

#[tokio::test]
async fn webhook_posts_masked_payload_no_secret() {
    let p = pki();
    let (port, hook) = hook_server(&p).await;
    let w = webhook_world(port, "/hook", p);
    w.add_secret(
        "hook-url",
        Kind::Token,
        "token",
        &format!("https://{HOOK_HOST}:{port}/hook/{HOOK_SECRET}"),
    );
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    let gh = format!("ghp_{}", "a".repeat(36));
    n.send(ev(
        Event::ApprovalCreated,
        7,
        &format!("refund needs approval token {gh}"),
    ));
    let sent = w.wait(2, |r| result_is(r, "sent")).await;
    assert_eq!(sent.len(), 2, "{:?}", w.records());
    let seen = hook.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    for (_, ct, body) in &seen {
        assert_eq!(ct, "application/json");
        assert!(!body.contains(&gh), "{body}");
        assert!(!body.contains(HOOK_SECRET), "{body}");
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["event"], "approval_created");
        assert_eq!(v["id"], 7);
        assert_eq!(v["service"], "shop");
        assert_eq!(v["operation"], "orders.refund");
        assert_eq!(v["uid"], 1001);
        assert_eq!(v["host"], "box1");
        assert!(v["summary"].as_str().unwrap().contains("[MASKED]"));
    }
    assert!(seen
        .iter()
        .any(|(p, _, _)| p == &format!("/hook/{HOOK_SECRET}")));
    // No record carries the secret URL.
    let all = serde_json::to_string(&w.records()).unwrap();
    assert!(!all.contains(HOOK_SECRET) && !all.contains(&gh), "{all}");
    let targets: Vec<String> = sent
        .iter()
        .map(|r| r["target"].as_str().unwrap().to_string())
        .collect();
    assert!(targets.contains(&"ops".to_string()) && targets.contains(&"direct".to_string()));
    let _ = &w.pki;
}

#[tokio::test]
async fn webhook_redirect_not_followed() {
    let p = pki();
    let (port, hook) = hook_server(&p).await;
    let w = world(
        |_| {
            format!(
                "[targets.r]\ntype = \"webhook\"\nurl = \"https://{HOOK_HOST}:{port}/redirect\"\n"
            )
        },
        p,
    );
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    n.send(ev(Event::ApprovalCreated, 1, "x"));
    let failed = w.wait(1, |r| result_is(r, "failed")).await;
    assert_eq!(failed.len(), 1, "{:?}", w.records());
    assert!(
        hook.seen
            .lock()
            .unwrap()
            .iter()
            .all(|(p, _, _)| p == "/redirect"),
        "a redirect was followed"
    );
    // Permanent: no second attempt.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(hook.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn permanent_failures_are_not_retried_server_errors_are() {
    let p = pki();
    let (port, hook) = hook_server(&p).await;
    let w = world(
        |_| {
            format!(
                "[targets.four]\ntype = \"webhook\"\nurl = \"https://{HOOK_HOST}:{port}/four\"\n\
                 [targets.five]\ntype = \"webhook\"\nurl = \"https://{HOOK_HOST}:{port}/five\"\n"
            )
        },
        p,
    );
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    n.send(ev(Event::ApprovalCreated, 1, "x"));
    let failed = w.wait(2, |r| result_is(r, "failed")).await;
    assert_eq!(failed.len(), 2, "{:?}", w.records());
    let count = |path: &str| {
        hook.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _, _)| p == path)
            .count()
    };
    assert_eq!(count("/four"), 1, "a 4xx was retried");
    assert_eq!(count("/five"), 2, "a 5xx gets one retry");
}

#[tokio::test]
async fn dead_target_does_not_stall_the_others() {
    let p = pki();
    let (port, hook) = hook_server(&p).await;
    let w = world(
        |_| {
            format!(
                "[targets.a]\ntype = \"webhook\"\nurl = \"https://{HOOK_HOST}:{port}/slow\"\n\
                 [targets.b]\ntype = \"webhook\"\nurl = \"https://{HOOK_HOST}:{port}/b\"\n"
            )
        },
        p,
    );
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    let t = Instant::now();
    n.send(ev(Event::ApprovalCreated, 1, "first"));
    n.send(ev(Event::ApprovalCreated, 2, "second"));
    let sent = w
        .wait(2, |r| result_is(r, "sent") && r["target"] == "b")
        .await;
    assert_eq!(sent.len(), 2, "{:?}", w.records());
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "b waited {:?}",
        t.elapsed()
    );
    // `a` is still stuck on its first event: nothing of it has finished.
    assert!(w.records().iter().all(|r| r["target"] != "a"));
    let _ = hook;
}

#[tokio::test]
async fn slow_target_does_not_block_send() {
    let p = pki();
    let (port, _hook) = hook_server(&p).await;
    let w = world(
        |_| format!("[targets.s]\ntype = \"webhook\"\nurl = \"https://{HOOK_HOST}:{port}/slow\"\n"),
        p,
    );
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    let t = Instant::now();
    for i in 0..20 {
        n.send(ev(Event::ApprovalCreated, i, "slow"));
    }
    assert!(
        t.elapsed() < Duration::from_millis(10),
        "send blocked for {:?}",
        t.elapsed()
    );
}

#[tokio::test]
async fn queue_full_drops_oldest_and_records() {
    let p = pki();
    let (port, hook) = hook_server(&p).await;
    let w = world(
        |_| format!("[targets.q]\ntype = \"webhook\"\nurl = \"https://{HOOK_HOST}:{port}/q\"\n"),
        p,
    );
    let n = Notifier::new();
    // Delivery has not started: the queue fills and drops its oldest.
    for i in 0..300 {
        n.send(ev(Event::ApprovalCreated, i, "q"));
    }
    assert_eq!(n.queued(), 256);
    assert_eq!(n.dropped(), 44);
    n.start(Arc::downgrade(&w.env));
    let sent = w.wait(256, |r| result_is(r, "sent")).await;
    assert_eq!(sent.len(), 256);
    let dropped = w.wait(1, |r| result_is(r, "dropped")).await;
    assert_eq!(dropped.len(), 1, "{:?}", w.records());
    assert_eq!(dropped[0]["reason"], "queue_full");
    assert_eq!(dropped[0]["count"], 44);
    assert_eq!(dropped[0]["event"], "approval_created");
    // Delivered in order, oldest 44 gone.
    let ids: Vec<u64> = hook
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, b)| {
            serde_json::from_str::<Value>(b).unwrap()["id"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(ids, (44..300).collect::<Vec<u64>>());
}

#[tokio::test]
async fn rate_limit_per_kind_except_approval_created() {
    let p = pki();
    let (port, hook) = hook_server(&p).await;
    let w = world(
        |_| format!("[targets.r]\ntype = \"webhook\"\nurl = \"https://{HOOK_HOST}:{port}/r\"\n"),
        p,
    );
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    for i in 0..3 {
        n.send(ev(Event::LimitReached, i, "limit"));
        n.send(ev(Event::ApprovalCreated, 10 + i, "ask"));
    }
    n.send(ev(
        Event::Lockdown,
        20,
        "other kind is not limited by limit_reached",
    ));
    let sent = w.wait(5, |r| result_is(r, "sent")).await;
    let dropped = w.wait(2, |r| result_is(r, "dropped")).await;
    assert_eq!(sent.len(), 5, "{:?}", w.records());
    assert_eq!(dropped.len(), 2);
    assert!(dropped
        .iter()
        .all(|r| r["reason"] == "rate_limited" && r["event"] == "limit_reached"));
    assert_eq!(hook.seen.lock().unwrap().len(), 5);
}

// ----------------------------------------------------------------- smtp

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Implicit,
    /// Implicit TLS, and AUTH is answered 535 with text that echoes the login.
    BadAuth,
    StartTls,
    Plain,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Stream = BufReader<Pin<Box<dyn Io>>>;

fn boxed<T: Io + 'static>(t: T) -> Stream {
    BufReader::new(Box::pin(t) as Pin<Box<dyn Io>>)
}

#[derive(Default)]
struct Mail {
    /// Every command line received, in order, with the TLS state.
    log: Mutex<Vec<(bool, String)>>,
    data: Mutex<Vec<String>>,
}

async fn put(s: &mut Stream, text: &str) {
    s.write_all(text.as_bytes()).await.unwrap();
    s.flush().await.unwrap();
}

async fn smtp_session(
    tcp: tokio::net::TcpStream,
    acc: tokio_rustls::TlsAcceptor,
    mode: Mode,
    m: Arc<Mail>,
) {
    let mut tls = false;
    let mut s: Stream = if matches!(mode, Mode::Implicit | Mode::BadAuth) {
        let Ok(t) = acc.accept(tcp).await else {
            return;
        };
        tls = true;
        boxed(t)
    } else {
        boxed(tcp)
    };
    put(&mut s, "220 mock ESMTP\r\n").await;
    loop {
        let mut line = String::new();
        if s.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let line = line.trim_end().to_string();
        m.log.lock().unwrap().push((tls, line.clone()));
        let up = line.to_ascii_uppercase();
        if up.starts_with("EHLO") {
            let mut r = String::from("250-mock\r\n");
            if mode == Mode::StartTls && !tls {
                r.push_str("250-STARTTLS\r\n");
            }
            r.push_str("250 AUTH PLAIN\r\n");
            put(&mut s, &r).await;
        } else if up == "STARTTLS" {
            put(&mut s, "220 go ahead\r\n").await;
            let raw = s.into_inner();
            let Ok(t) = acc.accept(raw).await else {
                return;
            };
            tls = true;
            s = boxed(t);
        } else if up.starts_with("AUTH PLAIN") && mode == Mode::BadAuth {
            put(
                &mut s,
                &format!("535 5.7.8 rejected mailer {SMTP_PASS} {line}\r\n"),
            )
            .await;
        } else if up.starts_with("AUTH PLAIN") {
            put(&mut s, "235 authenticated\r\n").await;
        } else if up.starts_with("MAIL FROM") || up.starts_with("RCPT TO") {
            put(&mut s, "250 ok\r\n").await;
        } else if up == "DATA" {
            put(&mut s, "354 go\r\n").await;
            let mut body = String::new();
            loop {
                let mut l = String::new();
                if s.read_line(&mut l).await.unwrap_or(0) == 0 {
                    return;
                }
                if l == ".\r\n" {
                    break;
                }
                body.push_str(&l);
            }
            m.data.lock().unwrap().push(body);
            put(&mut s, "250 queued\r\n").await;
        } else if up == "QUIT" {
            put(&mut s, "221 bye\r\n").await;
            return;
        } else {
            put(&mut s, "500 what\r\n").await;
        }
    }
}

async fn smtp_server(p: &Pki, mode: Mode) -> (u16, Arc<Mail>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acc = acceptor(p, &[b"smtp"]);
    let mail = Arc::new(Mail::default());
    let m2 = mail.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(smtp_session(tcp, acc.clone(), mode, m2.clone()));
        }
    });
    (port, mail)
}

fn smtp_cfg(port: u16, starttls: bool) -> String {
    format!(
        "[targets.mail]\ntype = \"smtp\"\nhost = \"{MAIL_HOST}\"\nport = {port}\n\
         from = \"saiife@box1.test\"\nto = [\"ops@corp.test\", \"oncall@corp.test\"]\n\
         secret = \"smtp-login\"\nstarttls = {starttls}\n"
    )
}

fn check_mail(mail: &Mail, tls_for_auth: bool) {
    let log = mail.log.lock().unwrap().clone();
    let auth = log
        .iter()
        .find(|(_, l)| l.starts_with("AUTH PLAIN"))
        .expect("AUTH PLAIN was sent");
    assert_eq!(auth.0, tls_for_auth);
    let b64 = auth.1.trim_start_matches("AUTH PLAIN ");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    assert_eq!(raw, format!("\0mailer\0{SMTP_PASS}").as_bytes());
    assert!(log.iter().any(|(_, l)| l == "MAIL FROM:<saiife@box1.test>"));
    assert!(log.iter().any(|(_, l)| l == "RCPT TO:<ops@corp.test>"));
    assert!(log.iter().any(|(_, l)| l == "RCPT TO:<oncall@corp.test>"));
    // Nothing but the greeting exchange and STARTTLS before TLS.
    for (t, l) in &log {
        if !t {
            assert!(l.starts_with("EHLO") || l == "STARTTLS", "plain: {l}");
        }
    }
    let data = mail.data.lock().unwrap().clone();
    assert_eq!(data.len(), 1);
    assert!(
        data[0].contains("Subject: [saiife] approval_created\r\n"),
        "{}",
        data[0]
    );
    assert!(data[0].contains("request: 3\r\n") && data[0].contains("service: shop\r\n"));
    assert!(data[0].contains("host: box1\r\n"));
    assert!(!data[0].contains(SMTP_PASS));
}

#[tokio::test]
async fn smtp_implicit_tls_and_starttls_send() {
    for (mode, starttls) in [(Mode::Implicit, false), (Mode::StartTls, true)] {
        let p = pki();
        let (port, mail) = smtp_server(&p, mode).await;
        let w = world(|_| smtp_cfg(port, starttls), p);
        let n = Notifier::new();
        n.start(Arc::downgrade(&w.env));
        n.send(ev(Event::ApprovalCreated, 3, "refund of 40 EUR"));
        let sent = w.wait(1, |r| result_is(r, "sent")).await;
        assert_eq!(sent.len(), 1, "{:?}", w.records());
        check_mail(&mail, true);
        let all = serde_json::to_string(&w.records()).unwrap();
        assert!(!all.contains(SMTP_PASS));
    }
}

#[tokio::test]
async fn smtp_plaintext_refused() {
    // STARTTLS wanted, server offers none: refused before any AUTH.
    let p = pki();
    let (port, mail) = smtp_server(&p, Mode::Plain).await;
    let w = world(|_| smtp_cfg(port, true), p);
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    n.send(ev(Event::ApprovalCreated, 3, "x"));
    let failed = w.wait(1, |r| result_is(r, "failed")).await;
    assert_eq!(failed.len(), 1, "{:?}", w.records());
    assert!(
        failed[0]["reason"]
            .as_str()
            .unwrap()
            .contains("plain-text SMTP is refused"),
        "{failed:?}"
    );
    assert!(mail
        .log
        .lock()
        .unwrap()
        .iter()
        .all(|(_, l)| !l.starts_with("AUTH")));

    // Implicit TLS against a plain-text server: the handshake fails.
    let p = pki();
    let (port, mail) = smtp_server(&p, Mode::Plain).await;
    let w = world(|_| smtp_cfg(port, false), p);
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    n.send(ev(Event::ApprovalCreated, 3, "x"));
    let failed = w.wait(1, |r| result_is(r, "failed")).await;
    assert_eq!(failed.len(), 1, "{:?}", w.records());
    assert!(mail
        .log
        .lock()
        .unwrap()
        .iter()
        .all(|(_, l)| !l.starts_with("AUTH")));
    assert!(mail.data.lock().unwrap().is_empty());
}

#[tokio::test]
async fn smtp_auth_refusal_text_is_not_recorded() {
    let p = pki();
    let (port, mail) = smtp_server(&p, Mode::BadAuth).await;
    let w = world(|_| smtp_cfg(port, false), p);
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    n.send(ev(Event::ApprovalCreated, 3, "x"));
    let failed = w.wait(1, |r| result_is(r, "failed")).await;
    assert_eq!(failed.len(), 1, "{:?}", w.records());
    let reason = failed[0]["reason"].as_str().unwrap();
    assert!(reason.contains("authentication refused"), "{reason}");
    let all = serde_json::to_string(&w.records()).unwrap();
    assert!(
        !all.contains(SMTP_PASS) && !all.contains("AUTH PLAIN") && !all.contains("rejected"),
        "{all}"
    );
    assert!(mail.data.lock().unwrap().is_empty());
}

// -------------------------------------------------------------- command

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn script(dir: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("page.sh");
    std::fs::write(
        &p,
        "#!/bin/sh\n/bin/cat > \"$0.out\"\n/usr/bin/env > \"$0.env\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn command_world(path: &std::path::Path) -> World {
    world(
        |_| {
            format!(
                "[targets.pager]\ntype = \"command\"\npath = \"{}\"\n",
                path.display()
            )
        },
        pki(),
    )
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn command_target_receives_json_stdin() {
    let d = scratch();
    let sh = script(d.path());
    let w = command_world(&sh);
    let uid = rustix::process::getuid().as_raw();
    let n = Notifier::with_trusted_owner(uid);
    n.start(Arc::downgrade(&w.env));
    n.send(ev(Event::Lockdown, 9, "lockdown on: maintenance"));
    let sent = w.wait(1, |r| result_is(r, "sent")).await;
    assert_eq!(sent.len(), 1, "{:?}", w.records());
    let out = std::fs::read_to_string(format!("{}.out", sh.display())).unwrap();
    let v: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["event"], "lockdown");
    assert_eq!(v["id"], 9);
    assert_eq!(v["summary"], "lockdown on: maintenance");
    // The environment was cleared: nothing of ours leaks to the program.
    let env = std::fs::read_to_string(format!("{}.env", sh.display())).unwrap_or_default();
    assert!(!env.contains("HOME=") && !env.contains("SAIIFE"), "{env}");
}

#[tokio::test]
async fn user_owned_command_refused() {
    let d = scratch();
    let sh = script(d.path());
    let w = command_world(&sh);
    // The real trust: root-owned, with root-owned parents. This file is ours.
    let n = Notifier::new();
    n.start(Arc::downgrade(&w.env));
    n.send(ev(Event::Lockdown, 9, "x"));
    let failed = w.wait(1, |r| result_is(r, "failed")).await;
    assert_eq!(failed.len(), 1, "{:?}", w.records());
    assert!(
        failed[0]["reason"]
            .as_str()
            .unwrap()
            .contains("not root-owned"),
        "{failed:?}"
    );
    assert!(!std::path::Path::new(&format!("{}.out", sh.display())).exists());
}

fn runs(sh: &std::path::Path) -> usize {
    std::fs::read_to_string(format!("{}.runs", sh.display()))
        .map(|t| t.lines().count())
        .unwrap_or(0)
}

// Reads /proc to see the grandchild gone (Linux).
#[cfg(all(debug_assertions, target_os = "linux"))]
#[tokio::test]
async fn command_timeout_kills_its_group_and_is_not_retried() {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch();
    let sh = d.path().join("hang.sh");
    std::fs::write(
        &sh,
        "#!/bin/sh\necho x >> \"$0.runs\"\n/bin/sleep 60 &\necho $! > \"$0.pid\"\nwait\n",
    )
    .unwrap();
    std::fs::set_permissions(&sh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let w = command_world(&sh);
    let uid = rustix::process::getuid().as_raw();
    let n = Notifier::with_trusted_owner_and_timeout(uid, Duration::from_millis(500));
    n.start(Arc::downgrade(&w.env));
    n.send(ev(Event::Lockdown, 9, "x"));
    let failed = w.wait(1, |r| result_is(r, "failed")).await;
    assert_eq!(failed.len(), 1, "{:?}", w.records());
    assert!(failed[0]["reason"].as_str().unwrap().contains("timed out"));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(runs(&sh), 1, "a timeout was retried");
    // The program's child (its group) is gone, or at most a zombie.
    let pid: u32 = std::fs::read_to_string(format!("{}.pid", sh.display()))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|t| t.rsplit(") ").next().and_then(|r| r.chars().next()));
        if state.is_none() || state == Some('Z') {
            break;
        }
        assert!(
            Instant::now() < end,
            "the grandchild {pid} is still running"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn command_nonzero_exit_is_not_retried() {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch();
    let sh = d.path().join("fail.sh");
    std::fs::write(&sh, "#!/bin/sh\necho x >> \"$0.runs\"\nexit 3\n").unwrap();
    std::fs::set_permissions(&sh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let w = command_world(&sh);
    let n = Notifier::with_trusted_owner(rustix::process::getuid().as_raw());
    n.start(Arc::downgrade(&w.env));
    n.send(ev(Event::Lockdown, 9, "x"));
    let failed = w.wait(1, |r| result_is(r, "failed")).await;
    assert_eq!(failed.len(), 1, "{:?}", w.records());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(runs(&sh), 1);
}
