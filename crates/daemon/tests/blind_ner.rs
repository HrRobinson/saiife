//! The name-detector model fetch and the `saiife-ner` client (plan 47
//! Task 4; R47-3, R47-11, spec §2.4): the pinned download against a
//! loopback HTTPS upstream (rcgen certificates, nothing leaves 127.0.0.1),
//! the re-hash on every helper start, and the client against plan 46's
//! `saiife-fake-ner` and small shell helpers that misbehave.
//!
//! The fake helper is `target/debug/saiife-fake-ner`: run
//! `cargo build -p saiife-shield-ner --features fake --bin saiife-fake-ner`
//! first (the daemon never depends on that crate, so its normal tree stays
//! free of tract). The helper seams are environment variables, so the
//! client tests take one lock and run one at a time.
#![cfg(target_os = "linux")]

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_daemon::blind::ner::{
    self, NerClient, NerFiles, NerState, ANSWER_MS_SEAM, HELPER_SEAM, MODEL_CAP,
};
use saiife_daemon::ops::{Conn, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::{Request as IpcRequest, OP_BLIND_NER_FETCH};
use saiife_ipc::peer::PeerCred;
use saiife_policy::blind::NerCfg;
use saiife_policy::{Directory, FixedDirectory, Fsync};
use saiife_shield::ner::{DetectError, NameDetector, SpanLabel};
use saiife_shield::ner_proto::MAX_TEXT;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

const HOST: &str = "ner.example.test";
const OWN: u32 = 1000;
const MODEL: &[u8] = b"p47-t4 model bytes: not an ONNX graph";
const VOCAB: &[u8] = b"[PAD]\n[UNK]\n[CLS]\n[SEP]\nsoren\n";
const LABELS: &[u8] = br#"{"id2label":{"0":"O","1":"B-PER"}}"#;

/// The env seams are process-wide: one client test at a time.
static SEAMS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

// ------------------------------------------------------------ loopback ----

struct Loopback;

impl Resolver for Loopback {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if host == HOST {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

struct Pki {
    ca_pem: String,
    leaf: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

fn pki() -> Pki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![HOST.to_string()])
        .unwrap()
        .signed_by(&key, &ca)
        .unwrap();
    Pki {
        ca_pem: ca.pem(),
        leaf: leaf.der().clone(),
        key: PrivatePkcs8KeyDer::from(key.serialize_der()),
    }
}

/// The files the upstream serves, by path, and how often each was asked.
#[derive(Default)]
struct Files {
    by_path: BTreeMap<String, Vec<u8>>,
    asked: Mutex<Vec<String>>,
}

impl Files {
    fn asked(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

async fn handle(
    req: Request<Incoming>,
    f: Arc<Files>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    f.asked.lock().unwrap().push(path.clone());
    Ok(match f.by_path.get(&path) {
        Some(b) => Response::new(Full::new(Bytes::from(b.clone()))),
        None => Response::builder()
            .status(404)
            .body(Full::new(Bytes::new()))
            .unwrap(),
    })
}

/// A TLS upstream on 127.0.0.1 serving `files`; its port.
async fn server(p: &Pki, files: Arc<Files>) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
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
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acc, f) = (acc.clone(), Arc::clone(&files));
            tokio::spawn(async move {
                let Ok(tls) = acc.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |r| handle(r, Arc::clone(&f)));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    port
}

/// The daemon's upstream for the test: the loopback resolver, and the
/// test CA through `with_ca_file` (as an audit forwarding target's `ca`).
fn upstream(root: &Path, p: &Pki) -> Upstream {
    let ca = root.join("ca.pem");
    std::fs::write(&ca, &p.ca_pem).unwrap();
    Upstream::with_roots(
        RootCertStore::empty(),
        Arc::new(Loopback),
        Duration::from_secs(10),
    )
    .with_ca_file(&ca, Duration::from_secs(10))
    .unwrap()
}

// -------------------------------------------------------------- context ----

const PASSWD: &str = "me:x:1000:1000::/home/me:/bin/sh\nyou:x:1001:1001::/home/you:/bin/sh\n";

/// A personal-mode context in `root`; `up` its upstream client.
fn ctx(root: &Path, up: Option<Upstream>) -> Arc<Ctx> {
    let audit = root.join("audit");
    let state = root.join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: "personal".into(),
            saiife: "test".into(),
            key: None,
        },
    )
    .unwrap();
    let cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, cfg, None).unwrap();
    let dirs: Arc<dyn Directory + Send + Sync> = Arc::new(FixedDirectory::from_text(PASSWD, ""));
    Arc::new(Ctx::new(CtxInit {
        audit_dir: audit,
        mode: Mode::Personal,
        own_uid: OWN,
        own_user: "me".into(),
        upstream: up.ok_or_else(|| "not configured".to_string()),
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }))
}

fn set_policy(ctx: &Ctx, root: &Path, text: &str) {
    let path = root.join("config.toml");
    std::fs::write(&path, text).unwrap();
    let l = saiife_policy::load_system(&path).unwrap();
    *ctx.policy.lock().unwrap() =
        PolicyState::from_loaded(&l, &[], saiife_broker::Catalog::new(&[], vec![]));
}

fn cfg(port: u16, model: &str, vocab: &str, labels: &str, max: Option<u64>) -> NerCfg {
    NerCfg {
        model_url: format!("https://{HOST}:{port}/m/model.onnx"),
        model_sha256: model.into(),
        vocab_url: format!("https://{HOST}:{port}/m/vocab.txt"),
        vocab_sha256: vocab.into(),
        labels_url: format!("https://{HOST}:{port}/m/labels.json"),
        labels_sha256: labels.into(),
        max_bytes: max,
    }
}

fn good_cfg(port: u16) -> NerCfg {
    cfg(port, &sha(MODEL), &sha(VOCAB), &sha(LABELS), None)
}

fn served() -> Arc<Files> {
    Arc::new(Files {
        by_path: BTreeMap::from([
            ("/m/model.onnx".to_string(), MODEL.to_vec()),
            ("/m/vocab.txt".to_string(), VOCAB.to_vec()),
            ("/m/labels.json".to_string(), LABELS.to_vec()),
        ]),
        asked: Mutex::new(Vec::new()),
    })
}

fn models(ctx: &Ctx) -> PathBuf {
    ctx.blind.root.join("models")
}

/// The names in the models dir, sorted.
fn listing(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

// ---------------------------------------------------------------- fetch ----

#[tokio::test]
async fn fetch_checks_hash() {
    let t = scratch();
    let p = pki();
    let files = served();
    let port = server(&p, Arc::clone(&files)).await;
    let c = ctx(t.path(), Some(upstream(t.path(), &p)));

    // Right pins: three files named by their hash, 0400 in a 0700 dir.
    let got = ner::fetch(&c, &good_cfg(port)).await.unwrap();
    let dir = models(&c);
    assert_eq!(got.model, dir.join(sha(MODEL)));
    assert_eq!(got.vocab, dir.join(sha(VOCAB)));
    assert_eq!(got.labels, dir.join(sha(LABELS)));
    for (path, bytes) in [
        (&got.model, MODEL),
        (&got.vocab, VOCAB),
        (&got.labels, LABELS),
    ] {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert_eq!(mode(path), 0o400);
    }
    assert_eq!(mode(&dir), 0o700);
    let mut want = vec![sha(MODEL), sha(VOCAB), sha(LABELS)];
    want.sort();
    assert_eq!(listing(&dir), want, "no temp file is left");
    assert_eq!(files.asked(), 3);
    assert_eq!(ner::present(&c.blind.root, &good_cfg(port)).unwrap(), got);

    // Again: every file is there with its hash, so nothing is fetched.
    assert_eq!(ner::fetch(&c, &good_cfg(port)).await.unwrap(), got);
    assert_eq!(files.asked(), 3);

    // A stored file that changed is fetched again.
    std::fs::set_permissions(&got.vocab, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&got.vocab, b"tampered").unwrap();
    ner::fetch(&c, &good_cfg(port)).await.unwrap();
    assert_eq!(std::fs::read(&got.vocab).unwrap(), VOCAB);
    assert_eq!(mode(&got.vocab), 0o400);
    assert_eq!(files.asked(), 4);

    // A wrong pin: refused, and nothing is stored under it.
    let t2 = scratch();
    let c2 = ctx(t2.path(), Some(upstream(t2.path(), &p)));
    let wrong = sha(b"another model");
    let e = ner::fetch(&c2, &cfg(port, &wrong, &sha(VOCAB), &sha(LABELS), None))
        .await
        .unwrap_err();
    assert!(
        e.contains("model") && e.contains("does not match its pinned sha256"),
        "{e}"
    );
    assert!(
        listing(&models(&c2)).is_empty(),
        "{:?}",
        listing(&models(&c2))
    );

    // Over `max_bytes`: refused before anything is stored.
    let t3 = scratch();
    let c3 = ctx(t3.path(), Some(upstream(t3.path(), &p)));
    let small = cfg(port, &sha(MODEL), &sha(VOCAB), &sha(LABELS), Some(8));
    let e = ner::fetch(&c3, &small).await.unwrap_err();
    assert!(e.contains("max_bytes"), "{e}");
    assert!(listing(&models(&c3)).is_empty());

    // A cap over the 1 GiB the helper can load is refused outright.
    let huge = cfg(
        port,
        &sha(MODEL),
        &sha(VOCAB),
        &sha(LABELS),
        Some(MODEL_CAP + 1),
    );
    let before = files.asked();
    let e = ner::fetch(&c3, &huge).await.unwrap_err();
    assert!(e.contains("1 GiB"), "{e}");
    assert_eq!(files.asked(), before);

    // A missing file upstream: the status, nothing stored.
    let t4 = scratch();
    let c4 = ctx(t4.path(), Some(upstream(t4.path(), &p)));
    let mut gone = good_cfg(port);
    gone.labels_url = format!("https://{HOST}:{port}/m/nothing.json");
    let e = ner::fetch(&c4, &gone).await.unwrap_err();
    assert!(e.contains("labels") && e.contains("404"), "{e}");
    assert!(!listing(&models(&c4)).contains(&sha(LABELS)));
}

/// Writes the three files where `fetch` puts them (0400); their config.
fn stored(ctx: &Ctx) -> NerCfg {
    let dir = models(ctx);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    for b in [MODEL, VOCAB, LABELS] {
        let p = dir.join(sha(b));
        if p.exists() {
            continue;
        }
        std::fs::write(&p, b).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    good_cfg(443)
}

// --------------------------------------------------------------- helpers ----

/// plan 46's fake helper, built beside this test binary.
fn fake_ner() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let p = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("saiife-fake-ner");
    assert!(
        p.is_file(),
        "{} is missing: run `cargo build -p saiife-shield-ner --features fake --bin saiife-fake-ner` first",
        p.display()
    );
    p
}

/// A helper script `name` in its own 0700 dir under `root` (mode 0700).
fn script(root: &Path, name: &str, body: &str) -> PathBuf {
    let dir = root.join(format!("{name}.d"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p
}

/// The fake helper behind a wrapper (the fake takes `--phrases`, not the
/// six model arguments), with these phrases (`LABEL\tphrase` lines).
fn fake_with(root: &Path, phrases: &str) -> PathBuf {
    let ph = root.join("phrases.txt");
    std::fs::write(&ph, phrases).unwrap();
    script(
        root,
        "fake-ner",
        &format!(
            "exec '{}' --phrases '{}'\n",
            fake_ner().display(),
            ph.display()
        ),
    )
}

const HELLO_PER: &str = r#"{"t":"hello","proto":1,"version":"0","labels":["PER"]}"#;

/// Points the seams at `helper` (and the answer timeout, in ms).
fn point(helper: &Path, answer_ms: Option<u64>) {
    std::env::set_var(HELPER_SEAM, helper);
    match answer_ms {
        Some(ms) => std::env::set_var(ANSWER_MS_SEAM, ms.to_string()),
        None => std::env::remove_var(ANSWER_MS_SEAM),
    }
}

fn unavailable(r: Result<Vec<saiife_shield::ner::NameSpan>, DetectError>) -> String {
    match r {
        Err(DetectError::Unavailable(why)) => why,
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

fn failed_why(s: NerState) -> String {
    match s {
        NerState::Failed(why) => why,
        other => panic!("expected Failed, got {other:?}"),
    }
}

fn files_in(ctx: &Ctx) -> NerFiles {
    ner::files_for(&ctx.blind.root, &stored(ctx))
}

// ---------------------------------------------------------------- client ----

#[tokio::test]
async fn present_rehashes() {
    let _g = SEAMS.lock().await;
    let t = scratch();
    let c = ctx(t.path(), None);
    let ncfg = stored(&c);
    let files = ner::present(&c.blind.root, &ncfg).unwrap();
    point(&fake_with(t.path(), "PER\tSøren Ærø\n"), None);
    let client = NerClient::new();
    assert_eq!(client.state(), NerState::NotConfigured);
    client.configure(Some(files.clone()), Mode::Personal, OWN);
    assert!(
        matches!(client.state(), NerState::Ready { .. }),
        "{:?}",
        client.state()
    );

    // One changed byte: present refuses, and the next helper start does too.
    let mut b = VOCAB.to_vec();
    b[0] ^= 1;
    std::fs::set_permissions(&files.vocab, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&files.vocab, &b).unwrap();
    let e = ner::present(&c.blind.root, &ncfg).unwrap_err();
    assert!(
        e.contains("vocab") && e.contains("saiife blind ner fetch"),
        "{e}"
    );
    client.configure(None, Mode::Personal, OWN);
    client.configure(Some(files.clone()), Mode::Personal, OWN);
    match client.state() {
        NerState::Missing(why) => assert!(why.contains("vocab"), "{why}"),
        other => panic!("expected Missing, got {other:?}"),
    }
    let why = unavailable(client.detect("Hvad skylder Søren Ærø?"));
    assert!(why.contains("vocab"), "{why}");

    // A missing file: Missing as well.
    std::fs::remove_file(&files.model).unwrap();
    let e = ner::present(&c.blind.root, &ncfg).unwrap_err();
    assert!(e.contains("model") && e.contains("missing"), "{e}");
}

#[tokio::test]
async fn client_detects_with_fake() {
    let _g = SEAMS.lock().await;
    let t = scratch();
    let c = ctx(t.path(), None);
    let files = files_in(&c);
    point(&fake_with(t.path(), "PER\tSøren Ærø\nLOC\tAarhus\n"), None);
    let client = NerClient::new();
    client.configure(Some(files), Mode::Personal, OWN);
    // A label subset in the hello is accepted (plan 46 T3-a).
    match client.state() {
        NerState::Ready { pid, labels } => {
            assert!(pid > 0);
            assert_eq!(labels, vec!["PER", "LOC"]);
        }
        other => panic!("expected Ready, got {other:?}"),
    }
    let text = "Hvad skylder søren ærø i Aarhus?";
    let spans = client.detect(text).unwrap();
    let got: Vec<(usize, usize, SpanLabel, &str)> = spans
        .iter()
        .map(|s| (s.start, s.end, s.label, &text[s.start..s.end]))
        .collect();
    assert_eq!(
        got,
        vec![
            (13, 25, SpanLabel::Person, "søren ærø"),
            (28, 34, SpanLabel::Location, "Aarhus"),
        ]
    );
    assert!(client.detect("ingen navne her").unwrap().is_empty());
    // Over the protocol's text cap: sent in overlapping parts, the offsets
    // still into the whole text (the name straddles the first cut).
    let mut long = "æ".repeat(MAX_TEXT / 2 - 4);
    long.push(' ');
    let at = long.len();
    assert!(at < MAX_TEXT && at + "Søren Ærø".len() > MAX_TEXT);
    long.push_str("Søren Ærø ");
    long.push_str(&"x".repeat(MAX_TEXT));
    long.push_str(" Aarhus");
    let spans = client.detect(&long).unwrap();
    let got: Vec<(usize, &str)> = spans
        .iter()
        .map(|s| (s.start, &long[s.start..s.end]))
        .collect();
    assert_eq!(got, vec![(at, "Søren Ærø"), (long.len() - 6, "Aarhus")]);
    // Usable through the trait object a build holds.
    let d: Arc<dyn NameDetector> = Arc::new(client);
    assert_eq!(d.detect(text).unwrap().len(), 2);
}

#[tokio::test]
async fn hello_without_per_is_refused() {
    let _g = SEAMS.lock().await;
    let t = scratch();
    let c = ctx(t.path(), None);
    point(&fake_with(t.path(), "LOC\tAarhus\n"), None);
    let client = NerClient::new();
    client.configure(Some(files_in(&c)), Mode::Personal, OWN);
    let why = failed_why(client.state());
    assert!(why.contains("PER"), "{why}");
    unavailable(client.detect("Aarhus"));
}

#[tokio::test]
async fn client_restarts_then_gives_up() {
    let _g = SEAMS.lock().await;
    let t = scratch();
    let c = ctx(t.path(), None);
    let count = t.path().join("starts");
    let helper = script(
        t.path(),
        "exits",
        &format!(
            "echo x >> '{}'\nprintf '%s\\n' '{HELLO_PER}'\nexit 0\n",
            count.display()
        ),
    );
    point(&helper, None);
    let starts = || {
        std::fs::read_to_string(&count)
            .unwrap_or_default()
            .lines()
            .count()
    };
    let client = NerClient::new();
    client.configure(Some(files_in(&c)), Mode::Personal, OWN);
    assert!(matches!(client.state(), NerState::Ready { .. }));
    assert_eq!(starts(), 1);
    // Each request fails closed; the next one restarts the helper, three
    // times within the minute.
    for n in 0..4 {
        unavailable(client.detect("Søren"));
        assert_eq!(starts(), 1 + n);
    }
    // Then no more: unavailable without a start.
    let why = unavailable(client.detect("Søren"));
    assert!(why.contains("3 times"), "{why}");
    assert_eq!(starts(), 4);
    assert!(failed_why(client.state()).contains("3 times"));
    unavailable(client.detect("Søren"));
    assert_eq!(starts(), 4);
    // `configure` again starts over.
    client.configure(Some(files_in(&c)), Mode::Personal, OWN);
    assert_eq!(starts(), 5);
    assert!(matches!(client.state(), NerState::Ready { .. }));
}

#[tokio::test]
async fn answer_timeout() {
    let _g = SEAMS.lock().await;
    let t = scratch();
    let c = ctx(t.path(), None);
    // Reads every request and never answers.
    let helper = script(
        t.path(),
        "silent",
        &format!("printf '%s\\n' '{HELLO_PER}'\nwhile read -r l; do :; done\n"),
    );
    point(&helper, Some(300));
    let client = NerClient::new();
    client.configure(Some(files_in(&c)), Mode::Personal, OWN);
    let NerState::Ready { .. } = client.state() else {
        panic!("not ready: {:?}", client.state());
    };
    let t0 = Instant::now();
    let why = unavailable(client.detect("Søren"));
    let took = t0.elapsed();
    assert!(why.contains("in time"), "{why}");
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_secs(5),
        "{took:?}"
    );
    assert!(failed_why(client.state()).contains("in time"));
    // The silent helper was stopped; the next request runs a new one,
    // which is just as silent.
    unavailable(client.detect("Søren"));
    std::env::remove_var(ANSWER_MS_SEAM);
}

#[tokio::test]
async fn error_frame_fails_the_request() {
    let _g = SEAMS.lock().await;
    let t = scratch();
    let c = ctx(t.path(), None);
    let helper = script(
        t.path(),
        "errs",
        &format!(
            "printf '%s\\n' '{HELLO_PER}'\nread -r l\nprintf '%s\\n' '{{\"t\":\"error\",\"id\":0,\"error\":\"malformed request\"}}'\nwhile read -r l; do :; done\n"
        ),
    );
    point(&helper, None);
    let client = NerClient::new();
    client.configure(Some(files_in(&c)), Mode::Personal, OWN);
    assert!(matches!(client.state(), NerState::Ready { .. }));
    // An error frame with id 0 after the hello fails the request and the
    // helper: never "no names".
    unavailable(client.detect("Søren"));
    assert!(matches!(client.state(), NerState::Failed(_)));
}

#[tokio::test]
async fn unsafe_ner_helper_refused() {
    let _g = SEAMS.lock().await;
    let t = scratch();
    let c = ctx(t.path(), None);
    let helper = fake_with(t.path(), "PER\tSøren\n");
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o666)).unwrap();
    point(&helper, None);
    let client = NerClient::new();
    client.configure(Some(files_in(&c)), Mode::Personal, OWN);
    let why = failed_why(client.state());
    assert!(why.contains("writable by group or others"), "{why}");
    unavailable(client.detect("Søren"));
    // A helper in a world-writable directory: refused as well.
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(
        helper.parent().unwrap(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    client.configure(Some(files_in(&c)), Mode::Personal, OWN);
    let why = failed_why(client.state());
    assert!(why.contains("writable by group or others"), "{why}");
}

// -------------------------------------------------------------------- op ----

fn peer(uid: u32) -> PeerCred {
    PeerCred {
        uid,
        gid: uid,
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

async fn call_as(ctx: &Arc<Ctx>, uid: u32) -> Value {
    let conn = Conn::new(peer(uid), None);
    let req = IpcRequest {
        id: 3,
        op: OP_BLIND_NER_FETCH.into(),
        args: serde_json::Map::new(),
    };
    saiife_daemon::blind::ops::handle(ctx, &conn, req).await
}

fn ner_policy(c: &NerCfg) -> String {
    format!(
        "version = 2\n\n[blind.ner]\nmodel_url = \"{}\"\nmodel_sha256 = \"{}\"\nvocab_url = \"{}\"\nvocab_sha256 = \"{}\"\nlabels_url = \"{}\"\nlabels_sha256 = \"{}\"\n",
        c.model_url, c.model_sha256, c.vocab_url, c.vocab_sha256, c.labels_url, c.labels_sha256
    )
}

#[tokio::test]
async fn fetch_op() {
    let _g = SEAMS.lock().await;
    let t = scratch();
    let p = pki();
    let files = served();
    let port = server(&p, Arc::clone(&files)).await;
    let c = ctx(t.path(), Some(upstream(t.path(), &p)));
    // No [blind.ner]: nothing to fetch.
    set_policy(&c, t.path(), "version = 2\n");
    let v = call_as(&c, OWN).await;
    assert_eq!(v["error"], "bad_request", "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("[blind.ner]"),
        "{v}"
    );

    set_policy(&c, t.path(), &ner_policy(&good_cfg(port)));
    // Not the broker's own user: refused, nothing fetched.
    let v = call_as(&c, 1001).await;
    assert_eq!(v["error"], "forbidden", "{v}");
    assert_eq!(files.asked(), 0);
    assert!(c.blind.detector().is_none());

    // The own user: fetched, and the build's detector is the client.
    point(&fake_with(t.path(), "PER\tSøren Ærø\n"), None);
    let v = call_as(&c, OWN).await;
    assert!(v.get("error").is_none(), "{v}");
    assert_eq!(v["model"], json!(sha(MODEL)));
    assert_eq!(v["detector"], "ready", "{v}");
    assert_eq!(files.asked(), 3);
    let d = c.blind.detector().expect("the detector slot is filled");
    let spans = d.detect("Hvad skylder Søren Ærø?").unwrap();
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].label, SpanLabel::Person);
    assert!(matches!(c.blind.ner.state(), NerState::Ready { .. }));

    // [blind.ner] removed and applied again: no detector.
    set_policy(&c, t.path(), "version = 2\n");
    ner::apply(Arc::clone(&c)).await;
    assert!(c.blind.detector().is_none());
    assert_eq!(c.blind.ner.state(), NerState::NotConfigured);
}
