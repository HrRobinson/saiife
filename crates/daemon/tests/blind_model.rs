//! The daemon-side model client (plan 47 Task 6; R47-7, R47-8): the request
//! body pinned byte for byte, the headers against a loopback HTTPS upstream
//! (rcgen certificates, nothing leaves 127.0.0.1), the send order (no
//! outbox entry or no record: nothing sent), the frame check, the stop
//! reasons, the retry, the incoming leak scan, the key rules and the
//! scripted planner. Every value here is made up.
#![cfg(target_os = "linux")]

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_audit::{ChainWriter, WriterOptions};
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_daemon::audit_query::{self, Scope};
use saiife_daemon::blind::model::{
    self, AnthropicPlanner, FakePlanner, PlanError, Planner, SYSTEM_PROMPT,
};
use saiife_daemon::ops::{Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_policy::{Directory, FixedDirectory, Fsync};
use saiife_shield::envelope::{
    cloud_schema, schema_sha256, sha256_hex, synthetic_sha256, CloudColumn, CloudSchema,
    CloudTable, Envelope, SyntheticRows, ENVELOPE_KIND, ENVELOPE_VERSION,
};
use saiife_shield::firewall::{Expected, Firewall};
use saiife_shield::index::{build_index, AllowList, IndexKey, KnownIndex};
use saiife_shield::ner::ListDetector;
use saiife_shield::norm::normalize;
use saiife_shield::schema::{
    ColType, ColumnClass, ColumnInfo, DatasetName, EntitySpec, Lang, Schema, TableInfo,
};
use saiife_shield::snapshot::build_snapshot;
use saiife_shield::source::{Cell, SourceTable, VecSource};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const HOST: &str = "model.example.test";
const SECRET: &str = "blind-key";
const RARE_FIRST: &str = "Quillfeather";
const RARE_LAST: &str = "Brandvold";
const EMAIL: &str = "quillfeather.brandvold.1@example.invalid";
const LIST_CAP: u32 = 50;
const QUESTION: &str = "how many customers are there in each city";

fn fake_key() -> String {
    concat!("test-", "key-", "blind").to_string()
}

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
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
    ca: CertificateDer<'static>,
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
        ca: ca.der().clone(),
        leaf: leaf.der().clone(),
        key: PrivatePkcs8KeyDer::from(key.serialize_der()),
    }
}

/// One request as the fake upstream saw it.
#[derive(Clone)]
struct Seen {
    method: String,
    path: String,
    headers: http::HeaderMap,
    body: Bytes,
}

/// (status, headers, body) answered in order; then 500.
type Scripted = (u16, Vec<(&'static str, String)>, String);

#[derive(Default)]
struct Server {
    seen: Mutex<Vec<Seen>>,
    script: Mutex<VecDeque<Scripted>>,
    /// Stopped while the request is handled: the records after the send
    /// fail (R-C9a).
    stop_writer: Mutex<Option<saiife_daemon::writer::WriterHandle>>,
}

impl Server {
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

async fn handle(
    req: Request<Incoming>,
    s: Arc<Server>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    s.seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        path: parts.uri.path().to_string(),
        headers: parts.headers,
        body,
    });
    let stop = s.stop_writer.lock().unwrap().take();
    if let Some(w) = stop {
        w.stop(None).await.unwrap();
    }
    let next = s.script.lock().unwrap().pop_front();
    let (status, headers, text) = next.unwrap_or((500, vec![], String::new()));
    let mut b = Response::builder().status(status);
    for (k, v) in headers {
        b = b.header(k, v);
    }
    Ok(b.body(Full::new(Bytes::from(text))).unwrap())
}

/// A TLS upstream on 127.0.0.1 answering `script`; its port and state.
async fn server(p: &Pki, script: Vec<Scripted>) -> (u16, Arc<Server>) {
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
    let s = Arc::new(Server {
        seen: Mutex::new(Vec::new()),
        script: Mutex::new(script.into()),
        stop_writer: Mutex::new(None),
    });
    let s2 = Arc::clone(&s);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acc, s) = (acc.clone(), Arc::clone(&s2));
            tokio::spawn(async move {
                let Ok(tls) = acc.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |r| handle(r, Arc::clone(&s)));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, s)
}

fn planner_for(p: &Pki, port: u16) -> AnthropicPlanner {
    let mut roots = RootCertStore::empty();
    roots.add(p.ca.clone()).unwrap();
    let up = Upstream::with_roots(roots, Arc::new(Loopback), Duration::from_secs(10));
    AnthropicPlanner::with_test_upstream(&format!("https://{HOST}:{port}"), up)
}

/// A 200 answer with `stop_reason` and the content blocks.
fn answer(stop: &str, content: Value) -> Scripted {
    let v = json!({
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-4-8",
        "stop_reason": stop,
        "stop_details": null,
        "content": content,
    });
    (
        200,
        vec![("content-type", "application/json".to_string())],
        v.to_string(),
    )
}

fn good_reply() -> String {
    json!({
        "method": "SELECT t.city, COUNT(*) AS n FROM customers t GROUP BY t.city",
        "template": "{list(city, n)}",
        "intent": "count the customers in each city",
    })
    .to_string()
}

/// A reply after a thinking block and a fallback block (clarification a).
fn ok_answer() -> Scripted {
    answer(
        "end_turn",
        json!([
            {"type": "fallback", "from": {"model": "claude-opus-5-5"}, "to": {"model": "claude-opus-4-8"}},
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "text", "text": good_reply()},
        ]),
    )
}

// -------------------------------------------------------------- fixture ----

fn ikey() -> IndexKey {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11).wrapping_add(5);
    }
    IndexKey(Zeroizing::new(k))
}

fn col(name: &str, class: ColumnClass) -> ColumnInfo {
    ColumnInfo {
        name: name.into(),
        ty: ColType::Text,
        class,
        alias: None,
    }
}

fn schema(rows: u64) -> Schema {
    Schema {
        dataset: "crm".parse().unwrap(),
        tables: vec![TableInfo {
            name: "customers".into(),
            alias: None,
            rows,
            columns: vec![
                col("first_name", ColumnClass::Identifier),
                col("last_name", ColumnClass::Identifier),
                col("email", ColumnClass::Identifier),
                col("city", ColumnClass::Quasi),
            ],
        }],
        entities: vec![EntitySpec {
            table: "customers".into(),
            key: "email".into(),
            names: vec!["first_name".into(), "last_name".into()],
            show: vec![],
            word: "customer".into(),
            word_da: "kunde".into(),
        }],
        joins: vec![],
    }
}

/// One rare customer and 40 common ones.
fn index(root: &Path) -> (KnownIndex, Schema) {
    let mut rows = vec![vec![
        Cell::Text(RARE_FIRST.into()),
        Cell::Text(RARE_LAST.into()),
        Cell::Text(EMAIL.into()),
        Cell::Text("Aarhus".into()),
    ]];
    for i in 0..40 {
        rows.push(vec![
            Cell::Text("Mette".into()),
            Cell::Text("Hansen".into()),
            Cell::Text(format!("mette.hansen.{i}@example.invalid")),
            Cell::Text("Odense".into()),
        ]);
    }
    let n = rows.len() as u64;
    let mut src = VecSource {
        tables: vec![(
            SourceTable {
                name: "customers".into(),
                columns: vec![
                    "first_name".into(),
                    "last_name".into(),
                    "email".into(),
                    "city".into(),
                ],
            },
            rows,
        )],
    };
    let ds = root.join("ds");
    let info = build_snapshot(&mut src, &ds, &mut |_| {}).unwrap();
    let s = schema(n);
    build_index(&info.path, &s, 10, &ikey(), &ds, &mut |_| {}).unwrap();
    (KnownIndex::open(&ds, ikey()).unwrap(), s)
}

struct Fx {
    _t: tempfile::TempDir,
    root: PathBuf,
    ctx: Arc<Ctx>,
    audit: PathBuf,
    index: KnownIndex,
    allow: AllowList,
    detector: ListDetector,
    env: Envelope,
    schema_hash: String,
    synth_hash: String,
}

fn token_entry(name: &str, kind: Kind, field: &str, services: &[&str]) -> Entry {
    Entry {
        name: name.into(),
        kind,
        fields: [(field.to_string(), Zeroizing::new(fake_key()))].into(),
        allowed_services: services.iter().map(|s| s.to_string()).collect(),
        created_by: 0,
        created: "2026-11-18T00:00:00Z".into(),
        last_used: None,
        rotate_after: None,
    }
}

/// A context with a ready vault holding `entry` (none: empty), the policy
/// naming `SECRET` as the model key, and the fixture's index and envelope.
fn fx(entry: Option<Entry>) -> Fx {
    let t = scratch();
    let root = t.path().to_path_buf();
    let audit = root.join("audit");
    let state = root.join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: "locked".into(),
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
    let dirs: Arc<dyn Directory + Send + Sync> = Arc::new(FixedDirectory::from_text("", ""));
    let mut vault = vault::open_with_key(
        Zeroizing::new([9u8; 32]),
        &state.join("vault").join("vault.bin"),
    );
    let VaultState::Ready(v) = &mut vault else {
        panic!("vault not ready");
    };
    if let Some(e) = entry {
        v.put(e).unwrap();
    }
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        mode: Mode::Locked,
        vault,
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }));
    let path = root.join("config.toml");
    std::fs::write(
        &path,
        format!("version = 2\n\n[blind.cloud]\nsecret = \"{SECRET}\"\n"),
    )
    .unwrap();
    let l = saiife_policy::load_system(&path).unwrap();
    *ctx.policy.lock().unwrap() =
        PolicyState::from_loaded(&l, &[], saiife_broker::Catalog::new(&[], vec![]));

    let (index, s) = index(&root);
    let cs = cloud_schema(&s, &[]);
    let mut allow = AllowList::default();
    for w in [
        "customers",
        "customer",
        "first_name",
        "last_name",
        "email",
        "city",
    ] {
        allow.words.insert(normalize(w));
    }
    let synthetic: SyntheticRows = BTreeMap::from([("customers".to_string(), Vec::new())]);
    // The caller's pins, from its own inputs (never from the envelope).
    let schema_hash = schema_sha256(&cloud_schema(&s, &[]));
    let synth_hash = synthetic_sha256(&BTreeMap::from([(
        "customers".to_string(),
        Vec::<BTreeMap<String, Value>>::new(),
    )]));
    let env = Envelope {
        v: ENVELOPE_VERSION,
        kind: ENVELOPE_KIND.to_string(),
        lang: Lang::En,
        schema: cs,
        synthetic,
        question: QUESTION.into(),
        params: vec![],
        context: vec![],
        retry: None,
        list_cap: LIST_CAP,
    };
    Fx {
        _t: t,
        root,
        ctx,
        audit,
        index,
        allow,
        detector: ListDetector::new(&[]),
        env,
        schema_hash,
        synth_hash,
    }
}

fn default_fx() -> Fx {
    fx(Some(token_entry(
        SECRET,
        Kind::Token,
        "token",
        &["blind-model"],
    )))
}

impl Fx {
    fn fw(&self) -> Firewall<'_> {
        Firewall {
            index: &self.index,
            allow: &self.allow,
            detector: &self.detector,
            released_names: &[],
            expected: Expected {
                list_cap: LIST_CAP,
                lang: Lang::En,
                schema_sha256: &self.schema_hash,
                synthetic_sha256: &self.synth_hash,
                symbols: &[],
                previous_method_sha256: None,
            },
        }
    }

    async fn plan(&self, p: &dyn Planner) -> Result<saiife_shield::plan::PlanReply, PlanError> {
        let ds: DatasetName = "crm".parse().unwrap();
        let fw = self.fw();
        p.plan(&self.ctx, 1000, "ask-1", &ds, &self.env, &fw).await
    }

    fn records(&self, kind: &str) -> Vec<Value> {
        let q = audit_query::parse(&serde_json::Map::new()).unwrap();
        audit_query::run(&self.audit, Scope::All, &q)
            .unwrap()
            .records
            .into_iter()
            .filter(|r| r["kind"] == kind)
            .collect()
    }

    fn outbox_dir(&self) -> PathBuf {
        self.ctx.blind.root.join("outbox")
    }

    fn outbox_lines(&self) -> Vec<Value> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(self.outbox_dir()) else {
            return out;
        };
        for e in rd {
            let text = std::fs::read_to_string(e.unwrap().path()).unwrap();
            out.extend(
                text.lines()
                    .map(|l| serde_json::from_str::<Value>(l).unwrap()),
            );
        }
        out
    }
}

// ---------------------------------------------------------------- tests ----

/// The fixed envelope of the pin (no index needed).
fn pin_envelope() -> Envelope {
    Envelope {
        v: ENVELOPE_VERSION,
        kind: ENVELOPE_KIND.to_string(),
        lang: Lang::En,
        schema: CloudSchema {
            tables: vec![CloudTable {
                name: "customers".into(),
                rows: "10-99".into(),
                columns: vec![CloudColumn {
                    name: "city".into(),
                    ty: ColType::Text,
                    class: ColumnClass::Quasi,
                    values: None,
                }],
                entity: Some("customer".into()),
            }],
            joins: vec![],
        },
        synthetic: BTreeMap::from([("customers".to_string(), Vec::new())]),
        question: QUESTION.into(),
        params: vec![],
        context: vec![],
        retry: None,
        list_cap: LIST_CAP,
    }
}

/// The SYSTEM_PROMPT is pinned by its hash; the body around it by bytes.
const PROMPT_SHA256: &str =
    "sha256:85548a9c4616b82c2ec65cc486916ae0145fcd9762195321d904a07998363187";

const PINNED_BODY: &str = concat!(
    r#"{"model":"claude-opus-5-5","max_tokens":16000,"system":<SYSTEM>,"#,
    r#""messages":[{"role":"user","content":"{\"context\":[],\"kind\":\"saiife-blind-plan\",\"lang\":\"en\",\"list_cap\":50,\"params\":[],\"question\":\"how many customers are there in each city\",\"retry\":null,\"schema\":{\"tables\":[{\"columns\":[{\"class\":\"quasi\",\"name\":\"city\",\"ty\":\"text\"}],\"entity\":\"customer\",\"name\":\"customers\",\"rows\":\"10-99\"}]},\"synthetic\":{\"customers\":[]},\"v\":1}"}],"#,
    r#""output_config":{"effort":"high","format":{"type":"json_schema","schema":{"additionalProperties":false,"properties":{"checks":{"items":{"anyOf":[{"additionalProperties":false,"properties":{"kind":{"const":"rows_between"},"max":{"type":"integer"},"min":{"type":"integer"}},"required":["kind","min","max"],"type":"object"},{"additionalProperties":false,"properties":{"a":{"type":"string"},"b":{"type":"string"},"kind":{"const":"equal"}},"required":["kind","a","b"],"type":"object"}]},"type":"array"},"intent":{"type":"string"},"method":{"type":"string"},"needs_judgment":{"type":"boolean"},"template":{"type":"string"}},"required":["method","template","intent"],"type":"object"}}},"#,
    r#""fallbacks":"default"}"#
);

#[test]
fn request_body_is_pinned() {
    let body = model::request_body("claude-opus-5-5", &pin_envelope());
    let want = PINNED_BODY.replace("<SYSTEM>", &serde_json::to_string(SYSTEM_PROMPT).unwrap());
    assert_eq!(String::from_utf8(body.clone()).unwrap(), want);
    assert_eq!(sha256_hex(SYSTEM_PROMPT.as_bytes()), PROMPT_SHA256);
    // No thinking, no sampling parameters.
    let v: Value = serde_json::from_slice(&body).unwrap();
    for k in ["thinking", "temperature", "top_p", "top_k", "stream"] {
        assert!(v.get(k).is_none(), "{k} must not be sent");
    }
    // The content is the canonical envelope, byte for byte.
    let content = v["messages"][0]["content"].as_str().unwrap();
    assert_eq!(content.as_bytes(), pin_envelope().canonical());
    // The schema is the wire form of PLAN_SCHEMA (ruling P47-30): no
    // keyword the API refuses.
    let schema: Value = serde_json::from_slice(&model::wire_schema()).unwrap();
    assert_eq!(v["output_config"]["format"]["schema"], schema);
    let text = String::from_utf8(body).unwrap();
    for k in [
        "maxLength",
        "minLength",
        "minimum",
        "maximum",
        "maxItems",
        "oneOf",
    ] {
        assert!(!text.contains(k), "{k}");
    }
}

#[tokio::test]
async fn headers_are_pinned() {
    let f = default_fx();
    let p = pki();
    let (port, s) = server(&p, vec![ok_answer()]).await;
    let r = f.plan(&planner_for(&p, port)).await.unwrap();
    assert_eq!(r.intent, "count the customers in each city");
    let seen = s.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let q = &seen[0];
    assert_eq!(q.method, "POST");
    assert_eq!(q.path, "/v1/messages");
    let h = |n: &str| q.headers.get(n).map(|v| v.to_str().unwrap().to_string());
    assert_eq!(h("x-api-key"), Some(fake_key()));
    assert_eq!(h("anthropic-version").as_deref(), Some("2026-10-21"));
    assert_eq!(
        h("anthropic-beta").as_deref(),
        Some("server-side-fallback-2026-07-01")
    );
    assert_eq!(h("content-type").as_deref(), Some("application/json"));
    assert!(h("authorization").is_none(), "never a bearer token");
    assert_eq!(
        q.body.as_ref(),
        model::request_body("claude-opus-5-5", &f.env).as_slice()
    );
    // The outbox holds the exact body; the records say what went and came.
    let ob = f.outbox_lines();
    assert_eq!(ob.len(), 1);
    assert_eq!(ob[0]["body"].as_str().unwrap().as_bytes(), q.body.as_ref());
    assert_eq!(ob[0]["sha256"], sha256_hex(&q.body));
    assert_eq!(ob[0]["ask"], "ask-1");
    let send = f.records("blind_send");
    assert_eq!(send.len(), 1);
    assert_eq!(send[0]["body_sha256"], sha256_hex(&q.body));
    assert_eq!(
        send[0]["prompt_sha256"],
        sha256_hex(SYSTEM_PROMPT.as_bytes())
    );
    assert_eq!(send[0]["envelope_sha256"], f.env.sha256());
    assert_eq!(send[0]["model"], "claude-opus-5-5");
    assert_eq!(send[0]["attempt"], 1);
    let recv = f.records("blind_receive");
    assert_eq!(recv.len(), 1);
    assert_eq!(recv[0]["status"], 200);
    assert_eq!(recv[0]["leak"], false);
    assert_eq!(recv[0]["stop_reason"], "end_turn");
    let m = f.records("model");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0]["credential"], "daemon");
    assert_eq!(m[0]["blind_ask"], "ask-1");
    assert_eq!(m[0]["model"], "claude-opus-5-5");
    assert_eq!(m[0]["served_model"], "claude-opus-4-8");
    assert!(m[0].get("box").is_none());
    // Nothing logged holds the key or the body.
    let raw = raw_log(&f.audit);
    assert!(!raw.contains(&fake_key()));
    assert!(!raw.contains(QUESTION));
}

fn raw_log(audit: &Path) -> String {
    let mut out = String::new();
    for e in std::fs::read_dir(audit).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            out.push_str(&String::from_utf8_lossy(&std::fs::read(&p).unwrap()));
        }
    }
    out
}

#[tokio::test]
async fn outbox_failure_blocks_send() {
    let f = default_fx();
    // The outbox cannot be written: its path is a file, not a dir.
    std::fs::write(f.outbox_dir(), b"not a dir").unwrap();
    let p = pki();
    let (port, s) = server(&p, vec![ok_answer()]).await;
    let e = f.plan(&planner_for(&p, port)).await.unwrap_err();
    assert!(matches!(e, PlanError::Unrecorded(_)), "{e:?}");
    assert_eq!(s.count(), 0, "nothing may reach the upstream");
    assert!(f.records("blind_send").is_empty());
}

/// R-C9a: once the request left, a record that fails means the reply is
/// not used; it is never told as "nothing sent".
#[tokio::test]
async fn reply_record_failure_is_not_nothing_sent() {
    let f = default_fx();
    let p = pki();
    let (port, s) = server(&p, vec![ok_answer()]).await;
    *s.stop_writer.lock().unwrap() = Some(f.ctx.writer.clone());
    let e = f.plan(&planner_for(&p, port)).await.unwrap_err();
    assert_eq!(e, PlanError::ReplyUnrecorded);
    assert_eq!(
        e.to_string(),
        "the planner's reply could not be recorded, so it was not used"
    );
    assert_eq!(s.count(), 1, "the request did leave");
}

#[tokio::test]
async fn record_failure_blocks_send() {
    let f = default_fx();
    f.ctx.writer.stop(None).await.unwrap();
    let p = pki();
    let (port, s) = server(&p, vec![ok_answer()]).await;
    let e = f.plan(&planner_for(&p, port)).await.unwrap_err();
    assert!(matches!(e, PlanError::Unrecorded(_)), "{e:?}");
    assert_eq!(s.count(), 0, "nothing may reach the upstream");
}

#[tokio::test]
async fn blocked_bytes_never_sent() {
    let f = default_fx();
    let p = pki();
    let (port, s) = server(&p, vec![ok_answer()]).await;
    // The envelope passes; the frame around it carries a rare name.
    let tampered = format!("{SYSTEM_PROMPT} {RARE_FIRST} {RARE_LAST}");
    let pl = planner_for(&p, port).with_test_prompt(&tampered);
    let e = f.plan(&pl).await.unwrap_err();
    let PlanError::Blocked(hits) = e else {
        panic!("not blocked: {e:?}");
    };
    assert!(hits.iter().any(|h| h.part == "frame"), "{hits:?}");
    assert_eq!(s.count(), 0);
    assert!(f.outbox_lines().is_empty());
    // A blocked envelope is blocked before any body exists.
    let mut f2 = default_fx();
    f2.env.question = format!("how many orders has {RARE_FIRST} {RARE_LAST}");
    let e = f2.plan(&planner_for(&p, port)).await.unwrap_err();
    assert!(matches!(e, PlanError::Blocked(_)), "{e:?}");
    assert_eq!(s.count(), 0);
}

#[tokio::test]
async fn refusal_stop_reason() {
    let f = default_fx();
    let p = pki();
    let (port, s) = server(&p, vec![answer("refusal", json!([])), ok_answer()]).await;
    let e = f.plan(&planner_for(&p, port)).await.unwrap_err();
    assert_eq!(e, PlanError::Refused);
    assert_eq!(s.count(), 1, "a refusal is never retried");
    assert_eq!(f.records("blind_receive")[0]["stop_reason"], "refusal");
    // max_tokens is Truncated; another reason is a bad reply; end_turn with
    // no text block is a bad reply.
    let (port, _) = server(&p, vec![answer("max_tokens", json!([]))]).await;
    assert_eq!(
        f.plan(&planner_for(&p, port)).await.unwrap_err(),
        PlanError::Truncated
    );
    let (port, _) = server(&p, vec![answer("tool_use", json!([]))]).await;
    assert!(matches!(
        f.plan(&planner_for(&p, port)).await.unwrap_err(),
        PlanError::BadReply(_)
    ));
    let (port, _) = server(
        &p,
        vec![answer(
            "end_turn",
            json!([{"type": "thinking", "thinking": ""}]),
        )],
    )
    .await;
    assert!(matches!(
        f.plan(&planner_for(&p, port)).await.unwrap_err(),
        PlanError::BadReply(_)
    ));
}

#[tokio::test]
async fn retry_on_429_once() {
    let f = default_fx();
    let p = pki();
    let busy = (429, vec![("retry-after", "0".to_string())], String::new());
    let (port, s) = server(&p, vec![busy.clone(), ok_answer()]).await;
    f.plan(&planner_for(&p, port)).await.unwrap();
    assert_eq!(s.count(), 2);
    // Each request has its own outbox entry and records.
    assert_eq!(f.outbox_lines().len(), 2);
    let sends = f.records("blind_send");
    assert_eq!(sends.len(), 2);
    assert_eq!(sends[1]["attempt"], 2);
    assert_eq!(f.records("blind_receive").len(), 2);
    assert_eq!(f.records("model").len(), 2);
    // Two in a row: one retry only.
    let five = (503, vec![("retry-after", "0".to_string())], String::new());
    let (port, s) = server(&p, vec![busy, five, ok_answer()]).await;
    assert_eq!(
        f.plan(&planner_for(&p, port)).await.unwrap_err(),
        PlanError::Http(503)
    );
    assert_eq!(s.count(), 2);
    // Another status is not retried.
    let (port, s) = server(&p, vec![(400, vec![], String::new())]).await;
    assert_eq!(
        f.plan(&planner_for(&p, port)).await.unwrap_err(),
        PlanError::Http(400)
    );
    assert_eq!(s.count(), 1);
}

#[tokio::test]
async fn incoming_leak_refuses() {
    let f = default_fx();
    let p = pki();
    let leak = json!({
        "method": format!("SELECT COUNT(*) AS n FROM customers t WHERE t.email = '{EMAIL}'"),
        "template": "{int(n)}",
        "intent": "count",
    })
    .to_string();
    let (port, _) = server(
        &p,
        vec![answer("end_turn", json!([{"type": "text", "text": leak}]))],
    )
    .await;
    let e = f.plan(&planner_for(&p, port)).await.unwrap_err();
    let PlanError::Leak(hits) = e else {
        panic!("not a leak: {e:?}");
    };
    assert!(hits.iter().any(|h| h.part == "method"), "{hits:?}");
    let r = f.records("blind_receive");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["leak"], true);
    assert!(!raw_log(&f.audit).contains(EMAIL));
    // A reply that does not parse is still scanned.
    let junk = format!("I think it is {RARE_FIRST} {RARE_LAST}");
    let (port, _) = server(
        &p,
        vec![answer("end_turn", json!([{"type": "text", "text": junk}]))],
    )
    .await;
    assert!(matches!(
        f.plan(&planner_for(&p, port)).await.unwrap_err(),
        PlanError::Leak(_)
    ));
}

const NO_KEY_HINT: &str = "saiife secret add blind-key --kind token --service blind-model";

#[tokio::test]
async fn no_key_refuses() {
    let p = pki();
    let (port, s) = server(&p, vec![ok_answer(), ok_answer()]).await;
    // Missing.
    let f = fx(None);
    let e = f.plan(&planner_for(&p, port)).await.unwrap_err();
    let PlanError::NoKey(text) = e else {
        panic!("{e:?}");
    };
    assert!(text.contains(NO_KEY_HINT), "{text}");
    // Not allowing blind-model.
    let f = fx(Some(token_entry(
        SECRET,
        Kind::Token,
        "token",
        &["box-model"],
    )));
    let e = f.plan(&planner_for(&p, port)).await.unwrap_err();
    let PlanError::NoKey(text) = e else {
        panic!("{e:?}");
    };
    assert!(text.contains(NO_KEY_HINT), "{text}");
    assert_eq!(s.count(), 0);
    assert!(f.outbox_lines().is_empty());
}

/// Ruling P47-32: what can fail before the send fails before the outbox
/// and the `blind_send` record, so nothing says a request went out.
#[tokio::test]
async fn nothing_recorded_when_send_cannot_start() {
    let p = pki();
    let (port, s) = server(&p, vec![ok_answer()]).await;
    // A key that is not a usable header value.
    let mut e = token_entry(SECRET, Kind::Token, "token", &["blind-model"]);
    e.fields.insert(
        "token".into(),
        Zeroizing::new(format!("{}\u{1}x", fake_key())),
    );
    let f = fx(Some(e));
    let r = f.plan(&planner_for(&p, port)).await.unwrap_err();
    assert!(matches!(r, PlanError::NoKey(_)), "{r:?}");
    assert!(f.outbox_lines().is_empty());
    assert!(f.records("blind_send").is_empty());
    assert_eq!(s.count(), 0);
    // No upstream client: the context of a test has none.
    let f = default_fx();
    let r = f.plan(&AnthropicPlanner::new()).await.unwrap_err();
    assert_eq!(r, PlanError::Unreachable);
    assert!(f.outbox_lines().is_empty());
    assert!(f.records("blind_send").is_empty());
    assert!(f.records("model").is_empty());
    assert_eq!(s.count(), 0);
}

#[tokio::test]
async fn subscription_never_used() {
    let p = pki();
    let (port, s) = server(&p, vec![ok_answer()]).await;
    for e in [
        token_entry(SECRET, Kind::OAuth2, "refresh_token", &["blind-model"]),
        token_entry(SECRET, Kind::Basic, "password", &["blind-model"]),
        token_entry(SECRET, Kind::Header, "token", &["blind-model"]),
    ] {
        let f = fx(Some(e));
        let r = f.plan(&planner_for(&p, port)).await.unwrap_err();
        assert!(matches!(r, PlanError::NoKey(_)), "{r:?}");
    }
    // A token secret holding a subscription (OAuth) token.
    let mut e = token_entry(SECRET, Kind::Token, "token", &["blind-model"]);
    e.fields.insert(
        "token".into(),
        Zeroizing::new(format!("{}{}", concat!("sk-", "ant-", "oat"), "01-test")),
    );
    let f = fx(Some(e));
    let r = f.plan(&planner_for(&p, port)).await.unwrap_err();
    assert!(matches!(r, PlanError::NoKey(_)), "{r:?}");
    assert_eq!(s.count(), 0);
}

#[tokio::test]
async fn fake_planner_scripts_replies() {
    let f = default_fx();
    let second = json!({
        "method": "SELECT COUNT(*) AS n FROM customers t",
        "template": "{int(n)}",
        "intent": "count all customers",
    })
    .to_string();
    let file = f.root.join("replies.jsonl");
    std::fs::write(&file, format!("{}\n{second}\n", good_reply())).unwrap();
    let fake = FakePlanner::from_file(&file).unwrap();
    assert_eq!(
        f.plan(&fake).await.unwrap().intent,
        "count the customers in each city"
    );
    assert_eq!(f.plan(&fake).await.unwrap().intent, "count all customers");
    assert!(matches!(
        f.plan(&fake).await.unwrap_err(),
        PlanError::BadReply(_)
    ));
    // The same order as the real one: outbox, records.
    assert_eq!(f.outbox_lines().len(), 3);
    assert_eq!(f.records("blind_send").len(), 3);
    assert_eq!(f.records("blind_receive").len(), 3);
    // The fake runs the firewall too.
    let leak = json!({"method": format!("SELECT '{EMAIL}'"), "template": "", "intent": "x"});
    let fake = FakePlanner::new(vec![leak.to_string()]);
    assert!(matches!(
        f.plan(&fake).await.unwrap_err(),
        PlanError::Leak(_)
    ));
    // And a blocked envelope never reaches it.
    let fake = FakePlanner::new(vec![good_reply()]);
    let mut f2 = default_fx();
    f2.env.question = format!("{QUESTION} {EMAIL}");
    assert!(matches!(
        f2.plan(&fake).await.unwrap_err(),
        PlanError::Blocked(_)
    ));
    assert!(f2.outbox_lines().is_empty());
}

/// Owner smoke only: one fixture envelope to the real API.
#[tokio::test]
#[ignore]
async fn live_planner_answers() {
    let key_file = std::env::var_os("SAIIFE_BLIND_LIVE_KEY_FILE")
        .expect("SAIIFE_BLIND_LIVE_KEY_FILE names a file holding the API key");
    let key = std::fs::read_to_string(key_file).unwrap();
    let mut e = token_entry(SECRET, Kind::Token, "token", &["blind-model"]);
    e.fields
        .insert("token".into(), Zeroizing::new(key.trim().to_string()));
    let f = fx(Some(e));
    let up = Upstream::with_ca_dir(None, Duration::from_secs(300)).unwrap();
    // The production URL; the ctx has no upstream in tests, so pass one.
    let pl = AnthropicPlanner::with_test_upstream("https://api.anthropic.com", up);
    let r = f.plan(&pl).await.expect("the planner answers");
    let s = schema(41);
    saiife_shield::sql::validate(&r.method, &s, &[], &[]).expect("the method validates");
}
