//! The Data Shield touches (plan 48 Task 3; R48-6, R48-8, R-C5, R-C12):
//! `blind.touch.begin` and `blind.touch.commit` for `blind:name`,
//! `blind:approve`, `blind:keys` and `blind:loosen`, with a soft key. A
//! context in `$SAIIFE_TEST_TMP` over plan 43's synthetic fixture (made-up
//! people only), as in `blind_ask.rs`; the planner is a scripted fake and
//! the name detector a fixed list.
#![cfg(target_os = "linux")]

#[path = "../../shield/tests/fixtures.rs"]
mod fixtures;

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::audit_query::{self, Scope};
use saiife_daemon::blind::model::FakePlanner;
use saiife_daemon::blind::{ask, touch, DatasetState};
use saiife_daemon::ops::{Conn, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::vault;
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::{
    Request, OP_BLIND_ASK, OP_BLIND_ASK_ANSWER, OP_BLIND_DATA_COMMIT, OP_BLIND_DATA_REFRESH,
    OP_BLIND_DATA_STAGE, OP_BLIND_TOUCH_BEGIN, OP_BLIND_TOUCH_COMMIT,
};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, FixedDirectory, Fsync};
use saiife_shield::dataset::{stage_snapshot, DatasetDir};
use saiife_shield::methods::{MethodStatus, MethodStore};
use saiife_shield::ner::{ListDetector, SpanLabel};
use saiife_shield::question::{self, template_key};
use saiife_shield::schema::{DatasetName, Lang};
use saiife_touch::soft::SoftAuthenticator;
use saiife_touch::{TouchRequest, LOCAL_RP_ID};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const OWN: u32 = 1000;
const OTHER: u32 = 1001;
const PASSWD: &str = "me:x:1000:1000::/home/me:/bin/sh\nyou:x:1001:1001::/home/you:/bin/sh\n";

const M_BAL: &str = "SELECT SUM(i.amount) AS owed, COUNT(*) AS n FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1";
const T_BAL: &str = "{param(p1)} owes {money(owed, NOK)} across {int(n)} invoices.";
const ANSWER_ANNA: &str = "Anna Berg owes 19,419.00 NOK across 4 invoices.";
/// A method with no parameter, for a question whose name was kept.
const M_COUNT: &str = "SELECT COUNT(*) AS n FROM customers c";
const T_COUNT: &str = "There are {int(n)} customers.";

const Q_ANNA: &str = "What is the balance of Anna Berg?";
const Q_STRANGER: &str = "What is the balance of Zed Quorra?";

/// Users and approvers for the locked tests: `you` asks, only `me`
/// approves.
const BOTH: &str = "users = [\"me\", \"you\"]\napprovers = [\"me\"]\n";
const YOU_APPROVE: &str = "users = [\"me\", \"you\"]\napprovers = [\"you\"]\n";

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

struct Fx {
    ctx: Arc<Ctx>,
    audit: PathBuf,
    root: PathBuf,
    sqlite: PathBuf,
}

/// Plan 43's fixture with customers 1 to 3 set by hand (Søren Østergård,
/// two Anna Bergs), Anna of Aarhus with four invoices of 19,419.00 in all.
fn fixture_sqlite(root: &Path) -> PathBuf {
    let csv = root.join("csv");
    std::fs::create_dir_all(&csv).unwrap();
    fixtures::write_fixture(&csv, 300, 11).unwrap();
    let path = csv.join("customers.csv");
    let mut rd = csv::Reader::from_path(&path).unwrap();
    let head = rd.headers().unwrap().clone();
    let mut rows: Vec<Vec<String>> = rd
        .records()
        .map(|r| r.unwrap().iter().map(str::to_string).collect())
        .collect();
    for r in rows.iter_mut() {
        if (r[1] == "Søren" && r[2] == "Østergård") || (r[1] == "Anna" && r[2] == "Berg") {
            r[2] = "Hansen".into();
        }
    }
    for (i, (first, last, city)) in [
        ("Søren", "Østergård", "København"),
        ("Anna", "Berg", "Aarhus"),
        ("Anna", "Berg", "Odense"),
    ]
    .into_iter()
    .enumerate()
    {
        rows[i][1] = first.into();
        rows[i][2] = last.into();
        rows[i][5] = city.into();
    }
    let mut w = csv::Writer::from_path(&path).unwrap();
    w.write_record(&head).unwrap();
    for r in &rows {
        w.write_record(r).unwrap();
    }
    w.flush().unwrap();
    drop(w);
    set_invoices(&csv.join("invoices.csv"));
    let mut src = fixtures::MultiSource::csv_dir(&csv).unwrap();
    let dir = DatasetDir {
        root: root.join("make").join("crm"),
    };
    let info = stage_snapshot(&dir, &mut src, &mut |_| {}).unwrap();
    let out = root.join("crm.sqlite");
    std::fs::copy(&info.path, &out).unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600)).unwrap();
    out
}

fn set_invoices(path: &Path) {
    let mut rd = csv::Reader::from_path(path).unwrap();
    let head = rd.headers().unwrap().clone();
    let mut rows: Vec<Vec<String>> = rd
        .records()
        .map(|r| r.unwrap().iter().map(str::to_string).collect())
        .filter(|r: &Vec<String>| !["1", "2", "3"].contains(&r[1].as_str()))
        .collect();
    let mut id = 100_000;
    for (amount, status, issued) in [
        ("6000.00", "open", "2025-02-03"),
        ("7000.00", "open", "2025-03-04"),
        ("5420.00", "open", "2025-04-05"),
        ("999.00", "paid", "2025-01-02"),
    ] {
        id += 1;
        let r = [&id.to_string(), "2", amount, status, issued, ""];
        rows.push(r.iter().map(|s| s.to_string()).collect());
    }
    let mut w = csv::Writer::from_path(path).unwrap();
    w.write_record(&head).unwrap();
    for r in &rows {
        w.write_record(r).unwrap();
    }
    w.flush().unwrap();
}

const COLUMNS: &[(&str, &str)] = &[
    ("customers.id", "identifier"),
    ("customers.first_name", "identifier"),
    ("customers.last_name", "identifier"),
    ("customers.email", "identifier"),
    ("customers.phone", "identifier"),
    ("customers.city", "quasi"),
    ("customers.postcode", "quasi"),
    ("customers.birth_date", "quasi"),
    ("customers.segment", "quasi"),
    ("customers.credit_limit", "sensitive"),
    ("customers.ref_code", "identifier"),
    ("invoices.id", "identifier"),
    ("invoices.customer_id", "identifier"),
    ("invoices.amount", "sensitive"),
    ("invoices.status", "public"),
    ("invoices.issued", "quasi"),
    ("invoices.notes", "free_text"),
];

fn ner_section() -> String {
    let h = "a".repeat(64);
    format!(
        "[blind.ner]\nmodel_url = \"https://example.invalid/model.onnx\"\nmodel_sha256 = \"{h}\"\n\
         vocab_url = \"https://example.invalid/vocab.txt\"\nvocab_sha256 = \"{h}\"\n\
         labels_url = \"https://example.invalid/labels.json\"\nlabels_sha256 = \"{h}\"\n\n"
    )
}

/// The policy naming `crm` (`extra`: users, approvers), with `classes`
/// overriding [`COLUMNS`]; `dataset: false` leaves it out of policy.
fn policy(extra: &str, classes: &[(&str, &str)], dataset: bool) -> String {
    let mut s = String::from("version = 2\n\n");
    s.push_str(&ner_section());
    if !dataset {
        return s;
    }
    s.push_str(
        "[[blind.dataset]]\nname = \"crm\"\n\
         source = { kind = \"sqlite\", file_name = \"crm.sqlite\" }\n",
    );
    s.push_str(extra);
    s.push_str("\n[blind.dataset.columns]\n");
    for (c, class) in COLUMNS {
        let class = classes
            .iter()
            .find(|(k, _)| k == c)
            .map_or(*class, |(_, v)| *v);
        s.push_str(&format!("\"{c}\" = {{ class = \"{class}\" }}\n"));
    }
    s.push_str(
        "\n[[blind.dataset.entity]]\ntable = \"customers\"\nkey = \"id\"\n\
         names = [\"first_name\", \"last_name\"]\nshow = [\"city\", \"email\"]\n\
         word = \"customer\"\nword_da = \"kunde\"\n",
    );
    s
}

fn set_policy(f: &Fx, text: &str) {
    let path = f.root.join("config.toml");
    std::fs::write(&path, text).unwrap();
    let l = saiife_policy::load_system(&path).unwrap();
    *f.ctx.policy.lock().unwrap() =
        PolicyState::from_loaded(&l, &[], saiife_broker::Catalog::new(&[], vec![]));
}

fn detector() -> Arc<ListDetector> {
    Arc::new(ListDetector::new(&[("Zed Quorra", SpanLabel::Person)]))
}

fn calc_seam() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let exe = std::env::current_exe().unwrap();
        let p = exe.parent().unwrap().parent().unwrap().join("saiife");
        assert!(
            p.is_file(),
            "{} is missing: run `cargo build -p saiife` first",
            p.display()
        );
        std::env::set_var(saiife_daemon::blind::calc::CALC_SEAM, p);
    });
}

/// No Landlock: the method cannot run here, so the test is skipped.
fn no_calc(name: &str) -> bool {
    let none = saiife_system::sandbox::landlock_abi() == 0;
    if none {
        eprintln!("{name}: skipped: this kernel has no Landlock");
    }
    none
}

async fn fx(root: &Path, replies: &[String]) -> Fx {
    fx_mode(root, replies, Mode::Personal, "").await
}

/// A context with `crm` live; locked: the daemon is uid 999, `me` and
/// `you` are peers.
async fn fx_mode(root: &Path, replies: &[String], mode: Mode, extra: &str) -> Fx {
    let audit = root.join("audit");
    std::fs::create_dir_all(&audit).unwrap();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: mode.as_str().into(),
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
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        mode,
        own_uid: if mode == Mode::Personal { OWN } else { 999 },
        own_user: "me".into(),
        vault: vault::open_with_key(Zeroizing::new([5; 32]), &state.join("vault/vault.bin")),
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }));
    calc_seam();
    let sqlite = fixture_sqlite(root);
    let f = Fx {
        ctx,
        audit,
        root: root.to_path_buf(),
        sqlite,
    };
    f.ctx.blind.set_test_detector(Some(detector()));
    f.ctx
        .blind
        .set_test_planner(Some(Arc::new(FakePlanner::new(replies.to_vec()))));
    set_policy(&f, &policy(extra, &[], true));
    let v = call(
        &f,
        OP_BLIND_DATA_STAGE,
        json!({"dataset": "crm", "kind": "sqlite", "file_name": "crm.sqlite"}),
        vec![fd_of(&f.sqlite)],
    )
    .await;
    assert!(v.get("error").is_none(), "{v}");
    let v = call(&f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await;
    assert!(v.get("error").is_none(), "{v}");
    f
}

fn reply(method: &str, template: &str) -> String {
    json!({"method": method, "template": template, "intent": "x"}).to_string()
}

fn balance() -> String {
    reply(M_BAL, T_BAL)
}

fn peer(uid: u32) -> PeerCred {
    PeerCred {
        uid,
        gid: uid,
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

fn fd_of(p: &Path) -> OwnedFd {
    OwnedFd::from(std::fs::File::open(p).unwrap())
}

async fn call_as(f: &Fx, uid: u32, op: &str, args: Value, fds: Vec<OwnedFd>) -> Value {
    let conn = Conn::new(peer(uid), None);
    conn.fds.lock().unwrap().extend(fds);
    let Value::Object(args) = args else {
        panic!("args")
    };
    let req = Request {
        id: 7,
        op: op.into(),
        args,
    };
    Box::pin(saiife_daemon::blind::ops::handle(&f.ctx, &conn, req)).await
}

async fn call(f: &Fx, op: &str, args: Value, fds: Vec<OwnedFd>) -> Value {
    call_as(f, OWN, op, args, fds).await
}

fn err(v: &Value) -> (String, String) {
    (
        v["error"].as_str().unwrap_or_default().to_string(),
        v["message"].as_str().unwrap_or_default().to_string(),
    )
}

fn ok(v: &Value) {
    assert!(v.get("error").is_none(), "{v}");
}

fn records(f: &Fx, kind: &str) -> Vec<Value> {
    let q = audit_query::parse(&serde_json::Map::new()).unwrap();
    audit_query::run(&f.audit, Scope::All, &q)
        .unwrap()
        .records
        .into_iter()
        .filter(|r| r["kind"] == kind)
        .collect()
}

fn raw_dir(dir: &Path) -> String {
    let mut out = String::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd {
        let p = e.unwrap().path();
        if p.is_file() {
            out.push_str(&String::from_utf8_lossy(&std::fs::read(&p).unwrap()));
        }
    }
    out
}

fn outbox(f: &Fx) -> Vec<Value> {
    raw_dir(&f.ctx.blind.root.join("outbox"))
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect()
}

fn envelope_of(entry: &Value) -> Value {
    let body: Value = serde_json::from_str(entry["body"].as_str().unwrap()).unwrap();
    serde_json::from_str(body["messages"][0]["content"].as_str().unwrap()).unwrap()
}

fn crm() -> DatasetName {
    "crm".parse().unwrap()
}

fn index_key(f: &Fx) -> saiife_shield::index::IndexKey {
    saiife_daemon::blind::keys::load(&f.ctx, &crm())
        .unwrap()
        .index_key()
}

fn methods(f: &Fx) -> MethodStore {
    MethodStore::load(&f.ctx.blind.dataset_dir(&crm()).root.join("methods.json")).unwrap()
}

/// A soft key enrolled for `uid`, labelled `soft`.
fn enrol(f: &Fx, uid: u32) -> SoftAuthenticator {
    let s = SoftAuthenticator::new_es256();
    f.ctx
        .touch
        .add(s.credential(LOCAL_RP_ID, uid, "soft"))
        .unwrap();
    s
}

async fn ask_as(f: &Fx, uid: u32, q: &str) -> (String, Value) {
    let v = call_as(
        f,
        uid,
        OP_BLIND_ASK,
        json!({"question": q, "dataset": "crm", "lang": "en"}),
        vec![],
    )
    .await;
    ok(&v);
    (v["ask"].as_str().unwrap().to_string(), v["step"].clone())
}

async fn answer_as(f: &Fx, uid: u32, id: &str, a: Value) -> Value {
    let v = call_as(
        f,
        uid,
        OP_BLIND_ASK_ANSWER,
        json!({"ask": id, "answer": a}),
        vec![],
    )
    .await;
    ok(&v);
    v["step"].clone()
}

/// Anna of Aarhus' balance, asked, picked and run by `uid`: (ask id, the
/// preview step).
async fn answered(f: &Fx, uid: u32) -> (String, Value) {
    let (id, step) = ask_as(f, uid, Q_ANNA).await;
    assert_eq!(step["kind"], "pick", "{step}");
    let preview = answer_as(f, uid, &id, json!({"pick": 1})).await;
    assert_eq!(preview["kind"], "preview", "{preview}");
    let step = answer_as(f, uid, &id, json!({"run": true})).await;
    assert_eq!(step["kind"], "answer", "{step}");
    assert_eq!(step["text"], ANSWER_ANNA);
    (id, preview)
}

async fn begin_as(f: &Fx, uid: u32, args: Value) -> Value {
    call_as(f, uid, OP_BLIND_TOUCH_BEGIN, args, vec![]).await
}

/// The soft key's answer to a begin's touch request.
fn assertion(s: &SoftAuthenticator, begun: &Value) -> Value {
    let tr: TouchRequest = serde_json::from_value(begun["touch"].clone()).unwrap();
    serde_json::to_value(s.assert_ctap(LOCAL_RP_ID, &tr.challenge)).unwrap()
}

async fn commit_as(f: &Fx, uid: u32, begun: &Value, asr: &Value) -> Value {
    call_as(
        f,
        uid,
        OP_BLIND_TOUCH_COMMIT,
        json!({"request_id": begun["request_id"], "assertion": asr}),
        vec![],
    )
    .await
}

/// Begin `args` as `uid`, touch with `s`, commit: the commit's answer.
async fn touch_as(f: &Fx, uid: u32, s: &SoftAuthenticator, args: Value) -> Value {
    let b = begin_as(f, uid, args).await;
    ok(&b);
    let asr = assertion(s, &b);
    commit_as(f, uid, &b, &asr).await
}

fn summary(begun: &Value) -> String {
    begun["touch"]["summary"].as_str().unwrap().to_string()
}

/// A record's `touch`: the soft key's credential id and sign count `n`
/// (never the label, never a bare count: either can be scrubbed).
fn touched(r: &Value, n: u32) {
    let t = r["touch"]
        .as_str()
        .unwrap_or_else(|| panic!("no touch: {r}"));
    let (id, c) = t.split_once(' ').unwrap();
    assert!(
        id.len() >= 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "{t}"
    );
    assert_eq!(c, format!("c{n}"), "{t}");
}

fn pending(f: &Fx) -> usize {
    f.ctx.blind.touches.lock().unwrap().len()
}

// ---------------------------------------------------------------- tests ----

/// R48-6: the approver role before any challenge, then the touch; the
/// method is stored with the touch, the keyed preview MAC and the
/// question's own template key, and the same question reuses it with no
/// cloud call.
#[tokio::test]
async fn approve_needs_role_and_touch() {
    let t = scratch();
    let f = fx_mode(t.path(), &[balance(), balance()], Mode::Locked, BOTH).await;
    if no_calc("approve_needs_role_and_touch") {
        return;
    }
    // `you` may ask but does not approve: forbidden, no challenge.
    let _yours = enrol(&f, OTHER);
    let (yid, _) = answered(&f, OTHER).await;
    let v = begin_as(&f, OTHER, json!({"purpose": "approve", "ask": yid})).await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
    assert!(v.get("touch").is_none());
    assert_eq!(pending(&f), 0);
    // `me` approves its own answered ask.
    let s = enrol(&f, OWN);
    let (id, preview) = answered(&f, OWN).await;
    let b = begin_as(&f, OWN, json!({"purpose": "approve", "ask": id})).await;
    ok(&b);
    assert_eq!(b["class"], "blind:approve");
    let (m, h) = f.ctx.blind.live(&crm()).unwrap();
    let d = {
        let lex = h.lexicon.lock().unwrap();
        match question::parameterize(Q_ANNA, Some(Lang::En), &m.schema, &lex, &*detector()).unwrap()
        {
            question::Step::Ready(d) | question::Step::Ask(d) => d,
            question::Step::Refuse(_) => panic!("refused"),
        }
    };
    let (key, tags) = template_key(&d);
    let text = preview["text"].as_str().unwrap();
    assert_eq!(
        summary(&b),
        format!("approve for reuse: {text} · template \"{key}\"")
    );
    assert!(b["request_id"].as_str().unwrap().parse::<u64>().is_ok());
    let asr = assertion(&s, &b);
    let v = commit_as(&f, OWN, &b, &asr).await;
    ok(&v);
    let mid = v["method"].as_str().unwrap().to_string();
    let store = methods(&f);
    assert_eq!(store.methods.len(), 1);
    let am = &store.methods[0];
    assert_eq!(am.id, mid);
    assert_eq!(am.touch, "soft #1");
    assert_eq!(am.template_key, key);
    assert_eq!(am.param_tags, tags);
    assert_eq!(am.approved_by, "me");
    assert_eq!(am.status, MethodStatus::Active);
    assert_eq!(am.reply.method, M_BAL);
    let mac = saiife_daemon::blind::audit::preview_mac(&index_key(&f), text);
    assert_eq!(am.preview_mac, mac);
    let r = records(&f, "blind_approve");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0]["action"], "add");
    // The touch field is kept (never scrubbed as a known value).
    let sc: Vec<Value> = records(&f, "blind_log_scrubbed")
        .into_iter()
        .filter(|r| r["scrubbed_kind"] == "blind_approve")
        .collect();
    assert!(sc.is_empty(), "{sc:?}");
    assert_eq!(r[0]["method"], mid.as_str());
    touched(&r[0], 1);
    // The approved ask is done.
    let v = begin_as(&f, OWN, json!({"purpose": "approve", "ask": id})).await;
    assert_eq!(
        err(&v),
        ("bad_request".to_string(), ask::NO_SUCH_ASK.to_string())
    );
    // The same question reuses it: no new outbox entry.
    let sent = outbox(&f).len();
    let (id2, _) = ask_as(&f, OWN, Q_ANNA).await;
    let p = answer_as(&f, OWN, &id2, json!({"pick": 1})).await;
    assert_eq!(p["approved"], mid.as_str(), "{p}");
    assert_eq!(outbox(&f).len(), sent);
    // A reused answer is approved already.
    let step = answer_as(&f, OWN, &id2, json!({"run": true})).await;
    assert_eq!(step["kind"], "answer", "{step}");
    let v = begin_as(&f, OWN, json!({"purpose": "approve", "ask": id2})).await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    assert!(err(&v).1.contains("approved already"), "{v}");
}

/// R48-6: only an ask that ended with a checked answer.
#[tokio::test]
async fn approve_needs_answered_ask() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let _s = enrol(&f, OWN);
    let (id, step) = ask_as(&f, OWN, Q_ANNA).await;
    assert_eq!(step["kind"], "pick");
    let v = begin_as(&f, OWN, json!({"purpose": "approve", "ask": id})).await;
    assert_eq!(
        err(&v),
        ("bad_request".to_string(), touch::NOT_ANSWERED.to_string())
    );
    let p = answer_as(&f, OWN, &id, json!({"pick": 1})).await;
    assert_eq!(p["kind"], "preview");
    let v = begin_as(&f, OWN, json!({"purpose": "approve", "ask": id})).await;
    assert_eq!(
        err(&v),
        ("bad_request".to_string(), touch::NOT_ANSWERED.to_string())
    );
    // Another uid's ask is not theirs to approve; an unknown one is gone.
    let v = begin_as(&f, OTHER, json!({"purpose": "approve", "ask": id})).await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
    let v = begin_as(
        &f,
        OWN,
        json!({"purpose": "approve", "ask": "0".repeat(32)}),
    )
    .await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    assert_eq!(pending(&f), 0);
    assert!(methods(&f).methods.is_empty());
}

/// R-C12 (T2 M6): the approver role is checked again at commit; a role
/// lost between begin and commit ends the ask and approves nothing.
#[tokio::test]
async fn approve_rechecks_the_role_at_commit() {
    let t = scratch();
    let f = fx_mode(t.path(), &[balance()], Mode::Locked, BOTH).await;
    if no_calc("approve_rechecks_the_role_at_commit") {
        return;
    }
    let s = enrol(&f, OWN);
    let (id, _) = answered(&f, OWN).await;
    let b = begin_as(&f, OWN, json!({"purpose": "approve", "ask": id})).await;
    ok(&b);
    set_policy(&f, &policy(YOU_APPROVE, &[], true));
    let asr = assertion(&s, &b);
    let v = commit_as(&f, OWN, &b, &asr).await;
    assert_eq!(
        err(&v),
        ("forbidden".to_string(), ask::APPROVER_LOST.to_string())
    );
    assert!(methods(&f).methods.is_empty());
    assert!(records(&f, "blind_approve").is_empty());
    let r = records(&f, "blind_check_refused");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0]["reason"], "role_lost");
    let denied = records(&f, "blind_touch");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["rule"], "role_lost");
    // The ask is gone.
    let v = begin_as(&f, OWN, json!({"purpose": "approve", "ask": id})).await;
    assert_eq!(
        err(&v),
        ("bad_request".to_string(), ask::NO_SUCH_ASK.to_string())
    );
}

/// `blind:name` (spec §2.1.7): the kept name goes to the planner as plain
/// text, the firewall lets it pass as released, the release is recorded
/// by its keyed hash only.
#[tokio::test]
async fn name_touch_continues_ask() {
    let t = scratch();
    let f = fx(t.path(), &[reply(M_COUNT, T_COUNT)]).await;
    let s = enrol(&f, OWN);
    let (id, step) = ask_as(&f, OWN, Q_STRANGER).await;
    assert_eq!(step, json!({"kind": "keep_name", "name": "Zed Quorra"}));
    // Another name than the pending one does not fit.
    let v = begin_as(
        &f,
        OWN,
        json!({"purpose": "name", "ask": id, "name": "Someone Else"}),
    )
    .await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    // Another uid may not keep it.
    let v = begin_as(
        &f,
        OTHER,
        json!({"purpose": "name", "ask": id, "name": "Zed Quorra"}),
    )
    .await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
    let b = begin_as(
        &f,
        OWN,
        json!({"purpose": "name", "ask": id, "name": "Zed Quorra"}),
    )
    .await;
    ok(&b);
    assert_eq!(b["class"], "blind:name");
    assert_eq!(
        summary(&b),
        "keep \"Zed Quorra\" as plain text in a question about crm"
    );
    let asr = assertion(&s, &b);
    let v = commit_as(&f, OWN, &b, &asr).await;
    ok(&v);
    assert_eq!(v["ask"], id.as_str());
    assert_eq!(v["step"]["kind"], "preview", "{v}");
    let ob = outbox(&f);
    assert_eq!(ob.len(), 1);
    let env = envelope_of(&ob[0]);
    assert!(
        env["question"].as_str().unwrap().contains("Zed Quorra"),
        "{env}"
    );
    assert_eq!(records(&f, "blind_send").len(), 1);
    let n = records(&f, "blind_name");
    assert_eq!(n.len(), 1, "{n:?}");
    assert_eq!(n[0]["ask"], id.as_str());
    touched(&n[0], 1);
    let mac = saiife_daemon::blind::audit::name_sha256(&index_key(&f), "Zed Quorra");
    assert_eq!(n[0]["name_sha256"], mac.as_str());
    assert_eq!(records(&f, "blind_resolve")[0]["kept_names"], 1);
    // The log holds the keyed hash only; the question shows the mark.
    let logs = raw_dir(&f.audit);
    assert!(!logs.contains("Zed") && !logs.contains("Quorra"));
    let q = &records(&f, "blind_ask")[0]["question"];
    assert_eq!(q, "What is the balance of [kept name]?");
}

/// `blind:keys` (R47-2, ruling P47-4): rotate, then delete, each recorded
/// in `blind_keys` with the touch; a dataset that left policy between
/// begin and commit is refused (R-C12).
#[tokio::test]
async fn keys_rotate_and_delete_by_touch() {
    let t = scratch();
    let f = fx(t.path(), &[]).await;
    let s = enrol(&f, OWN);
    let b = begin_as(
        &f,
        OWN,
        json!({"purpose": "keys", "dataset": "crm", "action": "rotate"}),
    )
    .await;
    ok(&b);
    assert_eq!(b["class"], "blind:keys");
    assert_eq!(summary(&b), "rotate the stand-in key of crm");
    let v = commit_as(&f, OWN, &b, &assertion(&s, &b)).await;
    ok(&v);
    assert_eq!(v["version"], 2, "{v}");
    let k = saiife_daemon::blind::keys::load(&f.ctx, &crm()).unwrap();
    assert_eq!(k.version, 2);
    let r = records(&f, "blind_keys");
    let rot: Vec<&Value> = r.iter().filter(|x| x["action"] == "rotate").collect();
    assert_eq!(rot.len(), 1, "{r:?}");
    assert_eq!(rot[0]["version"], 2);
    touched(rot[0], 1);
    // Bad args are refused before a challenge.
    let v = begin_as(
        &f,
        OWN,
        json!({"purpose": "keys", "dataset": "crm", "action": "burn"}),
    )
    .await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    // R-C12: the dataset left policy before the commit.
    let b = begin_as(
        &f,
        OWN,
        json!({"purpose": "keys", "dataset": "crm", "action": "delete"}),
    )
    .await;
    ok(&b);
    set_policy(&f, &policy("", &[], false));
    let v = commit_as(&f, OWN, &b, &assertion(&s, &b)).await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
    assert!(err(&v).1.contains("no longer in policy"), "{v}");
    assert!(saiife_daemon::blind::keys::load(&f.ctx, &crm()).is_ok());
    // Back in policy: the delete.
    set_policy(&f, &policy("", &[], true));
    let v = touch_as(
        &f,
        OWN,
        &s,
        json!({"purpose": "keys", "dataset": "crm", "action": "delete"}),
    )
    .await;
    ok(&v);
    assert!(saiife_daemon::blind::keys::load(&f.ctx, &crm()).is_err());
    assert!(!f
        .ctx
        .blind
        .dataset_dir(&crm())
        .root
        .join("keys.sealed")
        .exists());
    assert!(matches!(
        f.ctx.blind.state(&crm()),
        DatasetState::NeedsRefresh(_)
    ));
    let del: Vec<Value> = records(&f, "blind_keys")
        .into_iter()
        .filter(|x| x["action"] == "delete")
        .collect();
    assert_eq!(del.len(), 1, "{del:?}");
    assert_eq!(del[0]["version"], 2);
    // The refused commit spent touch #2.
    touched(&del[0], 3);
}

/// `blind:approve` for `methods rm` (R48-6).
#[tokio::test]
async fn method_rm_by_touch() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    if no_calc("method_rm_by_touch") {
        return;
    }
    let s = enrol(&f, OWN);
    let (id, _) = answered(&f, OWN).await;
    let v = touch_as(&f, OWN, &s, json!({"purpose": "approve", "ask": id})).await;
    ok(&v);
    let mid = v["method"].as_str().unwrap().to_string();
    let v = begin_as(
        &f,
        OWN,
        json!({"purpose": "method_rm", "dataset": "crm", "id": "m-nope-v1"}),
    )
    .await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    let b = begin_as(
        &f,
        OWN,
        json!({"purpose": "method_rm", "dataset": "crm", "id": mid}),
    )
    .await;
    ok(&b);
    assert_eq!(b["class"], "blind:approve");
    assert!(summary(&b).starts_with(&format!("remove approved method {mid} ")));
    let v = commit_as(&f, OWN, &b, &assertion(&s, &b)).await;
    ok(&v);
    assert_eq!(v["removed"], true);
    assert!(methods(&f).methods.is_empty());
    let r = records(&f, "blind_approve");
    assert_eq!(r.len(), 2, "{r:?}");
    assert_eq!(r[1]["action"], "remove");
    assert_eq!(r[1]["method"], mid.as_str());
}

/// R48-8: a `blind:loosen` grant, then the policy loosened and a refresh:
/// the granted column takes the new class and the grant is spent; a
/// column loosened in policy without a grant keeps its class (warning).
/// A stricter class needs no touch; names and IDs are never public.
#[tokio::test]
async fn loosen_grant_then_refresh_applies() {
    let t = scratch();
    let f = fx(t.path(), &[]).await;
    let s = enrol(&f, OWN);
    let v = begin_as(
        &f,
        OWN,
        json!({"purpose": "loosen", "dataset": "crm", "column": "customers.email", "to": "public"}),
    )
    .await;
    assert_eq!(
        err(&v),
        (
            "bad_request".to_string(),
            "customers.email cannot be public: it holds names or IDs".to_string()
        )
    );
    let v = begin_as(
        &f,
        OWN,
        json!({"purpose": "loosen", "dataset": "crm", "column": "customers.city", "to": "sensitive"}),
    )
    .await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    assert!(err(&v).1.contains("not looser"), "{v}");
    let v = begin_as(
        &f,
        OWN,
        json!({"purpose": "loosen", "dataset": "crm", "column": "customers.nope", "to": "quasi"}),
    )
    .await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    assert_eq!(pending(&f), 0);
    let b = begin_as(
        &f,
        OWN,
        json!({"purpose": "loosen", "dataset": "crm", "column": "customers.credit_limit", "to": "quasi"}),
    )
    .await;
    ok(&b);
    assert_eq!(b["class"], "blind:loosen");
    assert_eq!(
        summary(&b),
        "make customers.credit_limit quasi (now sensitive)"
    );
    let v = commit_as(&f, OWN, &b, &assertion(&s, &b)).await;
    ok(&v);
    let root = f.ctx.blind.dataset_dir(&crm()).root;
    let grants: Value =
        serde_json::from_slice(&std::fs::read(root.join("loosen.json")).unwrap()).unwrap();
    assert_eq!(grants["grants"].as_array().unwrap().len(), 1, "{grants}");
    assert_eq!(grants["grants"][0]["column"], "customers.credit_limit");
    assert_eq!(grants["grants"][0]["class"], "quasi");
    assert_eq!(grants["grants"][0]["by"], "me");
    let r = records(&f, "blind_loosen");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0]["from"], "sensitive");
    assert_eq!(r[0]["to"], "quasi");
    touched(&r[0], 1);
    // The CLI writes policy (both loosened), then refreshes.
    set_policy(
        &f,
        &policy(
            "",
            &[
                ("customers.credit_limit", "quasi"),
                ("invoices.amount", "quasi"),
            ],
            true,
        ),
    );
    let v = call(
        &f,
        OP_BLIND_DATA_REFRESH,
        json!({"dataset": "crm"}),
        vec![fd_of(&f.sqlite)],
    )
    .await;
    assert_eq!(v["started"], true, "{v}");
    f.ctx.blind.test_wait_builds().await;
    assert!(
        f.ctx.blind.live(&crm()).is_ok(),
        "{:?}",
        f.ctx.blind.state(&crm())
    );
    let classes: Value =
        serde_json::from_slice(&std::fs::read(root.join("classes.json")).unwrap()).unwrap();
    assert_eq!(classes["customers.credit_limit"], "quasi");
    assert_eq!(classes["invoices.amount"], "sensitive");
    let grants: Value =
        serde_json::from_slice(&std::fs::read(root.join("loosen.json")).unwrap()).unwrap();
    assert!(grants["grants"].as_array().unwrap().is_empty(), "{grants}");
    let w = saiife_daemon::blind::data::warnings(&f.ctx, &crm());
    assert_eq!(
        w,
        ["invoices.amount was made quasi in policy without a blind:loosen touch; still sensitive"]
    );
}

/// Touch challenges are bound to the uid: another uid's commit is
/// `touch_mismatch` and leaves the owner's touch to commit.
#[tokio::test]
async fn other_uid_cannot_answer() {
    let t = scratch();
    let f = fx(t.path(), &[]).await;
    let s = enrol(&f, OWN);
    let _o = enrol(&f, OTHER);
    let b = begin_as(
        &f,
        OWN,
        json!({"purpose": "keys", "dataset": "crm", "action": "rotate"}),
    )
    .await;
    ok(&b);
    let asr = assertion(&s, &b);
    let v = commit_as(&f, OTHER, &b, &asr).await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
    assert_eq!(v["rule"], "touch_mismatch", "{v}");
    assert_eq!(
        saiife_daemon::blind::keys::load(&f.ctx, &crm())
            .unwrap()
            .version,
        1
    );
    let v = commit_as(&f, OWN, &b, &asr).await;
    ok(&v);
    assert_eq!(v["version"], 2);
}

/// Burned on use: the same assertion again is `touch_expired`, and does
/// nothing.
#[tokio::test]
async fn touch_replay_refused() {
    let t = scratch();
    let f = fx(t.path(), &[]).await;
    let s = enrol(&f, OWN);
    let b = begin_as(
        &f,
        OWN,
        json!({"purpose": "keys", "dataset": "crm", "action": "rotate"}),
    )
    .await;
    let asr = assertion(&s, &b);
    ok(&commit_as(&f, OWN, &b, &asr).await);
    let v = commit_as(&f, OWN, &b, &asr).await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
    assert_eq!(v["rule"], "touch_expired", "{v}");
    assert_eq!(
        saiife_daemon::blind::keys::load(&f.ctx, &crm())
            .unwrap()
            .version,
        2
    );
    assert_eq!(pending(&f), 0);
    // A bad signature burns the touch too.
    let b = begin_as(
        &f,
        OWN,
        json!({"purpose": "keys", "dataset": "crm", "action": "rotate"}),
    )
    .await;
    let mut bad = assertion(&s, &b);
    let sig = bad["signature"].as_str().unwrap().to_string();
    let flipped: String = sig
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 10 {
                if c == 'A' {
                    'B'
                } else {
                    'A'
                }
            } else {
                c
            }
        })
        .collect();
    bad["signature"] = flipped.into();
    let v = commit_as(&f, OWN, &b, &bad).await;
    assert_eq!(v["rule"], "touch_failed", "{v}");
    let v = commit_as(&f, OWN, &b, &assertion(&s, &b)).await;
    assert_eq!(v["rule"], "touch_expired", "{v}");
    // The bad signature is recorded; a commit for a spent request names
    // no dataset and is not.
    let denied = records(&f, "blind_touch");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["rule"], "touch_failed");
}

/// No device: the plan's text, before any challenge.
#[tokio::test]
async fn no_device_refuses() {
    let t = scratch();
    let f = fx(t.path(), &[]).await;
    let v = begin_as(
        &f,
        OWN,
        json!({"purpose": "keys", "dataset": "crm", "action": "rotate"}),
    )
    .await;
    assert_eq!(
        err(&v),
        (
            "forbidden".to_string(),
            "refused: keys needs a touch (blind:keys) and no touch device is enrolled for you: saiife touch enrol"
                .to_string()
        )
    );
    assert_eq!(v["rule"], "touch_unavailable");
    assert_eq!(pending(&f), 0);
    // No reveal or show purpose (R-C5).
    for p in ["reveal", "show", "release"] {
        let v = begin_as(&f, OWN, json!({"purpose": p, "dataset": "crm"})).await;
        assert_eq!(err(&v).0, "bad_request", "{p}: {v}");
    }
}

/// T2 I1: a method bound through the session's context (a follow-up such
/// as "and her invoices?") only works in that session: never approved.
#[tokio::test]
async fn approve_refuses_a_context_method() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    if no_calc("approve_refuses_a_context_method") {
        return;
    }
    let _s = enrol(&f, OWN);
    answered(&f, OWN).await;
    let first = envelope_of(&outbox(&f)[0]);
    let sym = first["params"][0]["symbol"].as_str().unwrap().to_string();
    let hers = json!({
        "method": "SELECT COUNT(*) AS n FROM invoices i \
                   JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1",
        "template": "There are {int(n)} invoices for {param(p1)}.",
        "intent": "counts her invoices",
        "context": [{"name": "p1", "symbol": sym}]});
    f.ctx
        .blind
        .set_test_planner(Some(Arc::new(FakePlanner::new(vec![hers.to_string()]))));
    let (id, step) = ask_as(&f, OWN, "And her invoices?").await;
    assert_eq!(step["kind"], "preview", "{step}");
    let step = answer_as(&f, OWN, &id, json!({"run": true})).await;
    assert_eq!(
        step["text"], "There are 4 invoices for the customer.",
        "{step}"
    );
    let v = begin_as(&f, OWN, json!({"purpose": "approve", "ask": id})).await;
    assert_eq!(
        err(&v),
        ("bad_request".to_string(), touch::USES_CONTEXT.to_string())
    );
    assert_eq!(pending(&f), 0);
}
