//! Data Shield asks up to the method preview (plan 48 Task 1; R48-1,
//! R48-2, R48-2a, R48-5; controller rulings R-C2, R-C4, R-C5, R-C8 to
//! R-C11). A personal-mode context in `$SAIIFE_TEST_TMP`; the dataset is
//! plan 43's synthetic fixture (made-up people only) with three rows set by
//! hand, committed through the plan 47 ops; the planner is a scripted fake
//! and the name detector a fixed list.
#![cfg(target_os = "linux")]

#[path = "../../shield/tests/fixtures.rs"]
mod fixtures;

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::audit_query::{self, Scope};
use saiife_daemon::blind::ask;
use saiife_daemon::blind::model::FakePlanner;
use saiife_daemon::ops::{Conn, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::vault;
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::{
    Request, OP_BLIND_ASK, OP_BLIND_ASK_ANSWER, OP_BLIND_DATA_COMMIT, OP_BLIND_DATA_REFRESH,
    OP_BLIND_DATA_STAGE,
};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, FixedDirectory, Fsync};
use saiife_shield::dataset::{stage_snapshot, DatasetDir, Phase};
use saiife_shield::methods::{method_id, ApprovedMethod, MethodStatus, MethodStore};
use saiife_shield::ner::{ListDetector, SpanLabel};
use saiife_shield::plan::PlanReply;
use saiife_shield::preview::preview;
use saiife_shield::question::{self, template_key};
use saiife_shield::schema::{Bound, DatasetName, Lang, Param, ParamType};
use saiife_shield::sql::{validate, IDENTIFIER_OUTPUT_REASON};
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

/// The balance method and its template (cloud names: no aliases here).
const M_BAL: &str = "SELECT SUM(i.amount) AS owed, COUNT(*) AS n FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1";
const T_BAL: &str = "{param(p1)} owes {money(owed, NOK)} across {int(n)} invoices.";
/// A count over an amount threshold.
const M_OVER: &str = "SELECT COUNT(*) AS n FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.amount > :p2";
const T_OVER: &str = "{param(p1)} has {int(n)} invoices over {param(p2)}.";

const Q_SOREN: &str = "What is the balance of Søren Østergård?";
const Q_ANNA: &str = "What is the balance of Anna Berg?";
const Q_TYPO: &str = "What is the balance of Søren Østergåd?";
const Q_STRANGER: &str = "What is the balance of Zed Quorra?";

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

/// Plan 43's fixture with three customers set by hand: 1 Søren Østergård
/// (København), 2 Anna Berg (Aarhus), 3 Anna Berg (Odense). Any other row
/// with one of those names is renamed, so the names are unique as stated.
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
    ("invoices.status", "quasi"),
    ("invoices.issued", "quasi"),
    ("invoices.notes", "free_text"),
];

/// `[blind.ner]` pinning three files by sha256 (R-C8); never fetched here.
fn ner_section() -> String {
    let h = "a".repeat(64);
    format!(
        "[blind.ner]\nmodel_url = \"https://example.invalid/model.onnx\"\nmodel_sha256 = \"{h}\"\n\
         vocab_url = \"https://example.invalid/vocab.txt\"\nvocab_sha256 = \"{h}\"\n\
         labels_url = \"https://example.invalid/labels.json\"\nlabels_sha256 = \"{h}\"\n\n"
    )
}

/// The policy naming `crm`; the customers entity shows its city and its
/// email (an Identifier `show` column, never shown: R-C2).
fn policy_text(ner: bool, extra: &str) -> String {
    let mut s = String::from("version = 2\n\n");
    if ner {
        s.push_str(&ner_section());
    }
    s.push_str(
        "[[blind.dataset]]\nname = \"crm\"\n\
         source = { kind = \"sqlite\", file_name = \"crm.sqlite\" }\n",
    );
    s.push_str(extra);
    s.push_str("\n[blind.dataset.columns]\n");
    for (c, class) in COLUMNS {
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
    Arc::new(ListDetector::new(&[
        ("Søren Østergåd", SpanLabel::Person),
        ("Zed Quorra", SpanLabel::Person),
    ]))
}

/// A personal context with `crm` live, the detector set and `replies` as
/// the planner's script.
async fn fx(root: &Path, replies: &[String]) -> Fx {
    fx_mode(root, replies, Mode::Personal, "").await
}

/// [`fx`] in `mode` with `extra` dataset keys (users, approvers). Locked:
/// the daemon is uid 999; `me` (1000) and `you` (1001) are peers.
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
    let sqlite = fixture_sqlite(root);
    let f = Fx {
        ctx,
        audit,
        root: root.to_path_buf(),
        sqlite,
    };
    f.ctx.blind.set_test_detector(Some(detector()));
    script(&f, replies);
    set_policy(&f, &policy_text(true, extra));
    let v = stage(&f).await;
    assert!(v.get("error").is_none(), "{v}");
    let v = call(&f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await;
    assert!(v.get("error").is_none(), "{v}");
    f
}

fn script(f: &Fx, replies: &[String]) {
    f.ctx
        .blind
        .set_test_planner(Some(Arc::new(FakePlanner::new(replies.to_vec()))));
}

fn reply(method: &str, template: &str, intent: &str) -> String {
    json!({"method": method, "template": template, "intent": intent}).to_string()
}

fn balance() -> String {
    reply(M_BAL, T_BAL, "sums the invoices of the customer")
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
    saiife_daemon::blind::ops::handle(&f.ctx, &conn, req).await
}

async fn call(f: &Fx, op: &str, args: Value, fds: Vec<OwnedFd>) -> Value {
    call_as(f, OWN, op, args, fds).await
}

async fn stage(f: &Fx) -> Value {
    call(
        f,
        OP_BLIND_DATA_STAGE,
        json!({"dataset": "crm", "kind": "sqlite", "file_name": "crm.sqlite"}),
        vec![fd_of(&f.sqlite)],
    )
    .await
}

/// `blind.ask` in English: (ask id, step).
async fn ask_q(f: &Fx, q: &str) -> (String, Value) {
    ask_with(f, json!({"question": q, "dataset": "crm", "lang": "en"})).await
}

async fn ask_with(f: &Fx, args: Value) -> (String, Value) {
    let v = call(f, OP_BLIND_ASK, args, vec![]).await;
    assert!(v.get("error").is_none(), "{v}");
    (v["ask"].as_str().unwrap().to_string(), v["step"].clone())
}

async fn answer_as(f: &Fx, uid: u32, id: &str, a: Value) -> Value {
    call_as(
        f,
        uid,
        OP_BLIND_ASK_ANSWER,
        json!({"ask": id, "answer": a}),
        vec![],
    )
    .await
}

async fn answer(f: &Fx, id: &str, a: Value) -> Value {
    let v = answer_as(f, OWN, id, a).await;
    assert!(v.get("error").is_none(), "{v}");
    assert_eq!(v["ask"], id, "{v}");
    v["step"].clone()
}

fn err(v: &Value) -> (String, String) {
    (
        v["error"].as_str().unwrap_or_default().to_string(),
        v["message"].as_str().unwrap_or_default().to_string(),
    )
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

/// The envelope (the user message's content) of an outbox entry.
fn envelope_of(entry: &Value) -> Value {
    let body: Value = serde_json::from_str(entry["body"].as_str().unwrap()).unwrap();
    serde_json::from_str(body["messages"][0]["content"].as_str().unwrap()).unwrap()
}

fn crm() -> DatasetName {
    "crm".parse().unwrap()
}

/// The draft plan 44 makes of `q` on the live build (for its template key).
fn draft_of(f: &Fx, q: &str) -> question::Draft {
    let (m, h) = f.ctx.blind.live(&crm()).unwrap();
    let lex = h.lexicon.lock().unwrap();
    match question::parameterize(q, Some(Lang::En), &m.schema, &lex, &*detector()).unwrap() {
        question::Step::Ready(d) | question::Step::Ask(d) => d,
        question::Step::Refuse(_) => panic!("refused"),
    }
}

fn approved(f: &Fx, q: &str, method: &str, template: &str, status: MethodStatus) -> String {
    let (key, tags) = template_key(&draft_of(f, q));
    let id = method_id(&key, 1);
    let m = ApprovedMethod {
        id: id.clone(),
        version: 1,
        dataset: crm(),
        lang: Lang::En,
        template_key: key,
        param_tags: tags,
        reply: PlanReply {
            method: method.into(),
            template: template.into(),
            checks: vec![],
            intent: "approved".into(),
            needs_judgment: false,
        },
        preview_sha256: "0".repeat(64),
        approved_by: "me".into(),
        approved_at: "2026-11-18T00:00:00Z".into(),
        touch: "soft 1".into(),
        status,
    };
    let path = f.ctx.blind.dataset_dir(&crm()).root.join("methods.json");
    let mut store = MethodStore::load(&path).unwrap();
    store.methods.push(m);
    store.save(&path).unwrap();
    id
}

/// What plan 45 makes the preview of `method` with one customer named as
/// R-C2 says (the user's words, then the city).
fn plan45_preview(f: &Fx, method: &str, key: i64, display: &str) -> String {
    let (m, _) = f.ctx.blind.live(&crm()).unwrap();
    let ps = vec![Param {
        name: "p1".into(),
        ty: ParamType::Entity {
            table: "customers".into(),
            word: "customer".into(),
        },
        bound: Some(Bound::Keys(vec![key])),
        display: display.into(),
    }];
    let v = validate(method, &m.schema, &m.public, &ps).unwrap();
    preview(&v, &ps, &m.schema, Lang::En).text
}

fn assert_refused(step: &Value, code: &str, reason: &str) {
    assert_eq!(step["kind"], "refused", "{step}");
    assert_eq!(step["code"], code, "{step}");
    assert_eq!(step["reason"], reason, "{step}");
    assert!(
        step["head"].as_str().is_some_and(|h| !h.is_empty()),
        "{step}"
    );
}

// ---------------------------------------------------------------- tests ----

#[tokio::test]
async fn ready_question_reaches_preview() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (id, step) = ask_q(&f, Q_SOREN).await;
    assert_eq!(id.len(), 32, "16 random bytes in hex: {id}");
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(step["kind"], "preview", "{step}");
    let want = plan45_preview(&f, M_BAL, 1, "Søren Østergård, København");
    assert_eq!(step["text"], want.as_str());
    assert!(
        !want.contains("#1") && !want.contains("example.invalid"),
        "{want}"
    );
    assert_eq!(step["planner_says"], "sums the invoices of the customer");
    assert!(step.get("approved").is_none(), "{step}");
    assert!(step.get("envelope").is_none(), "{step}");
    assert_eq!(step["sent"]["params"], 1);
    assert_eq!(step["sent"]["personal_values"], 0);
    assert_eq!(step["sent"]["tables"], 2);
    // One request, recorded as plan 47 sends it.
    let ob = outbox(&f);
    assert_eq!(ob.len(), 1);
    assert_eq!(ob[0]["ask"], id.as_str());
    let env = envelope_of(&ob[0]);
    assert_eq!(env["question"], "What is the balance of :p1?");
    assert!(env["retry"].is_null(), "{env}");
    let sends = records(&f, "blind_send");
    assert_eq!(sends.len(), 1);
    assert_eq!(sends[0]["personal_values"], 0);
    assert_eq!(sends[0]["ask"], id.as_str());
    // blind_ask holds the question with its stand-in, never the name.
    let a = records(&f, "blind_ask");
    assert_eq!(a.len(), 1);
    let q = a[0]["question"].as_str().unwrap();
    assert!(q.starts_with("What is the balance of Customer_"), "{q}");
    assert!(!q.contains("Søren"), "{q}");
    assert!(a[0]["approved_method"].is_null());
    let r = records(&f, "blind_resolve");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["params"], json!([["entity:customers", 1]]));
    let p = records(&f, "blind_preview");
    assert_eq!(p.len(), 1);
    assert_eq!(p[0]["outcome"], "shown");
    assert_eq!(p[0]["fragments"], 0);
    // The preview text is never logged.
    assert!(!raw_dir(&f.audit).contains(want.as_str()));
}

#[tokio::test]
async fn show_sent_returns_the_exact_envelope() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (_, step) = ask_with(
        &f,
        json!({"question": Q_SOREN, "dataset": "crm", "lang": "en", "show_sent": true}),
    )
    .await;
    assert_eq!(step["kind"], "preview", "{step}");
    let ob = outbox(&f);
    let body: Value = serde_json::from_str(ob[0]["body"].as_str().unwrap()).unwrap();
    assert_eq!(step["envelope"], body["messages"][0]["content"]);
}

#[tokio::test]
async fn pick_then_preview() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (id, step) = ask_q(&f, Q_ANNA).await;
    assert_eq!(step["kind"], "pick", "{step}");
    assert_eq!(step["word"], "customer");
    assert_eq!(step["written"], "Anna Berg");
    assert_eq!(step["too_many"], false);
    // R-C2: the display name and the city; never the key or the email.
    assert_eq!(
        step["candidates"],
        json!([{"n": 1, "label": "Anna Berg, Aarhus"}, {"n": 2, "label": "Anna Berg, Odense"}])
    );
    assert!(outbox(&f).is_empty(), "nothing is sent before the pick");
    let step = answer(&f, &id, json!({"pick": 2})).await;
    assert_eq!(step["kind"], "preview", "{step}");
    let text = step["text"].as_str().unwrap();
    assert_eq!(text, plan45_preview(&f, M_BAL, 3, "Anna Berg, Odense"));
    assert!(text.contains("Anna Berg, Odense"), "{text}");
    assert!(!text.contains("#3") && !text.contains('@'), "{text}");
    assert_eq!(outbox(&f).len(), 1);
    let r = records(&f, "blind_resolve");
    assert_eq!(r[0]["params"], json!([["entity:customers", 2]]));
}

#[tokio::test]
async fn did_you_mean_yes_and_no() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (id, step) = ask_q(&f, Q_TYPO).await;
    assert_eq!(
        step,
        json!({"kind": "did_you_mean", "word": "customer", "written": "Søren Østergåd",
               "suggestion": "Søren Østergård, København"})
    );
    let step = answer(&f, &id, json!({"did_you_mean": true})).await;
    assert_eq!(step["kind"], "preview", "{step}");
    // The user's own words name the customer (R-C2).
    assert_eq!(
        step["text"],
        plan45_preview(&f, M_BAL, 1, "Søren Østergåd, København").as_str()
    );
    assert_eq!(records(&f, "blind_resolve")[0]["did_you_mean"], 1);
    // No: the name is unknown, so keeping it as text is the next question.
    let (id, step) = ask_q(&f, Q_TYPO).await;
    assert_eq!(step["kind"], "did_you_mean");
    let step = answer(&f, &id, json!({"did_you_mean": false})).await;
    assert_eq!(step, json!({"kind": "keep_name", "name": "Søren Østergåd"}));
    assert_eq!(outbox(&f).len(), 1);
}

#[tokio::test]
async fn keep_name_false_refuses() {
    let t = scratch();
    let f = fx(t.path(), &[]).await;
    let (id, step) = ask_q(&f, Q_STRANGER).await;
    assert_eq!(step, json!({"kind": "keep_name", "name": "Zed Quorra"}));
    // Keeping it needs the touch (Task 3), never this op.
    let v = answer_as(&f, OWN, &id, json!({"keep_name": true})).await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    let step = answer(&f, &id, json!({"keep_name": false})).await;
    assert_refused(
        &step,
        "name_refused",
        "\"Zed Quorra\" is not in crm and was not sent; ask without it, or check the spelling",
    );
    assert!(outbox(&f).is_empty());
    assert!(records(&f, "blind_send").is_empty());
    // The ask has ended.
    let v = answer_as(&f, OWN, &id, json!({"keep_name": false})).await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
}

#[tokio::test]
async fn no_match_refuses_without_sending() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (id, _) = ask_q(&f, Q_ANNA).await;
    // A pick past the list does not fit and leaves the ask as it was.
    let v = answer_as(&f, OWN, &id, json!({"pick": 3})).await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    let v = answer_as(&f, OWN, &id, json!({"did_you_mean": true})).await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    // "None of these".
    let step = answer(&f, &id, json!({"pick": 0})).await;
    assert_refused(&step, "no_match", "no customer named \"Anna Berg\"");
    assert!(outbox(&f).is_empty());
    assert!(records(&f, "blind_send").is_empty());
    let r = records(&f, "blind_resolve");
    assert_eq!(r.len(), 1);
    assert_eq!(r[0]["params"], json!([["entity:customers", 2]]));
}

#[tokio::test]
async fn invalid_method_retried_then_refused() {
    let t = scratch();
    let bad = reply(
        "SELECT SUM(i.nope) AS s FROM invoices i JOIN customers c ON c.id = i.customer_id \
         WHERE c.id = :p1",
        "{money(s)}",
        "x",
    );
    let f = fx(t.path(), &vec![bad; 5]).await;
    let (_, step) = ask_q(&f, Q_SOREN).await;
    assert_refused(
        &step,
        "invalid_method",
        "the planner's method was not valid after 4 tries (unknown_column)",
    );
    let ob = outbox(&f);
    assert_eq!(ob.len(), 4, "the first try plus 3 retries, one entry each");
    assert_eq!(records(&f, "blind_send").len(), 4);
    let hash = saiife_shield::envelope::method_sha256(
        "SELECT SUM(i.nope) AS s FROM invoices i JOIN customers c ON c.id = i.customer_id \
         WHERE c.id = :p1",
    );
    assert!(envelope_of(&ob[0])["retry"].is_null());
    for e in &ob[1..] {
        // R-C11: the hash and the class, never the method; a name the
        // schema does not have is not sent.
        assert_eq!(
            envelope_of(e)["retry"],
            json!({"error_class": "unknown_column", "previous_method_sha256": hash})
        );
        assert!(!e["body"].as_str().unwrap().contains("nope"));
    }
}

#[tokio::test]
async fn identifier_output_ends_with_its_code() {
    let t = scratch();
    let bad = reply(
        "SELECT c.email FROM customers c WHERE c.id = :p1",
        "{list(email)}",
        "x",
    );
    let f = fx(t.path(), &vec![bad; 4]).await;
    let (_, step) = ask_q(&f, Q_SOREN).await;
    // R-C5: the hook a later reveal keys on.
    assert_refused(&step, "identifier_output", IDENTIFIER_OUTPUT_REASON);
    let ob = outbox(&f);
    assert_eq!(ob.len(), 4);
    assert_eq!(
        envelope_of(&ob[3])["retry"]["error_class"],
        "identifier_output"
    );
}

#[tokio::test]
async fn retry_then_preview() {
    let t = scratch();
    let bad = reply(
        "SELECT SUM(i.amount) AS owed FROM invoices i",
        "{money(owed)}",
        "x",
    );
    let f = fx(t.path(), &[bad, balance()]).await;
    let (_, step) = ask_q(&f, Q_SOREN).await;
    assert_eq!(step["kind"], "preview", "{step}");
    let ob = outbox(&f);
    assert_eq!(ob.len(), 2);
    // An unused customer is param_misuse (ruling F-f), retried.
    assert_eq!(envelope_of(&ob[1])["retry"]["error_class"], "param_misuse");
}

#[tokio::test]
async fn reuse_needs_same_template_and_types() {
    let t = scratch();
    let f = fx(t.path(), &[reply(M_OVER, T_OVER, "counts")]).await;
    let id_bal = approved(&f, Q_ANNA, M_BAL, T_BAL, MethodStatus::Active);
    // A currency makes the threshold an amount; a plain number is an
    // integer (plan 44: a grouped `10 000` reads as an amount too).
    let q_kr = "How many invoices does Søren Østergård have over 500 kroner?";
    let q_int = "How many invoices does Søren Østergård have over 500?";
    let (k1, t1) = template_key(&draft_of(&f, q_kr));
    let (k2, t2) = template_key(&draft_of(&f, q_int));
    assert_eq!(k1, k2, "the same words");
    assert_eq!((t1[1].as_str(), t2[1].as_str()), ("amount", "integer"));
    let id_over = approved(&f, q_kr, M_OVER, T_OVER, MethodStatus::Active);
    // Anna's balance: the approved method, after the pick; no cloud call.
    let (id, step) = ask_q(&f, Q_ANNA).await;
    assert_eq!(step["kind"], "pick");
    let step = answer(&f, &id, json!({"pick": 1})).await;
    assert_eq!(step["kind"], "preview", "{step}");
    assert_eq!(step["approved"], id_bal.as_str());
    assert_eq!(
        step["text"],
        plan45_preview(&f, M_BAL, 2, "Anna Berg, Aarhus").as_str()
    );
    assert!(step.get("planner_says").is_none(), "{step}");
    assert_eq!(
        step["sent"],
        json!({"tables": 0, "synthetic_rows": 0, "params": 0, "personal_values": 0})
    );
    assert!(outbox(&f).is_empty());
    assert_eq!(
        records(&f, "blind_ask")[0]["approved_method"],
        id_bal.as_str()
    );
    // The amount threshold: reused.
    let (_, step) = ask_q(&f, q_kr).await;
    assert_eq!(step["approved"], id_over.as_str(), "{step}");
    assert!(outbox(&f).is_empty());
    // The same words with an integer: another parameter type, the planner.
    let (_, step) = ask_q(&f, q_int).await;
    assert_eq!(step["kind"], "preview", "{step}");
    assert!(step.get("approved").is_none(), "{step}");
    assert_eq!(outbox(&f).len(), 1);
}

#[tokio::test]
async fn suspended_method_not_reused() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    approved(
        &f,
        Q_SOREN,
        M_BAL,
        T_BAL,
        MethodStatus::Suspended {
            reason: "unknown_column amount".into(),
        },
    );
    let (_, step) = ask_q(&f, Q_SOREN).await;
    assert_eq!(step["kind"], "preview", "{step}");
    assert!(step.get("approved").is_none(), "{step}");
    assert_eq!(outbox(&f).len(), 1);
}

#[tokio::test]
async fn refreshing_answer() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (reached, release) = f.ctx.blind.test_hold_at(Phase::Index);
    let v = call(
        &f,
        OP_BLIND_DATA_REFRESH,
        json!({"dataset": "crm"}),
        vec![fd_of(&f.sqlite)],
    )
    .await;
    assert_eq!(v["started"], true, "{v}");
    tokio::task::spawn_blocking(move || reached.recv_timeout(Duration::from_secs(120)).unwrap())
        .await
        .unwrap();
    let (_, step) = ask_q(&f, Q_SOREN).await;
    assert_eq!(step["kind"], "refreshing", "{step}");
    assert!(
        step["text"]
            .as_str()
            .unwrap()
            .starts_with("crm is refreshing (index, "),
        "{step}"
    );
    assert!(outbox(&f).is_empty());
    release.send(()).unwrap();
    f.ctx.blind.test_wait_builds().await;
    let (_, step) = ask_q(&f, Q_SOREN).await;
    assert_eq!(step["kind"], "preview", "{step}");
}

/// Plan 48 C2: an ask keeps the build it began on; a refresh that starts
/// meanwhile does not stop its later steps.
#[tokio::test]
async fn ask_keeps_its_build_during_a_refresh() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (id, step) = ask_q(&f, Q_ANNA).await;
    assert_eq!(step["kind"], "pick");
    let (reached, release) = f.ctx.blind.test_hold_at(Phase::Index);
    let v = call(
        &f,
        OP_BLIND_DATA_REFRESH,
        json!({"dataset": "crm"}),
        vec![fd_of(&f.sqlite)],
    )
    .await;
    assert_eq!(v["started"], true, "{v}");
    tokio::task::spawn_blocking(move || reached.recv_timeout(Duration::from_secs(120)).unwrap())
        .await
        .unwrap();
    assert!(
        f.ctx.blind.live(&crm()).is_err(),
        "the dataset is refreshing"
    );
    let step = answer(&f, &id, json!({"pick": 1})).await;
    assert_eq!(step["kind"], "preview", "{step}");
    release.send(()).unwrap();
    f.ctx.blind.test_wait_builds().await;
}

/// R48-1: at most 4 open asks per uid; an ended one frees its slot.
#[tokio::test]
async fn open_asks_are_limited() {
    let t = scratch();
    let f = fx(t.path(), &[]).await;
    let mut ids = Vec::new();
    for _ in 0..ask::MAX_OPEN_PER_UID {
        ids.push(ask_q(&f, Q_ANNA).await.0);
    }
    let v = call(
        &f,
        OP_BLIND_ASK,
        json!({"question": Q_ANNA, "dataset": "crm"}),
        vec![],
    )
    .await;
    assert_eq!(err(&v).0, "busy", "{v}");
    let step = answer(&f, &ids[0], json!({"pick": 0})).await;
    assert_eq!(step["kind"], "refused");
    let (_, step) = ask_q(&f, Q_ANNA).await;
    assert_eq!(step["kind"], "pick");
}

#[tokio::test]
async fn needs_judgment_says_so() {
    let t = scratch();
    let judge =
        json!({"method": "", "template": "", "intent": "x", "needs_judgment": true}).to_string();
    let f = fx(t.path(), &[judge]).await;
    let (_, step) = ask_with(
        &f,
        json!({"question": Q_SOREN, "dataset": "crm", "lang": "en", "judgment": true}),
    )
    .await;
    assert_refused(&step, "needs_judgment", ask::JUDGMENT);
    assert!(outbox(&f).is_empty());
    // The planner says so: the same answer, never a silent switch.
    let (_, step) = ask_q(&f, Q_SOREN).await;
    assert_refused(&step, "needs_judgment", ask::JUDGMENT);
    assert_eq!(outbox(&f).len(), 1);
}

#[tokio::test]
async fn planner_says_drops_numbers() {
    let t = scratch();
    let f = fx(
        t.path(),
        &[
            reply(M_BAL, T_BAL, "sums 3 kinds of invoices"),
            reply(M_BAL, T_BAL, "sums two kinds of invoices"),
            reply(M_BAL, T_BAL, "sums the open invoices"),
        ],
    )
    .await;
    for want in [None, None, Some("sums the open invoices")] {
        let (_, step) = ask_q(&f, Q_SOREN).await;
        assert_eq!(step["kind"], "preview", "{step}");
        assert_eq!(
            step.get("planner_says").and_then(Value::as_str),
            want,
            "{step}"
        );
    }
}

#[tokio::test]
async fn candidates_never_logged() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (id, step) = ask_q(&f, Q_ANNA).await;
    assert_eq!(step["kind"], "pick");
    let step = answer(&f, &id, json!({"pick": 1})).await;
    assert_eq!(step["kind"], "preview", "{step}");
    let logs = raw_dir(&f.audit);
    let ob = raw_dir(&f.ctx.blind.root.join("outbox"));
    assert!(
        logs.contains("blind_resolve") && ob.contains("blind"),
        "nothing was written"
    );
    // (The envelope's synthetic emails are `synthetic<n>@example.invalid`.)
    for value in ["Anna", "Berg", "Aarhus", "Odense", "anna.berg"] {
        assert!(!logs.contains(value), "{value} in the audit log");
        assert!(!ob.contains(value), "{value} in the outbox");
    }
}

#[tokio::test]
async fn ask_belongs_to_uid() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (id, _) = ask_q(&f, Q_ANNA).await;
    let v = answer_as(&f, OTHER, &id, json!({"pick": 1})).await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
    // Another uid may not ask in personal mode either.
    let v = call_as(
        &f,
        OTHER,
        OP_BLIND_ASK,
        json!({"question": Q_ANNA, "dataset": "crm"}),
        vec![],
    )
    .await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
    // The owner's ask goes on.
    let step = answer(&f, &id, json!({"pick": 1})).await;
    assert_eq!(step["kind"], "preview", "{step}");
}

// ---- R-C12: the role is checked again at every step ----

const BOTH: &str = "users = [\"me\", \"you\"]\napprovers = [\"me\"]\n";
const ME_ONLY: &str = "users = [\"me\"]\napprovers = [\"me\"]\n";

#[tokio::test]
async fn role_lost_ends_the_ask() {
    let t = scratch();
    let f = fx_mode(t.path(), &[balance()], Mode::Locked, BOTH).await;
    let v = call_as(
        &f,
        OTHER,
        OP_BLIND_ASK,
        json!({"question": Q_ANNA, "dataset": "crm", "lang": "en"}),
        vec![],
    )
    .await;
    assert!(v.get("error").is_none(), "{v}");
    let id = v["ask"].as_str().unwrap().to_string();
    // The role is withdrawn (the policy changes under the ask).
    set_policy(&f, &policy_text(true, ME_ONLY));
    let v = answer_as(&f, OTHER, &id, json!({"pick": 1})).await;
    assert_eq!(
        err(&v),
        ("forbidden".to_string(), ask::ROLE_LOST.to_string())
    );
    // The ask is gone, and the end is recorded; nothing was sent.
    let v = answer_as(&f, OTHER, &id, json!({"pick": 1})).await;
    assert_eq!(
        err(&v),
        ("bad_request".to_string(), ask::NO_SUCH_ASK.to_string())
    );
    let r = records(&f, "blind_check_refused");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0]["ask"], id.as_str());
    assert_eq!(r[0]["reason"], "role_lost");
    assert!(outbox(&f).is_empty());
}

#[tokio::test]
async fn reload_drops_the_asks_of_a_lost_role() {
    let t = scratch();
    let f = fx_mode(t.path(), &[balance()], Mode::Locked, BOTH).await;
    let ask_as = |uid| {
        call_as(
            &f,
            uid,
            OP_BLIND_ASK,
            json!({"question": Q_ANNA, "dataset": "crm", "lang": "en"}),
            vec![],
        )
    };
    let yours = ask_as(OTHER).await["ask"].as_str().unwrap().to_string();
    let mine = ask_as(OWN).await["ask"].as_str().unwrap().to_string();
    // The reload hook (start::reload runs it after the new policy is in).
    set_policy(&f, &policy_text(true, ME_ONLY));
    ask::policy_reloaded(&f.ctx).await;
    let gone = f
        .ctx
        .blind
        .asks
        .lock()
        .unwrap()
        .peek(&yours, OTHER, |_| ())
        .unwrap_err();
    assert_eq!(gone.text, ask::NO_SUCH_ASK);
    assert_eq!(records(&f, "blind_check_refused").len(), 1);
    // An unchanged role goes on.
    let step = answer(&f, &mine, json!({"pick": 1})).await;
    assert_eq!(step["kind"], "preview", "{step}");
}

#[tokio::test]
async fn dataset_left_policy_ends_the_ask() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    let (id, _) = ask_q(&f, Q_ANNA).await;
    let (keep, _) = ask_q(&f, Q_ANNA).await;
    // The same policy again: nothing changes.
    set_policy(&f, &policy_text(true, ""));
    ask::policy_reloaded(&f.ctx).await;
    assert_eq!(
        answer(&f, &keep, json!({"pick": 1})).await["kind"],
        "preview"
    );
    // The dataset leaves policy.
    set_policy(&f, &ner_section_only());
    let v = answer_as(&f, OWN, &id, json!({"pick": 1})).await;
    assert_eq!(
        err(&v),
        ("forbidden".to_string(), ask::DATASET_GONE.to_string())
    );
    let v = answer_as(&f, OWN, &id, json!({"pick": 1})).await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
    assert_eq!(
        records(&f, "blind_check_refused")[0]["reason"],
        "dataset_not_in_policy"
    );
}

fn ner_section_only() -> String {
    format!("version = 2\n\n{}", ner_section())
}

#[tokio::test]
async fn asks_expire() {
    let t = scratch();
    let f = fx(t.path(), &[]).await;
    let (id, _) = ask_q(&f, Q_ANNA).await;
    f.ctx
        .blind
        .asks
        .lock()
        .unwrap()
        .test_backdate(Duration::from_secs(11 * 60));
    let v = answer_as(&f, OWN, &id, json!({"pick": 1})).await;
    assert_eq!(
        err(&v),
        ("bad_request".to_string(), ask::NO_SUCH_ASK.to_string())
    );
    let v = answer_as(&f, OWN, "00ff", json!({"pick": 1})).await;
    assert_eq!(err(&v).0, "bad_request", "{v}");
}

#[tokio::test]
async fn ner_must_be_pinned_and_ready() {
    let t = scratch();
    let f = fx(t.path(), &[balance()]).await;
    set_policy(&f, &policy_text(false, ""));
    let v = call(
        &f,
        OP_BLIND_ASK,
        json!({"question": Q_SOREN, "dataset": "crm"}),
        vec![],
    )
    .await;
    assert_eq!(
        err(&v),
        ("unavailable".to_string(), ask::NER_NOT_PINNED.to_string())
    );
    set_policy(&f, &policy_text(true, ""));
    f.ctx.blind.set_test_detector(None);
    let v = call(
        &f,
        OP_BLIND_ASK,
        json!({"question": Q_SOREN, "dataset": "crm"}),
        vec![],
    )
    .await;
    assert_eq!(
        err(&v),
        ("unavailable".to_string(), ask::NER_NOT_READY.to_string())
    );
    assert!(outbox(&f).is_empty());
}

#[tokio::test]
async fn ask_args_are_checked() {
    let t = scratch();
    let f = fx(t.path(), &[]).await;
    for (args, code) in [
        (json!({"dataset": "crm"}), "bad_request"),
        (json!({"question": "  ", "dataset": "crm"}), "bad_request"),
        (
            json!({"question": "x".repeat(2001), "dataset": "crm"}),
            "bad_request",
        ),
        (
            json!({"question": Q_SOREN, "dataset": "crm", "lang": "de"}),
            "bad_request",
        ),
        (
            json!({"question": Q_SOREN, "dataset": "crm", "limit": 101}),
            "bad_request",
        ),
        (
            json!({"question": Q_SOREN, "dataset": "crm", "limit": 0}),
            "bad_request",
        ),
        (
            json!({"question": Q_SOREN, "dataset": "nope"}),
            "bad_request",
        ),
        (
            json!({"question": Q_SOREN, "dataset": "Not A Name"}),
            "bad_request",
        ),
    ] {
        let v = call(&f, OP_BLIND_ASK, args.clone(), vec![]).await;
        assert_eq!(err(&v).0, code, "{args} -> {v}");
    }
    // The only dataset is the default.
    let (_, step) = ask_with(&f, json!({"question": Q_STRANGER})).await;
    assert_eq!(step["kind"], "keep_name");
}
