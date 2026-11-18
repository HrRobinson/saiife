//! Data Shield dataset import, commit, refresh and removal (plan 47, Task 2;
//! R47-3..R47-6, rulings P47-5, P47-6, P47-17). A personal-mode context in
//! `$SAIIFE_TEST_TMP`; the data is plan 43's synthetic fixture (made-up
//! people only), passed as an open descriptor as the CLI passes it.
#![cfg(target_os = "linux")]

#[path = "../../shield/tests/fixtures.rs"]
mod fixtures;

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::audit_query::{self, Scope};
use saiife_daemon::blind::data::{self, Classes, LoosenGrant};
use saiife_daemon::blind::pg::{self, PgMsg, PgSource};
use saiife_daemon::blind::DatasetState;
use saiife_daemon::ops::{Conn, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::vault;
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::{
    Request, OP_BLIND_DATA_COMMIT, OP_BLIND_DATA_REFRESH, OP_BLIND_DATA_RM, OP_BLIND_DATA_STAGE,
};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, FixedDirectory, Fsync};
use saiife_shield::dataset::{load_manifest, stage_snapshot, DatasetDir, Phase};
use saiife_shield::ner::{ListDetector, SpanLabel};
use saiife_shield::schema::{ColumnClass, DatasetName};
use saiife_shield::source::{Cell, RowSource, SourceTable};
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
    /// The fixture's two tables as one SQLite file.
    sqlite: PathBuf,
}

/// Plan 43's fixture CSVs (`customers`, `invoices`) as one SQLite file: the
/// shield's own snapshot of them.
fn fixture_sqlite(root: &Path, customers: u64, seed: u64) -> PathBuf {
    let csv = root.join(format!("csv-{seed}"));
    std::fs::create_dir_all(&csv).unwrap();
    fixtures::write_fixture(&csv, customers, seed).unwrap();
    let mut src = fixtures::MultiSource::csv_dir(&csv).unwrap();
    let dir = DatasetDir {
        root: root.join(format!("make-{seed}")).join("crm"),
    };
    let info = stage_snapshot(&dir, &mut src, &mut |_| {}).unwrap();
    let out = root.join(format!("crm-{seed}.sqlite"));
    std::fs::copy(&info.path, &out).unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600)).unwrap();
    out
}

fn fx(root: &Path) -> Fx {
    let audit = root.join("audit");
    std::fs::create_dir_all(&audit).unwrap();
    let state = root.join("state");
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
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        mode: Mode::Personal,
        own_uid: OWN,
        own_user: "me".into(),
        vault: vault::open_with_key(Zeroizing::new([5; 32]), &state.join("vault/vault.bin")),
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }));
    let sqlite = fixture_sqlite(root, 300, 11);
    Fx {
        ctx,
        audit,
        root: root.to_path_buf(),
        sqlite,
    }
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

/// The policy text naming `crm` (SQLite source), its classes overridden by
/// `over` (`table.column`, class).
fn policy_text(over: &[(&str, &str)]) -> String {
    let mut s = String::from(
        "version = 2\n\n[[blind.dataset]]\nname = \"crm\"\n\
         source = { kind = \"sqlite\", file_name = \"crm.sqlite\" }\n\n\
         [blind.dataset.columns]\n",
    );
    for (c, class) in COLUMNS {
        let class = over
            .iter()
            .find(|(o, _)| o == c)
            .map_or(*class, |(_, k)| *k);
        s.push_str(&format!("\"{c}\" = {{ class = \"{class}\" }}\n"));
    }
    s.push_str(
        "\n[[blind.dataset.entity]]\ntable = \"customers\"\nkey = \"id\"\n\
         names = [\"first_name\", \"last_name\"]\n",
    );
    s
}

/// A reload with `text` (an empty text: a policy without datasets).
fn set_policy(f: &Fx, text: &str) {
    let path = f.root.join("config.toml");
    std::fs::write(&path, text).unwrap();
    let l = saiife_policy::load_system(&path).unwrap();
    *f.ctx.policy.lock().unwrap() =
        PolicyState::from_loaded(&l, &[], saiife_broker::Catalog::new(&[], vec![]));
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

fn crm() -> DatasetName {
    "crm".parse().unwrap()
}

fn ok(v: &Value) -> &Value {
    assert!(v.get("error").is_none(), "{v}");
    v
}

fn err(v: &Value) -> (String, String) {
    (
        v["error"].as_str().unwrap_or_default().to_string(),
        v["message"].as_str().unwrap_or_default().to_string(),
    )
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

/// Stage, the policy, commit: `crm` live.
async fn build_live(f: &Fx, over: &[(&str, &str)]) -> Value {
    ok(&stage(f).await);
    set_policy(f, &policy_text(over));
    let v = call(f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await;
    ok(&v);
    v
}

async fn refresh(f: &Fx, file: &Path) -> Value {
    call(
        f,
        OP_BLIND_DATA_REFRESH,
        json!({"dataset": "crm"}),
        vec![fd_of(file)],
    )
    .await
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

fn raw_log(f: &Fx) -> String {
    let mut out = String::new();
    for e in std::fs::read_dir(&f.audit).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            out.push_str(&String::from_utf8_lossy(&std::fs::read(&p).unwrap()));
        }
    }
    out
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

fn ds_root(f: &Fx) -> PathBuf {
    f.ctx.blind.dataset_dir(&crm()).root
}

fn class_in_live(f: &Fx, col: &str) -> ColumnClass {
    let m = load_manifest(&f.ctx.blind.dataset_dir(&crm())).unwrap();
    let (t, c) = col.split_once('.').unwrap();
    m.schema.column(t, c).unwrap().class
}

fn columns<'a>(v: &'a Value, table: &str) -> &'a Vec<Value> {
    v["tables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == table)
        .unwrap()["columns"]
        .as_array()
        .unwrap()
}

fn column<'a>(v: &'a Value, table: &str, col: &str) -> &'a Value {
    columns(v, table).iter().find(|c| c["name"] == col).unwrap()
}

#[tokio::test]
async fn stage_proposes() {
    let t = scratch();
    let f = fx(t.path());
    let v = stage(&f).await;
    ok(&v);
    let names: Vec<&str> = v["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["customers", "invoices"]);
    assert_eq!(v["tables"][0]["rows_band"], "about 300");
    let uncertain: Vec<String> = ["customers", "invoices"]
        .iter()
        .flat_map(|t| {
            columns(&v, t)
                .iter()
                .filter(|c| c["uncertain"] == true)
                .map(|c| c["name"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(uncertain.iter().any(|c| c == "status"), "{uncertain:?}");
    assert!(uncertain.iter().any(|c| c == "segment"), "{uncertain:?}");
    let email = column(&v, "customers", "email");
    assert!(email["public_refusal"].is_string(), "{email}");
    assert!(email.get("public_preview").is_none(), "{email}");
    for key in ["type", "guess", "confidence"] {
        assert!(email.get(key).is_some(), "{key}: {email}");
    }
    // A preview gives counts, never values.
    let seg = column(&v, "customers", "segment");
    assert!(seg["public_preview"]["passing"].is_u64(), "{seg}");
    assert!(seg["public_preview"]["total"].is_u64(), "{seg}");
    let text = v.to_string();
    for value in ["retail", "Aarhus", "example.invalid", "paid"] {
        assert!(!text.contains(value), "{value} in the answer");
    }
    // Nothing is live and nothing is recorded yet.
    assert!(matches!(f.ctx.blind.state(&crm()), DatasetState::Absent));
    assert!(!raw_log(&f).contains("blind_"));
    // The SQLite copy is gone; the stage is private.
    let root = ds_root(&f);
    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&root.join("stage")), 0o700);
    assert!(!root.join("import").exists());
    // Only the own user (personal mode) may stage.
    let v = call_as(
        &f,
        OTHER,
        OP_BLIND_DATA_STAGE,
        json!({"dataset": "crm", "kind": "sqlite"}),
        vec![fd_of(&f.sqlite)],
    )
    .await;
    assert_eq!(err(&v).0, "forbidden");
    // A file kind needs its descriptor.
    let v = call(
        &f,
        OP_BLIND_DATA_STAGE,
        json!({"dataset": "crm", "kind": "csv"}),
        vec![],
    )
    .await;
    assert_eq!(err(&v).0, "bad_request");
}

#[tokio::test]
async fn commit_needs_policy() {
    let t = scratch();
    let f = fx(t.path());
    set_policy(&f, "version = 2\n");
    ok(&stage(&f).await);
    let v = call(&f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await;
    assert_eq!(
        err(&v),
        (
            "bad_request".to_string(),
            "crm is not in policy: write policy.d/blind-crm.toml and reload".to_string()
        )
    );
    assert!(!ds_root(&f).join("live").exists());
    assert!(!ds_root(&f).join("keys.sealed").exists());
}

#[tokio::test]
async fn commit_builds_live() {
    let t = scratch();
    let f = fx(t.path());
    let v = build_live(&f, &[]).await;
    assert_eq!(v["dataset"], "crm");
    assert!(v["snapshot_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(v["index_entries"].as_u64().unwrap() > 0);
    let root = ds_root(&f);
    assert!(root.join("live/manifest.json").is_file());
    assert!(!root.join("stage").exists());
    assert!(!root.join("staged.json").exists());
    assert_eq!(mode(&root.join("keys.sealed")), 0o600);
    // classes.json: the classes in force, 0600 in the 0700 dir.
    let classes = root.join("classes.json");
    assert_eq!(mode(&classes), 0o600);
    let c: Classes = serde_json::from_slice(&std::fs::read(&classes).unwrap()).unwrap();
    assert_eq!(c.0["customers.city"], ColumnClass::Quasi);
    assert_eq!(c.0["invoices.notes"], ColumnClass::FreeText);
    // Live, its handles open.
    let (m, h) = f.ctx.blind.live(&crm()).unwrap();
    assert_eq!(m.dataset, crm());
    assert!(h.index.is_some());
    // One blind_refresh record, first, with no cell value.
    let r = records(&f, "blind_refresh");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0]["first"], true);
    assert_eq!(r[0]["dataset"], "crm");
    assert_eq!(r[0]["suspended"], json!([]));
    assert!(r[0]["snapshot_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(r[0]["index_entries"].as_u64().unwrap() > 0);
    assert!(raw_log(&f).contains("blind_refresh"));
    let log = raw_log(&f);
    for value in [
        "example.invalid",
        "Aarhus",
        "Østergård",
        "Jensen",
        "retail",
        "overdue",
        "+45 00",
    ] {
        assert!(!log.contains(value), "{value} in the audit log");
    }
    // A second commit has no stage to build from.
    let v = call(&f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await;
    assert_eq!(err(&v).0, "bad_request");
    // Only a manager commits.
    let v = call_as(
        &f,
        OTHER,
        OP_BLIND_DATA_COMMIT,
        json!({"dataset": "crm"}),
        vec![],
    )
    .await;
    assert_eq!(err(&v).0, "forbidden");
}

#[tokio::test]
async fn reopen_at_start() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    // A daemon start: a new context over the same state.
    f.ctx.blind.set_state(&crm(), DatasetState::Absent);
    data::reopen_all(&f.ctx);
    assert!(f.ctx.blind.live(&crm()).is_ok());
    // A locked vault: not live, never unkeyed.
    f.ctx.blind.set_state(&crm(), DatasetState::Absent);
    *f.ctx.vault.lock() = vault::VaultState::Unavailable("locked".into());
    data::reopen_all(&f.ctx);
    let r = f.ctx.blind.live(&crm()).unwrap_err();
    assert_eq!(r.text, "the vault is unavailable");
}

#[tokio::test]
async fn refresh_is_exclusive() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    let (reached, release) = f.ctx.blind.test_hold_at(Phase::Index);
    let v = refresh(&f, &f.sqlite).await;
    assert_eq!(ok(&v)["started"], true);
    tokio::task::spawn_blocking(move || reached.recv_timeout(Duration::from_secs(120)).unwrap())
        .await
        .unwrap();
    // A second refresh, a commit, a stage, an rm: busy.
    let v = refresh(&f, &f.sqlite).await;
    assert_eq!(err(&v).0, "busy", "{v}");
    assert_eq!(
        err(&call(&f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await).0,
        "busy"
    );
    assert_eq!(err(&stage(&f).await).0, "busy");
    assert_eq!(
        err(&call(&f, OP_BLIND_DATA_RM, json!({"dataset": "crm"}), vec![]).await).0,
        "busy"
    );
    release.send(()).unwrap();
    f.ctx.blind.test_wait_builds().await;
    assert!(f.ctx.blind.live(&crm()).is_ok());
    assert_eq!(f.ctx.blind.last_build_error(&crm()), None);
    let r = records(&f, "blind_refresh");
    assert_eq!(r.len(), 2);
    assert_eq!(r[1]["first"], false);
}

#[tokio::test]
async fn ask_during_refresh_waits_out() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    // An ask that started before the refresh holds the old build.
    let (old_m, old_h) = f.ctx.blind.live(&crm()).unwrap();
    let other = fixture_sqlite(&f.root, 300, 12);
    let (reached, release) = f.ctx.blind.test_hold_at(Phase::Index);
    ok(&refresh(&f, &other).await);
    tokio::task::spawn_blocking(move || reached.recv_timeout(Duration::from_secs(120)).unwrap())
        .await
        .unwrap();
    // A new ask (the probe) gets the refreshing answer with the phase.
    let r = f.ctx.blind.live(&crm()).unwrap_err();
    assert_eq!(r.code, saiife_ipc::msg::ErrorCode::Busy);
    assert!(
        r.text.starts_with("crm is refreshing (index, "),
        "{}",
        r.text
    );
    assert!(r.text.ends_with("; try again in a moment"), "{}", r.text);
    release.send(()).unwrap();
    f.ctx.blind.test_wait_builds().await;
    let (new_m, _) = f.ctx.blind.live(&crm()).unwrap();
    assert_ne!(new_m.snapshot_sha256, old_m.snapshot_sha256);
    // The old ask finishes on its open files after the swap.
    let idx = old_h.index.as_ref().unwrap();
    assert!(idx.contains_value("no such value at all").is_ok());
    assert!(old_h.lexicon.lock().unwrap().did_you_mean("Jensen").is_ok());
}

#[tokio::test]
async fn refresh_reports_a_failed_build() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    // A file that is not SQLite: the build fails, the old build stays live.
    let junk = f.root.join("junk.sqlite");
    std::fs::write(&junk, b"not a database at all").unwrap();
    ok(&refresh(&f, &junk).await);
    f.ctx.blind.test_wait_builds().await;
    assert!(f.ctx.blind.live(&crm()).is_ok());
    assert!(f.ctx.blind.last_build_error(&crm()).is_some());
    assert_eq!(records(&f, "blind_refresh").len(), 1);
}

#[test]
fn loosen_without_grant_is_ignored() {
    let cfg: saiife_policy::SystemConfig =
        toml::from_str(&policy_text(&[("customers.city", "public")])).unwrap();
    let ds = &cfg.blind.dataset[0];
    let t = scratch();
    let m = manifest_of(t.path());
    let mut base = Classes::default();
    base.0.insert("customers.city".into(), ColumnClass::Quasi);
    let (s, warnings) = data::effective_schema(ds, &m, &base, &[]);
    assert_eq!(
        s.column("customers", "city").unwrap().class,
        ColumnClass::Quasi
    );
    assert_eq!(
        warnings,
        ["customers.city was made public in policy without a blind:loosen touch; still quasi"]
    );
    // A grant for another class does not count; tightening needs none.
    let g = LoosenGrant {
        column: "customers.city".into(),
        class: ColumnClass::Quasi,
        touched_at: "2026-11-18T10:00:00Z".into(),
        by: "me".into(),
    };
    let (s, _) = data::effective_schema(ds, &m, &base, &[g]);
    assert_eq!(
        s.column("customers", "city").unwrap().class,
        ColumnClass::Quasi
    );
    let mut base = Classes::default();
    base.0.insert("invoices.status".into(), ColumnClass::Public);
    let (s, w) = data::effective_schema(ds, &m, &base, &[]);
    assert_eq!(
        s.column("invoices", "status").unwrap().class,
        ColumnClass::Quasi
    );
    assert!(w.is_empty(), "{w:?}");
    // A column the policy leaves out is sensitive.
    let cfg: saiife_policy::SystemConfig = toml::from_str(
        &policy_text(&[]).replace("\"customers.postcode\" = { class = \"quasi\" }\n", ""),
    )
    .unwrap();
    let (s, _) = data::effective_schema(&cfg.blind.dataset[0], &m, &Classes::default(), &[]);
    assert_eq!(
        s.column("customers", "postcode").unwrap().class,
        ColumnClass::Sensitive
    );
}

/// A manifest of the fixture built straight with the shield (no daemon).
fn manifest_of(root: &Path) -> saiife_shield::dataset::Manifest {
    let csv = root.join("csv");
    std::fs::create_dir_all(&csv).unwrap();
    fixtures::write_fixture(&csv, 100, 3).unwrap();
    let mut src = fixtures::MultiSource::csv_dir(&csv).unwrap();
    let dir = DatasetDir {
        root: root.join("crm"),
    };
    let info = stage_snapshot(&dir, &mut src, &mut |_| {}).unwrap();
    let props = saiife_shield::dataset::propose(&info.path, 10).unwrap();
    let schema = fixtures::accept_all("crm", &props);
    let key = saiife_shield::index::IndexKey(Zeroizing::new([9; 32]));
    saiife_shield::dataset::finish(&dir, &schema, 10, &key, &mut |_| Ok(()), &mut |_| {}).unwrap()
}

#[tokio::test]
async fn loosen_without_grant_stays_at_refresh() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    set_policy(&f, &policy_text(&[("customers.city", "public")]));
    ok(&refresh(&f, &f.sqlite).await);
    f.ctx.blind.test_wait_builds().await;
    assert_eq!(f.ctx.blind.last_build_error(&crm()), None);
    assert_eq!(class_in_live(&f, "customers.city"), ColumnClass::Quasi);
    assert_eq!(
        data::warnings(&f.ctx, &crm()),
        ["customers.city was made public in policy without a blind:loosen touch; still quasi"]
    );
}

#[tokio::test]
async fn loosen_with_grant_applies_at_refresh() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    set_policy(&f, &policy_text(&[("customers.city", "public")]));
    let grants = json!({"grants": [{
        "column": "customers.city", "class": "public",
        "touched_at": "2026-11-18T10:00:00Z", "by": "me"
    }]});
    let lp = ds_root(&f).join("loosen.json");
    std::fs::write(&lp, grants.to_string()).unwrap();
    std::fs::set_permissions(&lp, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Public values are checked for names first (P47-6).
    f.ctx
        .blind
        .set_test_detector(Some(Arc::new(ListDetector::new(&[(
            "Søren",
            SpanLabel::Person,
        )]))));
    ok(&refresh(&f, &f.sqlite).await);
    f.ctx.blind.test_wait_builds().await;
    assert_eq!(f.ctx.blind.last_build_error(&crm()), None);
    assert_eq!(class_in_live(&f, "customers.city"), ColumnClass::Public);
    let m = load_manifest(&f.ctx.blind.dataset_dir(&crm())).unwrap();
    assert!(m.public.iter().any(|p| p.column == "customers.city"));
    // The grant is spent; the baseline now holds public.
    let c: Classes =
        serde_json::from_slice(&std::fs::read(ds_root(&f).join("classes.json")).unwrap()).unwrap();
    assert_eq!(c.0["customers.city"], ColumnClass::Public);
    let left: Value = serde_json::from_slice(&std::fs::read(&lp).unwrap()).unwrap();
    assert_eq!(left["grants"], json!([]));
    assert!(data::warnings(&f.ctx, &crm()).is_empty());
}

#[tokio::test]
async fn public_columns_need_the_name_detector() {
    let t = scratch();
    let f = fx(t.path());
    ok(&stage(&f).await);
    set_policy(&f, &policy_text(&[("customers.city", "public")]));
    // No detector: refused, naming the fetch.
    let v = call(&f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await;
    let (code, text) = err(&v);
    assert_eq!(code, "unavailable");
    assert_eq!(
        text,
        "crm has public columns, whose values are checked for names first: saiife blind ner fetch"
    );
    // A detector that finds a name in a public value: the column is refused,
    // the value is never shown.
    f.ctx
        .blind
        .set_test_detector(Some(Arc::new(ListDetector::new(&[(
            "Odense",
            SpanLabel::Person,
        )]))));
    let v = call(&f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await;
    let (code, text) = err(&v);
    assert_eq!(code, "bad_request");
    assert_eq!(
        text,
        "customers.city is public but a value looks like a person's name: mark it quasi"
    );
    assert!(!ds_root(&f).join("live").exists());
    // A clean detector: built.
    f.ctx
        .blind
        .set_test_detector(Some(Arc::new(ListDetector::new(&[(
            "Søren",
            SpanLabel::Person,
        )]))));
    ok(&call(&f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await);
    assert_eq!(class_in_live(&f, "customers.city"), ColumnClass::Public);
}

#[tokio::test]
async fn no_identifier_names_the_table() {
    let t = scratch();
    let f = fx(t.path());
    ok(&stage(&f).await);
    // invoices: no identifier, only quasi and sensitive columns.
    set_policy(
        &f,
        &policy_text(&[
            ("invoices.id", "sensitive"),
            ("invoices.customer_id", "sensitive"),
        ]),
    );
    let v = call(&f, OP_BLIND_DATA_COMMIT, json!({"dataset": "crm"}), vec![]).await;
    assert_eq!(
        err(&v),
        (
            "bad_request".to_string(),
            "table invoices holds personal data but no column identifies the person; \
             choose the column that identifies the person"
                .to_string()
        )
    );
}

#[tokio::test]
async fn rm_shreds() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    let root = ds_root(&f);
    assert!(root.join("keys.sealed").exists());
    let v = call(&f, OP_BLIND_DATA_RM, json!({"dataset": "crm"}), vec![]).await;
    ok(&v);
    assert!(!root.exists());
    assert!(matches!(f.ctx.blind.state(&crm()), DatasetState::Absent));
    let r = records(&f, "blind_keys");
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0]["action"], "delete");
    assert_eq!(r[0]["dataset"], "crm");
    assert_eq!(r[0]["reason"], "dataset removed");
    // Only a manager removes; a dataset that is not there is not an error.
    let v = call_as(
        &f,
        OTHER,
        OP_BLIND_DATA_RM,
        json!({"dataset": "crm"}),
        vec![],
    )
    .await;
    assert_eq!(err(&v).0, "forbidden");
    ok(&call(&f, OP_BLIND_DATA_RM, json!({"dataset": "crm"}), vec![]).await);
}

fn two_tables() -> Vec<SourceTable> {
    vec![
        SourceTable {
            name: "people".into(),
            columns: vec!["id".into(), "name".into(), "born".into()],
        },
        SourceTable {
            name: "empty".into(),
            columns: vec!["x".into()],
        },
    ]
}

/// A fetch fed by the test: each call starts a thread that sends `rows`
/// rows of `table` into a fresh bounded channel.
fn fed(rows: u64) -> pg::Fetch {
    Box::new(move |table: &str| {
        let (tx, rx) = pg::row_channel();
        let table = table.to_string();
        std::thread::spawn(move || {
            if table == "people" {
                for i in 0..rows {
                    let row = vec![
                        Cell::Int(i as i64),
                        Cell::Text(format!("Person {i}")),
                        Cell::Date("1980-01-02".into()),
                    ];
                    if tx.send(PgMsg::Row(row)).is_err() {
                        return;
                    }
                }
            }
            let _ = tx.send(PgMsg::End);
        });
        Ok(rx)
    })
}

#[test]
fn pg_source_bridge() {
    // More rows than the channel holds: the producer waits for the reader.
    let n = (pg::CHANNEL_ROWS as u64) * 2 + 5;
    let mut src = PgSource::from_fetch(two_tables(), fed(n));
    assert_eq!(src.tables(), two_tables());
    assert_eq!(src.file_name(), "postgres");
    let read = |s: &mut PgSource| -> Vec<Vec<Cell>> {
        s.rows("people").unwrap().map(|r| r.unwrap()).collect()
    };
    let a = read(&mut src);
    let b = read(&mut src);
    assert_eq!(a.len() as u64, n);
    assert_eq!(a, b);
    assert_eq!(src.rows("empty").unwrap().count(), 0);
    // A producer that stops without `End` is an error, never a short table.
    let mut cut = PgSource::from_fetch(
        two_tables(),
        Box::new(|_: &str| {
            let (tx, rx) = pg::row_channel();
            std::thread::spawn(move || {
                let _ = tx.send(PgMsg::Row(vec![Cell::Int(1), Cell::Null, Cell::Null]));
            });
            Ok(rx)
        }),
    );
    let got: Vec<_> = cut.rows("people").unwrap().collect();
    assert_eq!(got.len(), 2);
    assert!(got[1].is_err());
    // The snapshot reads it twice per table and builds.
    let t = scratch();
    let dir = DatasetDir {
        root: t.path().join("pg"),
    };
    let mut src = PgSource::from_fetch(two_tables(), fed(50));
    let info = stage_snapshot(&dir, &mut src, &mut |_| {}).unwrap();
    assert_eq!(info.tables[0].2, 50);
}

/// The owner's smoke: a real local Postgres. `SAIIFE_TEST_PG_HOST` (a socket
/// dir or loopback), `SAIIFE_TEST_PG_DB`, `SAIIFE_TEST_PG_USER`,
/// `SAIIFE_TEST_PG_TABLE`; the password from `SAIIFE_TEST_PG_PASSWORD`, put in
/// the test vault.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a local Postgres (owner smoke)"]
async fn pg_live() {
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set"));
    let t = scratch();
    let f = fx(t.path());
    {
        let mut g = f.ctx.vault.lock();
        let vault::VaultState::Ready(v) = &mut *g else {
            panic!("vault")
        };
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "password".to_string(),
            Zeroizing::new(var("SAIIFE_TEST_PG_PASSWORD")),
        );
        v.put(vault::Entry {
            name: "pg".into(),
            kind: vault::Kind::Basic,
            fields,
            allowed_services: vec![],
            created_by: OWN,
            created: "2026-11-18T00:00:00Z".into(),
            last_used: None,
            rotate_after: None,
        })
        .unwrap();
    }
    let src = saiife_policy::blind::BlindSource::Postgres {
        host: var("SAIIFE_TEST_PG_HOST"),
        port: None,
        dbname: var("SAIIFE_TEST_PG_DB"),
        user: var("SAIIFE_TEST_PG_USER"),
        password_secret: "pg".into(),
        tables: vec![var("SAIIFE_TEST_PG_TABLE")],
    };
    let mut s = pg::pg_source(&f.ctx, &src).await.unwrap();
    let table = s.tables()[0].name.clone();
    let a = tokio::task::spawn_blocking(move || {
        let a: Vec<_> = s.rows(&table).unwrap().map(|r| r.unwrap()).collect();
        let b: Vec<_> = s.rows(&table).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(a, b);
        a.len()
    })
    .await
    .unwrap();
    eprintln!("rows: {a}");
}
