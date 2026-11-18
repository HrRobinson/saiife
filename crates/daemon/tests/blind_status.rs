//! `blind.status` and `blind.methods.list` (plan 47, Task 7; R47-3). A
//! context in `$SAIIFE_TEST_TMP` over plan 43's synthetic fixture (made-up
//! people only). Personal mode unless a test says locked.
#![cfg(target_os = "linux")]

#[path = "../../shield/tests/fixtures.rs"]
mod fixtures;

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::blind::DatasetState;
use saiife_daemon::ops::{Conn, Ctx, CtxInit, Mode, PolicyState};
use saiife_daemon::vault::{self, Entry, Kind, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::{
    Request, OP_BLIND_DATA_COMMIT, OP_BLIND_DATA_STAGE, OP_BLIND_METHODS_LIST, OP_BLIND_STATUS,
};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, FixedDirectory, Fsync};
use saiife_shield::dataset::{stage_snapshot, DatasetDir};
use saiife_shield::methods::{ApprovedMethod, MethodStatus, MethodStore};
use saiife_shield::plan::PlanReply;
use saiife_shield::schema::{DatasetName, Lang};
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
    fx_mode(root, Mode::Personal)
}

/// [`fx`] for a locked daemon (own uid 999; `me` and `you` are peers).
fn fx_mode(root: &Path, mode: Mode) -> Fx {
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
    let sqlite = fixture_sqlite(root, 300, 11);
    Fx {
        ctx,
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

fn err(v: &Value) -> (String, String) {
    (
        v["error"].as_str().unwrap_or_default().to_string(),
        v["message"].as_str().unwrap_or_default().to_string(),
    )
}

fn ds_root(f: &Fx) -> PathBuf {
    f.ctx.blind.dataset_dir(&crm()).root
}

async fn status_as(f: &Fx, uid: u32) -> Value {
    call_as(f, uid, OP_BLIND_STATUS, json!({}), vec![]).await
}

fn names(v: &Value) -> Vec<String> {
    v["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap().to_string())
        .collect()
}

fn crm_of(v: &Value) -> &Value {
    v["datasets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "crm")
        .expect("crm in status")
}

/// A locked daemon (own uid 999): `crm` built by root, `users = [me]`,
/// `approvers = [me]`.
async fn locked_live(root: &Path) -> Fx {
    let f = fx_mode(root, Mode::Locked);
    let v = call_as(
        &f,
        0,
        OP_BLIND_DATA_STAGE,
        json!({"dataset": "crm", "kind": "sqlite", "file_name": "crm.sqlite"}),
        vec![fd_of(&f.sqlite)],
    )
    .await;
    ok(&v);
    let text = policy_text(&[]).replace(
        "[blind.dataset.columns]",
        "users = [\"me\"]\napprovers = [\"me\"]\n\n[blind.dataset.columns]",
    );
    set_policy(&f, &text);
    let v = call_as(
        &f,
        0,
        OP_BLIND_DATA_COMMIT,
        json!({"dataset": "crm"}),
        vec![],
    )
    .await;
    ok(&v);
    f.ctx.blind.test_wait_builds().await;
    f
}

#[tokio::test]
async fn status_shows_weaker_label() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    f.ctx.blind.test_wait_builds().await;
    // No Landlock (debug seam): the exact label, and what is missing.
    std::env::set_var("SAIIFE_TEST_BLIND_NO_LANDLOCK", "1");
    let v = status_as(&f, OWN).await;
    std::env::remove_var("SAIIFE_TEST_BLIND_NO_LANDLOCK");
    ok(&v);
    assert_eq!(v["calculator"]["label"], "calculator not in a box (weaker)");
    assert_eq!(v["calculator"]["landlock"], "none");
    assert!(v["calculator"]["gap"]
        .as_str()
        .is_some_and(|g| !g.is_empty()));
    // The label is there at full strength too (P47-33).
    let v = status_as(&f, OWN).await;
    assert_eq!(v["calculator"]["label"], "calculator not in a box (weaker)");
    // The dataset itself.
    let d = crm_of(&v);
    assert_eq!(d["state"], "live");
    assert_eq!(
        d["role"],
        json!({"admin": true, "approver": true, "user": true})
    );
    assert!(d["snapshot_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(d["built_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(d["keys_version"], 1);
    let rows = d["rows"].as_array().unwrap();
    assert!(rows.iter().any(|r| r[0] == "customers" && r[1].is_string()));
    assert_eq!(d["methods"], json!({"active": 0, "suspended": []}));
    assert_eq!(v["sessions"], json!({"yours": 0}));
}

#[tokio::test]
async fn status_scoped_by_role() {
    let t = scratch();
    let f = locked_live(t.path()).await;
    // `me` is a user and an approver.
    let v = status_as(&f, OWN).await;
    ok(&v);
    assert_eq!(names(&v), ["crm"]);
    assert_eq!(
        crm_of(&v)["role"],
        json!({"admin": false, "approver": true, "user": true})
    );
    // `you` has no role on crm: it is not there at all.
    let v = status_as(&f, OTHER).await;
    ok(&v);
    assert!(names(&v).is_empty(), "{v}");
    assert!(!v.to_string().contains("crm"), "{v}");
    // Root is an admin: sees every dataset.
    let v = status_as(&f, 0).await;
    ok(&v);
    assert_eq!(names(&v), ["crm"]);
    assert_eq!(crm_of(&v)["role"]["admin"], true);
}

fn token(name: &str, services: &[&str]) -> Entry {
    Entry {
        name: name.into(),
        kind: Kind::Token,
        fields: [(
            "token".to_string(),
            Zeroizing::new(concat!("test-", "key-", "blind").to_string()),
        )]
        .into(),
        allowed_services: services.iter().map(|s| s.to_string()).collect(),
        created_by: 0,
        created: "2026-11-18T00:00:00Z".into(),
        last_used: None,
        rotate_after: None,
    }
}

fn put(f: &Fx, e: Entry) {
    let mut g = f.ctx.vault.lock();
    let VaultState::Ready(v) = &mut *g else {
        panic!("vault")
    };
    v.put(e).unwrap();
}

#[tokio::test]
async fn status_reports_ner_and_cloud() {
    let t = scratch();
    let f = fx(t.path());
    // Nothing configured.
    let v = status_as(&f, OWN).await;
    ok(&v);
    assert_eq!(v["ner"]["state"], "not configured");
    assert!(v["ner"].get("labels").is_none());
    assert_eq!(v["cloud"]["secret_present"], false);
    assert_eq!(v["cloud"]["model"], "claude-opus-5-5");
    // A cloud section whose secret is not in the vault.
    let base = "version = 2\n\n[blind.cloud]\nsecret = \"mk\"\nmodel = \"claude-test-1\"\n";
    set_policy(&f, base);
    let v = status_as(&f, OWN).await;
    assert_eq!(v["cloud"]["secret_present"], false);
    assert_eq!(v["cloud"]["model"], "claude-test-1");
    // Present, but not for blind-model.
    put(&f, token("mk", &["other"]));
    let v = status_as(&f, OWN).await;
    assert_eq!(v["cloud"]["secret_present"], false);
    // Present and allowed: true, and the key itself is nowhere.
    put(&f, token("mk", &["blind-model"]));
    let v = status_as(&f, OWN).await;
    assert_eq!(v["cloud"]["secret_present"], true);
    assert!(!v.to_string().contains(concat!("test-", "key-", "blind")));
    // A ner section whose files were never fetched.
    set_policy(
        &f,
        &format!(
            "{base}\n[blind.ner]\nmodel_url = \"https://example.invalid/m.onnx\"\n\
             model_sha256 = \"{h}\"\nvocab_url = \"https://example.invalid/v.txt\"\n\
             vocab_sha256 = \"{h}\"\nlabels_url = \"https://example.invalid/l.json\"\n\
             labels_sha256 = \"{h}\"\n",
            h = "0".repeat(64)
        ),
    );
    saiife_daemon::blind::ner::apply(Arc::clone(&f.ctx)).await;
    let v = status_as(&f, OWN).await;
    assert_eq!(v["ner"]["state"], "missing");
    assert!(v["ner"]["reason"].as_str().is_some_and(|r| !r.is_empty()));
}

#[tokio::test]
async fn status_warns_about_old_builds() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    f.ctx.blind.test_wait_builds().await;
    let v = status_as(&f, OWN).await;
    assert_eq!(crm_of(&v)["warnings"], json!([]), "{v}");
    // A v1 manifest (row-counted floors).
    let DatasetState::Live { manifest, open } = f.ctx.blind.state(&crm()) else {
        panic!("live")
    };
    let mut old = (*manifest).clone();
    old.v = 1;
    f.ctx.blind.set_state(
        &crm(),
        DatasetState::Live {
            manifest: Arc::new(old),
            open: Arc::clone(&open),
        },
    );
    let v = status_as(&f, OWN).await;
    let w = crm_of(&v)["warnings"].to_string();
    assert!(w.contains("saiife blind data refresh --dataset crm"), "{w}");
    f.ctx.blind.set_state(
        &crm(),
        DatasetState::Live {
            manifest,
            open: Arc::clone(&open),
        },
    );
    // A snapshot without the join indexes (built before they existed).
    let snap = f.ctx.blind.dataset_dir(&crm()).snapshot();
    std::fs::set_permissions(&snap, std::fs::Permissions::from_mode(0o600)).unwrap();
    let c = rusqlite::Connection::open(&snap).unwrap();
    let ix: Vec<String> = c
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'saiife\\_ix:%' ESCAPE '\\'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(!ix.is_empty(), "the fixture has join indexes");
    for n in ix {
        c.execute(&format!("DROP INDEX \"{n}\""), []).unwrap();
    }
    drop(c);
    std::fs::set_permissions(&snap, std::fs::Permissions::from_mode(0o400)).unwrap();
    let v = status_as(&f, OWN).await;
    let w = crm_of(&v)["warnings"].to_string();
    assert!(w.contains("saiife blind data refresh --dataset crm"), "{w}");
}

#[tokio::test]
async fn status_shows_needs_refresh_text() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    f.ctx.blind.test_wait_builds().await;
    f.ctx.blind.set_state(
        &crm(),
        DatasetState::NeedsRefresh("crm keys were deleted: saiife blind data refresh".into()),
    );
    let v = status_as(&f, OWN).await;
    let d = crm_of(&v);
    assert_eq!(d["state"], "needs_refresh");
    assert_eq!(
        d["reason"],
        "crm keys were deleted: saiife blind data refresh"
    );
}

fn approved(key: &str, sql: &str) -> ApprovedMethod {
    ApprovedMethod {
        id: String::new(),
        version: 1,
        dataset: crm(),
        lang: Lang::En,
        template_key: key.into(),
        param_tags: vec![],
        reply: PlanReply {
            method: sql.into(),
            template: "{int(n)}".into(),
            checks: vec![],
            intent: "count".into(),
            needs_judgment: false,
        },
        preview_sha256: "ab".into(),
        approved_by: "me".into(),
        approved_at: "2026-11-18T10:00:00Z".into(),
        touch: "key-1 #1".into(),
        status: MethodStatus::Active,
    }
}

fn store_two(f: &Fx) {
    let mut s = MethodStore::default();
    s.add(approved(
        "count invoices",
        "SELECT COUNT(*) AS n FROM invoices",
    ));
    let id = s
        .add(approved(
            "count credit",
            "SELECT COUNT(credit_limit) AS n FROM customers",
        ))
        .id
        .clone();
    s.methods.iter_mut().find(|m| m.id == id).unwrap().status = MethodStatus::Suspended {
        reason: "unknown_column".into(),
    };
    s.save(&ds_root(f).join("methods.json")).unwrap();
}

#[tokio::test]
async fn methods_list_scoped() {
    let t = scratch();
    let f = locked_live(t.path()).await;
    store_two(&f);
    let args = json!({"dataset": "crm"});
    // A user of the dataset lists them.
    let v = call_as(&f, OWN, OP_BLIND_METHODS_LIST, args.clone(), vec![]).await;
    ok(&v);
    let ms = v["methods"].as_array().unwrap();
    assert_eq!(ms.len(), 2);
    let m = ms
        .iter()
        .find(|m| m["template_key"] == "count invoices")
        .unwrap();
    assert_eq!(m["id"], "m-count-invoices-v1");
    assert_eq!(m["version"], 1);
    assert_eq!(m["lang"], "en");
    assert_eq!(m["param_tags"], json!([]));
    assert_eq!(m["approved_by"], "me");
    assert_eq!(m["approved_at"], "2026-11-18T10:00:00Z");
    assert_eq!(m["status"], json!({"state": "active"}));
    let s = ms
        .iter()
        .find(|m| m["template_key"] == "count credit")
        .unwrap();
    assert_eq!(
        s["status"],
        json!({"state": "suspended", "reason": "unknown_column"})
    );
    // Never the method text.
    let all = v.to_string();
    assert!(
        !all.contains("SELECT") && !all.contains("credit_limit"),
        "{all}"
    );
    // The status counts them.
    let st = status_as(&f, OWN).await;
    assert_eq!(
        crm_of(&st)["methods"],
        json!({"active": 1, "suspended": [{"id": "m-count-credit-v1", "reason": "unknown_column"}]})
    );
    // No role: refused, naming nothing.
    let v = call_as(&f, OTHER, OP_BLIND_METHODS_LIST, args.clone(), vec![]).await;
    let (code, msg) = err(&v);
    assert_eq!(code, "forbidden", "{v}");
    assert!(!msg.contains("count"), "{msg}");
    // An admin who is neither user nor approver: refused (users and
    // approvers only, R47-3).
    let v = call_as(&f, 0, OP_BLIND_METHODS_LIST, args, vec![]).await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
    // A name that is no dataset: the same refusal as an unlisted one.
    let v = call_as(
        &f,
        OWN,
        OP_BLIND_METHODS_LIST,
        json!({"dataset": "nope"}),
        vec![],
    )
    .await;
    assert_eq!(err(&v).0, "forbidden", "{v}");
}

#[tokio::test]
async fn status_tells_damaged_keys_from_a_locked_vault() {
    let t = scratch();
    let f = fx(t.path());
    build_live(&f, &[]).await;
    f.ctx.blind.test_wait_builds().await;
    let v = status_as(&f, OWN).await;
    assert_eq!(crm_of(&v)["keys_version"], 1);
    assert_eq!(crm_of(&v)["warnings"], json!([]), "{v}");
    // A flipped byte in keys.sealed.
    let p = ds_root(&f).join("keys.sealed");
    let good = std::fs::read(&p).unwrap();
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    std::fs::write(&p, &bad).unwrap();
    let v = status_as(&f, OWN).await;
    let d = crm_of(&v);
    assert_eq!(d["keys_version"], Value::Null);
    assert_eq!(
        d["warnings"],
        json!([
            "the dataset keys cannot be opened: saiife blind keys delete --dataset crm starts over"
        ]),
        "{v}"
    );
    // A locked vault: its own warning.
    std::fs::write(&p, &good).unwrap();
    *f.ctx.vault.lock() = VaultState::Unavailable("locked".into());
    let v = status_as(&f, OWN).await;
    let w = crm_of(&v)["warnings"].to_string();
    assert!(w.contains("the vault is unavailable"), "{w}");
    assert!(!w.contains("cannot be opened"), "{w}");
}
