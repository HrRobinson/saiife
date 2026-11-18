//! Data Shield records, the outbox and the log scrub (plan 47, Task 3;
//! R47-9, R47-10). Every value here is made up.
#![cfg(target_os = "linux")]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::audit_query::{self, Scope};
use saiife_daemon::blind::audit::{self, BlindRecord};
use saiife_daemon::blind::outbox::{Outbox, OutboxEntry};
use saiife_daemon::ops::{Ctx, CtxInit, Mode};
use saiife_daemon::vault::VaultState;
use saiife_daemon::writer::{self, WriterConfig};
use saiife_policy::{Directory, FixedDirectory, Fsync};
use saiife_shield::index::{build_index, IndexKey, KnownIndex};
use saiife_shield::schema::{
    ColType, ColumnClass, ColumnInfo, EntitySpec, Lang, Schema, TableInfo,
};
use saiife_shield::snapshot::build_snapshot;
use saiife_shield::source::{Cell, SourceTable, VecSource};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

const NAME: &str = "Quillfeather Brandvold";
const EMAIL: &str = "quillfeather.brandvold.1@example.invalid";

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn key() -> IndexKey {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    IndexKey(Zeroizing::new(k))
}

struct Fx {
    ctx: Arc<Ctx>,
    audit: PathBuf,
    index: KnownIndex,
}

fn fx(root: &Path) -> Fx {
    let audit = root.join("audit");
    std::fs::create_dir_all(&audit).unwrap();
    let state = root.join("state");
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
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        mode: Mode::Locked,
        vault: VaultState::Unavailable("not configured".into()),
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }));
    Fx {
        ctx,
        audit,
        index: index(root),
    }
}

fn col(name: &str, class: ColumnClass) -> ColumnInfo {
    ColumnInfo {
        name: name.into(),
        ty: ColType::Text,
        class,
        alias: None,
    }
}

/// An index of one rare customer and 40 common ones.
fn index(root: &Path) -> KnownIndex {
    let mut rows = vec![vec![
        Cell::Text("Quillfeather".into()),
        Cell::Text("Brandvold".into()),
        Cell::Text(EMAIL.into()),
    ]];
    for i in 0..40 {
        rows.push(vec![
            Cell::Text("Mette".into()),
            Cell::Text("Hansen".into()),
            Cell::Text(format!("mette.hansen.{i}@example.invalid")),
        ]);
    }
    let n = rows.len() as u64;
    let mut src = VecSource {
        tables: vec![(
            SourceTable {
                name: "customers".into(),
                columns: vec!["first_name".into(), "last_name".into(), "email".into()],
            },
            rows,
        )],
    };
    let ds = root.join("ds");
    let info = build_snapshot(&mut src, &ds, &mut |_| {}).unwrap();
    let schema = Schema {
        dataset: "crm".parse().unwrap(),
        tables: vec![TableInfo {
            name: "customers".into(),
            alias: Some("t1".into()),
            rows: n,
            columns: vec![
                col("first_name", ColumnClass::Identifier),
                col("last_name", ColumnClass::Identifier),
                col("email", ColumnClass::Identifier),
            ],
        }],
        entities: vec![EntitySpec {
            table: "customers".into(),
            key: "first_name".into(),
            names: vec!["first_name".into(), "last_name".into()],
            show: vec![],
            word: "customer".into(),
            word_da: "kunde".into(),
        }],
        joins: vec![],
    };
    build_index(&info.path, &schema, 10, &key(), &ds, &mut |_| {}).unwrap();
    KnownIndex::open(&ds, key()).unwrap()
}

fn all_records(audit: &Path, scope: Scope) -> Vec<serde_json::Value> {
    let q = audit_query::parse(&serde_json::Map::new()).unwrap();
    audit_query::run(audit, scope, &q).unwrap().records
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

fn sha(c: char) -> String {
    c.to_string().repeat(64)
}

fn every_variant() -> Vec<BlindRecord> {
    vec![
        BlindRecord::Ask {
            ask: "a1".into(),
            dataset: "crm".into(),
            lang: Lang::En,
            question: "how many customers in {city_1}".into(),
            session: "s1".into(),
            approved_method: Some("m1".into()),
        },
        BlindRecord::Resolve {
            ask: "a1".into(),
            params: vec![("city".into(), 2)],
            did_you_mean: 1,
            kept_names: 0,
        },
        BlindRecord::Preview {
            ask: "a1".into(),
            sha256: sha('a'),
            outcome: "shown",
            fragments: 3,
        },
        BlindRecord::Send {
            ask: "a1".into(),
            envelope_sha256: sha('b'),
            body_sha256: sha('c'),
            prompt_sha256: sha('d'),
            model: "claude-opus-5-5".into(),
            tables: 1,
            synthetic_rows: 5,
            params: 1,
            personal_values: 0,
            k: 10,
            attempt: 1,
        },
        BlindRecord::Receive {
            ask: "a1".into(),
            status: 200,
            bytes: 900,
            reply_sha256: sha('e'),
            leak: false,
            stop_reason: "end_turn".into(),
        },
        BlindRecord::Run {
            ask: "a1".into(),
            method: sha('f'),
            snapshot_sha256: sha('1'),
            ms: 12,
            rows_band: "10-99".into(),
            calculator: "exact-decimal",
            landlock_abi: 4,
            seccomp: true,
            netns: true,
        },
        BlindRecord::CheckRefused {
            ask: "a1".into(),
            reason: "class".into(),
        },
        BlindRecord::Approve {
            method: "m1".into(),
            version: 1,
            dataset: "crm".into(),
            template_sha256: sha('2'),
            touch: "t1".into(),
            action: "add",
        },
        BlindRecord::Keys {
            dataset: "crm".into(),
            action: "create",
            version: 1,
            touch: None,
        },
        BlindRecord::Refresh {
            dataset: "crm".into(),
            snapshot_sha256: sha('3'),
            rows: vec![("customers".into(), "41".into())],
            index_entries: 400,
            ms: 90,
            suspended: vec!["notes".into()],
            first: true,
        },
        BlindRecord::Loosen {
            dataset: "crm".into(),
            column: "customers.city".into(),
            from: ColumnClass::Quasi,
            to: ColumnClass::Public,
            touch: "t2".into(),
        },
        BlindRecord::Name {
            ask: "a1".into(),
            touch: "t3".into(),
            name_sha256: audit::name_sha256(&key(), NAME),
        },
    ]
}

#[tokio::test]
async fn records_have_no_values() {
    let t = scratch();
    let f = fx(t.path());
    for r in every_variant() {
        audit::write(&f.ctx, 1000, r, Some(&f.index)).await.unwrap();
    }
    let recs = all_records(&f.audit, Scope::All);
    let kinds: Vec<&str> = recs.iter().filter_map(|r| r["kind"].as_str()).collect();
    for k in [
        "blind_ask",
        "blind_resolve",
        "blind_preview",
        "blind_send",
        "blind_receive",
        "blind_run",
        "blind_check_refused",
        "blind_approve",
        "blind_keys",
        "blind_refresh",
        "blind_loosen",
        "blind_name",
    ] {
        assert!(kinds.contains(&k), "{k} missing in {kinds:?}");
    }
    assert!(!kinds.contains(&"blind_log_scrubbed"));
    let send = recs.iter().find(|r| r["kind"] == "blind_send").unwrap();
    assert_eq!(send["input"], "blind_send a1");
    assert_eq!(send["model"], "claude-opus-5-5");
    assert_eq!(send["k"], 10);
    let name = recs.iter().find(|r| r["kind"] == "blind_name").unwrap();
    // A keyed hash: not the plain sha256 of the name, stable for the key.
    assert_eq!(name["name_sha256"], audit::name_sha256(&key(), NAME));
    assert_eq!(
        audit::name_sha256(&key(), "  QUILLFEATHER brandvold "),
        name["name_sha256"].as_str().unwrap()
    );
    let raw = raw_log(&f.audit);
    for v in [NAME, "Quillfeather", "Brandvold", EMAIL] {
        assert!(!raw.contains(v), "{v} in the audit log");
    }
}

#[tokio::test]
async fn scrub_drops_and_marks() {
    let t = scratch();
    let f = fx(t.path());
    let r = BlindRecord::Ask {
        ask: "a2".into(),
        dataset: "crm".into(),
        lang: Lang::En,
        question: format!("what did {NAME} pay"),
        session: "s1".into(),
        approved_method: None,
    };
    audit::write(&f.ctx, 1000, r, Some(&f.index)).await.unwrap();
    let recs = all_records(&f.audit, Scope::All);
    let ask = recs.iter().find(|r| r["kind"] == "blind_ask").unwrap();
    assert!(ask.get("question").is_none(), "{ask}");
    assert_eq!(ask["ask"], "a2");
    let mark = recs
        .iter()
        .find(|r| r["kind"] == "blind_log_scrubbed")
        .unwrap();
    assert_eq!(mark["scrubbed_kind"], "blind_ask");
    assert_eq!(mark["field"], "question");
    assert!(!raw_log(&f.audit).contains("Quillfeather"));
}

#[tokio::test]
async fn scrub_catches_a_value_in_a_list() {
    let t = scratch();
    let f = fx(t.path());
    let r = BlindRecord::Refresh {
        dataset: "crm".into(),
        snapshot_sha256: sha('3'),
        rows: vec![("customers".into(), "41".into())],
        index_entries: 1,
        ms: 1,
        suspended: vec!["notes".into(), EMAIL.into()],
        first: false,
    };
    audit::write(&f.ctx, 1000, r, Some(&f.index)).await.unwrap();
    let recs = all_records(&f.audit, Scope::All);
    let rf = recs.iter().find(|r| r["kind"] == "blind_refresh").unwrap();
    assert!(rf.get("suspended").is_none());
    assert_eq!(rf["rows"][0][0], "customers");
    assert!(!raw_log(&f.audit).contains("quillfeather"));
}

#[tokio::test]
async fn write_fails_when_the_writer_refuses() {
    let t = scratch();
    let f = fx(t.path());
    // A stopped writer refuses every append; the error must surface.
    let rec = BlindRecord::Keys {
        dataset: "crm".into(),
        action: "create",
        version: 1,
        touch: None,
    };
    audit::write(&f.ctx, 1, rec, None).await.unwrap();
    f.ctx.writer.stop(None).await.unwrap();
    let rec = BlindRecord::Keys {
        dataset: "crm".into(),
        action: "rotate",
        version: 2,
        touch: None,
    };
    let e = audit::write(&f.ctx, 1, rec, None).await;
    assert!(e.is_err(), "a refused write must be an error");
}

fn entry(ts: &str, sha: &str, body: &str) -> OutboxEntry {
    OutboxEntry {
        ts: ts.into(),
        sha256: sha.into(),
        uid: 1000,
        dataset: "crm".into(),
        ask: "a1".into(),
        body: body.into(),
    }
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn outbox_append_fsync_0600() {
    let t = scratch();
    let dir = t.path().join("blind/outbox");
    let ob = Outbox::new(dir.clone());
    ob.append(&entry("2026-11-17T10:00:00.000Z", &sha('a'), "{\"x\":1}"))
        .unwrap();
    ob.append(&entry("2026-11-18T10:00:00.000Z", &sha('b'), "{\"x\":2}"))
        .unwrap();
    assert_eq!(mode(&dir), 0o700);
    let f = dir.join("2026-11.jsonl");
    assert_eq!(mode(&f), 0o600);
    let text = std::fs::read_to_string(&f).unwrap();
    assert_eq!(text.lines().count(), 2);
    let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(v["body"], "{\"x\":1}");
    assert_eq!(v["uid"], 1000);
    // A loose file left from before is repaired, never followed as a link.
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    ob.append(&entry("2026-11-19T10:00:00.000Z", &sha('c'), "{}"))
        .unwrap();
    assert_eq!(mode(&f), 0o600);
    let target = t.path().join("elsewhere");
    std::fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, dir.join("2026-12.jsonl")).unwrap();
    assert!(ob
        .append(&entry("2026-12-01T00:00:00.000Z", &sha('d'), "{}"))
        .is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
    // A ts that is not a date never makes a file name.
    assert!(ob.append(&entry("../../etc", &sha('e'), "{}")).is_err());
}

#[test]
fn outbox_purge_by_month() {
    let t = scratch();
    let dir = t.path().join("outbox");
    let ob = Outbox::new(dir.clone());
    for ts in [
        "2025-01-15T00:00:00.000Z",
        "2025-12-15T00:00:00.000Z",
        "2026-01-15T00:00:00.000Z",
        "2026-11-15T00:00:00.000Z",
    ] {
        ob.append(&entry(ts, &sha('a'), "{}")).unwrap();
    }
    std::fs::write(dir.join("notes.txt"), b"x").unwrap();
    // 2026-11-18, 365 days: a month that ended before 2025-11-18 goes.
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_794_960_000);
    assert_eq!(ob.purge(now, 365).unwrap(), 1);
    assert!(!dir.join("2025-01.jsonl").exists());
    assert!(dir.join("2025-12.jsonl").exists());
    assert!(dir.join("notes.txt").exists());
    // Zero days keeps only what has not ended yet.
    assert_eq!(ob.purge(now, 0).unwrap(), 2);
    assert!(dir.join("2026-11.jsonl").exists());
    assert_eq!(ob.purge(now, 0).unwrap(), 0);
}

#[test]
fn outbox_find() {
    let t = scratch();
    let ob = Outbox::new(t.path().join("outbox"));
    assert!(ob.find(&sha('a')).unwrap().is_none());
    ob.append(&entry("2026-10-17T10:00:00.000Z", &sha('a'), "{\"o\":1}"))
        .unwrap();
    ob.append(&entry("2026-11-17T10:00:00.000Z", &sha('b'), "{\"o\":2}"))
        .unwrap();
    let e = ob.find(&sha('b')).unwrap().unwrap();
    assert_eq!(e.body, "{\"o\":2}");
    assert_eq!(e.ask, "a1");
    assert_eq!(ob.find(&sha('a')).unwrap().unwrap().body, "{\"o\":1}");
    assert!(ob.find(&sha('c')).unwrap().is_none());
    // The body never shows in Debug.
    assert!(!format!("{e:?}").contains("\"o\""));
}

#[tokio::test]
async fn user_sees_own_blind_records() {
    let t = scratch();
    let f = fx(t.path());
    for (uid, ask) in [(1000u32, "mine"), (2000, "theirs")] {
        let r = BlindRecord::CheckRefused {
            ask: ask.into(),
            reason: "class".into(),
        };
        audit::write(&f.ctx, uid, r, Some(&f.index)).await.unwrap();
    }
    let mine = all_records(&f.audit, Scope::Uid(1000));
    let asks: Vec<&str> = mine.iter().filter_map(|r| r["ask"].as_str()).collect();
    assert_eq!(asks, ["mine"], "{mine:?}");
    assert_eq!(mine[0]["kind"], "blind_check_refused");
    assert_eq!(mine[0]["uid"], 1000);
    let theirs = all_records(&f.audit, Scope::Uid(2000));
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0]["ask"], "theirs");
}
