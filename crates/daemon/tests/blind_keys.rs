//! The Data Shield key store (plan 47, Task 1; R47-1, R47-2): each
//! dataset's `KeySet` sealed with the vault key into `keys.sealed`, an
//! unavailable vault or a damaged file refusing (never unkeyed), rotation
//! keeping the old stand-in key as retired, and crypto-shredding. Also: every
//! `blind.*` op reaches the blind module.
#![cfg(target_os = "linux")]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::blind::keys::{self, KeyError};
use saiife_daemon::blind::DatasetState;
use saiife_daemon::ops::{Ctx, CtxInit, Mode};
use saiife_daemon::vault::{self, VaultState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::{ErrorCode, Request, FD_OPS, OP_BLIND_DATA_REFRESH, OP_BLIND_DATA_STAGE};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, FixedDirectory, Fsync};
use saiife_shield::schema::DatasetName;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

/// A context over `root/state`, its vault opened with `key` (none:
/// unavailable). Each has its own audit dir (the chain is locked).
fn ctx(root: &Path, key: Option<[u8; 32]>) -> Arc<Ctx> {
    std::fs::create_dir_all(root.join("audits")).unwrap();
    let audit = tempfile::tempdir_in(root.join("audits")).unwrap().keep();
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
    let vault = match key {
        Some(k) => vault::open_with_key(Zeroizing::new(k), &state.join("vault").join("vault.bin")),
        None => VaultState::Unavailable("not configured".into()),
    };
    Arc::new(Ctx::new(CtxInit {
        audit_dir: audit,
        mode: Mode::Locked,
        vault,
        ..CtxInit::minimal(handle, cfg, dirs, &state)
    }))
}

fn crm() -> DatasetName {
    "crm".parse().unwrap()
}

fn sealed_path(ctx: &Ctx, ds: &DatasetName) -> PathBuf {
    ctx.blind.dataset_dir(ds).root.join("keys.sealed")
}

fn mode_of(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// A session of `ds` for uid 1000, as an ask would make it; its id.
fn session_id(ctx: &Ctx, ds: &DatasetName, keys: &saiife_shield::standin::KeySet) -> [u8; 16] {
    let mut s = ctx.blind.sessions.lock().unwrap();
    s.get_or_new(
        1000,
        ds,
        keys,
        1_800_000_000,
        Duration::from_secs(1800),
        false,
    )
    .unwrap()
    .id
    .0
}

#[tokio::test]
async fn keys_round_trip_sealed() {
    let t = scratch();
    let c = ctx(t.path(), Some([7; 32]));
    let ds = crm();
    let made = keys::create(&c, &ds).unwrap();
    let p = sealed_path(&c, &ds);
    assert_eq!(mode_of(&p), 0o600);
    assert_eq!(mode_of(p.parent().unwrap()), 0o700);
    assert_eq!(mode_of(&c.blind.root), 0o700);
    let on_disk = std::fs::read(&p).unwrap();
    let plain = made.to_bytes();
    assert!(!on_disk.windows(plain.len()).any(|w| w == &plain[..]));
    assert!(!on_disk.windows(9).any(|w| w == b"\"version\""));
    let loaded = keys::load(&c, &ds).unwrap();
    assert_eq!(loaded.version, made.version);
    assert_eq!(loaded, made);
    // No temp file is left beside it.
    let names: Vec<_> = std::fs::read_dir(p.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["keys.sealed"]);
    // A second create refuses: the keys are never replaced by accident.
    assert!(matches!(keys::create(&c, &ds), Err(KeyError::Exists)));
    assert_eq!(keys::load(&c, &ds).unwrap(), made);
    // Debug prints versions only.
    let dbg = format!("{loaded:?}");
    assert!(dbg.contains("version") && !dbg.contains("standin:") && !dbg.contains("index:"));
}

#[tokio::test]
async fn vault_unavailable_refuses() {
    let t = scratch();
    let ds = crm();
    let made = keys::create(&ctx(t.path(), Some([7; 32])), &ds).unwrap();
    let locked = ctx(t.path(), None);
    assert!(matches!(
        keys::load(&locked, &ds),
        Err(KeyError::VaultUnavailable)
    ));
    assert!(matches!(
        keys::rotate(&locked, &ds),
        Err(KeyError::VaultUnavailable)
    ));
    let other: DatasetName = "hr".parse().unwrap();
    assert!(matches!(
        keys::create(&locked, &other),
        Err(KeyError::VaultUnavailable)
    ));
    assert!(matches!(
        keys::load(&locked, &other),
        Err(KeyError::VaultUnavailable)
    ));
    assert!(!sealed_path(&locked, &other).exists());
    let r = KeyError::VaultUnavailable.refusal(&ds);
    assert_eq!(r.code, ErrorCode::Unavailable);
    assert_eq!(r.text, "the vault is unavailable");
    // The file is untouched: the vault back, the keys are there.
    assert_eq!(
        keys::load(&ctx(t.path(), Some([7; 32])), &ds).unwrap(),
        made
    );
}

#[tokio::test]
async fn damaged_keys_refuse() {
    let t = scratch();
    let c = ctx(t.path(), Some([7; 32]));
    let ds = crm();
    keys::create(&c, &ds).unwrap();
    let p = sealed_path(&c, &ds);
    let good = std::fs::read(&p).unwrap();
    for i in [0, 30, good.len() - 1] {
        let mut b = good.clone();
        b[i] ^= 0x01;
        std::fs::write(&p, &b).unwrap();
        assert!(
            matches!(keys::load(&c, &ds), Err(KeyError::Damaged)),
            "byte {i}"
        );
        assert!(
            matches!(keys::rotate(&c, &ds), Err(KeyError::Damaged)),
            "byte {i}"
        );
    }
    std::fs::write(&p, &good[..10]).unwrap();
    assert!(matches!(keys::load(&c, &ds), Err(KeyError::Damaged)));
    // Another vault key, or the file of another dataset (AAD), is damaged too.
    std::fs::write(&p, &good).unwrap();
    assert!(matches!(
        keys::load(&ctx(t.path(), Some([8; 32])), &ds),
        Err(KeyError::Damaged)
    ));
    let hr: DatasetName = "hr".parse().unwrap();
    let hp = sealed_path(&c, &hr);
    std::fs::create_dir_all(hp.parent().unwrap()).unwrap();
    std::fs::write(&hp, &good).unwrap();
    assert!(matches!(keys::load(&c, &hr), Err(KeyError::Damaged)));
    let r = KeyError::Damaged.refusal(&ds);
    assert_eq!(r.code, ErrorCode::Unavailable);
    assert_eq!(
        r.text,
        "the dataset keys cannot be opened: saiife blind keys delete --dataset crm starts over"
    );
    // Missing is its own answer.
    assert!(matches!(
        keys::load(&c, &"none".parse().unwrap()),
        Err(KeyError::Missing)
    ));
}

#[tokio::test]
async fn rotate_keeps_retired() {
    let t = scratch();
    let c = ctx(t.path(), Some([7; 32]));
    let ds = crm();
    let made = keys::create(&c, &ds).unwrap();
    let before = session_id(&c, &ds, &made);
    let other: DatasetName = "hr".parse().unwrap();
    let other_keys = keys::create(&c, &other).unwrap();
    let other_session = session_id(&c, &other, &other_keys);
    assert_eq!(keys::rotate(&c, &ds).unwrap(), 2);
    let now = keys::load(&c, &ds).unwrap();
    assert_eq!(now.version, 2);
    assert_ne!(*now.standin, *made.standin);
    assert_eq!(*now.index, *made.index, "the index key is kept");
    assert_eq!(now.retired.len(), 1);
    assert_eq!(now.retired[0].version, 1);
    assert_eq!(*now.retired[0].standin, *made.standin);
    assert_eq!(mode_of(&sealed_path(&c, &ds)), 0o600);
    // The dataset's sessions are dropped; another dataset's stay.
    assert_ne!(session_id(&c, &ds, &now), before);
    assert_eq!(session_id(&c, &other, &other_keys), other_session);
    assert_eq!(keys::rotate(&c, &ds).unwrap(), 3);
    assert_eq!(keys::load(&c, &ds).unwrap().retired.len(), 2);
    // No keys, nothing to rotate.
    assert!(matches!(
        keys::rotate(&c, &"none".parse().unwrap()),
        Err(KeyError::Missing)
    ));
}

#[tokio::test]
async fn shred_removes_key_index_and_sessions() {
    let t = scratch();
    let c = ctx(t.path(), Some([7; 32]));
    let ds = crm();
    let made = keys::create(&c, &ds).unwrap();
    let dir = c.blind.dataset_dir(&ds);
    std::fs::create_dir_all(dir.live()).unwrap();
    let (index, bloom) = (dir.live().join("index.bin"), dir.live().join("index.bloom"));
    std::fs::write(&index, b"x").unwrap();
    std::fs::write(&bloom, b"y").unwrap();
    std::fs::write(dir.lexicon(), b"z").unwrap();
    let before = session_id(&c, &ds, &made);
    keys::shred(&c, &ds).unwrap();
    assert!(!sealed_path(&c, &ds).exists());
    assert!(!index.exists() && !bloom.exists());
    assert!(
        dir.lexicon().exists(),
        "only what the old index key built goes"
    );
    assert_ne!(session_id(&c, &ds, &made), before);
    assert!(matches!(c.blind.state(&ds), DatasetState::NeedsRefresh(_)));
    let r = c.blind.live(&ds).unwrap_err();
    assert_eq!(r.code, ErrorCode::Unavailable);
    assert!(
        r.text.contains("crm") && r.text.contains("refresh"),
        "{}",
        r.text
    );
    assert!(matches!(keys::load(&c, &ds), Err(KeyError::Missing)));
    // Again: nothing left to remove is not an error.
    keys::shred(&c, &ds).unwrap();
    // The next refresh makes new keys.
    let fresh = keys::create(&c, &ds).unwrap();
    assert_ne!(*fresh.index, *made.index);
}

fn peer() -> PeerCred {
    PeerCred {
        uid: 0,
        gid: 0,
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

#[tokio::test]
async fn ops_registered() {
    let t = scratch();
    let c = ctx(t.path(), Some([7; 32]));
    assert_eq!(saiife_daemon::blind::OPS, saiife_ipc::msg::BLIND_OPS);
    for op in saiife_daemon::blind::OPS {
        let req = Request {
            id: 5,
            op: (*op).to_string(),
            args: serde_json::Map::new(),
        };
        let a = saiife_daemon::ops::dispatch(&c, &peer(), req).await;
        assert_eq!(a["ok"], false, "{op}: {a}");
        // Task 2 built the data ops: with no arguments they ask for one.
        if op.starts_with("blind.data.") {
            assert_eq!(a["error"], "bad_request", "{op}: {a}");
            assert_eq!(a["message"], "dataset is required", "{op}: {a}");
            continue;
        }
        // Task 4 built the fetch: with no `[blind.ner]` it names it.
        if *op == saiife_ipc::msg::OP_BLIND_NER_FETCH {
            assert_eq!(a["error"], "bad_request", "{op}: {a}");
            assert!(
                a["message"].as_str().unwrap_or("").contains("[blind.ner]"),
                "{op}: {a}"
            );
            continue;
        }
        assert_eq!(a["error"], "unavailable", "{op}: {a}");
        assert_eq!(
            a["message"],
            format!("{op} is not available in this build yet"),
            "{op}: {a}"
        );
    }
    assert!(FD_OPS.contains(&OP_BLIND_DATA_STAGE));
    assert!(FD_OPS.contains(&OP_BLIND_DATA_REFRESH));
}
