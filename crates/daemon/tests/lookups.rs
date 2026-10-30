//! Directory lookups in the daemon fail closed: a failed group lookup is
//! never cached as "no groups", and `policy.show` answers an error rather
//! than a policy without the user's environment.
#![cfg(unix)]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::ops::{Ctx, CtxInit, PolicyState};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::Request as IpcRequest;
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync, GroupEntry, UserEntry};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// `alice` (uid 4242) in group `devs`; group lookups fail while `down`.
#[derive(Default)]
struct Flaky {
    down: AtomicBool,
    lookups: AtomicUsize,
}

impl Directory for Flaky {
    fn user(&self, name: &str) -> Option<UserEntry> {
        (name == "alice").then_some(UserEntry {
            uid: 4242,
            gid: 4242,
        })
    }
    fn name_of(&self, uid: u32) -> Option<String> {
        (uid == 4242).then(|| "alice".to_string())
    }
    fn group(&self, _name: &str) -> Option<GroupEntry> {
        None
    }
    fn groups_of(&self, user: &str) -> Vec<String> {
        self.try_groups_of(user).unwrap_or_default()
    }
    fn try_groups_of(&self, user: &str) -> Result<Vec<String>, String> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        if self.down.load(Ordering::SeqCst) {
            return Err("nss down".into());
        }
        Ok(if user == "alice" {
            vec!["devs".into()]
        } else {
            Vec::new()
        })
    }
}

const CONFIG: &str = r#"version = 2
locked = true

[admin]
groups = ["devs"]

[[scope]]
name = "devs"
users = ["group:devs"]
services = []
env = "prod"

[environments.prod]
guard.packs = ["db.postgres"]
"#;

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

fn ctx(tmp: &tempfile::TempDir, dir: Arc<Flaky>) -> Arc<Ctx> {
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
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
    let writer_cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, writer_cfg, None).unwrap();
    let config = tmp.path().join("config.toml");
    std::fs::write(&config, CONFIG).unwrap();
    let l = saiife_policy::load_system(&config).unwrap();
    let policy = PolicyState::from_loaded(&l, &[], saiife_broker::Catalog::new(&[], vec![]));
    Arc::new(Ctx::new(CtxInit {
        audit_dir: audit,
        config_path: config,
        policy,
        ..CtxInit::minimal(handle, writer_cfg, dir, &state)
    }))
}

fn alice() -> PeerCred {
    PeerCred {
        uid: 4242,
        gid: 4242,
        pid: std::process::id(),
    }
}

async fn show(ctx: &Arc<Ctx>) -> Value {
    let req = IpcRequest {
        id: 9,
        op: "policy.show".into(),
        args: json!({}).as_object().unwrap().clone(),
    };
    saiife_daemon::ops::dispatch(ctx, &alice(), req).await
}

/// A failed group lookup is not remembered: the next call looks again
/// (within the 60 s TTL) and gets the answer.
#[tokio::test]
async fn failed_group_lookup_is_not_cached() {
    let tmp = scratch();
    let dir = Arc::new(Flaky::default());
    let ctx = ctx(&tmp, Arc::clone(&dir));
    dir.down.store(true, Ordering::SeqCst);
    assert!(ctx.try_groups_of("alice").await.is_err());
    assert!(!ctx.is_admin(4242).await, "a failed lookup is not an admin");
    dir.down.store(false, Ordering::SeqCst);
    assert_eq!(ctx.try_groups_of("alice").await.unwrap(), ["devs"]);
    assert!(ctx.is_admin(4242).await);
    // An answer is cached: no further lookup.
    let n = dir.lookups.load(Ordering::SeqCst);
    assert!(ctx.is_admin(4242).await);
    assert_eq!(dir.lookups.load(Ordering::SeqCst), n);
}

/// `policy.show` with a failed group lookup is an error, never the view of
/// a user with no scope and no environment.
#[tokio::test]
async fn policy_show_lookup_failure_is_an_error() {
    let tmp = scratch();
    let dir = Arc::new(Flaky::default());
    let ctx = ctx(&tmp, Arc::clone(&dir));
    let a = show(&ctx).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["view"]["scope"]["env"], "prod", "{a}");

    dir.down.store(true, Ordering::SeqCst);
    let a = show(&ctx).await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "unavailable", "{a}");
    assert!(
        a["message"].as_str().unwrap_or("").contains("nss down"),
        "{a}"
    );
}
