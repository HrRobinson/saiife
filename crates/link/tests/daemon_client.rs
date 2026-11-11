//! `Daemon::call` against an in-process daemon with `link.sock` on a tempdir
//! (the harness pattern of crates/daemon/tests/workspace_link.rs).
#![cfg(unix)]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::ops::{Ctx, CtxInit, Mode as DaemonMode};
use saiife_daemon::workspace::{dir_in, now_secs, Workspace};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::{LINK_SOCKET_NAME, OP_WORKSPACE_HELLO, OP_WORKSPACE_SIGN};
use saiife_link::{Daemon, LinkError};
use saiife_policy::{Directory, Fsync, GroupEntry, UserEntry};
use saiife_wire::fake::FakeBoxSource;
use saiife_wire::source::BoxSource;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UnixListener;

const ME: &str = "me";

/// `user(name)` from a table the test can change; no groups.
#[derive(Default)]
struct Users(Mutex<HashMap<String, u32>>);

impl Users {
    fn set(&self, name: &str, uid: u32) {
        self.0.lock().unwrap().insert(name.into(), uid);
    }
}

struct Dir(Arc<Users>);

impl Directory for Dir {
    fn user(&self, name: &str) -> Option<UserEntry> {
        let uid = *self.0 .0.lock().unwrap().get(name)?;
        Some(UserEntry { uid, gid: uid })
    }
    fn name_of(&self, uid: u32) -> Option<String> {
        self.0
             .0
            .lock()
            .unwrap()
            .iter()
            .find(|(_, u)| **u == uid)
            .map(|(n, _)| n.clone())
    }
    fn group(&self, _name: &str) -> Option<GroupEntry> {
        None
    }
    fn groups_of(&self, _user: &str) -> Vec<String> {
        Vec::new()
    }
}

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

/// A scratch dir outside /tmp: `SAIIFE_TEST_TMP`, else cargo's target tmp.
fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

struct World {
    _ctx: Arc<Ctx>,
    run: PathBuf,
    _tmp: tempfile::TempDir,
}

/// The personal broker of this test's uid (named `me`), its Workspace in
/// `state` (a fresh dir unless given), its audit chain in its own dir.
async fn world_in(state: Option<PathBuf>) -> World {
    let tmp = scratch();
    let state = state.unwrap_or_else(|| tmp.path().join("state"));
    let (ws, warning) = Workspace::open(dir_in(&state));
    assert!(warning.is_none(), "{warning:?}");
    build(tmp, state, ws).await
}

async fn build(tmp: tempfile::TempDir, state: PathBuf, ws: Workspace) -> World {
    let audit = tmp.path().join("audit");
    let run = tmp.path().join("run");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(&run).unwrap();
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
    let users = Arc::new(Users::default());
    users.set(ME, me());
    let boxes = Arc::new(FakeBoxSource::demo(now_secs()));
    let ctx = Arc::new(Ctx::new(CtxInit {
        mode: DaemonMode::Personal,
        own_uid: me(),
        own_user: ME.into(),
        audit_dir: audit.clone(),
        socket_dir: run.clone(),
        workspace: Arc::new(ws),
        boxes: boxes.clone() as Arc<dyn BoxSource>,
        ..CtxInit::minimal(handle, cfg, Arc::new(Dir(Arc::clone(&users))), &state)
    }));
    let listener = UnixListener::bind(run.join(LINK_SOCKET_NAME)).unwrap();
    tokio::spawn(saiife_daemon::server::serve_link(
        listener,
        Arc::clone(&ctx),
    ));
    World {
        _ctx: ctx,
        run,
        _tmp: tmp,
    }
}

async fn world() -> World {
    world_in(None).await
}

fn args(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[tokio::test]
async fn daemon_call_roundtrip() {
    let w = world().await;
    let d = Daemon::new(w.run.clone(), me());

    let hello = d.call(OP_WORKSPACE_HELLO, args(json!({}))).await.unwrap();
    assert!(
        hello["machine_id"].as_str().is_some_and(|m| !m.is_empty()),
        "{hello:?}"
    );

    // An op link.sock does not serve is refused before its args are read.
    match d.call("policy.reload", args(json!({}))).await {
        Err(LinkError::Refused { error, .. }) => assert_eq!(error, "unknown_op"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn refusal_keeps_the_daemons_rule() {
    let w = world().await;
    let d = Daemon::new(w.run.clone(), me());
    // A hub hello that is not for this machine: bad_request with its rule.
    let r = d
        .call(
            OP_WORKSPACE_SIGN,
            args(json!({"purpose": "hub_hello", "data": "AAAA"})),
        )
        .await;
    match r {
        Err(LinkError::Refused { rule, message, .. }) => {
            assert_eq!(rule.as_deref(), Some("bad_request"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn missing_daemon_is_unreachable() {
    let tmp = scratch();
    let d = Daemon::new(tmp.path().to_path_buf(), me());
    match d.call(OP_WORKSPACE_HELLO, args(json!({}))).await {
        Err(LinkError::Unreachable(_)) => {}
        other => panic!("{other:?}"),
    }
}
