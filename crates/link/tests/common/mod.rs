//! Shared harness: an in-process daemon with `link.sock` on a tempdir (the
//! pattern of crates/daemon/tests/workspace_link.rs).
#![allow(dead_code)]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::ops::{self, Ctx, CtxInit, Mode as DaemonMode};
use saiife_daemon::workspace::{dir_in, now_secs, Workspace};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::msg::{Request, LINK_SOCKET_NAME};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync, GroupEntry, UserEntry};
use saiife_wire::fake::FakeBoxSource;
use saiife_wire::source::BoxSource;
use serde_json::{Map, Value};
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

pub fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

/// A scratch dir outside /tmp: `SAIIFE_TEST_TMP`, else cargo's target tmp.
pub fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::tempdir_in(base).unwrap()
}

pub struct World {
    pub ctx: Arc<Ctx>,
    pub boxes: Arc<FakeBoxSource>,
    pub run: PathBuf,
    pub _tmp: tempfile::TempDir,
}

/// The personal broker of this test's uid (named `me`), its Workspace in
/// `state` (a fresh dir unless given), its audit chain in its own dir.
pub async fn world_in(state: Option<PathBuf>) -> World {
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
        boxes: Arc::clone(&boxes) as Arc<dyn BoxSource>,
        ..CtxInit::minimal(handle, cfg, Arc::new(Dir(Arc::clone(&users))), &state)
    }));
    let listener = UnixListener::bind(run.join(LINK_SOCKET_NAME)).unwrap();
    tokio::spawn(saiife_daemon::server::serve_link(
        listener,
        Arc::clone(&ctx),
    ));
    World {
        ctx,
        boxes,
        run,
        _tmp: tmp,
    }
}

pub async fn world() -> World {
    world_in(None).await
}

pub fn args(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

pub fn peer() -> PeerCred {
    PeerCred {
        uid: me(),
        gid: me(),
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

/// A control-socket op, as this test's uid.
pub async fn control(w: &World, op: &str, a: Value) -> Value {
    let req = Request {
        id: 1,
        op: op.into(),
        args: args(a),
    };
    ops::dispatch(&w.ctx, &peer(), req).await
}
