//! `link.sock` end to end in process (plan 29, Task 4): a daemon context on
//! temp dirs (the real audit writer, a Workspace on disk, the wire crate's
//! demo boxes), `server::serve_link` on a Unix socket, and a `TestDevice`
//! paired through the control ops and `workspace.pair.finish`. The tests
//! speak the daemon's frames over the socket by hand, so every answer's
//! `rule` is visible.
#![cfg(unix)]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_daemon::ops::{self, Ctx, CtxInit, Mode as DaemonMode};
use saiife_daemon::workspace::{dir_in, now_secs, Workspace};
use saiife_daemon::workspace_ops::{HANDLED, LATER};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_ipc::frame::{body_len_max, encode_max, MAX_ANSWER_FRAME, MAX_FRAME};
use saiife_ipc::msg::{
    Request, LINK_OPS, LINK_SOCKET_NAME, OP_HELLO, OP_STATUS, OP_WORKSPACE_FRAME,
    OP_WORKSPACE_HELLO, OP_WORKSPACE_PAIR_BEGIN, OP_WORKSPACE_PAIR_CONFIRM,
    OP_WORKSPACE_PAIR_FINISH, OP_WORKSPACE_REVOKE, OP_WORKSPACE_SIGN, OP_WORKSPACE_WAKE, PROTO,
};
use saiife_ipc::peer::PeerCred;
use saiife_policy::{Directory, Fsync, GroupEntry, UserEntry};
use saiife_wire::fake::{FakeBoxSource, FakeCall};
use saiife_wire::frame::{Frame, SignedFrame};
use saiife_wire::level::{Level, REMOTE};
use saiife_wire::seal::{MachineHandshake, SealBinding, TestBrowserEnd};
use saiife_wire::sig::TestDevice;
use saiife_wire::source::{BoxId, BoxSource, Start};
use saiife_wire::{b64, pair};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

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
    ctx: Arc<Ctx>,
    boxes: Arc<FakeBoxSource>,
    users: Arc<Users>,
    run: PathBuf,
    audit: PathBuf,
    state: PathBuf,
    _tmp: tempfile::TempDir,
    _keep: Option<tempfile::TempDir>,
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
    build_as(tmp, state, ws, DaemonMode::Personal, me()).await
}

/// [`build`] with the daemon's mode and own uid.
async fn build_as(
    tmp: tempfile::TempDir,
    state: PathBuf,
    ws: Workspace,
    mode: DaemonMode,
    own: u32,
) -> World {
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
        mode,
        own_uid: own,
        own_user: ME.into(),
        audit_dir: audit.clone(),
        socket_dir: run.clone(),
        workspace: Arc::new(ws),
        boxes: boxes.clone() as Arc<dyn BoxSource>,
        approvals: saiife_daemon::approvals::Store::open(&saiife_daemon::approvals::dir_in(&state))
            .map_err(|e| e.to_string()),
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
        users,
        run,
        audit,
        state,
        _tmp: tmp,
        _keep: None,
    }
}

async fn world() -> World {
    world_in(None).await
}

fn peer() -> PeerCred {
    PeerCred {
        uid: me(),
        gid: me(),
        pid: std::process::id(),
        sid: None,
        group_sids: Vec::new(),
    }
}

/// A control-socket op, as this test's uid.
async fn control(w: &World, op: &str, args: Value) -> Value {
    let req = Request {
        id: 1,
        op: op.into(),
        args: args.as_object().unwrap().clone(),
    };
    ops::dispatch(&w.ctx, &peer(), req).await
}

/// A raw client of `link.sock`.
struct Link {
    s: UnixStream,
    next: u64,
}

impl Link {
    async fn open(w: &World) -> Link {
        let s = UnixStream::connect(w.run.join(LINK_SOCKET_NAME))
            .await
            .unwrap();
        let mut l = Link { s, next: 1 };
        let h = l.call(OP_HELLO, json!({"proto": PROTO})).await;
        assert_eq!(h["ok"], true, "{h}");
        l
    }

    async fn call(&mut self, op: &str, args: Value) -> Value {
        let mut m = args.as_object().unwrap().clone();
        m.insert("id".into(), self.next.into());
        m.insert("op".into(), op.into());
        self.next += 1;
        let bytes = encode_max(&Value::Object(m), MAX_FRAME).unwrap();
        self.s.write_all(&bytes).await.unwrap();
        let mut h = [0u8; 4];
        self.s.read_exact(&mut h).await.unwrap();
        let n = body_len_max(h, MAX_ANSWER_FRAME).unwrap();
        let mut body = vec![0u8; n];
        self.s.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}

/// Pairs a new device through the control ops and `link.sock`.
async fn pair_device(w: &World, link: &mut Link) -> TestDevice {
    let b = control(w, OP_WORKSPACE_PAIR_BEGIN, json!({"label": "laptop"})).await;
    assert_eq!(b["ok"], true, "{b}");
    let (pair_id, secret, _, _) = pair::parse_fragment(b["fragment"].as_str().unwrap()).unwrap();
    let d = TestDevice::generate();
    let pubkey = d.public_raw();
    let f = link
        .call(
            OP_WORKSPACE_PAIR_FINISH,
            json!({
                "pair_id": pair_id,
                "device_pub": b64::enc(&pubkey),
                "label": "phone",
                "proof": b64::enc(&pair::proof(&secret, &pair_id, &pubkey)),
            }),
        )
        .await;
    assert_eq!(f["ok"], true, "{f}");
    assert_eq!(f["device_id"], d.device_id());
    assert_eq!(f["short_code"].as_str().unwrap().len(), 7, "{f}");
    let c = control(
        w,
        OP_WORKSPACE_PAIR_CONFIRM,
        json!({"pair_id": pair_id, "accept": true}),
    )
    .await;
    assert_eq!(c["ok"], true, "{c}");
    d
}

/// 16 random bytes: no two frames of a test share a nonce.
fn nonce() -> String {
    let mut n = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut n).unwrap();
    b64::enc(&n)
}

fn frame_for(ws: &Workspace, d: &TestDevice, action: &str, args: Value) -> SignedFrame {
    let h = ws.hello();
    let now = ws.now();
    d.frame(&Frame {
        v: 1,
        machine_id: h["machine_id"].as_str().unwrap().into(),
        epoch: h["epoch"].as_str().unwrap().into(),
        device_id: d.device_id(),
        action: action.into(),
        args: args.as_object().unwrap().clone(),
        nonce: nonce(),
        issued_at: now,
        expires_at: now + 60,
    })
}

fn frame_args(sf: &SignedFrame) -> Value {
    json!({"body": sf.body, "sig": sf.sig, "via": "local"})
}

async fn send(w: &World, link: &mut Link, d: &TestDevice, action: &str, args: Value) -> Value {
    let sf = frame_for(&w.ctx.workspace, d, action, args);
    link.call(OP_WORKSPACE_FRAME, frame_args(&sf)).await
}

/// The `workspace` records so far, oldest first.
fn records(w: &World) -> Vec<Value> {
    fn walk(p: &Path, out: &mut Vec<Value>) {
        let mut entries: Vec<_> = std::fs::read_dir(p).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if let Ok(t) = std::fs::read_to_string(&p) {
                for line in t.lines() {
                    if let Ok(v) = serde_json::from_str::<Value>(line) {
                        if v["kind"] == "workspace" {
                            out.push(v);
                        }
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&w.audit, &mut out);
    out
}

/// The record's `extra` fields may sit at the top level or under `extra`.
fn field<'a>(r: &'a Value, k: &str) -> &'a Value {
    match &r[k] {
        Value::Null => &r["extra"][k],
        v => v,
    }
}

async fn paired() -> (World, Link, TestDevice) {
    let w = world().await;
    let mut link = Link::open(&w).await;
    let d = pair_device(&w, &mut link).await;
    (w, link, d)
}

#[tokio::test]
async fn overview_over_link_sock() {
    let (w, mut link, d) = paired().await;
    // The ipc crate's own client reaches link.sock as Task 6 will.
    let run = w.run.clone();
    let hello = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut c =
            saiife_ipc::client::Client::connect_named(&run, LINK_SOCKET_NAME, me(), deadline)
                .unwrap();
        c.call(OP_WORKSPACE_HELLO, Map::new(), deadline).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(hello["machine_id"], w.ctx.workspace.machine_id());
    assert_eq!(hello["frame_version"], 1);
    let a = send(&w, &mut link, &d, "box.overview", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(
        a["result"],
        serde_json::to_value(w.boxes.overview()).unwrap()
    );
    assert_eq!(a["result"]["boxes"].as_array().unwrap().len(), 4);
}

/// Every `OP_*` value in crates/ipc/src/msg.rs, as wire's
/// `every_ipc_op_is_classified` scans them.
fn all_ops() -> Vec<String> {
    let src = include_str!("../../ipc/src/msg.rs");
    let mut found = Vec::new();
    for line in src.lines() {
        let line = line.trim_start();
        if !line.starts_with("pub const OP_") {
            continue;
        }
        let Some(i) = line.find(": &str = \"") else {
            continue;
        };
        let rest = &line[i + ": &str = \"".len()..];
        let Some(j) = rest.find('"') else { continue };
        found.push(rest[..j].to_string());
    }
    found
}

#[tokio::test]
async fn link_socket_refuses_every_other_op() {
    let (w, mut link, d) = paired().await;
    let ops = all_ops();
    assert!(ops.len() >= 40, "found {}", ops.len());
    for op in LINK_OPS {
        assert!(ops.iter().any(|o| o == op), "{op} not scanned");
    }
    let before = records(&w).len();
    let mut refused = 0;
    for op in ops.iter().filter(|o| !LINK_OPS.contains(&o.as_str())) {
        // Args a handler would act on, were one reached.
        let a = link
            .call(
                op,
                json!({"on": true, "pair_id": "x", "accept": true,
                       "device_id": d.device_id(), "label": "x"}),
            )
            .await;
        assert_eq!(a["error"], "unknown_op", "{op}: {a}");
        refused += 1;
    }
    assert!(refused >= 35, "{refused}");
    // Names that are no op at all, too.
    for op in ["lockdown.off", "", "workspace.frame ", "WORKSPACE.FRAME"] {
        let a = link.call(op, json!({})).await;
        assert_eq!(a["error"], "unknown_op", "{op:?}: {a}");
    }
    // No handler ran: nothing recorded, lockdown off, the device still active.
    assert_eq!(records(&w).len(), before);
    assert!(w.ctx.lockdown.get().is_none());
    assert_eq!(
        w.ctx.workspace.device(&d.device_id()).unwrap().state,
        saiife_wire::device::DeviceState::Active
    );
    // The connection is still in step.
    let a = send(&w, &mut link, &d, "box.list", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
}

#[tokio::test]
async fn frame_from_other_uid_is_refused() {
    let (w, mut link, d) = paired().await;
    // The owner `me` is now another uid than this process.
    w.users.set(ME, me().wrapping_add(1));
    let a = send(&w, &mut link, &d, "box.stop", json!({"id": "b-run"})).await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "wrong_owner", "{a}");
    assert!(w.boxes.calls().is_empty());
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(last["decision"], "deny", "{last}");
    assert_eq!(last["rule"], "wrong_owner", "{last}");
}

#[tokio::test]
async fn stop_is_recorded_with_device() {
    let (w, mut link, d) = paired().await;
    let before = records(&w).len();
    let a = send(&w, &mut link, &d, "box.stop", json!({"id": "b-run"})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"], json!({}));
    assert_eq!(
        w.boxes.calls(),
        vec![FakeCall::Stop(BoxId::parse("b-run").unwrap())]
    );
    let r = records(&w);
    assert_eq!(r.len(), before + 1);
    let rec = r.last().unwrap();
    assert_eq!(rec["decision"], "allow", "{rec}");
    assert_eq!(field(rec, "action"), "box.stop", "{rec}");
    assert_eq!(field(rec, "device"), d.device_id().as_str(), "{rec}");
    assert_eq!(field(rec, "label"), "phone", "{rec}");
    assert_eq!(field(rec, "via"), "local", "{rec}");
    assert_eq!(field(rec, "level"), "signed", "{rec}");
    assert_eq!(field(rec, "box"), "b-run", "{rec}");
    assert_eq!(rec["uid"], me(), "{rec}");
}

#[tokio::test]
async fn reads_are_not_recorded() {
    let (w, mut link, d) = paired().await;
    let before = records(&w).len();
    for (action, args) in [
        ("box.overview", json!({})),
        ("box.list", json!({})),
        ("box.templates", json!({})),
        ("box.diff", json!({"id": "b-done"})),
        ("box.term.read", json!({"id": "b-run", "after": 1})),
        ("box.term.read", json!({"id": "b-run"})),
        ("box.inbox", json!({})),
        ("workspace.whoami", json!({})),
        // A source error on a read is an answer, not a refusal.
        ("box.diff", json!({"id": "b-nope"})),
    ] {
        let a = send(&w, &mut link, &d, action, args).await;
        if action == "box.diff" && a["ok"] == false {
            assert_eq!(a["rule"], "not_found", "{a}");
            continue;
        }
        assert_eq!(a["ok"], true, "{action}: {a}");
    }
    assert_eq!(records(&w).len(), before);
    let who = send(&w, &mut link, &d, "workspace.whoami", json!({})).await;
    assert_eq!(
        who["result"],
        json!({"device_id": d.device_id(), "label": "phone", "owner_user": ME, "passkeys": []})
    );
    let inbox = send(&w, &mut link, &d, "box.inbox", json!({})).await;
    let items = inbox["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{inbox}");
    assert_eq!(items[0]["class"], "land");
    let t = send(
        &w,
        &mut link,
        &d,
        "box.term.read",
        json!({"id": "b-run", "after": 1}),
    )
    .await;
    assert_eq!(t["result"]["next"], 3, "{t}");
}

#[tokio::test]
async fn unsigned_junk_is_not_recorded() {
    let (w, mut link, d) = paired().await;
    let before = records(&w).len();
    let stranger = TestDevice::generate();
    let mut rules = std::collections::BTreeSet::new();
    for i in 0..100u32 {
        let mut sf = frame_for(&w.ctx.workspace, &d, "box.stop", json!({"id": "b-run"}));
        match i % 5 {
            0 => sf.sig = b64::enc(&[7u8; 64]),
            1 => sf.sig = "not b64!".into(),
            2 => sf.sig = d.sign_body("another body"),
            // Signed by another key in d's name.
            3 => sf.sig = TestDevice::generate().sign_body(&sf.body),
            // A device this machine never paired, signing for itself.
            _ => {
                sf = frame_for(
                    &w.ctx.workspace,
                    &stranger,
                    "box.stop",
                    json!({"id": "b-run"}),
                )
            }
        }
        let a = link.call(OP_WORKSPACE_FRAME, frame_args(&sf)).await;
        assert_eq!(a["ok"], false, "{a}");
        rules.insert(a["rule"].as_str().unwrap().to_string());
        assert!(
            ["bad_signature", "bad_frame", "unknown_device"].contains(&a["rule"].as_str().unwrap()),
            "{a}"
        );
    }
    assert_eq!(rules.len(), 3, "{rules:?}");
    assert_eq!(records(&w).len(), before);
    assert!(w.boxes.calls().is_empty());
    let s = control(&w, OP_STATUS, json!({})).await;
    assert_eq!(s["workspace"]["refused_unsigned"], 100, "{s}");
}

#[tokio::test]
async fn touch_action_is_refused_touch_required() {
    let (w, mut link, d) = paired().await;
    for action in ["box.land", "approval.approve", "box.steer"] {
        let a = send(&w, &mut link, &d, action, json!({"id": "b-done"})).await;
        assert_eq!(a["error"], "forbidden", "{action}: {a}");
        assert_eq!(a["rule"], "touch_required", "{action}: {a}");
    }
    assert!(w.boxes.calls().is_empty());
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(last["decision"], "deny", "{last}");
    assert_eq!(last["rule"], "touch_required");
    assert_eq!(field(last, "level"), "touch");
    // box.push and box.pr are unavailable by design (plan 39).
    for action in ["box.push", "box.pr"] {
        let a = send(&w, &mut link, &d, action, json!({"id": "b-done"})).await;
        assert_eq!(a["error"], "unavailable", "{action}: {a}");
        assert_eq!(a["rule"], "unavailable", "{action}: {a}");
    }
}

#[tokio::test]
async fn touch_action_with_a_junk_touch_proof_is_refused() {
    let (w, mut link, d) = paired().await;
    let sf = frame_for(&w.ctx.workspace, &d, "box.land", json!({"id": "b-done"}));
    let mut args = frame_args(&sf);
    args["touch"] = json!({
        "request_id": "1",
        "credential_id": b64::enc(&[1u8; 16]),
        "authenticator_data": b64::enc(&[2u8; 37]),
        "client_data_json": b64::enc(br#"{"type":"webauthn.get"}"#),
        "signature": b64::enc(&[3u8; 70]),
    });
    let a = link.call(OP_WORKSPACE_FRAME, args).await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_failed", "{a}");
    assert!(w.boxes.calls().is_empty());
}

#[tokio::test]
async fn spawn_with_secret_template_needs_touch() {
    let (w, mut link, d) = paired().await;
    let a = send(
        &w,
        &mut link,
        &d,
        "box.spawn",
        json!({"template": "claude-gh", "repo": "erp", "task": "push it", "start": "now"}),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_required", "{a}");
    assert!(w.boxes.calls().is_empty());
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(last["decision"], "deny");
    assert_eq!(field(last, "level"), "touch", "{last}");
}

#[tokio::test]
async fn spawn_plain_template_runs() {
    let (w, mut link, d) = paired().await;
    let a = send(
        &w,
        &mut link,
        &d,
        "box.spawn",
        json!({"template": "claude", "repo": "web", "task": "write tests", "start": "queue"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let id = a["result"]["id"].as_str().unwrap().to_string();
    match w.boxes.calls().as_slice() {
        [FakeCall::Spawn(req)] => {
            assert_eq!(req.template, "claude");
            assert_eq!(req.repo, "web");
            assert_eq!(req.task, "write tests");
            assert_eq!(req.start, Start::Queue);
        }
        other => panic!("{other:?}"),
    }
    assert!(w.boxes.list().iter().any(|b| b.id.as_str() == id));
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(field(last, "action"), "box.spawn");
    assert_eq!(last["decision"], "allow");
    // Bad args are refused before the source sees them.
    for args in [
        json!({"template": "claude", "repo": "web", "task": "x\u{1b}y", "start": "now"}),
        json!({"template": "claude", "repo": "web", "task": "x", "start": "later"}),
        json!({"template": "nope", "repo": "web", "task": "x", "start": "now"}),
        json!({"template": "claude", "repo": "web", "task": "x", "start": "now", "admin": true}),
    ] {
        let a = send(&w, &mut link, &d, "box.spawn", args.clone()).await;
        assert_eq!(a["error"], "bad_request", "{args}: {a}");
        assert_eq!(a["rule"], "invalid", "{args}: {a}");
    }
    assert_eq!(w.boxes.calls().len(), 1);
}

#[tokio::test]
async fn lockdown_on_from_remote() {
    let (w, mut link, d) = paired().await;
    let a = send(
        &w,
        &mut link,
        &d,
        "lockdown.on",
        json!({"reason": "lost laptop"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"]["lockdown"]["scope"], "all", "{a}");
    let l = w.ctx.lockdown.get().unwrap();
    assert_eq!(l.by_uid, me());
    assert!(l.reason.contains("lost laptop"), "{}", l.reason);
    assert!(l.reason.contains(&d.device_id()), "{}", l.reason);
    let since = l.since.clone();
    let lockdowns = || {
        w.ctx
            .notifier
            .queued_events()
            .into_iter()
            .filter(|e| e.event == saiife_policy::Event::Lockdown)
            .collect::<Vec<_>>()
    };
    let n = lockdowns();
    assert_eq!(n.len(), 1, "{n:?}");
    assert!(
        n[0].summary
            .starts_with("lockdown on (all) by Workspace device phone ("),
        "{n:?}"
    );
    assert!(n[0].summary.contains(&d.device_id()), "{n:?}");
    assert!(n[0].summary.contains("lost laptop"), "{n:?}");
    assert_eq!(n[0].uid, Some(me()));
    // Already `all`: a no-op that still answers ok, and says nothing.
    let a = send(&w, &mut link, &d, "lockdown.on", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(lockdowns().len(), 1);
    let l2 = w.ctx.lockdown.get().unwrap();
    assert_eq!(l2.since, since);
    assert!(l2.reason.contains("lost laptop"));
    let r = records(&w);
    let ons: Vec<_> = r
        .iter()
        .filter(|x| field(x, "action") == "lockdown.on")
        .collect();
    assert_eq!(ons.len(), 2);
    assert!(ons.iter().all(|x| x["decision"] == "allow"));
}

#[tokio::test]
async fn lockdown_on_widens_connectors() {
    let (w, mut link, d) = paired().await;
    w.ctx
        .lockdown
        .set(Some(saiife_broker::pipeline::Lockdown {
            scope: saiife_broker::pipeline::LockScope::Connectors,
            reason: "drill".into(),
            by_uid: 0,
            since: "2026-11-11T00:00:00Z".into(),
        }))
        .unwrap();
    let a = send(&w, &mut link, &d, "lockdown.on", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(
        w.ctx.lockdown.get().unwrap().scope,
        saiife_broker::pipeline::LockScope::All
    );
}

#[tokio::test]
async fn machine_only_action_is_refused_after_signature() {
    let (w, mut link, d) = paired().await;
    let before = records(&w).len();
    w.ctx
        .lockdown
        .set(Some(saiife_broker::pipeline::Lockdown {
            scope: saiife_broker::pipeline::LockScope::All,
            reason: "on".into(),
            by_uid: 0,
            since: "2026-11-11T00:00:00Z".into(),
        }))
        .unwrap();
    for action in [
        "lockdown.off",
        "workspace.revoke",
        "policy.reload",
        "lockdown.set",
    ] {
        let a = send(&w, &mut link, &d, action, json!({"on": false})).await;
        assert_eq!(a["error"], "forbidden", "{action}: {a}");
        assert_eq!(a["rule"], "machine_only", "{action}: {a}");
    }
    assert!(w.ctx.lockdown.get().is_some(), "lockdown stays on");
    let r = records(&w);
    assert_eq!(r.len(), before + 4);
    let rec = &r[before];
    assert_eq!(rec["decision"], "deny", "{rec}");
    assert_eq!(rec["rule"], "machine_only");
    assert_eq!(field(rec, "action"), "lockdown.off");
    assert_eq!(field(rec, "level"), "machine_only", "{rec}");
    assert_eq!(field(rec, "device"), d.device_id().as_str());
    // An action no table names: refused too, after the signature.
    let a = send(&w, &mut link, &d, "box.reboot", json!({})).await;
    assert_eq!(a["rule"], "unknown_action", "{a}");
    let last = records(&w).last().cloned().unwrap();
    assert_eq!(field(&last, "level"), "unknown", "{last}");
}

#[tokio::test]
async fn revoked_device_is_refused_next_frame() {
    let (w, mut link, d) = paired().await;
    let a = send(&w, &mut link, &d, "box.list", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    let r = control(&w, OP_WORKSPACE_REVOKE, json!({"device_id": d.device_id()})).await;
    assert_eq!(r["ok"], true, "{r}");
    let a = send(&w, &mut link, &d, "box.stop", json!({"id": "b-run"})).await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "unknown_device", "{a}");
    assert!(w.boxes.calls().is_empty());
}

#[tokio::test]
async fn restart_changes_epoch() {
    let (w, link, d) = paired().await;
    let old = frame_for(&w.ctx.workspace, &d, "box.list", json!({}));
    // The daemon restarts on the same state dir: same key, same devices,
    // a new epoch.
    let w2 = world_in(Some(w.state.clone())).await;
    assert_eq!(w2.ctx.workspace.machine_id(), w.ctx.workspace.machine_id());
    assert_ne!(
        w2.ctx.workspace.hello()["epoch"],
        w.ctx.workspace.hello()["epoch"]
    );
    let mut link2 = Link::open(&w2).await;
    let a = link2.call(OP_WORKSPACE_FRAME, frame_args(&old)).await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "stale_epoch", "{a}");
    // A signed frame: the refusal is recorded.
    let last = records(&w2).last().cloned().unwrap();
    assert_eq!(last["rule"], "stale_epoch", "{last}");
    assert_eq!(field(&last, "level"), "signed", "{last}");
    // A fresh frame for the new epoch works.
    let a = send(&w2, &mut link2, &d, "box.list", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    drop(link);
}

#[tokio::test]
async fn every_signed_action_is_handled_or_later() {
    for (name, lvl) in REMOTE {
        if *lvl == Level::Signed {
            assert!(
                HANDLED.contains(name) || LATER.contains(name),
                "{name} is Signed but has no handler and is not LATER"
            );
        }
    }
    for n in HANDLED {
        assert!(!LATER.contains(n), "{n} is handled and LATER");
        assert_eq!(saiife_wire::level_for(n), Some(Level::Signed), "{n}");
    }
    // And over the socket: no Signed action reaches the "unhandled" arm.
    let (w, mut link, d) = paired().await;
    for (name, lvl) in REMOTE {
        let a = send(&w, &mut link, &d, name, json!({})).await;
        assert_ne!(a["rule"], "unhandled", "{name}: {a}");
        assert_ne!(a["error"], "internal", "{name}: {a}");
        if *lvl == Level::Signed && LATER.contains(name) {
            assert_eq!(a["error"], "unavailable", "{name}: {a}");
        }
    }
}

#[tokio::test]
async fn hostile_diff_passes_through_as_data() {
    let (w, mut link, d) = paired().await;
    let a = send(&w, &mut link, &d, "box.diff", json!({"id": "b-done"})).await;
    assert_eq!(a["ok"], true);
    let want = w.boxes.diff(&BoxId::parse("b-done").unwrap()).unwrap();
    assert_eq!(a["result"], serde_json::to_value(&want).unwrap());
    let unified = a["result"]["unified"].as_str().unwrap();
    assert_eq!(unified.as_bytes(), want.unified.as_bytes());
    assert!(unified.contains("\u{1b}]52;c;"));
    assert!(unified.contains("<img src=x onerror=alert(1)>"));
    assert_eq!(a["result"]["truncated"], true);
}

#[tokio::test]
async fn frame_envelope_is_strict() {
    let (w, mut link, d) = paired().await;
    let sf = frame_for(&w.ctx.workspace, &d, "box.list", json!({}));
    for args in [
        json!({"body": sf.body, "sig": sf.sig}),
        json!({"body": sf.body, "sig": sf.sig, "via": "carrier pigeon"}),
        json!({"body": sf.body, "sig": sf.sig, "via": "hub"}),
        json!({"body": sf.body, "sig": sf.sig, "via": "local", "channel_device": d.device_id()}),
        json!({"body": sf.body, "sig": sf.sig, "via": "local", "admin": true}),
        json!({"body": 5, "sig": sf.sig, "via": "local"}),
        json!({"body": sf.body, "sig": sf.sig, "via": "local", "touch": {"x": 1}}),
    ] {
        let a = link.call(OP_WORKSPACE_FRAME, args.clone()).await;
        assert_eq!(a["error"], "bad_request", "{args}: {a}");
    }
    let s = control(&w, OP_STATUS, json!({})).await;
    assert_eq!(s["workspace"]["refused_unsigned"], 7, "{s}");
    // The nonce was never burned: the frame still works.
    let a = link.call(OP_WORKSPACE_FRAME, frame_args(&sf)).await;
    assert_eq!(a["ok"], true, "{a}");
    // A replay of it is refused, after the signature.
    let a = link.call(OP_WORKSPACE_FRAME, frame_args(&sf)).await;
    assert_eq!(a["rule"], "replayed", "{a}");
}

#[tokio::test]
async fn hub_frame_for_another_device_is_refused() {
    let (w, mut link, d) = paired().await;
    let other = pair_device(&w, &mut link).await;
    let sf = frame_for(&w.ctx.workspace, &d, "box.stop", json!({"id": "b-run"}));
    let a = link
        .call(
            OP_WORKSPACE_FRAME,
            json!({"body": sf.body, "sig": sf.sig, "via": "hub",
                   "channel_device": other.device_id()}),
        )
        .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "wrong_device", "{a}");
    assert!(w.boxes.calls().is_empty());
    let last = records(&w).last().cloned().unwrap();
    assert_eq!(last["decision"], "deny");
    assert_eq!(last["rule"], "wrong_device");
    assert_eq!(field(&last, "via"), "hub");
    // The right channel works.
    let sf = frame_for(&w.ctx.workspace, &d, "box.stop", json!({"id": "b-run"}));
    let a = link
        .call(
            OP_WORKSPACE_FRAME,
            json!({"body": sf.body, "sig": sf.sig, "via": "hub",
                   "channel_device": d.device_id()}),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
}

/// A real machine handshake and its 81 signed bytes (session_id ‖ eph).
fn handshake() -> (MachineHandshake, Vec<u8>) {
    let mh = MachineHandshake::new(&ring::rand::SystemRandom::new()).unwrap();
    let mut v = mh.session_id().to_vec();
    v.extend_from_slice(&mh.eph_pub());
    (mh, v)
}

fn seal_data() -> Vec<u8> {
    handshake().1
}

fn machine_pub(w: &World) -> [u8; 65] {
    b64::dec_n::<65>(w.ctx.workspace.hello()["machine_pub"].as_str().unwrap()).unwrap()
}

/// Whether a browser expecting `expect` accepts the daemon's seal answer.
fn browser_accepts(w: &World, mh: &MachineHandshake, a: &Value, expect: &SealBinding) -> bool {
    let sig = b64::dec_n::<64>(a["sig"].as_str().unwrap()).unwrap();
    TestBrowserEnd::new(None)
        .finish(
            &mh.eph_pub(),
            &mh.session_id(),
            &sig,
            &machine_pub(w),
            expect,
        )
        .is_ok()
}

async fn sign(link: &mut Link, args: Value) -> Value {
    link.call(OP_WORKSPACE_SIGN, args).await
}

fn hub_hello_data(w: &World) -> Vec<u8> {
    let mut hh = vec![1u8; 32];
    hh.extend_from_slice(w.ctx.workspace.machine_id().as_bytes());
    hh
}

fn hub_hello_verifies(w: &World, hh: &[u8], a: &Value) -> bool {
    let sig = b64::dec_n::<64>(a["sig"].as_str().unwrap()).unwrap();
    saiife_wire::sig::verify_p256_domain(
        &machine_pub(w),
        saiife_wire::seal::HUB_HELLO_DOMAIN,
        hh,
        &sig,
    )
}

/// An admin (the personal broker's own user) gets a hub hello with no
/// device yet: the first phone pairs over the hub. A seal for a device
/// still needs that device.
#[tokio::test]
async fn admin_without_a_device_gets_a_hub_hello() {
    let w = world().await;
    let mut link = Link::open(&w).await;
    let hh = hub_hello_data(&w);
    let a = sign(
        &mut link,
        json!({"purpose": "hub_hello", "data": b64::enc(&hh)}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(hub_hello_verifies(&w, &hh, &a));
    let (_, data) = handshake();
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&data), "device_id": "d-none"}),
    )
    .await;
    assert_eq!(a["rule"], "no_active_device", "{a}");
}

#[tokio::test]
async fn sign_needs_an_active_device() {
    let w = world().await;
    let mut link = Link::open(&w).await;
    let d = pair_device(&w, &mut link).await;
    let (mh, data) = handshake();
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&data), "device_id": d.device_id()}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(browser_accepts(
        &w,
        &mh,
        &a,
        &SealBinding::Device(d.device_id())
    ));
    // Revoked: no Active device left for a device seal.
    control(&w, OP_WORKSPACE_REVOKE, json!({"device_id": d.device_id()})).await;
    let (_, data) = handshake();
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&data), "device_id": d.device_id()}),
    )
    .await;
    assert_eq!(a["rule"], "no_active_device", "{a}");
}

/// A locked daemon of another uid with no `[admin] groups` and no
/// approvers: this process is neither admin nor approver. It gets a hub
/// hello only while it owns an Active device.
#[tokio::test]
async fn non_approver_needs_a_device_for_a_hub_hello() {
    if me() == 0 {
        return; // root is always an admin
    }
    let tmp = scratch();
    let state = tmp.path().join("state");
    let (ws, _) = Workspace::open(dir_in(&state));
    let w = build_as(tmp, state, ws, DaemonMode::Locked, me().wrapping_add(1)).await;
    let mut link = Link::open(&w).await;
    let hh = hub_hello_data(&w);
    let hello = json!({"purpose": "hub_hello", "data": b64::enc(&hh)});
    let a = sign(&mut link, hello.clone()).await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "no_active_device", "{a}");

    // A device of this process's user (paired on the Workspace itself: the
    // control ops would refuse a non-approver).
    let ws = &w.ctx.workspace;
    let now = ws.now();
    let offer = ws.begin_pair(ME, None, now).unwrap();
    let d = TestDevice::generate();
    let pubkey = d.public_raw();
    let req = pair::PairRequest {
        pair_id: offer.pair_id.clone(),
        device_pub: b64::enc(&pubkey),
        label: "phone".into(),
        proof: b64::enc(&pair::proof(&offer.secret, &offer.pair_id, &pubkey)),
        passkey: None,
    };
    ws.finish_pair(&req, now).unwrap();
    assert!(ws
        .confirm_pair(&offer.pair_id, true, now)
        .unwrap()
        .is_some());
    let a = sign(&mut link, hello.clone()).await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(hub_hello_verifies(&w, &hh, &a));
    ws.revoke(&d.device_id()).unwrap();
    let a = sign(&mut link, hello).await;
    assert_eq!(a["rule"], "no_active_device", "{a}");
}

/// `workspace.wake` (content-free hub wake-ups): how many Workspace events
/// were raised and whether `[workspace] push` is on; nothing else. Strict
/// args, never recorded.
#[tokio::test]
async fn wake_counts_events_and_reports_push() {
    let w = world().await;
    let mut link = Link::open(&w).await;
    let before = records(&w).len();
    let a = link.call(OP_WORKSPACE_WAKE, json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    let mut keys: Vec<&str> = a.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["id", "ok", "push", "seq"], "{a}");
    assert_eq!(
        (a["push"].clone(), a["seq"].clone()),
        (json!(false), json!(0))
    );

    // A land waiting in the inbox raises one.
    let pa = pending_land(&w);
    saiife_daemon::workspace_touch::notify_pending(&w.ctx, &pa);
    w.ctx.workspace.note_wake();
    let a = link.call(OP_WORKSPACE_WAKE, json!({})).await;
    assert_eq!(
        (a["push"].clone(), a["seq"].clone()),
        (json!(false), json!(2))
    );

    // The owner opts in.
    let cfg: saiife_policy::SystemConfig =
        toml::from_str("version = 2\n[workspace]\npush = true\n").unwrap();
    w.ctx.policy.lock().unwrap().system = Some(Arc::new(cfg));
    let a = link.call(OP_WORKSPACE_WAKE, json!({})).await;
    assert_eq!(
        (a["push"].clone(), a["seq"].clone()),
        (json!(true), json!(2))
    );

    // It takes nothing.
    let a = link.call(OP_WORKSPACE_WAKE, json!({"box": "b-done"})).await;
    assert_eq!(a["error"], "bad_request", "{a}");
    assert_eq!(records(&w).len(), before);
}

/// Only a user who may hold the hub link (an Active device, or one who may
/// pair) learns the count.
#[tokio::test]
async fn wake_needs_a_device_or_pairing_right() {
    if me() == 0 {
        return; // root is always an admin
    }
    let tmp = scratch();
    let state = tmp.path().join("state");
    let (ws, _) = Workspace::open(dir_in(&state));
    let w = build_as(tmp, state, ws, DaemonMode::Locked, me().wrapping_add(1)).await;
    let mut link = Link::open(&w).await;
    let a = link.call(OP_WORKSPACE_WAKE, json!({})).await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "no_active_device", "{a}");
}

#[tokio::test]
async fn seal_signature_is_bound_to_its_device() {
    let (w, mut link, a_dev) = paired().await;
    let b_dev = pair_device(&w, &mut link).await;
    let (mh, data) = handshake();
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&data), "device_id": a_dev.device_id()}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(browser_accepts(
        &w,
        &mh,
        &a,
        &SealBinding::Device(a_dev.device_id())
    ));
    assert!(!browser_accepts(
        &w,
        &mh,
        &a,
        &SealBinding::Device(b_dev.device_id())
    ));
    assert!(!browser_accepts(
        &w,
        &mh,
        &a,
        &SealBinding::Pair(a_dev.device_id())
    ));
}

#[tokio::test]
async fn seal_needs_exactly_one_binding() {
    let (w, mut link, d) = paired().await;
    let o = w.ctx.workspace.begin_pair(ME, None, now_secs()).unwrap();
    for args in [
        json!({"purpose": "seal", "data": b64::enc(&seal_data())}),
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": null, "pair_id": null}),
        json!({"purpose": "seal", "data": b64::enc(&seal_data()),
               "device_id": d.device_id(), "pair_id": o.pair_id}),
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": 5}),
    ] {
        let a = sign(&mut link, args.clone()).await;
        assert_eq!(a["error"], "bad_request", "{args}: {a}");
    }
}

#[tokio::test]
async fn seal_refuses_revoked_and_pending_devices() {
    let (w, mut link, d) = paired().await;
    // A second device stays pending: finished, never confirmed.
    let b = control(&w, OP_WORKSPACE_PAIR_BEGIN, json!({})).await;
    let (pair_id, secret, _, _) = pair::parse_fragment(b["fragment"].as_str().unwrap()).unwrap();
    let pending = TestDevice::generate();
    let pk = pending.public_raw();
    let f = link
        .call(
            OP_WORKSPACE_PAIR_FINISH,
            json!({"pair_id": pair_id, "device_pub": b64::enc(&pk), "label": "tab",
                   "proof": b64::enc(&pair::proof(&secret, &pair_id, &pk))}),
        )
        .await;
    assert_eq!(f["ok"], true, "{f}");
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": pending.device_id()}),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert!(
        ["unknown_device", "device_pending"].contains(&a["rule"].as_str().unwrap()),
        "{a}"
    );
    // A revoked device, while another Active device keeps the peer's gate open.
    let other = pair_device(&w, &mut link).await;
    control(&w, OP_WORKSPACE_REVOKE, json!({"device_id": d.device_id()})).await;
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": d.device_id()}),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "unknown_device", "{a}");
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": other.device_id()}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
}

#[tokio::test]
async fn seal_refuses_an_invalid_point() {
    let (_w, mut link, d) = paired().await;
    let mut data = seal_data();
    data[16] = 0x04;
    for b in &mut data[17..] {
        *b = 0x5a;
    }
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&data), "device_id": d.device_id()}),
    )
    .await;
    assert_eq!(a["error"], "bad_request", "{a}");
}

#[tokio::test]
async fn seal_for_a_pairing_offer() {
    // No device at all: an offer of the peer's own user is enough.
    let w = world().await;
    let mut link = Link::open(&w).await;
    let o = w.ctx.workspace.begin_pair(ME, None, now_secs()).unwrap();
    let (mh, data) = handshake();
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&data), "pair_id": o.pair_id}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(a.get("device_pub").is_none(), "{a}");
    assert!(browser_accepts(
        &w,
        &mh,
        &a,
        &SealBinding::Pair(o.pair_id.clone())
    ));
    assert!(!browser_accepts(
        &w,
        &mh,
        &a,
        &SealBinding::Pair("p-other".into())
    ));
    // Another user's offer.
    w.users.set("bob", me().wrapping_add(7));
    let ob = w.ctx.workspace.begin_pair("bob", None, now_secs()).unwrap();
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "pair_id": ob.pair_id}),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "wrong_owner", "{a}");
    // No such offer.
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "pair_id": "p-nope"}),
    )
    .await;
    assert_eq!(a["rule"], "pair_expired", "{a}");
}

#[tokio::test]
async fn sign_refuses_arbitrary_data() {
    let (w, mut link, d) = paired().await;
    let mid = w.ctx.workspace.machine_id();
    let with_mid = |n: usize| {
        let mut v = vec![1u8; n];
        v.extend_from_slice(mid.as_bytes());
        v
    };
    let mut not_a_point = seal_data();
    not_a_point[16] = 0x02;
    let mut other_machine = vec![1u8; 32];
    other_machine.extend_from_slice(b"m-someone-else");
    for (purpose, data) in [
        ("seal", b"a frame body".to_vec()),
        ("seal", seal_data()[..80].to_vec()),
        ("seal", [seal_data(), vec![0]].concat()),
        ("seal", not_a_point),
        ("hub_hello", with_mid(15)),
        ("hub_hello", with_mid(65)),
        ("hub_hello", vec![1u8; 32]),
        ("hub_hello", other_machine),
        ("hub_hello", seal_data()),
    ] {
        let mut args = json!({"purpose": purpose, "data": b64::enc(&data)});
        if purpose == "seal" {
            args["device_id"] = d.device_id().into();
        }
        let a = sign(&mut link, args).await;
        assert_eq!(a["error"], "bad_request", "{purpose} {}: {a}", data.len());
    }
    for args in [
        json!({"purpose": "frame", "data": b64::enc(&seal_data())}),
        json!({"purpose": "seal", "data": "not b64!", "device_id": d.device_id()}),
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": d.device_id(), "extra": 1}),
        json!({"purpose": "hub_hello", "data": b64::enc(&with_mid(16)), "device_id": d.device_id()}),
        json!({"purpose": "hub_hello", "data": b64::enc(&with_mid(16)), "pair_id": "p-1"}),
    ] {
        let a = sign(&mut link, args.clone()).await;
        assert_eq!(a["error"], "bad_request", "{args}: {a}");
    }
    // The edges of the nonce length are fine.
    for n in [16, 64] {
        let a = sign(
            &mut link,
            json!({"purpose": "hub_hello", "data": b64::enc(&with_mid(n))}),
        )
        .await;
        assert_eq!(a["ok"], true, "{n}: {a}");
    }
}

#[tokio::test]
async fn sign_returns_device_pub_for_own_device() {
    let (_w, mut link, d) = paired().await;
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": d.device_id()}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["device_pub"], b64::enc(&d.public_raw()));
    let a = sign(
        &mut link,
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": "d-0000000000000000"}),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "unknown_device", "{a}");
}

#[tokio::test]
async fn sign_refuses_other_owners_device() {
    let (w, mut link, d) = paired().await;
    // A second device whose owner is another account.
    let other = pair_device(&w, &mut link).await;
    let path = dir_in(&w.state).join(saiife_daemon::workspace::DEVICES_FILE);
    let mut list: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for dev in list["devices"].as_array_mut().unwrap() {
        if dev["id"] == other.device_id() {
            dev["owner_user"] = "bob".into();
        }
    }
    std::fs::write(&path, serde_json::to_vec(&list).unwrap()).unwrap();
    let w2 = world_in(Some(w.state.clone())).await;
    w2.users.set("bob", me().wrapping_add(7));
    let mut link2 = Link::open(&w2).await;
    let a = sign(
        &mut link2,
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": other.device_id()}),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "wrong_owner", "{a}");
    // Our own device still signs.
    let a = sign(
        &mut link2,
        json!({"purpose": "seal", "data": b64::enc(&seal_data()), "device_id": d.device_id()}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
}

#[tokio::test]
async fn a_locked_workspace_refuses_hello_sign_and_pair() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = scratch();
    let state = tmp.path().join("state");
    let wdir = dir_in(&state);
    std::fs::create_dir_all(&wdir).unwrap();
    let key = wdir.join(saiife_daemon::workspace::KEY_FILE);
    std::fs::write(&key, b"not a key").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (ws, warning) = Workspace::open(wdir);
    assert!(warning.is_some() && ws.locked());
    let w = build(tmp, state, ws).await;
    let mut link = Link::open(&w).await;
    for (op, args) in [
        (OP_WORKSPACE_HELLO, json!({})),
        (
            OP_WORKSPACE_SIGN,
            json!({"purpose": "seal", "data": b64::enc(&seal_data())}),
        ),
        (
            OP_WORKSPACE_PAIR_FINISH,
            json!({"pair_id": "p", "device_pub": "x", "label": "l", "proof": "y"}),
        ),
    ] {
        let a = link.call(op, args).await;
        assert_eq!(a["error"], "unavailable", "{op}: {a}");
        assert_eq!(a["rule"], "workspace_locked", "{op}: {a}");
    }
}

// ---- workspace.touch.begin (plan 31, Task 4) ----

const ORIGIN: &str = "http://localhost:47810";

/// Pairs a device with a soft passkey made for `localhost`, as the browser
/// does: a create-side authData, a clientDataJSON for this pairing's
/// challenge, and the device key's signature over both. Returns the
/// credential id.
async fn pair_with_passkey(w: &World, link: &mut Link) -> (TestDevice, Vec<u8>) {
    let (d, auth) = pair_with_soft(w, link).await;
    let cid = auth.credential_id();
    (d, cid)
}

/// [`pair_with_passkey`], keeping the soft authenticator to sign with.
async fn pair_with_soft(
    w: &World,
    link: &mut Link,
) -> (TestDevice, saiife_touch::soft::SoftAuthenticator) {
    use saiife_touch::{EnrolRequest, Touch};
    let b = control(w, OP_WORKSPACE_PAIR_BEGIN, json!({"label": "laptop"})).await;
    assert_eq!(b["ok"], true, "{b}");
    let (pair_id, secret, _, _) = pair::parse_fragment(b["fragment"].as_str().unwrap()).unwrap();
    let d = TestDevice::generate();
    let pubkey = d.public_raw();
    let auth = saiife_touch::soft::SoftAuthenticator::new_es256();
    let ad = auth
        .enrol(&EnrolRequest {
            rp_id: "localhost".into(),
            rp_name: "saiife".into(),
            user_id: vec![1],
            user_name: "phone".into(),
            challenge: [0; 32],
            exclude: vec![],
        })
        .unwrap();
    let challenge = b64::enc(&pair::passkey_challenge(&pair_id, &pubkey));
    let cdj = format!(
        "{{\"type\":\"webauthn.create\",\"challenge\":\"{challenge}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}"
    );
    let mut att = pair::PasskeyAttestation {
        credential_id: b64::enc(&auth.credential_id()),
        authenticator_data: b64::enc(&ad),
        client_data_json: b64::enc(cdj.as_bytes()),
        device_sig: String::new(),
    };
    let msg = pair::passkey_sig_msg(&pair_id, &att).unwrap();
    att.device_sig = b64::enc(&d.sign_domain(pair::PASSKEY_DOMAIN, &msg));
    let f = link
        .call(
            OP_WORKSPACE_PAIR_FINISH,
            json!({
                "pair_id": pair_id,
                "device_pub": b64::enc(&pubkey),
                "label": "phone",
                "proof": b64::enc(&pair::proof(&secret, &pair_id, &pubkey)),
                "passkey": att,
            }),
        )
        .await;
    assert_eq!(f["ok"], true, "{f}");
    let c = control(
        w,
        OP_WORKSPACE_PAIR_CONFIRM,
        json!({"pair_id": pair_id, "accept": true}),
    )
    .await;
    assert_eq!(c["ok"], true, "{c}");
    assert_eq!(c["passkey"], b64::enc(&auth.credential_id()), "{c}");
    (d, auth)
}

async fn paired_with_passkey() -> (World, Link, TestDevice, Vec<u8>) {
    let w = world().await;
    let mut link = Link::open(&w).await;
    let (d, cid) = pair_with_passkey(&w, &mut link).await;
    (w, link, d, cid)
}

/// The page learns from the daemon, not from its own claim, whether this
/// browser has a passkey: `whoami` lists the ids the device and the owner's
/// touch store both hold (what `begin` would allow); none without one.
#[tokio::test]
async fn whoami_lists_the_passkeys_the_daemon_holds() {
    let (w, mut link, d, cid) = paired_with_passkey().await;
    let who = send(&w, &mut link, &d, "workspace.whoami", json!({})).await;
    assert_eq!(who["result"]["passkeys"], json!([b64::enc(&cid)]), "{who}");
    // Removed from the touch store: no longer listed (fail closed).
    w.ctx.touch.remove(&cid).unwrap();
    let who = send(&w, &mut link, &d, "workspace.whoami", json!({})).await;
    assert_eq!(who["result"]["passkeys"], json!([]), "{who}");
}

fn begin_args(action: &str, args: Value) -> Value {
    json!({"action": action, "args": args})
}

fn touch_request(a: &Value) -> saiife_touch::TouchRequest {
    assert_eq!(a["ok"], true, "{a}");
    serde_json::from_value(a["result"].clone()).unwrap()
}

/// The challenge entry the daemon issued for web request `rid`.
fn issued(w: &World, d: &TestDevice, rid: u64) -> saiife_daemon::touch::Issued {
    w.ctx
        .touch
        .take(
            &saiife_daemon::touch::IssueKey::Web {
                device: d.device_id(),
                request_id: rid,
            },
            me(),
        )
        .unwrap()
}

fn fields(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[tokio::test]
async fn begin_for_steer_answers_a_touch_request() {
    let (w, mut link, d, cid) = paired_with_passkey().await;
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("box.steer", json!({"id": "b-run"})),
    )
    .await;
    let tr = touch_request(&a);
    assert_eq!(tr.rp_id, "localhost");
    assert_eq!(tr.allow, vec![cid]);
    assert!(tr.uv);
    assert_eq!(tr.short_code, saiife_touch::short_code(&tr.challenge));
    assert_eq!(tr.summary, "box.steer box b-run");
    assert_eq!(a["result"]["request_id"], "1");
    assert_eq!(a["result"]["class"], "steer");
    assert!(a["result"]["expires_at"].as_u64().unwrap() > now_secs());
    // No box action ran.
    assert!(w.boxes.calls().is_empty());
}

/// Task 5 (b): one device holds at most 4 live touch challenges, inside
/// its owner's 8. A fifth begin from that device is refused (`busy`, the
/// uid cap's shape) with its own reason in the record; another device of
/// the same owner still begins up to the owner's 8, and the uid cap fires
/// there.
#[tokio::test]
async fn begin_caps_per_device_inside_the_owner_cap() {
    let (w, mut link, a, _) = paired_with_passkey().await;
    let (b, _) = pair_with_passkey(&w, &mut link).await;
    let (c, _) = pair_with_passkey(&w, &mut link).await;
    let begin = |d: &TestDevice| {
        let sf = frame_for(
            &w.ctx.workspace,
            d,
            "workspace.touch.begin",
            begin_args("box.steer", json!({"id": "b-run"})),
        );
        json!({"body": sf.body, "sig": sf.sig, "via": "local"})
    };
    for _ in 0..4 {
        let r = link.call(OP_WORKSPACE_FRAME, begin(&a)).await;
        touch_request(&r);
    }
    let r = link.call(OP_WORKSPACE_FRAME, begin(&a)).await;
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(r["error"], "busy", "{r}");
    assert_eq!(r["rule"], "busy", "{r}");
    let dev_reason = "too many touches in progress on this device";
    assert_eq!(r["message"], dev_reason, "{r}");
    // Another device of the same owner: up to the owner's 8.
    for _ in 0..4 {
        let r = link.call(OP_WORKSPACE_FRAME, begin(&b)).await;
        touch_request(&r);
    }
    // A third device has room of its own, but the owner is at 8.
    let r = link.call(OP_WORKSPACE_FRAME, begin(&c)).await;
    assert_eq!(r["error"], "busy", "{r}");
    assert_eq!(r["rule"], "busy", "{r}");
    let uid_reason = "too many touches in progress";
    assert_eq!(r["message"], uid_reason, "{r}");
    // Each refusal is recorded, and the record says which cap fired.
    let denied: Vec<(Value, Value)> = records(&w)
        .into_iter()
        .filter(|r| field(r, "action") == "workspace.touch.begin" && r["decision"] == "deny")
        .map(|r| (field(&r, "device").clone(), r["reason"].clone()))
        .collect();
    assert_eq!(
        denied,
        vec![
            (json!(a.device_id()), json!(dev_reason)),
            (json!(c.device_id()), json!(uid_reason)),
        ],
    );
    // No box action ran.
    assert!(w.boxes.calls().is_empty());
}

#[tokio::test]
async fn begin_binds_daemon_fields() {
    let (w, mut link, d, _) = paired_with_passkey().await;
    for args in [
        json!({"id": "b-run", "fields": {"action": "box.stop"}}),
        json!({"id": "b-run", "msg": "hello"}),
        json!({}),
    ] {
        let a = send(
            &w,
            &mut link,
            &d,
            "workspace.touch.begin",
            begin_args("box.steer", args.clone()),
        )
        .await;
        assert_eq!(a["error"], "bad_request", "{args}: {a}");
        assert_eq!(a["rule"], "invalid", "{args}: {a}");
    }
    // A box that does not exist is refused, not bound.
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("box.steer", json!({"id": "b-nope"})),
    )
    .await;
    assert_eq!(a["rule"], "not_found", "{a}");
    // The envelope takes only action and args.
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        json!({"action": "box.steer", "args": {"id": "b-run"}, "fields": {}}),
    )
    .await;
    assert_eq!(a["rule"], "invalid", "{a}");
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("box.revise", json!({"id": "b-run"})),
    )
    .await;
    let tr = touch_request(&a);
    let rid: u64 = a["result"]["request_id"].as_str().unwrap().parse().unwrap();
    let i = issued(&w, &d, rid);
    assert_eq!(
        i.fields,
        fields(&[("action", "box.revise"), ("box", "b-run")])
    );
    assert_eq!(i.class, saiife_touch::TouchClass::Steer);
    let rec = saiife_touch::ActionRecord {
        instance_id: w.ctx.touch.instance_id(),
        request_id: rid,
        class: i.class,
        summary: i.summary.clone(),
        fields: i.fields.clone(),
        nonce: i.nonce,
        expires_at: i.expires_at,
    };
    assert_eq!(tr.challenge, saiife_touch::challenge(&rec));
}

#[tokio::test]
async fn begin_for_spawn_binds_the_task_hash() {
    use sha2::{Digest, Sha256};
    let (w, mut link, d, _) = paired_with_passkey().await;
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args(
            "box.spawn",
            json!({"template": "claude-gh", "repo": "erp", "task": "push it", "start": "now"}),
        ),
    )
    .await;
    let tr = touch_request(&a);
    assert_eq!(tr.summary, "spawn claude-gh on erp");
    let i = issued(&w, &d, 1);
    let digest: String = Sha256::digest(b"push it")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        i.fields,
        fields(&[
            ("action", "box.spawn"),
            ("template", "claude-gh"),
            ("repo", "erp"),
            ("task_sha256", &digest),
            ("start", "now"),
        ])
    );
    assert!(w.boxes.calls().is_empty());
}

#[tokio::test]
async fn begin_for_land_is_refused() {
    let (w, mut link, d, _) = paired_with_passkey().await;
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("box.land", json!({"id": "b-done"})),
    )
    .await;
    assert_eq!(a["error"], "bad_request", "{a}");
    assert_eq!(a["rule"], "invalid", "{a}");
    assert!(a["message"].as_str().unwrap().contains("inbox"), "{a}");
}

fn new_connector(touch_class: Option<&str>) -> saiife_daemon::approvals::NewRequest {
    saiife_daemon::approvals::NewRequest {
        uid: me(),
        sid: None,
        user: ME.into(),
        session: None,
        agent: "agent".into(),
        project: "erp".into(),
        kind: saiife_daemon::approvals::ApprovalType::Connector,
        service: Some("stripe".into()),
        operation: Some("refund".into()),
        capability: None,
        params: Default::default(),
        input: None,
        grant_key: None,
        scope: None,
        ask_rule: None,
        touch_class: touch_class.map(String::from),
        send: Default::default(),
    }
}

fn make_request(w: &World, touch_class: Option<&str>) -> saiife_daemon::approvals::Request {
    w.ctx
        .approvals
        .as_ref()
        .unwrap()
        .create(
            new_connector(touch_class),
            |_| Ok(None),
            Duration::from_secs(600),
            std::time::SystemTime::now(),
        )
        .unwrap()
}

#[tokio::test]
async fn begin_for_approval_binds_the_stored_request() {
    let (w, mut link, d, _) = paired_with_passkey().await;
    let r = make_request(&w, Some("deploy"));
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("approval.approve", json!({"id": r.id})),
    )
    .await;
    let tr = touch_request(&a);
    assert_eq!(a["result"]["class"], "deploy", "{a}");
    let i = issued(&w, &d, 1);
    let rec = saiife_daemon::approvals::action_record(
        &r,
        saiife_touch::TouchClass::Deploy,
        w.ctx.touch.instance_id(),
        i.nonce,
        i.expires_at,
    );
    assert_eq!(tr.challenge, saiife_touch::challenge(&rec));
    assert_eq!(tr.summary, rec.summary);
    // Each refusal has its own rule.
    let plain = make_request(&w, None);
    let decided = make_request(&w, Some("deploy"));
    w.ctx
        .approvals
        .as_ref()
        .unwrap()
        .transition(
            decided.id,
            &[saiife_daemon::approvals::State::Pending],
            saiife_daemon::approvals::State::Rejected,
            Some(me()),
            None,
            std::time::SystemTime::now(),
        )
        .unwrap();
    for (args, rule) in [
        (json!({"id": plain.id}), "invalid"),
        (json!({"id": decided.id}), "invalid"),
        (json!({"id": 999}), "not_found"),
        (json!({"id": r.id, "class": "land"}), "invalid"),
        (json!({"id": r.id.to_string()}), "invalid"),
    ] {
        let a = send(
            &w,
            &mut link,
            &d,
            "workspace.touch.begin",
            begin_args("approval.approve", args.clone()),
        )
        .await;
        assert_eq!(a["ok"], false, "{args}: {a}");
        assert_eq!(a["rule"], rule, "{args}: {a}");
    }
    // The not-pending one says so.
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("approval.approve", json!({"id": decided.id})),
    )
    .await;
    assert!(
        a["message"].as_str().unwrap().contains("not pending"),
        "{a}"
    );
}

/// A request shown cut cannot be approved from the browser: the begin is
/// refused before any touch is issued (none is spent on a doomed approval).
#[tokio::test]
async fn begin_for_a_truncated_approval_is_refused_before_the_touch() {
    let (w, mut link, d, _) = paired_with_passkey().await;
    let mut new = new_connector(Some("deploy"));
    new.send.body_truncated = true;
    let cut = w
        .ctx
        .approvals
        .as_ref()
        .unwrap()
        .create(
            new,
            |_| Ok(None),
            Duration::from_secs(600),
            std::time::SystemTime::now(),
        )
        .unwrap();
    assert!(cut.body_truncated);
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("approval.approve", json!({"id": cut.id})),
    )
    .await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "truncated_not_acknowledged", "{a}");
    assert!(
        a["message"]
            .as_str()
            .unwrap()
            .contains("--accept-truncated"),
        "{a}"
    );
    // Nothing was issued: the next begin gets the first web request id.
    let r = make_request(&w, Some("deploy"));
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("approval.approve", json!({"id": r.id})),
    )
    .await;
    assert_eq!(a["result"]["request_id"], "1", "{a}");
    issued(&w, &d, 1);
}

/// The daemon's own uid is not the device owner's: the owner is a requester
/// but no approver, so a begin for their own pending request is refused.
#[tokio::test]
async fn begin_for_approval_needs_an_approver() {
    // Paired (with a passkey) in a personal broker, then the same state
    // dir served by a locked daemon of another uid with no approvers.
    let (w0, link0, d, _) = paired_with_passkey().await;
    drop(link0);
    let state = w0.state.clone();
    let (ws, warning) = Workspace::open(dir_in(&state));
    assert!(warning.is_none(), "{warning:?}");
    let w = build_as(scratch(), state, ws, DaemonMode::Locked, me() + 1).await;
    let mut link = Link::open(&w).await;
    let r = make_request(&w, Some("deploy"));
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("approval.approve", json!({"id": r.id})),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "not_approver", "{a}");
    assert_eq!(w.ctx.touch.credentials_of(me()).len(), 1);
}

#[tokio::test]
async fn begin_for_signed_action_is_refused() {
    let (w, mut link, d, _) = paired_with_passkey().await;
    for action in [
        "box.stop",
        "box.pause",
        "box.push",
        "lockdown.on",
        "workspace.touch.begin",
        "nonsense",
    ] {
        let a = send(
            &w,
            &mut link,
            &d,
            "workspace.touch.begin",
            begin_args(action, json!({"id": "b-run"})),
        )
        .await;
        assert_eq!(a["error"], "bad_request", "{action}: {a}");
        assert_eq!(a["rule"], "invalid", "{action}: {a}");
    }
}

#[tokio::test]
async fn begin_for_plain_spawn_is_refused() {
    let (w, mut link, d, _) = paired_with_passkey().await;
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args(
            "box.spawn",
            json!({"template": "claude", "repo": "web", "task": "x", "start": "now"}),
        ),
    )
    .await;
    assert_eq!(a["error"], "bad_request", "{a}");
    assert_eq!(a["rule"], "invalid", "{a}");
    assert!(w.boxes.calls().is_empty());
}

#[tokio::test]
async fn begin_without_passkey_is_unavailable() {
    let (w, mut link, d) = paired().await;
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("box.steer", json!({"id": "b-run"})),
    )
    .await;
    assert_eq!(a["error"], "unavailable", "{a}");
    assert_eq!(a["rule"], "touch_unavailable", "{a}");
    assert!(a["message"].as_str().unwrap().contains("pair it again"));
}

#[tokio::test]
async fn ninth_open_touch_is_busy() {
    let (w, mut link, d, _) = paired_with_passkey().await;
    // Two browsers of the owner, 4 each (the per-device cap, Task 5 (b)).
    let (e, _) = pair_with_passkey(&w, &mut link).await;
    for n in 0..8 {
        let a = send(
            &w,
            &mut link,
            if n % 2 == 0 { &d } else { &e },
            "workspace.touch.begin",
            begin_args("box.steer", json!({"id": "b-run"})),
        )
        .await;
        assert_eq!(a["ok"], true, "begin {n}: {a}");
    }
    let (f, _) = pair_with_passkey(&w, &mut link).await;
    let a = send(
        &w,
        &mut link,
        &f,
        "workspace.touch.begin",
        begin_args("box.steer", json!({"id": "b-run"})),
    )
    .await;
    assert_eq!(a["error"], "busy", "{a}");
    assert_eq!(a["rule"], "busy", "{a}");
}

#[tokio::test]
async fn begin_is_recorded() {
    let (w, mut link, d, _) = paired_with_passkey().await;
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("box.resume", json!({"id": "b-run"})),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(field(last, "action"), "workspace.touch.begin", "{last}");
    assert_eq!(last["decision"], "allow", "{last}");
    assert_eq!(field(last, "touch_begin")["request_id"], "1", "{last}");
    assert_eq!(field(last, "touch_begin")["class"], "steer", "{last}");
    assert_eq!(field(last, "touch_begin")["action"], "box.resume", "{last}");
    assert_eq!(field(last, "touch_begin")["box"], "b-run", "{last}");
    // The audit detail is not part of the answer.
    assert!(a["result"].get("touch_begin").is_none(), "{a}");
}

// ---- verify Touch frames (plan 31, Task 5) ----

use saiife_touch::soft::SoftAuthenticator;
use saiife_touch::{challenge, Assertion};
use saiife_wire::frame::TouchProof;

/// The proof a browser would send for `asr` as touch request `rid`.
fn proof_json(rid: u64, asr: &Assertion) -> Value {
    match asr {
        Assertion::WebAuthn {
            credential_id,
            auth_data,
            signature,
            client_data_json,
            ..
        } => json!({
            "request_id": rid.to_string(),
            "credential_id": b64::enc(credential_id),
            "authenticator_data": b64::enc(auth_data),
            "client_data_json": b64::enc(client_data_json),
            "signature": b64::enc(signature),
        }),
        other => panic!("not a web assertion: {other:?}"),
    }
}

fn sign_for(soft: &SoftAuthenticator, rid: u64, ch: &[u8; 32]) -> Value {
    proof_json(rid, &soft.assert_webauthn("localhost", ORIGIN, ch))
}

/// A frame with a touch proof, sent over the link.
async fn send_touch(
    w: &World,
    link: &mut Link,
    d: &TestDevice,
    action: &str,
    args: Value,
    proof: Value,
) -> Value {
    let sf = frame_for(&w.ctx.workspace, d, action, args);
    let mut a = frame_args(&sf);
    a["touch"] = proof;
    link.call(OP_WORKSPACE_FRAME, a).await
}

/// `workspace.touch.begin` for `action`: the request id and the challenge.
async fn begin_touch(
    w: &World,
    link: &mut Link,
    d: &TestDevice,
    action: &str,
    args: Value,
) -> (u64, [u8; 32]) {
    let a = send(
        w,
        link,
        d,
        "workspace.touch.begin",
        begin_args(action, args),
    )
    .await;
    let tr = touch_request(&a);
    (
        a["result"]["request_id"].as_str().unwrap().parse().unwrap(),
        tr.challenge,
    )
}

/// The pending `land` of `b-done` in the demo fake.
fn pending_land(w: &World) -> saiife_wire::source::PendingAction {
    let p = w.boxes.pending_actions();
    assert_eq!(p.len(), 1, "{p:?}");
    p.into_iter().next().unwrap()
}

fn land_args(pa: &saiife_wire::source::PendingAction) -> Value {
    json!({"id": "b-done", "diff_sha256": pa.record.fields["diff_sha256"]})
}

fn completes(w: &World) -> usize {
    w.boxes
        .calls()
        .iter()
        .filter(|c| matches!(c, FakeCall::Complete(..)))
        .count()
}

async fn paired_soft() -> (World, Link, TestDevice, SoftAuthenticator) {
    let w = world().await;
    let mut link = Link::open(&w).await;
    let (d, soft) = pair_with_soft(&w, &mut link).await;
    (w, link, d, soft)
}

#[tokio::test]
async fn land_with_touch_completes() {
    let (w, mut link, d, soft) = paired_soft().await;
    let pa = pending_land(&w);
    let proof = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"], json!({}), "{a}");
    assert_eq!(
        w.boxes.calls(),
        vec![FakeCall::Complete(
            pa.request_id,
            saiife_wire::source::Decision::Approve,
            true
        )]
    );
    assert!(w.boxes.pending_actions().is_empty());
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(field(last, "action"), "box.land", "{last}");
    assert_eq!(last["decision"], "allow", "{last}");
    assert_eq!(field(last, "box"), "b-done", "{last}");
    assert_eq!(field(last, "touch")["kind"], "webauthn", "{last}");
    assert_eq!(field(last, "touch")["via"], "web", "{last}");
    assert_eq!(field(last, "touch")["uv"], true, "{last}");
    assert_eq!(
        field(last, "touch")["challenge"],
        challenge(&pa.record)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "{last}"
    );
}

#[tokio::test]
async fn touch_for_other_box_is_mismatch() {
    let (w, mut link, d, soft) = paired_soft().await;
    let (rid, ch) = begin_touch(&w, &mut link, &d, "box.steer", json!({"id": "b-run"})).await;
    let proof = sign_for(&soft, rid, &ch);
    // Box A's touch on box B.
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-q1", "msg": "hi"}),
        proof.clone(),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    // The entry is burned: the right frame with the same proof is refused too.
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-run", "msg": "hi"}),
        proof,
    )
    .await;
    assert_eq!(a["rule"], "touch_failed", "{a}");
    assert!(a["message"].as_str().unwrap().contains("no live"), "{a}");
    assert!(w.boxes.calls().is_empty());
}

#[tokio::test]
async fn land_proof_on_revise_is_mismatch() {
    let (w, mut link, d, soft) = paired_soft().await;
    let pa = pending_land(&w);
    let rid = pa.request_id;
    let proof = sign_for(&soft, rid, &challenge(&pa.record));
    // R-P1: a live Web entry for this device under the land's request id,
    // bound to a revise: the refusal is the challenge compare.
    let fields = fields(&[("action", "box.revise"), ("box", "b-run")]);
    w.ctx
        .touch
        .issue(
            saiife_daemon::touch::IssueKey::Web {
                device: d.device_id(),
                request_id: rid,
            },
            me(),
            saiife_touch::TouchClass::Steer,
            "box.revise box b-run".into(),
            fields,
            saiife_daemon::touch::unix_now(),
        )
        .unwrap();
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.revise",
        json!({"id": "b-run", "comment": "go"}),
        proof.clone(),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    // No entry (it was burned): the same proof is Expired, touch_failed.
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.revise",
        json!({"id": "b-run", "comment": "go"}),
        proof,
    )
    .await;
    assert_eq!(a["rule"], "touch_failed", "{a}");
    // Nothing ran, and the pending land is untouched.
    assert!(w.boxes.calls().is_empty(), "{:?}", w.boxes.calls());
    assert_eq!(w.boxes.pending_actions().len(), 1);
}

#[tokio::test]
async fn assertion_reuse_is_refused() {
    let (w, mut link, d, soft) = paired_soft().await;
    // A web touch: verified once (the action is not available yet), then
    // the same frame body re-signed with a new nonce and the same proof.
    let (rid, ch) = begin_touch(&w, &mut link, &d, "box.resume", json!({"id": "b-run"})).await;
    let proof = sign_for(&soft, rid, &ch);
    let first = send_touch(
        &w,
        &mut link,
        &d,
        "box.resume",
        json!({"id": "b-run"}),
        proof.clone(),
    )
    .await;
    // Verified and run: b-run is not paused, so the box source refuses.
    assert_eq!(first["rule"], "wrong_state", "{first}");
    let again = send_touch(
        &w,
        &mut link,
        &d,
        "box.resume",
        json!({"id": "b-run"}),
        proof,
    )
    .await;
    assert_eq!(again["error"], "forbidden", "{again}");
    assert_eq!(again["rule"], "touch_failed", "{again}");
    // A land: the pending action goes with the first completion; the same
    // proof again finds none.
    let pa = pending_land(&w);
    let proof = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof.clone()).await;
    assert_eq!(a["ok"], true, "{a}");
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["rule"], "touch_failed", "{a}");
    assert!(a["message"].as_str().unwrap().contains("no pending"), "{a}");
    assert_eq!(completes(&w), 1);
}

#[tokio::test]
async fn a_replayed_counter_is_refused() {
    let (w, mut link, d, mut soft) = paired_soft().await;
    let (rid, ch) = begin_touch(&w, &mut link, &d, "box.resume", json!({"id": "b-run"})).await;
    let ok = send_touch(
        &w,
        &mut link,
        &d,
        "box.resume",
        json!({"id": "b-run"}),
        sign_for(&soft, rid, &ch),
    )
    .await;
    assert_eq!(ok["rule"], "wrong_state", "{ok}");
    // A counter that does not advance past the stored one.
    soft.counter_step = 0;
    let (rid, ch) = begin_touch(&w, &mut link, &d, "box.resume", json!({"id": "b-run"})).await;
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.resume",
        json!({"id": "b-run"}),
        sign_for(&soft, rid, &ch),
    )
    .await;
    assert_eq!(a["rule"], "touch_failed", "{a}");
    assert!(
        a["message"].as_str().unwrap().contains("used before"),
        "{a}"
    );
}

/// A frame as the daemon would hand `verify_frame`, for direct calls.
fn verified(w: &World, d: &TestDevice, action: &str, args: Value) -> saiife_wire::verify::Verified {
    let h = w.ctx.workspace.hello();
    let now = w.ctx.workspace.now();
    saiife_wire::verify::Verified {
        frame: Frame {
            v: 1,
            machine_id: h["machine_id"].as_str().unwrap().into(),
            epoch: h["epoch"].as_str().unwrap().into(),
            device_id: d.device_id(),
            action: action.into(),
            args: args.as_object().unwrap().clone(),
            nonce: nonce(),
            issued_at: now,
            expires_at: now + 60,
        },
        device_id: d.device_id(),
        owner_user: ME.into(),
        level: Level::Touch,
    }
}

fn proof_of(v: &Value) -> TouchProof {
    serde_json::from_value(v.clone()).unwrap()
}

#[tokio::test]
async fn a_second_valid_assertion_for_a_spent_land_is_refused() {
    use saiife_daemon::workspace_touch::{verify_frame, Proven};
    let (w, _link, d, soft) = paired_soft().await;
    let pa = pending_land(&w);
    let ch = challenge(&pa.record);
    let v = verified(&w, &d, "box.land", land_args(&pa));
    let src = Arc::clone(&w.ctx.boxes);
    // Two different valid assertions (the counter advances) for one challenge:
    // the first verifies, the second finds the challenge spent.
    let p1 = proof_of(&sign_for(&soft, pa.request_id, &ch));
    let p2 = proof_of(&sign_for(&soft, pa.request_id, &ch));
    let first = verify_frame(&w.ctx, &v, me(), &src, &p1).await;
    assert!(matches!(first, Ok(Proven::Pending(..))));
    let second = verify_frame(&w.ctx, &v, me(), &src, &p2)
        .await
        .err()
        .unwrap();
    assert_eq!(second.rule, "touch_failed");
    assert!(second.message.contains("used before"), "{second:?}");
}

#[tokio::test]
async fn uv_clear_is_refused() {
    let (w, mut link, d, mut soft) = paired_soft().await;
    soft.uv = false;
    let pa = pending_land(&w);
    let proof = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_failed", "{a}");
    assert!(
        a["message"].as_str().unwrap().contains("user verification"),
        "{a}"
    );
    // The pending land can still be touched (a bad proof burns nothing).
    soft.uv = true;
    let proof = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["ok"], true, "{a}");
    // A steer touch without UV is refused the same way.
    soft.uv = false;
    let (rid, ch) = begin_touch(&w, &mut link, &d, "box.steer", json!({"id": "b-run"})).await;
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-run", "msg": "x"}),
        sign_for(&soft, rid, &ch),
    )
    .await;
    assert_eq!(a["rule"], "touch_failed", "{a}");
    assert!(
        a["message"].as_str().unwrap().contains("user verification"),
        "{a}"
    );
}

#[tokio::test]
async fn foreign_origin_is_refused() {
    let (w, mut link, d, soft) = paired_soft().await;
    let pa = pending_land(&w);
    let asr = soft.assert_webauthn(
        "localhost",
        "https://app.saiife.com",
        &challenge(&pa.record),
    );
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.land",
        land_args(&pa),
        proof_json(pa.request_id, &asr),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    assert_eq!(completes(&w), 0);
}

#[tokio::test]
async fn listed_origin_not_enrolled_for_the_credential_is_refused() {
    let (w, mut link, d, soft) = paired_soft().await;
    // A second origin is listed, but the passkey was enrolled for ORIGIN only.
    let other = "https://other.example.com";
    let cfg: saiife_policy::SystemConfig = toml::from_str(&format!(
        "version = 2\n[workspace]\norigins = [\"{ORIGIN}\", \"{other}\"]\n"
    ))
    .unwrap();
    w.ctx.policy.lock().unwrap().system = Some(Arc::new(cfg));
    let pa = pending_land(&w);
    let asr = soft.assert_webauthn("localhost", other, &challenge(&pa.record));
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.land",
        land_args(&pa),
        proof_json(pa.request_id, &asr),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    assert_eq!(completes(&w), 0);
    // The enrolled origin still works.
    let proof = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(completes(&w), 1);
}

#[tokio::test]
async fn rp_id_of_other_host_is_refused() {
    let (w, mut link, d, mut soft) = paired_soft().await;
    soft.rp_override = Some("soft.rs".into());
    let pa = pending_land(&w);
    let proof = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    assert_eq!(completes(&w), 0);
}

#[tokio::test]
async fn other_devices_passkey_is_refused() {
    let (w, mut link, a_dev, _soft_a) = paired_soft().await;
    let (_b_dev, soft_b) = pair_with_soft(&w, &mut link).await;
    // Both belong to the same user and both credentials are in the store;
    // B's passkey on A's frame is still refused.
    assert_eq!(w.ctx.touch.credentials_of(me()).len(), 2);
    let pa = pending_land(&w);
    let proof = sign_for(&soft_b, pa.request_id, &challenge(&pa.record));
    let a = send_touch(&w, &mut link, &a_dev, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    assert_eq!(completes(&w), 0);
    // Through begin too: A's request lists only A's passkey.
    let a = send(
        &w,
        &mut link,
        &a_dev,
        "workspace.touch.begin",
        begin_args("box.steer", json!({"id": "b-run"})),
    )
    .await;
    assert_eq!(touch_request(&a).allow.len(), 1);
}

#[tokio::test]
async fn revoked_devices_credential_is_refused() {
    use saiife_daemon::workspace_touch::verify_frame;
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().as_raw() == 0 {
        return; // root writes through a read-only directory
    }
    let (w, mut link, d, soft) = paired_soft().await;
    let pa = pending_land(&w);
    let proof = proof_of(&sign_for(&soft, pa.request_id, &challenge(&pa.record)));
    // Revoke with the credential removal failing: the credential stays in
    // the touch store.
    let touch_dir = w.state.join("state").join("touch");
    std::fs::set_permissions(&touch_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let r = control(&w, OP_WORKSPACE_REVOKE, json!({"device_id": d.device_id()})).await;
    std::fs::set_permissions(&touch_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(w.ctx.touch.credentials_of(me()).len(), 1);
    // The frame never gets that far...
    let sf = frame_for(&w.ctx.workspace, &d, "box.land", land_args(&pa));
    let mut args = frame_args(&sf);
    args["touch"] = serde_json::to_value(&proof).unwrap();
    let a = link.call(OP_WORKSPACE_FRAME, args).await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(completes(&w), 0);
    // ...and if it did, the gate holds on its own (R-T3b).
    let v = verified(&w, &d, "box.land", land_args(&pa));
    let src = Arc::clone(&w.ctx.boxes);
    let e = verify_frame(&w.ctx, &v, me(), &src, &proof)
        .await
        .err()
        .unwrap();
    assert_eq!(e.rule, "touch_mismatch", "{e:?}");
    assert_eq!(w.boxes.pending_actions().len(), 1);
}

#[tokio::test]
async fn expired_challenge_is_refused() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let tmp = scratch();
    let state = tmp.path().join("state");
    let skew = Arc::new(AtomicU64::new(0));
    let s2 = Arc::clone(&skew);
    let (ws, warning) = Workspace::open(dir_in(&state));
    assert!(warning.is_none(), "{warning:?}");
    let ws = ws.with_clock(Arc::new(move || now_secs() + s2.load(Ordering::SeqCst)));
    let w = build(tmp, state, ws).await;
    let mut link = Link::open(&w).await;
    let (d, soft) = pair_with_soft(&w, &mut link).await;
    let (rid, ch) = begin_touch(&w, &mut link, &d, "box.steer", json!({"id": "b-run"})).await;
    let proof = sign_for(&soft, rid, &ch);
    skew.store(301, Ordering::SeqCst);
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-run", "msg": "x"}),
        proof,
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "touch_failed", "{a}");
    assert!(a["message"].as_str().unwrap().contains("no live"), "{a}");
}

#[tokio::test]
async fn diff_hash_mismatch_is_refused() {
    let (w, mut link, d, soft) = paired_soft().await;
    let pa = pending_land(&w);
    let proof = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    let other = "0".repeat(64);
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.land",
        json!({"id": "b-done", "diff_sha256": other}),
        proof.clone(),
    )
    .await;
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    // Another box than the pending action's.
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.land",
        json!({"id": "b-run", "diff_sha256": pa.record.fields["diff_sha256"]}),
        proof.clone(),
    )
    .await;
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    // The frame's args are exactly id and diff_sha256.
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.land",
        json!({"id": "b-done", "diff_sha256": pa.record.fields["diff_sha256"], "x": 1}),
        proof.clone(),
    )
    .await;
    assert_eq!(a["rule"], "invalid", "{a}");
    assert_eq!(completes(&w), 0);
    // Nothing was spent: the right frame still lands.
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["ok"], true, "{a}");
}

#[tokio::test]
async fn land_without_a_pending_action_is_refused() {
    let (w, mut link, d, soft) = paired_soft().await;
    let pa = pending_land(&w);
    let proof = sign_for(&soft, pa.request_id + 100, &challenge(&pa.record));
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["rule"], "touch_failed", "{a}");
    assert!(
        a["message"]
            .as_str()
            .unwrap()
            .contains("expired or was decided"),
        "{a}"
    );
}

#[tokio::test]
async fn a_bad_proof_envelope_is_refused() {
    let (w, mut link, d, soft) = paired_soft().await;
    let pa = pending_land(&w);
    let good = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    for rid in ["", "x1", "+1", "-1", "1.0", "99999999999999999999999"] {
        let mut p = good.clone();
        p["request_id"] = json!(rid);
        let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), p).await;
        assert_eq!(a["error"], "bad_request", "{rid}: {a}");
        assert_eq!(a["rule"], "invalid", "{rid}: {a}");
    }
    // The origin comes from the signed client data; junk there is Malformed.
    let mut p = good.clone();
    p["client_data_json"] = json!(b64::enc(b"{}"));
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), p).await;
    assert_eq!(a["rule"], "touch_failed", "{a}");
    // A touch on a Signed action is ignored, not acted on as a land.
    assert_eq!(completes(&w), 0);
}

#[tokio::test]
async fn approval_proof_verifies_for_its_request_only() {
    use saiife_daemon::workspace_touch::{verify_frame, Proven};
    let (w, mut link, d, soft) = paired_soft().await;
    let r1 = make_request(&w, Some("deploy"));
    let r2 = make_request(&w, Some("deploy"));
    let src = Arc::clone(&w.ctx.boxes);
    // A touch begun for r1, shown for r2: its challenge is not r2's.
    let (rid, ch) = begin_touch(&w, &mut link, &d, "approval.approve", json!({"id": r1.id})).await;
    let p = proof_of(&sign_for(&soft, rid, &ch));
    let v2 = verified(&w, &d, "approval.approve", json!({"id": r2.id}));
    let e = verify_frame(&w.ctx, &v2, me(), &src, &p)
        .await
        .err()
        .unwrap();
    assert_eq!(e.rule, "touch_mismatch", "{e:?}");
    // Burned: the right frame with a fresh signature has no live entry.
    let p = proof_of(&sign_for(&soft, rid, &ch));
    let v1 = verified(&w, &d, "approval.approve", json!({"id": r1.id}));
    let e = verify_frame(&w.ctx, &v1, me(), &src, &p)
        .await
        .err()
        .unwrap();
    assert_eq!(e.rule, "touch_failed", "{e:?}");
    // A fresh begin and the right frame verifies.
    let (rid, ch) = begin_touch(&w, &mut link, &d, "approval.approve", json!({"id": r1.id})).await;
    let p = proof_of(&sign_for(&soft, rid, &ch));
    match verify_frame(&w.ctx, &v1, me(), &src, &p).await {
        Ok(Proven::Approval(ev, id)) => {
            assert_eq!(id, r1.id);
            assert_eq!(ev.via, "web");
        }
        other => panic!("not an approval proof: {:?}", other.err()),
    }
    // A steer touch cannot approve a request.
    let (rid, ch) = begin_touch(&w, &mut link, &d, "box.steer", json!({"id": "b-run"})).await;
    let p = proof_of(&sign_for(&soft, rid, &ch));
    let e = verify_frame(&w.ctx, &v1, me(), &src, &p)
        .await
        .err()
        .unwrap();
    assert_eq!(e.rule, "touch_mismatch", "{e:?}");
    // Over the link the approval is verified and decided; the evidence
    // is recorded.
    let cfg: saiife_policy::SystemConfig = toml::from_str("version = 2\n").unwrap();
    w.ctx.policy.lock().unwrap().system = Some(Arc::new(cfg));
    let (rid, ch) = begin_touch(&w, &mut link, &d, "approval.approve", json!({"id": r1.id})).await;
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "approval.approve",
        json!({"id": r1.id}),
        sign_for(&soft, rid, &ch),
    )
    .await;
    assert_eq!(a["result"]["state"], "approved", "{a}");
    let rs = records(&w);
    assert_eq!(field(rs.last().unwrap(), "touch")["kind"], "webauthn");
}

#[tokio::test]
async fn refusal_records_the_rule() {
    let (w, mut link, d, mut soft) = paired_soft().await;
    soft.uv = false;
    let pa = pending_land(&w);
    let proof = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    let sig = proof["signature"].as_str().unwrap().to_string();
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), proof).await;
    assert_eq!(a["rule"], "touch_failed", "{a}");
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(field(last, "action"), "box.land", "{last}");
    assert_eq!(last["decision"], "deny", "{last}");
    assert_eq!(last["rule"], "touch_failed", "{last}");
    assert_eq!(field(last, "level"), "touch", "{last}");
    // The proof's bytes are not in the record.
    assert!(field(last, "touch").is_null(), "{last}");
    assert!(!last.to_string().contains(&sig), "{last}");
    // A malformed proof records its rule too, with no assertion bytes.
    let mut p = sign_for(&soft, pa.request_id, &challenge(&pa.record));
    p["client_data_json"] = json!(b64::enc(b"nope"));
    let junk = p["authenticator_data"].as_str().unwrap().to_string();
    let a = send_touch(&w, &mut link, &d, "box.land", land_args(&pa), p).await;
    assert_eq!(a["rule"], "touch_failed", "{a}");
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(last["rule"], "touch_failed", "{last}");
    assert!(field(last, "touch").is_null(), "{last}");
    assert!(!last.to_string().contains(&junk), "{last}");
}

// ---------------------------------------------------------------- Task 6

/// A touch for `action` on `args`, then the frame carrying it.
async fn touched_frame(
    w: &World,
    link: &mut Link,
    d: &TestDevice,
    soft: &SoftAuthenticator,
    action: &str,
    args: Value,
) -> Value {
    let bound = match action {
        "box.steer" | "box.revise" | "box.resume" | "approval.approve" => json!({"id": args["id"]}),
        _ => args.clone(),
    };
    let (rid, ch) = begin_touch(w, link, d, action, bound).await;
    send_touch(w, link, d, action, args, sign_for(soft, rid, &ch)).await
}

/// A world whose Workspace clock can be moved forward.
async fn skewed() -> (
    World,
    Link,
    TestDevice,
    SoftAuthenticator,
    Arc<std::sync::atomic::AtomicU64>,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    let tmp = scratch();
    let state = tmp.path().join("state");
    let skew = Arc::new(AtomicU64::new(0));
    let s2 = Arc::clone(&skew);
    let (ws, warning) = Workspace::open(dir_in(&state));
    assert!(warning.is_none(), "{warning:?}");
    let ws = ws.with_clock(Arc::new(move || now_secs() + s2.load(Ordering::SeqCst)));
    let w = build(tmp, state, ws).await;
    let mut link = Link::open(&w).await;
    let (d, soft) = pair_with_soft(&w, &mut link).await;
    (w, link, d, soft, skew)
}

#[tokio::test]
async fn steer_window_is_per_box_and_expires() {
    use std::sync::atomic::Ordering;
    let (w, mut link, d, soft, skew) = skewed().await;
    // No touch, no window.
    let a = send(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-run", "msg": "hi"}),
    )
    .await;
    assert_eq!(a["rule"], "touch_required", "{a}");
    // A touch on b-run runs and opens b-run's window.
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "box.steer",
        json!({"id": "b-run", "msg": "first"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    // A plain frame on b-run runs; on another box it needs a touch.
    let a = send(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-run", "msg": "second"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let a = send(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-q1", "msg": "third"}),
    )
    .await;
    assert_eq!(a["rule"], "touch_required", "{a}");
    let steers: Vec<_> = w
        .boxes
        .calls()
        .into_iter()
        .filter(|c| matches!(c, FakeCall::Steer(..)))
        .collect();
    assert_eq!(steers.len(), 2, "{steers:?}");
    // Inside the window still; past 600 s it is closed.
    skew.store(500, Ordering::SeqCst);
    let a = send(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-run", "msg": "late"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    skew.store(601, Ordering::SeqCst);
    let a = send(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-run", "msg": "later"}),
    )
    .await;
    assert_eq!(a["rule"], "touch_required", "{a}");
}

#[tokio::test]
async fn revoke_closes_windows() {
    let (w, mut link, d, soft) = paired_soft().await;
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "box.steer",
        json!({"id": "b-run", "msg": "x"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let id = BoxId::parse("b-run").unwrap();
    let now = w.ctx.workspace.now();
    assert!(w.ctx.web_touch.window_open(&d.device_id(), &id, now));
    let r = control(&w, OP_WORKSPACE_REVOKE, json!({"device_id": d.device_id()})).await;
    assert_eq!(r["ok"], true, "{r}");
    assert!(!w.ctx.web_touch.window_open(&d.device_id(), &id, now));
}

#[tokio::test]
async fn window_frames_are_marked() {
    let (w, mut link, d, soft) = paired_soft().await;
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "box.steer",
        json!({"id": "b-run", "msg": "one"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(field(last, "action"), "box.steer", "{last}");
    assert_eq!(field(last, "touch")["via"], "web", "{last}");
    assert!(field(last, "window").is_null(), "{last}");
    let a = send(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-run", "msg": "two"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(field(last, "action"), "box.steer", "{last}");
    assert_eq!(field(last, "window"), true, "{last}");
    assert!(field(last, "touch").is_null(), "{last}");
    assert_eq!(field(last, "box"), "b-run", "{last}");
}

/// R25/N1: a revise on a box that held a prompt unsent (sent ahead of the
/// comment) says so in its frame record's reason; the answer carries
/// nothing more.
#[tokio::test]
async fn a_revise_frame_record_names_a_held_prompt_sent_first() {
    let (w, mut link, d, soft) = paired_soft().await;
    w.boxes.hold_prompt(&BoxId::parse("b-done").unwrap());
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "box.revise",
        json!({"id": "b-done", "comment": "again"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"], json!({}), "{a}");
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(field(last, "action"), "box.revise", "{last}");
    assert_eq!(
        field(last, "reason"),
        saiife_wire::source::HELD_PROMPT_SENT_FIRST,
        "{last}"
    );
}

#[tokio::test]
async fn resume_and_revise_use_the_window() {
    let (w, mut link, d, soft) = paired_soft().await;
    // Pause b-run (signed), then resume it under a touch.
    let a = send(&w, &mut link, &d, "box.pause", json!({"id": "b-run"})).await;
    assert_eq!(a["ok"], true, "{a}");
    let a = send(&w, &mut link, &d, "box.resume", json!({"id": "b-run"})).await;
    assert_eq!(a["rule"], "touch_required", "{a}");
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "box.resume",
        json!({"id": "b-run"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    // The window of b-run covers a steer, but not b-done's revise.
    let a = send(
        &w,
        &mut link,
        &d,
        "box.revise",
        json!({"id": "b-done", "comment": "again"}),
    )
    .await;
    assert_eq!(a["rule"], "touch_required", "{a}");
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "box.revise",
        json!({"id": "b-done", "comment": "again"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    // b-done runs again; the touch's window now covers a steer.
    let a = send(
        &w,
        &mut link,
        &d,
        "box.steer",
        json!({"id": "b-done", "msg": "and more"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let calls = w.boxes.calls();
    assert!(calls
        .iter()
        .any(|c| matches!(c, FakeCall::Revise(i, t) if i.as_str() == "b-done" && t == "again")));
    assert!(calls
        .iter()
        .any(|c| matches!(c, FakeCall::Resume(i) if i.as_str() == "b-run")));
    // Bad text is refused before the touch is spent.
    let (rid, ch) = begin_touch(&w, &mut link, &d, "box.revise", json!({"id": "b-run"})).await;
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.revise",
        json!({"id": "b-run", "comment": "x\u{1b}y"}),
        sign_for(&soft, rid, &ch),
    )
    .await;
    assert_eq!(a["rule"], "invalid", "{a}");
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.revise",
        json!({"id": "b-run", "comment": "fine"}),
        sign_for(&soft, rid, &ch),
    )
    .await;
    // The touch was kept: it verifies and runs, and b-run (Running) is no
    // box to revise.
    assert_eq!(a["rule"], "wrong_state", "{a}");
}

#[tokio::test]
async fn lockdown_refuses_steer_even_in_window() {
    let (w, mut link, d, soft) = paired_soft().await;
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "box.steer",
        json!({"id": "b-run", "msg": "x"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let l = send(&w, &mut link, &d, "lockdown.on", json!({})).await;
    assert_eq!(l["ok"], true, "{l}");
    let before = w.boxes.calls().len();
    for (action, args) in [
        ("box.steer", json!({"id": "b-run", "msg": "y"})),
        ("box.resume", json!({"id": "b-run"})),
        ("box.revise", json!({"id": "b-done", "comment": "y"})),
    ] {
        let a = send(&w, &mut link, &d, action, args.clone()).await;
        assert_eq!(a["error"], "lockdown", "{action}: {a}");
        // A touch does not lift it either, and is not spent.
        let a = touched_frame(&w, &mut link, &d, &soft, action, args).await;
        assert_eq!(a["error"], "lockdown", "{action}: {a}");
    }
    assert_eq!(w.boxes.calls().len(), before);
}

#[tokio::test]
async fn spawn_secret_template_with_touch_spawns() {
    let (w, mut link, d, soft) = paired_soft().await;
    let args = json!({"template": "claude-gh", "repo": "erp", "task": "push it", "start": "now"});
    let a = touched_frame(&w, &mut link, &d, &soft, "box.spawn", args.clone()).await;
    assert_eq!(a["ok"], true, "{a}");
    let id = a["result"]["id"].as_str().unwrap().to_string();
    match w.boxes.calls().as_slice() {
        [FakeCall::Spawn(req)] => {
            assert_eq!(req.template, "claude-gh");
            assert_eq!(req.repo, "erp");
            assert_eq!(req.task, "push it");
            assert_eq!(req.start, Start::Now);
        }
        other => panic!("{other:?}"),
    }
    assert!(w.boxes.list().iter().any(|b| b.id.as_str() == id));
    let r = records(&w);
    let last = r.last().unwrap();
    assert_eq!(field(last, "action"), "box.spawn", "{last}");
    assert_eq!(last["decision"], "allow", "{last}");
    assert_eq!(field(last, "touch")["via"], "web", "{last}");
    // A touch for another task cannot spawn this one.
    let (rid, ch) = begin_touch(&w, &mut link, &d, "box.spawn", args.clone()).await;
    let mut other = args.clone();
    other["task"] = json!("push something else");
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "box.spawn",
        other,
        sign_for(&soft, rid, &ch),
    )
    .await;
    assert_eq!(a["rule"], "touch_mismatch", "{a}");
    assert_eq!(w.boxes.calls().len(), 1);
}

#[tokio::test]
async fn push_and_pr_stay_unavailable() {
    let (w, mut link, d, soft) = paired_soft().await;
    for action in ["box.push", "box.pr"] {
        let a = send(&w, &mut link, &d, action, json!({"id": "b-done"})).await;
        assert_eq!(a["error"], "unavailable", "{action}: {a}");
        assert_eq!(a["rule"], "unavailable", "{action}: {a}");
        // Even with a (junk-free) touch the answer is the same.
        let a = send_touch(
            &w,
            &mut link,
            &d,
            action,
            json!({"id": "b-done"}),
            sign_for(&soft, 1, &[0; 32]),
        )
        .await;
        assert_eq!(a["rule"], "unavailable", "{action}: {a}");
    }
    assert!(w.boxes.calls().is_empty());
}

/// The `approval` records so far, oldest first.
fn approval_records(w: &World) -> Vec<Value> {
    fn walk(p: &Path, out: &mut Vec<Value>) {
        let mut entries: Vec<_> = std::fs::read_dir(p).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if let Ok(t) = std::fs::read_to_string(&p) {
                for line in t.lines() {
                    if let Ok(v) = serde_json::from_str::<Value>(line) {
                        if v["kind"] == "approval" {
                            out.push(v);
                        }
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&w.audit, &mut out);
    out
}

/// The paired device of [`paired_soft`], served by a locked daemon of
/// another uid whose policy is `policy`.
async fn paired_locked(policy: &str) -> (World, Link, TestDevice, SoftAuthenticator) {
    let (w0, link0, d, soft) = paired_soft().await;
    drop(link0);
    let state = w0.state.clone();
    // The state dir lives as long as the new world.
    let keep = w0._tmp;
    let (ws, warning) = Workspace::open(dir_in(&state));
    assert!(warning.is_none(), "{warning:?}");
    let mut w = build_as(scratch(), state, ws, DaemonMode::Locked, me() + 1).await;
    w._keep = Some(keep);
    let cfg: saiife_policy::SystemConfig = toml::from_str(policy).unwrap();
    w.ctx.policy.lock().unwrap().system = Some(Arc::new(cfg));
    let link = Link::open(&w).await;
    (w, link, d, soft)
}

fn request_of(w: &World, uid: u32, user: &str) -> saiife_daemon::approvals::Request {
    let mut n = new_connector(Some("deploy"));
    n.uid = uid;
    n.user = user.into();
    w.ctx
        .approvals
        .as_ref()
        .unwrap()
        .create(
            n,
            |_| Ok(None),
            Duration::from_secs(600),
            std::time::SystemTime::now(),
        )
        .unwrap()
}

const APPROVER_POLICY: &str =
    "version = 2\nlocked = true\n[approval]\napprovers = [\"me\"]\nsame_user = \"deny\"\n";

#[tokio::test]
async fn approval_list_is_for_approvers() {
    // A non-approver (a locked daemon with no approvers) gets nothing.
    let (w, mut link, d, _) = paired_locked("version = 2\nlocked = true\n").await;
    let r = request_of(&w, 4242, "other");
    let a = send(&w, &mut link, &d, "approval.list", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"], json!({"items": []}), "{a}");
    drop(r);
    // An approver sees the pending requests, with their touch class.
    let (w, mut link, d, _) = paired_locked(APPROVER_POLICY).await;
    let r = request_of(&w, 4242, "other");
    let decided = request_of(&w, 4242, "other");
    w.ctx
        .approvals
        .as_ref()
        .unwrap()
        .transition(
            decided.id,
            &[saiife_daemon::approvals::State::Pending],
            saiife_daemon::approvals::State::Rejected,
            Some(me()),
            None,
            std::time::SystemTime::now(),
        )
        .unwrap();
    let a = send(&w, &mut link, &d, "approval.list", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    let items = a["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{a}");
    assert_eq!(items[0]["id"], r.id, "{a}");
    assert_eq!(items[0]["touch_class"], "deploy", "{a}");
    assert!(items[0].get("request_sealed").is_none(), "{a}");
    assert!(items[0].get("grant_key").is_none(), "{a}");
    // List takes no arguments.
    let a = send(&w, &mut link, &d, "approval.list", json!({"x": 1})).await;
    assert_eq!(a["rule"], "invalid", "{a}");
}

#[tokio::test]
async fn approval_approve_needs_touch_and_approver() {
    // Personal broker: its own user approves.
    let (w, mut link, d, soft) = paired_soft().await;
    let cfg: saiife_policy::SystemConfig = toml::from_str("version = 2\n").unwrap();
    w.ctx.policy.lock().unwrap().system = Some(Arc::new(cfg));
    let r = make_request(&w, Some("deploy"));
    let a = send(&w, &mut link, &d, "approval.approve", json!({"id": r.id})).await;
    assert_eq!(a["rule"], "touch_required", "{a}");
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "approval.approve",
        json!({"id": r.id}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"]["state"], "approved", "{a}");
    let rs = approval_records(&w);
    let rec = rs
        .iter()
        .rev()
        .find(|v| field(v, "action") == "approved")
        .unwrap_or_else(|| panic!("{rs:?}"));
    assert_eq!(field(rec, "id"), r.id, "{rec}");
    assert_eq!(field(rec, "touch")["via"], "web", "{rec}");
    assert_eq!(field(rec, "workspace")["device"], d.device_id(), "{rec}");
    assert_eq!(field(rec, "workspace")["label"], "phone", "{rec}");
    assert_eq!(field(rec, "by_uid"), me(), "{rec}");
    let s = w.ctx.approvals.as_ref().unwrap().get(r.id).unwrap();
    assert_eq!(s.state, saiife_daemon::approvals::State::Approved);
    // Approved once: a second decision finds it decided.
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("approval.approve", json!({"id": r.id})),
    )
    .await;
    assert_eq!(a["rule"], "invalid", "{a}");

    // Another requester's request, an approver of a locked daemon.
    let (w, mut link, d, soft) = paired_locked(APPROVER_POLICY).await;
    let r = request_of(&w, 4242, "other");
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "approval.approve",
        json!({"id": r.id, "note": "ok by me"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"]["state"], "approved", "{a}");
    let s = w.ctx.approvals.as_ref().unwrap().get(r.id).unwrap();
    assert_eq!(s.note.as_deref(), Some("ok by me"));

    // The device owner is no approver: forbidden, nothing decided.
    // (Their own request, so they may see it, but not decide it.)
    let (w, mut link, d, soft) = paired_locked("version = 2\nlocked = true\n").await;
    let r = request_of(&w, me(), ME);
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "approval.approve",
        json!({"id": r.id}),
        sign_for(&soft, 1, &[0; 32]),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "not_approver", "{a}");
    let s = w.ctx.approvals.as_ref().unwrap().get(r.id).unwrap();
    assert_eq!(s.state, saiife_daemon::approvals::State::Pending);
}

#[tokio::test]
async fn requester_cannot_approve_own_request() {
    let (w, mut link, d, soft) = paired_locked(APPROVER_POLICY).await;
    let r = request_of(&w, me(), ME);
    // Refused before any touch is issued (so none is spent), and recorded.
    let a = send(
        &w,
        &mut link,
        &d,
        "workspace.touch.begin",
        begin_args("approval.approve", json!({"id": r.id})),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "same_user", "{a}");
    assert!(w
        .ctx
        .touch
        .take(
            &saiife_daemon::touch::IssueKey::Web {
                device: d.device_id(),
                request_id: 1,
            },
            me()
        )
        .is_err());
    let a = send_touch(
        &w,
        &mut link,
        &d,
        "approval.approve",
        json!({"id": r.id}),
        sign_for(&soft, 1, &[0; 32]),
    )
    .await;
    assert_eq!(a["rule"], "same_user", "{a}");
    let s = w.ctx.approvals.as_ref().unwrap().get(r.id).unwrap();
    assert_eq!(s.state, saiife_daemon::approvals::State::Pending);
    let rs = records(&w);
    assert_eq!(rs.last().unwrap()["rule"], "same_user", "{rs:?}");
    assert_eq!(rs.last().unwrap()["decision"], "deny");
    // The requester's own pending request is not listed for them either.
    let a = send(&w, &mut link, &d, "approval.list", json!({})).await;
    assert_eq!(a["result"], json!({"items": []}), "{a}");
    // [approval] same_user = "reauth": the web touch is the re-authentication.
    let (w, mut link, d, soft) = paired_locked(
        "version = 2\nlocked = true\n[approval]\napprovers = [\"me\"]\nsame_user = \"reauth\"\n",
    )
    .await;
    let r = request_of(&w, me(), ME);
    let a = touched_frame(
        &w,
        &mut link,
        &d,
        &soft,
        "approval.approve",
        json!({"id": r.id}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
}

#[tokio::test]
async fn approval_reject_is_signed() {
    let (w, mut link, d, _) = paired_locked(APPROVER_POLICY).await;
    let r = request_of(&w, 4242, "other");
    // No touch needed; the note is kept.
    let a = send(
        &w,
        &mut link,
        &d,
        "approval.reject",
        json!({"id": r.id, "note": "not now"}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"]["state"], "rejected", "{a}");
    let s = w.ctx.approvals.as_ref().unwrap().get(r.id).unwrap();
    assert_eq!(s.state, saiife_daemon::approvals::State::Rejected);
    let rs = approval_records(&w);
    let rec = rs
        .iter()
        .rev()
        .find(|v| field(v, "action") == "rejected")
        .unwrap_or_else(|| panic!("{rs:?}"));
    assert_eq!(field(rec, "workspace")["device"], d.device_id(), "{rec}");
    assert!(field(rec, "touch").is_null(), "{rec}");
    // Decided already; unknown; bad arguments.
    for (args, rule) in [
        (json!({"id": r.id}), "invalid"),
        (json!({"id": 999}), "not_found"),
        (json!({"id": "x"}), "invalid"),
        (json!({"id": r.id, "extra": 1}), "invalid"),
        (json!({"id": r.id, "note": "x\u{1b}"}), "invalid"),
    ] {
        let a = send(&w, &mut link, &d, "approval.reject", args.clone()).await;
        assert_eq!(a["ok"], false, "{args}: {a}");
        assert_eq!(a["rule"], rule, "{args}: {a}");
    }
    // A non-approver cannot reject another user's request.
    let (w, mut link, d, _) = paired_locked("version = 2\nlocked = true\n").await;
    let r = request_of(&w, 4242, "other");
    let a = send(&w, &mut link, &d, "approval.reject", json!({"id": r.id})).await;
    assert_eq!(a["error"], "bad_request", "{a}");
    assert_eq!(a["rule"], "not_found", "{a}");
    // The requester may withdraw their own request.
    let r = request_of(&w, me(), ME);
    let a = send(&w, &mut link, &d, "approval.reject", json!({"id": r.id})).await;
    assert_eq!(a["ok"], true, "{a}");
    let s = w.ctx.approvals.as_ref().unwrap().get(r.id).unwrap();
    assert_eq!(s.state, saiife_daemon::approvals::State::Rejected);
}

#[tokio::test]
async fn later_list_matches_remote() {
    assert_eq!(LATER, ["box.push", "box.pr"]);
    for (name, lvl) in REMOTE {
        if *lvl == Level::Signed {
            assert!(
                HANDLED.contains(name) || LATER.contains(name),
                "{name} is Signed and neither handled nor LATER"
            );
        }
        if LATER.contains(name) {
            assert!(!HANDLED.contains(name), "{name}");
        }
    }
    for n in ["approval.list", "approval.reject"] {
        assert!(HANDLED.contains(&n), "{n}");
    }
}
