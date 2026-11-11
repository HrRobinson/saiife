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
    OP_WORKSPACE_PAIR_FINISH, OP_WORKSPACE_REVOKE, OP_WORKSPACE_SIGN, PROTO,
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
        ctx,
        boxes,
        users,
        run,
        audit,
        state,
        _tmp: tmp,
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
    let now = now_secs();
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
        json!({"device_id": d.device_id(), "label": "phone", "owner_user": ME})
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
    for action in [
        "box.land",
        "box.push",
        "box.pr",
        "approval.approve",
        "box.steer",
    ] {
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
}

#[tokio::test]
async fn touch_action_with_a_touch_proof_is_still_refused() {
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
    assert_eq!(a["rule"], "touch_required", "{a}");
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

#[tokio::test]
async fn sign_needs_an_active_device() {
    let w = world().await;
    let mut link = Link::open(&w).await;
    let mut hh = vec![1u8; 32];
    hh.extend_from_slice(w.ctx.workspace.machine_id().as_bytes());
    let a = sign(
        &mut link,
        json!({"purpose": "hub_hello", "data": b64::enc(&hh)}),
    )
    .await;
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "no_active_device", "{a}");
    let d = pair_device(&w, &mut link).await;
    let a = sign(
        &mut link,
        json!({"purpose": "hub_hello", "data": b64::enc(&hh)}),
    )
    .await;
    assert_eq!(a["ok"], true, "{a}");
    let sig = b64::dec_n::<64>(a["sig"].as_str().unwrap()).unwrap();
    assert!(saiife_wire::sig::verify_p256_domain(
        &machine_pub(&w),
        saiife_daemon::workspace::HUB_HELLO_DOMAIN,
        &hh,
        &sig
    ));
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
    // Revoked: no Active device left.
    control(&w, OP_WORKSPACE_REVOKE, json!({"device_id": d.device_id()})).await;
    let a = sign(
        &mut link,
        json!({"purpose": "hub_hello", "data": b64::enc(&hh)}),
    )
    .await;
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
