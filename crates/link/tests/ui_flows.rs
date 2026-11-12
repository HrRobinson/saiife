//! What the Workspace pages do, end to end: the bodies `assets/js/pairing.js`
//! sends, built in Rust with a `TestDevice`, against the localhost link and
//! an in-process daemon with `FakeBoxSource::demo`.
#![cfg(unix)]

mod common;

use common::http::{frame_for, frame_with, json_of, Server};
use common::{control, me, world, World};
use http::StatusCode;
use saiife_ipc::msg::{OP_WORKSPACE_PAIR_BEGIN, OP_WORKSPACE_PAIR_CONFIRM};
use saiife_link::Daemon;
use saiife_wire::fake::FakeCall;
use saiife_wire::sig::TestDevice;
use saiife_wire::source::{BoxId, BoxSource, SpawnReq, Start};
use saiife_wire::{b64, pair};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

/// The label the pair view starts with.
const LABEL: &str = "Browser on this machine";

async fn up() -> (World, Server) {
    let w = world().await;
    let s = Server::start(Daemon::new(w.run.clone(), me())).await;
    (w, s)
}

/// An offer begun on the machine: (fragment, pair_id, secret, machine_pub).
struct Offer {
    fragment: String,
    pair_id: String,
    secret: [u8; 32],
    machine_pub: [u8; 65],
}

async fn begin(w: &World) -> Offer {
    let b = control(w, OP_WORKSPACE_PAIR_BEGIN, json!({"label": "laptop"})).await;
    assert_eq!(b["ok"], true, "{b}");
    let fragment = b["fragment"].as_str().unwrap().to_string();
    let (pair_id, secret, _, machine_pub) = pair::parse_fragment(&fragment).unwrap();
    Offer {
        fragment,
        pair_id,
        secret,
        machine_pub,
    }
}

/// `POST /api/pair` exactly as pairing.js builds it.
fn pair_body(o: &Offer, d: &TestDevice) -> Value {
    let pubkey = d.public_raw();
    json!({
        "pair_id": o.pair_id,
        "device_pub": b64::enc(&pubkey),
        "label": LABEL,
        "proof": b64::enc(&pair::proof(&o.secret, &o.pair_id, &pubkey)),
    })
}

async fn post_pair(s: &Server, o: &Offer, d: &TestDevice) -> Value {
    let (st, _, body) = s.post("/api/pair", &pair_body(o, d)).await;
    assert_eq!(st, StatusCode::OK);
    json_of(&body)
}

async fn confirm(w: &World, o: &Offer, accept: bool) {
    let c = control(
        w,
        OP_WORKSPACE_PAIR_CONFIRM,
        json!({"pair_id": o.pair_id, "accept": accept}),
    )
    .await;
    assert_eq!(c["ok"], true, "{c}");
}

async fn frame(w: &World, s: &Server, d: &TestDevice, action: &str) -> Value {
    let sf = frame_for(w, d, action);
    let (st, _, body) = s
        .post("/api/frame", &json!({"body": sf.body, "sig": sf.sig}))
        .await;
    assert_eq!(st, StatusCode::OK);
    json_of(&body)
}

#[tokio::test]
async fn pair_then_overview() {
    let (w, s) = up().await;
    // The page checks the fragment's machine against /api/hello first.
    let (_, _, body) = s.get("/api/hello").await;
    let hello = json_of(&body);
    let o = begin(&w).await;
    let (_, _, mid, _) = pair::parse_fragment(&o.fragment).unwrap();
    assert_eq!(hello["result"]["machine_id"], mid.as_str(), "{hello}");

    let d = TestDevice::generate();
    let a = post_pair(&s, &o, &d).await;
    assert_eq!(a["ok"], true, "{a}");
    // The page compares the daemon's code with its own.
    let ours = pair::short_code(&o.machine_pub, &d.public_raw(), &o.secret);
    assert_eq!(a["result"]["short_code"], ours.as_str(), "{a}");
    assert_eq!(a["result"]["device_id"], d.device_id(), "{a}");

    confirm(&w, &o, true).await;
    let who = frame(&w, &s, &d, "workspace.whoami").await;
    assert_eq!(who["ok"], true, "{who}");
    assert_eq!(who["result"]["device_id"], d.device_id(), "{who}");
    assert_eq!(who["result"]["label"], LABEL, "{who}");
    let ov = frame(&w, &s, &d, "box.overview").await;
    assert_eq!(ov["ok"], true, "{ov}");
    assert_eq!(ov["result"]["boxes"].as_array().unwrap().len(), 4, "{ov}");
}

#[tokio::test]
async fn second_tab_cannot_reuse_the_offer() {
    let (w, s) = up().await;
    let o = begin(&w).await;
    let first = TestDevice::generate();
    assert_eq!(post_pair(&s, &o, &first).await["ok"], true);
    // A second tab with the same fragment makes its own key: refused.
    for d in [TestDevice::generate(), first] {
        let a = post_pair(&s, &o, &d).await;
        assert_eq!(a["ok"], false, "{a}");
        assert_eq!(a["rule"], "pair_expired", "{a}");
        assert!(a["message"].as_str().is_some_and(|m| !m.is_empty()), "{a}");
    }
    // And after the owner confirms, the offer is spent for good.
    confirm(&w, &o, true).await;
    let a = post_pair(&s, &o, &TestDevice::generate()).await;
    assert_eq!(a["rule"], "pair_expired", "{a}");
}

/// While the owner has not confirmed, the daemon keeps the device in the
/// offer book, not the device list (workspace.rs `finish_pair`), so its
/// frames are refused `unknown_device`, not `device_pending` (that rule is
/// for a listed Pending device, verify.rs). The pair view therefore keeps
/// polling on both rules until the offer's 5 minutes are over.
#[tokio::test]
async fn pending_device_is_refused_until_confirmed() {
    let (w, s) = up().await;
    let o = begin(&w).await;
    let d = TestDevice::generate();
    assert_eq!(post_pair(&s, &o, &d).await["ok"], true);
    // What the pair view polls while the owner has not confirmed.
    for action in ["workspace.whoami", "box.overview"] {
        let a = frame(&w, &s, &d, action).await;
        assert_eq!(a["ok"], false, "{a}");
        assert_eq!(a["rule"], "unknown_device", "{action}: {a}");
        assert!(a["message"].is_string(), "{a}");
    }
    // A rejected browser looks the same; the view stops at the deadline.
    confirm(&w, &o, false).await;
    let a = frame(&w, &s, &d, "workspace.whoami").await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "unknown_device", "{a}");
    // After an accept the same key is in.
    let o2 = begin(&w).await;
    assert_eq!(post_pair(&s, &o2, &d).await["ok"], true);
    confirm(&w, &o2, true).await;
    assert_eq!(frame(&w, &s, &d, "workspace.whoami").await["ok"], true);
}

#[tokio::test]
async fn hostile_label_is_refused() {
    let (w, s) = up().await;
    let o = begin(&w).await;
    let d = TestDevice::generate();
    let mut b = pair_body(&o, &d);
    b["label"] = "a\u{202e}b".into();
    let (_, _, body) = s.post("/api/pair", &b).await;
    let a = json_of(&body);
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "bad_frame", "{a}");
    // The offer survives a refused label.
    assert_eq!(post_pair(&s, &o, &d).await["ok"], true);
}

/// pairing.js itself, under node, against the real link: its proof
/// verifies and its short code is the daemon's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_pairs_with_the_real_link() {
    if Command::new("node").arg("--version").output().is_err() {
        println!("skipped: no node");
        return;
    }
    let (w, s) = up().await;
    let o = begin(&w).await;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/tests/pair-once.mjs");
    let base = s.origin();
    let hash = format!("#pair={}", o.fragment);
    let home = common::scratch();
    let hp = home.path().to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        Command::new("node")
            .arg(&script)
            .arg(&base)
            .arg(&hash)
            .env("HOME", &hp)
            .env("XDG_CONFIG_HOME", &hp)
            .env("XDG_DATA_HOME", &hp)
            .env("XDG_CACHE_HOME", &hp)
            .env("XDG_RUNTIME_DIR", &hp)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/nonexistent/p30-t3-bus",
            )
            .current_dir(&hp)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["replaced"], "/", "{v}");
    assert_eq!(
        v["saved"], false,
        "nothing is saved before the confirm: {v}"
    );
    let device_pub = b64::dec_n::<65>(v["devicePub"].as_str().unwrap()).unwrap();
    assert_eq!(
        v["shortCode"],
        pair::short_code(&o.machine_pub, &device_pub, &o.secret).as_str(),
        "{v}"
    );
    assert_eq!(
        v["deviceId"],
        saiife_wire::sig::device_id_of(&device_pub).as_str(),
        "{v}"
    );
    confirm(&w, &o, true).await;
    let dev = w
        .ctx
        .workspace
        .device(v["deviceId"].as_str().unwrap())
        .unwrap();
    assert_eq!(dev.label, LABEL);
}

/// A paired, confirmed device (the pair view's steps, then the owner's).
async fn paired(w: &World, s: &Server) -> TestDevice {
    let o = begin(w).await;
    let d = TestDevice::generate();
    assert_eq!(post_pair(s, &o, &d).await["ok"], true);
    confirm(w, &o, true).await;
    d
}

/// `POST /api/frame` with the args a view builds from `ACTIONS`.
async fn act(w: &World, s: &Server, d: &TestDevice, action: &str, args: Value) -> Value {
    let sf = frame_with(w, d, action, common::args(args));
    let (st, _, body) = s
        .post("/api/frame", &json!({"body": sf.body, "sig": sf.sig}))
        .await;
    assert_eq!(st, StatusCode::OK);
    json_of(&body)
}

fn bid(s: &str) -> BoxId {
    BoxId::parse(s).unwrap()
}

/// The `workspace` audit records so far, oldest first.
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
    walk(&w._tmp.path().join("audit"), &mut out);
    out
}

/// The record's extra fields may sit at the top level or under `extra`.
fn field<'a>(r: &'a Value, k: &str) -> &'a Value {
    match &r[k] {
        Value::Null => &r["extra"][k],
        v => v,
    }
}

#[tokio::test]
async fn overview_lists_demo_boxes() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let a = act(&w, &s, &d, "box.overview", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    let r = &a["result"];
    let states: Vec<_> = r["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| (b["id"].as_str().unwrap(), b["state"].as_str().unwrap()))
        .collect();
    assert_eq!(
        states,
        vec![
            ("b-run", "running"),
            ("b-done", "done"),
            ("b-q1", "queued"),
            ("b-q2", "queued")
        ],
        "{a}"
    );
    // The fields the cards and the header line read.
    assert_eq!(r["load"]["cpu_pct"], 37, "{a}");
    assert!(r["slots_free"].is_u64() && r["slots_total"].is_u64(), "{a}");
    let b = &r["boxes"][0];
    for k in ["template", "repo", "task", "started_at", "queue_pos"] {
        assert!(b.get(k).is_some(), "{k} in {b}");
    }
}

#[tokio::test]
async fn overview_with_200_boxes() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    for n in 0..196 {
        w.boxes
            .spawn(&SpawnReq {
                template: "claude".into(),
                repo: "erp".into(),
                task: format!("task number {n}"),
                start: Start::Queue,
            })
            .unwrap();
    }
    let sf = frame_with(&w, &d, "box.overview", common::args(json!({})));
    let t = std::time::Instant::now();
    let (st, _, body) = s
        .post("/api/frame", &json!({"body": sf.body, "sig": sf.sig}))
        .await;
    let took = t.elapsed();
    assert_eq!(st, StatusCode::OK);
    let a = json_of(&body);
    assert_eq!(
        a["result"]["boxes"].as_array().unwrap().len(),
        200,
        "{took:?}"
    );
    assert!(took < std::time::Duration::from_secs(1), "{took:?}");
    assert!(body.len() < 1_000_000, "{} bytes", body.len());
}

#[tokio::test]
async fn stop_and_pause_run() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let before = records(&w).len();
    let a = act(&w, &s, &d, "box.pause", json!({"id": "b-run"})).await;
    assert_eq!(a["ok"], true, "{a}");
    let a = act(&w, &s, &d, "box.stop", json!({"id": "b-run"})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(
        w.boxes.calls(),
        vec![FakeCall::Pause(bid("b-run")), FakeCall::Stop(bid("b-run"))]
    );
    let r = records(&w);
    assert_eq!(r.len(), before + 2, "{r:?}");
    for (rec, action) in r[before..].iter().zip(["box.pause", "box.stop"]) {
        assert_eq!(field(rec, "action"), action, "{rec}");
        assert_eq!(field(rec, "device"), d.device_id().as_str(), "{rec}");
        assert_eq!(field(rec, "box"), "b-run", "{rec}");
    }
}

#[tokio::test]
async fn reorder_sends_full_order() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    // The "↑" on b-q2 sends the whole queue with b-q2 first.
    let a = act(&w, &s, &d, "box.reorder", json!({"ids": ["b-q2", "b-q1"]})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(
        w.boxes.calls(),
        vec![FakeCall::Reorder(vec![bid("b-q2"), bid("b-q1")])]
    );
    let a = act(&w, &s, &d, "box.overview", json!({})).await;
    let ids: Vec<_> = a["result"]["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["state"] == "queued")
        .map(|b| b["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["b-q2", "b-q1"], "{a}");
    // A partial order is refused by the daemon, not guessed at.
    let a = act(&w, &s, &d, "box.reorder", json!({"ids": ["b-q1"]})).await;
    assert_eq!(a["ok"], false, "{a}");
    assert!(a["message"].is_string(), "{a}");
}

#[tokio::test]
async fn steer_is_refused_touch_required() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    for (action, args) in [
        (
            "box.steer",
            json!({"id": "b-run", "msg": "use the new API"}),
        ),
        ("box.resume", json!({"id": "b-run"})),
    ] {
        let a = act(&w, &s, &d, action, args).await;
        assert_eq!(a["ok"], false, "{a}");
        assert_eq!(a["rule"], "touch_required", "{a}");
        assert!(a["message"].as_str().is_some_and(|m| !m.is_empty()), "{a}");
    }
    // Nothing reached the box.
    assert_eq!(w.boxes.calls(), vec![]);
}

#[tokio::test]
async fn lockdown_on_from_ui() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    assert!(w.ctx.lockdown.get().is_none());
    let a = act(&w, &s, &d, "lockdown.on", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(w.ctx.lockdown.get().is_some(), "{a}");
    let rec = records(&w)
        .into_iter()
        .rev()
        .find(|r| field(r, "action") == "lockdown.on")
        .expect("lockdown.on recorded");
    assert_eq!(field(&rec, "device"), d.device_id().as_str(), "{rec}");
}

/// The Review screen's `box.diff {id}` for the demo's done box: the hostile
/// names arrive byte for byte (the page escapes them, not the daemon), and
/// the 2.5 MB diff is cut to one 2 MB answer with `truncated`.
#[tokio::test]
async fn diff_of_done_box() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let sf = frame_with(&w, &d, "box.diff", common::args(json!({"id": "b-done"})));
    let (st, _, body) = s
        .post("/api/frame", &json!({"body": sf.body, "sig": sf.sig}))
        .await;
    assert_eq!(st, StatusCode::OK);
    let needle = b"<img src=x onerror=alert(1)>.md";
    assert!(
        body.windows(needle.len()).any(|x| x == needle),
        "the hostile name is in the answer as is"
    );
    let a = json_of(&body);
    assert_eq!(a["ok"], true, "{}", a["error"]);
    let r = &a["result"];
    assert_eq!(r["id"], "b-done");
    assert_eq!(r["truncated"], true);
    let unified = r["unified"].as_str().unwrap();
    assert!(unified.len() <= saiife_wire::source::MAX_DIFF_BYTES);
    assert!(unified.ends_with('\n'));
    assert!(unified.contains("+\u{1b}]52;c;ZXZpbA==\u{7} a clipboard attempt\n"));
    let sha = r["diff_sha256"].as_str().unwrap();
    assert!(
        sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "{sha}"
    );
    assert_eq!(r["base_commit"].as_str().unwrap().len(), 40);
    let paths: Vec<_> = r["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        vec![
            "../../.ssh/authorized_keys",
            "<img src=x onerror=alert(1)>.md",
            "logo.png",
            "src/big.rs"
        ]
    );
    assert_eq!(r["files"][2]["binary"], true);
    assert_eq!(r["files"][0]["added"], 1);
    assert_eq!(r["files"][0]["removed"], 0);
    assert_eq!(r["tests"]["passed"], 41);
    assert_eq!(r["tests"]["failed"], 0);
    assert_eq!(r["tests"]["skipped"], 2);
    assert_eq!(r["tests"]["summary"], "41 passed, 2 skipped");
    // Reading the diff changes nothing.
    assert_eq!(w.boxes.calls(), vec![]);
}

/// "Approve with touch" sends `box.land {id, diff_sha256}`; until plan 31
/// the daemon refuses it `touch_required` and the box stays done.
#[tokio::test]
async fn land_is_refused_touch_required() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let diff = act(&w, &s, &d, "box.diff", json!({"id": "b-done"})).await;
    let sha = diff["result"]["diff_sha256"].as_str().unwrap().to_string();
    let a = act(
        &w,
        &s,
        &d,
        "box.land",
        json!({"id": "b-done", "diff_sha256": sha}),
    )
    .await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "touch_required", "{a}");
    assert!(a["message"].as_str().is_some_and(|m| !m.is_empty()), "{a}");
    assert_eq!(w.boxes.calls(), vec![]);
    let ov = act(&w, &s, &d, "box.overview", json!({})).await;
    let done = ov["result"]["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["id"] == "b-done")
        .cloned()
        .unwrap();
    assert_eq!(done["state"], "done", "{ov}");
}

/// "Reject" (after the confirm) sends `box.discard {id}`.
#[tokio::test]
async fn reject_discards() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let a = act(&w, &s, &d, "box.discard", json!({"id": "b-done"})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(w.boxes.calls(), vec![FakeCall::Discard(bid("b-done"))]);
    let rec = records(&w)
        .into_iter()
        .rev()
        .find(|r| field(r, "action") == "box.discard")
        .expect("box.discard recorded");
    assert_eq!(field(&rec, "box"), "b-done", "{rec}");
    assert_eq!(field(&rec, "device"), d.device_id().as_str(), "{rec}");
}

/// "Revise" sends `box.revise {id, comment}`: touch level, refused for now.
#[tokio::test]
async fn revise_is_refused_touch_required() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let a = act(
        &w,
        &s,
        &d,
        "box.revise",
        json!({"id": "b-done", "comment": "rename the helper"}),
    )
    .await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "touch_required", "{a}");
    assert!(a["message"].as_str().is_some_and(|m| !m.is_empty()), "{a}");
    assert_eq!(w.boxes.calls(), vec![]);
}

/// `#/box/<id>` loads the Review screen, which builds on the diff renderer;
/// both are served, and the frames above are the ones it sends.
#[tokio::test]
async fn review_screen_is_served() {
    let (_w, s) = up().await;
    let (st, _, app) = s.get("/js/app.js").await;
    assert_eq!(st, StatusCode::OK);
    let app = String::from_utf8(app.to_vec()).unwrap();
    assert!(
        app.contains("import { render as review } from \"./views/review.js\";"),
        "app.js routes #/box/<id> to the Review screen"
    );
    let (st, _, view) = s.get("/js/views/review.js").await;
    assert_eq!(st, StatusCode::OK);
    let view = String::from_utf8(view.to_vec()).unwrap();
    for sent in [
        "ACTIONS.diff, { id }",
        "ACTIONS.land, { id, diff_sha256: ",
        "ACTIONS.discard, { id }",
        "ACTIONS.revise, { id, comment }",
    ] {
        assert!(view.contains(sent), "review.js sends {sent}");
    }
    let (st, _, _) = s.get("/js/diff.js").await;
    assert_eq!(st, StatusCode::OK);
}

/// The Approve inbox lists what the daemon holds; the code is the one the
/// touch challenge yields (plan 26).
#[tokio::test]
async fn inbox_lists_demo_land() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let a = act(&w, &s, &d, "box.inbox", json!({})).await;
    assert_eq!(a["ok"], true, "{a}");
    let items = a["result"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{a}");
    let it = &items[0];
    assert_eq!(it["class"], "land", "{a}");
    assert!(it["box_id"].is_string() && it["expires_at"].is_u64(), "{a}");
    let ch: [u8; 32] = b64_hex(it["challenge_hex"].as_str().unwrap());
    assert_eq!(
        it["short_code"].as_str().unwrap(),
        saiife_touch::short_code(&ch),
        "{a}"
    );
    assert_eq!(it["short_code"].as_str().unwrap().len(), 6, "{a}");
}

fn b64_hex(h: &str) -> [u8; 32] {
    assert_eq!(h.len(), 64, "{h}");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[tokio::test]
async fn spawn_plain_template_queues() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let t = act(&w, &s, &d, "box.templates", json!({})).await;
    assert_eq!(t["result"].as_array().unwrap().len(), 2, "{t}");
    let args = json!({"template": "claude", "repo": "saiife", "task": "fix the flaky test", "start": "queue"});
    let a = act(&w, &s, &d, "box.spawn", args).await;
    assert_eq!(a["ok"], true, "{a}");
    assert!(a["result"]["id"].is_string(), "{a}");
    assert_eq!(
        w.boxes.calls(),
        vec![FakeCall::Spawn(SpawnReq {
            template: "claude".into(),
            repo: "saiife".into(),
            task: "fix the flaky test".into(),
            start: Start::Queue,
        })]
    );
}

#[tokio::test]
async fn spawn_secret_template_needs_touch() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let args =
        json!({"template": "claude-gh", "repo": "saiife", "task": "open a PR", "start": "now"});
    let a = act(&w, &s, &d, "box.spawn", args).await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "touch_required", "{a}");
    assert_eq!(w.boxes.calls(), vec![]);
}

#[tokio::test]
async fn spawn_task_with_escape_is_refused() {
    let (w, s) = up().await;
    let d = paired(&w, &s).await;
    let args =
        json!({"template": "claude", "repo": "saiife", "task": "hi \u{1b}[2J", "start": "queue"});
    let a = act(&w, &s, &d, "box.spawn", args).await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "invalid", "{a}");
    assert!(a["message"].as_str().is_some_and(|m| !m.is_empty()), "{a}");
}

/// §9.6: no row is a link that approves. inbox.js builds one `href`, to the
/// box page, and calls nothing but `box.inbox`.
#[tokio::test]
async fn inbox_has_no_approve_url() {
    let (_w, s) = up().await;
    let (st, _, v) = s.get("/js/views/inbox.js").await;
    assert_eq!(st, StatusCode::OK);
    let v = String::from_utf8(v.to_vec()).unwrap();
    let hrefs: Vec<_> = v.match_indices("href").collect();
    assert_eq!(hrefs.len(), 1, "one href in inbox.js");
    assert!(
        v.contains("href: `#/box/${boxId}`"),
        "the one href is the box page"
    );
    assert!(!v.contains("request_id"), "no href built from a request id");
    assert!(
        !v.contains("ACTIONS.land") && !v.contains("box.land\""),
        "no land call"
    );
    assert!(
        v.contains("ACTIONS.inbox") && v.contains("show("),
        "reads, then the prompt"
    );
    assert_eq!(
        v.matches("client.send(").count(),
        1,
        "the only send is the inbox read"
    );
    let (st, _, app) = s.get("/js/app.js").await;
    assert_eq!(st, StatusCode::OK);
    let app = String::from_utf8(app.to_vec()).unwrap();
    assert!(app.contains("import { render as inbox } from \"./views/inbox.js\";"));
    assert!(app.contains("import { render as spawn } from \"./views/spawn.js\";"));
    let (_, _, sp) = s.get("/js/views/spawn.js").await;
    let sp = String::from_utf8(sp.to_vec()).unwrap();
    assert!(sp.contains("ACTIONS.spawn") && sp.contains("ACTIONS.templates"));
}
