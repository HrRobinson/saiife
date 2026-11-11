//! What the Workspace pages do, end to end: the bodies `assets/js/pairing.js`
//! sends, built in Rust with a `TestDevice`, against the localhost link and
//! an in-process daemon with `FakeBoxSource::demo`.
#![cfg(unix)]

mod common;

use common::http::{frame_for, json_of, Server};
use common::{control, me, world, World};
use http::StatusCode;
use saiife_ipc::msg::{OP_WORKSPACE_PAIR_BEGIN, OP_WORKSPACE_PAIR_CONFIRM};
use saiife_link::Daemon;
use saiife_wire::sig::TestDevice;
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
