//! `saiife touch enrol | ls | rm | test` end to end (plan 27, Task 2),
//! against the in-process daemon world of tests/approvals_cmd.rs. The own
//! user is made an approver (who may manage touch devices). The key is the
//! soft key seam (`SAIIFE_TEST_TOUCH_SOFT`, debug builds only): a key file,
//! or a `{"chain": [...]}` of key files that answer one touch each.
// Debug builds only: the CLI honours SAIIFE_TEST_TOUCH_SOFT only there.
#![cfg(all(unix, debug_assertions))]
#![allow(dead_code)]

#[path = "common/approvals_world.rs"]
mod approvals_world;
mod common;

use approvals_world::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use common::daemon::{own_group, own_user};
use saiife_daemon::approvals::State;
use saiife_daemon::ops::{dispatch_conn, hello_in, Conn};
use saiife_ipc::frame::{read_frame, write_frame};
use saiife_ipc::msg::{err, ErrorCode, Request, OP_HELLO};
use saiife_touch::soft::SoftAuthenticator;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

/// The world, with the own user an approver (and, with `admin`, in
/// `[admin] groups`).
fn touch_world(admin: bool) -> World {
    let w = world();
    let mut text = config_text(w.path(), w.m.port, "").replace(
        "approvers = [\"boss\"]",
        &format!("approvers = [\"boss\", {:?}]", own_user()),
    );
    if admin {
        text = text.replace(
            "[approval]",
            &format!("[admin]\ngroups = [{:?}]\n\n[approval]", own_group()),
        );
    }
    *w.ctx.policy.lock().unwrap() = policy_of(w.path(), w.m.port, &text);
    w
}

/// A new soft key file at `p` (the seam's format); `uv: false` when `uv`
/// is not set.
fn soft_key(p: &Path, uv: bool) -> PathBuf {
    let (_, pkcs8, id, counter) = SoftAuthenticator::new_es256().parts();
    let mut f = json!({
        "alg": "es256",
        "pkcs8": URL_SAFE_NO_PAD.encode(pkcs8),
        "credential_id": URL_SAFE_NO_PAD.encode(id),
        "counter": counter,
    });
    if !uv {
        f["uv"] = false.into();
    }
    fs::write(p, f.to_string()).unwrap();
    p.to_path_buf()
}

/// `saiife touch --system-config ... <args>` with the soft key `key`.
fn touch_cmd(w: &World, key: &Path, args: &[&str]) -> Command {
    let mut c = w.cli_cmd("touch", args);
    c.env("SAIIFE_TEST_TOUCH_SOFT", key);
    c
}

fn touch(w: &World, key: &Path, args: &[&str]) -> Output {
    touch_cmd(w, key, args).output().unwrap()
}

fn text(o: &Output) -> String {
    stdout(o) + &stderr(o)
}

fn code(o: &Output) -> Option<i32> {
    o.status.code()
}

/// `touch ls --json`: the devices.
fn listed(w: &World, key: &Path) -> Vec<Value> {
    let o = touch(w, key, &["ls", "--json"]);
    ok(&o);
    json_out(&o).as_array().cloned().expect("an array")
}

fn enrol(w: &World, key: &Path, label: &str) -> Output {
    touch(w, key, &["enrol", "--label", label])
}

#[test]
fn enrol_ls_test_rm() {
    let w = touch_world(false);
    let key = soft_key(&w.path().join("soft.json"), true);

    let o = enrol(&w, &key, "key1");
    ok(&o);
    let t = text(&o);
    assert!(stdout(&o).contains("enrolled \"key1\" ("), "{t}");
    assert!(
        stderr(&o).contains("saiife: enrolling \"key1\": touch the new key twice"),
        "{t}"
    );
    assert!(
        stderr(&o).contains(
            "saiife: add a second device (spec §8.4): a lost key leaves only root to remove it"
        ),
        "{t}"
    );

    let items = listed(&w, &key);
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0]["label"], "key1");
    assert_eq!(items[0]["kind"], "fido2");
    let id = items[0]["id"].as_str().unwrap().to_string();
    assert!(
        stdout(&o).contains(&format!("enrolled \"key1\" ({})", &id[..8])),
        "{id}: {}",
        text(&o)
    );

    // The text table.
    let o = touch(&w, &key, &["ls"]);
    ok(&o);
    let lines: Vec<String> = stdout(&o).lines().map(String::from).collect();
    let head: Vec<&str> = lines[0].split_whitespace().collect();
    assert_eq!(head, ["ID", "LABEL", "KIND", "ALG", "ADDED", "COUNT"]);
    let row: Vec<&str> = lines[1].split_whitespace().collect();
    assert_eq!(row[0], &id[..12]);
    assert_eq!(&row[1..4], ["key1", "fido2", "es256"]);
    assert_eq!(row[4].len(), 10, "{row:?}");

    let o = touch(&w, &key, &["test"]);
    ok(&o);
    assert!(
        stdout(&o).contains("ok: \"key1\" answered (user verified: yes, counter"),
        "{}",
        text(&o)
    );

    let o = touch(&w, &key, &["rm", &id[..8]]);
    ok(&o);
    assert!(stdout(&o).contains("removed \"key1\""), "{}", text(&o));

    let o = touch(&w, &key, &["ls"]);
    ok(&o);
    assert!(
        stdout(&o).contains("no touch devices enrolled; saiife touch enrol --label <name>"),
        "{}",
        text(&o)
    );
}

#[test]
fn second_device_needs_the_first() {
    let w = touch_world(false);
    let a = soft_key(&w.path().join("a.json"), true);
    let b = soft_key(&w.path().join("b.json"), true);
    ok(&enrol(&w, &a, "key1"));

    // B alone: its approval cannot name an enrolled device. The key
    // refuses before anything is sent (as a real key does: the request
    // allows only the enrolled devices).
    let o = enrol(&w, &b, "key2");
    assert_eq!(code(&o), Some(2), "{}", text(&o));
    assert!(
        stderr(&o).contains("then one of your enrolled keys"),
        "{}",
        text(&o)
    );
    assert!(
        stderr(&o).contains("saiife: touch: this device is not enrolled for you"),
        "{}",
        text(&o)
    );
    assert_eq!(listed(&w, &a).len(), 1);

    // B for the enrolment and its proof, then A for the approval.
    let chain = w.path().join("chain.json");
    fs::write(&chain, json!({"chain": [b, b, a]}).to_string()).unwrap();
    let o = enrol(&w, &chain, "key2");
    ok(&o);
    assert!(stdout(&o).contains("enrolled \"key2\""), "{}", text(&o));
    assert!(
        stderr(&o).contains("unplug the new key and plug in an enrolled one, then press Enter"),
        "{}",
        text(&o)
    );
    assert!(!stderr(&o).contains("add a second device"), "{}", text(&o));
    let labels: Vec<Value> = listed(&w, &a).iter().map(|i| i["label"].clone()).collect();
    assert_eq!(labels, ["key1", "key2"]);
}

#[test]
fn enrol_without_uv_is_refused() {
    let w = touch_world(false);
    let key = soft_key(&w.path().join("soft.json"), false);
    let o = enrol(&w, &key, "key1");
    assert_eq!(code(&o), Some(2), "{}", text(&o));
    assert!(
        stderr(&o).contains("refused (touch_failed)"),
        "{}",
        text(&o)
    );
    assert!(stderr(&o).contains("user verification"), "{}", text(&o));
    assert!(listed(&w, &key).is_empty());
}

#[test]
fn rm_unknown_prefix() {
    let w = touch_world(false);
    let key = soft_key(&w.path().join("soft.json"), true);
    ok(&enrol(&w, &key, "key1"));
    let o = touch(&w, &key, &["rm", "________"]);
    assert_eq!(code(&o), Some(2), "{}", text(&o));
    assert!(
        stderr(&o).contains("no enrolled device starts with \"________\""),
        "{}",
        text(&o)
    );
    // Too short a prefix.
    let o = touch(&w, &key, &["rm", "abc"]);
    assert_eq!(code(&o), Some(2), "{}", text(&o));
    assert!(stderr(&o).contains("at least 8 characters"), "{}", text(&o));
    assert_eq!(listed(&w, &key).len(), 1);
}

#[test]
fn rm_host_needs_root() {
    // An admin (who may list every device) but not root.
    let w = touch_world(true);
    let key = soft_key(&w.path().join("soft.json"), true);
    ok(&enrol(&w, &key, "key1"));
    let id = listed(&w, &key)[0]["id"].as_str().unwrap().to_string();
    let o = touch(&w, &key, &["rm", &id[..8], "--host"]);
    assert_eq!(code(&o), Some(2), "{}", text(&o));
    assert!(
        stderr(&o).contains("only root can remove a touch device without its touch"),
        "{}",
        text(&o)
    );
    assert_eq!(listed(&w, &key).len(), 1);
}

/// Review Focus 4: a daemon that predates plan 26. The world's control
/// socket is replaced by one whose dispatch answers `unknown_op` to every
/// `touch.*` op and hands the rest to the real `dispatch_conn`.
#[test]
fn old_daemon_is_named() {
    let w = touch_world(false);
    let key = soft_key(&w.path().join("soft.json"), true);
    let sock = w.path().join("run/saiife.sock");
    fs::remove_file(&sock).unwrap();
    let listener = UnixListener::bind(&sock).unwrap();
    let (ctx, rt) = (Arc::clone(&w.ctx), w.rt.handle().clone());
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let Ok(peer) = saiife_ipc::peer::peer_cred(&s) else {
                continue;
            };
            let conn = Conn::new(peer, None);
            while let Ok(frame) = read_frame(&mut s) {
                let Ok(req) = Request::from_map(frame) else {
                    break;
                };
                let answer = if req.op == OP_HELLO {
                    hello_in(req.id, "locked")
                } else if req.op.starts_with("touch.") {
                    err(
                        req.id,
                        ErrorCode::UnknownOp,
                        &format!("unknown op {:?}", req.op),
                    )
                } else {
                    rt.block_on(dispatch_conn(&ctx, &conn, req))
                };
                if write_frame(&mut s, &answer).is_err() {
                    break;
                }
            }
        }
    });
    let o = touch(&w, &key, &["ls"]);
    assert_eq!(code(&o), Some(5), "{}", text(&o));
    assert!(
        stderr(&o).contains("saiife: this saiife daemon has no touch support; update it"),
        "{}",
        text(&o)
    );
    assert!(!text(&o).contains("unknown_op"), "{}", text(&o));
    assert!(!text(&o).contains("unknown op"), "{}", text(&o));
}

#[test]
fn audit_has_the_enrol_record() {
    let w = touch_world(false);
    let key = soft_key(&w.path().join("soft.json"), true);
    ok(&enrol(&w, &key, "key1"));
    let recs: Vec<Value> = w
        .records()
        .into_iter()
        .filter(|r| r["action"] == "touch_enrolled")
        .collect();
    assert_eq!(recs.len(), 1, "{:?}", w.records());
    assert_eq!(recs[0]["kind"], "touch");
    assert_eq!(recs[0]["label"], "key1");
    assert_eq!(recs[0]["cred_kind"], "fido2");
    assert_eq!(recs[0]["approved_by"], "host");

    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sb = common::hermetic_audit(&mut c, &w.path().join("audit"), ["verify"]);
    let o = c.output().unwrap();
    assert_eq!(code(&o), Some(0), "{}", text(&o));
}

// ------------------------------------------------- approve with a touch

/// The erp `invoices:write` capability (what `World::ask` asks for) is a
/// deploy: a touch with its PIN (plan 26 D4).
const DEPLOY: &str = "deploy = [\"invoices:write\"]";

/// A world whose `invoices.create` needs a touch, the own user an approver
/// who re-authenticates for its own requests (the fake says yes), with the
/// soft key `soft.json` enrolled. The key file and its credential id.
fn marked_world() -> (World, PathBuf, String) {
    let w = world_with(DEPLOY);
    w.serial
        .get_or_init(|| REAUTH_SERIAL.lock().unwrap_or_else(|p| p.into_inner()));
    w.reauth
        .allow
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let text = config_text(w.path(), w.m.port, DEPLOY).replace(
        "approvers = [\"boss\"]",
        &format!(
            "approvers = [\"boss\", {:?}]\nsame_user = \"reauth\"",
            own_user()
        ),
    );
    *w.ctx.policy.lock().unwrap() = policy_of(w.path(), w.m.port, &text);
    let key = soft_key(&w.path().join("soft.json"), true);
    ok(&enrol(&w, &key, "key1"));
    let id = listed(&w, &key)[0]["id"].as_str().unwrap().to_string();
    (w, key, id)
}

/// `saiife approve <id>` with the soft key seam set to `key`.
fn approve(w: &World, key: &Path, id: u64) -> Output {
    let mut c = w.cli_cmd("approve", &[&id.to_string()]);
    c.env("SAIIFE_TEST_TOUCH_SOFT", key);
    c.output().unwrap()
}

/// No `approval`/`refused` record for `id`: nothing was decided.
fn no_refusal(w: &World, id: u64) {
    let refused: Vec<Value> = w
        .approval_records(id)
        .into_iter()
        .filter(|r| r["action"] == "refused")
        .collect();
    assert!(refused.is_empty(), "{refused:?}");
}

#[test]
fn approve_with_touch_round_trip() {
    let (w, key, cred) = marked_world();
    let id = w.ask(BODY_A);
    let o = approve(&w, &key, id);
    ok(&o);
    let e = stderr(&o);
    let approving = format!("saiife: approving request #{id}: connector erp invoices.create");
    let at = e.find(&approving).unwrap_or_else(|| panic!("{e}"));
    let lead = "saiife: touch needed (deploy); code ";
    let t = e.find(lead).unwrap_or_else(|| panic!("{e}"));
    assert!(at < t, "the request is shown before the touch: {e}");
    let rest = &e[t + lead.len()..];
    let code: String = rest.chars().take(6).collect();
    assert!(code.chars().all(|c| c.is_ascii_digit()), "{e}");
    assert!(
        rest[6..].starts_with("; check that the same code shows wherever you started this\n"),
        "{e}"
    );
    assert!(
        stdout(&o).contains(&format!("request #{id} approved")),
        "{}",
        text(&o)
    );
    // D6: the same-user re-authentication ran too, after the touch.
    assert!(!w.reauth.details.lock().unwrap().is_empty(), "{}", text(&o));
    let rec = w.wait_record(id, "approved");
    assert_eq!(rec["touch"]["cred_id"], cred.as_str(), "{rec}");
    assert_eq!(rec["touch"]["uv"], true, "{rec}");
    w.wait_state(id, State::Sent);
    assert_eq!(w.m.hits().len(), 1);
}

#[test]
fn show_prints_the_touch_line() {
    let (w, _key, _) = marked_world();
    let id = w.ask(BODY_A);
    let o = w.cli("approvals", &["show", &id.to_string()]);
    ok(&o);
    let out = stdout(&o);
    assert!(
        out.lines()
            .any(|l| l == "  touch:     deploy (your enrolled key, and its PIN)"),
        "{out}"
    );
    // An unmarked request has no touch line.
    let w = world();
    let id = w.ask(BODY_A);
    let o = w.cli("approvals", &["show", &id.to_string()]);
    ok(&o);
    assert!(!stdout(&o).contains("touch:"), "{}", stdout(&o));
}

/// Review Focus 2. The request allows only the approver's own devices, so
/// a key that is not enrolled refuses it itself (as a real key does: no
/// credential): exit 2, nothing sent to `approval.decide`.
#[test]
fn unenrolled_key_is_refused_before_decide() {
    let (w, _key, _) = marked_world();
    let other = soft_key(&w.path().join("other.json"), true);
    let id = w.ask(BODY_A);
    let o = approve(&w, &other, id);
    assert_eq!(code(&o), Some(2), "{}", text(&o));
    assert!(
        stderr(&o).contains("saiife: touch: this device is not enrolled for you"),
        "{}",
        text(&o)
    );
    assert_eq!(w.state(id), Some(State::Pending));
    no_refusal(&w, id);
    assert!(w.reauth.details.lock().unwrap().is_empty());
    assert!(w.m.hits().is_empty());
}

/// Review Focus 1: no key, exit 5; nothing decided and no password prompt
/// offered instead.
#[test]
fn unavailable_key_leaves_the_request_pending() {
    let (w, _key, _) = marked_world();
    let id = w.ask(BODY_A);
    let o = approve(&w, &w.path().join("missing.json"), id);
    assert_eq!(code(&o), Some(5), "{}", text(&o));
    assert!(
        stderr(&o).contains("cannot read the soft key"),
        "{}",
        text(&o)
    );
    assert_eq!(w.state(id), Some(State::Pending));
    no_refusal(&w, id);
    assert!(w.reauth.details.lock().unwrap().is_empty());
    assert!(w.m.hits().is_empty());
}

#[test]
fn slow_soft_key_times_out() {
    let (w, key, _) = marked_world();
    let mut f: Value = serde_json::from_slice(&fs::read(&key).unwrap()).unwrap();
    f["delay_ms"] = 3000.into();
    fs::write(&key, f.to_string()).unwrap();
    let id = w.ask(BODY_A);
    let mut c = w.cli_cmd("approve", &[&id.to_string()]);
    c.env("SAIIFE_TEST_TOUCH_SOFT", &key)
        .env("SAIIFE_TEST_TOUCH_TIMEOUT_MS", "200");
    let t = std::time::Instant::now();
    let o = c.output().unwrap();
    assert_eq!(code(&o), Some(5), "{}", text(&o));
    assert!(stderr(&o).contains("no touch within"), "{}", text(&o));
    assert!(
        t.elapsed() < std::time::Duration::from_secs(3),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(w.state(id), Some(State::Pending));
    no_refusal(&w, id);
    assert!(w.reauth.details.lock().unwrap().is_empty());
}

#[test]
fn reject_needs_no_touch() {
    let (w, _key, _) = marked_world();
    let id = w.ask(BODY_A);
    let o = w.cli("reject", &[&id.to_string()]);
    ok(&o);
    assert!(
        stdout(&o).contains(&format!("request #{id} rejected")),
        "{}",
        text(&o)
    );
    assert!(!stderr(&o).contains("touch"), "{}", text(&o));
    assert_eq!(w.state(id), Some(State::Rejected));
}

/// A regression guard: an unmarked request never enters the touch path
/// (the seam names a missing key, which would exit 5).
#[test]
fn unmarked_approve_unchanged() {
    let w = world();
    w.own_reauth(true);
    let id = w.ask(BODY_A);
    let o = approve(&w, &w.path().join("missing.json"), id);
    ok(&o);
    assert!(
        stdout(&o).contains(&format!("request #{id} approved")),
        "{}",
        text(&o)
    );
    assert!(!stderr(&o).contains("touch"), "{}", text(&o));
    w.wait_state(id, State::Sent);
    assert!(w.wait_record(id, "approved").get("touch").is_none());
}
