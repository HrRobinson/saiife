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
