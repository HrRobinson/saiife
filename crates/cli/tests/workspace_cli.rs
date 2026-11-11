//! `saiife workspace pair | devices | revoke` end to end (plan 29, Task 5):
//! a real personal broker on temp dirs (its control socket and `link.sock`),
//! the real `saiife` binary as separate processes, and a `TestDevice` as the
//! browser, posting `workspace.pair.finish` over `link.sock`. The broker's
//! user is its own admin-equivalent, so no re-authentication is asked.
#![cfg(unix)]

mod common;

use common::personal::{dl, TestBroker};
use saiife_ipc::client::Client;
use saiife_ipc::msg::{LINK_SOCKET_NAME, OP_WORKSPACE_PAIR_FINISH};
use saiife_wire::sig::TestDevice;
use saiife_wire::{b64, pair};
use serde_json::{json, Map, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::Stdio;

fn map(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

/// The browser: `workspace.pair.finish` over `link.sock` for the URL's
/// fragment.
fn browser_finishes(b: &TestBroker, url: &str, label: &str) -> (TestDevice, Map<String, Value>) {
    let frag = url.split_once("#pair=").unwrap().1;
    let (pair_id, secret, _, _) = pair::parse_fragment(frag).unwrap();
    let d = TestDevice::generate();
    let pk = d.public_raw();
    let mut c = Client::connect_named(
        &b.socket_dir(),
        LINK_SOCKET_NAME,
        common::daemon::own_uid(),
        dl(),
    )
    .expect("link.sock");
    let ans = c
        .call(
            OP_WORKSPACE_PAIR_FINISH,
            map(json!({
                "pair_id": pair_id,
                "device_pub": b64::enc(&pk),
                "label": label,
                "proof": b64::enc(&pair::proof(&secret, &pair_id, &pk)),
            })),
            dl(),
        )
        .expect("pair.finish");
    (d, ans)
}

#[test]
fn workspace_pair_end_to_end() {
    let b = TestBroker::start(None);
    let mut child = b
        .cli(&["workspace", "pair", "--label", "my laptop", "--local"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    // Not a terminal: no QR code, the URL is the first line.
    let mut url = String::new();
    out.read_line(&mut url).unwrap();
    let url = url.trim().to_string();
    assert!(url.starts_with("http://localhost:47810/#pair="), "{url}");
    let mut waiting = String::new();
    out.read_line(&mut waiting).unwrap();
    assert!(
        waiting.starts_with("Waiting for the browser (5 min)"),
        "{waiting}"
    );

    let (device, fin) = browser_finishes(&b, &url, "phone");
    let code = fin["short_code"].as_str().unwrap().to_string();

    // The prompt has no newline: read up to the question mark.
    let mut prompt = Vec::new();
    out.read_until(b'?', &mut prompt).unwrap();
    let prompt = String::from_utf8(prompt).unwrap();
    assert!(
        prompt.contains(&format!("shows: {code}. Same code?")),
        "{prompt:?}"
    );
    assert!(prompt.contains("\"phone\""), "{prompt:?}");

    let mut sin = child.stdin.take().unwrap();
    sin.write_all(b"y\n").unwrap();
    drop(sin);
    let mut rest = String::new();
    std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
    let st = child.wait().unwrap();
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    assert!(st.success(), "{rest} {err}");
    assert!(
        rest.contains(&format!("Paired {}", device.device_id())),
        "{rest}"
    );

    let list = b.run_cli(&["workspace", "devices"]);
    assert!(list.status.success());
    let text = String::from_utf8_lossy(&list.stdout);
    assert!(
        text.contains(&device.device_id()) && text.contains("active"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'), "{text:?}");

    // Revoke it; a second revoke is idempotent, an unknown id exits 2.
    let r = b.run_cli(&["workspace", "revoke", &device.device_id()]);
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    let list = b.run_cli(&["workspace", "devices"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains("revoked"));
}

#[test]
fn answering_n_rejects_and_pairs_nothing() {
    let b = TestBroker::start(None);
    let mut child = b
        .cli(&["workspace", "pair", "--local"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut url = String::new();
    out.read_line(&mut url).unwrap();
    let mut skip = String::new();
    out.read_line(&mut skip).unwrap();
    let (_d, _) = browser_finishes(&b, url.trim(), "tab");
    let mut prompt = Vec::new();
    out.read_until(b'?', &mut prompt).unwrap();
    let mut sin = child.stdin.take().unwrap();
    sin.write_all(b"n\n").unwrap();
    drop(sin);
    let o = child.wait_with_output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let list = b.run_cli(&["workspace", "devices"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains("no paired browsers"));
}

#[test]
fn revoke_unknown_device_exits_2() {
    let b = TestBroker::start(None);
    let o = b.run_cli(&["workspace", "revoke", "d-nope"]);
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("no such device"));
}

#[test]
fn no_daemon_exits_5() {
    let b = TestBroker::prepare();
    let o = b.run_cli(&["workspace", "devices"]);
    assert_eq!(
        o.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn serve_refuses_a_ws_hub_with_exit_2() {
    let b = TestBroker::start(None);
    let o = b.run_cli(&[
        "workspace",
        "serve",
        "--port",
        "0",
        "--hub",
        "ws://example.invalid/v1/link",
    ]);
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("wss://"));
}

#[test]
fn ctrl_c_while_waiting_exits_2_and_pairs_nothing() {
    let b = TestBroker::start(None);
    let mut child = b
        .cli(&["workspace", "pair", "--local"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut url = String::new();
    out.read_line(&mut url).unwrap();
    // SIGINT to the test's own child.
    let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();
    let st = child.wait().unwrap();
    assert_eq!(st.code(), Some(2), "{st:?}");
    let list = b.run_cli(&["workspace", "devices"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains("no paired browsers"));
}
