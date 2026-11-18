//! The browser seal (`assets/js/seal.js`, run under node) and the machine
//! seal (`saiife_wire::seal`) complete a device handshake and exchange
//! sealed messages both ways. The frozen vectors pin the bytes; this pins
//! the two live implementations against each other.

use saiife_wire::seal::{MachineHandshake, SealBinding, MACHINE_HELLO_DOMAIN};
use saiife_wire::{b64, sig::TestDevice};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn node_and_rust_seal_to_each_other() {
    if Command::new("node").arg("--version").output().is_err() {
        println!("skipped: no node");
        return;
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/tests/seal-once.mjs");
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new("node")
        .arg(&script)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("XDG_RUNTIME_DIR", home.path())
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent/wsh-c1-bus",
        )
        .current_dir(home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut read = || -> serde_json::Value {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "node ended early");
        serde_json::from_str(&line).unwrap()
    };

    let v = read();
    let browser_eph = b64::dec_n::<65>(v["browser_eph"].as_str().unwrap()).unwrap();
    let device_pub = b64::dec_n::<65>(v["device_pub"].as_str().unwrap()).unwrap();
    let device_id = saiife_wire::sig::device_id_of(&device_pub);

    let machine_key = TestDevice::generate();
    let mh = MachineHandshake::new(&ring::rand::SystemRandom::new()).unwrap();
    let machine_sig = machine_key.sign_domain(
        MACHINE_HELLO_DOMAIN,
        &mh.to_sign(&SealBinding::Device(device_id)),
    );
    let hello = serde_json::json!({
        "machine_eph": b64::enc(&mh.eph_pub()),
        "session_id": b64::enc(&mh.session_id()),
        "machine_sig": b64::enc(&machine_sig),
        "machine_pub": b64::enc(&machine_key.public_raw()),
    });
    writeln!(stdin, "{hello}").unwrap();

    let v = read();
    let auth = b64::dec_n::<64>(v["seal_auth_sig"].as_str().unwrap()).unwrap();
    let sealed = b64::dec(v["sealed"].as_str().unwrap()).unwrap();
    let mut ch = mh
        .finish(&browser_eph, Some(&auth), Some(&device_pub))
        .unwrap();
    assert_eq!(ch.open(&sealed).unwrap(), b"ping from js");

    let pong = ch.seal(b"pong from rust").unwrap();
    writeln!(
        stdin,
        "{}",
        serde_json::json!({ "sealed": b64::enc(&pong) })
    )
    .unwrap();
    let v = read();
    assert_eq!(v["opened"], "pong from rust");
    drop(stdin);
    assert!(child.wait().unwrap().success());
}
