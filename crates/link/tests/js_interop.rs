//! A frame signed by the browser code (`assets/js/wire.js`, run under node)
//! verifies in Rust. The frozen vector pins Rust -> JS; this pins JS -> Rust.

use saiife_wire::{b64, frame, sig};
use std::path::Path;
use std::process::Command;

#[test]
fn node_signed_frame_verifies_in_rust() {
    if Command::new("node").arg("--version").output().is_err() {
        println!("skipped: no node");
        return;
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/tests/sign-once.mjs");
    let home = tempfile::tempdir().unwrap();
    let out = Command::new("node")
        .arg(&script)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("XDG_RUNTIME_DIR", home.path())
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent/p30-t2-bus",
        )
        .current_dir(home.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let public_raw = b64::dec_n::<65>(v["public_raw"].as_str().unwrap()).unwrap();
    let body = v["body"].as_str().unwrap();
    let sig_raw = b64::dec_n::<64>(v["sig"].as_str().unwrap()).unwrap();

    assert!(sig::verify_p256(&public_raw, body.as_bytes(), &sig_raw));
    let mut other = body.to_string();
    other.push(' ');
    assert!(!sig::verify_p256(&public_raw, other.as_bytes(), &sig_raw));

    let f = frame::parse_body(body.as_bytes()).unwrap();
    assert_eq!(f.device_id, sig::device_id_of(&public_raw));
    assert_eq!(f.action, "box.stop");
    assert_eq!(f.expires_at - f.issued_at, 120);
    assert_eq!(f.args["note"], "caf\u{e9} \u{202e}");
}
