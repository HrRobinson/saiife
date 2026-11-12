//! `saiife box vmm status|fetch` (plan 35, Task 2). No network: nothing here
//! runs curl.
#![cfg(unix)]

use std::process::{Command, Output, Stdio};

fn vmm(args: &[&str], locked: bool) -> (tempfile::TempDir, Output) {
    let d = tempfile::tempdir().unwrap();
    let cfg = d.path().join("system.toml");
    if locked {
        let me = Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .unwrap()
            .stdout;
        let me = String::from_utf8(me).unwrap();
        let body = format!(
            "version = 2\nlocked = true\n[daemon]\nuser = \"{}\"\nsocket_dir = \"{}\"\n[audit]\ndir = \"{}\"\n",
            me.trim(),
            d.path().display(),
            d.path().display()
        );
        std::fs::write(&cfg, body).unwrap();
    }
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["box", "vmm"])
        .args(args)
        .env_clear()
        .env("HOME", d.path().join("home"))
        .env("XDG_DATA_HOME", d.path().join("data"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_TEST_SYSTEM_CONFIG", &cfg)
        .env("SAIIFE_TOOL_CURL", d.path().join("no-curl"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (d, o)
}

#[test]
fn vmm_status_shows_pins() {
    let (_d, o) = vmm(&["status"], false);
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(o.status.code(), Some(0), "{out} {:?}", o.stderr);
    assert!(out.contains("cloud-hypervisor v54.0"), "{out}");
    assert!(out.contains("CLOUDHV.fd ch-97eeb7b09"), "{out}");
    assert!(out.contains("missing"), "{out}");
}

#[test]
fn vmm_fetch_in_locked_mode_points_at_the_installer() {
    let (_d, o) = vmm(&["fetch"], true);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(err.contains("sudo saiife system install --boxes"), "{err}");
}
