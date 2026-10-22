//! `saiife doctor` against a fake locked-mode tree (`--root`): never root,
//! never the real /etc, /opt, /var or /run.

mod common;

use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn doctor(root: &Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("doctor")
        .args(args)
        .arg("--root")
        .arg(root)
        .env("HOME", root.join("home"))
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap()
}

fn check<'v>(report: &'v Value, id: &str) -> &'v Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no check {id} in {report:#}"))
}

#[test]
fn doctor_json_exit_matches_report() {
    let tmp = tempfile::tempdir().unwrap();
    saiife_system::testing::fake_install(tmp.path());

    let out = doctor(tmp.path(), &["--json"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["saiife_doctor"], 1);
    // No daemon runs under the fake tree.
    assert_eq!(report["exit"], 2, "{report:#}");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(check(&report, "keys")["status"], "pass");
    assert_eq!(check(&report, "daemon.unit")["status"], "fail");

    let out = doctor(tmp.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("PASS  keys  audit signing key\n"), "{text}");
    assert!(text.ends_with("doctor: 2 failures, 0 warnings\n"), "{text}");
}

#[test]
fn doctor_not_installed_exits_0() {
    let tmp = tempfile::tempdir().unwrap();
    let out = doctor(tmp.path(), &[]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains(
        "INFO  install.record  install record: locked mode is not installed: developer mode checks only"
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_sees_running_daemon() {
    use common::daemon::{Opts, TestDaemon};
    let d = TestDaemon::start(Opts::default());
    let tmp = tempfile::tempdir().unwrap();
    saiife_system::testing::fake_install(tmp.path());
    std::fs::write(
        tmp.path().join("etc/saiife/config.toml"),
        d.config_text(&Opts::default()),
    )
    .unwrap();

    let out = doctor(tmp.path(), &["--json"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let health = check(&report, "daemon.health");
    assert_eq!(health["status"], "pass", "{report:#}");
    let detail = health["detail"].as_str().unwrap();
    assert!(
        detail.starts_with("chain ")
            && detail.contains(", head seq ")
            && detail.contains(", last checkpoint seq "),
        "{detail}"
    );
}

#[test]
fn doctor_user_other_than_self_needs_root() {
    if rustix::process::geteuid().is_root() {
        return; // The real-root job covers root.
    }
    let tmp = tempfile::tempdir().unwrap();
    let out = doctor(tmp.path(), &["--user", "not-me-saiife-test"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "saiife: --user not-me-saiife-test needs root\n"
    );
    assert!(out.stdout.is_empty());
}

#[test]
fn doctor_output_escapes_hostile_names() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    saiife_system::testing::fake_install(tmp.path());
    let p = tmp.path().join("etc/saiife/policy.d/\x1b[31mevil\n.toml");
    std::fs::write(&p, "").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();

    let out = doctor(tmp.path(), &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!out.stdout.contains(&0x1b), "raw ESC in text output");
    let text = String::from_utf8(out.stdout).unwrap();
    let line = text.lines().find(|l| l.contains("paths.owner")).unwrap();
    assert!(line.contains("\\x1b[31mevil⏎.toml"), "{line}");

    let out = doctor(tmp.path(), &["--json"]);
    assert!(!out.stdout.contains(&0x1b), "raw ESC in JSON output");
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let detail = check(&report, "paths.owner")["detail"].as_str().unwrap();
    assert!(detail.contains("\x1b[31mevil\n.toml"), "{detail}");
}

#[test]
fn doctor_user_name_is_escaped() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let out = doctor(tmp.path(), &["--user", "x\x1b[2Jy"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        "saiife: --user x\\x1b[2Jy needs root\n"
    );
}

#[test]
fn doctor_as_user_checks_self() {
    let tmp = tempfile::tempdir().unwrap();
    saiife_system::testing::fake_install(tmp.path());
    let home = tempfile::tempdir().unwrap();
    let netrc = home.path().join(".netrc");
    std::fs::write(
        &netrc,
        "machine example.com login me password hunter2-s3cr3t\n",
    )
    .unwrap();

    let out = Command::cargo_bin("saiife")
        .unwrap()
        .args(["doctor", "--json", "--root"])
        .arg(tmp.path())
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains("hunter2-s3cr3t"), "{stdout}");
    let report: Value = serde_json::from_str(&stdout).unwrap();
    let found: Vec<&Value> = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            c["id"].as_str().is_some_and(|id| id.ends_with(".secrets"))
                && c["status"] == "warn"
                && c["detail"]
                    .as_str()
                    .is_some_and(|d| d.contains(&netrc.display().to_string()))
        })
        .collect();
    assert_eq!(found.len(), 1, "{report:#}");

    let out = Command::cargo_bin("saiife")
        .unwrap()
        .args(["doctor", "--root"])
        .arg(tmp.path())
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains("hunter2-s3cr3t"), "{text}");
    assert!(
        text.contains(&format!("{}: holds a password", netrc.display())),
        "{text}"
    );
}
