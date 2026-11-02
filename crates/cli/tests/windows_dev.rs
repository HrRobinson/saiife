//! Windows (plan 19a): locked mode is refused with one line and exit 2, and
//! developer mode works. Compiled and run on `windows-latest` only; Linux and
//! macOS never see this file. HOME-like variables point at a temp dir.
#![cfg(windows)]

use assert_cmd::Command;
use predicates::str::contains;

const REFUSAL: &str = "saiife: locked mode on Windows arrives in plan 19b. Developer mode works.";

fn saiife(home: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("saiife").unwrap();
    c.env("USERPROFILE", home)
        .env("HOME", home)
        .env("APPDATA", home.join("AppData").join("Roaming"))
        .env("LOCALAPPDATA", home.join("AppData").join("Local"))
        .env("SAIIFE_DATA_DIR", home.join("data"))
        .env("SAIIFE_AUDIT_DIR", home.join("audit"));
    c
}

#[test]
fn locked_commands_refuse_on_windows() {
    let home = tempfile::tempdir().unwrap();
    let cases: &[&[&str]] = &[
        &["system", "install"],
        &["system", "uninstall"],
        &["daemon", "--system"],
        &["daemon", "--user"],
        &["approve", "1"],
        &["reject", "1"],
        &["secret", "list"],
        &["api", "--list"],
        &["run", "--secret", "x", "--", "cmd"],
        &["doctor"],
        &["env", "list"],
        &["lockdown"],
        &["policy", "reload"],
        &["check", "--managed"],
        &["audit", "--broker"],
    ];
    for args in cases {
        saiife(home.path())
            .args(*args)
            .assert()
            .code(2)
            .stderr(contains(REFUSAL));
    }
}

#[test]
fn developer_commands_work_on_windows() {
    let home = tempfile::tempdir().unwrap();
    saiife(home.path())
        .args(["test", "echo hi"])
        .assert()
        .code(0);
    saiife(home.path()).args(["packs"]).assert().code(0);
    saiife(home.path()).args(["audit"]).assert().code(0);
}
