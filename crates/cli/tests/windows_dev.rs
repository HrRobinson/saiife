//! Windows (plan 19a): locked mode is refused with one line and exit 2, and
//! developer mode works. Compiled and run on `windows-latest` only; Linux and
//! macOS never see this file.
//!
//! What these tests touch: `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` are temp
//! dirs, and `init`, `check` and `status` run in a dedicated temp project
//! directory. HOME and USERPROFILE are set too, but `dirs` 5 `home_dir()` on
//! Windows asks the known-folder API and ignores both, so anything that reads
//! the user's home (agent config lookups) sees the runner's real profile. The
//! tests only read there; the runner is disposable.
#![cfg(windows)]

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use std::path::Path;

const REFUSAL: &str = "saiife: locked mode on Windows arrives in plan 19b. Developer mode works.";

fn saiife(home: &Path) -> Command {
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
        &["approvals"],
        &["secret", "list"],
        &["connect", "svc"],
        &["api", "--list"],
        &["mcp"],
        &["run", "--secret", "x", "--", "cmd"],
        &["doctor"],
        &["env", "list"],
        &["lockdown"],
        &["policy", "show"],
        &["policy", "reload"],
        &["check", "--managed"],
        &["__eval"],
        &["__mcp-spawn"],
        &["audit", "--broker"],
        &["audit", "--kind", "guard"],
        &["audit", "--service", "x"],
        &["audit", "--system-config", "x.toml"],
        &["audit", "verify", "--broker"],
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
    let project = tempfile::tempdir().unwrap();
    saiife(home.path())
        .args(["test", "echo hi"])
        .assert()
        .code(0);
    saiife(home.path()).args(["packs"]).assert().code(0);
    saiife(home.path()).args(["audit"]).assert().code(0);

    // init, status and check in a dedicated project directory.
    saiife(home.path())
        .current_dir(project.path())
        .args(["init", "--agent", "claude"])
        .assert()
        .code(0);
    assert!(project.path().join(".claude").exists());
    saiife(home.path())
        .current_dir(project.path())
        .arg("status")
        .assert()
        .code(predicate::in_iter([0, 1]));
    let payload = |cmd: &str| {
        serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": cmd },
            "cwd": project.path(),
        })
        .to_string()
    };
    saiife(home.path())
        .current_dir(project.path())
        .args(["check", "--hook-exit", "--agent", "claude"])
        .write_stdin(payload("echo hi"))
        .assert()
        .code(0);
    saiife(home.path())
        .current_dir(project.path())
        .args(["check", "--hook-exit", "--agent", "claude"])
        .write_stdin(payload("rm -rf /"))
        .assert()
        .code(2);
}
