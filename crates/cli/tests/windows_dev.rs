//! Windows (plan 19a): locked mode is refused with one line and exit 2, and
//! developer mode works. Compiled and run on `windows-latest` only; Linux and
//! macOS never see this file.
//!
//! What these tests touch: `SAIIFE_DATA_DIR` and `SAIIFE_AUDIT_DIR` are temp
//! dirs, and `init`, `check` and `status` run in a dedicated temp project
//! directory. USERPROFILE and LOCALAPPDATA are temp dirs too, and saiife reads
//! them first (ruling P4), so nothing reads or writes the runner's real profile.
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

/// Ruling P4: `~` is what `USERPROFILE` says, and the audit log's default sits
/// under what `LOCALAPPDATA` says, not the known folders.
#[test]
fn the_profile_comes_from_the_environment() {
    let home = tempfile::tempdir().unwrap();
    let name = home.path().file_name().unwrap().to_str().unwrap();
    let out = saiife(home.path())
        .args(["explain", "--read", "~/.ssh/id_rsa"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("decision: DENY"), "{text}");
    let resolved = text
        .lines()
        .find(|l| l.starts_with("resolved:"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(resolved.contains(name), "{text}");

    let out = saiife(home.path())
        .env_remove("SAIIFE_AUDIT_DIR")
        .env_remove("SAIIFE_DATA_DIR")
        .args(["check", "--agent", "claude"])
        .current_dir(home.path())
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let log = home
        .path()
        .join("AppData")
        .join("Local")
        .join("saiife")
        .join("audit");
    assert!(log.is_dir(), "{}", log.display());
}

/// Outside the service manager `daemon --system` runs on its own, and as anything but
/// the service account it refuses (plan 19b, W10).
#[test]
fn daemon_system_runs_outside_the_service_manager_and_refuses_this_user() {
    let home = tempfile::tempdir().unwrap();
    let out = saiife(home.path())
        .args(["daemon", "--system"])
        .env_remove("SAIIFE_TEST_PIPE")
        .assert()
        .code(2);
    let text = String::from_utf8_lossy(&out.get_output().stderr).into_owned();
    assert!(!text.contains(REFUSAL), "{text}");
    assert!(text.contains("the daemon"), "{text}");
}

#[test]
fn locked_commands_refuse_on_windows() {
    let home = tempfile::tempdir().unwrap();
    let cases: &[&[&str]] = &[
        &["system", "install"],
        &["system", "uninstall"],
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
