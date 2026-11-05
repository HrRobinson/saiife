//! Windows: what is not ported yet is refused with one line and exit 2, and
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

/// The spec's refusal, for what the rest of plan 19b brings. Each task that ports a
/// command takes its line out of [`locked_commands_refuse_on_windows`].
const REFUSAL: &str = "saiife: locked mode is not supported here: this command is not ported to Windows yet. Developer mode works as before.";
/// W18.
const NO_GATEWAY: &str = "saiife: locked mode is not supported here: the MCP gateway needs Linux. Developer mode works as before.";

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

/// W11's line reaches stderr, which the service's log takes over: the CLI, a squatted test
/// pipe, and exit 1. Task 5's own test could not read stderr, as it is one per process.
#[test]
fn a_squatted_pipe_is_w11s_line_and_exit_1() {
    use saiife_win::ffi::pipe::create_server;
    use saiife_win::ffi::{acl, token};
    use saiife_win::pipe::control_sddl;
    let home = tempfile::tempdir().unwrap();
    let me = token::current().unwrap().sid;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();
    let pipe = format!(r"\\.\pipe\saiife-test-{}-w11", std::process::id());
    let _squat = create_server(&pipe, &control_sddl(&me), true).unwrap();
    let user = saiife_win::ffi::account::lookup_sid(&me).unwrap();
    let top = home.path().join("t");
    acl::create_dir_with_sddl(
        &top,
        &format!("O:{me}D:PAI(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)"),
    )
    .unwrap();
    let audit = top.join("audit");
    std::fs::create_dir_all(&audit).unwrap();
    let config = top.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "version = 2\nlocked = true\n[daemon]\nuser = {user:?}\n[audit]\ndir = {:?}\nmin_free_mb = 0\n",
            audit.display().to_string()
        ),
    )
    .unwrap();
    saiife(home.path())
        .args(["daemon", "--system", "--config"])
        .arg(&config)
        .arg("--state-dir")
        .arg(top.join("state"))
        .arg("--credentials-dir")
        .arg(top.join("state").join("keys"))
        .env("SAIIFE_TEST_PIPE", &pipe)
        .assert()
        .code(1)
        .stderr(contains("exists and is not ours; refusing to start"));
}

#[test]
fn locked_commands_refuse_on_windows() {
    let home = tempfile::tempdir().unwrap();
    let cases: &[&[&str]] = &[
        &["audit", "--broker"],
        &["audit", "verify", "--broker"],
    ];
    for args in cases {
        saiife(home.path())
            .args(*args)
            .assert()
            .code(2)
            .stderr(contains(REFUSAL));
    }
    // W18 stays: no sandbox for a gateway's children.
    saiife(home.path())
        .args(["__mcp-spawn"])
        .assert()
        .code(2)
        .stderr(contains(NO_GATEWAY));
}

/// `system` and `daemon --user` are ported, so neither gets the refusal. Nothing here can
/// change the runner: `--help` installs nothing, `--root` uses the fake host below a temp
/// dir, and `daemon --user` stops at a flag it takes no value for. `system install` itself
/// is never run here, because the runner is elevated: that is `locked-windows`.
#[test]
fn ported_commands_no_longer_refuse() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("root");
    std::fs::create_dir(&root).unwrap();
    saiife(home.path())
        .args(["system", "--help"])
        .assert()
        .code(0)
        .stdout(contains("install"));
    let out = saiife(home.path())
        .args(["system", "uninstall", "--root"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains(REFUSAL),
        "{out:?}"
    );
    saiife(home.path())
        .args(["daemon", "--user", "--config", "elsewhere"])
        .assert()
        .code(2)
        .stderr(contains("takes no --config"))
        .stderr(contains(REFUSAL).not());
    // Doctor on the runner, which has no install: developer mode, and no refusal.
    saiife(home.path())
        .args(["doctor", "--json"])
        .assert()
        .code(0)
        .stdout(contains("\"saiife_doctor\": 1"))
        .stdout(contains("install.record"))
        .stderr(contains(REFUSAL).not());
}

/// A client on a host with no install says it cannot reach a daemon or names the missing
/// broker. Neither is the old blanket refusal, and neither sends anything anywhere.
#[test]
fn locked_clients_no_longer_refuse_outright() {
    let home = tempfile::tempdir().unwrap();
    let cases: &[&[&str]] = &[
        &["secret", "list"],
        &["connect", "svc"],
        &["api", "--list"],
        &["run", "--secret", "x", "--", "cmd"],
        &["lockdown"],
        &["policy", "reload"],
    ];
    for args in cases {
        let out = saiife(home.path()).args(*args).output().unwrap();
        assert!(!out.status.success(), "{args:?}");
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(!text.contains(REFUSAL), "{args:?}: {text}");
    }
}

/// `check --managed` denies when the policy cannot be loaded: the first thing a missing
/// install gets, with no daemon to tell.
#[test]
fn managed_hook_denies_without_an_install() {
    let home = tempfile::tempdir().unwrap();
    let missing = home.path().join("absent.toml");
    saiife(home.path())
        .args(["check", "--managed", "--hook-exit", "--agent", "claude"])
        .arg("--system-config")
        .arg(&missing)
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#)
        .assert()
        .code(2)
        .stderr(contains("BLOCKED (fail closed)"));
}

/// `--managed` with a flag this binary does not know is denied too.
#[test]
fn managed_hook_denies_on_bad_arguments() {
    let home = tempfile::tempdir().unwrap();
    saiife(home.path())
        .args(["check", "--managed", "--no-such-flag"])
        .write_stdin("{}")
        .assert()
        .code(2)
        .stderr(contains("BLOCKED (fail closed)"));
}

/// The worker runs on Windows: a plain `__eval` answers its request.
#[test]
fn the_worker_runs() {
    let home = tempfile::tempdir().unwrap();
    let out = saiife(home.path())
        .arg("__eval")
        .write_stdin(
            r#"{"payload":"{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git status\"}}","packs":[],"budget_ms":50}"#,
        )
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("\"verdict\""), "{text}");
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
