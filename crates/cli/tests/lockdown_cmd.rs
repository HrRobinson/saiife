//! `saiife lockdown on|off` end to end (plan 11, Task 7): a real daemon on
//! temp dirs, the CLI and the managed hook as separate processes. Nothing
//! leaves loopback (no connector call reaches a network: lockdown denies
//! at step 2); signals go to the test's own child through a syscall.
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{own_group, own_user, Opts, TestDaemon};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

fn policy(extra: &str) -> String {
    format!(
        r#"[admin]
groups = [{group:?}]

[[scope]]
name = "agents"
users = [{user:?}]
services = ["erp"]
env = "prod"

[services.erp]
connector = "http"
base_url = "https://127.0.0.1:9/api"
secret = "erp-key"
auth = {{ kind = "header", name = "X-Api-Key" }}
allow = ["invoices:read"]

[[services.erp.operation]]
id = "invoices.list"
capability = "invoices:read"
kind = "read"
method = "GET"
path = "/echo"

{extra}
"#,
        group = own_group(),
        user = own_user(),
    )
}

fn world(extra: &str) -> TestDaemon {
    let opts = Opts {
        extra: policy(extra),
        ..Opts::default()
    };
    let d = TestDaemon::start(opts);
    fs::create_dir_all(d.path().join("project")).unwrap();
    d
}

fn base_cmd(d: &TestDaemon) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    c.env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .current_dir(d.path().join("project"))
        .stdin(Stdio::null());
    c
}

fn lockdown(d: &TestDaemon, args: &[&str]) -> Output {
    base_cmd(d)
        .arg("lockdown")
        .arg("--system-config")
        .arg(d.config())
        .args(args)
        .output()
        .unwrap()
}

fn api(d: &TestDaemon) -> Output {
    base_cmd(d)
        .arg("api")
        .arg("--system-config")
        .arg(d.config())
        .args(["erp", "invoices.list"])
        .output()
        .unwrap()
}

/// One managed hook call for a harmless Bash command.
fn hook(d: &TestDaemon) -> Output {
    let payload = json!({
        "session_id": "s-l",
        "cwd": d.path().join("project"),
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hi"}
    })
    .to_string();
    let mut child = base_cmd(d)
        .args(["check", "--managed", "--agent", "claude", "--system-config"])
        .arg(d.config())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut sin = child.stdin.take().unwrap();
    let w = std::thread::spawn(move || {
        let _ = sin.write_all(payload.as_bytes());
    });
    let out = child.wait_with_output().unwrap();
    w.join().unwrap();
    out
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}
fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn lockdown_records(d: &TestDaemon) -> Vec<Value> {
    d.of_kind("lockdown")
}

#[test]
fn connectors_lockdown_denies_api_call_rule_lockdown() {
    let d = world("");
    let o = lockdown(&d, &["on", "--scope", "connectors", "--reason", "runaway"]);
    assert_eq!(code(&o), 0, "{} / {}", stderr(&o), d.stderr_text());
    assert!(
        stdout(&o).contains("lockdown: on (scope connectors)") && stdout(&o).contains("runaway"),
        "{}",
        stdout(&o)
    );

    let o = api(&d);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    let c = d.of_kind("connector");
    let last = c.last().expect("a connector record");
    assert_eq!(last["decision"], "deny", "{last}");
    assert_eq!(last["rule"], "lockdown", "{last}");

    // Hooks still work under `connectors`.
    let o = hook(&d);
    assert_eq!(code(&o), 0, "{}", stderr(&o));

    // The state is shown, and `off` lifts it.
    let o = lockdown(&d, &[]);
    assert!(
        stdout(&o).contains("lockdown: on (scope connectors)"),
        "{}",
        stdout(&o)
    );
    let o = lockdown(&d, &["off"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("lockdown: off"), "{}", stdout(&o));
    let _ = api(&d);
    let c = d.of_kind("connector");
    assert_ne!(c.last().unwrap()["rule"], "lockdown", "{c:?}");

    let recs = lockdown_records(&d);
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(recs[0]["action"], "on");
    assert_eq!(recs[0]["scope"], "connectors");
    assert_eq!(recs[0]["reason"], "runaway");
    assert_eq!(recs[1]["action"], "off");
}

#[test]
fn all_lockdown_denies_hooks_with_message_and_record() {
    let d = world("");
    let o = lockdown(&d, &["on", "--reason", "stop everything"]);
    assert_eq!(code(&o), 0, "{} / {}", stderr(&o), d.stderr_text());

    let o = hook(&d);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife lockdown is on: stop everything"),
        "{}",
        stderr(&o)
    );
    let g = d.of_kind("guard");
    let last = g.last().expect("the guard record is still written");
    assert_eq!(last["decision"], "deny", "{last}");
    assert_eq!(last["rule"], "lockdown", "{last}");

    let o = lockdown(&d, &["off"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = hook(&d);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

#[test]
fn lockdown_survives_restart() {
    let mut d = world("");
    let o = lockdown(&d, &["on", "--scope", "connectors", "--reason", "persist"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let file = d.state_dir().join("state/lockdown.json");
    assert!(file.exists());
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let pid = rustix::process::Pid::from_raw(d.pid() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    assert!(d.wait_exit(Duration::from_secs(10)).is_some());
    d.spawn_and_wait();

    let o = lockdown(&d, &[]);
    assert!(
        stdout(&o).contains("lockdown: on (scope connectors)") && stdout(&o).contains("persist"),
        "{}",
        stdout(&o)
    );
    let _ = api(&d);
    assert_eq!(d.of_kind("connector").last().unwrap()["rule"], "lockdown");
}

#[test]
fn non_approver_off_refused_and_recorded() {
    // The test user is neither an admin nor an approver.
    let d = TestDaemon::start(Opts {
        extra: "[admin]\ngroups = [\"saiife-no-such-group\"]\n".into(),
        ..Opts::default()
    });
    fs::create_dir_all(d.path().join("project")).unwrap();
    let o = lockdown(&d, &["off"]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(stderr(&o).contains("lockdown is for"), "{}", stderr(&o));
    let o = lockdown(&d, &["on"]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    let recs = lockdown_records(&d);
    assert_eq!(recs.len(), 2, "{recs:?}");
    for (r, action) in recs.iter().zip(["off", "on"]) {
        assert_eq!(r["decision"], "deny", "{r}");
        assert_eq!(r["action"], action, "{r}");
    }
    // Nothing changed.
    assert!(stdout(&lockdown(&d, &[])).contains("lockdown: off"));
    assert!(!d.state_dir().join("state/lockdown.json").exists());
}

#[test]
fn approver_may_set_lockdown() {
    let d = TestDaemon::start(Opts {
        extra: format!(
            "[admin]\ngroups = [\"saiife-no-such-group\"]\n\n[approval]\napprovers = [{:?}]\n",
            own_user()
        ),
        ..Opts::default()
    });
    fs::create_dir_all(d.path().join("project")).unwrap();
    let o = lockdown(&d, &["on", "--scope", "connectors"]);
    assert_eq!(code(&o), 0, "{} / {}", stderr(&o), d.stderr_text());
    let o = lockdown(&d, &["off"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let recs = lockdown_records(&d);
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert!(recs.iter().all(|r| r["decision"] == "allow"), "{recs:?}");
}

#[test]
fn unreadable_flag_fails_closed_to_all() {
    let mut d = world("");
    let dir = d.state_dir().join("state");
    fs::create_dir_all(&dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Stop, damage the flag file, start again.
    let pid = rustix::process::Pid::from_raw(d.pid() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    assert!(d.wait_exit(Duration::from_secs(10)).is_some());
    fs::write(dir.join("lockdown.json"), b"{ not json").unwrap();
    d.spawn_and_wait();

    let o = hook(&d);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife lockdown is on: lockdown file unreadable"),
        "{}",
        stderr(&o)
    );
    let _ = api(&d);
    assert_eq!(d.of_kind("connector").last().unwrap()["rule"], "lockdown");
    assert_eq!(d.events("lockdown_unreadable").len(), 1);
    // `off` clears it.
    let o = lockdown(&d, &["off"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(code(&hook(&d)), 0);
}

#[test]
fn status_shows_lockdown() {
    use common::{code as ccode, stdout as cstdout, Env};
    let d = world("");
    let root = tempfile::tempdir().unwrap();
    saiife_system::testing::fake_install(root.path());
    fs::write(
        root.path().join("etc/saiife/config.toml"),
        d.config_text(&Opts {
            extra: policy(""),
            ..Opts::default()
        }),
    )
    .unwrap();
    let status = || {
        let env = Env::new(&["claude"]);
        let out = env.saiife(&["status", "--root", root.path().to_str().unwrap()]);
        (ccode(&out), cstdout(&out))
    };
    let (_, text) = status();
    assert!(text.contains("  lockdown: off\n"), "{text}");

    let o = lockdown(&d, &["on", "--scope", "connectors", "--reason", "drill"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let (_, text) = status();
    assert!(
        text.contains("  lockdown: ON (scope connectors) since ") && text.contains(": drill\n"),
        "{text}"
    );
    // TODO(plan 11, Task 3): the pending-approvals line, once `approval.list`
    // exists.
}

fn api_token(d: &TestDaemon) -> Output {
    base_cmd(d)
        .args(["api", "token", "--system-config"])
        .arg(d.config())
        .output()
        .unwrap()
}

#[test]
fn lockdown_denies_lease_and_token_for_any_scope() {
    use serde_json::Map;
    for scope in ["connectors", "all"] {
        let d = world("");
        let o = api_token(&d);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert_eq!(code(&lockdown(&d, &["on", "--scope", scope])), 0);

        let o = api_token(&d);
        assert_eq!(code(&o), 2, "{scope}: {}", stderr(&o));
        assert!(stderr(&o).contains("lockdown"), "{}", stderr(&o));
        let r = d.events("gateway_token");
        let last = r.last().unwrap();
        assert_eq!(last["decision"], "deny", "{last}");
        assert_eq!(last["rule"], "lockdown", "{last}");

        let mut a = Map::new();
        a.insert("name".into(), json!("erp-key"));
        a.insert("exe".into(), json!("/usr/bin/true"));
        let e = d.client().call("secret.lease", a, common::daemon::dl());
        match e {
            Err(saiife_ipc::client::ClientError::Refused { code, message }) => {
                assert_eq!(code, "denied");
                assert!(message.starts_with("lockdown:"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        let s = d.of_kind("secret");
        let last = s.last().unwrap();
        assert_eq!(last["event"], "secret_use", "{last}");
        assert_eq!(last["decision"], "deny", "{last}");
        assert_eq!(last["rule"], "lockdown", "{last}");

        // api.list stays open.
        let o = base_cmd(&d)
            .args(["api", "--list", "--system-config"])
            .arg(d.config())
            .output()
            .unwrap();
        assert_eq!(code(&o), 0, "{}", stderr(&o));
    }
}

#[test]
fn all_lockdown_keeps_the_original_verdict_and_masks_the_reason() {
    let d = world("");
    let o = lockdown(
        &d,
        &[
            "on",
            "--reason",
            "leak ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stdout(&o).contains("ghp_abc"), "{}", stdout(&o));
    let o = hook(&d);
    assert_eq!(code(&o), 2);
    assert!(!stderr(&o).contains("ghp_abc"), "{}", stderr(&o));
    let g = d.of_kind("guard");
    let last = g.last().unwrap();
    assert_eq!(last["rule"], "lockdown", "{last}");
    assert_eq!(last["would_have"]["decision"], "allow", "{last}");
    assert!(last.get("lockdown").is_none(), "{last}");
    assert!(!last.to_string().contains("ghp_abc"), "{last}");
    assert!(!lockdown_records(&d)[0].to_string().contains("ghp_abc"));
}

#[test]
fn lockdown_over_a_guard_deny_keeps_it_and_marks_lockdown() {
    let d = world("");
    let payload = json!({
        "session_id": "s-l", "cwd": d.path().join("project"),
        "permission_mode": "default", "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "rm -rf /"}
    })
    .to_string();
    let run = |d: &TestDaemon| {
        let mut child = base_cmd(d)
            .args(["check", "--managed", "--agent", "claude", "--system-config"])
            .arg(d.config())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut sin = child.stdin.take().unwrap();
        let p = payload.clone();
        let w = std::thread::spawn(move || {
            let _ = sin.write_all(p.as_bytes());
        });
        let out = child.wait_with_output().unwrap();
        w.join().unwrap();
        out
    };
    assert_eq!(code(&run(&d)), 2);
    let before = d.of_kind("guard").pop().unwrap();
    assert_eq!(before["decision"], "deny", "{before}");
    assert_eq!(code(&lockdown(&d, &["on"])), 0);
    assert_eq!(code(&run(&d)), 2);
    let after = d.of_kind("guard").pop().unwrap();
    assert_eq!(after["decision"], "deny", "{after}");
    assert_eq!(after["rule"], "lockdown", "{after}");
    assert_eq!(after["lockdown"], true, "{after}");
    assert_eq!(after["would_have"]["rule"], before["rule"], "{after}");
    assert_eq!(after["reason"], before["reason"], "{after}");
}

#[test]
fn unsafe_state_dir_fails_closed_to_all() {
    use std::os::unix::fs::PermissionsExt;
    let mut d = world("");
    let pid = rustix::process::Pid::from_raw(d.pid() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    assert!(d.wait_exit(Duration::from_secs(10)).is_some());
    let dir = d.state_dir().join("state");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    d.spawn_and_wait();
    let o = hook(&d);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("saiife lockdown is on: lockdown dir unsafe"),
        "{}",
        stderr(&o)
    );
    assert_eq!(d.events("lockdown_unreadable").len(), 1);
}

#[test]
fn unsaved_on_is_applied_and_reported() {
    let d = world("");
    // A non-empty directory where the file goes: the rename fails.
    let blocker = d.state_dir().join("state/lockdown.json/x");
    fs::create_dir_all(&blocker).unwrap();
    let o = lockdown(&d, &["on", "--scope", "connectors"]);
    assert_eq!(code(&o), 2, "{}", stdout(&o));
    assert!(
        stderr(&o).contains("lockdown is ON but not saved; it will not survive a restart"),
        "{}",
        stderr(&o)
    );
    let r = lockdown_records(&d);
    assert_eq!(r[0]["applied"], true, "{r:?}");
    assert_eq!(r[0]["saved"], false, "{r:?}");
    // It is in force now.
    let _ = api(&d);
    assert_eq!(d.of_kind("connector").last().unwrap()["rule"], "lockdown");
}
