//! `saiife box ...` against a real locked-mode daemon (plan 34, Task 9) whose
//! boxes run on the fake VM (`fake-vmm` build, `SAIIFE_BOX_FAKE_VMM=1`). The
//! host is pinned to one default box with `SAIIFE_BOX_FAKE_SLOTS=1`.
#![cfg(all(unix, feature = "fake-vmm"))]

mod common;

use common::daemon::{Opts, TestDaemon};
use serde_json::Value;
use std::fs;
use std::process::{Command, Output, Stdio};

fn daemon_with(slots: Option<u32>) -> TestDaemon {
    let mut env = vec![("SAIIFE_BOX_FAKE_VMM".to_string(), "1".to_string())];
    if let Some(n) = slots {
        env.push(("SAIIFE_BOX_FAKE_SLOTS".to_string(), n.to_string()));
    }
    let d = TestDaemon::start(Opts {
        env,
        ..Opts::default()
    });
    fs::create_dir_all(d.path().join("project")).unwrap();
    d
}

/// One slot.
fn world() -> TestDaemon {
    daemon_with(Some(1))
}

fn bx(d: &TestDaemon, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("box")
        .arg("--system-config")
        .arg(d.config())
        .args(args)
        .env("HOME", d.path().join("home"))
        .env("XDG_RUNTIME_DIR", d.path().join("no-runtime"))
        .env("XDG_CONFIG_HOME", d.path().join("home/.config"))
        .env("PATH", "/usr/bin:/bin")
        .env("DBUS_SESSION_BUS_ADDRESS", d.path().join("no-bus"))
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", d.audit_dir())
        .current_dir(d.path().join("project"))
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}
fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn ls_json(d: &TestDaemon) -> Value {
    let o = bx(d, &["ls", "--json"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    serde_json::from_str(&out(&o)).unwrap()
}

fn state_of(d: &TestDaemon, id: &str) -> String {
    let v = ls_json(d);
    v["boxes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["id"] == id)
        .unwrap_or_else(|| panic!("no {id} in {v}"))["state"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A spawned box is `starting` until the fake VM's guest says ready, at the
/// daemon's next tick (5 s).
fn running(d: &TestDaemon, id: &str) {
    assert!(
        common::daemon::wait_for(common::daemon::HANG_GUARD, || {
            std::thread::sleep(std::time::Duration::from_millis(250));
            state_of(d, id) == "running"
        }),
        "{id} never ran"
    );
}

#[test]
fn spawn_then_ls_shows_the_box() {
    let d = world();
    let o = bx(&d, &["spawn", "--task", "fix the tests"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).starts_with("box b1 "), "{}", out(&o));
    let o = bx(&d, &["ls"]);
    assert_eq!(code(&o), 0);
    let t = out(&o);
    let head = t.lines().next().unwrap();
    for col in ["ID", "STATE", "TEMPLATE", "REPO", "AGE", "QUEUE", "TASK"] {
        assert!(head.contains(col), "{head}");
    }
    assert!(t.contains("b1"), "{t}");
    assert!(t.contains("claude-code"), "{t}");
    assert!(t.contains("project"), "{t}");
    assert!(t.contains("fix the tests"), "{t}");
    assert!(t.contains("slots: 0 of 1 free"), "{t}");
}

#[test]
fn ls_json_shape() {
    let d = world();
    bx(&d, &["spawn"]);
    let v = ls_json(&d);
    assert!(v["boxes"].is_array(), "{v}");
    assert_eq!(v["slots_total"], 1, "{v}");
    assert_eq!(v["slots_free"], 0, "{v}");
    assert_eq!(v["boxes"][0]["id"], "b1");
}

#[test]
fn full_machine_queues_and_now_refuses() {
    let d = world();
    assert_eq!(code(&bx(&d, &["spawn"])), 0);
    let o = bx(&d, &["spawn"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).contains("box b2 queued"), "{}", out(&o));
    assert!(out(&o).contains("queue position 1"), "{}", out(&o));
    let o = bx(&d, &["spawn", "--now"]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("busy"), "{}", err(&o));
    // Cancel the queued box; then reorder with it gone is refused.
    let o = bx(&d, &["stop", "b2"]);
    assert_eq!(code(&o), 2, "stop of a queued box is wrong_state");
    let o = bx(&d, &["discard", "b2", "--yes"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
}

#[test]
fn stop_twice_is_ok() {
    let d = world();
    bx(&d, &["spawn"]);
    running(&d, "b1");
    for _ in 0..2 {
        let o = bx(&d, &["stop", "b1"]);
        assert_eq!(code(&o), 0, "{}", err(&o));
    }
    assert_eq!(state_of(&d, "b1"), "done");
}

#[test]
fn pause_resume_say_done_roundtrip() {
    let d = world();
    bx(&d, &["spawn"]);
    running(&d, "b1");
    let o = bx(&d, &["say", "b1", "keep going"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(code(&bx(&d, &["pause", "b1"])), 0);
    assert_eq!(state_of(&d, "b1"), "paused");
    assert_eq!(code(&bx(&d, &["resume", "b1"])), 0);
    assert_eq!(state_of(&d, "b1"), "running");
    let o = bx(&d, &["done", "b1"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert_eq!(state_of(&d, "b1"), "done");
    let o = bx(&d, &["gc"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
}

#[test]
fn discard_without_tty_or_yes_refuses() {
    let d = world();
    bx(&d, &["spawn"]);
    running(&d, "b1");
    bx(&d, &["stop", "b1"]);
    let o = bx(&d, &["discard", "b1"]);
    assert_eq!(code(&o), 2);
    assert!(err(&o).contains("--yes"), "{}", err(&o));
    assert_eq!(state_of(&d, "b1"), "done", "nothing was discarded");
    let o = bx(&d, &["discard", "b1", "--yes"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
}

#[test]
fn revise_running_is_exit_2_wrong_state() {
    let d = world();
    bx(&d, &["spawn"]);
    running(&d, "b1");
    let o = bx(&d, &["revise", "b1", "please redo it"]);
    assert_eq!(code(&o), 2);
    assert!(!err(&o).is_empty());
}

#[test]
fn unknown_box_is_exit_2() {
    let d = world();
    let o = bx(&d, &["pause", "b9"]);
    assert_eq!(code(&o), 2, "{}", err(&o));
    let o = bx(&d, &["pause", "not an id"]);
    assert_eq!(code(&o), 2, "{}", err(&o));
}

#[test]
fn hostile_task_is_sanitized_in_ls() {
    let d = world();
    let o = bx(&d, &["spawn", "--task", "a\u{202e}b"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let t = out(&bx(&d, &["ls"]));
    assert!(t.contains("a\\u{202E}b"), "{t:?}");
    assert!(!t.contains('\u{202e}'), "{t:?}");
    let o = bx(&d, &["spawn", "--task", "bad\x1bthing"]);
    assert_eq!(code(&o), 2, "{}", err(&o));
}

#[test]
fn json_output_is_ascii_and_round_trips_a_hostile_task() {
    let d = world();
    let task = "a\u{202e}b \u{1F600}";
    assert_eq!(code(&bx(&d, &["spawn", "--task", task])), 0);
    let o = bx(&d, &["ls", "--json"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let raw = out(&o);
    assert!(raw.is_ascii(), "{raw:?}");
    assert!(!raw.contains('\u{202e}'), "{raw:?}");
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["boxes"][0]["task"], task, "{v}");
}

#[test]
fn long_task_is_cut_to_40_chars() {
    let d = world();
    bx(&d, &["spawn", "--task", &"x".repeat(100)]);
    let t = out(&bx(&d, &["ls"]));
    assert!(t.contains(&format!("{}…", "x".repeat(39))), "{t}");
    assert!(!t.contains(&"x".repeat(41)), "{t}");
}

#[test]
fn templates_lists_builtin() {
    let d = world();
    let o = bx(&d, &["templates"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).contains("claude-code"), "{}", out(&o));
    let o = bx(&d, &["templates", "--json"]);
    let v: Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v["templates"][0]["name"], "claude-code", "{v}");
    assert!(v["warnings"].is_array(), "{v}");
}

#[test]
fn run_agent_alias_spawns() {
    let d = world();
    let o = bx(&d, &["run-agent", "--task", "t"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).starts_with("box b1 "), "{}", out(&o));
}

#[test]
fn reorder_queue() {
    let d = world();
    for _ in 0..3 {
        bx(&d, &["spawn"]);
    }
    let o = bx(&d, &["reorder", "b3", "b2"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let v = ls_json(&d);
    let pos = |id: &str| {
        v["boxes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["id"] == id)
            .and_then(|b| b["queue_pos"].as_u64())
    };
    assert_eq!(pos("b3"), Some(1), "{v}");
    assert_eq!(pos("b2"), Some(2), "{v}");
    // A list that misses a queued box is refused.
    let o = bx(&d, &["reorder", "b3"]);
    assert_eq!(code(&o), 2, "{}", err(&o));
}

#[test]
fn unavailable_without_fake_env_is_exit_5() {
    let d = TestDaemon::start(Opts::default());
    fs::create_dir_all(d.path().join("project")).unwrap();
    let o = bx(&d, &["ls"]);
    assert_eq!(code(&o), 5, "{}", err(&o));
    assert!(
        err(&o).contains("boxes are not available in this version"),
        "{}",
        err(&o)
    );
}

#[test]
fn daemon_not_running_is_exit_5() {
    let d = world();
    let cfg = d.path().join("etc/config-gone.toml");
    fs::copy(d.config(), &cfg).unwrap();
    // A config whose socket dir holds no daemon.
    let text = fs::read_to_string(&cfg)
        .unwrap()
        .replace("/run\"", "/run-nobody\"");
    fs::write(&cfg, text).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["box", "--system-config"])
        .arg(&cfg)
        .arg("ls")
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert_eq!(code(&o), 5, "{}", err(&o));
}

/// R29: a box whose VM is gone after a daemon restart is a `box` record of
/// the new daemon (the fake VMM forgets every VM when the daemon stops).
#[test]
fn restart_recovery_is_recorded() {
    let mut d = world();
    assert_eq!(code(&bx(&d, &["spawn"])), 0);
    running(&d, "b1");
    d.signal("TERM");
    assert!(d.wait_exit(common::daemon::HANG_GUARD).is_some());
    d.spawn_and_wait_with(&[("SAIIFE_BOX_FAKE_VMM", "1"), ("SAIIFE_BOX_FAKE_SLOTS", "1")]);
    assert_eq!(state_of(&d, "b1"), "done");
    let recs = d.of_kind("box");
    let lost: Vec<&Value> = recs
        .iter()
        .filter(|r| r["reason"] == "vm lost after restart")
        .collect();
    assert_eq!(lost.len(), 1, "{recs:?}");
    let r = lost[0];
    assert_eq!(r["action"], "tick");
    assert_eq!(r["via"], "tick");
    assert_eq!(r["box"], "b1");
    assert_eq!(r["from"], "running");
    assert_eq!(r["to"], "done");
}
