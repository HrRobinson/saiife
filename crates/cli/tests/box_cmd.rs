//! `saiife box ...` against a real locked-mode daemon (plan 34, Task 9) whose
//! boxes run on the fake VM (`fake-vmm` build, `SAIIFE_BOX_FAKE_VMM=1`). The
//! host is pinned to one default box with `SAIIFE_BOX_FAKE_SLOTS=1`.
//!
//! The project is a git repo (real git, no global or system config): spawn
//! snapshots it into a repo disk (plan 37), built by a fake `mke2fs` that
//! writes the ext4 magic and nothing else.
#![cfg(all(unix, feature = "fake-vmm"))]

mod common;

use common::daemon::{Opts, TestDaemon};
use serde_json::Value;
use std::fs;
use std::process::{Command, Output, Stdio};

fn daemon_with(slots: Option<u32>) -> TestDaemon {
    daemon_with_env(slots, Vec::new())
}

/// [`daemon_with`] plus `extra` daemon environment; the project is a git
/// repo (spawn snapshots it into a repo disk, plan 37).
fn daemon_with_env(slots: Option<u32>, extra: Vec<(String, String)>) -> TestDaemon {
    let mut env = vec![("SAIIFE_BOX_FAKE_VMM".to_string(), "1".to_string())];
    if let Some(n) = slots {
        env.push(("SAIIFE_BOX_FAKE_SLOTS".to_string(), n.to_string()));
    }
    env.extend(extra);
    let d = TestDaemon::start(Opts {
        env,
        ..Opts::default()
    });
    let project = d.path().join("project");
    fs::create_dir_all(&project).unwrap();
    git(&d, &["init", "-q", "-b", "main"]);
    fs::write(project.join("README"), "hello\n").unwrap();
    fs::create_dir_all(d.path().join("bin")).unwrap();
    exec(
        &d.path().join("bin/mke2fs"),
        // The image is the next-to-last argument.
        "#!/bin/sh\nfor a; do img=$last; last=$a; done\n\
         head -c 1080 /dev/zero > \"$img\" && printf '\\123\\357' >> \"$img\" \
         && head -c 4096 /dev/zero >> \"$img\"\n",
    );
    exec(
        &d.path().join("bin/mke2fs-fails"),
        "#!/bin/sh\necho 'mke2fs: no space' >&2\nexit 1\n",
    );
    d
}

fn exec(p: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(p, body).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Git's environment here: no global or system config, HOME in the world.
fn git_env(c: &mut Command, d: &TestDaemon) {
    c.env("HOME", d.path().join("home"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
}

/// Real git in the project; its stdout.
fn git(d: &TestDaemon, args: &[&str]) -> String {
    let mut c = Command::new("/usr/bin/git");
    c.arg("-C").arg(d.path().join("project")).args(args);
    git_env(&mut c, d);
    let o = c.output().unwrap();
    assert!(
        o.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// One slot.
fn world() -> TestDaemon {
    daemon_with(Some(1))
}

fn bx(d: &TestDaemon, args: &[&str]) -> Output {
    bx_with(d, args, &[])
}

/// `bx` with `extra` environment.
fn bx_with(d: &TestDaemon, args: &[&str], extra: &[(&str, std::path::PathBuf)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_saiife"));
    git_env(&mut c, d);
    c.env("XDG_CACHE_HOME", d.path().join("cache"))
        .env("SAIIFE_TOOL_MKE2FS", d.path().join("bin/mke2fs"));
    for (k, v) in extra {
        c.env(k, v);
    }
    c.arg("box")
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
    for col in [
        "ID", "STATE", "TEMPLATE", "REPO", "AGE", "DISK", "QUEUE", "TASK",
    ] {
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
    // M1 / I-C: every TestDaemon re-roots the locked box layout under its
    // own dir (`<daemon>/box-root`, debug-only seam), so a `boxes` build's
    // preflight never reads the host's install.
    let d = TestDaemon::start(Opts::default());
    let root = d.path().join("box-root");
    fs::create_dir_all(d.path().join("project")).unwrap();
    let o = bx(&d, &["ls"]);
    assert_eq!(code(&o), 5, "{}", err(&o));
    // Without the fake flag: a `boxes` build runs the real driver's
    // preflight (plan 35), which on a host without `system install --boxes`
    // names the install; any other build says boxes are not enabled (R38).
    if cfg!(feature = "boxes") {
        assert!(err(&o).contains("install --boxes"), "{}", err(&o));
        assert!(
            err(&o).contains(&root.display().to_string()),
            "the test root: {}",
            err(&o)
        );
    } else {
        assert!(
            err(&o).contains("boxes are not available in this version"),
            "{}",
            err(&o)
        );
        assert!(err(&o).contains("not enabled in this build"), "{}", err(&o));
    }
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

/// What is left under the CLI's staging root.
fn staging_left(d: &TestDaemon) -> Vec<std::path::PathBuf> {
    match fs::read_dir(d.path().join("cache/saiife/box-spawn")) {
        Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Plan 37: spawn snapshots the project into a repo disk, passes it and
/// its manifest to the daemon (which places both in the box dir), points
/// `refs/saiife/box-<id>/base` at the snapshot commit and removes its
/// staging.
#[test]
fn spawn_sends_repo_and_sets_base_ref() {
    let d = world();
    fs::write(d.path().join("project/new.txt"), "untracked\n").unwrap();
    let o = bx(&d, &["spawn", "--task", "t", "--timings"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    assert!(out(&o).starts_with("box b1 "), "{}", out(&o));
    for step in ["snapshot", "image", "snapshot commit", "spawn", "base ref"] {
        assert!(
            err(&o).contains(&format!("saiife: timing {step} ")),
            "{step}: {}",
            err(&o)
        );
    }
    let dir = d.state_dir().join("boxes/b1");
    let disk = fs::read(dir.join("repo.img")).unwrap();
    assert_eq!(&disk[1080..1082], &[0x53, 0xEF]);
    let base: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("base.json")).unwrap()).unwrap();
    assert_eq!(base["repo"], "project", "{base}");
    let entries: Vec<&String> = base["entries"].as_object().unwrap().keys().collect();
    assert_eq!(entries, ["README", "new.txt"], "{base}");
    let commit = base["snapshot_commit"].as_str().unwrap();
    let r = git(&d, &["rev-parse", "refs/saiife/box-b1/base"]);
    assert_eq!(r.trim(), commit);
    let tree = git(&d, &["ls-tree", "--name-only", commit]);
    assert_eq!(tree, "README\nnew.txt\n");
    assert!(staging_left(&d).is_empty(), "{:?}", staging_left(&d));
    let v = ls_json(&d);
    assert_eq!(v["boxes"][0]["repo"], "project", "{v}");
}

/// Every failure removes the staging: the daemon refusing the spawn (no
/// box, so no base ref) and the disk build failing.
#[test]
fn spawn_cleans_staging_on_error() {
    let d = world();
    let o = bx(&d, &["spawn", "--template", "nope"]);
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(err(&o).contains("nope"), "{}", err(&o));
    assert!(staging_left(&d).is_empty(), "{:?}", staging_left(&d));
    assert!(!d.state_dir().join("boxes/b1").exists());
    assert!(!git(&d, &["for-each-ref", "refs/saiife"]).contains("box-"));
    let fails = d.path().join("bin/mke2fs-fails");
    let o = bx_with(&d, &["spawn"], &[("SAIIFE_TOOL_MKE2FS", fails)]);
    assert_eq!(code(&o), 1, "{}", err(&o));
    assert!(err(&o).contains("no space"), "{}", err(&o));
    assert!(staging_left(&d).is_empty(), "{:?}", staging_left(&d));
    // Not a git repo: refused before anything is staged.
    let plain = d.path().join("plain");
    fs::create_dir_all(&plain).unwrap();
    let o = bx(&d, &["spawn", "--repo", plain.to_str().unwrap()]);
    assert_eq!(code(&o), 2, "{}", err(&o));
    assert!(staging_left(&d).is_empty());
    // The daemon has nothing of these.
    assert!(ls_json(&d)["boxes"].as_array().unwrap().is_empty());
}

#[test]
fn attach_prints_sanitized_lines() {
    let frames = serde_json::json!([{"snapshot": {"seq": 1, "rows": 40, "cols": 120,
        "lines": ["hello", "evil\u{1b}[31m\u{202e}rtl\u{85}\u{2028}x"], "cursor": [0, 0]}}]);
    let d = daemon_with_term(&frames.to_string());
    assert_eq!(code(&bx(&d, &["spawn"])), 0);
    let o = bx(&d, &["attach", "b1"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let t = out(&o);
    assert!(t.starts_with("box b1 ("), "{t}");
    assert!(
        t.contains("): read-only, q quits; type into it with saiife box say b1 \"…\""),
        "{t}"
    );
    assert!(t.contains("hello\n"), "{t}");
    assert!(
        t.contains("evil\\x1b[31m\\u{202E}rtl\\x85\\u{2028}x"),
        "{t}"
    );
    for bad in ['\u{1b}', '\u{202e}', '\u{85}', '\u{2028}'] {
        assert!(!t.contains(bad), "{t:?}");
    }
}

#[test]
fn attach_without_tty_prints_once() {
    let frames = serde_json::json!([
        {"snapshot": {"seq": 1, "rows": 40, "cols": 120, "lines": ["one"], "cursor": [0, 0]}},
        {"delta": {"seq": 2, "lines": [[1, "two"]], "cursor": [0, 0]}}]);
    let d = daemon_with_term(&frames.to_string());
    assert_eq!(code(&bx(&d, &["spawn"])), 0);
    let o = bx(&d, &["attach", "b1"]);
    assert_eq!(code(&o), 0, "{}", err(&o));
    let t = out(&o);
    assert!(t.contains("one\ntwo\n"), "{t}");
    assert!(
        !t.contains("\u{1b}"),
        "no clear sequence without a tty: {t:?}"
    );
    assert_eq!(code(&bx(&d, &["attach", "b9"])), 2);
}

fn daemon_with_term(term: &str) -> TestDaemon {
    daemon_with_env(
        Some(1),
        vec![("SAIIFE_BOX_FAKE_TERMINAL".to_string(), term.to_string())],
    )
}
