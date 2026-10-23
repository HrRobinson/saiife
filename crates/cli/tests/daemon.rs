//! `saiife daemon --system` end to end, as the current user with every path
//! in a temp dir (plan 9a, Task 6).
#![cfg(target_os = "linux")]

mod common;

use common::daemon::{
    append, dl, guard_rec, own_group, own_uid, refused_code, wait_for, Opts, TestDaemon,
};
use saiife_ipc::msg::MAX_RECORD_BYTES;
use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::{Duration, Instant};

fn out(o: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn assert_verifies(d: &TestDaemon) -> String {
    let v = d.verify();
    assert_eq!(v.status.code(), Some(0), "verify: {}", out(&v));
    out(&v)
}

#[test]
fn daemon_requires_system_flag() {
    for args in [&["daemon"][..], &["daemon", "--user"][..]] {
        let o = Command::new(env!("CARGO_BIN_EXE_saiife"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(err.contains("--system"), "{err}");
        assert!(err.contains("after v2.0"), "{err}");
    }
}

#[test]
fn daemon_refuses_wrong_user() {
    let d = TestDaemon::prepare(&Opts {
        user: Some("root".into()),
        ..Opts::default()
    });
    let o = d.run_to_exit();
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(out(&o).contains("per [daemon] user"), "{}", out(&o));
    assert!(!d.socket().exists());
}

#[test]
fn daemon_refuses_unlocked_config() {
    let d = TestDaemon::prepare(&Opts::default());
    let text = std::fs::read_to_string(d.config()).unwrap();
    std::fs::write(d.config(), text.replace("locked = true", "locked = false")).unwrap();
    let o = d.run_to_exit();
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(out(&o).contains("locked = true"), "{}", out(&o));
}

#[test]
fn daemon_refuses_bad_key_file() {
    use std::os::unix::fs::PermissionsExt;
    let d = TestDaemon::prepare(&Opts::default());
    let keys = d.state_dir().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = keys.join("audit.ed25519");
    std::fs::write(&key, [7u8; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = d.run_to_exit();
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(out(&o).contains("audit.ed25519"), "{}", out(&o));
}

#[test]
fn hello_answers_proto_1_and_mode_locked() {
    let d = TestDaemon::start(Opts::default());
    let c = d.client();
    let h = c.hello_answer();
    assert_eq!(h["proto"], json!(1));
    assert_eq!(h["mode"], json!("locked"));
    assert_eq!(h["daemon"], json!(env!("CARGO_PKG_VERSION")));
}

#[test]
fn append_returns_increasing_seq_and_chain_verifies() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    let mut last = 0;
    for i in 0..10 {
        let a = append(&mut c, guard_rec(&format!("echo {i}"))).unwrap();
        let seq = a["seq"].as_u64().unwrap();
        assert!(seq > last, "{seq} after {last}");
        last = seq;
    }
    assert_verifies(&d);
    let guards = d.of_kind("guard");
    assert_eq!(guards.len(), 10);
    for g in guards {
        assert_eq!(g["uid"], json!(own_uid()));
        assert_eq!(g["mode"], json!("locked"));
        assert_eq!(g["peer"]["pid"], json!(std::process::id()));
        assert!(g["peer"]["comm"].is_string(), "{g}");
    }
    // The daemon's own records.
    let start = &d.events("start")[0];
    assert_eq!(start["mode"], json!("locked"));
    assert_eq!(start["uid"], json!(own_uid()));
    assert_eq!(start["chain_check"], json!("ok"));
    assert!(start["policy"].as_str().unwrap().starts_with("sha256:"));
    let loaded = d.of_kind("policy");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0]["result"], json!("loaded"));
    assert_eq!(
        loaded[0]["files"][0]["name"],
        json!(d.config().display().to_string())
    );
    assert_eq!(loaded[0]["files"][0]["sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn append_overwrites_identity_fields() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    let mut rec = guard_rec("echo spoof");
    rec["uid"] = json!(0);
    rec["user"] = json!("root");
    rec["seq"] = json!(99);
    rec["prev"] = json!("ab".repeat(32));
    rec["host"] = json!("x");
    rec["mode"] = json!("developer");
    rec["v"] = json!(1);
    rec["peer"] = json!({"pid": 1, "comm": "init"});
    let seq = append(&mut c, rec).unwrap()["seq"].as_u64().unwrap();
    assert_ne!(seq, 99);
    let g = &d.of_kind("guard")[0];
    assert_eq!(g["uid"], json!(own_uid()));
    assert_eq!(g["user"], json!(common::daemon::own_user()));
    assert_eq!(g["seq"], json!(seq));
    assert_ne!(g["host"], json!("x"));
    assert_eq!(g["mode"], json!("locked"));
    assert_eq!(g["v"], json!(2));
    assert_eq!(g["peer"]["pid"], json!(std::process::id()));
    assert_verifies(&d);
}

#[test]
fn append_non_guard_kind_is_forbidden() {
    let d = TestDaemon::start(Opts::default());
    let before = d.records().len();
    let mut c = d.client();
    for kind in ["connector", "checkpoint", "genesis", "daemon"] {
        let mut rec = guard_rec("x");
        rec["kind"] = json!(kind);
        let e = append(&mut c, rec).unwrap_err();
        assert_eq!(refused_code(&e), "forbidden", "{kind}");
    }
    // Not a record at all, or a field of the wrong type: bad_request.
    let e = append(&mut c, json!({"nope": 1})).unwrap_err();
    assert_eq!(refused_code(&e), "bad_request");
    let mut rec = guard_rec("x");
    rec["decision"] = json!(42);
    let e = append(&mut c, rec).unwrap_err();
    assert_eq!(refused_code(&e), "bad_request");
    let e = c.call("audit.append", Map::new(), dl()).unwrap_err();
    assert_eq!(refused_code(&e), "bad_request");
    // Four refusals, one record: at most one notice per uid per minute.
    assert!(wait_for(Duration::from_secs(5), || d
        .events("forbidden")
        .len()
        == 1));
    let f = d.events("forbidden");
    assert_eq!(f.len(), 1);
    let reason = f[0]["reason"].as_str().unwrap();
    assert!(reason.contains(&format!("uid {} ", own_uid())), "{reason}");
    assert_eq!(d.records().len(), before + 1);
}

#[test]
fn rotate_key_forbidden_is_recorded_once() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    for _ in 0..2 {
        let e = c.call("audit.rotate_key", Map::new(), dl()).unwrap_err();
        assert_eq!(refused_code(&e), "forbidden");
    }
    assert!(wait_for(Duration::from_secs(5), || d
        .events("forbidden")
        .len()
        == 1));
    assert_eq!(d.events("forbidden").len(), 1);
    assert_verifies(&d);
}

fn raw(d: &TestDaemon) -> UnixStream {
    let s = UnixStream::connect(d.socket()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn send_frame(s: &mut UnixStream, v: &Value) {
    let b = serde_json::to_vec(v).unwrap();
    s.write_all(&(b.len() as u32).to_be_bytes()).unwrap();
    s.write_all(&b).unwrap();
}

fn read_frame(s: &mut UnixStream) -> Option<Value> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).ok()?;
    let mut b = vec![0u8; u32::from_be_bytes(h) as usize];
    s.read_exact(&mut b).ok()?;
    serde_json::from_slice(&b).ok()
}

/// Read until EOF; panics on a read timeout.
fn drain_to_eof(s: &mut UnixStream) -> Vec<u8> {
    let mut all = Vec::new();
    s.read_to_end(&mut all)
        .expect("connection should be closed");
    all
}

#[test]
fn first_frame_must_be_hello() {
    let d = TestDaemon::start(Opts::default());
    let mut s = raw(&d);
    send_frame(&mut s, &json!({"id": 1, "op": "status"}));
    let a = read_frame(&mut s).unwrap();
    assert_eq!(a["ok"], json!(false));
    assert_eq!(a["error"], json!("hello_required"));
    assert!(drain_to_eof(&mut s).is_empty());
}

#[test]
fn unknown_op_is_refused_and_connection_stays_usable() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    let e = c.call("no.such.op", Map::new(), dl()).unwrap_err();
    assert_eq!(refused_code(&e), "unknown_op");
    assert!(append(&mut c, guard_rec("after")).is_ok());
}

#[test]
fn oversized_frame_closes_connection() {
    let d = TestDaemon::start(Opts::default());
    let mut s = raw(&d);
    s.write_all(&1_048_577u32.to_be_bytes()).unwrap();
    let rest = drain_to_eof(&mut s);
    if !rest.is_empty() {
        let a: Value = serde_json::from_slice(&rest[4..]).unwrap();
        assert_eq!(a["error"], json!("bad_frame"));
        assert_eq!(a["id"], json!(0));
    }
    let mut c = d.client();
    assert!(append(&mut c, guard_rec("still up")).is_ok());
}

#[test]
fn half_frame_client_does_not_block_others() {
    let d = TestDaemon::start(Opts::default());
    let mut staller = raw(&d);
    staller.write_all(&[0, 0]).unwrap();
    let t0 = Instant::now();
    std::thread::sleep(Duration::from_millis(100));
    let mut c = d.client();
    let a0 = Instant::now();
    append(&mut c, guard_rec("other")).unwrap();
    assert!(a0.elapsed() < Duration::from_secs(1), "{:?}", a0.elapsed());
    drain_to_eof(&mut staller);
    let closed = t0.elapsed();
    assert!(
        closed >= Duration::from_secs(4) && closed < Duration::from_secs(8),
        "staller closed after {closed:?}"
    );
}

#[test]
fn parallel_clients_keep_one_chain() {
    let d = TestDaemon::start(Opts::default());
    let mut seqs: Vec<u64> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|t| {
                let d = &d;
                s.spawn(move || {
                    let mut c = d.client();
                    (0..50)
                        .map(|i| {
                            append(&mut c, guard_rec(&format!("t{t} {i}"))).unwrap()["seq"]
                                .as_u64()
                                .unwrap()
                        })
                        .collect::<Vec<u64>>()
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    seqs.sort();
    seqs.dedup();
    assert_eq!(seqs.len(), 400);
    assert_verifies(&d);
}

fn checkpoint_count(d: &TestDaemon) -> usize {
    d.of_kind("checkpoint").len()
}

#[test]
fn checkpoint_on_interval() {
    let d = TestDaemon::start(Opts {
        checkpoint_interval: "1s".into(),
        ..Opts::default()
    });
    let mut c = d.client();
    let seq = append(&mut c, guard_rec("one")).unwrap()["seq"]
        .as_u64()
        .unwrap();
    std::thread::sleep(Duration::from_millis(2500));
    let covering: Vec<Value> = d
        .of_kind("checkpoint")
        .into_iter()
        .filter(|r| r["head_seq"].as_u64().unwrap() >= seq)
        .collect();
    assert_eq!(covering.len(), 1, "{covering:?}");
    let n = checkpoint_count(&d);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(checkpoint_count(&d), n, "no records, no new checkpoint");
}

#[test]
fn checkpoint_after_every_n_records() {
    let d = TestDaemon::start(Opts {
        checkpoint_every: 5,
        ..Opts::default()
    });
    let mut c = d.client();
    for i in 0..12 {
        append(&mut c, guard_rec(&format!("n{i}"))).unwrap();
    }
    assert!(checkpoint_count(&d) >= 2);
    assert_verifies(&d);
}

#[test]
fn sigterm_writes_stop_and_checkpoint() {
    let mut d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    append(&mut c, guard_rec("before stop")).unwrap();
    d.signal("TERM");
    let st = d.wait_exit(Duration::from_secs(5)).expect("daemon exits");
    assert_eq!(st.code(), Some(0));
    let recs = d.records();
    let n = recs.len();
    assert_eq!(recs[n - 2]["kind"], json!("daemon"));
    assert_eq!(recs[n - 2]["event"], json!("stop"));
    assert_eq!(recs[n - 1]["kind"], json!("checkpoint"));
    assert!(!d.socket().exists());
    let v = assert_verifies(&d);
    assert!(v.contains("last checkpoint"), "{v}");
    let report = saiife_audit::verify(&d.audit_dir());
    assert!(report.checkpoints >= 1);

    // A start after a clean stop says so.
    d.spawn_and_wait();
    let starts = d.events("start");
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[1]["previous_clean_stop"], json!(true));
}

#[test]
fn restart_with_lost_key_after_clean_stop_is_clean() {
    let mut d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    append(&mut c, guard_rec("before stop")).unwrap();
    d.signal("TERM");
    let st = d.wait_exit(Duration::from_secs(5)).expect("daemon exits");
    assert_eq!(st.code(), Some(0));
    std::fs::remove_file(d.state_dir().join("keys/audit.ed25519")).unwrap();

    d.spawn_and_wait();
    let starts = d.events("start");
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[1]["previous_clean_stop"], json!(true));
    assert_eq!(d.of_kind("key_rotate").len(), 1);
    // The lost key is still reported.
    let v = d.verify();
    assert_eq!(v.status.code(), Some(1), "verify: {}", out(&v));
    let report = saiife_audit::verify(&d.audit_dir());
    assert!(
        report
            .breaks
            .iter()
            .any(|b| b.kind == saiife_audit::BreakKind::UnsignedKeyRotate),
        "{:?}",
        report.breaks
    );
}

#[test]
fn sigint_stops_cleanly_too() {
    let mut d = TestDaemon::start(Opts::default());
    d.signal("INT");
    let st = d.wait_exit(Duration::from_secs(5)).expect("daemon exits");
    assert_eq!(st.code(), Some(0));
    assert_eq!(d.events("stop").len(), 1);
}

#[test]
fn restart_after_kill_says_unclean() {
    let mut d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    append(&mut c, guard_rec("before kill")).unwrap();
    d.signal("KILL");
    d.wait_exit(Duration::from_secs(5)).expect("daemon dies");
    d.spawn_and_wait();
    let starts = d.events("start");
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[1]["previous_clean_stop"], json!(false));
    assert_eq!(d.of_kind("genesis").len(), 1, "same chain");
    let chain = d.of_kind("genesis")[0]["chain"].clone();
    assert_eq!(d.status()["chain"], chain);
    assert_verifies(&d);
}

#[test]
fn second_daemon_same_dirs_refused() {
    let d = TestDaemon::start(Opts::default());
    let o = d.run_to_exit();
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(
        out(&o).contains("holds the audit chain lock"),
        "{}",
        out(&o)
    );
    // The first one still answers.
    let mut c = d.client();
    assert!(append(&mut c, guard_rec("still mine")).is_ok());
}

#[test]
fn invalid_policy_at_start_still_accepts_audit() {
    let d = TestDaemon::start(Opts {
        extra: "[guard]\nbogus = 1\n".into(),
        ..Opts::default()
    });
    let inv = d.events("policy_invalid");
    assert_eq!(inv.len(), 1);
    assert!(
        inv[0]["reason"].as_str().unwrap().contains("bogus"),
        "{}",
        inv[0]
    );
    let mut c = d.client();
    assert!(append(&mut c, guard_rec("audit still works")).is_ok());
    let s = d.status();
    assert_eq!(s["policy_ok"], json!(false));
    assert_eq!(s["policy"], Value::Null);
    assert_verifies(&d);
}

fn policy_results(d: &TestDaemon, result: &str) -> usize {
    d.of_kind("policy")
        .iter()
        .filter(|r| r["result"] == json!(result))
        .count()
}

#[test]
fn sighup_reload_rejects_invalid_and_loads_valid() {
    let d = TestDaemon::start(Opts::default());
    let h1 = d.status()["policy"].clone();
    assert!(h1.as_str().unwrap().starts_with("sha256:"));

    d.write_config(&Opts {
        extra: "[guard]\nbogus = 1\n".into(),
        ..Opts::default()
    });
    d.signal("HUP");
    assert!(wait_for(Duration::from_secs(5), || policy_results(
        &d, "rejected"
    ) == 1));
    let s = d.status();
    assert_eq!(s["policy"], h1);
    assert_eq!(s["policy_ok"], json!(true));

    d.write_config(&Opts {
        extra: "[guard]\nbudget_ms = 60\n".into(),
        ..Opts::default()
    });
    d.signal("HUP");
    assert!(wait_for(Duration::from_secs(5), || policy_results(
        &d, "loaded"
    ) == 2));
    let h2 = d.status()["policy"].clone();
    assert_ne!(h2, h1);
    let last = d.of_kind("policy").pop().unwrap();
    assert_eq!(last["policy"], h2);
    assert_verifies(&d);
}

#[test]
fn rotate_key_needs_admin() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    let e = c.call("audit.rotate_key", Map::new(), dl()).unwrap_err();
    assert_eq!(refused_code(&e), "forbidden");

    d.write_config(&Opts {
        extra: format!("[admin]\ngroups = [{:?}]\n", own_group()),
        ..Opts::default()
    });
    d.signal("HUP");
    assert!(wait_for(Duration::from_secs(5), || policy_results(
        &d, "loaded"
    ) == 2));
    let mut c = d.client();
    let a = c.call("audit.rotate_key", Map::new(), dl()).unwrap();
    let key = a["key"].as_str().unwrap().to_string();
    assert!(key.starts_with("ed25519:"));
    assert!(a["seq"].as_u64().is_some());
    append(&mut c, guard_rec("after rotation")).unwrap();
    c.call("status", Map::new(), dl()).unwrap();
    let v = assert_verifies(&d);
    assert!(v.contains(&format!("signed with key {key}")), "{v}");
}

#[test]
fn status_reports_chain_and_policy() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    let seq = append(&mut c, guard_rec("s")).unwrap()["seq"]
        .as_u64()
        .unwrap();
    let s = d.status();
    assert_eq!(s["mode"], json!("locked"));
    assert_eq!(s["head_seq"], json!(seq));
    assert_eq!(s["head"].as_str().unwrap().len(), 64);
    assert!(s["chain"].is_string());
    assert!(s["policy"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(s["policy_ok"], json!(true));
    assert!(s["uptime_s"].as_u64().is_some());
    assert!(s.contains_key("last_checkpoint_seq"));
}

fn this_month() -> String {
    let r = guard_rec("now");
    r["ts"].as_str().unwrap()[..7].to_string()
}

#[test]
fn daemon_stamps_ts_and_keeps_client_ts() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    let long = format!("2001-01-01T00:00:00.000Z{}", "x".repeat(40));
    for ts in [
        "9999-12-31T23:59:59.999Z",
        "2001-01-01T00:00:00.000Z",
        "nonsense",
        &long,
    ] {
        let mut rec = guard_rec(&format!("ts {ts}"));
        rec["ts"] = json!(ts);
        append(&mut c, rec).unwrap();
    }
    append(&mut c, guard_rec("after")).unwrap();
    let month = this_month();
    let files: Vec<String> = std::fs::read_dir(d.audit_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".jsonl"))
        .collect();
    assert_eq!(files, [format!("{month}.jsonl")]);
    let guards = d.of_kind("guard");
    let client: Vec<&str> = guards
        .iter()
        .map(|g| g["client_ts"].as_str().unwrap())
        .collect();
    assert_eq!(client[0], "9999-12-31T23:59:59.999Z");
    assert_eq!(client[1], "2001-01-01T00:00:00.000Z");
    assert_eq!(client[2], "nonsense");
    assert_eq!(client[3].chars().count(), 32);
    for g in &guards {
        let ts = g["ts"].as_str().unwrap();
        assert!(ts.starts_with(&month), "{ts}");
        assert_eq!(ts.len(), 24, "{ts}");
        assert!(ts.ends_with('Z'));
    }
    assert_verifies(&d);
}

#[test]
fn hello_without_proto_is_bad_request() {
    let d = TestDaemon::start(Opts::default());
    let mut s = raw(&d);
    send_frame(&mut s, &json!({"id": 1, "op": "hello"}));
    let a = read_frame(&mut s).unwrap();
    assert_eq!(a["error"], json!("bad_request"));
    assert!(drain_to_eof(&mut s).is_empty());
}

#[test]
fn silent_client_is_closed_after_hello_deadline() {
    let d = TestDaemon::start(Opts::default());
    let mut silent = raw(&d);
    let t0 = Instant::now();
    let mut c = d.client();
    append(&mut c, guard_rec("other")).unwrap();
    drain_to_eof(&mut silent);
    let closed = t0.elapsed();
    assert!(
        closed >= Duration::from_secs(4) && closed < Duration::from_secs(8),
        "silent client closed after {closed:?}"
    );
    // Greeted clients have no idle timeout.
    std::thread::sleep(Duration::from_millis(500));
    append(&mut c, guard_rec("still greeted")).unwrap();
}

#[test]
fn connection_cap_per_uid_is_32() {
    let d = TestDaemon::start(Opts::default());
    let mut held: Vec<_> = (0..32).map(|_| d.client()).collect();
    let mut s = raw(&d);
    let a = read_frame(&mut s).expect("a busy answer");
    assert_eq!(a["error"], json!("busy"));
    assert_eq!(a["id"], json!(0));
    assert!(drain_to_eof(&mut s).is_empty());
    for c in held.iter_mut() {
        append(c, guard_rec("held")).unwrap();
    }
    assert!(wait_for(Duration::from_secs(3), || d
        .events("rate_limited")
        .len()
        == 1));
    held.pop();
    // A freed slot is usable again (the close may take a moment to land).
    assert!(wait_for(Duration::from_secs(3), || d.try_client().is_ok()));
    // Still one rate_limited record within the minute.
    let mut s = raw(&d);
    let _ = read_frame(&mut s);
    drop(held);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(d.events("rate_limited").len(), 1);
}

#[test]
fn created_socket_dir_and_socket_modes() {
    use std::os::unix::fs::PermissionsExt;
    let d = TestDaemon::start(Opts::default());
    let dm = std::fs::metadata(d.socket_dir())
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    let sm = std::fs::symlink_metadata(d.socket())
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(dm, 0o755);
    assert_eq!(sm, 0o666);
}

#[test]
fn foreign_socket_path_is_left_alone() {
    let d = TestDaemon::prepare(&Opts::default());
    std::fs::create_dir_all(d.socket_dir()).unwrap();
    std::fs::write(d.socket(), "not a socket").unwrap();
    let o = d.run_to_exit();
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(out(&o).contains("not a socket"), "{}", out(&o));
    assert_eq!(std::fs::read_to_string(d.socket()).unwrap(), "not a socket");
}

#[test]
fn symlinked_socket_path_is_left_alone() {
    let d = TestDaemon::prepare(&Opts::default());
    std::fs::create_dir_all(d.socket_dir()).unwrap();
    let target = d.path().join("elsewhere");
    std::fs::write(&target, "x").unwrap();
    std::os::unix::fs::symlink(&target, d.socket()).unwrap();
    let o = d.run_to_exit();
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(std::fs::symlink_metadata(d.socket())
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn writable_socket_dir_refuses_start() {
    use std::os::unix::fs::PermissionsExt;
    let d = TestDaemon::prepare(&Opts::default());
    std::fs::create_dir_all(d.socket_dir()).unwrap();
    std::fs::set_permissions(d.socket_dir(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let o = d.run_to_exit();
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(
        out(&o).contains("writable by group or others"),
        "{}",
        out(&o)
    );
}

#[test]
fn reload_of_unlocked_config_warns() {
    let d = TestDaemon::start(Opts::default());
    let text = d
        .config_text(&Opts::default())
        .replace("locked = true", "locked = false");
    std::fs::write(d.config(), text).unwrap();
    d.signal("HUP");
    assert!(wait_for(Duration::from_secs(5), || !d
        .events("reload_warning")
        .is_empty()));
    let w = &d.events("reload_warning")[0];
    assert!(w["reason"].as_str().unwrap().contains("locked"), "{w}");
}

/// A record above `MAX_RECORD_BYTES` (64 KiB) serialized is refused (I2): 1 000 of them a
/// second would fill the audit volume for everyone.
#[test]
fn oversized_record_is_bad_request() {
    let d = TestDaemon::start(Opts::default());
    let before = d.records().len();
    let mut c = d.client();
    // `rec` padded to exactly `size` bytes serialized.
    let padded = |size: usize| {
        let mut rec = guard_rec("x");
        rec["pad"] = json!("");
        let base = serde_json::to_vec(&rec).unwrap().len();
        rec["pad"] = json!("p".repeat(size - base));
        assert_eq!(serde_json::to_vec(&rec).unwrap().len(), size);
        rec
    };
    let e = append(&mut c, padded(MAX_RECORD_BYTES + 1)).unwrap_err();
    assert_eq!(refused_code(&e), "bad_request");
    assert_eq!(d.records().len(), before);
    // Exactly at the cap is fine, and the connection stays usable.
    append(&mut c, padded(MAX_RECORD_BYTES)).unwrap();
    assert_eq!(d.records().len(), before + 1);
}

/// The writer thread dying outside a stop takes the daemon down with a
/// non-zero exit (I4), so systemd restarts it instead of a daemon that
/// answers `internal` forever.
#[test]
fn writer_death_exits_the_daemon() {
    let mut d = TestDaemon::prepare(&Opts::default());
    d.spawn_and_wait_with(&[("SAIIFE_DAEMON_FAULT", "writer_panic")]);
    let mut c = d.client();
    // `internal`, or no answer at all when the daemon exits first.
    match append(&mut c, guard_rec("x")) {
        Ok(a) => panic!("acked by a dead writer: {a:?}"),
        Err(saiife_ipc::client::ClientError::Refused { code, .. }) => assert_eq!(code, "internal"),
        Err(_) => {}
    }
    let st = d
        .wait_exit(Duration::from_secs(5))
        .unwrap_or_else(|| panic!("daemon still running: {}", d.stderr_text()));
    assert!(!st.success(), "{st:?}");
    assert!(
        d.stderr_text().contains("the audit writer stopped"),
        "{}",
        d.stderr_text()
    );
    assert!(std::fs::symlink_metadata(d.socket()).is_err());
}

/// Writer settings are fixed at start: a reload that changes them says so
/// (M5).
#[test]
fn reload_of_writer_settings_warns() {
    let d = TestDaemon::start(Opts::default());
    let text = d.config_text(&Opts {
        checkpoint_every: 5,
        checkpoint_interval: "1m".into(),
        extra: String::new(),
        ..Opts::default()
    });
    let text = text.replace("[audit]\n", "[audit]\nfsync = \"always\"\n");
    std::fs::write(d.config(), text).unwrap();
    d.signal("HUP");
    assert!(wait_for(Duration::from_secs(5), || !d
        .events("reload_warning")
        .is_empty()));
    let w = d.events("reload_warning")[0]["reason"]
        .as_str()
        .unwrap()
        .to_string();
    for k in ["checkpoint_every", "checkpoint_interval", "fsync"] {
        assert!(w.contains(k), "{k}: {w}");
    }
}
