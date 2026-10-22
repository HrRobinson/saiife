//! `saiife audit verify` over logs written by real hook calls.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn check_cmd(audit: &Path) -> (Command, tempfile::TempDir) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let sandbox = common::hermetic(&mut cmd, audit);
    (cmd, sandbox)
}

fn payload(cmd: &str) -> String {
    serde_json::json!({
        "session_id": "s", "cwd": common::FIXTURE_CWD,
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": { "command": cmd }
    })
    .to_string()
}

fn hook(audit: &Path, cmd: &str) {
    let home = common::FixtureHome::new();
    let (mut c, _sb) = check_cmd(audit);
    let mut child = c
        .args(["check", "--hook-exit", "--agent", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(home.real(&payload(cmd)).as_bytes())
        .unwrap();
    child.wait().unwrap();
}

fn verify(audit: &Path) -> (i32, String) {
    let (mut c, _sb) = check_cmd(audit);
    let out = c.args(["audit", "verify"]).output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn month_file(audit: &Path) -> std::path::PathBuf {
    std::fs::read_dir(audit)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .unwrap()
}

#[test]
fn verify_empty_log_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    let (code, out) = verify(dir.path());
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("audit chain: intact"), "{out}");
}

#[test]
fn parallel_hooks_then_verify_is_intact() {
    let dir = tempfile::tempdir().unwrap();
    let workers: Vec<_> = (0..6)
        .map(|w| {
            let p = dir.path().to_path_buf();
            std::thread::spawn(move || {
                for i in 0..5 {
                    hook(&p, &format!("echo {w} {i}"));
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let (code, out) = verify(dir.path());
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("audit chain: intact"), "{out}");
    assert!(out.contains("records: 31 chained "), "{out}");
}

#[test]
fn edited_log_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..3 {
        hook(dir.path(), &format!("echo {i}"));
    }
    let f = month_file(dir.path());
    let body = std::fs::read_to_string(&f).unwrap();
    std::fs::write(&f, body.replace("echo 1", "echo X")).unwrap();
    let (code, out) = verify(dir.path());
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("BROKEN") && out.contains("line"), "{out}");
}

#[test]
fn unreadable_log_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("audit");
    std::fs::write(&file, "x").unwrap();
    let (code, out) = verify(&file);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("could not read the log"), "{out}");
}

#[test]
fn upgrade_from_v1_log() {
    let dir = tempfile::tempdir().unwrap();
    let now = time::OffsetDateTime::now_utc();
    let name = "2020-01.jsonl";
    let old = format!(
        "{{\"ts\":\"{}\",\"agent\":\"claude\",\"project\":\"/p\",\"tool\":\"Bash\",\"input\":\"ls\",\"decision\":\"allow\",\"saiife\":\"0.1.0\"}}\n",
        now.format(&time::format_description::well_known::Rfc3339).unwrap()
    );
    std::fs::write(dir.path().join(name), old).unwrap();
    hook(dir.path(), "echo new");
    let (code, out) = verify(dir.path());
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("not chained (v1)"), "{out}");
}

#[test]
fn verify_prints_no_record_content() {
    let dir = tempfile::tempdir().unwrap();
    hook(dir.path(), "echo \u{1b}[31msecretword");
    let (code, out) = verify(dir.path());
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(!out.contains("secretword"), "{out}");
}
