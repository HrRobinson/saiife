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
    assert!(
        out.contains(&format!("  log: {}", dir.path().display())),
        "{out}"
    );
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

#[test]
fn verify_prints_last_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../audit/tests/fixtures/v2-locked/2026-11.jsonl");
    std::fs::copy(src, dir.path().join("2026-11.jsonl")).unwrap();
    let (code, out) = verify(dir.path());
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("audit chain: intact"), "{out}");
    assert!(out.contains("last checkpoint: seq 6"), "{out}");
    assert!(out.contains("key ed25519:"), "{out}");
    assert!(!out.contains("developer mode:"), "{out}");
}

// ---------------------------------------------------------------------------
// `--external <file|dir>`: the local log against a forwarded copy.

fn locked_fixture() -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../audit/tests/fixtures/v2-locked/2026-11.jsonl");
    std::fs::read_to_string(src).unwrap()
}

fn verify_external(audit: &Path, external: &Path) -> (i32, String) {
    let (mut c, _sb) = check_cmd(audit);
    let out = c
        .args(["audit", "verify", "--external"])
        .arg(external)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn external_copy_matches() {
    let dir = tempfile::tempdir().unwrap();
    let ext = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("2026-11.jsonl"), locked_fixture()).unwrap();
    let copy = ext.path().join("forwarded.jsonl");
    std::fs::write(&copy, locked_fixture()).unwrap();
    let (code, out) = verify_external(dir.path(), &copy);
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("audit chain: intact"), "{out}");
    assert!(out.contains("external copy: intact"), "{out}");
    assert!(
        out.contains("all 2 checkpoints of the external copy are in the local log"),
        "{out}"
    );
    assert!(
        out.contains(&format!("\n  log: {}\n", dir.path().display())),
        "{out}"
    );
    assert!(
        out.contains(&format!("\nexternal: {}\n", copy.display())),
        "{out}"
    );
}

#[test]
fn external_copy_shows_a_tail_rewritten_after_the_last_checkpoint() {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let ext = tempfile::tempdir().unwrap();
    let full = locked_fixture();
    let copy = ext.path().join("forwarded.jsonl");
    std::fs::write(&copy, &full).unwrap();
    // Keep seq 0..=4 (through the first checkpoint), forge seq 5..=7 with
    // a recomputed chain: records are not signed, so no key is needed.
    let mut l: Vec<String> = full.lines().take(5).map(String::from).collect();
    let template: serde_json::Value = serde_json::from_str(&l[3]).unwrap();
    for seq in 5..=7u64 {
        let mut v = template.clone();
        v["seq"] = seq.into();
        v["input"] = format!("harmless {seq}").into();
        let prev: String = Sha256::digest(l.last().unwrap().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        v["prev"] = prev.into();
        l.push(v.to_string());
    }
    std::fs::write(dir.path().join("2026-11.jsonl"), l.join("\n") + "\n").unwrap();
    assert_eq!(verify(dir.path()).0, 0, "the forged log chains on its own");
    let (code, out) = verify_external(dir.path(), &copy);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("local log REWRITTEN after seq 4: its seq 6 differs from the external copy"),
        "{out}"
    );
    assert!(
        out.contains("seq 7 differs between the local log and the last line"),
        "{out}"
    );
}

#[test]
fn external_copy_shows_a_cut_local_log() {
    let dir = tempfile::tempdir().unwrap();
    let ext = tempfile::tempdir().unwrap();
    let full = locked_fixture();
    let cut: String = full.lines().take(6).map(|l| format!("{l}\n")).collect();
    std::fs::write(dir.path().join("2026-11.jsonl"), cut).unwrap();
    std::fs::write(ext.path().join("2026-11.jsonl"), full).unwrap();
    assert_eq!(verify(dir.path()).0, 0, "the cut log is valid on its own");
    let (code, out) = verify_external(dir.path(), ext.path());
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("REWRITTEN OR CUT"), "{out}");
    assert!(out.contains("head seq 5"), "{out}");
    assert!(
        out.contains("local log CUT OFF: it ends at seq 5, the external copy reaches seq 7"),
        "{out}"
    );
}

#[test]
fn damaged_external_copy_is_labelled_as_such() {
    let dir = tempfile::tempdir().unwrap();
    let ext = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("2026-11.jsonl"), locked_fixture()).unwrap();
    let copy = ext.path().join("forwarded.jsonl");
    let mut l: Vec<String> = locked_fixture().lines().map(String::from).collect();
    l[2] = l[2].replacen("\"seq\":2,", "\"seq\":2, ", 1);
    std::fs::write(&copy, l.join("\n") + "\n").unwrap();
    let (code, out) = verify_external(dir.path(), &copy);
    assert_eq!(code, 1, "{out}");
    assert!(out.starts_with("audit chain: intact"), "{out}");
    assert!(out.contains("external copy damaged (1 problem)"), "{out}");
    assert!(out.contains("forwarded.jsonl line 4"), "{out}");
    assert!(!out.contains("REWRITTEN OR CUT"), "{out}");
}

#[test]
fn unreadable_external_copy_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("2026-11.jsonl"), locked_fixture()).unwrap();
    let (code, out) = verify_external(dir.path(), &dir.path().join("missing.jsonl"));
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("external copy: could not read it"), "{out}");
}

#[cfg(unix)]
#[test]
fn locked_mode_needs_the_audit_group() {
    if rustix::process::geteuid().is_root() {
        return; // root reads the audit files
    }
    let etc = tempfile::tempdir().unwrap();
    let audit = etc.path().join("audit");
    std::fs::create_dir(&audit).unwrap();
    let config = etc.path().join("config.toml");
    std::fs::write(
        &config,
        format!("version = 2\nlocked = true\n\n[audit]\ndir = {audit:?}\n"),
    )
    .unwrap();
    let (mut c, _sb) = check_cmd(&audit);
    let out = c
        .env_remove("SAIIFE_AUDIT_DIR")
        .env_remove("XDG_DATA_HOME")
        .args(["audit", "verify", "--system-config"])
        .arg(&config)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(
        text.contains("audit files need the saiife-audit group; ask an auditor"),
        "{text}"
    );

    // Developer mode (no `locked = true`) keeps the user's own log.
    std::fs::write(&config, "version = 2\n").unwrap();
    let (mut c, _sb) = check_cmd(&audit);
    let out = c
        .env_remove("SAIIFE_AUDIT_DIR")
        .env_remove("XDG_DATA_HOME")
        .args(["audit", "verify", "--system-config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}
