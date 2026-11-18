//! Plan 45 Task 7: `saiife __blind-calc`, the sandboxed calculator process.
//! Each test spawns the debug `saiife` binary with one job frame on stdin and
//! reads one answer frame from stdout. On a kernel without Landlock every job
//! must be refused with `sandbox_unavailable` (fail closed): the tests check
//! that instead and say so.
#![cfg(target_os = "linux")]

// The shield executor tests' fixture (it allows its own dead code).
#[path = "../../shield/tests/common/mod.rs"]
mod common;

use saiife_shield::calc::{CellValue, ResultSet};
use saiife_shield::calc_proto::{
    read_frame, write_frame, CalcAnswer, CalcJob, CALC_JOB_VERSION, CLASS_SANDBOX_UNAVAILABLE,
    CLASS_SNAPSHOT_MISMATCH, MAX_ANSWER_BYTES, MAX_JOB_BYTES,
};
use saiife_shield::snapshot::hash_file;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BALANCE: &str = "SELECT SUM(i.amount) AS owed, c.credit_limit FROM invoices i \
    JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.status = 'open'";

fn scratch() -> tempfile::TempDir {
    match std::env::var_os("SAIIFE_TEST_TMP") {
        Some(d) => tempfile::tempdir_in(d).unwrap(),
        None => tempfile::tempdir().unwrap(),
    }
}

/// The shield executor fixture, written to a snapshot file.
fn snapshot(dir: &Path) -> PathBuf {
    let path = dir.join("snapshot.sqlite");
    let db = common::fixture();
    db.execute("VACUUM INTO ?1", [path.to_str().unwrap()])
        .unwrap();
    path
}

fn job(snapshot: &Path, method: &str) -> CalcJob {
    let mut p = common::entity(1);
    // The daemon strips the display before the job is written.
    p.display = String::new();
    CalcJob {
        v: CALC_JOB_VERSION,
        snapshot: snapshot.to_path_buf(),
        snapshot_sha256: hash_file(snapshot).unwrap(),
        schema: common::schema(),
        public: common::public(),
        method: method.into(),
        checks: vec![],
        params: vec![p],
        caps: Default::default(),
    }
}

/// Runs the calculator on raw stdin bytes; exit code and stdout.
fn run_raw(input: Vec<u8>, tmp: &Path) -> (i32, Vec<u8>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("__blind-calc")
        .env("TMPDIR", tmp)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // The calculator may stop reading early (an oversized frame): a broken
    // pipe here is expected and ignored.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    let status = child.wait().unwrap();
    writer.join().unwrap();
    (status.code().unwrap_or(-1), out, err)
}

fn run(job: &CalcJob, tmp: &Path) -> CalcAnswer {
    let mut frame = Vec::new();
    write_frame(&mut frame, job, MAX_JOB_BYTES).unwrap();
    let (code, out, err) = run_raw(frame, tmp);
    assert_eq!(code, 0, "stderr: {err}");
    let mut r: &[u8] = &out;
    let a: CalcAnswer = read_frame(&mut r, MAX_ANSWER_BYTES).unwrap();
    assert!(r.is_empty(), "one answer frame only");
    a
}

fn landlock() -> bool {
    saiife_system::sandbox::landlock_abi() > 0
}

/// Without Landlock every job is refused, never run unconfined.
fn refused_without_landlock(a: &CalcAnswer, test: &str) -> bool {
    if landlock() {
        return false;
    }
    eprintln!("{test}: skipped: this kernel has no Landlock; checked the refusal instead");
    match a {
        CalcAnswer::Err {
            class, confinement, ..
        } => {
            assert_eq!(class, CLASS_SANDBOX_UNAVAILABLE);
            assert!(confinement.is_none());
        }
        CalcAnswer::Ok { .. } => panic!("ran a method without Landlock"),
    }
    true
}

fn ok(a: CalcAnswer) -> (ResultSet, saiife_shield::calc_proto::ConfinementInfo) {
    match a {
        CalcAnswer::Ok {
            result,
            confinement,
        } => (result, confinement),
        CalcAnswer::Err { class, .. } => panic!("refused: {class}"),
    }
}

fn err_class(a: &CalcAnswer) -> &str {
    match a {
        CalcAnswer::Err { class, .. } => class,
        CalcAnswer::Ok { result, .. } => panic!("expected a refusal, got {result:?}"),
    }
}

#[test]
fn calc_answers_a_job() {
    let d = scratch();
    let snap = snapshot(d.path());
    let a = run(&job(&snap, BALANCE), d.path());
    if refused_without_landlock(&a, "calc_answers_a_job") {
        return;
    }
    let (rs, conf) = ok(a);
    assert_eq!(rs.rows.len(), 1);
    assert_eq!(rs.rows[0][0], CellValue::Real(600.0));
    assert_eq!(rs.rows[0][1], CellValue::Real(5000.0));
    assert!(conf.landlock_abi > 0);
    assert!(conf.seccomp);
    assert_eq!(conf.net_denied, conf.landlock_abi >= 4);
    assert_eq!(conf.scopes, conf.landlock_abi >= 6);
    eprintln!("confinement: {conf:?}");
}

#[test]
fn calc_rejects_bad_method() {
    let d = scratch();
    let snap = snapshot(d.path());
    let a = run(
        &job(
            &snap,
            "SELECT SUM(x.amount) AS owed FROM secrets x WHERE x.id = :p1",
        ),
        d.path(),
    );
    if refused_without_landlock(&a, "calc_rejects_bad_method") {
        return;
    }
    assert_eq!(err_class(&a), "unknown_table");
    let CalcAnswer::Err {
        empty_for,
        confinement,
        ..
    } = a
    else {
        unreachable!()
    };
    assert_eq!(empty_for, None);
    assert!(confinement.is_some_and(|c| c.seccomp));
}

#[test]
fn calc_checks_snapshot_hash() {
    let d = scratch();
    let snap = snapshot(d.path());
    let mut j = job(&snap, BALANCE);
    j.snapshot_sha256 = format!("sha256:{}", "0".repeat(64));
    let a = run(&j, d.path());
    if refused_without_landlock(&a, "calc_checks_snapshot_hash") {
        return;
    }
    assert_eq!(err_class(&a), CLASS_SNAPSHOT_MISMATCH);
    // A snapshot that is not there at all, or not a file: `runtime_error`,
    // before any rule is made, with no path or error text in it.
    for gone in [d.path().join("gone.sqlite"), d.path().to_path_buf()] {
        let mut j = job(&snap, BALANCE);
        j.snapshot = gone;
        let a = run(&j, d.path());
        assert_eq!(
            a,
            CalcAnswer::Err {
                class: "runtime_error".into(),
                empty_for: None,
                confinement: None,
            }
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn calc_cannot_escape() {
    let d = scratch();
    let snap = snapshot(d.path());
    let mut j = job(&snap, BALANCE);
    j.v = saiife_shield::calc_proto::PROBE_JOB_VERSION;
    let a = run(&j, d.path());
    if refused_without_landlock(&a, "calc_cannot_escape") {
        return;
    }
    let (rs, conf) = ok(a);
    assert_eq!(rs.columns, ["probe", "outcome"]);
    let got: Vec<(String, String)> = rs
        .rows
        .iter()
        .map(|r| match (&r[0], &r[1]) {
            (CellValue::Text(p), CellValue::Text(o)) => (p.clone(), o.clone()),
            other => panic!("{other:?}"),
        })
        .collect();
    let probes: Vec<&str> = got.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        probes,
        [
            "read /etc/passwd",
            "open a TCP socket",
            "write $TMPDIR/x",
            // Denied at the fork already (clone3 EPERM, NPROC 0); the
            // allowlist unit tests are the execve proof.
            "spawn /bin/true",
            "unshare a namespace",
            "open a pidfd",
            "set O_ASYNC (fcntl F_SETFL)",
            "read the snapshot",
        ]
    );
    for (p, o) in &got[..7] {
        assert_eq!(o, "denied", "{p}");
    }
    // The control: the one file it may read.
    assert_eq!(got[7].1, "allowed");
    assert!(!d.path().join("x").exists());
    eprintln!("confinement: {conf:?}");
}

#[test]
fn calc_frames_are_bounded() {
    let d = scratch();
    // A 2 MiB job: refused from its length alone, before any confinement.
    let len: u32 = 2 * 1024 * 1024;
    let mut input = len.to_be_bytes().to_vec();
    input.extend(std::iter::repeat_n(b' ', len as usize));
    let (code, out, err) = run_raw(input, d.path());
    assert_eq!(code, 0, "stderr: {err}");
    let mut r: &[u8] = &out;
    let a: CalcAnswer = read_frame(&mut r, MAX_ANSWER_BYTES).unwrap();
    assert_eq!(
        a,
        CalcAnswer::Err {
            class: "runtime_error".into(),
            empty_for: None,
            confinement: None,
        }
    );
    // Not JSON, an empty stdin: the same, with no input echoed back.
    for input in [b"\x00\x00\x00\x05hello".to_vec(), Vec::new()] {
        let (code, out, _) = run_raw(input, d.path());
        assert_eq!(code, 0);
        let mut r: &[u8] = &out;
        let a: CalcAnswer = read_frame(&mut r, MAX_ANSWER_BYTES).unwrap();
        assert_eq!(err_class(&a), "runtime_error");
        assert!(!String::from_utf8_lossy(&out).contains("hello"));
    }
}

/// M4: a panic inside the confined part answers `runtime_error` (with the
/// confinement), exit 0, and its message reaches neither the frame nor
/// stderr.
#[cfg(debug_assertions)]
#[test]
fn calc_panic_answers_runtime_error() {
    let d = scratch();
    let snap = snapshot(d.path());
    let mut j = job(&snap, BALANCE);
    j.v = saiife_shield::calc_proto::PANIC_JOB_VERSION;
    let mut frame = Vec::new();
    write_frame(&mut frame, &j, MAX_JOB_BYTES).unwrap();
    let (code, out, err) = run_raw(frame, d.path());
    assert_eq!(code, 0, "stderr: {err}");
    let mut r: &[u8] = &out;
    let a: CalcAnswer = read_frame(&mut r, MAX_ANSWER_BYTES).unwrap();
    if refused_without_landlock(&a, "calc_panic_answers_runtime_error") {
        return;
    }
    let CalcAnswer::Err {
        class, confinement, ..
    } = &a
    else {
        panic!("{a:?}")
    };
    assert_eq!(class, "runtime_error");
    assert!(confinement.is_some_and(|c| c.seccomp));
    let secret = saiife_shield::calc_proto::PANIC_PROBE_TEXT;
    assert!(!String::from_utf8_lossy(&out).contains(secret));
    assert!(!err.contains(secret), "{err}");
    assert!(err.contains("internal error"), "{err}");
}
