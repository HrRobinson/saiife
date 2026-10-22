//! Tamper tests for the verifier: build a real chain with `append_chained`,
//! damage it, and check the first reported break.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use saiife_audit::chain::append_chained;
use saiife_audit::{verify, BreakKind, DecisionKind, NewRecord, Record};
use time::macros::datetime;
use time::OffsetDateTime;

const F1: &str = "2026-09.jsonl";
const F2: &str = "2026-10.jsonl";

fn rec(n: u32, at: OffsetDateTime) -> Record {
    let input = format!("cmd-{n}");
    Record::at(
        NewRecord {
            agent: "claude",
            project: "/p",
            session: None,
            tool: "Bash",
            input: &input,
            decision: DecisionKind::Allow,
            pack: None,
            rule: None,
            reason: None,
            mode: "developer",
            policy: None,
            permission_mode: None,
        },
        "0.2.0",
        at,
    )
}

/// Genesis plus records 1..=20: 1..=10 in September (file lines 2..=11),
/// 11..=20 in October (file lines 1..=10).
fn build() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for n in 1..=20 {
        let at = if n <= 10 {
            datetime!(2026-09-15 10:00:00 UTC)
        } else {
            datetime!(2026-10-15 10:00:00 UTC)
        };
        assert_eq!(append_chained(dir.path(), rec(n, at)).unwrap(), n as u64);
    }
    dir
}

fn lines(dir: &Path, f: &str) -> Vec<String> {
    fs::read_to_string(dir.join(f))
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

fn write_lines(dir: &Path, f: &str, l: &[String]) {
    fs::write(dir.join(f), l.join("\n") + "\n").unwrap();
}

fn at(dir: &Path) -> PathBuf {
    dir.to_path_buf()
}

#[track_caller]
fn assert_first(dir: &Path, file: &str, line: usize, kind: BreakKind) {
    let r = verify(&at(dir));
    assert_eq!(r.exit_code(), 1, "{r:?}");
    let b = r.first_break().unwrap();
    assert_eq!((b.file.as_str(), b.line), (file, line), "{r:?}");
    assert_eq!(b.kind, kind, "{r:?}");
}

#[test]
fn intact_log_verifies() {
    let dir = build();
    let r = verify(dir.path());
    assert_eq!(r.exit_code(), 0, "{r:?}");
    assert_eq!(r.chained, 21);
    assert_eq!(r.head.as_ref().unwrap().0, 20);
    assert!(r.chain.is_some());
    assert!(r.breaks.is_empty() && r.v1_files.is_empty());
}

#[test]
fn missing_dir_is_an_intact_log() {
    let dir = tempfile::tempdir().unwrap();
    let r = verify(&dir.path().join("nope"));
    assert_eq!(r.exit_code(), 0);
    assert_eq!(r.chained, 0);
}

#[test]
fn edit_one_byte() {
    let dir = build();
    let mut l = lines(dir.path(), F1);
    assert!(l[10].contains("cmd-10"));
    l[10] = l[10].replace("cmd-10", "cmd-1O");
    write_lines(dir.path(), F1, &l);
    // Record 10 is the last line of September; the line after it is the
    // first of October.
    assert_first(dir.path(), F2, 1, BreakKind::PrevMismatch);
    assert_eq!(verify(dir.path()).breaks.len(), 1);
}

#[test]
fn delete_a_line() {
    let dir = build();
    let mut l = lines(dir.path(), F1);
    l.remove(5); // record 5
    write_lines(dir.path(), F1, &l);
    assert_first(
        dir.path(),
        F1,
        6,
        BreakKind::SeqGap {
            expected: 5,
            found: 6,
        },
    );
}

#[test]
fn insert_a_copied_line() {
    let dir = build();
    let mut l = lines(dir.path(), F1);
    let copy = l[5].clone(); // record 5
    l.insert(6, copy);
    write_lines(dir.path(), F1, &l);
    assert_first(
        dir.path(),
        F1,
        7,
        BreakKind::SeqGap {
            expected: 6,
            found: 5,
        },
    );
}

#[test]
fn reorder_two_lines() {
    let dir = build();
    let mut l = lines(dir.path(), F1);
    l.swap(5, 6);
    write_lines(dir.path(), F1, &l);
    assert_first(
        dir.path(),
        F1,
        6,
        BreakKind::SeqGap {
            expected: 5,
            found: 6,
        },
    );
}

#[test]
fn swap_month_files() {
    let dir = build();
    let (a, b) = (
        fs::read(dir.path().join(F1)).unwrap(),
        fs::read(dir.path().join(F2)).unwrap(),
    );
    fs::write(dir.path().join(F1), b).unwrap();
    fs::write(dir.path().join(F2), a).unwrap();
    assert_first(dir.path(), F1, 1, BreakKind::MissingGenesis);
}

#[test]
fn delete_oldest_file() {
    let dir = build();
    fs::remove_file(dir.path().join(F1)).unwrap();
    assert_first(dir.path(), F2, 1, BreakKind::MissingGenesis);
    assert_eq!(verify(dir.path()).breaks.len(), 1);
}

#[test]
fn partial_line_is_one_break() {
    let dir = build();
    let mut body = fs::read(dir.path().join(F2)).unwrap();
    body.pop(); // final newline
    let start = body.iter().rposition(|&b| b == b'\n').unwrap() + 1;
    let cut = start + (body.len() - start) / 2;
    body.truncate(cut); // half of record 20, no newline
    fs::write(dir.path().join(F2), body).unwrap();
    append_chained(dir.path(), rec(21, datetime!(2026-10-16 10:00:00 UTC))).unwrap();
    assert_first(dir.path(), F2, 10, BreakKind::Unparseable);
    let r = verify(dir.path());
    assert_eq!(r.breaks.len(), 1, "{r:?}");
    assert_eq!(r.chained, 21); // genesis + records 1..=19 + record 21
}

#[test]
fn v1_line_inside_chain_and_restart() {
    let dir = build();
    let v1 = r#"{"v":1,"ts":"2026-10-20T00:00:00.000Z","agent":"claude","project":"/p","tool":"Bash","input":"ls","decision":"allow","saiife":"0.1.0"}"#;
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open(dir.path().join(F2))
        .unwrap();
    writeln!(f, "{v1}").unwrap();
    drop(f);
    for n in [21, 22] {
        append_chained(dir.path(), rec(n, datetime!(2026-10-21 10:00:00 UTC))).unwrap();
    }
    let r = verify(dir.path());
    assert_eq!(r.exit_code(), 1, "{r:?}");
    let kinds: Vec<_> = r.breaks.iter().map(|b| (b.line, b.kind.clone())).collect();
    assert_eq!(
        kinds,
        vec![
            (11, BreakKind::V1InsideChain),
            (12, BreakKind::ChainRestarted)
        ],
        "{r:?}"
    );
}

#[test]
fn v1_only_log_is_not_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = r#"{"v":1,"ts":"2026-09-01T00:00:00.000Z","agent":"claude","project":"/p","tool":"Bash","input":"ls","decision":"allow","saiife":"0.1.0"}"#;
    fs::write(dir.path().join(F1), format!("{v1}\n{v1}\n")).unwrap();
    let r = verify(dir.path());
    assert_eq!(r.exit_code(), 0, "{r:?}");
    assert_eq!(r.v1_files, vec![F1.to_string()]);
    assert_eq!(r.v1_records, 2);
    assert_eq!(r.chained, 0);
}

#[cfg(unix)]
#[test]
fn unreadable_file_is_exit_2() {
    use std::os::unix::fs::PermissionsExt;
    let dir = build();
    let p = dir.path().join(F1);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&p).is_ok() {
        return; // running as root: permissions do not apply
    }
    let r = verify(dir.path());
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(r.exit_code(), 2, "{r:?}");
    assert_eq!(r.read_errors.len(), 1);
}

#[test]
fn truncated_tail_is_not_detected_without_checkpoints() {
    // Dropping the newest records leaves a shorter, perfectly valid chain.
    // Catching it needs a checkpoint forwarded off the machine (spec §6.4.2,
    // plan 12), so for now the verifier cannot and must not claim to.
    let dir = build();
    let mut l = lines(dir.path(), F2);
    l.truncate(l.len() - 3);
    write_lines(dir.path(), F2, &l);
    let r = verify(dir.path());
    assert_eq!(r.exit_code(), 0, "{r:?}");
    assert_eq!(r.head.unwrap().0, 17);
}

#[test]
fn describe_has_plain_text() {
    assert_eq!(
        BreakKind::SeqGap {
            expected: 3,
            found: 5
        }
        .describe(),
        "expected seq 3, found 5 (records were deleted, inserted or moved)"
    );
}

#[test]
fn fixture_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2/2026-11.jsonl");
    fs::copy(src, dir.path().join("2026-11.jsonl")).unwrap();
    let r = verify(dir.path());
    assert_eq!(r.exit_code(), 0, "{r:?}");
    assert_eq!(r.chained, 6);
}

/// The fixture has the shape `append_chained` writes, with stand-ins for
/// this machine's identity (never a real machine id or user name).
#[test]
fn fixture_has_the_written_shape() {
    let body = include_str!("fixtures/v2/2026-11.jsonl");
    let host = saiife_audit::chain::sha256_hex(b"fixture-host");
    for (i, line) in body.lines().enumerate() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["host"], host.as_str(), "line {}", i + 1);
        assert_eq!(v["uid"], 1000, "line {}", i + 1);
        assert_eq!(v["user"], "fixture", "line {}", i + 1);
        assert_eq!(v["mode"], "developer", "line {}", i + 1);
        if i > 0 {
            assert!(v["policy"].as_str().unwrap().starts_with("sha256:"));
            assert_eq!(v["permission_mode"], "default", "line {}", i + 1);
        }
    }
}
