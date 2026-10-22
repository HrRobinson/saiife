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

// ---------------------------------------------------------------------------
// Locked mode: signed checkpoints and key rotation (spec §6.4.2, §6.4.3).

mod locked {
    use super::*;
    use saiife_audit::chain::sha256_hex;
    use saiife_audit::sign::{key_rotate_message, AuditKey};
    use saiife_audit::{ChainWriter, WriterOptions};
    use saiife_audit::{DecisionKind, NewRecord};

    const F: &str = "2026-11.jsonl";

    fn guard(n: u32) -> Record {
        let mut r = rec(
            n,
            datetime!(2026-11-02 08:00:00 UTC) + time::Duration::minutes(n.into()),
        );
        r.mode = Some("locked".into());
        r.uid = Some(1000);
        r.user = Some("bob".into());
        r
    }

    fn writer(dir: &Path, key: Option<AuditKey>) -> ChainWriter {
        ChainWriter::open(
            dir,
            WriterOptions {
                mode: "locked".into(),
                saiife: "0.2.0".into(),
                key,
            },
        )
        .unwrap()
    }

    /// Two handles on one key (`AuditKey` is not `Clone`): one for the
    /// writer, one for the test.
    fn key_twice(keys: &Path, name: &str) -> (AuditKey, AuditKey) {
        let path = keys.join(name);
        let (a, _) = AuditKey::load_or_create(&path).unwrap();
        let (b, _) = AuditKey::load_or_create(&path).unwrap();
        (a, b)
    }

    /// Genesis, guard records 1..=25 (lines 2..=26) and a checkpoint (seq 26,
    /// line 27), all in `F`. The writer is returned still open.
    fn build_keyed(dir: &Path, key: AuditKey) -> ChainWriter {
        let mut w = writer(dir, Some(key));
        for n in 1..=25 {
            assert_eq!(w.append(guard(n)).unwrap(), n as u64);
        }
        assert_eq!(w.records_since_checkpoint(), 25);
        let seq = w.checkpoint(datetime!(2026-11-02 09:00:00 UTC)).unwrap();
        assert_eq!(seq, Some(26));
        assert_eq!(w.records_since_checkpoint(), 0);
        assert_eq!(
            w.checkpoint(datetime!(2026-11-02 09:01:00 UTC)).unwrap(),
            None
        );
        w
    }

    fn value(line: &str) -> serde_json::Value {
        serde_json::from_str(line).unwrap()
    }

    #[test]
    fn checkpoints_verify() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let (a, a2) = key_twice(keys.path(), "a");
        drop(build_keyed(dir.path(), a));
        let r = verify(dir.path());
        assert_eq!(r.exit_code(), 0, "{r:?}");
        assert_eq!(r.checkpoints, 1);
        let (seq, ts) = r.last_checkpoint.clone().unwrap();
        assert_eq!(seq, 26);
        assert_eq!(ts, "2026-11-02T09:00:00.000Z");
        assert_eq!(r.key, Some(a2.fingerprint()));

        let l = lines(dir.path(), F);
        assert_eq!(l.len(), 27);
        let g = value(&l[0]);
        assert_eq!(g["key"], a2.spki().as_str());
        let c = value(&l[26]);
        assert_eq!(c["kind"], "checkpoint");
        assert_eq!(c["tool"], "checkpoint");
        assert_eq!(
            (
                c["agent"].as_str(),
                c["project"].as_str(),
                c["input"].as_str()
            ),
            (Some(""), Some(""), Some(""))
        );
        assert_eq!(c["decision"], "allow");
        assert_eq!(c["mode"], "locked");
        assert_eq!(c["head_seq"], 25);
        assert_eq!(c["head"], sha256_hex(l[25].as_bytes()).as_str());
        assert_eq!(c["key"], a2.fingerprint().as_str());
    }

    #[test]
    fn forged_checkpoint_signature() {
        let dir = tempfile::tempdir().unwrap();
        drop(build_keyed(dir.path(), AuditKey::generate().unwrap()));
        let mut l = lines(dir.path(), F);
        let at = l[26].find("\"sig\":\"").unwrap() + 7;
        let c = l[26].as_bytes()[at];
        let swap = if c == b'A' { "B" } else { "A" };
        l[26].replace_range(at..at + 1, swap);
        write_lines(dir.path(), F, &l);
        assert_first(dir.path(), F, 27, BreakKind::BadCheckpoint);
    }

    #[test]
    fn rewritten_history_with_other_key() {
        // The attacker has key B, not A, and rewrites the whole log: same
        // genesis key A, every `prev` recomputed, the checkpoint re-signed
        // over the new head with B.
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let a = AuditKey::generate().unwrap();
        let (b, b2) = key_twice(keys.path(), "b");
        drop(build_keyed(dir.path(), b));
        let mut l = lines(dir.path(), F);
        l[0] = l[0].replace(&b2.spki(), &a.spki());
        for i in 1..l.len() {
            let old = value(&l[i])["prev"].as_str().unwrap().to_string();
            let new = sha256_hex(l[i - 1].as_bytes());
            l[i] = l[i].replace(
                &format!("\"prev\":\"{old}\""),
                &format!("\"prev\":\"{new}\""),
            );
            if i == 26 {
                let c = value(&l[i]);
                let old_sig = c["sig"].as_str().unwrap().to_string();
                let chain = value(&l[0])["chain"].as_str().unwrap().to_string();
                let msg = saiife_audit::sign::checkpoint_message(
                    &chain,
                    25,
                    &new,
                    c["ts"].as_str().unwrap(),
                );
                l[i] = l[i]
                    .replace(
                        &format!("\"head\":\"{old}\""),
                        &format!("\"head\":\"{new}\""),
                    )
                    .replace(&old_sig, &b2.sign_b64(msg.as_bytes()));
            }
        }
        write_lines(dir.path(), F, &l);
        let r = verify(dir.path());
        assert_eq!(
            r.breaks.len(),
            1,
            "only the checkpoint gives it away: {r:?}"
        );
        assert_first(dir.path(), F, 27, BreakKind::BadCheckpoint);
    }

    #[test]
    fn key_rotation_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let (b, b2) = key_twice(keys.path(), "b");
        let mut w = build_keyed(dir.path(), AuditKey::generate().unwrap());
        let a_fp = value(&lines(dir.path(), F)[26])["key"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(w.rotate_key(b).unwrap(), 27);
        for n in 26..=28 {
            w.append(guard(n)).unwrap();
        }
        assert_eq!(
            w.checkpoint(datetime!(2026-11-02 10:00:00 UTC)).unwrap(),
            Some(31)
        );
        drop(w);
        let l = lines(dir.path(), F);
        let k = value(&l[27]);
        assert_eq!(k["kind"], "key_rotate");
        assert_eq!(k["key"], a_fp.as_str());
        assert_eq!(k["new_key"], b2.spki().as_str());
        assert_eq!(k["head_seq"], 26);
        assert_eq!(k["head"], sha256_hex(l[26].as_bytes()).as_str());
        assert!(k["sig"].is_string());
        let r = verify(dir.path());
        assert_eq!(r.exit_code(), 0, "{r:?}");
        assert_eq!(r.checkpoints, 2);
        assert_eq!(r.last_checkpoint.as_ref().map(|c| c.0), Some(31));
        assert_eq!(r.key, Some(b2.fingerprint()));
    }

    #[test]
    fn key_rotate_signed_by_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = build_keyed(dir.path(), AuditKey::generate().unwrap());
        w.rotate_key(AuditKey::generate().unwrap()).unwrap();
        drop(w);
        let mut l = lines(dir.path(), F);
        let k = value(&l[27]);
        let chain = value(&l[0])["chain"].as_str().unwrap().to_string();
        let msg = key_rotate_message(
            &chain,
            k["head_seq"].as_u64().unwrap(),
            k["head"].as_str().unwrap(),
            k["new_key"].as_str().unwrap(),
            k["ts"].as_str().unwrap(),
        );
        let other = AuditKey::generate().unwrap();
        l[27] = l[27].replace(k["sig"].as_str().unwrap(), &other.sign_b64(msg.as_bytes()));
        write_lines(dir.path(), F, &l);
        assert_first(dir.path(), F, 28, BreakKind::BadKeyRotate);
        // The key was not switched: the old key is still in force.
        let r = verify(dir.path());
        assert_eq!(r.key.as_deref(), k["key"].as_str());
    }

    #[test]
    fn lost_key_is_unsigned_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let (b, b2) = key_twice(keys.path(), "b");
        drop(build_keyed(dir.path(), AuditKey::generate().unwrap()));
        let mut w = writer(dir.path(), Some(b));
        assert_eq!(
            w.head().map(|h| h.0),
            Some(27),
            "key_rotate written at open"
        );
        for n in 26..=28 {
            w.append(guard(n)).unwrap();
        }
        let cp = w.checkpoint(datetime!(2026-11-02 10:00:00 UTC)).unwrap();
        assert_eq!(cp, Some(31));
        drop(w);
        let r = verify(dir.path());
        assert_eq!(r.exit_code(), 1, "{r:?}");
        assert_eq!(r.breaks.len(), 1, "{r:?}");
        assert_eq!(r.breaks[0].kind, BreakKind::UnsignedKeyRotate);
        assert_eq!(r.breaks[0].seq, Some(27));
        assert_eq!(r.last_checkpoint.as_ref().map(|c| c.0), Some(31));
        assert_eq!(r.key, Some(b2.fingerprint()));
        let all: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| {
                let p = e.unwrap().path();
                (p.extension()? == "jsonl").then(|| fs::read_to_string(p).unwrap())
            })
            .collect();
        let rot = all
            .iter()
            .flat_map(|b| b.lines())
            .map(value)
            .find(|v| v["kind"] == "key_rotate")
            .unwrap();
        assert!(rot["sig"].is_null(), "{rot}");
        assert_eq!(rot["reason"], "previous signing key missing");
        assert_eq!(rot["new_key"], b2.spki().as_str());
    }

    #[test]
    fn reopening_with_the_same_key_writes_no_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let (a, a2) = key_twice(keys.path(), "a");
        drop(build_keyed(dir.path(), a));
        let w = writer(dir.path(), Some(a2));
        assert_eq!(w.head().map(|h| h.0), Some(26));
    }

    #[test]
    fn checkpoint_in_developer_chain_is_break() {
        let dir = tempfile::tempdir().unwrap();
        for n in 1..=3 {
            append_chained(dir.path(), rec(n, datetime!(2026-10-15 10:00:00 UTC))).unwrap();
        }
        let mut c = rec(4, datetime!(2026-10-15 11:00:00 UTC));
        c.kind = Some("checkpoint".into());
        c.tool = "checkpoint".into();
        c.input = String::new();
        c.extra.insert("head_seq".into(), 3.into());
        c.extra.insert("head".into(), "00".into());
        c.extra.insert("key".into(), "ed25519:00".into());
        c.extra.insert("sig".into(), "AAAA".into());
        append_chained(dir.path(), c).unwrap();
        assert_first(dir.path(), F2, 5, BreakKind::CheckpointWithoutKey);
        assert_eq!(verify(dir.path()).key, None);
    }

    #[test]
    fn break_kinds_describe() {
        assert_eq!(
            BreakKind::BadCheckpoint.describe(),
            "checkpoint does not match its signature or the records before it (records were changed, or the checkpoint is forged)"
        );
        assert_eq!(
            BreakKind::CheckpointWithoutKey.describe(),
            "checkpoint in a chain that has no signing key"
        );
        assert_eq!(
            BreakKind::BadKeyRotate.describe(),
            "signing key change not signed by the previous key"
        );
        assert_eq!(
            BreakKind::UnsignedKeyRotate.describe(),
            "signing key replaced without the previous key (the daemon's key file was lost or removed)"
        );
    }

    #[test]
    fn startup_check_reports_edited_recent_line() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let (a, a2) = key_twice(keys.path(), "a");
        drop(build_keyed(dir.path(), a));
        let mut l = lines(dir.path(), F);
        assert!(l[20].contains("cmd-20"));
        l[20] = l[20].replace("cmd-20", "cmd-2O");
        write_lines(dir.path(), F, &l);
        let w = writer(dir.path(), Some(a2));
        let c = w.startup_check(1000);
        let err = c.recent.unwrap_err();
        assert!(err.contains("seq 21"), "{err}");
        assert!(err.contains("does not follow the line before"), "{err}");
        assert_eq!(c.last_checkpoint, Some(26));
        // The edit is older than the last 3 chained lines.
        let c = w.startup_check(3);
        assert_eq!(c.recent, Ok(()));
        assert_eq!(c.last_checkpoint, Some(26));
    }

    #[test]
    fn startup_check_catches_a_forged_recent_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let (a, a2) = key_twice(keys.path(), "a");
        drop(build_keyed(dir.path(), a));
        let mut l = lines(dir.path(), F);
        let at = l[26].find("\"sig\":\"").unwrap() + 7;
        let swap = if l[26].as_bytes()[at] == b'A' {
            "B"
        } else {
            "A"
        };
        l[26].replace_range(at..at + 1, swap);
        write_lines(dir.path(), F, &l);
        let w = writer(dir.path(), Some(a2));
        let err = w.startup_check(10).recent.unwrap_err();
        assert!(err.contains("seq 26"), "{err}");
        assert!(err.contains("checkpoint does not match"), "{err}");
    }

    fn daemon_stop() -> Record {
        let mut r = guard(99);
        r.kind = Some("daemon".into());
        r.tool = "daemon".into();
        r.agent = String::new();
        r.project = String::new();
        r.input = "stop".into();
        r.extra.insert("event".into(), "stop".into());
        r
    }

    #[test]
    fn startup_check_ok_and_clean_stop() {
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let (a, a2) = key_twice(keys.path(), "a");
        let mut w = writer(dir.path(), Some(a));
        for n in 1..=5 {
            w.append(guard(n)).unwrap();
        }
        w.append(daemon_stop()).unwrap();
        assert_eq!(
            w.checkpoint(datetime!(2026-11-02 09:00:00 UTC)).unwrap(),
            Some(7)
        );
        drop(w);
        let mut w = writer(dir.path(), Some(a2));
        let c = w.startup_check(1000);
        assert_eq!(c.recent, Ok(()));
        assert_eq!(c.last_checkpoint, Some(7));
        assert!(c.last_clean_stop);
        w.append(guard(6)).unwrap();
        let c = w.startup_check(1000);
        assert_eq!(c.recent, Ok(()));
        assert!(!c.last_clean_stop, "a guard record after the stop");
        assert_eq!(c.last_checkpoint, Some(7));
    }

    #[test]
    fn startup_check_on_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let w = writer(dir.path(), Some(AuditKey::generate().unwrap()));
        let c = w.startup_check(1000);
        assert_eq!(c.recent, Ok(()));
        assert_eq!(c.last_checkpoint, None);
        assert!(!c.last_clean_stop);
    }

    #[test]
    fn key_added_to_keyless_chain_is_not_a_break() {
        // A chain started without a key (developer mode) has no key to sign
        // the change with: the writer adopts its key with an unsigned
        // `key_rotate` that names no old key, and that is not a loss.
        let dir = tempfile::tempdir().unwrap();
        for n in 1..=3 {
            append_chained(dir.path(), guard(n)).unwrap();
        }
        let mut w = writer(dir.path(), Some(AuditKey::generate().unwrap()));
        assert_eq!(w.head().map(|h| h.0), Some(4));
        w.append(guard(4)).unwrap();
        assert_eq!(
            w.checkpoint(datetime!(2026-11-02 09:00:00 UTC)).unwrap(),
            Some(6)
        );
        drop(w);
        let rot = lines(dir.path(), F)
            .iter()
            .map(|l| value(l))
            .find(|v| v["kind"] == "key_rotate")
            .unwrap();
        assert!(rot["sig"].is_null() && rot["key"].is_null(), "{rot}");
        assert_eq!(rot["reason"], "chain had no signing key");
        let r = verify(dir.path());
        assert_eq!(r.exit_code(), 0, "{r:?}");
        assert_eq!(r.last_checkpoint.as_ref().map(|c| c.0), Some(6));
    }

    #[test]
    fn checkpoint_without_key_is_refused_by_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = writer(dir.path(), None);
        w.append(guard(1)).unwrap();
        assert!(w.checkpoint(datetime!(2026-11-02 09:00:00 UTC)).is_err());
        assert!(w.rotate_key(AuditKey::generate().unwrap()).is_err());
    }

    /// Writes `tests/fixtures/v2-locked/2026-11.jsonl`: a locked-mode log
    /// with stand-ins for the machine's identity. Run once with
    /// `cargo test -p saiife-audit --test tamper -- --ignored generate_locked_fixture`
    /// and commit the file; it is static from then on.
    #[test]
    #[ignore]
    fn generate_locked_fixture() {
        use saiife_audit::chain::ZERO_PREV;
        use saiife_audit::sign::checkpoint_message;

        let host = sha256_hex(b"fixture-host");
        let chain = "11111111-2222-4333-8444-666666666666";
        let policy = format!("sha256:{}", sha256_hex(b"fixture-policy"));
        let a = AuditKey::generate().unwrap();
        let b = AuditKey::generate().unwrap();
        let base = |tool: &str, input: &str, min: i64| {
            let mut r = Record::at(
                NewRecord {
                    agent: "",
                    project: "",
                    session: None,
                    tool,
                    input,
                    decision: DecisionKind::Allow,
                    pack: None,
                    rule: None,
                    reason: None,
                    mode: "locked",
                    policy: None,
                    permission_mode: None,
                },
                "0.2.0",
                datetime!(2026-11-03 09:00:00 UTC) + time::Duration::minutes(min),
            );
            r.kind = Some(tool.into());
            r.host = Some(host.clone());
            r.uid = Some(1000);
            r.user = Some("fixture".into());
            r
        };
        let mut out: Vec<String> = Vec::new();
        let push = |out: &mut Vec<String>, mut r: Record| {
            let seq = out.len() as u64;
            r.seq = Some(seq);
            r.prev = Some(match out.last() {
                Some(l) => sha256_hex(l.as_bytes()),
                None => ZERO_PREV.to_string(),
            });
            out.push(serde_json::to_string(&r).unwrap());
        };
        let head = |out: &Vec<String>| {
            (
                out.len() as u64 - 1,
                sha256_hex(out.last().unwrap().as_bytes()),
            )
        };
        let checkpoint = |out: &mut Vec<String>, key: &AuditKey, min: i64| {
            let (head_seq, h) = head(out);
            let mut r = base("checkpoint", "", min);
            let msg = checkpoint_message(chain, head_seq, &h, &r.ts);
            r.extra.insert("head_seq".into(), head_seq.into());
            r.extra.insert("head".into(), h.into());
            r.extra.insert("key".into(), key.fingerprint().into());
            r.extra
                .insert("sig".into(), key.sign_b64(msg.as_bytes()).into());
            push(out, r);
        };

        let mut g = base("genesis", "", 0);
        g.extra.insert("chain".into(), chain.into());
        g.extra.insert("key".into(), a.spki().into());
        push(&mut out, g);
        for (i, cmd) in ["ls -la", "git status", "rm -rf /"].iter().enumerate() {
            let mut r = base("guard", "", i as i64 + 1);
            r.agent = "claude".into();
            r.project = "/work/demo".into();
            r.session = Some("s1".into());
            r.tool = "Bash".into();
            r.input = (*cmd).into();
            r.policy = Some(policy.clone());
            r.permission_mode = Some("default".into());
            r.extra.insert(
                "peer".into(),
                serde_json::json!({"pid": 4242, "comm": "claude"}),
            );
            if cmd.starts_with("rm") {
                r.decision = DecisionKind::Deny;
                r.pack = Some("core.filesystem".into());
                r.rule = Some("rm-root".into());
                r.reason = Some("deletes the filesystem root".into());
            }
            push(&mut out, r);
        }
        checkpoint(&mut out, &a, 10);
        let (head_seq, h) = head(&out);
        let mut k = base("key_rotate", "", 11);
        let msg = key_rotate_message(chain, head_seq, &h, &b.spki(), &k.ts);
        k.extra.insert("head_seq".into(), head_seq.into());
        k.extra.insert("head".into(), h.into());
        k.extra.insert("key".into(), a.fingerprint().into());
        k.extra.insert("new_key".into(), b.spki().into());
        k.extra
            .insert("sig".into(), a.sign_b64(msg.as_bytes()).into());
        push(&mut out, k);
        checkpoint(&mut out, &b, 12);
        let mut stop = base("daemon", "stop", 13);
        stop.policy = Some(policy.clone());
        stop.extra.insert("event".into(), "stop".into());
        push(&mut out, stop);

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2-locked");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join(F), out.join("\n") + "\n").unwrap();
    }

    #[test]
    fn locked_fixture_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let src =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2-locked/2026-11.jsonl");
        fs::copy(src, dir.path().join(F)).unwrap();
        let r = verify(dir.path());
        assert_eq!(r.exit_code(), 0, "{r:?}");
        assert_eq!(r.chained, 8);
        assert_eq!(r.checkpoints, 2);
        assert_eq!(r.last_checkpoint.as_ref().map(|c| c.0), Some(6));
        assert!(r.key.is_some());
    }
}
