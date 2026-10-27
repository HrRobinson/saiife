//! `verify_external` (spec §6.4.3 item 3, plan 12 decision 7): the local
//! chain must hold every checkpoint of a forwarded copy, and must not end
//! before it. Chains are written by the real `ChainWriter` with a signing
//! key, then the local log or the copy is damaged.

use std::fs;
use std::path::{Path, PathBuf};

use saiife_audit::chain::sha256_hex;
use saiife_audit::sign::AuditKey;
use saiife_audit::verify::{verify_external, ExternalReport};
use saiife_audit::{verify, ChainWriter, DecisionKind, NewRecord, Record, WriterOptions};
use serde_json::Value;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

const OCT: &str = "2026-10.jsonl";
const NOV: &str = "2026-11.jsonl";

fn rec(n: u32, at: OffsetDateTime, word: &str) -> Record {
    let input = format!("{word}-{n}");
    let mut r = Record::at(
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
            mode: "locked",
            policy: None,
            permission_mode: None,
        },
        "0.2.0",
        at,
    );
    r.uid = Some(1000);
    r
}

/// Genesis, records 1..=10 in October, checkpoint (seq 11), records
/// 12..=21 in November, checkpoint (seq 22), records 23..=25 after it.
fn build_with(dir: &Path, key: AuditKey, word: &str) {
    let mut w = ChainWriter::open(
        dir,
        WriterOptions {
            mode: "locked".into(),
            saiife: "0.2.0".into(),
            key: Some(key),
        },
    )
    .unwrap();
    let oct = datetime!(2026-10-10 08:00:00 UTC);
    let nov = datetime!(2026-11-10 08:00:00 UTC);
    for n in 1..=10 {
        w.append(rec(n, oct + Duration::minutes(n.into()), word))
            .unwrap();
    }
    assert_eq!(w.checkpoint(oct + Duration::hours(1)).unwrap(), Some(11));
    for n in 12..=21 {
        w.append(rec(n, nov + Duration::minutes(n.into()), word))
            .unwrap();
    }
    assert_eq!(w.checkpoint(nov + Duration::hours(1)).unwrap(), Some(22));
    for n in 23..=25 {
        assert_eq!(
            w.append(rec(n, nov + Duration::hours(2), word)).unwrap(),
            n as u64
        );
    }
}

fn build() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    build_with(dir.path(), AuditKey::generate().unwrap(), "cmd");
    dir
}

fn lines(dir: &Path, f: &str) -> Vec<String> {
    fs::read_to_string(dir.join(f))
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

fn write_lines(path: &Path, l: &[String]) {
    fs::write(path, l.join("\n") + "\n").unwrap();
}

/// The forwarded copy as one JSONL file: every line of every month file,
/// exactly as written.
fn forward_as_file(local: &Path, to: &Path) -> PathBuf {
    let mut all = lines(local, OCT);
    all.extend(lines(local, NOV));
    let p = to.join("siem-export.jsonl");
    write_lines(&p, &all);
    p
}

#[track_caller]
fn assert_ok(r: &ExternalReport) {
    assert_eq!(r.exit_code(), 0, "{r:?}");
    assert!(r.local.breaks.is_empty(), "{r:?}");
    assert!(r.external.breaks.is_empty(), "{r:?}");
    assert!(r.missing_checkpoints.is_empty(), "{r:?}");
    assert!(r.missing_near_damage.is_empty(), "{r:?}");
    assert!(r.rewritten.is_empty(), "{r:?}");
    assert_eq!(r.cut_tail, None, "{r:?}");
}

#[test]
fn intact_copy_ok() {
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    let r = verify_external(local.path(), &copy);
    assert_ok(&r);
    assert_eq!(r.external.checkpoints, 2);
    assert_eq!(r.compared, 2);

    // A copy that lags behind (the forwarder has not sent the tail yet).
    let mut l = lines(ext.path(), "siem-export.jsonl");
    l.truncate(l.len() - 3);
    write_lines(&copy, &l);
    assert_ok(&verify_external(local.path(), &copy));

    // A copy that starts mid-chain (the SIEM dropped the oldest months):
    // no genesis, so no key, but its checkpoints still have to be local.
    let l = lines(local.path(), NOV);
    write_lines(&copy, &l);
    let r = verify_external(local.path(), &copy);
    assert_ok(&r);
    assert_eq!(r.compared, 1);
}

#[test]
fn resent_lines_in_the_copy_are_not_damage() {
    // Delivery is at least once: after a forwarder crash the lines since
    // its cursor arrive again, byte for byte.
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    let l = lines(ext.path(), "siem-export.jsonl");
    let mut resent = l[..15].to_vec();
    resent.extend_from_slice(&l[9..]);
    write_lines(&copy, &resent);
    let r = verify_external(local.path(), &copy);
    assert_ok(&r);
    assert_eq!(r.external.duplicates, 6);
    assert_eq!(r.compared, 2);

    // A repeat that is not byte for byte the same is still damage.
    let mut edited = l[..15].to_vec();
    edited.push(l[9].replace("cmd-9", "cmd-Z"));
    edited.extend_from_slice(&l[10..]);
    write_lines(&copy, &edited);
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert!(!r.external.breaks.is_empty() && r.local.breaks.is_empty());

    // The local log never tolerates a repeated line.
    let mut l = lines(local.path(), OCT);
    let again = l[5].clone();
    l.insert(6, again);
    write_lines(&local.path().join(OCT), &l);
    assert_eq!(verify(local.path()).exit_code(), 1);
}

#[test]
fn local_tail_cut_detected() {
    // Records after the last checkpoint deleted: only the copy shows it.
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    let mut l = lines(local.path(), NOV);
    l.truncate(l.len() - 3);
    write_lines(&local.path().join(NOV), &l);
    assert_eq!(verify(local.path()).exit_code(), 0, "the cut log is valid");
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert_eq!(r.cut_tail, Some((22, 25)));
    assert!(r.missing_checkpoints.is_empty(), "{r:?}");
    assert!(r.local.breaks.is_empty() && r.external.breaks.is_empty());

    // The whole of November deleted: a checkpoint is gone as well.
    fs::remove_file(local.path().join(NOV)).unwrap();
    assert_eq!(verify(local.path()).exit_code(), 0);
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert_eq!(r.missing_checkpoints, vec![21]);
    assert_eq!(r.cut_tail, Some((11, 25)));
}

#[test]
fn local_rewritten_and_resigned_detected() {
    // The attacker rewrites the whole log with a key of their own: the
    // local chain verifies on its own, but none of the forwarded
    // checkpoints are in it.
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    for f in [OCT, NOV] {
        fs::remove_file(local.path().join(f)).unwrap();
    }
    build_with(local.path(), AuditKey::generate().unwrap(), "innocent");
    assert_eq!(verify(local.path()).exit_code(), 0, "self-consistent");
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert_eq!(r.missing_checkpoints, vec![10, 21]);
    assert!(r.external.breaks.is_empty(), "{r:?}");
    assert_eq!(r.cut_tail, None);
}

#[test]
fn local_edit_with_checkpoint_kept_is_a_local_break() {
    // One record edited and every later `prev` recomputed; the checkpoint
    // lines are copied as they were, so they still match the copy, but
    // their `head` no longer hashes the line before them.
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    let mut l = lines(local.path(), OCT);
    l[3] = l[3].replace("cmd-3", "cmd-X");
    for i in 4..l.len() {
        let old = serde_json::from_str::<Value>(&l[i]).unwrap()["prev"]
            .as_str()
            .unwrap()
            .to_string();
        let new = sha256_hex(l[i - 1].as_bytes());
        l[i] = l[i].replacen(
            &format!("\"prev\":\"{old}\""),
            &format!("\"prev\":\"{new}\""),
            1,
        );
    }
    write_lines(&local.path().join(OCT), &l);
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert!(!r.local.breaks.is_empty(), "{r:?}");
    assert!(r.external.breaks.is_empty(), "{r:?}");
}

#[test]
fn external_edited_reported_as_external() {
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    let mut l = lines(ext.path(), "siem-export.jsonl");
    // A record edited, and the November checkpoint's signature changed.
    l[4] = l[4].replace("cmd-4", "cmd-Y");
    let cp = l
        .iter()
        .position(|x| x.contains("\"head_seq\":21"))
        .unwrap();
    let at = l[cp].find("\"sig\":\"").unwrap() + 7;
    let swap = if l[cp].as_bytes()[at] == b'A' {
        "B"
    } else {
        "A"
    };
    l[cp].replace_range(at..at + 1, swap);
    write_lines(&copy, &l);

    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert!(r.local.breaks.is_empty(), "{r:?}");
    assert!(
        r.missing_checkpoints.is_empty() && r.rewritten.is_empty(),
        "a damaged copy never accuses the local log: {r:?}"
    );
    assert_eq!(r.missing_near_damage, vec![21], "{r:?}");
    assert_eq!(r.cut_tail, None);
    assert!(r.external.breaks.len() >= 2, "{r:?}");
    assert!(r
        .external
        .breaks
        .iter()
        .all(|b| b.file == "siem-export.jsonl"));
    assert_eq!(r.compared, 2);

    // The last line of the copy is a checkpoint with a changed signature
    // (nothing after it to notice): its own check catches it.
    let mut fresh = lines(local.path(), OCT);
    fresh.extend(lines(local.path(), NOV));
    fresh.truncate(cp + 1);
    let at = fresh[cp].find("\"sig\":\"").unwrap() + 7;
    let swap = if fresh[cp].as_bytes()[at] == b'A' {
        "B"
    } else {
        "A"
    };
    fresh[cp].replace_range(at..at + 1, swap);
    write_lines(&copy, &fresh);
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert!(r.missing_checkpoints.is_empty(), "{r:?}");
    assert_eq!(r.missing_near_damage, vec![21], "{r:?}");
    assert!(r.rewritten.is_empty(), "{r:?}");
    assert!(!r.external.breaks.is_empty(), "{r:?}");
    assert!(r.local.breaks.is_empty(), "{r:?}");
}

#[test]
fn checkpoint_next_to_damage_is_still_compared() {
    // The line after the October checkpoint is dropped from the copy: the
    // copy breaks there (`seq` gap), but the checkpoint itself is intact
    // and found locally, so nothing is reported against the local log.
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    let mut l = lines(ext.path(), "siem-export.jsonl");
    assert!(l[11].contains("\"head_seq\":10"));
    l.remove(12);
    write_lines(&copy, &l);
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "the copy is damaged: {r:?}");
    assert_eq!(r.compared, 2);
    assert!(r.missing_checkpoints.is_empty(), "{r:?}");
    assert!(r.missing_near_damage.is_empty(), "{r:?}");
    assert!(r.rewritten.is_empty(), "{r:?}");
    assert!(r.local.breaks.is_empty(), "{r:?}");
    assert_eq!(r.external.breaks.len(), 1, "{r:?}");

    // The same damage next to a checkpoint the local log lacks (its
    // history rewritten under another key): listed, never dropped.
    for f in [OCT, NOV] {
        fs::remove_file(local.path().join(f)).unwrap();
    }
    build_with(local.path(), AuditKey::generate().unwrap(), "innocent");
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert_eq!(r.missing_near_damage, vec![10], "{r:?}");
    assert_eq!(r.missing_checkpoints, vec![21], "{r:?}");
}

/// Truncate the local log right after the checkpoint at `seq`, then append
/// re-chained forged records with the same `seq`s (no key needed: records
/// are not signed, only checkpoints are).
fn rewrite_tail_after(local: &Path, keep_through_line: usize, upto: usize) {
    let mut l = lines(local, NOV);
    let n_forged = upto - keep_through_line;
    l.truncate(keep_through_line + 1);
    let template = l[keep_through_line - 1].clone();
    let tv: Value = serde_json::from_str(&template).unwrap();
    let mut seq = serde_json::from_str::<Value>(&l[keep_through_line]).unwrap()["seq"]
        .as_u64()
        .unwrap();
    for i in 0..n_forged {
        seq += 1;
        let mut v = tv.clone();
        v["seq"] = seq.into();
        v["input"] = format!("harmless-{i}").into();
        v["prev"] = sha256_hex(l.last().unwrap().as_bytes()).into();
        l.push(serde_json::to_string(&v).unwrap());
    }
    write_lines(&local.join(NOV), &l);
}

#[test]
fn local_tail_rewritten_after_last_checkpoint_detected() {
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    // NOV: lines 0..=9 are seq 12..=21, line 10 the checkpoint (seq 22),
    // lines 11..=13 seq 23..=25. Keep through the checkpoint, forge 23..=25.
    rewrite_tail_after(local.path(), 10, 13);
    let lv = verify(local.path());
    assert_eq!(lv.exit_code(), 0, "the forged tail chains: {lv:?}");
    assert_eq!(lv.head.as_ref().unwrap().0, 25);
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert!(
        r.missing_checkpoints.is_empty() && r.cut_tail.is_none(),
        "{r:?}"
    );
    assert!(r.external.breaks.is_empty(), "{r:?}");
    assert_eq!(
        r.rewritten,
        vec![
            saiife_audit::HeadMismatch {
                seq: 24,
                after_checkpoint: Some(22),
                vouched: true
            },
            saiife_audit::HeadMismatch {
                seq: 25,
                after_checkpoint: Some(22),
                vouched: false
            },
        ]
    );
}

#[test]
fn local_tail_rewritten_with_a_damaged_copy_segment() {
    // The copy is damaged in October (a record edited), the local log is
    // rewritten after the November checkpoint: the intact stretch of the
    // copy after the damage still exposes the rewrite.
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    let mut l = lines(ext.path(), "siem-export.jsonl");
    l[4] = l[4].replace("cmd-4", "cmd-Y");
    write_lines(&copy, &l);
    rewrite_tail_after(local.path(), 10, 13);
    let r = verify_external(local.path(), &copy);
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert_eq!(r.external.breaks.len(), 1, "{r:?}");
    assert!(r.local.breaks.is_empty(), "{r:?}");
    let vouched: Vec<u64> = r
        .rewritten
        .iter()
        .filter(|h| h.vouched)
        .map(|h| h.seq)
        .collect();
    assert_eq!(vouched, vec![24], "{r:?}");

    // Without the rewrite, the damaged copy blames nothing local: the
    // stretch before the damage ends on a line the copy vouches for.
    let local = build_same_as(&copy);
    let r = verify_external(local.path(), &copy);
    assert!(r.rewritten.is_empty(), "{r:?}");
}

/// A local log whose lines are the copy's, except the copy's damage
/// (record 4) is undone.
fn build_same_as(copy: &Path) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let l: Vec<String> = fs::read_to_string(copy)
        .unwrap()
        .lines()
        .map(|x| x.replace("cmd-Y", "cmd-4"))
        .collect();
    write_lines(&dir.path().join(OCT), &l[..12]);
    write_lines(&dir.path().join(NOV), &l[12..]);
    dir
}

#[test]
fn external_dir_with_month_files() {
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    // The file target's names: `<host id>-YYYY-MM.jsonl`.
    let host = "a3b5bcb8ac41efac99df55fb3706b0a81ee27d5765626a60004c981aad009345";
    for f in [OCT, NOV] {
        fs::copy(local.path().join(f), ext.path().join(format!("{host}-{f}"))).unwrap();
    }
    fs::write(ext.path().join("README.txt"), "not a month file\n").unwrap();
    let r = verify_external(local.path(), ext.path());
    assert_ok(&r);
    assert_eq!(r.external.chained, 26);
    assert_eq!(r.compared, 2);
    // Named after a host that is not this one: noted, not an error.
    if saiife_audit::chain::host_id().as_deref() != Some(host) {
        assert_eq!(r.external_host.as_deref(), Some(host));
    }

    // Plain `YYYY-MM.jsonl` names (a copy of the audit dir) work as well.
    let plain = tempfile::tempdir().unwrap();
    for f in [OCT, NOV] {
        fs::copy(local.path().join(f), plain.path().join(f)).unwrap();
    }
    let r = verify_external(local.path(), plain.path());
    assert_ok(&r);
    assert_eq!(r.external_host, None);

    // And a cut is caught through a dir too.
    fs::remove_file(local.path().join(NOV)).unwrap();
    let r = verify_external(local.path(), ext.path());
    assert_eq!(r.exit_code(), 1, "{r:?}");
    assert_eq!(r.missing_checkpoints, vec![21]);
}

#[test]
fn external_dir_with_two_hosts_is_unreadable() {
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    for host in ["aaaa", "bbbb"] {
        fs::copy(
            local.path().join(OCT),
            ext.path().join(format!("{host}-{OCT}")),
        )
        .unwrap();
    }
    let r = verify_external(local.path(), ext.path());
    assert_eq!(r.exit_code(), 2, "{r:?}");
}

#[test]
fn missing_or_empty_copy_is_unreadable() {
    let local = build();
    let ext = tempfile::tempdir().unwrap();
    let r = verify_external(local.path(), &ext.path().join("nope.jsonl"));
    assert_eq!(r.exit_code(), 2, "{r:?}");
    let empty = ext.path().join("empty.jsonl");
    fs::write(&empty, "").unwrap();
    assert_eq!(verify_external(local.path(), &empty).exit_code(), 2);
    assert_eq!(verify_external(local.path(), ext.path()).exit_code(), 2);
}

#[test]
fn v1_files_listed_not_failed() {
    let local = build();
    let v1 = r#"{"v":1,"ts":"2026-09-01T00:00:00.000Z","agent":"claude","project":"/p","tool":"Bash","input":"ls","decision":"allow","saiife":"0.1.0"}"#;
    fs::write(local.path().join("2026-09.jsonl"), format!("{v1}\n{v1}\n")).unwrap();
    let ext = tempfile::tempdir().unwrap();
    let copy = forward_as_file(local.path(), ext.path());
    let r = verify_external(local.path(), &copy);
    assert_ok(&r);
    assert_eq!(r.local.v1_files, vec!["2026-09.jsonl".to_string()]);

    // v1 lines at the head of the copy are not a failure either.
    let mut l = vec![v1.to_string()];
    l.extend(lines(ext.path(), "siem-export.jsonl"));
    write_lines(&copy, &l);
    let r = verify_external(local.path(), &copy);
    assert_ok(&r);
    assert_eq!(r.external.v1_records, 1);
}
