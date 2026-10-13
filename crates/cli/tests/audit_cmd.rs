use assert_cmd::Command;
use predicates::prelude::*;
use saiife_audit::store::{append, DIR_ENV};
use saiife_audit::{DecisionKind, NewRecord, Record};
use time::{Duration, OffsetDateTime};

fn seed(dir: &std::path::Path) {
    let now = OffsetDateTime::now_utc();
    let mk = |input: &str, decision, pack, at| {
        Record::at(
            NewRecord {
                agent: "claude",
                project: "/home/u/app",
                session: None,
                tool: "Bash",
                input,
                decision,
                pack,
                rule: None,
                reason: Some("r"),
            },
            "0.1.0",
            at,
        )
    };
    append(dir, &mk("ls", DecisionKind::Allow, None, now)).unwrap();
    append(
        dir,
        &mk("rm -rf /", DecisionKind::Deny, Some("core.filesystem"), now),
    )
    .unwrap();
    append(
        dir,
        &mk(
            "git status",
            DecisionKind::Allow,
            None,
            now - Duration::days(40),
        ),
    )
    .unwrap();
    // A crashed half-line must not hide the rest.
    std::fs::write(dir.join("1999-01.jsonl"), "{\"v\":1,\"ts\":").unwrap();
}

#[test]
fn shows_all_records_and_summary() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path());
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("audit")
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("BLOCKED"))
        .stdout(predicate::str::contains(
            "3 decisions · 1 blocked · 0 fail-open",
        ));
}

#[test]
fn filters_blocked_and_since() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path());
    Command::cargo_bin("saiife")
        .unwrap()
        .args(["audit", "--blocked"])
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("1 decisions · 1 blocked"));
    Command::cargo_bin("saiife")
        .unwrap()
        .args(["audit", "--since", "7d"])
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("2 decisions"))
        .stdout(predicate::str::contains("git status").not());
}

#[test]
fn empty_log_says_so() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("audit")
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No audit records found"));
}

#[test]
fn bad_since_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("saiife")
        .unwrap()
        .args(["audit", "--since", "7w"])
        .env(DIR_ENV, dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid --since"));
}

#[test]
fn invalid_utf8_does_not_hide_a_month_and_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path());
    let month = OffsetDateTime::now_utc();
    let path = dir.path().join(format!(
        "{:04}-{:02}.jsonl",
        month.year(),
        u8::from(month.month())
    ));
    let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    std::io::Write::write_all(&mut f, b"{\"v\":1,\"input\":\"\xff\"}\n").unwrap();
    drop(f);
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("audit")
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("rm -rf /"))
        .stdout(predicate::str::contains(
            "3 decisions · 1 blocked · 0 fail-open",
        ))
        .stdout(predicate::str::contains("2 unreadable lines skipped"));
}

#[test]
fn unknown_decision_is_shown_as_other() {
    let dir = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let ts = format!(
        "{:04}-{:02}-{:02}T00:00:00.000Z",
        now.year(),
        u8::from(now.month()),
        now.day()
    );
    let line = format!(
        r#"{{"v":1,"ts":"{ts}","agent":"claude","project":"/p","tool":"Bash","input":"curl evil","decision":"error_denied","saiife":"2.0.0"}}"#
    );
    std::fs::write(dir.path().join(format!("{}.jsonl", &ts[..7])), line + "\n").unwrap();
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("audit")
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("OTHER"))
        .stdout(predicate::str::contains("curl evil"))
        .stdout(predicate::str::contains("unreadable").not());
    Command::cargo_bin("saiife")
        .unwrap()
        .args(["audit", "--blocked"])
        .env(DIR_ENV, dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No audit records found"));
}

#[test]
fn unreadable_audit_dir_is_an_error_not_an_empty_log() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("audit");
    std::fs::write(&file, "x").unwrap();
    Command::cargo_bin("saiife")
        .unwrap()
        .arg("audit")
        .env(DIR_ENV, &file)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot be read"));
}
