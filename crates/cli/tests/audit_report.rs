use assert_cmd::Command;
use predicates::prelude::*;
use saiife_audit::store::{append, DIR_ENV};
use saiife_audit::{DecisionKind, NewRecord, Record};
use std::path::Path;
use tempfile::TempDir;
use time::OffsetDateTime;

struct Sandbox {
    audit: TempDir,
    home: TempDir,
    data: TempDir,
    work: TempDir,
}

fn rec(input: &str, decision: DecisionKind, pack: Option<&str>, at: OffsetDateTime) -> Record {
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
}

impl Sandbox {
    fn new() -> Sandbox {
        let s = Sandbox {
            audit: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
            data: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        };
        let now = OffsetDateTime::now_utc();
        append(
            s.audit.path(),
            &rec("echo allowed-input", DecisionKind::Allow, None, now),
        )
        .unwrap();
        append(
            s.audit.path(),
            &rec("rm -rf /", DecisionKind::Deny, Some("core.filesystem"), now),
        )
        .unwrap();
        s
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("saiife").unwrap();
        c.env(DIR_ENV, self.audit.path())
            .env("HOME", self.home.path())
            .env("SAIIFE_DATA_DIR", self.data.path())
            .current_dir(self.work.path());
        c
    }

    fn path(&self, rel: &str) -> std::path::PathBuf {
        self.work.path().join(rel)
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

#[test]
fn writes_default_named_report() {
    let s = Sandbox::new();
    let today = OffsetDateTime::now_utc().date();
    let name = format!("saiife-report-{today}.html");
    let abs = std::fs::canonicalize(s.work.path()).unwrap().join(&name);
    s.cmd()
        .args(["audit", "--report"])
        .assert()
        .success()
        .stdout(format!("Report written: {} (2 decisions)\n", abs.display()));
    let html = read(&s.path(&name));
    assert!(html.contains("Blocked actions"));
    assert!(html.contains("rm -rf /"));
}

#[test]
fn explicit_path_and_filters() {
    let s = Sandbox::new();
    std::fs::create_dir(s.path("out")).unwrap();
    s.cmd()
        .args([
            "audit",
            "--since",
            "7d",
            "--blocked",
            "--report",
            "out/r.html",
        ])
        .assert()
        .success();
    let html = read(&s.path("out/r.html"));
    assert!(
        html.contains("Filters: last 7d, only blocked actions"),
        "{html}"
    );
    assert!(html.contains("rm -rf /"));
    assert!(!html.contains("echo allowed-input"));
}

#[test]
fn refuses_non_html_path() {
    let s = Sandbox::new();
    std::fs::create_dir(s.path(".claude")).unwrap();
    std::fs::write(s.path(".claude/settings.json"), "{\"keep\":1}").unwrap();
    for p in ["settings.json", ".claude/settings.json"] {
        s.cmd()
            .args(["audit", "--report", p])
            .assert()
            .code(2)
            .stderr(predicate::str::contains(
                "the report file name must end in .html or .htm",
            ));
    }
    assert_eq!(read(&s.path(".claude/settings.json")), "{\"keep\":1}");
    assert!(!s.path("settings.json").exists());
}

#[test]
fn refuses_symlink_target() {
    let s = Sandbox::new();
    std::fs::write(s.path("target.json"), "precious").unwrap();
    std::os::unix::fs::symlink(s.path("target.json"), s.path("r.html")).unwrap();
    s.cmd()
        .args(["audit", "--report", "r.html"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("is not a regular file"));
    assert_eq!(read(&s.path("target.json")), "precious");

    std::fs::create_dir(s.path("d.html")).unwrap();
    s.cmd()
        .args(["audit", "--report", "d.html"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("is not a regular file"));
}

#[test]
fn overwrites_existing_regular_report() {
    let s = Sandbox::new();
    std::fs::write(s.path("r.html"), "old").unwrap();
    s.cmd()
        .args(["audit", "--report", "r.html"])
        .assert()
        .success();
    assert!(read(&s.path("r.html")).contains("Blocked actions"));
    let leftovers: Vec<_> = std::fs::read_dir(s.work.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn missing_parent_dir_is_an_error() {
    let s = Sandbox::new();
    s.cmd()
        .args(["audit", "--report", "nope/r.html"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot write"));
}

#[test]
fn bad_since_still_exit_2() {
    let s = Sandbox::new();
    s.cmd()
        .args(["audit", "--since", "7w", "--report"])
        .assert()
        .code(2);
    let any_html = std::fs::read_dir(s.work.path()).unwrap().count();
    assert_eq!(any_html, 0);
}

#[test]
fn large_log_renders() {
    let s = Sandbox::new();
    let now = OffsetDateTime::now_utc();
    let mut lines = String::new();
    for i in 0..19_998 {
        let r = rec(&format!("echo {i}"), DecisionKind::Allow, None, now);
        lines.push_str(&serde_json::to_string(&r).unwrap());
        lines.push('\n');
    }
    // 19 998 + the 2 seeded records. A month file far from the seeded current month.
    std::fs::write(s.audit.path().join("2026-01.jsonl"), lines).unwrap();
    let start = std::time::Instant::now();
    s.cmd()
        .args(["audit", "--report", "big.html"])
        .assert()
        .success();
    assert!(start.elapsed().as_secs() < 10, "{:?}", start.elapsed());
    assert!(read(&s.path("big.html")).contains("Show all 20000 decisions"));
}
