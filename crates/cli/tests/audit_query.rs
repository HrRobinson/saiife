//! `saiife audit` in locked mode (plan 12, Task 5): a non-auditor reads its
//! own records through the daemon's `audit.query`; an auditor reads the
//! locked audit dir directly; the home log is shown labelled. The daemon
//! runs as the current user on temp dirs (see common/daemon.rs). Who counts
//! as an auditor is set with the debug-build seam `SAIIFE_TEST_AUDIT_GROUP`,
//! so the host's groups never matter.
#![cfg(all(target_os = "linux", debug_assertions))]

mod common;

use common::daemon::{append, guard_rec, own_group, Opts, TestDaemon};
use saiife_audit::{DecisionKind, NewRecord, Record};
use std::process::{Command, Output};

const LABEL: &str = "v1, before locked mode, not tamper-evident";
const NO_GROUP: &str = "saiife-test-no-such-group";

fn home_audit(d: &TestDaemon) -> std::path::PathBuf {
    d.path().join("home-audit")
}

/// A v1 record in the user's home log.
fn seed_home(d: &TestDaemon, input: &str) {
    let mut r = Record::new(
        NewRecord {
            agent: "claude",
            project: "/p",
            session: None,
            tool: "Bash",
            input,
            decision: DecisionKind::Deny,
            pack: Some("core.filesystem"),
            rule: None,
            reason: Some("r"),
            mode: "developer",
            policy: None,
            permission_mode: None,
        },
        "0.1.0",
    );
    r.v = 1;
    saiife_audit::store::append(&home_audit(d), &r).unwrap();
}

fn audit(d: &TestDaemon, group: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("audit")
        .args(args)
        .arg("--system-config")
        .arg(d.config())
        .env("HOME", d.path().join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("SAIIFE_DATA_DIR", d.path().join("data"))
        .env("SAIIFE_AUDIT_DIR", home_audit(d))
        .env("SAIIFE_TEST_AUDIT_GROUP", group)
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn cli_locked_non_auditor_uses_daemon() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    append(&mut c, guard_rec("echo mine-via-daemon")).unwrap();
    let o = audit(&d, NO_GROUP, &[]);
    let out = text(&o);
    assert!(
        o.status.success(),
        "{out}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(out.contains("echo mine-via-daemon"), "{out}");
    // Only the guard record: the daemon's own records (same uid here, kind
    // `daemon`) are not the caller's, so audit.query leaves them out; a
    // direct read would show them.
    assert!(out.contains("1 decisions"), "{out}");
    assert!(!out.contains(LABEL), "{out}");
    // The filters go through too.
    let o = audit(&d, NO_GROUP, &["--kind", "connector"]);
    let out = text(&o);
    assert!(o.status.success());
    assert!(
        out.contains("No audit records found in your records from the saiife daemon"),
        "{out}"
    );
    let o = audit(&d, NO_GROUP, &["--kind", "guard", "--agent", "claude"]);
    assert!(text(&o).contains("echo mine-via-daemon"));
    // An auditor reads the files: the daemon's records are there too.
    let o = audit(&d, &own_group(), &[]);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(out.contains("echo mine-via-daemon"), "{out}");
    assert!(!out.contains("1 decisions"), "{out}");
}

#[test]
fn cli_locked_non_auditor_without_daemon_exits_5() {
    let mut d = TestDaemon::start(Opts::default());
    if let Some(mut child) = d.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let o = audit(&d, NO_GROUP, &[]);
    assert_eq!(o.status.code(), Some(5), "{}", text(&o));
    assert!(String::from_utf8_lossy(&o.stderr).contains("cannot reach the saiife daemon"));
    // An auditor does not need the daemon.
    let o = audit(&d, &own_group(), &[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn v1_home_log_labelled() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    append(&mut c, guard_rec("echo locked-record")).unwrap();
    seed_home(&d, "rm -rf old-home-record");
    for group in [NO_GROUP.to_string(), own_group()] {
        let o = audit(&d, &group, &[]);
        let out = text(&o);
        assert!(o.status.success(), "{out}");
        let at = out
            .find(&format!("{LABEL} ("))
            .unwrap_or_else(|| panic!("no label: {out}"));
        // The locked records come first, the home log after its label.
        assert!(out[..at].contains("echo locked-record"), "{out}");
        assert!(!out[..at].contains("old-home-record"), "{out}");
        assert!(out[at..].contains("rm -rf old-home-record"), "{out}");
    }
    // The report says the home log is not in it.
    let report = d.path().join("r.html");
    let o = audit(&d, NO_GROUP, &["--report", report.to_str().unwrap()]);
    let out = text(&o);
    assert!(o.status.success(), "{out}");
    assert!(
        out.contains(&format!("1 records of your home log ({LABEL})")),
        "{out}"
    );
    let html = std::fs::read_to_string(&report).unwrap();
    assert!(html.contains("echo locked-record"));
    assert!(!html.contains("old-home-record"));
}

#[test]
fn auditor_refused_by_the_files_falls_back_to_the_daemon() {
    use std::os::unix::fs::PermissionsExt;
    if rustix::process::geteuid().is_root() {
        return; // root reads through any mode
    }
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    append(&mut c, guard_rec("echo fallback-record")).unwrap();
    let dir = d.audit_dir();
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
    // Not listable by this user: an auditor by its groups is refused.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o300)).unwrap();
    let o = audit(&d, &own_group(), &[]);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("(permission denied); asking the saiife daemon instead"),
        "{err}"
    );
    // The daemon runs as the same user here, so it cannot list the dir
    // either: the answer is its refusal, proving the query was sent.
    assert!(err.contains("audit.query"), "{err}");
    assert_eq!(o.status.code(), Some(5), "{err}");
}

/// Through audit.query too, the report's host sections honour --since
/// only: --agent narrows the decisions, not the error_denied rows.
#[test]
fn report_host_sections_from_the_daemon_ignore_narrowing_filters() {
    let d = TestDaemon::start(Opts::default());
    let mut c = d.client();
    let mut rec = guard_rec("echo err-denied-host");
    rec["decision"] = "error_denied".into();
    rec["reason"] = "guard worker crashed".into();
    append(&mut c, rec).unwrap();
    let report = d.path().join("h.html");
    let o = audit(
        &d,
        NO_GROUP,
        &[
            "--agent",
            "codex",
            "--since",
            "1d",
            "--report",
            report.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(text(&o).contains("(0 decisions)"), "{}", text(&o));
    let html = std::fs::read_to_string(&report).unwrap();
    assert!(html.contains("echo err-denied-host"), "{html}");
    assert!(html.contains("not checked: your records come through the saiife daemon"));
}
