//! Pins the live lock-check results (docs/lock-check.md) kept as fixtures.

use std::fs;
use std::path::PathBuf;

fn read(agent: &str) -> String {
    let p: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests/fixtures/lock-check",
        &format!("{agent}.tsv"),
    ]
    .iter()
    .collect();
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn label(tsv: &str) -> &str {
    tsv.lines()
        .rev()
        .find_map(|l| l.strip_prefix("# label="))
        .expect("label line")
}

fn rows(tsv: &str) -> Vec<Vec<&str>> {
    tsv.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| l.split('\t').collect())
        .collect()
}

#[test]
fn claude_is_lockable() {
    let tsv = read("claude");
    assert_eq!(label(&tsv), "lockable");
    let rows = rows(&tsv);
    assert!(rows.len() >= 20, "expected the full check set");
    for r in &rows {
        assert!(r.len() >= 5, "malformed row: {r:?}");
        assert!(
            matches!(r[4], "PASS" | "INFO"),
            "{} is {}, not PASS",
            r[0],
            r[4]
        );
    }
    for id in [
        "claude.disable.user",
        "claude.disable.cli",
        "claude.config-dir",
        "claude.fail.missing",
        "claude.configchange.blocks",
    ] {
        assert!(rows.iter().any(|r| r[0] == id), "missing row {id}");
    }
}

/// The lock label saiife reports for Claude Code is the recorded one.
#[test]
fn claude_label_matches_recording() {
    use saiife_agents::{lock, Agent};
    let tsv = read("claude");
    assert_eq!(label(&tsv), lock::label(Agent::Claude).id());
}

/// Codex and Gemini CLI have no recording yet, so they are unverified. When
/// a recording lands, this fails until `lock::label` follows it.
#[test]
fn unrecorded_agents_are_unverified() {
    use saiife_agents::{lock, Agent};
    for a in [Agent::Codex, Agent::Gemini] {
        let p: PathBuf = [
            env!("CARGO_MANIFEST_DIR"),
            "tests/fixtures/lock-check",
            &format!("{}.tsv", a.name()),
        ]
        .iter()
        .collect();
        if p.exists() {
            let tsv = read(a.name());
            assert_eq!(label(&tsv), lock::label(a).id(), "{}", a.name());
        } else {
            assert_eq!(lock::label(a), lock::LockLabel::Unverified, "{}", a.name());
        }
    }
}
