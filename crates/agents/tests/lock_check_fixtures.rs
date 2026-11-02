//! Pins the live lock-check results (docs/lock-check.md) kept as fixtures:
//! `tests/fixtures/lock-check/<agent>.tsv` for Linux (the Docker run) and
//! `tests/fixtures/lock-check/macos/<agent>.tsv` for macOS (the VM run,
//! `scripts/lock-check/macos-vm.sh`) and `tests/fixtures/lock-check/windows/
//! <agent>.tsv` for Windows (none yet; plan 19b Task 14).

use std::fs;
use std::path::PathBuf;

use saiife_agents::lock::LockPlatform;

/// The recording of `agent` for `platform`.
fn recording_path(agent: &str, platform: LockPlatform) -> PathBuf {
    let mut p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests/fixtures/lock-check"]
        .iter()
        .collect();
    if let Some(d) = platform.fixture_dir() {
        p.push(d);
    }
    p.push(format!("{agent}.tsv"));
    p
}

fn read(agent: &str) -> String {
    let p = recording_path(agent, LockPlatform::Linux);
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

/// The Linux lock label saiife reports for Claude Code is the recorded one.
#[test]
fn claude_label_matches_recording() {
    use saiife_agents::{lock, Agent};
    let tsv = read("claude");
    assert_eq!(
        label(&tsv),
        lock::label_for(Agent::Claude, LockPlatform::Linux).id()
    );
}

/// All tables follow the recordings: an agent with a recording for a
/// platform has its recorded label there, and one without is unverified.
/// When a recording lands (Linux or `macos/`), this fails until
/// `lock::label_for` follows it.
#[test]
fn labels_match_recordings_on_both_platforms() {
    use saiife_agents::{lock, Agent};
    for platform in LockPlatform::ALL {
        for a in Agent::ALL {
            let p = recording_path(a.name(), platform);
            let want = lock::label_for(a, platform);
            if p.exists() {
                let tsv = fs::read_to_string(&p).unwrap();
                assert_eq!(label(&tsv), want.id(), "{}", p.display());
                if let Some(d) = platform.fixture_dir() {
                    let marker = format!("# platform={d}");
                    assert!(
                        tsv.lines().any(|l| l == marker),
                        "{} is not a {d} recording (no `{marker}`)",
                        p.display()
                    );
                }
            } else {
                assert_eq!(want, lock::LockLabel::Unverified, "{}", p.display());
            }
        }
    }
}

/// The macOS and Windows recordings live in their own dirs, which exist
/// before the first recording (`.gitkeep`).
#[test]
fn macos_and_windows_recording_dirs_exist() {
    for platform in [LockPlatform::Macos, LockPlatform::Windows] {
        let dir = recording_path("x", platform);
        assert!(dir.parent().unwrap().is_dir(), "{}", dir.display());
    }
}
