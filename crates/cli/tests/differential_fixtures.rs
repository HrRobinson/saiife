//! `scripts/differential-windows.ps1` runs its cmd fixtures on a real shell, so
//! what its fixtures may do is checked here, where it can run on any OS.

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The script is the first thing to run the readers on real shells, so what it
/// promises never to do is pinned: no fixture a shell actually runs can delete.
#[test]
fn the_differential_runs_nothing_destructive() {
    let root = root();
    let text = fs::read_to_string(root.join("scripts/differential-windows.fixtures.json")).unwrap();
    let fixtures: serde_json::Value = serde_json::from_str(&text).unwrap();
    let cmd = fixtures["cmd"].as_array().unwrap();
    assert!(cmd.len() > 40);
    for f in cmd {
        let line = f["line"].as_str().unwrap().to_ascii_lowercase();
        let words = line.split(|c: char| !c.is_ascii_alphanumeric());
        for word in words {
            assert!(
                ![
                    "rd",
                    "rmdir",
                    "del",
                    "erase",
                    "format",
                    "move",
                    "ren",
                    "rename",
                    "copy",
                    "xcopy",
                    "robocopy",
                    "mklink",
                    "attrib",
                    "icacls",
                    "takeown",
                    "reg",
                    "net",
                    "sc",
                    "taskkill",
                    "powershell",
                    "pwsh",
                    "git",
                ]
                .contains(&word),
                "the differential must not run {word}: {line}"
            );
        }
    }
    // PowerShell lines are parsed by name; they must never reach an invocation.
    let script = fs::read_to_string(root.join("scripts/differential-windows.ps1")).unwrap();
    assert!(script.contains("Parser]::ParseInput"));
    assert!(!script.contains("Invoke-Expression"));
    assert!(!script.contains("iex "));
}

/// A mismatch only becomes an exception with a reason, and nothing else: the plain
/// `over: true` of the first fixtures is closed, and an exception for one line
/// leaves every other mismatch failing.
#[test]
fn every_new_exception_says_why_it_is_safe() {
    let text =
        fs::read_to_string(root().join("scripts/differential-windows.fixtures.json")).unwrap();
    let fixtures: serde_json::Value = serde_json::from_str(&text).unwrap();
    let reason = |v: &serde_json::Value, what: &str| {
        let why = v.as_str().unwrap_or_default();
        assert!(why.len() > 40, "{what} has no reason: {v}");
    };
    let cmd = fixtures["cmd"].as_array().unwrap();
    let bare = cmd.iter().filter(|f| f["over"] == true).count();
    assert_eq!(
        bare, 15,
        "a new over-read needs its reason as the value of `over`"
    );
    let with_reason: Vec<_> = cmd.iter().filter(|f| f["over"].is_string()).collect();
    assert_eq!(with_reason.len(), 5);
    for f in with_reason {
        reason(&f["over"], f["line"].as_str().unwrap());
    }
    for d in fixtures["powershell_documented"].as_array().unwrap() {
        let line = d["line"].as_str().unwrap();
        reason(&d["reason"], line);
        assert!(!d["parser"].as_array().unwrap().is_empty(), "{line}");
        assert!(!d["reader"].as_array().unwrap().is_empty(), "{line}");
    }
    for a in fixtures["alias_over"].as_array().unwrap() {
        reason(&a["reason"], a["alias"].as_str().unwrap());
    }
}
