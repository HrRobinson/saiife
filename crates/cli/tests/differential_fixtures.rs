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
