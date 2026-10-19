//! Differential check: the guard's here-document handling versus the shells
//! actually installed. Every shell must satisfy "no bypass": if it ran the
//! marker command, the engine must deny the line. For bash (any version),
//! exact agreement is required too: ran == denied. For other shells an
//! over-deny (engine denies, shell did not run the marker) is tolerated only
//! for the cases in `KNOWN_NON_BASH_OVER_DENIES`. The marker is a harmless
//! `touch ran` executed with a tempdir as the working directory.

use std::process::Command;

use saiifeguard::engine::{Decision, Engine};
use saiifeguard::pack::load_pack_str;

const PACK: &str = r#"
[pack]
id = "test.touch"
name = "Touch"
triggers = ["touch"]

[[deny]]
pattern = '^touch'
reason = "marker command"
"#;

const TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

fn engine() -> Engine {
    let mut warnings = Vec::new();
    let pack = load_pack_str("<shell_differential>", PACK, &mut warnings).expect("pack loads");
    assert!(warnings.is_empty(), "pack warnings: {warnings:?}");
    Engine::new(vec![pack]).with_budget(TEST_BUDGET)
}

/// Cases where zsh 5.9 and dash end the here-document differently from bash:
/// they do not stop at an `EOF)`-style line, so the rest is body and the
/// marker never runs, while the engine (following bash) denies. Over-denying
/// is the safe direction, so it is allowed (and noted) for non-bash shells.
const KNOWN_NON_BASH_OVER_DENIES: [&str; 3] = [
    "x=$(cat <<EOF\nhi\nEOF)\ntouch ran",
    "x=$(cat <<'EOF'\na\nEOF )\ntouch ran",
    "x=$(cat <<EOF\nEOF x)\ntouch ran\nEOF\n)",
];

fn cases() -> Vec<String> {
    [
        // marker inside a body (data, never runs)
        "x=$(cat <<EOF\ntouch ran\nEOF\n)",
        "x=$(cat <<'EOF'\ntouch ran\nEOF\n)",
        "x=$(cat <<\"EOF\"\ntouch ran\nEOF\n)",
        "cat <<EOF\ntouch ran\nEOF",
        // marker right after the body
        "x=$(cat <<EOF\nhi\nEOF\n)\ntouch ran",
        "x=$(cat <<EOF\nhi\nEOF)\ntouch ran",
        "x=$(cat <<'EOF'\na\nEOF )\ntouch ran",
        "cat <<EOF\nhi\nEOF\ntouch ran",
        // dashed delimiter with tab-indented body and terminator
        "x=$(cat <<-EOF\n\ttouch ran\n\tEOF\n)",
        "x=$(cat <<-EOF\n\thi\n\tEOF\n)\ntouch ran",
        "cat <<-'EOF'\n\ttouch ran\n\tEOF\ntouch ran",
        // two here-documents on one line
        "cat <<A; cat <<B\nx\nA\ntouch ran\nB",
        "x=$(cat <<A <<B\none\nA\ntwo\nB\n)\ntouch ran",
        "cat <<A; cat <<B\nx\nA\ny\nB\ntouch ran",
        // backticks
        "x=`cat <<EOF\ntouch ran\nEOF\n`",
        "x=`cat <<EOF\nhi\nEOF\n`\ntouch ran",
        // body line that merely starts with the delimiter
        "x=$(cat <<EOF\nEOF x)\ntouch ran\nEOF\n)",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn candidate_shells() -> Vec<String> {
    let mut paths: Vec<std::path::PathBuf> = [
        "/bin/bash",
        "/usr/bin/bash",
        "/bin/sh",
        "/bin/zsh",
        "/usr/bin/zsh",
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .collect();
    // `bash` on PATH.
    if let Ok(path) = std::env::var("PATH") {
        paths.extend(std::env::split_paths(&path).map(|d| d.join("bash")));
    }
    // One run per real binary.
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for p in paths {
        if let Ok(real) = p.canonicalize() {
            if real.is_file() && seen.insert(real) {
                out.push(p.to_string_lossy().into_owned());
            }
        }
    }
    out
}

fn version_line(shell: &str) -> String {
    Command::new(shell)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .map(str::to_string)
        })
        .unwrap_or_else(|| "<unknown version>".to_string())
}

#[test]
fn heredoc_matches_installed_shells() {
    let shells = candidate_shells();
    if shells.is_empty() {
        println!("no shells found; skipped");
        return;
    }
    let e = engine();
    let mut failures = Vec::new();
    for shell in &shells {
        let version = version_line(shell);
        let is_bash = version.contains("bash");
        for (n, case) in cases().into_iter().enumerate() {
            let tmp = tempfile::tempdir().expect("tempdir");
            if let Err(err) = Command::new(shell)
                .arg("-c")
                .arg(&case)
                .current_dir(tmp.path())
                .output()
            {
                println!("note: {shell} cannot be executed ({err}); skipped");
                break;
            }
            let ran = tmp.path().join("ran").exists();
            let denied = matches!(e.evaluate(&case), Decision::Deny { .. });
            if ran && !denied {
                // Hard invariant on every shell: no bypass.
                failures.push(format!(
                    "{shell} ({version}): BYPASS, shell ran marker but engine allows\n  case: {case:?}"
                ));
            } else if !ran && denied {
                if is_bash {
                    failures.push(format!(
                        "{shell} ({version}): bash over-deny\n  case: {case:?}"
                    ));
                } else {
                    if KNOWN_NON_BASH_OVER_DENIES.contains(&case.as_str()) {
                        println!("note: {shell} over-denies case {n}: {case:?}");
                    } else {
                        failures.push(format!(
                            "{shell} ({version}): unlisted non-bash over-deny\n  case: {case:?}"
                        ));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "mismatches:\n{}", failures.join("\n"));
}
