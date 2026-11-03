//! `saiife check`, end to end: a `PowerShell` tool call goes through the
//! PowerShell reader on every OS, and what it cannot read is never an allow.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Run `saiife check --hook-exit` on `stdin`; the exit code and stderr.
fn check(dir: &Path, stdin: &[u8]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, dir);
    let mut child = cmd
        .args(["check", "--hook-exit", "--agent", "claude"])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A payload too large is drained, but may not be read to its end.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `check` with the audit in `audit` and `config` as the system config.
fn check_as(dir: &Path, audit: &Path, stdin: &[u8], config: &Path) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
    let _sandbox = common::hermetic(&mut cmd, audit);
    let mut child = cmd
        .args([
            "check",
            "--hook-exit",
            "--agent",
            "claude",
            "--system-config",
        ])
        .arg(config)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn call(dir: &Path, tool: &str, command: &str) -> (i32, String) {
    let payload = serde_json::json!({
        "tool_name": tool,
        "cwd": dir,
        "tool_input": { "command": command },
    });
    check(dir, payload.to_string().as_bytes())
}

/// `g`it` is `git` to PowerShell, and an unterminated substitution to POSIX.
/// `R`m` is `rm` the same way, on a file the path rules protect.
#[test]
fn a_backtick_means_what_it_means_to_powershell() {
    let dir = tempfile::tempdir().unwrap();
    for cmd in ["g`it reset --hard", "R`m -Recurse -Force .env"] {
        let (code, stderr) = call(dir.path(), "PowerShell", cmd);
        assert_eq!(code, 2, "{cmd}: {stderr}");
        assert!(stderr.contains("BLOCKED by core."), "{cmd}: {stderr}");
        // The same text as Bash is not what was judged above.
        let (code, stderr) = call(dir.path(), "Bash", cmd);
        assert_eq!(code, 0, "{cmd}: {stderr}");
    }
}

/// The two grammars disagree the other way too: POSIX takes `\` as an escape.
#[test]
fn a_backslash_is_no_escape_to_powershell() {
    let dir = tempfile::tempdir().unwrap();
    let (code, stderr) = call(dir.path(), "Bash", r"git reset \--hard");
    assert_eq!(code, 2, "{stderr}");
    let (code, stderr) = call(dir.path(), "PowerShell", r"git reset \--hard");
    assert_eq!(code, 0, "{stderr}");
}

#[test]
fn what_the_reader_cannot_read_is_blocked() {
    let dir = tempfile::tempdir().unwrap();
    for cmd in [
        "iex $x",
        "& $x",
        "pwsh -e !!notbase64",
        "[IO.File]::Delete('x')",
        "Set-Alias x Remove-Item",
        "'open",
        "Get-Content $x",
    ] {
        let (code, stderr) = call(dir.path(), "PowerShell", cmd);
        assert_eq!(code, 2, "{cmd}: {stderr}");
        assert!(stderr.contains("BLOCKED"), "{cmd}: {stderr}");
    }
    let (code, stderr) = call(dir.path(), "PowerShell", "git status; npm test");
    assert_eq!(code, 0, "{stderr}");
    // POSIX keeps its recorded fail-open.
    let (code, stderr) = call(dir.path(), "Bash", r#"eval "$(x)""#);
    assert_eq!(code, 0, "{stderr}");
}

/// A broken payload whose tool is `PowerShell` is no allow, in any mode. The
/// word elsewhere in a broken payload is nothing.
#[test]
fn a_broken_powershell_payload_is_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let cases: [&[u8]; 2] = [
        br#"{"tool_name":"PowerShell""#,
        br#"{"tool_name":"PowerShell","tool_input":{}}"#,
    ];
    for payload in cases {
        let (code, stderr) = check(dir.path(), payload);
        assert_eq!(code, 2, "{stderr}");
        assert!(stderr.contains("BLOCKED (fail closed)"), "{stderr}");
    }
    for payload in [
        &br#"{"tool_name":"Bash""#[..],
        br#"{"tool_name":"Bash","tool_input":{"command":"powershell"#,
    ] {
        let (code, stderr) = check(dir.path(), payload);
        assert_eq!(code, 0, "{stderr}");
    }
}

/// Fail policy, through the real binary, in both modes: what is too large to
/// judge follows `Fail`, what the reader cannot read denies, and the record says
/// which.
#[test]
fn fail_policy_in_developer_and_locked() {
    use saiife_audit::{store, DecisionKind};
    let large = format!(
        r#"{{"tool_name":"PowerShell","tool_input":{{"command":"{}"}}}}"#,
        "x".repeat(300 * 1024)
    );
    let huge = format!(
        r#"{{"tool_name":"PowerShell","tool_input":{{"command":"{}"}}}}"#,
        "x".repeat(16 * 1024 * 1024)
    );
    let last = |dir: &Path| {
        store::read_all(dir)
            .records
            .last()
            .map(|r| r.decision)
            .unwrap()
    };
    for locked in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("system-config.toml");
        let text = if locked {
            "version = 2\n[guard]\nfail = \"closed\"\n"
        } else {
            "version = 2\n"
        };
        std::fs::write(&config, text).unwrap();
        let audit = dir.path().join("audit");
        std::fs::create_dir(&audit).unwrap();
        let (code, kind) = if locked {
            (2, DecisionKind::ErrorDenied)
        } else {
            (0, DecisionKind::ErrorAllowed)
        };
        for payload in [large.as_bytes(), huge.as_bytes()] {
            let (got, stderr) = check_as(dir.path(), &audit, payload, &config);
            assert_eq!(
                got,
                code,
                "locked {locked}, {} bytes: {stderr}",
                payload.len()
            );
            assert_eq!(last(&audit), kind, "locked {locked}");
        }
        let call = serde_json::json!({
            "tool_name": "PowerShell",
            "cwd": dir.path(),
            "tool_input": { "command": "iex $x" },
        })
        .to_string();
        let (got, stderr) = check_as(dir.path(), &audit, call.as_bytes(), &config);
        assert_eq!(got, 2, "locked {locked}: {stderr}");
        assert!(stderr.contains("BLOCKED by"), "{stderr}");
        assert_eq!(last(&audit), DecisionKind::Deny, "locked {locked}");
    }
}
