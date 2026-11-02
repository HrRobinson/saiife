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

/// Not judged for any other reason: no allow either.
#[test]
fn a_powershell_payload_that_cannot_be_judged_is_blocked() {
    let dir = tempfile::tempdir().unwrap();
    // Over the payload limit, over the parse limit, not JSON, no command.
    let large = format!(
        r#"{{"tool_name":"PowerShell","tool_input":{{"command":"{}"}}}}"#,
        "x".repeat(300 * 1024)
    );
    let huge = format!(
        r#"{{"tool_name":"PowerShell","tool_input":{{"command":"{}"}}}}"#,
        "x".repeat(16 * 1024 * 1024)
    );
    let cases: [&[u8]; 4] = [
        large.as_bytes(),
        huge.as_bytes(),
        br#"{"tool_name":"PowerShell""#,
        br#"{"tool_name":"PowerShell","tool_input":{}}"#,
    ];
    for payload in cases {
        let (code, stderr) = check(dir.path(), payload);
        assert_eq!(code, 2, "{} bytes: {stderr}", payload.len());
        assert!(stderr.contains("BLOCKED (fail closed)"), "{stderr}");
    }
    // A Bash payload as broken stays as it was.
    let (code, stderr) = check(dir.path(), br#"{"tool_name":"Bash""#);
    assert_eq!(code, 0, "{stderr}");
}
