//! `saiife __eval --serve`, the service's warm re-judge worker (plan 21,
//! Task 2): length-prefixed frames in and out, lexical whatever it is asked.
//! The pool itself is tested in `crates/cli/src/rejudge.rs`.

use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn request(payload: &str) -> Vec<u8> {
    let req = json!({
        "payload": payload,
        "packs": ["core.secrets", "core.filesystem", "core.git", "core.lock", "core.self"],
        "budget_ms": 1000,
        "agent": "claude",
        "vars": [["HOME", "/home/other"], ["USER", "other"], ["LANG", "C"]],
    });
    frame(&serde_json::to_vec(&req).unwrap())
}

fn bash(cwd: &str, command: &str) -> String {
    json!({
        "session_id": "c-1", "cwd": cwd, "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "toolu_01"
    })
    .to_string()
}

/// The worker run on `input`, with a cleared environment as the service
/// starts it.
fn serve(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .args(["__eval", "--serve"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();
    out
}

/// The answer frames on `out`.
fn answers(mut out: &[u8]) -> Vec<Value> {
    let mut all = Vec::new();
    while !out.is_empty() {
        let mut len = [0u8; 4];
        out.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        out.read_exact(&mut body).unwrap();
        all.push(serde_json::from_slice(&body).unwrap());
    }
    all
}

#[test]
fn serve_answers_many_frames() {
    let mut input = Vec::new();
    for cmd in ["ls -la", "cat ~/.ssh/id_rsa", "git status", "rm -rf /"] {
        input.extend(request(&bash("/home/other/app", cmd)));
    }
    let out = serve(&input);
    assert!(out.status.success(), "{out:?}");
    let got = answers(&out.stdout);
    let verdicts: Vec<&str> = got.iter().map(|a| a["verdict"].as_str().unwrap()).collect();
    assert_eq!(verdicts, ["allow", "deny", "allow", "deny"]);
    // `~` is the HOME the request carries.
    assert!(
        got[1]["reason"]
            .as_str()
            .unwrap()
            .contains("/home/other/.ssh/id_rsa"),
        "{}",
        got[1]
    );
}

#[test]
fn serve_exits_on_a_bad_frame() {
    let good = request(&bash("/tmp", "ls"));
    // Not JSON: one answer for the good frame, then exit 1.
    let mut input = good.clone();
    input.extend(frame(b"not json"));
    input.extend(good.clone());
    let out = serve(&input);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(answers(&out.stdout).len(), 1);
    // A length over the limit is never read.
    let out = serve(&u32::MAX.to_be_bytes());
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    // A stream that ends inside a frame.
    let out = serve(&good[..good.len() - 1]);
    assert_eq!(out.status.code(), Some(1));
    let out = serve(&[0, 0]);
    assert_eq!(out.status.code(), Some(1));
    // EOF at a frame boundary is the end: exit 0.
    let out = serve(b"");
    assert!(out.status.success());
}

/// The worker never looks at the file system, whatever view it is asked
/// for: a link that the host would follow to a secret is judged as spelled.
#[cfg(unix)]
#[test]
fn serve_is_lexical_whatever_it_is_asked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("secrets")).unwrap();
    std::fs::write(root.join("secrets/.env"), "K=V\n").unwrap();
    std::os::unix::fs::symlink(root.join("secrets/.env"), root.join("notes.txt")).unwrap();
    let cwd = root.to_str().unwrap();
    let payload = bash(cwd, "cat notes.txt");
    let mut req: Value = serde_json::from_slice(&request(&payload)[4..]).unwrap();
    req["view"] = json!("host");
    let out = serve(&frame(&serde_json::to_vec(&req).unwrap()));
    assert!(out.status.success(), "{out:?}");
    assert_eq!(answers(&out.stdout)[0]["verdict"], "allow");
    // The same request, judged by the hook's one-shot worker on the host,
    // follows the link and denies.
    let mut child = Command::new(env!("CARGO_BIN_EXE_saiife"))
        .arg("__eval")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&req).unwrap())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let host: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(host["verdict"], "deny", "{host}");
}
