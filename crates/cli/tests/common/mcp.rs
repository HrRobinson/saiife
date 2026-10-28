//! An in-process MCP client for `saiife mcp` under test: the real binary
//! with piped stdio, spoken to with `saiife_mcp::codec`. A reader thread
//! sorts what the server writes into answers (by id) and notifications.
//! The server's stderr goes to a file, so it can never block on a pipe.
#![allow(dead_code)]

use super::daemon::TestDaemon;
use saiife_mcp::codec::{self, LineReader};
use saiife_mcp::jsonrpc::{Id, Message};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a test waits for an answer.
pub const ANSWER: Duration = Duration::from_secs(60);

pub struct McpClient {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    next_id: i64,
    answers: Arc<Mutex<HashMap<Id, Value>>>,
    notes: Receiver<Value>,
    answered: Receiver<()>,
    stderr: PathBuf,
}

/// Where `saiife mcp` runs: the dirs of a daemon under test.
pub struct Where<'a> {
    /// The temp root: HOME, data and the runtime dir live under it.
    pub root: &'a Path,
    pub config: &'a Path,
    pub audit: &'a Path,
    /// The cwd (the project).
    pub cwd: &'a Path,
}

impl McpClient {
    /// `saiife mcp --system-config <daemon's config> <args>` in
    /// `<daemon>/project`.
    pub fn spawn(d: &TestDaemon, args: &[&str]) -> McpClient {
        Self::spawn_env(d, args, &[])
    }

    pub fn spawn_env(d: &TestDaemon, args: &[&str], env: &[(&str, &str)]) -> McpClient {
        let cwd = d.path().join("project");
        std::fs::create_dir_all(&cwd).unwrap();
        Self::spawn_at(
            &Where {
                root: d.path(),
                config: &d.config(),
                audit: &d.audit_dir(),
                cwd: &cwd,
            },
            args,
            env,
        )
    }

    pub fn spawn_at(w: &Where, args: &[&str], env: &[(&str, &str)]) -> McpClient {
        let stderr = w.root.join(format!(
            "mcp-{}.stderr",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let log = std::fs::File::create(&stderr).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_saiife"));
        cmd.arg("mcp")
            .arg("--system-config")
            .arg(w.config)
            .args(args)
            .current_dir(w.cwd)
            .env("HOME", w.root.join("home"))
            .env("XDG_RUNTIME_DIR", w.root.join("no-runtime"))
            .env("PATH", "/usr/bin:/bin")
            .env("SAIIFE_DATA_DIR", w.root.join("data"))
            .env("SAIIFE_AUDIT_DIR", w.audit)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log));
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let answers: Arc<Mutex<HashMap<Id, Value>>> = Arc::default();
        let (ntx, notes) = mpsc::channel();
        let (atx, answered) = mpsc::channel();
        let a = Arc::clone(&answers);
        std::thread::spawn(move || {
            let mut r = LineReader::new(BufReader::new(stdout), 64 << 20);
            while let Ok(Some(m)) = r.next_message() {
                let m = m.unwrap_or_else(|e| panic!("saiife mcp wrote a bad line: {e}"));
                let v = m.to_value();
                match m {
                    Message::Response { id, .. } | Message::Error { id: Some(id), .. } => {
                        a.lock().unwrap().insert(id, v);
                        let _ = atx.send(());
                    }
                    Message::Error { id: None, .. } => {
                        a.lock().unwrap().insert(Id::String("null".into()), v);
                        let _ = atx.send(());
                    }
                    Message::Notification { .. } => {
                        let _ = ntx.send(v);
                    }
                    Message::Request { .. } => panic!("saiife mcp sent a request: {v}"),
                }
            }
        });
        McpClient {
            child: Some(child),
            stdin,
            next_id: 0,
            answers,
            notes,
            answered,
            stderr,
        }
    }

    /// One raw line to the server's stdin.
    pub fn send_line(&mut self, line: &str) {
        let s = self.stdin.as_mut().expect("stdin open");
        s.write_all(line.as_bytes()).unwrap();
        s.write_all(b"\n").unwrap();
        s.flush().unwrap();
    }

    fn send(&mut self, m: &Message) {
        let line = codec::encode(m);
        let s = self.stdin.as_mut().expect("stdin open");
        s.write_all(line.as_bytes()).unwrap();
        s.flush().unwrap();
    }

    /// Send a request; its id.
    pub fn send_request(&mut self, method: &str, params: Value) -> Id {
        self.next_id += 1;
        let id = Id::from(self.next_id);
        self.send(&Message::request(id.clone(), method, Some(params)));
        id
    }

    /// The answer to `id` (the whole message), waiting at most `limit`.
    pub fn answer_within(&mut self, id: &Id, limit: Duration) -> Option<Value> {
        let end = Instant::now() + limit;
        loop {
            if let Some(v) = self.answers.lock().unwrap().remove(id) {
                return Some(v);
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            match self
                .answered
                .recv_timeout(left.min(Duration::from_millis(200)))
            {
                Ok(()) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return self.answers.lock().unwrap().remove(id);
                }
            }
        }
    }

    /// A request and its whole answer message (`result` or `error`).
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.send_request(method, params);
        self.answer_within(&id, ANSWER)
            .unwrap_or_else(|| panic!("no answer to {method}; stderr: {}", self.stderr_text()))
    }

    /// `result` of a request that must succeed.
    pub fn result(&mut self, method: &str, params: Value) -> Value {
        let a = self.request(method, params);
        assert!(a.get("error").is_none(), "{method}: {a}");
        a["result"].clone()
    }

    pub fn notify(&mut self, method: &str, params: Value) {
        self.send(&Message::notification(method, Some(params)));
    }

    pub fn next_notification(&self, limit: Duration) -> Option<Value> {
        self.notes.recv_timeout(limit).ok()
    }

    /// `initialize` (as `2025-11-25`) and `notifications/initialized`.
    pub fn initialize(&mut self) -> Value {
        self.initialize_as("2025-11-25")
    }

    pub fn initialize_as(&mut self, version: &str) -> Value {
        let r = self.result(
            "initialize",
            json!({
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            }),
        );
        self.notify("notifications/initialized", json!({}));
        r
    }

    /// `tools/call name arguments`: the result (an `isError` result too).
    pub fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.result("tools/call", json!({"name": name, "arguments": arguments}))
    }

    pub fn tool_names(&mut self) -> Vec<String> {
        self.result("tools/list", json!({}))["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    /// End of input.
    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    pub fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child.as_mut().unwrap().try_wait().unwrap()
    }

    /// Wait (at most `limit`) for the server to exit.
    pub fn wait_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let end = Instant::now() + limit;
        loop {
            if let Some(s) = self.try_wait() {
                return Some(s);
            }
            if Instant::now() > end {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn stderr_text(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        self.stdin = None;
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// The text of every text item of a tool result, joined by `\n`.
pub fn texts(result: &Value) -> String {
    result["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}
