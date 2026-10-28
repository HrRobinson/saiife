//! `saiife __fake-mcp-server` (debug builds only): a scripted MCP stdio
//! server for the gateway and sandbox tests. Never in a release binary,
//! like the `SAIIFE_EVAL_FAULT` seam.
//!
//! Tools (all always callable; the list shows them unless `--tools` gives
//! the list):
//! - `echo`: the arguments, as JSON text;
//! - `introspect`: `{env, cwd, no_new_privs, fds}` of this process;
//! - `read_file {path}` (`--read-file-tool`): the file, or `isError` with
//!   the errno name (`EACCES`);
//! - `echo_env` (`--echo-env VAR`): the value of `VAR`, which is also
//!   written to stderr at start;
//! - `change_tools`: sends `notifications/tools/list_changed` and adds
//!   `added_tool` to the list;
//! - `--hang-tool T`: never answers `T`;
//! - `--huge-tool T`: answers `T` with `bytes` (default 8 MiB) of text on
//!   one line.
//!
//! Every message received is logged to stderr as `fake-mcp: got <method>`
//! (`notifications/cancelled` with its request id).

use saiife_mcp::codec::{encode, LineReader};
use saiife_mcp::jsonrpc::{Id, Message, RpcError};
use saiife_mcp::types as t;
use serde_json::{json, Map, Value};
use std::io::Write;
use std::process::ExitCode;

#[derive(clap::Args, Debug, Default)]
pub struct FakeArgs {
    /// The tools to list, as a JSON array of MCP tools.
    #[arg(long)]
    tools: Option<String>,
    /// Add the `echo_env` tool for this variable.
    #[arg(long = "echo-env", value_name = "VAR")]
    echo_env: Option<String>,
    /// Exit (code 3) after answering this many tool calls.
    #[arg(long = "crash-after", value_name = "N")]
    crash_after: Option<u64>,
    /// Never answer calls to this tool.
    #[arg(long = "hang-tool", value_name = "T")]
    hang_tool: Option<String>,
    /// Answer calls to this tool with a huge line.
    #[arg(long = "huge-tool", value_name = "T")]
    huge_tool: Option<String>,
    /// Answer `initialize` with this protocol version.
    #[arg(long, value_name = "V")]
    version: Option<String>,
    /// Send a `sampling/createMessage` request after `initialized`.
    #[arg(long = "server-request")]
    server_request: bool,
    /// Add the `read_file` tool.
    #[arg(long = "read-file-tool")]
    read_file_tool: bool,
}

const DEFAULT_HUGE: usize = 8 * 1024 * 1024;
const MAX_LINE: usize = 16 * 1024 * 1024;

fn tool(name: &str, desc: &str) -> Value {
    json!({
        "name": name,
        "description": desc,
        "inputSchema": {"type": "object"},
    })
}

struct Fake {
    args: FakeArgs,
    tools: Vec<Value>,
    calls: u64,
}

pub fn run(args: FakeArgs) -> ExitCode {
    let tools = match &args.tools {
        Some(j) => match serde_json::from_str::<Vec<Value>>(j) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("fake-mcp: --tools is not a JSON array");
                return ExitCode::from(2);
            }
        },
        None => {
            let mut v = vec![
                tool("echo", "Echo the arguments."),
                tool("introspect", "Report this process."),
            ];
            if args.read_file_tool {
                v.push(tool("read_file", "Read a file."));
            }
            if args.echo_env.is_some() {
                v.push(tool("echo_env", "Echo an environment variable."));
            }
            for t in [&args.hang_tool, &args.huge_tool].into_iter().flatten() {
                v.push(tool(t, "Scripted."));
            }
            v
        }
    };
    if let Some(var) = &args.echo_env {
        let val = std::env::var(var).unwrap_or_default();
        eprintln!("fake-mcp: {var}={val}");
    }
    let mut fake = Fake {
        args,
        tools,
        calls: 0,
    };
    let stdin = std::io::stdin();
    let mut reader = LineReader::new(stdin.lock(), MAX_LINE);
    loop {
        let msg = match reader.next_message() {
            Ok(None) | Err(_) => return ExitCode::SUCCESS,
            Ok(Some(Err(e))) => {
                send(&e.into_message());
                continue;
            }
            Ok(Some(Ok(m))) => m,
        };
        if let Some(code) = fake.handle(msg) {
            return code;
        }
    }
}

fn send(m: &Message) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(encode(m).as_bytes());
    let _ = out.flush();
}

impl Fake {
    /// `Some` ends the server with that exit code.
    fn handle(&mut self, msg: Message) -> Option<ExitCode> {
        match msg {
            Message::Request { id, method, params } => {
                eprintln!("fake-mcp: got {method}");
                self.request(id, &method, params)
            }
            Message::Notification { method, params } => {
                if method == t::CANCELLED {
                    let rid = params
                        .as_ref()
                        .and_then(|p| p.get("requestId"))
                        .map_or_else(String::new, Value::to_string);
                    eprintln!("fake-mcp: got {method} {rid}");
                } else {
                    eprintln!("fake-mcp: got {method}");
                }
                if method == t::INITIALIZED && self.args.server_request {
                    send(&Message::request(
                        Id::String("srv-1".into()),
                        "sampling/createMessage",
                        Some(json!({"messages": [], "maxTokens": 1})),
                    ));
                }
                None
            }
            Message::Response { id, .. } => {
                eprintln!(
                    "fake-mcp: server request {} answered: result",
                    id.to_value()
                );
                None
            }
            Message::Error { id, error } => {
                let id = id.map_or(Value::Null, |i| i.to_value());
                eprintln!(
                    "fake-mcp: server request {id} answered: error {}",
                    error.code
                );
                None
            }
        }
    }

    fn request(&mut self, id: Id, method: &str, params: Option<Value>) -> Option<ExitCode> {
        let result = match method {
            t::INITIALIZE => {
                let asked = params
                    .as_ref()
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let v = self
                    .args
                    .version
                    .clone()
                    .unwrap_or_else(|| saiife_mcp::version::negotiate(asked).to_string());
                json!({
                    "protocolVersion": v,
                    "capabilities": {"tools": {"listChanged": true}},
                    "serverInfo": {"name": "saiife-fake-mcp", "version": "0"},
                })
            }
            t::PING => json!({}),
            t::TOOLS_LIST => json!({"tools": self.tools}),
            t::TOOLS_CALL => return self.call(id, params),
            _ => {
                send(&Message::error(
                    Some(id),
                    RpcError::method_not_found(method),
                ));
                return None;
            }
        };
        send(&Message::response(id, result));
        None
    }

    fn call(&mut self, id: Id, params: Option<Value>) -> Option<ExitCode> {
        let p = params.unwrap_or(Value::Null);
        let name = p.get("name").and_then(Value::as_str).unwrap_or_default();
        let args = p
            .get("arguments")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if self.args.hang_tool.as_deref() == Some(name) {
            return None;
        }
        let result = if self.args.huge_tool.as_deref() == Some(name) {
            let n = args
                .get("bytes")
                .and_then(Value::as_u64)
                .map_or(DEFAULT_HUGE, |n| n as usize);
            text("x".repeat(n), false)
        } else {
            match name {
                "echo" => text(Value::Object(args).to_string(), false),
                "introspect" => text(introspect().to_string(), false),
                "read_file" => read_file(&args),
                "echo_env" => {
                    let var = self.args.echo_env.clone().unwrap_or_default();
                    text(std::env::var(var).unwrap_or_default(), false)
                }
                "change_tools" => {
                    send(&Message::notification(t::TOOLS_LIST_CHANGED, None));
                    self.tools.push(tool("added_tool", "Added."));
                    text("changed".into(), false)
                }
                _ if self.tools.iter().any(|t| t["name"] == name) => {
                    text(Value::Object(args).to_string(), false)
                }
                _ => {
                    send(&Message::error(
                        Some(id),
                        RpcError::invalid_params(format!("unknown tool {name}")),
                    ));
                    return None;
                }
            }
        };
        send(&Message::response(id, result));
        self.calls += 1;
        if self.args.crash_after.is_some_and(|n| self.calls >= n) {
            eprintln!("fake-mcp: crashing after {} calls", self.calls);
            return Some(ExitCode::from(3));
        }
        None
    }
}

fn text(s: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": s}], "isError": is_error})
}

fn read_file(args: &Map<String, Value>) -> Value {
    let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
    match std::fs::read_to_string(path) {
        Ok(s) => text(s, false),
        Err(e) => {
            let name = match e.raw_os_error() {
                Some(13) => "EACCES".to_string(),
                Some(2) => "ENOENT".to_string(),
                Some(n) => format!("errno {n}"),
                None => "error".to_string(),
            };
            text(format!("read_file: {name}"), true)
        }
    }
}

fn introspect() -> Value {
    let env: Map<String, Value> = std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                Value::String(v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let nnp = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("NoNewPrivs:").map(|v| v.trim().to_string()))
        })
        .unwrap_or_default();
    json!({"env": env, "cwd": cwd, "no_new_privs": nnp, "fds": open_fds()})
}

/// The open descriptors, without the one that lists them.
fn open_fds() -> Vec<i64> {
    let Ok(dir) = std::fs::read_dir("/proc/self/fd") else {
        return Vec::new();
    };
    let mut out: Vec<i64> = dir
        .flatten()
        .filter(|e| {
            // The listing's own handle points at the fd dir it lists.
            std::fs::read_link(e.path())
                .map(|p| !p.to_string_lossy().ends_with("/fd"))
                .unwrap_or(false)
        })
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    out.sort_unstable();
    out
}
