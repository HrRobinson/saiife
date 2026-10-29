//! One gateway child (plan 17, decisions 12 and 13): the process started
//! through `saiife __mcp-spawn`, its three pipes, and the JSON-RPC session
//! the daemon runs on them as an MCP client.
//!
//! Everything read from the child is untrusted: lines are capped (an
//! over-cap line stops the child), server-initiated requests get `-32601`
//! (`ping` gets `{}`), tool lists are bounded and cleaned, results are
//! kept as JSON values and masked, and stderr is masked and rate-capped
//! before it reaches the daemon's journal.

use saiife_broker::mask::Masker;
use saiife_mcp::codec::{decode_line, encode};
use saiife_mcp::jsonrpc::{Id, Message, RpcError};
use saiife_mcp::types::{self as t, Tool};
use saiife_system::sandbox::{encode_spec, SpawnSpec};
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, ChildStdout};
use tokio::sync::{mpsc, oneshot, Semaphore};

use super::{ChildError, Log};

/// Calls in flight per child (decision 13).
pub const POOL_SIZE: usize = 4;
/// At most this many tools are kept from `tools/list`.
pub const MAX_TOOLS: usize = 1000;
/// A tool description is cut at this many bytes.
pub const MAX_DESCRIPTION: usize = 2 * 1024;
/// A tool schema over this many bytes (compact JSON) is replaced.
pub const MAX_SCHEMA: usize = 64 * 1024;
/// A child's line may be `max_response_bytes` plus this (decision 2).
pub const LINE_SLACK: usize = 64 * 1024;
/// Child stderr budget per minute (decision 13).
pub const STDERR_PER_MINUTE: usize = 64 * 1024;
/// One stderr line is cut at this many bytes.
const STDERR_LINE: usize = 4 * 1024;
/// `tools/list` pages at most.
const MAX_PAGES: usize = 64;
/// The text an image or audio item is replaced with.
pub const OMITTED: &str = "[image content omitted by saiife]";
/// Tool names longer than this (bytes) are dropped.
const MAX_TOOL_NAME: usize = 128;

type Reply = Result<(Value, usize), ChildError>;

/// What the reader tells the supervisor.
#[derive(Debug)]
pub(crate) enum Event {
    /// `notifications/tools/list_changed`.
    ListChanged,
    /// The child broke the protocol in a way that stops it.
    Fatal(String),
}

/// The JSON-RPC side of a running child, shared by callers.
pub(crate) struct Conn {
    /// Lines to the child's stdin. `None` once stdin was closed (EOF).
    out: Mutex<Option<mpsc::Sender<String>>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    next_id: AtomicU64,
    pub pool: Semaphore,
    pub masker: Arc<Masker>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Conn {
    fn new(out: mpsc::Sender<String>, masker: Arc<Masker>) -> Conn {
        Conn {
            out: Mutex::new(Some(out)),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            pool: Semaphore::new(POOL_SIZE),
            masker,
        }
    }

    /// Close the child's stdin: the writer task ends and drops the pipe.
    pub fn close_stdin(&self) {
        lock(&self.out).take();
    }

    async fn send_line(&self, m: &Message) -> Result<(), ChildError> {
        let tx = lock(&self.out).clone().ok_or(ChildError::Exited)?;
        tx.send(encode(m)).await.map_err(|_| ChildError::Exited)
    }

    /// Fail every call still waiting with `e`.
    pub fn fail_all(&self, e: ChildError) {
        let drained: Vec<_> = lock(&self.pending).drain().collect();
        for (_, tx) in drained {
            let _ = tx.send(Err(e.clone()));
        }
    }

    fn take(&self, id: u64) -> Option<oneshot::Sender<Reply>> {
        lock(&self.pending).remove(&id)
    }

    /// Send `method` and wait at most `limit` for its answer. On timeout
    /// the request is cancelled (`notifications/cancelled`).
    pub async fn request(
        &self,
        method: &str,
        params: Value,
        limit: Duration,
    ) -> Result<(Value, usize), ChildError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock(&self.pending).insert(id, tx);
        if let Err(e) = self
            .send_line(&Message::request(id, method, Some(params)))
            .await
        {
            self.take(id);
            return Err(e);
        }
        match tokio::time::timeout(limit, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(ChildError::Exited),
            Err(_) => {
                self.take(id);
                let cancel = Message::notification(
                    t::CANCELLED,
                    Some(json!({"requestId": id, "reason": "timeout"})),
                );
                let _ = tokio::time::timeout(Duration::from_secs(1), self.send_line(&cancel)).await;
                Err(ChildError::Timeout)
            }
        }
    }

    pub async fn notify(&self, method: &str) -> Result<(), ChildError> {
        self.send_line(&Message::notification(method, None)).await
    }
}

/// A started child: the process, its connection and the reader's events.
pub(crate) struct Running {
    pub process: tokio::process::Child,
    pub pid: u32,
    pub conn: Arc<Conn>,
    pub events: mpsc::UnboundedReceiver<Event>,
}

/// Why a start failed; `permanent` ones are not retried.
#[derive(Debug)]
pub(crate) struct StartError {
    pub reason: String,
    pub permanent: bool,
}

impl StartError {
    pub fn retry(reason: impl Into<String>) -> StartError {
        StartError {
            reason: reason.into(),
            permanent: false,
        }
    }
    pub fn permanent(reason: impl Into<String>) -> StartError {
        StartError {
            reason: reason.into(),
            permanent: true,
        }
    }
}

/// Spawn the helper with `spec`, then start the pipe tasks. The spec frame
/// goes first on stdin; the JSON-RPC session follows on the same pipe.
pub(crate) async fn spawn(
    helper: &Path,
    name: &str,
    spec: &SpawnSpec,
    masker: Arc<Masker>,
    line_cap: usize,
    log: Log,
) -> Result<Running, StartError> {
    let frame = encode_spec(spec).map_err(|e| StartError::permanent(e.to_string()))?;
    let mut cmd = tokio::process::Command::new(helper);
    cmd.arg("__mcp-spawn")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut process = cmd
        .spawn()
        .map_err(|e| StartError::retry(format!("cannot start the spawn helper: {}", e.kind())))?;
    let pid = process
        .id()
        .ok_or_else(|| StartError::retry("the spawn helper exited at once"))?;
    let mut stdin = process
        .stdin
        .take()
        .ok_or_else(|| StartError::retry("no stdin"))?;
    let stdout = process
        .stdout
        .take()
        .ok_or_else(|| StartError::retry("no stdout"))?;
    let stderr = process
        .stderr
        .take()
        .ok_or_else(|| StartError::retry("no stderr"))?;
    tokio::spawn(forward_stderr(
        name.to_string(),
        stderr,
        Arc::clone(&masker),
        log,
    ));
    // A helper that refuses exits before it reads the frame: the error
    // shows on its stderr and in its exit.
    let _ = tokio::time::timeout(Duration::from_secs(10), stdin.write_all(&frame)).await;
    drop(frame);
    let (tx, mut rx) = mpsc::channel::<String>(64);
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if stdin.write_all(line.as_bytes()).await.is_err() || stdin.flush().await.is_err() {
                break;
            }
        }
        // Dropping stdin here is the EOF.
    });
    let conn = Arc::new(Conn::new(tx, masker));
    let (ev_tx, events) = mpsc::unbounded_channel();
    tokio::spawn(read_stdout(
        BufReader::new(stdout),
        Arc::clone(&conn),
        ev_tx,
        line_cap,
    ));
    Ok(Running {
        process,
        pid,
        conn,
        events,
    })
}

/// One line read with a cap.
enum Line {
    Full(Vec<u8>),
    TooLong,
    Eof,
}

/// Reads one `\n`-terminated line, never buffering more than `cap` + one
/// read. A partial line at EOF is dropped. Over the cap: with
/// `discard_rest` the rest of that line is read and dropped (the next call
/// starts at the next line, so no tail of the long line is ever taken for
/// a line of its own); without it the reader stops there.
async fn read_capped<R: AsyncBufRead + Unpin>(
    r: &mut R,
    cap: usize,
    discard_rest: bool,
) -> std::io::Result<Line> {
    let mut buf = Vec::new();
    let mut over = false;
    loop {
        let avail = r.fill_buf().await?;
        if avail.is_empty() {
            return Ok(Line::Eof);
        }
        if let Some(i) = avail.iter().position(|&b| b == b'\n') {
            over |= buf.len() + i > cap + 1;
            if !over {
                buf.extend_from_slice(&avail[..i]);
            }
            r.consume(i + 1);
            return Ok(if over { Line::TooLong } else { Line::Full(buf) });
        }
        let n = avail.len();
        if !over && buf.len() + n > cap + 1 {
            over = true;
            buf = Vec::new();
        }
        if !over {
            buf.extend_from_slice(avail);
        }
        r.consume(n);
        if over && !discard_rest {
            return Ok(Line::TooLong);
        }
    }
}

async fn read_stdout(
    mut r: BufReader<ChildStdout>,
    conn: Arc<Conn>,
    events: mpsc::UnboundedSender<Event>,
    cap: usize,
) {
    loop {
        let line = match read_capped(&mut r, cap, false).await {
            Ok(Line::Full(l)) => l,
            Ok(Line::TooLong) => {
                conn.fail_all(ChildError::TooLarge);
                let _ = events.send(Event::Fatal(format!(
                    "the server sent a message over {cap} bytes"
                )));
                return;
            }
            Ok(Line::Eof) | Err(_) => {
                conn.fail_all(ChildError::Exited);
                return;
            }
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let bytes = line.len();
        let msg = match decode_line(&line, cap) {
            Ok(m) => m,
            // An unreadable line names no call of ours; it is skipped.
            Err(_) => continue,
        };
        match msg {
            Message::Response { id, result } => {
                if let Some(tx) = our_id(&id).and_then(|n| conn.take(n)) {
                    let _ = tx.send(Ok((result, bytes)));
                }
            }
            Message::Error {
                id: Some(id),
                error,
            } => {
                if let Some(tx) = our_id(&id).and_then(|n| conn.take(n)) {
                    let _ = tx.send(Err(ChildError::Protocol(format!(
                        "server error {}: {}",
                        error.code, error.message
                    ))));
                }
            }
            Message::Error { id: None, .. } => {}
            Message::Request { id, method, .. } => {
                // We declare no client capabilities: sampling, elicitation
                // and roots are refused; ping is answered.
                let answer = if method == t::PING {
                    Message::response(id, json!({}))
                } else {
                    Message::error(Some(id), RpcError::method_not_found(&method))
                };
                let _ = conn.send_line(&answer).await;
            }
            Message::Notification { method, .. } => {
                if method == t::TOOLS_LIST_CHANGED {
                    let _ = events.send(Event::ListChanged);
                }
            }
        }
    }
}

fn our_id(id: &Id) -> Option<u64> {
    match id {
        Id::Number(n) => n.as_u64(),
        Id::String(_) => None,
    }
}

/// The child's stderr, masked, one journal line per line, at most
/// [`STDERR_PER_MINUTE`] bytes a minute.
async fn forward_stderr(name: String, stderr: ChildStderr, masker: Arc<Masker>, log: Log) {
    let mut r = BufReader::new(stderr);
    let mut window = tokio::time::Instant::now();
    let mut used = 0usize;
    let mut warned = false;
    loop {
        let line = match read_capped(&mut r, STDERR_LINE, true).await {
            Ok(Line::Full(l)) => l,
            Ok(Line::TooLong) => b"(a line over 4 KiB, dropped)".to_vec(),
            Ok(Line::Eof) | Err(_) => return,
        };
        if window.elapsed() >= Duration::from_secs(60) {
            window = tokio::time::Instant::now();
            used = 0;
            warned = false;
        }
        used += line.len();
        if used > STDERR_PER_MINUTE {
            if !warned {
                log.line(&format!(
                    "saiife: mcp {name}: stderr over 64 KiB this minute; dropped until the next minute"
                ));
                warned = true;
            }
            continue;
        }
        let text = String::from_utf8_lossy(&line);
        let text: String = text.chars().filter(|c| !c.is_control()).collect();
        log.line(&format!("saiife: mcp {name}: {}", masker.mask_text(&text)));
    }
}

/// `initialize`, the version check, then `notifications/initialized`.
pub(crate) async fn initialize(conn: &Conn, limit: Duration) -> Result<(), StartError> {
    let params = json!({
        "protocolVersion": saiife_mcp::version::PREFERRED,
        "capabilities": {},
        "clientInfo": {"name": "saiife", "version": crate::ops::VERSION},
    });
    let (v, _) = conn
        .request(t::INITIALIZE, params, limit)
        .await
        .map_err(|e| StartError::retry(format!("initialize failed: {e}")))?;
    let version = v
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !saiife_mcp::version::is_supported(version) {
        let shown: String = version
            .chars()
            .filter(|c| !c.is_control())
            .take(32)
            .collect();
        return Err(StartError::permanent(format!(
            "mcp_version_unsupported: the server answered protocol version {:?}; saiife speaks {}",
            conn.masker.mask_text(&shown),
            saiife_mcp::version::SUPPORTED.join(", ")
        )));
    }
    conn.notify(t::INITIALIZED)
        .await
        .map_err(|e| StartError::retry(format!("initialized failed: {e}")))?;
    Ok(())
}

/// Every page of `tools/list`, cleaned ([`clean_tools`]).
pub(crate) async fn list_tools(conn: &Conn, limit: Duration) -> Result<Vec<Tool>, ChildError> {
    let mut raw: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_PAGES {
        let params = match &cursor {
            Some(c) => json!({"cursor": c}),
            None => json!({}),
        };
        let (v, _) = conn.request(t::TOOLS_LIST, params, limit).await?;
        let Some(tools) = v.get("tools").and_then(Value::as_array) else {
            return Err(ChildError::Protocol("tools/list has no tools array".into()));
        };
        raw.extend(tools.iter().cloned());
        if raw.len() > MAX_TOOLS {
            break;
        }
        match v.get("nextCursor").and_then(Value::as_str) {
            Some(c) if !c.is_empty() && seen.insert(c.to_string()) => cursor = Some(c.to_string()),
            _ => break,
        }
    }
    Ok(clean_tools(raw, &conn.masker))
}

fn strip_control(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

fn cut(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Every string of `v` (keys too) without control chars and masked.
fn clean_value(v: &mut Value, masker: &Masker) {
    match v {
        Value::String(s) => *s = masker.mask_text(&strip_control(s)),
        Value::Array(a) => a.iter_mut().for_each(|x| clean_value(x, masker)),
        Value::Object(o) => {
            let old = std::mem::take(o);
            for (k, mut x) in old {
                clean_value(&mut x, masker);
                o.insert(masker.mask_text(&strip_control(&k)), x);
            }
        }
        _ => {}
    }
}

/// The tools saiife keeps from a server's list:
/// - names are kept byte-for-byte; a tool whose name is empty, over 128
///   bytes or holds a control char is dropped, and so are both of two
///   tools with the same name;
/// - at most [`MAX_TOOLS`];
/// - title and description without control chars, masked, the
///   description cut at 2 KiB;
/// - the schema's strings cleaned the same way; a schema over 64 KiB, or
///   one that is not an object, becomes `{"type": "object"}`;
/// - annotations and output schemas are not kept (third-party hints are
///   untrusted).
pub(crate) fn clean_tools(raw: Vec<Value>, masker: &Masker) -> Vec<Tool> {
    let mut out: Vec<Tool> = Vec::new();
    let mut dup: BTreeSet<String> = BTreeSet::new();
    for v in raw {
        let Some(o) = v.as_object() else { continue };
        let Some(name) = o.get("name").and_then(Value::as_str) else {
            continue;
        };
        if name.is_empty() || name.len() > MAX_TOOL_NAME || name.chars().any(char::is_control) {
            continue;
        }
        if out.iter().any(|t| t.name == name) {
            dup.insert(name.to_string());
            continue;
        }
        let text = |k: &str| {
            o.get(k)
                .and_then(Value::as_str)
                .map(|s| masker.mask_text(&strip_control(s)))
        };
        let mut schema = o.get("inputSchema").cloned().unwrap_or(Value::Null);
        let size = serde_json::to_vec(&schema).map_or(usize::MAX, |b| b.len());
        if !schema.is_object() || size > MAX_SCHEMA {
            schema = json!({"type": "object"});
        } else {
            clean_value(&mut schema, masker);
        }
        out.push(Tool {
            name: name.to_string(),
            title: text("title"),
            description: text("description").map(|d| cut(d, MAX_DESCRIPTION)),
            input_schema: schema,
            output_schema: None,
            annotations: None,
        });
        if out.len() >= MAX_TOOLS {
            break;
        }
    }
    out.retain(|t| !dup.contains(&t.name));
    out
}

/// A `tools/call` result as the agent may see it: an object with a
/// `content` array, image and audio items (and any other type saiife does
/// not pass on) replaced with [`OMITTED`], and every string masked.
pub(crate) fn mask_result(v: Value, masker: &Masker) -> Result<Value, ChildError> {
    let Value::Object(mut o) = v else {
        return Err(ChildError::Protocol(
            "a tools/call result is an object".into(),
        ));
    };
    let Some(Value::Array(items)) = o.remove("content") else {
        return Err(ChildError::Protocol(
            "a tools/call result has a content array".into(),
        ));
    };
    let items: Vec<Value> = items
        .into_iter()
        .map(|item| {
            let kind = item.get("type").and_then(Value::as_str).unwrap_or_default();
            match kind {
                "text" | "resource" | "resource_link" => item,
                _ => json!({"type": "text", "text": OMITTED}),
            }
        })
        .collect();
    o.insert("content".into(), Value::Array(items));
    if let Some(e) = o.get("isError") {
        if !e.is_boolean() {
            o.insert("isError".into(), Value::Bool(true));
        }
    }
    let mut v = Value::Object(o);
    mask_strings(&mut v, masker);
    Ok(v)
}

/// Every string of `v` (keys too) through the masker. Control chars stay:
/// a result's text is the server's answer.
fn mask_strings(v: &mut Value, masker: &Masker) {
    match v {
        Value::String(s) => *s = masker.mask_text(s),
        Value::Array(a) => a.iter_mut().for_each(|x| mask_strings(x, masker)),
        Value::Object(o) => {
            let old = std::mem::take(o);
            let mut m = Map::new();
            for (k, mut x) in old {
                mask_strings(&mut x, masker);
                m.insert(masker.mask_text(&k), x);
            }
            *o = m;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> Masker {
        Masker::new(&[])
    }

    #[tokio::test]
    async fn capped_reader_reports_long_lines_and_goes_on() {
        let data = b"short\n0123456789abcdef\nnext\npartial".to_vec();
        let mut r = BufReader::with_capacity(4, &data[..]);
        assert!(
            matches!(read_capped(&mut r, 8, true).await.unwrap(), Line::Full(l) if l == b"short")
        );
        assert!(matches!(
            read_capped(&mut r, 8, true).await.unwrap(),
            Line::TooLong
        ));
        assert!(
            matches!(read_capped(&mut r, 8, true).await.unwrap(), Line::Full(l) if l == b"next")
        );
        assert!(matches!(
            read_capped(&mut r, 8, true).await.unwrap(),
            Line::Eof
        ));
    }

    #[test]
    fn tools_are_bounded_and_cleaned_names_kept_exactly() {
        let long = "d".repeat(5000);
        let raw = vec![
            json!({"name": "Tool.With Spaces", "description": format!("a\u{7}b{long}"),
                   "inputSchema": {"type": "object", "description": "x\u{1b}y"},
                   "annotations": {"readOnlyHint": true}}),
            json!({"name": "dup", "inputSchema": {}}),
            json!({"name": "dup", "inputSchema": {}}),
            json!({"name": "bad\nname", "inputSchema": {}}),
            json!({"name": "", "inputSchema": {}}),
            json!({"name": "big", "inputSchema": {"x": "y".repeat(70 * 1024)}}),
            json!({"name": "noschema"}),
            json!("not a tool"),
        ];
        let tools = clean_tools(raw, &none());
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Tool.With Spaces", "big", "noschema"]);
        let d = tools[0].description.as_deref().unwrap();
        assert!(d.starts_with("ab"), "{d:.10}");
        assert_eq!(d.len(), MAX_DESCRIPTION);
        assert_eq!(tools[0].input_schema["description"], "xy");
        assert!(tools[0].annotations.is_none());
        assert_eq!(tools[1].input_schema, json!({"type": "object"}));
        assert_eq!(tools[2].input_schema, json!({"type": "object"}));
    }

    #[test]
    fn at_most_1000_tools() {
        let raw: Vec<Value> = (0..1500)
            .map(|i| json!({"name": format!("t{i}"), "inputSchema": {"type": "object"}}))
            .collect();
        assert_eq!(clean_tools(raw, &none()).len(), MAX_TOOLS);
    }

    #[test]
    fn results_masked_and_media_omitted() {
        let secret = concat!("sk", "-test-", "0123456789");
        let m = Masker::new(&[secret]);
        let r = json!({
            "content": [
                {"type": "text", "text": format!("tok {secret}")},
                {"type": "image", "data": "AAAA", "mimeType": "image/png"},
                {"type": "audio", "data": "AAAA", "mimeType": "audio/wav"},
                {"type": "resource", "resource": {"uri": "x://y", "text": secret}},
                {"type": "resource_link", "uri": format!("x://{secret}"), "name": "n"},
            ],
            "structuredContent": {secret: secret},
            "isError": false,
        });
        let out = mask_result(r, &m).unwrap();
        let s = out.to_string();
        assert!(!s.contains(secret), "{s}");
        assert_eq!(out["content"][1], json!({"type": "text", "text": OMITTED}));
        assert_eq!(out["content"][2], json!({"type": "text", "text": OMITTED}));
        assert_eq!(out["content"][0]["text"], "tok [MASKED]");
        assert!(mask_result(json!({"isError": true}), &m).is_err());
        assert!(mask_result(json!([1]), &m).is_err());
    }
}
