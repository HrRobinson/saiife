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
/// A tool title is cut at this many bytes.
pub const MAX_TITLE: usize = 256;
/// The cleaned tools of one list are at most this many bytes in all.
pub const MAX_LIST_BYTES: usize = 16 * 1024 * 1024;
/// Names of tools past [`MAX_TOOLS`] remembered for the duplicate check.
const MAX_OVERFLOW_NAMES: usize = 10_000;
/// Any text built from what a child said (an error message, a reason) is
/// cut at this many bytes, after control chars are stripped and it is
/// masked ([`sanitize`]).
pub const MAX_REASON: usize = 512;

type Reply = Result<(Value, usize), ChildError>;

/// Child-provided text made safe for a record, `status`, the journal or an
/// answer: control chars stripped, masked with the child's secret forms
/// and the v1 patterns, cut at [`MAX_REASON`] bytes.
pub(crate) fn sanitize(masker: &Masker, s: &str) -> String {
    cut(masker.mask_text(&strip_control(s)), MAX_REASON)
}

/// The JSON-RPC side of a running child, shared by callers.
pub(crate) struct Conn {
    /// Lines to the child's stdin. `None` once stdin was closed (EOF).
    out: Mutex<Option<mpsc::Sender<String>>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    next_id: AtomicU64,
    pub pool: Semaphore,
    pub masker: Arc<Masker>,
    /// `notifications/tools/list_changed`: one stored permit however many
    /// arrive, so they coalesce into at most one more relist.
    pub list_changed: tokio::sync::Notify,
    pub log: Log,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Conn {
    fn new(out: mpsc::Sender<String>, masker: Arc<Masker>, log: Log) -> Conn {
        Conn {
            out: Mutex::new(Some(out)),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            pool: Semaphore::new(POOL_SIZE),
            masker,
            list_changed: tokio::sync::Notify::new(),
            log,
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

    /// Send `method` and wait for its answer, both within `limit`: a child
    /// that stops reading its stdin cannot hold the caller (or its pool
    /// slot) past it. On timeout the request is cancelled
    /// (`notifications/cancelled`, best effort: never waited for).
    pub async fn request(
        &self,
        method: &str,
        params: Value,
        limit: Duration,
    ) -> Result<(Value, usize), ChildError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock(&self.pending).insert(id, tx);
        let line = Message::request(id, method, Some(params));
        let exchange = async {
            self.send_line(&line).await?;
            match rx.await {
                Ok(r) => r,
                Err(_) => Err(ChildError::Exited),
            }
        };
        match tokio::time::timeout(limit, exchange).await {
            Ok(r) => {
                self.take(id);
                r
            }
            Err(_) => {
                self.take(id);
                let cancel = Message::notification(
                    t::CANCELLED,
                    Some(json!({"requestId": id, "reason": "timeout"})),
                );
                let tx = lock(&self.out).clone();
                if let Some(tx) = tx {
                    let _ = tx.try_send(encode(&cancel));
                }
                Err(ChildError::Timeout)
            }
        }
    }

    pub async fn notify(&self, method: &str) -> Result<(), ChildError> {
        self.send_line(&Message::notification(method, None)).await
    }
}

/// The pid set entry and the process group of one child, for as long as
/// it exists. While armed (the leader not yet waited for, so its pid and
/// group id cannot have been reused), dropping it kills the child's group
/// first, then removes the pid from the gateway's set. Once the leader was
/// waited for (any outcome) it is disarmed and never signals again.
pub(crate) struct Reaper {
    pid: u32,
    pids: Arc<Mutex<BTreeSet<u32>>>,
    armed: bool,
}

impl Reaper {
    fn new(pid: u32, pids: Arc<Mutex<BTreeSet<u32>>>) -> Reaper {
        lock(&pids).insert(pid);
        Reaper {
            pid,
            pids,
            armed: true,
        }
    }

    /// Kill the group, only while armed.
    fn kill_group(&self) {
        if self.armed {
            kill_group(self.pid);
        }
    }

    /// The leader was waited for: no signal from here on.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Reaper {
    fn drop(&mut self) {
        self.kill_group();
        lock(&self.pids).remove(&self.pid);
    }
}

/// SIGKILL the process group `pid` leads. Called only while the leader is
/// unreaped (running or a zombie), so `pid` is still our child and the
/// group id cannot have been reused; and only when the child leads its
/// own group (`getpgid(pid) == pid`: the helper calls `setsid`). A syscall
/// on a group we created, never a shell `kill`.
fn kill_group(pid: u32) {
    use rustix::process::{getpgid, kill_process_group, Pid, Signal};
    let Some(raw) = Pid::from_raw(pid as i32) else {
        return;
    };
    if getpgid(Some(raw)).is_ok_and(|g| g == raw) {
        let _ = kill_process_group(raw, Signal::KILL);
    }
}

/// Watches for the leader's exit without reaping it: a pidfd (readable once
/// the process has exited, while it is still a zombie), or, where pidfds
/// are unavailable, `waitid(P_PID, WEXITED | WNOWAIT)` on a blocking
/// thread.
pub(crate) enum ExitWatch {
    Pidfd(tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>, u32),
    Waitid(u32),
}

impl ExitWatch {
    fn new(pid: u32) -> ExitWatch {
        use rustix::process::{pidfd_open, Pid, PidfdFlags};
        let fd = Pid::from_raw(pid as i32)
            .and_then(|p| pidfd_open(p, PidfdFlags::empty()).ok())
            .and_then(|fd| {
                tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::READABLE).ok()
            });
        match fd {
            Some(fd) => ExitWatch::Pidfd(fd, pid),
            None => ExitWatch::Waitid(pid),
        }
    }

    /// Returns once the leader has exited; it stays unreaped.
    pub async fn exited(&self) {
        let pid = match self {
            ExitWatch::Pidfd(fd, pid) => {
                // Readiness is never cleared: once exited, always exited.
                if fd.readable().await.is_ok() {
                    return;
                }
                // The reactor refused the fd: wait the blocking way.
                *pid
            }
            ExitWatch::Waitid(pid) => *pid,
        };
        wait_nowait(pid).await
    }
}

/// `waitid(P_PID, pid, WEXITED | WNOWAIT)` on a blocking thread. Any error
/// other than EINTR (ECHILD: already reaped) counts as exited.
async fn wait_nowait(pid: u32) {
    use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};
    let Some(raw) = Pid::from_raw(pid as i32) else {
        return;
    };
    let _ = tokio::task::spawn_blocking(move || loop {
        match waitid(
            WaitId::Pid(raw),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            _ => return,
        }
    })
    .await;
}

/// A started child: the process, its connection and the reader's fatal
/// reason. `reaper` is the first field, so it drops (and kills the group)
/// while the leader is still unreaped, before `process` drops.
pub(crate) struct Running {
    reaper: Reaper,
    pub process: tokio::process::Child,
    pub pid: u32,
    pub conn: Arc<Conn>,
    /// The reader's one fatal protocol break, already sanitized.
    pub fatal: mpsc::UnboundedReceiver<String>,
    pub exit: ExitWatch,
}

impl Running {
    /// After [`ExitWatch::exited`]: kill what is left of the group while
    /// the leader is a zombie, then reap it.
    pub async fn reap_exited(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.reaper.kill_group();
        let st = self.process.wait().await;
        self.reaper.disarm();
        st
    }

    /// Kill the child's group and the leader (before any reap), through
    /// our handle; then reap it, bounded.
    pub async fn kill(&mut self) {
        self.reaper.kill_group();
        let _ = self.process.start_kill();
        if tokio::time::timeout(Duration::from_secs(1), self.process.wait())
            .await
            .is_ok()
        {
            self.reaper.disarm();
        }
    }
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
    pids: Arc<Mutex<BTreeSet<u32>>>,
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
    // From here on every way out kills the group and clears the pid.
    let reaper = Reaper::new(pid, pids);
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
        log.clone(),
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
    let conn = Arc::new(Conn::new(tx, masker, log));
    let (fatal_tx, fatal) = mpsc::unbounded_channel();
    tokio::spawn(read_stdout(
        BufReader::new(stdout),
        Arc::clone(&conn),
        fatal_tx,
        line_cap,
    ));
    Ok(Running {
        reaper,
        process,
        pid,
        conn,
        fatal,
        exit: ExitWatch::new(pid),
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
    fatal: mpsc::UnboundedSender<String>,
    cap: usize,
) {
    loop {
        let line = match read_capped(&mut r, cap, false).await {
            Ok(Line::Full(l)) => l,
            Ok(Line::TooLong) => {
                conn.fail_all(ChildError::TooLarge);
                // The only message on this channel, sent once.
                let _ = fatal.send(format!("the server sent a message over {cap} bytes"));
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
                    let text = format!("server error {}: {}", error.code, error.message);
                    let _ = tx.send(Err(ChildError::Protocol(sanitize(&conn.masker, &text))));
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
                // Bounded: a ping flood with an unread stdin must not
                // stall the reader.
                let _ = tokio::time::timeout(Duration::from_secs(1), conn.send_line(&answer)).await;
            }
            Message::Notification { method, .. } => {
                if method == t::TOOLS_LIST_CHANGED {
                    conn.list_changed.notify_one();
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
        // Masked whole, then cut (never a cut-then-masked fragment).
        let shown = cut(sanitize(&conn.masker, version), 64);
        return Err(StartError::permanent(format!(
            "mcp_version_unsupported: the server answered protocol version {:?}; saiife speaks {}",
            shown,
            saiife_mcp::version::SUPPORTED.join(", ")
        )));
    }
    conn.notify(t::INITIALIZED)
        .await
        .map_err(|e| StartError::retry(format!("initialized failed: {e}")))?;
    Ok(())
}

/// Every page of `tools/list`, each page cleaned as it arrives
/// ([`Collector`]): at most [`MAX_TOOLS`] tools and [`MAX_LIST_BYTES`]
/// kept, at most 64 pages.
pub(crate) async fn list_tools(conn: &Conn, limit: Duration) -> Result<Vec<Tool>, ChildError> {
    let mut c = Collector::default();
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
        for t in tools {
            c.add(t, &conn.masker);
        }
        let cursor_next = v
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        drop(v);
        if c.full() {
            break;
        }
        match cursor_next {
            Some(n) if !n.is_empty() && seen.insert(n.clone()) => cursor = Some(n),
            _ => break,
        }
    }
    let (tools, notes) = c.finish();
    for n in notes {
        conn.log.line(&n);
    }
    Ok(tools)
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

/// The tools saiife keeps from a server's list, built page by page:
/// - names are kept byte-for-byte; a tool whose name is empty, over 128
///   bytes, holds a control char, or would change under masking (it holds
///   a secret form or matches a v1 pattern) is dropped, with a masked
///   note; so are all tools sharing a name, including a name seen again
///   past the cap;
/// - at most [`MAX_TOOLS`] tools and [`MAX_LIST_BYTES`] kept;
/// - title and description without control chars, masked, cut at 256 B
///   and 2 KiB;
/// - the schema's strings cleaned the same way; a schema over 64 KiB, or
///   one that is not an object, becomes `{"type": "object"}`;
/// - annotations and output schemas are not kept (third-party hints are
///   untrusted).
#[derive(Default)]
pub(crate) struct Collector {
    out: Vec<Tool>,
    bytes: usize,
    /// Names seen after the list was full.
    overflow: BTreeSet<String>,
    dup: BTreeSet<String>,
    masked_names: usize,
    full: bool,
}

impl Collector {
    pub fn full(&self) -> bool {
        self.full && self.overflow.len() >= MAX_OVERFLOW_NAMES
    }

    pub fn add(&mut self, v: &Value, masker: &Masker) {
        let Some(o) = v.as_object() else { return };
        let Some(name) = o.get("name").and_then(Value::as_str) else {
            return;
        };
        if name.is_empty() || name.len() > MAX_TOOL_NAME || name.chars().any(char::is_control) {
            return;
        }
        if masker.mask_text(name) != name {
            self.masked_names += 1;
            return;
        }
        if self.out.iter().any(|t| t.name == name) {
            self.dup.insert(name.to_string());
            return;
        }
        if self.full {
            if self.overflow.len() < MAX_OVERFLOW_NAMES {
                self.overflow.insert(name.to_string());
            }
            return;
        }
        let text = |k: &str, max: usize| {
            o.get(k)
                .and_then(Value::as_str)
                .map(|s| cut(masker.mask_text(&strip_control(s)), max))
        };
        let mut schema = o.get("inputSchema").cloned().unwrap_or(Value::Null);
        let size = serde_json::to_vec(&schema).map_or(usize::MAX, |b| b.len());
        let size = if !schema.is_object() || size > MAX_SCHEMA {
            schema = json!({"type": "object"});
            16
        } else {
            clean_value(&mut schema, masker);
            // Counted after cleaning: masking can make a string longer.
            serde_json::to_vec(&schema).map_or(usize::MAX, |b| b.len())
        };
        let tool = Tool {
            name: name.to_string(),
            title: text("title", MAX_TITLE),
            description: text("description", MAX_DESCRIPTION),
            input_schema: schema,
            output_schema: None,
            annotations: None,
        };
        let cost = name.len()
            + size
            + tool.title.as_ref().map_or(0, String::len)
            + tool.description.as_ref().map_or(0, String::len);
        if self.bytes + cost > MAX_LIST_BYTES {
            self.full = true;
            self.overflow.insert(name.to_string());
            return;
        }
        self.bytes += cost;
        self.out.push(tool);
        if self.out.len() >= MAX_TOOLS {
            self.full = true;
        }
    }

    /// The kept tools and the journal notes about what was dropped.
    pub fn finish(mut self) -> (Vec<Tool>, Vec<String>) {
        let mut notes = Vec::new();
        if self.masked_names > 0 {
            notes.push(format!(
                "saiife: mcp: {} tool(s) dropped: the name holds a secret or a secret-like value ([MASKED])",
                self.masked_names
            ));
        }
        let dup = &self.dup;
        let overflow = &self.overflow;
        self.out
            .retain(|t| !dup.contains(&t.name) && !overflow.contains(&t.name));
        if self.full {
            notes.push(format!(
                "saiife: mcp: the tool list was cut at {} tool(s)",
                self.out.len()
            ));
        }
        (self.out, notes)
    }
}

/// [`Collector`] over one list (unit tests).
#[cfg(test)]
pub(crate) fn clean_tools(raw: Vec<Value>, masker: &Masker) -> Vec<Tool> {
    let mut c = Collector::default();
    for v in &raw {
        c.add(v, masker);
    }
    c.finish().0
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

    /// The exit watch sees an exit without reaping: the leader is still a
    /// zombie (so its group can be killed safely) until `wait`. Both ways.
    #[tokio::test]
    async fn exit_watch_does_not_reap() {
        for fallback in [false, true] {
            let mut c = tokio::process::Command::new("true").spawn().unwrap();
            let pid = c.id().unwrap();
            let w = if fallback {
                ExitWatch::Waitid(pid)
            } else {
                ExitWatch::new(pid)
            };
            if !fallback {
                assert!(matches!(w, ExitWatch::Pidfd(..)), "no pidfd here");
            }
            tokio::time::timeout(Duration::from_secs(10), w.exited())
                .await
                .expect("exit seen");
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            let state = stat.rsplit_once(") ").unwrap().1.chars().next().unwrap();
            assert_eq!(state, 'Z', "fallback {fallback}: reaped too early");
            assert!(c.wait().await.unwrap().success());
        }
    }

    #[test]
    fn sanitize_strips_masks_and_cuts() {
        let secret = concat!("sk", "-test-", "0123456789");
        let m = Masker::new(&[secret]);
        let s = sanitize(&m, &format!("bad\u{1b}[31m {secret} {}", "x".repeat(2000)));
        assert!(s.starts_with("bad[31m [MASKED] x"), "{s:.40}");
        assert_eq!(s.len(), MAX_REASON);
    }

    #[test]
    fn masked_names_dropped_and_duplicates_past_the_cap_seen() {
        let secret = concat!("sk", "-test-", "0123456789");
        let m = Masker::new(&[secret]);
        let mut raw = vec![json!({"name": format!("t_{secret}"), "inputSchema": {}})];
        raw.extend((0..MAX_TOOLS).map(|i| json!({"name": format!("t{i}"), "inputSchema": {}})));
        // Past the cap: a second `t5`.
        raw.push(json!({"name": "t5", "inputSchema": {}}));
        let mut c = Collector::default();
        for v in &raw {
            c.add(v, &m);
        }
        let (tools, notes) = c.finish();
        assert_eq!(tools.len(), MAX_TOOLS - 1);
        assert!(!tools
            .iter()
            .any(|t| t.name == "t5" || t.name.contains(secret)));
        assert!(
            notes.iter().any(|n| n.contains("1 tool(s) dropped")),
            "{notes:?}"
        );
        assert!(!notes.concat().contains(secret));
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
