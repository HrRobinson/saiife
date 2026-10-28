//! `saiife mcp`: an MCP server on stdio that offers the connector
//! operations you may call as tools (plan 17, Task 4). Linux only.
//!
//! The protocol is UTF-8 JSON-RPC, one message per line; logs go to
//! stderr (decision 2). `saiife mcp` decides nothing, caches no verdict and
//! holds no credential: every `tools/call` is one `api.call` to the daemon
//! (the same `call_one` as `saiife api`, with `via = "mcp"`), which runs
//! the whole pipeline and writes its record before it answers (decision
//! 4). `via` is a claim the client makes, attribution only, never proof of
//! where a call came from.
//!
//! - `tools/list` lists the operations whose action is `allow` or `ask`
//!   (`api.list {schema: true}`), named `<service>_<op>` (decision 5), plus
//!   the built-in `saiife_result`. A name that two operations map to is
//!   dropped for both, with a warning: a name is never routed by guesswork.
//! - A result is the daemon's masked body; a refusal, a limit, an upstream
//!   failure, an upstream status >= 400 and `saiife unavailable` are
//!   `isError` results, never JSON-RPC errors (decision 7). JSON-RPC errors
//!   are for what never reached the daemon: malformed requests, unknown
//!   methods, unknown tools and bad argument shapes.
//! - `ask` answers `waiting for approval #<id>` at once (decision 8);
//!   `saiife_result {request}` fetches the result later, and `--wait`
//!   polls for it, with `notifications/progress` when the client gave a
//!   progress token. MCP elicitation and sampling are never used: an answer
//!   inside the agent's own UI would be self-approval.
//! - Every 30 s the daemon's `tools_hash` is compared with the one last
//!   listed; `notifications/tools/list_changed` follows a move.
//!
//! Threads: the reader (main), at most 4 call workers (each with its own
//! daemon connection; the peer pid stays this process, so the daemon's
//! session attribution walks up to the agent), the `tools_hash` poller and
//! a writer behind a mutex on stdout.

use std::path::PathBuf;
use std::process::ExitCode;

#[derive(clap::Args)]
pub struct McpArgs {
    /// Wait this long (at most 1h) for an approval before a tool call that
    /// needs one answers; without it, the call answers at once with the
    /// request id.
    #[arg(long, value_name = "DURATION")]
    pub wait: Option<String>,
    /// The system config (default /etc/saiife/config.toml).
    #[arg(long = "system-config", hide = true)]
    pub system_config: Option<PathBuf>,
}

#[cfg(not(target_os = "linux"))]
pub fn run(a: McpArgs) -> ExitCode {
    let McpArgs {
        wait: _,
        system_config: _,
    } = a;
    eprintln!("saiife: locked mode needs Linux in this version (macOS: v2.1)");
    ExitCode::from(5)
}

#[cfg(target_os = "linux")]
pub fn run(a: McpArgs) -> ExitCode {
    linux::run(a)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::McpArgs;
    use crate::api_cmd::linux::{self as api, Daemon, Stop};
    use crate::broker::{self, Target};
    use saiife_broker::tool_schema::{self, BodyArg};
    use saiife_mcp::codec::{self, LineReader};
    use saiife_mcp::jsonrpc::{Id, Message, RpcError};
    use saiife_mcp::types as t;
    use serde_json::{json, Map, Value};
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::io::Write as _;
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    /// An inbound line is at most the control socket's request frame.
    const MAX_LINE: usize = 1 << 20;
    /// Call workers, each with its own daemon connection.
    const WORKERS: usize = 4;
    /// Requests read but not yet taken by a worker; past this the reader
    /// waits, so a flooding client holds bounded memory.
    const QUEUE: usize = 64;
    /// How often the daemon's `tools_hash` is compared (decision 6).
    const HASH_EVERY: Duration = Duration::from_secs(30);
    /// The deadline of the small control calls (`api.list`, `api.result`).
    const CONTROL: Duration = Duration::from_secs(10);
    /// The in-flight drain at end of input when the config cannot be
    /// read: the default upstream timeout (30 s) twice, plus 15 s.
    const DEFAULT_DRAIN: Duration = Duration::from_secs(75);

    /// What every thread shares.
    struct Shared {
        out: Mutex<std::io::Stdout>,
        /// The daemon to talk to, or why there is none.
        target: Result<Target, String>,
        wait: Option<Duration>,
        /// The exact name → operation map of the last listing.
        tools: Mutex<HashMap<String, ToolTarget>>,
        /// The `tools_hash` last listed or announced.
        hash: Mutex<Option<String>>,
        /// The cancel flag of each request a worker has not answered yet.
        cancels: Mutex<HashMap<Id, Arc<AtomicBool>>>,
        /// End of input: a `--wait` poll stops at once.
        closing: AtomicBool,
    }

    impl Shared {
        /// One message, one line, flushed. A closed stdout is ignored: the
        /// client is gone and the record is already written.
        fn send(&self, m: &Message) {
            let line = codec::encode(m);
            let mut out = self.out.lock().unwrap_or_else(|p| p.into_inner());
            let _ = out.write_all(line.as_bytes());
            let _ = out.flush();
        }
    }

    /// The operation behind a listed tool name.
    #[derive(Clone)]
    struct ToolTarget {
        service: String,
        operation: String,
        /// How the free `body` argument is sent (Task 3's `body_arg`, never
        /// guessed from the property name: some operations have a string
        /// param called `body`).
        body: Option<BodyArg>,
        /// The argument names the schema lists.
        args: BTreeSet<String>,
    }

    enum Work {
        List,
        Call(t::CallToolParams),
    }

    struct Job {
        id: Id,
        work: Work,
        cancel: Arc<AtomicBool>,
    }

    fn log(m: &str) {
        eprintln!("saiife mcp: {}", crate::text::sanitize(m));
    }

    pub fn run(a: McpArgs) -> ExitCode {
        let wait = match api::wait_limit(a.wait.as_deref()) {
            Ok(w) => w,
            Err(Stop(code, m)) => {
                eprintln!("saiife: {m}");
                return ExitCode::from(code);
            }
        };
        let target = broker::resolve_here(a.system_config.as_deref());
        if let Err(e) = &target {
            // Not fatal: tools/list answers -32603 and calls `isError`.
            log(&format!("saiife unavailable: {e}"));
        }
        let drain = target
            .as_ref()
            .ok()
            .and_then(|t| saiife_policy::load_system(t.config()).ok())
            .map(|l| l.config.gateway.upstream_timeout * 2 + Duration::from_secs(15))
            .unwrap_or(DEFAULT_DRAIN);
        let sh = Arc::new(Shared {
            out: Mutex::new(std::io::stdout()),
            target,
            wait,
            tools: Mutex::new(HashMap::new()),
            hash: Mutex::new(None),
            cancels: Mutex::new(HashMap::new()),
            closing: AtomicBool::new(false),
        });
        let (tx, rx) = mpsc::sync_channel::<Job>(QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        let workers: Vec<JoinHandle<()>> = (0..WORKERS)
            .map(|_| {
                let (sh, rx) = (Arc::clone(&sh), Arc::clone(&rx));
                std::thread::spawn(move || worker(&sh, &rx))
            })
            .collect();

        let mut initialized = false;
        let mut poller = false;
        let stdin = std::io::stdin();
        let mut reader = LineReader::new(stdin.lock(), MAX_LINE);
        loop {
            let m = match reader.next_message() {
                Ok(None) => break,
                Err(e) => {
                    log(&format!("cannot read stdin: {e}"));
                    break;
                }
                Ok(Some(Err(e))) => {
                    sh.send(&e.into_message());
                    continue;
                }
                Ok(Some(Ok(m))) => m,
            };
            match m {
                Message::Request { id, method, params } => match method.as_str() {
                    t::PING => sh.send(&Message::response(id, json!({}))),
                    t::INITIALIZE => match initialize(params) {
                        Ok(v) => {
                            initialized = true;
                            sh.send(&Message::response(id, v));
                            if !poller {
                                poller = true;
                                let sh = Arc::clone(&sh);
                                std::thread::spawn(move || hash_poller(&sh));
                            }
                        }
                        Err(e) => sh.send(&Message::error(Some(id), e)),
                    },
                    _ if !initialized => sh.send(&Message::error(
                        Some(id),
                        RpcError::invalid_request("not initialized: send initialize first"),
                    )),
                    t::TOOLS_LIST => enqueue(&sh, &tx, id, Work::List),
                    t::TOOLS_CALL => match call_params(params) {
                        Ok(p) => enqueue(&sh, &tx, id, Work::Call(p)),
                        Err(e) => sh.send(&Message::error(Some(id), e)),
                    },
                    other => sh.send(&Message::error(Some(id), RpcError::method_not_found(other))),
                },
                Message::Notification { method, params } => {
                    if method == t::CANCELLED {
                        cancel(&sh, params);
                    }
                    // `notifications/initialized` and any other notice need
                    // nothing.
                }
                // saiife sends no requests, so no answer is expected.
                Message::Response { .. } | Message::Error { .. } => {}
            }
        }

        // End of input: the calls already taken finish (a `--wait` poll
        // stops at once), bounded as `saiife api` bounds one call.
        sh.closing.store(true, Ordering::SeqCst);
        drop(tx);
        let deadline = Instant::now() + drain;
        while !workers.iter().all(|w| w.is_finished()) {
            if Instant::now() >= deadline {
                log("calls still in flight at the end of input were abandoned");
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        ExitCode::SUCCESS
    }

    fn enqueue(sh: &Shared, tx: &mpsc::SyncSender<Job>, id: Id, work: Work) {
        let cancel = Arc::new(AtomicBool::new(false));
        sh.cancels
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id.clone(), Arc::clone(&cancel));
        if tx.send(Job { id, work, cancel }).is_err() {
            log("no call worker is left");
        }
    }

    /// `notifications/cancelled`: the request is not answered. A daemon
    /// call already sent is not undone (its record exists); a `--wait`
    /// poll stops.
    fn cancel(sh: &Shared, params: Option<Value>) {
        let Some(p) = params.and_then(|p| serde_json::from_value::<t::CancelledParams>(p).ok())
        else {
            return;
        };
        if let Some(id) = p.request_id {
            if let Some(f) = sh
                .cancels
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&id)
            {
                f.store(true, Ordering::SeqCst);
            }
        }
    }

    /// The `initialize` answer (decision 1).
    fn initialize(params: Option<Value>) -> Result<Value, RpcError> {
        let p: t::InitializeParams = params
            .and_then(|p| serde_json::from_value(p).ok())
            .ok_or_else(|| RpcError::invalid_params("initialize needs protocolVersion"))?;
        let r = t::InitializeResult {
            protocol_version: saiife_mcp::version::negotiate(&p.protocol_version).into(),
            capabilities: t::ServerCapabilities {
                tools: Some(t::ToolsCapability { list_changed: true }),
            },
            server_info: t::Implementation {
                name: "saiife".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                title: None,
            },
            instructions: None,
        };
        serde_json::to_value(r).map_err(|e| RpcError::internal_error(e.to_string()))
    }

    fn call_params(params: Option<Value>) -> Result<t::CallToolParams, RpcError> {
        params
            .and_then(|p| serde_json::from_value(p).ok())
            .ok_or_else(|| RpcError::invalid_params("tools/call needs a name and object arguments"))
    }

    fn worker(sh: &Shared, rx: &Mutex<Receiver<Job>>) {
        let mut conn: Option<Daemon> = None;
        loop {
            let job = {
                let r = rx.lock().unwrap_or_else(|p| p.into_inner());
                match r.recv() {
                    Ok(j) => j,
                    Err(_) => return,
                }
            };
            if !job.cancel.load(Ordering::SeqCst) {
                let answer = match job.work {
                    Work::List => list_tools(sh, &mut conn).map(|(v, _)| v),
                    Work::Call(p) => call(sh, &mut conn, p, &job.cancel),
                };
                // A cancelled request is not answered (MCP).
                if !job.cancel.load(Ordering::SeqCst) {
                    sh.send(&match answer {
                        Ok(v) => Message::response(job.id.clone(), v),
                        Err(e) => Message::error(Some(job.id.clone()), e),
                    });
                }
            }
            sh.cancels
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&job.id);
        }
    }

    /// This worker's daemon connection, made when there is none.
    fn daemon<'a>(sh: &Shared, conn: &'a mut Option<Daemon>) -> Result<&'a mut Daemon, String> {
        if conn.is_none() {
            let t = sh.target.as_ref().map_err(Clone::clone)?;
            *conn = Some(api::connect(t).map_err(|Stop(_, m)| m)?);
        }
        Ok(conn.as_mut().expect("just connected"))
    }

    /// `api.list {schema: true}` with the project's overlays (and env, for
    /// the personal broker), as `saiife api --list` sends them.
    fn api_list(d: &mut Daemon) -> Result<Map<String, Value>, Stop> {
        let (_, overlays, env) = api::project(d);
        let mut args = Map::new();
        args.insert("overlays".into(), json!(overlays));
        args.insert("schema".into(), true.into());
        if let Some(e) = env {
            args.insert("env".into(), e.into());
        }
        let ans = d
            .client
            .call_answer("api.list", args, Instant::now() + CONTROL)
            .map_err(|e| api::unavailable(broker::unreachable(&d.target, &e)))?;
        if ans.get("ok") != Some(&Value::Bool(true)) {
            return Err(api::refusal(&ans));
        }
        Ok(ans)
    }

    /// `tools/list`: the answer, and the name map it was built from (also
    /// kept in `sh`, with the `tools_hash`). An unreachable daemon is
    /// `-32603 saiife unavailable: <reason>`.
    fn list_tools(
        sh: &Shared,
        conn: &mut Option<Daemon>,
    ) -> Result<(Value, HashMap<String, ToolTarget>), RpcError> {
        let unavailable = |m: &str| RpcError::internal_error(format!("saiife unavailable: {m}"));
        let ans = match daemon(sh, conn) {
            Ok(d) => api_list(d),
            Err(m) => return Err(unavailable(&m)),
        };
        let ans = match ans {
            Ok(a) => a,
            Err(Stop(_, m)) => {
                *conn = None;
                return Err(unavailable(&m));
            }
        };
        api::env_warning(&ans);
        let (tools, map) = build(&ans);
        *sh.tools.lock().unwrap_or_else(|p| p.into_inner()) = map.clone();
        if let Some(h) = ans.get("tools_hash").and_then(Value::as_str) {
            *sh.hash.lock().unwrap_or_else(|p| p.into_inner()) = Some(h.to_string());
        }
        let r = t::ListToolsResult {
            tools,
            next_cursor: None,
        };
        let v = serde_json::to_value(r).map_err(|e| RpcError::internal_error(e.to_string()))?;
        Ok((v, map))
    }

    /// The tools of an `api.list` answer (decisions 5 and 6): the `allow`
    /// and `ask` operations, a name two operations share dropped for both,
    /// and `saiife_result` last.
    fn build(ans: &Map<String, Value>) -> (Vec<t::Tool>, HashMap<String, ToolTarget>) {
        let mut seen: BTreeMap<String, Vec<(ToolTarget, t::Tool)>> = BTreeMap::new();
        let services = ans.get("services").and_then(Value::as_array);
        for s in services.into_iter().flatten() {
            let service = s["name"].as_str().unwrap_or_default();
            for op in s["operations"].as_array().into_iter().flatten() {
                let s = |k: &str| op[k].as_str().unwrap_or_default();
                let policy = match s("action") {
                    "allow" => "Policy: allowed.",
                    "ask" => "Policy: needs approval; the result says how to get it.",
                    _ => continue,
                };
                let id = s("id");
                let Some(name) = tool_schema::tool_name(service, id) else {
                    log(&format!(
                        "{service} {id} is not listed: its tool name would be over {} chars, hold \"__\", a char outside [A-Za-z0-9_.-] or a reserved name",
                        tool_schema::MAX_TOOL_NAME
                    ));
                    continue;
                };
                let body = match op.get("body_arg").and_then(Value::as_str) {
                    None => None,
                    Some("json") => Some(BodyArg::Json),
                    Some("text") => Some(BodyArg::Text),
                    Some(other) => {
                        log(&format!(
                            "{service} {id} is not listed: unknown body argument {other:?}"
                        ));
                        continue;
                    }
                };
                let schema = op["input_schema"].clone();
                let Some(props) = schema.get("properties").and_then(Value::as_object) else {
                    log(&format!("{service} {id} is not listed: no input schema"));
                    continue;
                };
                let args = props.keys().cloned().collect();
                let kind = s("kind");
                let title = s("title");
                let annotations = t::ToolAnnotations {
                    read_only_hint: (kind == "read").then_some(true),
                    destructive_hint: matches!(kind, "delete" | "bulk").then_some(true),
                    ..t::ToolAnnotations::default()
                };
                let tool = t::Tool {
                    name: name.clone(),
                    title: (!title.is_empty()).then(|| title.to_string()),
                    description: Some(format!(
                        "{title} ({kind}, capability {}). {policy}",
                        s("capability")
                    )),
                    input_schema: schema,
                    output_schema: None,
                    annotations: Some(annotations),
                };
                let target = ToolTarget {
                    service: service.to_string(),
                    operation: id.to_string(),
                    body,
                    args,
                };
                seen.entry(name).or_default().push((target, tool));
            }
        }
        let mut tools = Vec::new();
        let mut map = HashMap::new();
        for (name, mut v) in seen {
            if v.len() > 1 {
                let ops: Vec<String> = v
                    .iter()
                    .map(|(t, _)| format!("{} {}", t.service, t.operation))
                    .collect();
                log(&format!(
                    "tool name {name} is shared by {}; none of them is listed",
                    ops.join(", ")
                ));
                continue;
            }
            let (target, tool) = v.pop().expect("one");
            map.insert(name, target);
            tools.push(tool);
        }
        tools.push(t::Tool {
            name: tool_schema::RESULT_TOOL.into(),
            title: Some("saiife: the result of a request that needed approval".into()),
            description: Some(
                "The result of a tool call that answered \"waiting for approval #<id>\": \
                 call it with {\"request\": <id>} once an approver has decided."
                    .into(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {"request": {"type": "integer", "minimum": 1}},
                "required": ["request"],
                "additionalProperties": false,
            }),
            output_schema: None,
            annotations: Some(t::ToolAnnotations {
                read_only_hint: Some(true),
                ..t::ToolAnnotations::default()
            }),
        });
        (tools, map)
    }

    /// The operation behind `name`: from the last listing, else from a
    /// fresh one (a client may call without listing first). `Ok(None)`:
    /// no listed tool has that name. `Err`: the daemon cannot be asked.
    fn lookup(
        sh: &Shared,
        conn: &mut Option<Daemon>,
        name: &str,
    ) -> Result<Option<ToolTarget>, String> {
        if let Some(t) = sh.tools.lock().unwrap_or_else(|p| p.into_inner()).get(name) {
            return Ok(Some(t.clone()));
        }
        match list_tools(sh, conn) {
            Ok((_, map)) => Ok(map.get(name).cloned()),
            Err(e) => Err(e
                .message
                .strip_prefix("saiife unavailable: ")
                .unwrap_or(&e.message)
                .to_string()),
        }
    }

    /// The `api.call` params and the body bytes of a tool call.
    type CallArgs = (Map<String, Value>, Option<Vec<u8>>);

    /// The `api.call` params and body for a tool's arguments: scalars
    /// become strings, the free `body` is sent as `body_b64`; anything else
    /// is `-32602`, answered without calling the daemon.
    fn map_args(t: &ToolTarget, args: &Map<String, Value>) -> Result<CallArgs, RpcError> {
        let bad = |m: String| RpcError::invalid_params(crate::text::sanitize(&m));
        let mut params = Map::new();
        let mut body = None;
        for (k, v) in args {
            if !t.args.contains(k) {
                return Err(bad(format!("unknown argument {k:?}")));
            }
            if k == "body" {
                if let Some(b) = t.body {
                    let bytes = b.encode(v).ok_or_else(|| {
                        bad(match b {
                            BodyArg::Json => "body must be a JSON object".to_string(),
                            BodyArg::Text => "body must be a string".to_string(),
                        })
                    })?;
                    if bytes.len() > api::MAX_BODY {
                        return Err(bad(format!(
                            "the body is larger than {} KiB",
                            api::MAX_BODY / 1024
                        )));
                    }
                    body = Some(bytes);
                    continue;
                }
            }
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => {
                    return Err(bad(format!(
                        "argument {k:?} must be a string, number or boolean"
                    )))
                }
            };
            params.insert(k.clone(), Value::String(s));
        }
        Ok((params, body))
    }

    /// `tools/call`. Policy outcomes are results; only an unknown tool or
    /// a bad argument shape is a JSON-RPC error (decision 7).
    fn call(
        sh: &Shared,
        conn: &mut Option<Daemon>,
        p: t::CallToolParams,
        cancel: &AtomicBool,
    ) -> Result<Value, RpcError> {
        let progress = p.meta.and_then(|m| m.progress_token);
        let args = p.arguments.unwrap_or_default();
        if p.name == tool_schema::RESULT_TOOL {
            let id = request_arg(&args)?;
            return Ok(settle(sh, conn, id, progress.as_ref(), cancel));
        }
        connector_call(sh, conn, &p.name, &args, progress.as_ref(), cancel)
    }

    fn connector_call(
        sh: &Shared,
        conn: &mut Option<Daemon>,
        name: &str,
        args: &Map<String, Value>,
        progress: Option<&Id>,
        cancel: &AtomicBool,
    ) -> Result<Value, RpcError> {
        let target = match lookup(sh, conn, name) {
            Ok(Some(t)) => t,
            Ok(None) => {
                return Err(RpcError::invalid_params(format!(
                    "unknown tool {}",
                    crate::text::sanitize(name)
                )))
            }
            Err(m) => return Ok(unavailable_result(&m)),
        };
        let (params, body) = map_args(&target, args)?;
        let r = match daemon(sh, conn) {
            Ok(d) => api::call_one(
                d,
                &target.service,
                &target.operation,
                params,
                body,
                None,
                "mcp",
            ),
            Err(m) => return Ok(unavailable_result(&m)),
        };
        Ok(match r {
            Ok((3, ans)) => {
                let id = ans.get("pending").and_then(Value::as_u64).unwrap_or(0);
                if sh.wait.is_some() {
                    settle(sh, conn, id, progress, cancel)
                } else {
                    pending_result(id)
                }
            }
            Ok((_, ans)) => done_result(&ans, args),
            Err(s) => {
                if s.0 == 5 {
                    *conn = None;
                }
                stop_result(s)
            }
        })
    }

    /// `saiife_result`'s `request`: an integer >= 1.
    fn request_arg(args: &Map<String, Value>) -> Result<u64, RpcError> {
        if args.keys().any(|k| k != "request") {
            return Err(RpcError::invalid_params(
                "saiife_result takes only {\"request\": <id>}",
            ));
        }
        args.get("request")
            .and_then(Value::as_u64)
            .filter(|n| *n >= 1)
            .ok_or_else(|| RpcError::invalid_params("request must be an integer >= 1"))
    }

    /// The result of request `id` (`api.result`), polled every 2 s while
    /// it waits and `--wait` lasts (decision 8), with a progress
    /// notification on each poll when the client gave a token. A cancel or
    /// the end of input stops the poll.
    fn settle(
        sh: &Shared,
        conn: &mut Option<Daemon>,
        id: u64,
        progress: Option<&Id>,
        cancel: &AtomicBool,
    ) -> Value {
        let deadline = Instant::now() + sh.wait.unwrap_or_default();
        let mut polls: u64 = 0;
        loop {
            let d = match daemon(sh, conn) {
                Ok(d) => d,
                Err(m) => return unavailable_result(&m),
            };
            let mut args = Map::new();
            args.insert("request".into(), id.into());
            let ans = match d
                .client
                .call_answer("api.result", args, Instant::now() + CONTROL)
            {
                Ok(a) => a,
                Err(e) => {
                    let m = broker::unreachable(&d.target, &e);
                    *conn = None;
                    return unavailable_result(&m);
                }
            };
            if ans.get("ok") != Some(&Value::Bool(true)) {
                return stop_result(api::refusal(&ans));
            }
            let state = ans.get("state").and_then(Value::as_str).unwrap_or_default();
            match state {
                "pending" | "approved" => {
                    let stop =
                        || cancel.load(Ordering::SeqCst) || sh.closing.load(Ordering::SeqCst);
                    if Instant::now() >= deadline || stop() {
                        return pending_result(id);
                    }
                    polls += 1;
                    if let Some(tok) = progress {
                        let p = t::ProgressParams {
                            progress_token: tok.clone(),
                            progress: polls as f64,
                            total: None,
                            message: Some(format!("waiting for approval #{id}")),
                        };
                        if let Ok(v) = serde_json::to_value(p) {
                            sh.send(&Message::notification(t::PROGRESS, Some(v)));
                        }
                    }
                    let until = deadline.min(Instant::now() + api::POLL_EVERY);
                    while Instant::now() < until && !stop() {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
                "rejected" | "expired" => {
                    return error_result(&format!("request #{id} was {state}"));
                }
                "sent" | "send_failed" => {
                    return match ans.get("result").and_then(Value::as_object) {
                        Some(r) if r.get("ok") == Some(&Value::Bool(true)) => {
                            done_result(r, &Map::new())
                        }
                        Some(r) => stop_result(api::refusal(r)),
                        None if state == "sent" => error_result(&format!(
                            "request #{id} was sent; its result is kept 24 h and is gone"
                        )),
                        None => error_result(&format!("request #{id}: send failed")),
                    };
                }
                other => {
                    return unavailable_result(&format!(
                        "request #{id} is in an unknown state {other:?}"
                    ))
                }
            }
        }
    }

    fn result(content: Vec<t::Content>, structured: Option<Value>, is_error: bool) -> Value {
        serde_json::to_value(t::CallToolResult {
            content,
            structured_content: structured,
            is_error,
        })
        .unwrap_or_else(|_| json!({"content": [], "isError": true}))
    }

    fn text(s: impl Into<String>) -> t::Content {
        t::Content::Text { text: s.into() }
    }

    fn error_result(m: &str) -> Value {
        result(vec![text(m)], None, true)
    }

    fn unavailable_result(m: &str) -> Value {
        error_result(&format!("saiife unavailable: {m}"))
    }

    /// A refusal, a limit, an upstream failure: the line `saiife api`
    /// prints (without its `saiife: `), as an error result.
    fn stop_result(Stop(code, m): Stop) -> Value {
        if code == 5 {
            unavailable_result(&m)
        } else {
            error_result(&m)
        }
    }

    /// Decision 8, verbatim.
    fn pending_result(id: u64) -> Value {
        result(
            vec![text(format!(
                "waiting for approval #{id}. Call the tool saiife_result with {{\"request\": {id}}} later to get the result. Do not repeat this call."
            ))],
            Some(json!({ "pending": id })),
            false,
        )
    }

    /// A done `api.call` answer (decision 7): the masked body as text (as
    /// an embedded resource when it is not UTF-8), then a note for a cut
    /// response and the next page. Status >= 400 is an error result.
    fn done_result(ans: &Map<String, Value>, args: &Map<String, Value>) -> Value {
        let status = ans.get("status").and_then(Value::as_u64).unwrap_or(0);
        let is_error = status >= 400;
        let mut content = Vec::new();
        if is_error {
            content.push(text(format!("upstream status {status}")));
        }
        match String::from_utf8(api::body_of(ans)) {
            Ok(s) => content.push(text(s)),
            Err(_) => {
                let mime = ans
                    .get("headers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .find(|h| {
                        h[0].as_str()
                            .is_some_and(|k| k.eq_ignore_ascii_case("content-type"))
                    })
                    .and_then(|h| h[1].as_str())
                    .map(str::to_string);
                content.push(t::Content::Resource {
                    resource: t::ResourceContents {
                        uri: "saiife://response".into(),
                        mime_type: mime,
                        text: None,
                        blob: Some(
                            ans.get("body_b64")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        ),
                    },
                });
            }
        }
        if ans.get("truncated") == Some(&Value::Bool(true)) {
            content.push(text("the response was cut at max_response_bytes"));
        }
        if let Some(Value::Object(n)) = ans.get("next") {
            let mut again = args.clone();
            for (k, v) in n {
                again.insert(k.clone(), v.clone());
            }
            content.push(text(format!(
                "next page: call again with {}",
                Value::Object(again)
            )));
        }
        result(content, None, is_error)
    }

    /// How often the poller compares `tools_hash`: 30 s, or (debug builds
    /// only, for tests) `SAIIFE_TEST_MCP_HASH_MS`.
    fn hash_every() -> Duration {
        #[cfg(debug_assertions)]
        if let Some(ms) = std::env::var("SAIIFE_TEST_MCP_HASH_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            return Duration::from_millis(ms.max(10));
        }
        HASH_EVERY
    }

    /// Every 30 s: `notifications/tools/list_changed` when the daemon's
    /// `tools_hash` moved from the one last listed (or announced).
    fn hash_poller(sh: &Shared) {
        let every = hash_every();
        let mut conn: Option<Daemon> = None;
        loop {
            std::thread::sleep(every);
            let got = match daemon(sh, &mut conn) {
                Ok(d) => api_list(d).ok(),
                Err(_) => None,
            };
            let Some(h) = got
                .as_ref()
                .and_then(|a| a.get("tools_hash"))
                .and_then(Value::as_str)
            else {
                conn = None;
                continue;
            };
            let mut known = sh.hash.lock().unwrap_or_else(|p| p.into_inner());
            match known.as_deref() {
                None => *known = Some(h.to_string()),
                Some(k) if k == h => {}
                Some(_) => {
                    *known = Some(h.to_string());
                    drop(known);
                    sh.send(&Message::notification(t::TOOLS_LIST_CHANGED, None));
                }
            }
        }
    }
}
