//! The MCP gateway supervisor (plan 17, §6.15, decisions 12 and 13): one
//! child per `[mcp.<name>]`, spawned as the daemon user through
//! `saiife __mcp-spawn` (Landlock, `no_new_privs`, a cleared environment
//! holding only its secrets), initialized as an MCP client, its tools
//! cached, restarted with backoff when it exits and stopped at a reload
//! that removes or changes it, or at the daemon's stop.
//!
//! Lifecycle events are `daemon` records with `event` =
//! `mcp_server_started` | `mcp_server_exited` | `mcp_server_failed` and a
//! `server` field. Secret values reach only the child's environment and the
//! per-child masker: never a record, `status`, the journal or an answer.
//!
//! The gateway also answers who its children are
//! ([`Gateway::is_child_or_descendant`]): the control and gateway sockets
//! refuse them (`mcp_child_peer`), since a pathname-socket connect is not
//! covered by Landlock.

pub mod child;

use crate::ops::{now_ts, Ctx};
use crate::vault::{Kind, VaultState};
use child::{Conn, Event, Running, StartError};
use saiife_broker::mask::Masker;
use saiife_mcp::types::Tool;
use saiife_policy::{McpServerCfg, Sandbox, SystemConfig};
use saiife_system::sandbox::SpawnSpec;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

/// How long `initialize` and each `tools/list` page may take.
pub const INIT_TIMEOUT: Duration = Duration::from_secs(30);
/// After EOF on stdin, a child gets this long to exit before it is killed.
pub const STOP_GRACE: Duration = Duration::from_secs(2);
/// The first and the longest wait before a restart.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A child that ran this long restarts after [`BACKOFF_MIN`] again.
const STABLE_AFTER: Duration = Duration::from_secs(60);

/// Debug builds only: `SAIIFE_TEST_OWN_UID_PEERS=allow` lets the locked
/// daemon serve peers of its own uid. The test suite runs the system
/// daemon and its clients as one user; release builds never read it.
pub const OWN_UID_PEERS_SEAM: &str = "SAIIFE_TEST_OWN_UID_PEERS";

/// Whether [`OWN_UID_PEERS_SEAM`] is set (always false in release builds).
pub fn own_uid_peers_allowed() -> bool {
    #[cfg(debug_assertions)]
    let seam = std::env::var_os(OWN_UID_PEERS_SEAM);
    #[cfg(not(debug_assertions))]
    let seam: Option<std::ffi::OsString> = None;
    cfg!(debug_assertions) && seam.is_some_and(|v| v == "allow")
}

/// Why a gateway call failed. Task 7 maps every one to
/// `Outcome::UpstreamFailed { reason }`; the texts hold no secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildError {
    Exited,
    Timeout,
    TooLarge,
    Protocol(String),
    NotRunning(String),
}

impl std::fmt::Display for ChildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChildError::Exited => f.write_str("mcp server exited"),
            ChildError::Timeout => f.write_str("mcp server did not answer in time"),
            ChildError::TooLarge => f.write_str("mcp server answer too large"),
            ChildError::Protocol(m) => write!(f, "mcp server protocol error: {m}"),
            ChildError::NotRunning(m) => write!(f, "mcp server not running: {m}"),
        }
    }
}

impl std::error::Error for ChildError {}

/// A boxed future, for the object-safe [`ToolCaller`].
pub type CallFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, ChildError>> + Send + 'a>>;

/// What the gateway pipeline (Task 7) needs from the supervisor; tests use
/// a fake.
pub trait ToolCaller: Send + Sync {
    /// The cached tools of a running server, `None` when it is not running.
    fn tools(&self, server: &str) -> Option<Arc<Vec<Tool>>>;
    /// `tools/call`. The result is the server's `CallToolResult` as a JSON
    /// value (never read into a closed type): an object with a `content`
    /// array, image/audio and unknown items replaced with text, and every
    /// string masked with the server's secret values and the v1 patterns.
    /// `tool` is sent byte-for-byte as the server listed it.
    fn call<'a>(
        &'a self,
        server: &'a str,
        tool: &'a str,
        args: Value,
        timeout: Duration,
        cap: usize,
    ) -> CallFuture<'a>;
    /// The secret values (every form the vault holds) of `server`, for
    /// masking what the pipeline records. Empty for a server without
    /// secrets or one that is not configured.
    fn secret_values(&self, server: &str) -> Vec<Zeroizing<String>> {
        let _ = server;
        Vec::new()
    }
}

/// Where the gateway runs its children.
#[derive(Debug, Clone)]
pub struct GatewaySetup {
    /// `saiife __mcp-spawn`'s binary ([`saiife_system::sandbox::spawn_helper`]).
    pub helper: PathBuf,
    /// The daemon's state dir: homes are `<state>/mcp/<name>/`.
    pub state_dir: PathBuf,
    /// The daemon's own dirs (config, state, audit, sockets, credentials),
    /// for [`SpawnSpec::protected`].
    pub protected: Vec<PathBuf>,
    /// False for the personal broker: its config cannot hold `[mcp.*]`
    /// (decision 12), and the gateway starts nothing.
    pub enabled: bool,
    /// Where the gateway's journal lines go (the children's masked stderr,
    /// lifecycle lines): the daemon's stderr.
    pub log: Log,
}

/// A sink for journal lines; [`Log::stderr`] in the daemon, a capture in
/// tests.
#[derive(Clone)]
pub struct Log(Arc<dyn Fn(&str) + Send + Sync>);

impl Log {
    pub fn stderr() -> Log {
        Log(Arc::new(|l: &str| eprintln!("{l}")))
    }

    pub fn new(f: impl Fn(&str) + Send + Sync + 'static) -> Log {
        Log(Arc::new(f))
    }

    pub fn line(&self, l: &str) {
        (self.0)(l)
    }
}

impl std::fmt::Debug for Log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Log")
    }
}

impl GatewaySetup {
    /// The defaults for a state dir: the installed (or, in debug builds,
    /// the seam's) helper, enabled.
    pub fn in_state(state_dir: &Path) -> GatewaySetup {
        GatewaySetup {
            helper: saiife_system::sandbox::spawn_helper(),
            state_dir: state_dir.to_path_buf(),
            protected: vec![state_dir.to_path_buf()],
            enabled: true,
            log: Log::stderr(),
        }
    }
}

/// What a server should run as, resolved from the policy and the vault.
#[derive(Clone)]
struct Desired {
    cfg: McpServerCfg,
    env: Vec<(String, Zeroizing<String>)>,
    /// Every secret form to mask in what the child says.
    values: Vec<Zeroizing<String>>,
    line_cap: usize,
}

impl PartialEq for Desired {
    fn eq(&self, o: &Desired) -> bool {
        self.cfg == o.cfg
            && self.line_cap == o.line_cap
            && self.env.len() == o.env.len()
            && self
                .env
                .iter()
                .zip(&o.env)
                .all(|(a, b)| a.0 == b.0 && *a.1 == *b.1)
    }
}

/// A desired server, or why it cannot start (no secrets in the text).
#[derive(Clone, PartialEq)]
enum Plan {
    Run(Box<Desired>),
    Refused(String),
}

struct ServerState {
    state: &'static str,
    since: String,
    tools: Arc<Vec<Tool>>,
    last_error: Option<String>,
    conn: Option<Arc<Conn>>,
}

struct Server {
    name: String,
    plan: Plan,
    masker: Arc<Masker>,
    state: Mutex<ServerState>,
    stop: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Server {
    fn set(&self, state: &'static str, err: Option<String>) {
        let mut s = lock(&self.state);
        s.state = state;
        s.since = now_ts();
        if err.is_some() {
            s.last_error = err;
        }
    }

    fn values(&self) -> Vec<Zeroizing<String>> {
        match &self.plan {
            Plan::Run(d) => d.values.clone(),
            Plan::Refused(_) => Vec::new(),
        }
    }
}

struct Inner {
    setup: GatewaySetup,
    host: OnceLock<Weak<Ctx>>,
    /// Pids of the children (the helper's pid is the server's: it execs).
    pids: Mutex<BTreeSet<u32>>,
}

/// The gateway: the servers of the policy in force and their children.
pub struct Gateway {
    inner: Arc<Inner>,
    servers: Mutex<BTreeMap<String, Arc<Server>>>,
    stopping: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Gateway {
    pub fn new(setup: GatewaySetup) -> Gateway {
        Gateway {
            inner: Arc::new(Inner {
                setup,
                host: OnceLock::new(),
                pids: Mutex::new(BTreeSet::new()),
            }),
            servers: Mutex::new(BTreeMap::new()),
            stopping: AtomicBool::new(false),
        }
    }

    /// The context lifecycle records go through (set once, after the
    /// context is shared). Without one, events go to stderr only.
    pub fn attach(&self, ctx: Weak<Ctx>) {
        let _ = self.inner.host.set(ctx);
    }

    /// Match the running servers to `cfg`: servers no longer listed, or
    /// whose config or secret values changed, are stopped; new and changed
    /// ones are started. Secrets are read from `vault` now (a server whose
    /// secret is missing or not allowed for `mcp:<name>` is `failed`, with
    /// a `mcp_server_failed` record). Synchronous: the starts and stops run
    /// in tasks of the current runtime, so the caller may hold the vault
    /// lock.
    pub fn reconcile(&self, cfg: &SystemConfig, vault: &VaultState) {
        if self.stopping.load(Ordering::Acquire) {
            return;
        }
        let wanted: BTreeMap<String, Plan> = if self.inner.setup.enabled {
            cfg.mcp
                .iter()
                .map(|(name, s)| (name.clone(), plan_for(name, s, cfg, vault)))
                .collect()
        } else {
            BTreeMap::new()
        };
        let mut servers = lock(&self.servers);
        let mut previous: BTreeMap<String, Option<JoinHandle<()>>> = BTreeMap::new();
        let names: Vec<String> = servers.keys().cloned().collect();
        for name in names {
            let keep = wanted.get(&name).is_some_and(|p| *p == servers[&name].plan);
            if keep {
                continue;
            }
            if let Some(old) = servers.remove(&name) {
                let _ = old.stop.send(true);
                previous.insert(name, lock(&old.task).take());
            }
        }
        for (name, plan) in wanted {
            if servers.contains_key(&name) {
                continue;
            }
            let masker = Arc::new(match &plan {
                Plan::Run(d) => {
                    let v: Vec<&str> = d.values.iter().map(|s| s.as_str()).collect();
                    Masker::new(&v)
                }
                Plan::Refused(_) => Masker::new(&[]),
            });
            let (stop, _) = watch::channel(false);
            let srv = Arc::new(Server {
                name: name.clone(),
                plan,
                masker,
                state: Mutex::new(ServerState {
                    state: "starting",
                    since: now_ts(),
                    tools: Arc::new(Vec::new()),
                    last_error: None,
                    conn: None,
                }),
                stop,
                task: Mutex::new(None),
            });
            let prev = previous.remove(&name).flatten();
            let task = tokio::spawn(supervise(Arc::clone(&self.inner), Arc::clone(&srv), prev));
            *lock(&srv.task) = Some(task);
            servers.insert(name, srv);
        }
        // Removed servers: their supervisors stop on their own; nothing
        // waits for them here.
        drop(previous);
    }

    /// The cached tools of `server` while it runs.
    pub fn tools(&self, server: &str) -> Option<Arc<Vec<Tool>>> {
        let s = lock(&self.servers).get(server).cloned()?;
        let st = lock(&s.state);
        (st.state == "running").then(|| Arc::clone(&st.tools))
    }

    /// `tools/call` on `server` (see [`ToolCaller::call`]). At most 4 calls
    /// are in flight per child; `timeout` covers the wait for a slot too.
    /// On a timeout the request is cancelled (`notifications/cancelled`).
    /// A result line over `cap` bytes is [`ChildError::TooLarge`].
    pub async fn call(
        &self,
        server: &str,
        tool: &str,
        args: Value,
        timeout: Duration,
        cap: usize,
    ) -> Result<Value, ChildError> {
        let srv = lock(&self.servers)
            .get(server)
            .cloned()
            .ok_or_else(|| ChildError::NotRunning(format!("no mcp server {server}")))?;
        let conn = {
            let st = lock(&srv.state);
            match (&st.conn, st.state) {
                (Some(c), "running") => Arc::clone(c),
                (_, state) => {
                    return Err(ChildError::NotRunning(format!(
                        "mcp server {server} is {state}"
                    )))
                }
            }
        };
        let arguments = match args {
            Value::Object(_) => args,
            Value::Null => json!({}),
            _ => return Err(ChildError::Protocol("arguments must be an object".into())),
        };
        let deadline = tokio::time::Instant::now() + timeout;
        let _slot = tokio::time::timeout_at(deadline, conn.pool.acquire())
            .await
            .map_err(|_| ChildError::Timeout)?
            .map_err(|_| ChildError::Exited)?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let params = json!({"name": tool, "arguments": arguments});
        let masked = |e: ChildError| match e {
            ChildError::Protocol(m) => ChildError::Protocol(srv.masker.mask_text(&m)),
            other => other,
        };
        let (v, bytes) = conn
            .request(saiife_mcp::types::TOOLS_CALL, params, left)
            .await
            .map_err(masked)?;
        if bytes > cap {
            return Err(ChildError::TooLarge);
        }
        child::mask_result(v, &srv.masker).map_err(masked)
    }

    /// The masker's values of `server` (see [`ToolCaller::secret_values`]).
    pub fn secret_values(&self, server: &str) -> Vec<Zeroizing<String>> {
        lock(&self.servers)
            .get(server)
            .map(|s| s.values())
            .unwrap_or_default()
    }

    /// Whether any child is running (or starting).
    pub fn has_children(&self) -> bool {
        !lock(&self.inner.pids).is_empty()
    }

    /// Whether `pid` is a gateway child or descends from one: one of its
    /// ancestors (by parent pid) or its session (each child is a session
    /// leader: the helper calls `setsid`) is a child. A pid whose `/proc`
    /// entry cannot be read while children run counts as one (fail
    /// closed).
    pub fn is_child_or_descendant(&self, pid: u32) -> bool {
        let pids = lock(&self.inner.pids).clone();
        descends(&pids, pid, &|p| proc_stat(Path::new("/proc"), p))
    }

    /// Whether a gateway child or one of its descendants holds the socket
    /// with this inode (a loopback TCP peer, found in `/proc/net/tcp*`).
    pub fn holds_socket(&self, inode: u64) -> bool {
        let pids = lock(&self.inner.pids).clone();
        if pids.is_empty() {
            return false;
        }
        let want = format!("socket:[{inode}]");
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return true;
        };
        let stat = |p| proc_stat(Path::new("/proc"), p);
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            // Only the children's own processes: they run as the daemon
            // user, so their fds are readable.
            if !pids.contains(&pid) && !descends_strict(&pids, pid, &stat) {
                continue;
            }
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if std::fs::read_link(fd.path()).is_ok_and(|l| l.as_os_str() == want.as_str()) {
                    return true;
                }
            }
        }
        false
    }

    /// `[{name, state, tools, since, last_error}]`, by name. `state` is
    /// `starting`, `running`, `backoff`, `failed` or `stopped`.
    pub fn status(&self) -> Value {
        let servers: Vec<Arc<Server>> = lock(&self.servers).values().cloned().collect();
        Value::Array(
            servers
                .iter()
                .map(|s| {
                    let st = lock(&s.state);
                    json!({
                        "name": s.name,
                        "state": st.state,
                        "tools": st.tools.len(),
                        "since": st.since,
                        "last_error": st.last_error,
                    })
                })
                .collect(),
        )
    }

    /// Stop every child: EOF on its stdin, [`STOP_GRACE`] to exit, then a
    /// kill through the child's own handle. Returns once each supervisor
    /// wrote its exit record, at most a few seconds: a child that ignores
    /// EOF never holds up the daemon's stop.
    pub async fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        let servers: Vec<Arc<Server>> = std::mem::take(&mut *lock(&self.servers))
            .into_values()
            .collect();
        let mut tasks = Vec::new();
        for s in &servers {
            let _ = s.stop.send(true);
            if let Some(t) = lock(&s.task).take() {
                tasks.push(t);
            }
        }
        let limit = STOP_GRACE + Duration::from_secs(2);
        let all = async {
            for t in tasks {
                let _ = t.await;
            }
        };
        if tokio::time::timeout(limit, all).await.is_err() {
            self.inner
                .setup
                .log
                .line("saiife: warning: mcp servers still stopping at the daemon stop");
        }
    }

    /// Tests: count `pid` as a child.
    #[cfg(test)]
    pub(crate) fn add_test_pid(&self, pid: u32) {
        lock(&self.inner.pids).insert(pid);
    }
}

impl ToolCaller for Gateway {
    fn tools(&self, server: &str) -> Option<Arc<Vec<Tool>>> {
        Gateway::tools(self, server)
    }

    fn call<'a>(
        &'a self,
        server: &'a str,
        tool: &'a str,
        args: Value,
        timeout: Duration,
        cap: usize,
    ) -> CallFuture<'a> {
        Box::pin(Gateway::call(self, server, tool, args, timeout, cap))
    }

    fn secret_values(&self, server: &str) -> Vec<Zeroizing<String>> {
        Gateway::secret_values(self, server)
    }
}

/// The env value of a vault entry, as `secret.lease` hands it out.
fn env_value(
    kind: Kind,
    fields: &BTreeMap<String, Zeroizing<String>>,
) -> Option<Zeroizing<String>> {
    let f = |k: &str| fields.get(k).map(|v| v.as_str()).unwrap_or("");
    match kind {
        Kind::Token => Some(Zeroizing::new(f("token").to_string())),
        Kind::Basic => Some(Zeroizing::new(format!(
            "{}:{}",
            f("username"),
            f("password")
        ))),
        Kind::Header => Some(Zeroizing::new(f("value").to_string())),
        Kind::OAuth2 => None,
    }
}

fn plan_for(name: &str, s: &McpServerCfg, sys: &SystemConfig, vault: &VaultState) -> Plan {
    let service = format!("mcp:{name}");
    let mut env = Vec::new();
    let mut values = Vec::new();
    for (var, secret) in &s.env {
        let VaultState::Ready(v) = vault else {
            return Plan::Refused(format!(
                "vault_unavailable: secret {secret} (env {var}) cannot be read"
            ));
        };
        let Some(e) = v.get(secret) else {
            return Plan::Refused(format!(
                "secret_missing: secret {secret} (env {var}) is not in the vault"
            ));
        };
        if !e.allowed_services.contains(&service) {
            return Plan::Refused(format!(
                "secret_not_allowed_for_service: secret {secret} (env {var}) does not list {service} in allowed_services"
            ));
        }
        let Some(value) = env_value(e.kind, &e.fields) else {
            return Plan::Refused(format!(
                "secret_kind_unsupported: secret {secret} (env {var}) is an oauth2 secret, for connectors only"
            ));
        };
        values.extend(e.fields.values().filter(|v| !v.is_empty()).cloned());
        values.push(value.clone());
        env.push((var.clone(), value));
    }
    let max = s
        .limits
        .max_response_bytes
        .unwrap_or(sys.gateway.max_response_bytes);
    let line_cap = usize::try_from(max)
        .unwrap_or(usize::MAX)
        .saturating_add(child::LINE_SLACK);
    Plan::Run(Box::new(Desired {
        cfg: s.clone(),
        env,
        values,
        line_cap,
    }))
}

impl Inner {
    /// A lifecycle record for `server`; also one stderr line.
    async fn record(&self, event: &str, server: &str, reason: &str, tools: Option<usize>) {
        self.setup
            .log
            .line(&format!("saiife: mcp {server}: {event}: {reason}"));
        let Some(ctx) = self.host.get().and_then(Weak::upgrade) else {
            return;
        };
        let mut r = ctx.event(event);
        r.extra.insert("server".into(), server.into());
        if let Some(n) = tools {
            r.extra.insert("tools".into(), n.into());
        }
        r.reason = Some(reason.to_string());
        let writer = ctx.writer.clone();
        drop(ctx);
        if let Err(e) = writer.append(r).await {
            self.setup.log.line(&format!(
                "saiife: warning: cannot write the {event} record: {e}"
            ));
        }
    }

    fn home_of(&self, name: &str) -> Result<PathBuf, String> {
        let base = self.setup.state_dir.join("mcp");
        let home = base.join(name);
        for d in [&base, &home] {
            saiife_system::fsops::create_dir_mode(d, 0o700)
                .and_then(|_| saiife_system::fsops::set_dir_mode(d, 0o700))
                .map_err(|e| format!("cannot prepare the home dir: {}", e.kind()))?;
        }
        Ok(home)
    }

    /// Spawn, initialize and list the tools of one child.
    async fn start(&self, srv: &Server, d: &Desired) -> Result<(Running, Vec<Tool>), StartError> {
        if d.cfg.sandbox == Sandbox::Landlock && saiife_system::sandbox::landlock_abi() == 0 {
            return Err(StartError::permanent(
                "sandbox_unavailable: the kernel has no Landlock (set sandbox = \"off\" to run this server unconfined)",
            ));
        }
        saiife_system::fsops::root_owned_chain(&d.cfg.command).map_err(|e| {
            StartError::permanent(format!(
                "command_not_root_owned: {}",
                srv.masker.mask_text(&e)
            ))
        })?;
        let home = self.home_of(&srv.name).map_err(StartError::retry)?;
        let spec = SpawnSpec {
            command: d.cfg.command.clone(),
            args: d.cfg.args.clone(),
            env: d.env.clone(),
            home,
            read_paths: d.cfg.read_paths.clone(),
            sandbox: d.cfg.sandbox,
            protected: self.setup.protected.clone(),
        };
        let mut running = child::spawn(
            &self.setup.helper,
            &srv.name,
            &spec,
            Arc::clone(&srv.masker),
            d.line_cap,
            self.setup.log.clone(),
        )
        .await?;
        drop(spec);
        lock(&self.pids).insert(running.pid);
        let init = async {
            child::initialize(&running.conn, INIT_TIMEOUT).await?;
            child::list_tools(&running.conn, INIT_TIMEOUT)
                .await
                .map_err(|e| StartError::retry(format!("tools/list failed: {e}")))
        };
        match init.await {
            Ok(tools) => Ok((running, tools)),
            Err(e) => {
                kill(&mut running.process, running.pid).await;
                lock(&self.pids).remove(&running.pid);
                Err(e)
            }
        }
    }
}

/// Kill the child and its process group (it is the leader: the helper
/// calls `setsid`), through the handle we hold; reap it, bounded.
async fn kill(p: &mut tokio::process::Child, pid: u32) {
    if let Some(raw) = rustix::process::Pid::from_raw(pid as i32) {
        // Only while unreaped, and only when it leads its own group.
        if p.try_wait().ok().flatten().is_none()
            && rustix::process::getpgid(Some(raw)).is_ok_and(|g| g == raw)
        {
            let _ = rustix::process::kill_process_group(raw, rustix::process::Signal::KILL);
        }
    }
    let _ = p.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(1), p.wait()).await;
}

fn exit_text(st: std::io::Result<std::process::ExitStatus>) -> String {
    match st {
        Ok(s) => match (s.code(), s.signal()) {
            (Some(c), _) => format!("exited with code {c}"),
            (None, Some(sig)) => format!("killed by signal {sig}"),
            _ => "exited".to_string(),
        },
        Err(e) => format!("exited (wait failed: {})", e.kind()),
    }
}

/// How a running child ended.
enum End {
    Stopped(String),
    Exited(String),
}

/// One server, for as long as it is in the policy.
async fn supervise(inner: Arc<Inner>, srv: Arc<Server>, prev: Option<JoinHandle<()>>) {
    let mut stop = srv.stop.subscribe();
    if let Some(p) = prev {
        // The old child of a changed server goes first (same home dir).
        let _ = tokio::time::timeout(STOP_GRACE + Duration::from_secs(3), p).await;
    }
    let d = match &srv.plan {
        Plan::Run(d) => d.as_ref().clone(),
        Plan::Refused(reason) => {
            srv.set("failed", Some(reason.clone()));
            inner
                .record("mcp_server_failed", &srv.name, reason, None)
                .await;
            return;
        }
    };
    let mut backoff = BACKOFF_MIN;
    loop {
        if *stop.borrow() {
            srv.set("stopped", None);
            return;
        }
        srv.set("starting", None);
        let started = tokio::select! {
            r = inner.start(&srv, &d) => r,
            _ = stopped(&mut stop) => {
                srv.set("stopped", None);
                return;
            }
        };
        let (mut running, tools) = match started {
            Ok(x) => x,
            Err(e) => {
                srv.set(
                    if e.permanent { "failed" } else { "backoff" },
                    Some(e.reason.clone()),
                );
                inner
                    .record("mcp_server_failed", &srv.name, &e.reason, None)
                    .await;
                if e.permanent {
                    return;
                }
                if !sleep_or_stop(&mut stop, backoff).await {
                    srv.set("stopped", None);
                    return;
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        let n = tools.len();
        {
            let mut st = lock(&srv.state);
            st.tools = Arc::new(tools);
            st.conn = Some(Arc::clone(&running.conn));
            st.state = "running";
            st.since = now_ts();
        }
        inner
            .record(
                "mcp_server_started",
                &srv.name,
                &format!("pid {}, {n} tool(s)", running.pid),
                Some(n),
            )
            .await;
        let up = tokio::time::Instant::now();
        let end = run(&srv, &mut running, &mut stop, &inner.setup.log).await;
        lock(&inner.pids).remove(&running.pid);
        running.conn.fail_all(ChildError::Exited);
        {
            let mut st = lock(&srv.state);
            st.conn = None;
            st.tools = Arc::new(Vec::new());
        }
        match end {
            End::Stopped(why) => {
                srv.set("stopped", None);
                inner
                    .record("mcp_server_exited", &srv.name, &why, None)
                    .await;
                return;
            }
            End::Exited(why) => {
                srv.set("backoff", Some(why.clone()));
                inner
                    .record("mcp_server_exited", &srv.name, &why, None)
                    .await;
            }
        }
        if up.elapsed() >= STABLE_AFTER {
            backoff = BACKOFF_MIN;
        }
        if !sleep_or_stop(&mut stop, backoff).await {
            srv.set("stopped", None);
            return;
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// Until a stop is asked for (or the server is gone).
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|s| *s).await;
}

/// Sleep `d`; false when a stop came first.
async fn sleep_or_stop(stop: &mut watch::Receiver<bool>, d: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => true,
        _ = stopped(stop) => false,
    }
}

/// Serve one running child until it exits, breaks the protocol, or a stop.
async fn run(
    srv: &Arc<Server>,
    r: &mut Running,
    stop: &mut watch::Receiver<bool>,
    log: &Log,
) -> End {
    let mut events_open = true;
    loop {
        tokio::select! {
            st = r.process.wait() => {
                let why = format!("mcp server exited: {}", exit_text(st));
                return End::Exited(why);
            }
            ev = r.events.recv(), if events_open => match ev {
                Some(Event::ListChanged) => {
                    let srv = Arc::clone(srv);
                    let conn = Arc::clone(&r.conn);
                    let log = log.clone();
                    tokio::spawn(async move { relist(srv, conn, log).await });
                }
                Some(Event::Fatal(why)) => {
                    kill(&mut r.process, r.pid).await;
                    return End::Exited(format!("stopped: {why}"));
                }
                None => events_open = false,
            },
            _ = stopped(stop) => {
                r.conn.close_stdin();
                let how = match tokio::time::timeout(STOP_GRACE, r.process.wait()).await {
                    Ok(st) => exit_text(st),
                    Err(_) => {
                        kill(&mut r.process, r.pid).await;
                        "killed after 2 s without exiting on EOF".to_string()
                    }
                };
                return End::Stopped(format!("stopped: {how}"));
            }
        }
    }
}

/// `notifications/tools/list_changed`: list again; a failed list keeps the
/// old one.
async fn relist(srv: Arc<Server>, conn: Arc<Conn>, log: Log) {
    match child::list_tools(&conn, INIT_TIMEOUT).await {
        Ok(tools) => {
            let mut st = lock(&srv.state);
            if st.conn.as_ref().is_some_and(|c| Arc::ptr_eq(c, &conn)) {
                st.tools = Arc::new(tools);
            }
        }
        Err(e) => log.line(&format!(
            "saiife: mcp {}: tools/list after list_changed failed: {e}",
            srv.name
        )),
    }
}

/// `(ppid, session)` of `pid` from `<proc>/<pid>/stat`.
fn proc_stat(proc: &Path, pid: u32) -> Option<(u32, u32)> {
    let s = std::fs::read_to_string(proc.join(pid.to_string()).join("stat")).ok()?;
    // `comm` may hold spaces and parens: the fields start after the last ')'.
    let rest = &s[s.rfind(')')? + 1..];
    let mut f = rest.split_ascii_whitespace();
    let _state = f.next()?;
    let ppid = f.next()?.parse().ok()?;
    let _pgrp = f.next()?;
    let session = f.next()?.parse().ok()?;
    Some((ppid, session))
}

/// [`Gateway::is_child_or_descendant`] over `stat`. Unreadable `pid`
/// while children run: true (fail closed).
fn descends(pids: &BTreeSet<u32>, pid: u32, stat: &dyn Fn(u32) -> Option<(u32, u32)>) -> bool {
    if pids.is_empty() {
        return false;
    }
    if pids.contains(&pid) {
        return true;
    }
    if stat(pid).is_none() {
        return true;
    }
    descends_strict(pids, pid, stat)
}

/// Whether an ancestor or the session of `pid` is in `pids`; an
/// unreadable entry ends the walk (false).
fn descends_strict(
    pids: &BTreeSet<u32>,
    pid: u32,
    stat: &dyn Fn(u32) -> Option<(u32, u32)>,
) -> bool {
    let mut cur = pid;
    for _ in 0..256 {
        if pids.contains(&cur) {
            return true;
        }
        let Some((ppid, session)) = stat(cur) else {
            return false;
        };
        if pids.contains(&session) {
            return true;
        }
        if ppid <= 1 || ppid == cur {
            return false;
        }
        cur = ppid;
    }
    false
}

/// The uid and inode of the client end of a loopback TCP connection the
/// daemon accepted (`local` is the daemon's end, `peer` the client's),
/// from `/proc/net/tcp` and `/proc/net/tcp6`.
pub fn tcp_peer_socket(local: SocketAddr, peer: SocketAddr) -> Option<(u32, u64)> {
    tcp_peer_socket_in(Path::new("/proc/net"), local, peer)
}

fn tcp_peer_socket_in(net: &Path, local: SocketAddr, peer: SocketAddr) -> Option<(u32, u64)> {
    for file in ["tcp", "tcp6"] {
        let Ok(text) = std::fs::read_to_string(net.join(file)) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_ascii_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            // The client's socket: its local end is `peer`, its remote end
            // the daemon's `local`.
            if parse_addr(f[1]) == Some(peer) && parse_addr(f[2]) == Some(local) {
                return Some((f[7].parse().ok()?, f[9].parse().ok()?));
            }
        }
    }
    None
}

/// `0100007F:1F90` (IPv4) or 32 hex digits and a port (IPv6). Each 32-bit
/// word is printed as the kernel holds it, so it is read back in native
/// byte order.
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        Some(
            u32::from_str_radix(ip.get(i * 8..i * 8 + 8)?, 16)
                .ok()?
                .to_ne_bytes(),
        )
    };
    let ip: std::net::IpAddr = match ip.len() {
        8 => std::net::Ipv4Addr::from(word(0)?).into(),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            let v6 = std::net::Ipv6Addr::from(b);
            // A v4 client of a dual-stack listener shows as v4-mapped.
            match v6.to_ipv4_mapped() {
                Some(v4) => v4.into(),
                None => v6.into(),
            }
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Normalise a v4-mapped address as [`parse_addr`] does.
fn canonical(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => a,
        },
        SocketAddr::V4(_) => a,
    }
}

/// Which listener refused a peer, for the `mcp_child_peer` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerSocket {
    Control,
    Gateway,
    Tcp,
}

impl PeerSocket {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerSocket::Control => "control socket",
            PeerSocket::Gateway => "gateway socket",
            PeerSocket::Tcp => "gateway TCP listener",
        }
    }
}

/// Whether a unix socket peer is refused before anything is read: in
/// locked mode any process of the daemon's own uid (no client runs as the
/// daemon user, and gateway children do), in every mode a gateway child
/// or a descendant of one.
pub(crate) fn unix_peer_refused(ctx: &Ctx, peer: &saiife_ipc::peer::PeerCred) -> bool {
    (ctx.refuse_own_uid_peers && peer.uid == ctx.own_uid)
        || (ctx.mcp.has_children() && ctx.mcp.is_child_or_descendant(peer.pid))
}

/// [`unix_peer_refused`] for the loopback TCP listener: the client
/// socket's uid and holder are found in `/proc`. `Some(uid)` (the socket's
/// uid, or [`crate::ops::UNKNOWN_UID`]) when refused. A peer that cannot be
/// found while a check is due is refused (fail closed).
pub(crate) async fn tcp_peer_refused(
    ctx: &Arc<Ctx>,
    local: SocketAddr,
    peer: SocketAddr,
) -> Option<u32> {
    let own = ctx.refuse_own_uid_peers;
    let children = ctx.mcp.has_children();
    if !own && !children {
        return None;
    }
    let c = Arc::clone(ctx);
    tokio::task::spawn_blocking(move || {
        let Some((uid, inode)) = tcp_peer_socket(canonical(local), canonical(peer)) else {
            return Some(crate::ops::UNKNOWN_UID);
        };
        let refused = (own && uid == c.own_uid) || (children && c.mcp.holds_socket(inode));
        refused.then_some(uid)
    })
    .await
    .unwrap_or(Some(crate::ops::UNKNOWN_UID))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descends_by_parent_or_session() {
        // pid -> (ppid, session)
        let table: BTreeMap<u32, (u32, u32)> = [
            (100, (1, 100)),   // a child, its own session
            (101, (100, 100)), // its child
            (102, (101, 102)), // a grandchild in a new session
            (200, (1, 200)),   // unrelated
            (201, (200, 100)), // reparented but still in the child's session
            (300, (1, 300)),
        ]
        .into();
        let stat = |p: u32| table.get(&p).copied();
        let kids: BTreeSet<u32> = [100].into();
        assert!(descends(&kids, 100, &stat));
        assert!(descends(&kids, 101, &stat));
        assert!(descends(&kids, 102, &stat));
        assert!(descends(&kids, 201, &stat));
        assert!(!descends(&kids, 200, &stat));
        assert!(!descends(&kids, 300, &stat));
        // Unreadable while children run: refused; no children: never.
        assert!(descends(&kids, 999, &stat));
        assert!(!descends(&BTreeSet::new(), 101, &stat));
        assert!(!descends_strict(&kids, 999, &stat));
    }

    #[test]
    fn proc_stat_reads_ppid_and_session_past_odd_comm() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("42")).unwrap();
        std::fs::write(
            t.path().join("42/stat"),
            "42 (a) b (c)) S 7 42 9 0 -1 4194560 0 0",
        )
        .unwrap();
        assert_eq!(proc_stat(t.path(), 42), Some((7, 9)));
        assert_eq!(proc_stat(t.path(), 43), None);
        // This process: its parent is the test runner.
        let me = std::process::id();
        let (ppid, _) = proc_stat(Path::new("/proc"), me).unwrap();
        assert_eq!(ppid, std::os::unix::process::parent_id());
    }

    #[test]
    fn real_descendant_found() {
        let gw = Gateway::new(GatewaySetup::in_state(Path::new("/nonexistent")));
        let mut sleeper = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = sleeper.id();
        assert!(!gw.is_child_or_descendant(pid));
        gw.add_test_pid(std::process::id());
        assert!(gw.is_child_or_descendant(pid));
        assert!(gw.is_child_or_descendant(std::process::id()));
        let _ = sleeper.kill();
        let _ = sleeper.wait();
    }

    #[test]
    fn addrs_parse_in_native_order() {
        let v4: [u8; 4] = [127, 0, 0, 1];
        let hex = format!("{:08X}:1F90", u32::from_ne_bytes(v4));
        assert_eq!(parse_addr(&hex), Some("127.0.0.1:8080".parse().unwrap()));
        let mut six = String::new();
        let b = std::net::Ipv6Addr::LOCALHOST.octets();
        for i in 0..4 {
            let w: [u8; 4] = b[i * 4..i * 4 + 4].try_into().unwrap();
            six.push_str(&format!("{:08X}", u32::from_ne_bytes(w)));
        }
        assert_eq!(
            parse_addr(&format!("{six}:0050")),
            Some("[::1]:80".parse().unwrap())
        );
        assert_eq!(parse_addr("zz"), None);
    }

    #[test]
    fn tcp_peer_found_with_uid_and_inode() {
        use std::os::fd::AsRawFd;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (_server, peer) = l.accept().unwrap();
        let (uid, inode) = tcp_peer_socket(l.local_addr().unwrap(), peer).expect("found");
        assert_eq!(uid, rustix::process::getuid().as_raw());
        let link = std::fs::read_link(format!("/proc/self/fd/{}", client.as_raw_fd())).unwrap();
        assert_eq!(link.to_string_lossy(), format!("socket:[{inode}]"));
        let gw = Gateway::new(GatewaySetup::in_state(Path::new("/nonexistent")));
        assert!(!gw.holds_socket(inode));
        gw.add_test_pid(std::process::id());
        assert!(gw.holds_socket(inode));
    }

    #[test]
    fn env_values_per_kind() {
        let f = |k: &str, v: &str| -> BTreeMap<String, Zeroizing<String>> {
            [(k.to_string(), Zeroizing::new(v.to_string()))].into()
        };
        assert_eq!(
            *env_value(Kind::Token, &f("token", "abcd")).unwrap(),
            "abcd"
        );
        assert_eq!(
            *env_value(Kind::Header, &f("value", "wxyz")).unwrap(),
            "wxyz"
        );
        assert!(env_value(Kind::OAuth2, &f("refresh_token", "r")).is_none());
    }
}
