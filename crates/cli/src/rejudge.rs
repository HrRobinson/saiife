//! The service's re-judge pool (plan 21): warm `saiife __eval --serve`
//! workers that judge each co-signed Claude Code call again, lexically, as
//! the asking user.
//!
//! - **Who runs them.** The workers are children of the service and run
//!   under its own account: never root (a root service refuses to start
//!   them) and never the agent's user, so code of the agent's user cannot
//!   trace, kill or patch the judgment. Their environment is cleared, and on
//!   Windows they run in a kill-on-close job, so none outlives the service.
//! - **What they judge with.** Each request carries the asking user's path
//!   variables, built from the account record (Unix: `HOME` and `USER` from
//!   the uid's entry; Windows: the SID's `ProfileImagePath`), and the system
//!   policy's packs for that user's scope. The project config is not read: in
//!   locked mode it only adds packs (A18), so the service's judgment is never
//!   stricter than the hook's. The worker judges with `FsView::Lexical` and
//!   makes no file system call.
//! - **Bounds.** At most `REJUDGE_POOL` workers in all, at most
//!   `REJUDGE_PER_PRINCIPAL` requests of one principal judged at once, and at
//!   most `REJUDGE_MAX_WAITING` requests waiting. A request takes its
//!   waiting place before any work is done for it, and gives it up at once
//!   when its co-signed request is gone (`RejudgeRequest.cancel`). A worker
//!   serves `REJUDGE_MAX_USES` requests, then is replaced.
//! - **Failure.** A worker that crashes, hangs past the deadline or answers
//!   badly is killed and reaped, its request is `Failed` (the co-signer
//!   denies), and a new worker takes its place. Nothing a worker does reaches
//!   the service beyond that.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use saiife_daemon::hooks::Principal;
use saiife_daemon::rejudge::{
    Cancel, Rejudge, RejudgeAnswer, RejudgeRequest, REJUDGE_MAX_USES, REJUDGE_MAX_WAITING,
    REJUDGE_PER_PRINCIPAL, REJUDGE_POOL, REJUDGE_TIMEOUT,
};
use saiife_policy::SystemConfig;
use saiifeguard::payload::context_from_hook_json_bounded;

use crate::check_managed::{load_locked, locked_paths, policy_with, Applied, ScopeEnv};
use crate::eval::{
    self, read_frame, write_frame, EvalAnswer, EvalRequest, McpCheck, Verdict, View,
    PARSE_MAX_BYTES,
};

/// The agent whose calls are co-signed.
const AGENT: &str = "claude";

/// The pool's bounds. [`Limits::default`] is the plan's fixed values; tests
/// lower them.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub workers: usize,
    pub per_principal: usize,
    pub waiting: usize,
    pub max_uses: u32,
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            workers: REJUDGE_POOL,
            per_principal: REJUDGE_PER_PRINCIPAL,
            waiting: REJUDGE_MAX_WAITING,
            max_uses: REJUDGE_MAX_USES,
            timeout: REJUDGE_TIMEOUT,
        }
    }
}

/// How a worker is started: a child with its stdin and stdout piped, that
/// speaks the `__eval --serve` frames. Tests start it their own way.
pub trait Launch: Send + Sync {
    fn launch(&self) -> io::Result<Child>;
}

/// The service's own launcher: `<exe> __eval --serve`, under this process's
/// account, with a cleared environment.
pub struct ServiceLaunch {
    exe: PathBuf,
    /// Every worker is in it; closing it (the service ends) kills them.
    #[cfg(windows)]
    job: saiife_win::ffi::job::KillOnClose,
}

impl ServiceLaunch {
    pub fn new(exe: PathBuf) -> io::Result<ServiceLaunch> {
        Ok(ServiceLaunch {
            exe,
            #[cfg(windows)]
            job: saiife_win::ffi::job::KillOnClose::new()?,
        })
    }
}

/// The command a worker is started with: no environment at all, except, on
/// Windows, the machine's `SystemRoot` (some system DLLs need it), and in
/// debug builds the `SAIIFE_EVAL_FAULT` test seam.
fn serve_command(exe: &Path) -> Command {
    let mut cmd = Command::new(exe);
    cmd.args(["__eval", "--serve"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        cmd.env("SystemRoot", root);
    }
    #[cfg(debug_assertions)]
    if let Some(f) = std::env::var_os("SAIIFE_EVAL_FAULT") {
        cmd.env("SAIIFE_EVAL_FAULT", f);
    }
    cmd
}

impl Launch for ServiceLaunch {
    fn launch(&self) -> io::Result<Child> {
        #[cfg(unix)]
        if rustix::process::geteuid().is_root() {
            return Err(io::Error::other("re-judge workers never run as root"));
        }
        #[allow(unused_mut)]
        let mut child = serve_command(&self.exe).spawn()?;
        // A worker that cannot be tied to the service is not run: it could
        // outlive it. It has judged nothing yet.
        #[cfg(windows)]
        if let Err(e) = self.job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        Ok(child)
    }
}

/// The account record of a principal: what its path rules and its scope are
/// built from. Never an environment the agent set.
pub trait Accounts: Send + Sync {
    /// The whole environment a worker judging for `who` reads (no `PATH`:
    /// nothing is looked up on it).
    fn environment(&self, who: &Principal) -> Result<Vec<(String, String)>, String>;
    /// `cfg` with `who`'s scope environment applied.
    fn applied<'a>(&self, cfg: &'a SystemConfig, who: &Principal) -> Result<Applied<'a>, String>;
}

/// This host's accounts: `/etc/passwd` and `/etc/group` (Directory Services
/// on macOS), or the Windows profile list and directory.
pub struct HostAccounts {
    /// Tests: `(passwd, group)` text in place of the host's files.
    #[cfg(unix)]
    files: Option<(String, String)>,
}

impl Default for HostAccounts {
    fn default() -> HostAccounts {
        HostAccounts::new()
    }
}

impl HostAccounts {
    pub fn new() -> HostAccounts {
        HostAccounts {
            #[cfg(unix)]
            files: None,
        }
    }

    /// Accounts from `passwd` and `group` text, with groups from the files
    /// alone (tests).
    #[cfg(all(test, unix))]
    pub fn from_files(passwd: &str, group: &str) -> HostAccounts {
        HostAccounts {
            files: Some((passwd.to_string(), group.to_string())),
        }
    }
}

fn no_record(who: &Principal) -> String {
    format!("no account record for {who:?}")
}

#[cfg(unix)]
impl Accounts for HostAccounts {
    fn environment(&self, who: &Principal) -> Result<Vec<(String, String)>, String> {
        let Principal::Uid(uid) = who else {
            return Err(no_record(who));
        };
        let entry = match &self.files {
            Some((passwd, _)) => saiife_ipc::client::entry_by_uid(passwd, *uid),
            None => saiife_ipc::client::system_entry(*uid),
        }
        .ok_or_else(|| no_record(who))?;
        let home = entry
            .home
            .into_os_string()
            .into_string()
            .map_err(|_| format!("the home of uid {uid} is not UTF-8"))?;
        Ok(vec![
            ("HOME".into(), home),
            ("USER".into(), entry.name),
            ("LANG".into(), "C".into()),
        ])
    }

    fn applied<'a>(&self, cfg: &'a SystemConfig, who: &Principal) -> Result<Applied<'a>, String> {
        let Principal::Uid(uid) = who else {
            return Err(no_record(who));
        };
        match &self.files {
            Some((passwd, group)) => crate::check_managed::hook_env(
                cfg,
                *uid,
                (passwd, group),
                Some("group: files"),
                &saiife_policy::Getent,
            ),
            None => crate::check_managed::uid_env(cfg, *uid),
        }
    }
}

#[cfg(windows)]
impl Accounts for HostAccounts {
    fn environment(&self, who: &Principal) -> Result<Vec<(String, String)>, String> {
        let Principal::Sid(sid) = who else {
            return Err(no_record(who));
        };
        let env = crate::win_locked::environment_of(&saiife_system::host::RealHost, sid)?;
        Ok(env
            .into_iter()
            .filter(|(k, _)| *k != "PATH")
            .map(|(k, v)| (k.to_string(), v))
            .collect())
    }

    fn applied<'a>(&self, cfg: &'a SystemConfig, who: &Principal) -> Result<Applied<'a>, String> {
        let Principal::Sid(sid) = who else {
            return Err(no_record(who));
        };
        let name = saiife_win::ffi::account::lookup_sid(sid)
            .map_err(|e| format!("cannot tell which user {sid} is: {e}"))?;
        saiife_policy::applied_for(cfg, &saiife_policy::WinDirectory::system(), &name)
            .map_err(|e| format!("environment: {e}"))
    }
}

/// [`Accounts::applied`] for one principal, as the hook's policy takes it.
struct PrincipalEnv<'a> {
    accounts: &'a dyn Accounts,
    who: &'a Principal,
}

impl ScopeEnv for PrincipalEnv<'_> {
    fn applied<'a>(&self, cfg: &'a SystemConfig) -> Result<Applied<'a>, String> {
        self.accounts.applied(cfg, self.who)
    }
}

/// A started worker, between requests.
struct Warm {
    child: Child,
    /// Frames for the writer thread; dropping it closes the worker's stdin.
    frames: mpsc::Sender<Vec<u8>>,
    /// The reader thread's frames; an error ends the stream.
    answers: mpsc::Receiver<io::Result<Vec<u8>>>,
    uses: u32,
}

impl Warm {
    fn start(launch: &dyn Launch) -> io::Result<Warm> {
        let mut child = launch.launch()?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("the worker has no pipes"));
        };
        let (frames, to_write) = mpsc::channel::<Vec<u8>>();
        let (read, answers) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("saiife-rejudge-w".into())
            .spawn(move || write_frames(stdin, &to_write))
            .and_then(|_| {
                std::thread::Builder::new()
                    .name("saiife-rejudge-r".into())
                    .spawn(move || read_frames(stdout, &read))
            });
        if let Err(e) = spawned {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        Ok(Warm {
            child,
            frames,
            answers,
            uses: 0,
        })
    }

    /// One request and its answer, by `deadline`. Any error leaves the worker
    /// unusable: the caller kills it.
    fn ask(&mut self, body: Vec<u8>, deadline: Instant) -> Result<EvalAnswer, String> {
        self.uses += 1;
        self.frames
            .send(body)
            .map_err(|_| "the worker is gone".to_string())?;
        let left = deadline.saturating_duration_since(Instant::now());
        let frame = match self.answers.recv_timeout(left) {
            Ok(Ok(frame)) => frame,
            Ok(Err(e)) => return Err(self.ended(&e.to_string())),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err("the worker gave no answer in time".into())
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(self.ended("lost")),
        };
        serde_json::from_slice(&frame).map_err(|_| "the worker's answer is unparsable".into())
    }

    /// Why the worker's output ended: its exit, when it has one already.
    fn ended(&mut self, read: &str) -> String {
        // Its stdout is closed: the exit follows at once.
        let until = Instant::now() + Duration::from_millis(50);
        loop {
            match self.child.try_wait() {
                Ok(Some(st)) => return format!("the worker ended ({st})"),
                Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(1)),
                _ => return format!("the worker's output ended ({read})"),
            }
        }
    }
}

/// A worker is never left behind: dropped, it is killed and reaped.
impl Drop for Warm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_frames(stdin: ChildStdin, frames: &mpsc::Receiver<Vec<u8>>) {
    let mut w = io::BufWriter::new(stdin);
    // A worker that dies closes the pipe: the write fails and this ends.
    for frame in frames {
        if write_frame(&mut w, &frame).is_err() {
            return;
        }
    }
}

fn read_frames(stdout: ChildStdout, answers: &mpsc::Sender<io::Result<Vec<u8>>>) {
    let mut r = io::BufReader::new(stdout);
    loop {
        let got = match read_frame(&mut r) {
            Ok(Some(frame)) => Ok(frame),
            Ok(None) => Err(io::ErrorKind::UnexpectedEof.into()),
            Err(e) => Err(e),
        };
        let last = got.is_err();
        if answers.send(got).is_err() || last {
            return;
        }
    }
}

/// When the system config and its drop-ins were last seen as they are.
type Stamp = Vec<(PathBuf, Option<(SystemTime, u64)>)>;

fn stamp(config: &Path) -> Stamp {
    let seen = |p: &Path| {
        std::fs::symlink_metadata(p)
            .ok()
            .map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()))
    };
    let dropins = config
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("policy.d");
    let mut out = vec![
        (config.to_path_buf(), seen(config)),
        (dropins.clone(), seen(&dropins)),
    ];
    if let Ok(dir) = std::fs::read_dir(&dropins) {
        let mut entries: Vec<PathBuf> = dir.flatten().map(|e| e.path()).collect();
        entries.sort();
        out.extend(entries.into_iter().map(|p| {
            let s = seen(&p);
            (p, s)
        }));
    }
    out
}

#[derive(Default)]
struct State {
    idle: Vec<Warm>,
    /// Workers idle, busy or being started.
    live: usize,
    /// Requests being judged, per principal.
    busy: HashMap<Principal, usize>,
    /// Requests waiting for a worker.
    waiting: usize,
}

/// How often a request waiting for a worker looks at its cancel flag.
const CANCEL_POLL: Duration = Duration::from_millis(20);

/// Why a request whose co-signed request is gone gets no judgment.
const GONE: &str = "the co-signed request is gone";

/// A request's place among the waiting ([`State::waiting`]), given up on
/// drop unless [`Pool::take`] gave it up.
struct Place<'a> {
    pool: &'a Pool,
    held: bool,
}

impl Place<'_> {
    fn leave(&mut self, st: &mut State) {
        if self.held {
            st.waiting = st.waiting.saturating_sub(1);
            self.held = false;
        }
    }
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        if self.held {
            let mut st = self.pool.lock();
            self.leave(&mut st);
        }
    }
}

/// The pool. Blocking: the daemon calls [`Rejudge::judge`] on
/// `spawn_blocking`.
pub struct Pool {
    launch: Box<dyn Launch>,
    accounts: Box<dyn Accounts>,
    config: PathBuf,
    limits: Limits,
    state: Mutex<State>,
    freed: Condvar,
    cached: Mutex<Option<(Stamp, Arc<SystemConfig>)>>,
}

impl Pool {
    /// The service's pool: `exe __eval --serve` workers, judging with the
    /// system config at `cfg_path`, as this host's accounts say.
    pub fn start(exe: PathBuf, cfg_path: PathBuf) -> io::Result<Pool> {
        Pool::with(
            Box::new(ServiceLaunch::new(exe)?),
            Box::new(HostAccounts::new()),
            cfg_path,
            Limits::default(),
        )
    }

    /// A pool with its launcher, accounts and bounds given, its workers
    /// started.
    pub fn with(
        launch: Box<dyn Launch>,
        accounts: Box<dyn Accounts>,
        config: PathBuf,
        limits: Limits,
    ) -> io::Result<Pool> {
        let pool = Pool {
            launch,
            accounts,
            config,
            limits,
            state: Mutex::new(State::default()),
            freed: Condvar::new(),
            cached: Mutex::new(None),
        };
        let mut warm = Vec::new();
        for _ in 0..limits.workers {
            warm.push(Warm::start(pool.launch.as_ref())?);
        }
        let mut st = pool.lock();
        st.live = warm.len();
        st.idle = warm;
        drop(st);
        Ok(pool)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The system config, loaded again when it or a drop-in changed.
    fn system_config(&self) -> Result<Arc<SystemConfig>, String> {
        let now = stamp(&self.config);
        let mut cached = self.cached.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((seen, cfg)) = cached.as_ref() {
            if *seen == now {
                return Ok(cfg.clone());
            }
        }
        let cfg = Arc::new(load_locked(&self.config)?);
        *cached = Some((now, cfg.clone()));
        Ok(cfg)
    }

    /// The request the worker gets, or the answer without one.
    fn prepare(&self, req: &RejudgeRequest) -> Result<EvalRequest, RejudgeAnswer> {
        let failed = |why: String| RejudgeAnswer::Failed(why);
        let payload = std::str::from_utf8(&req.payload)
            .map_err(|_| failed("the request body is not UTF-8".into()))?;
        let cfg = self
            .system_config()
            .map_err(|e| failed(format!("the system policy cannot be loaded ({e})")))?;
        let who = PrincipalEnv {
            accounts: self.accounts.as_ref(),
            who: &req.principal,
        };
        // No project: its config is not read here.
        let (packs, _hash) = policy_with(&cfg, None, &who)
            .map_err(|e| failed(format!("the policy for this call is unavailable ({e})")))?;
        let vars = self
            .accounts
            .environment(&req.principal)
            .map_err(|e| failed(format!("the asking user's paths are unknown ({e})")))?;
        if let Some(answer) = mcp_answer(payload, &cfg) {
            return Err(answer);
        }
        Ok(EvalRequest {
            payload: payload.to_string(),
            packs,
            budget_ms: cfg.guard.budget_ms,
            locked: Some(locked_paths(&cfg, &self.config)),
            event: None,
            ask: cfg.guard.ask.clone(),
            agent: Some(AGENT.to_string()),
            view: View::Lexical,
            vars: Some(vars),
        })
    }

    /// A place among the waiting, or `Err` when [`Limits::waiting`] are
    /// waiting already. Taken before any work is done for a request.
    fn enter(&self) -> Result<Place<'_>, String> {
        let mut st = self.lock();
        if st.waiting >= self.limits.waiting {
            return Err("too many calls are waiting to be judged".into());
        }
        st.waiting += 1;
        Ok(Place {
            pool: self,
            held: true,
        })
    }

    /// Waits in `place` for a worker `who` may use, by `deadline`, unless
    /// `cancel` is set first. `Ok(None)`: none is idle, and one may be
    /// started.
    fn take(
        &self,
        mut place: Place<'_>,
        who: &Principal,
        deadline: Instant,
        cancel: &Cancel,
    ) -> Result<Option<Warm>, String> {
        let mut st = self.lock();
        loop {
            if cancel.is_cancelled() {
                place.leave(&mut st);
                return Err(GONE.into());
            }
            let mine = st.busy.get(who).copied().unwrap_or(0);
            let free = !st.idle.is_empty() || st.live < self.limits.workers;
            if mine < self.limits.per_principal && free {
                place.leave(&mut st);
                *st.busy.entry(who.clone()).or_insert(0) += 1;
                return Ok(match st.idle.pop() {
                    Some(w) => Some(w),
                    None => {
                        st.live += 1;
                        None
                    }
                });
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                place.leave(&mut st);
                return Err("no worker was free in time".into());
            }
            st = self
                .freed
                .wait_timeout(st, left.min(CANCEL_POLL))
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// Gives back `who`'s turn and, unless it is spent or failed, the worker.
    /// A worker that is not given back is replaced.
    fn give_back(&self, who: &Principal, worker: Option<Warm>) {
        let keep = worker.filter(|w| w.uses < self.limits.max_uses);
        let mut st = self.lock();
        if let Some(n) = st.busy.get_mut(who) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.busy.remove(who);
            }
        }
        match keep {
            Some(w) => st.idle.push(w),
            None => st.live = st.live.saturating_sub(1),
        }
        let refill = st.live < self.limits.workers;
        if refill {
            st.live += 1;
        }
        drop(st);
        if refill {
            let started = Warm::start(self.launch.as_ref());
            let mut st = self.lock();
            match started {
                Ok(w) => st.idle.push(w),
                Err(_) => st.live = st.live.saturating_sub(1),
            }
        }
        self.freed.notify_all();
    }
}

/// A Claude Code MCP call judged against the system's `[guard.mcp]
/// allow_servers`, without the hook's pin check (it reads a file): `None` when
/// the guard judges it.
fn mcp_answer(payload: &str, cfg: &SystemConfig) -> Option<RejudgeAnswer> {
    let ctx = context_from_hook_json_bounded(payload, PARSE_MAX_BYTES);
    let tool = ctx.tool.as_deref()?;
    let deny = |reason: String| RejudgeAnswer::Deny {
        reason,
        pack: None,
        rule: None,
        input: tool.to_string(),
        askable: false,
    };
    match eval::mcp_check_pinned(
        AGENT,
        tool,
        &eval::mcp_identity(payload),
        &cfg.guard.mcp.allow_servers,
        &|| true,
    ) {
        McpCheck::NotMcp | McpCheck::Allowed => None,
        McpCheck::Brokered => Some(RejudgeAnswer::Allow),
        McpCheck::Denied(s) => Some(deny(format!(
            "MCP server {s} is not in [guard.mcp] allow_servers"
        ))),
        McpCheck::Unknown => Some(deny("MCP server unknown".into())),
    }
}

/// The worker's answer as the co-signer takes it. A call the guard could not
/// judge is `Failed`: the service has no judgment of it.
fn from_answer(a: EvalAnswer) -> RejudgeAnswer {
    match a.verdict {
        Verdict::Allow => RejudgeAnswer::Allow,
        Verdict::Deny => RejudgeAnswer::Deny {
            reason: a.reason.unwrap_or_default(),
            pack: a.pack,
            rule: a.rule,
            input: a.input,
            askable: a.askable,
        },
        Verdict::Unjudged => RejudgeAnswer::Failed(format!(
            "the guard could not judge it ({})",
            a.reason.unwrap_or_default()
        )),
    }
}

impl Rejudge for Pool {
    fn workers(&self) -> usize {
        self.lock().live
    }

    fn judge(&self, req: RejudgeRequest) -> RejudgeAnswer {
        let deadline = req.deadline.min(Instant::now() + self.limits.timeout);
        if req.cancel.is_cancelled() {
            return RejudgeAnswer::Failed(GONE.into());
        }
        // The waiting cap is checked before the request is built.
        let place = match self.enter() {
            Ok(p) => p,
            Err(why) => return RejudgeAnswer::Failed(why),
        };
        let eval = match self.prepare(&req) {
            Ok(eval) => eval,
            Err(answer) => return answer,
        };
        let Ok(body) = serde_json::to_vec(&eval) else {
            return RejudgeAnswer::Failed("the request cannot be written".into());
        };
        drop(eval);
        let who = &req.principal;
        let mut worker = match self.take(place, who, deadline, &req.cancel) {
            Ok(Some(w)) => w,
            Ok(None) => match Warm::start(self.launch.as_ref()) {
                Ok(w) => w,
                Err(e) => {
                    // Frees the slot `take` reserved, and tries once more for the pool.
                    self.give_back(who, None);
                    return RejudgeAnswer::Failed(format!("no worker could be started ({e})"));
                }
            },
            Err(why) => return RejudgeAnswer::Failed(why),
        };
        if req.cancel.is_cancelled() {
            self.give_back(who, Some(worker));
            return RejudgeAnswer::Failed(GONE.into());
        }
        match worker.ask(body, deadline) {
            Ok(answer) => {
                self.give_back(who, Some(worker));
                from_answer(answer)
            }
            Err(why) => {
                // Killed and reaped before the turn is given back.
                drop(worker);
                self.give_back(who, None);
                RejudgeAnswer::Failed(why)
            }
        }
    }
}

/// The re-judge for `saiife daemon --system`, or `None` (with the reason on
/// stderr) when it cannot be started: the co-signer then denies every call.
pub fn for_system_daemon(config: &Path) -> Option<Arc<dyn Rejudge>> {
    let started = std::env::current_exe().and_then(|exe| Pool::start(exe, config.to_path_buf()));
    match started {
        Ok(pool) => Some(Arc::new(pool)),
        Err(e) => {
            crate::warn(&format!(
                "the re-judge pool cannot start ({e}); every co-signed call is denied"
            ));
            None
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use saiife_daemon::rejudge::Bytes;

    /// The `saiife` binary of this build, next to the test binary's `deps`.
    fn saiife_exe() -> PathBuf {
        let me = std::env::current_exe().unwrap();
        let exe = me
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .join(format!("saiife{}", std::env::consts::EXE_SUFFIX));
        assert!(
            exe.is_file(),
            "{} is missing: `cargo test -p saiife` builds it",
            exe.display()
        );
        exe
    }

    /// The real worker binary, with `SAIIFE_EVAL_FAULT=fault` on the
    /// launches `faulty` names (counted from 0).
    struct TestLaunch {
        exe: PathBuf,
        faulty: Vec<(usize, &'static str)>,
        launched: AtomicUsize,
        pids: Mutex<Vec<u32>>,
    }

    impl TestLaunch {
        fn new(faulty: Vec<(usize, &'static str)>) -> Arc<TestLaunch> {
            Arc::new(TestLaunch {
                exe: saiife_exe(),
                faulty,
                launched: AtomicUsize::new(0),
                pids: Mutex::new(Vec::new()),
            })
        }
        fn launched(&self) -> usize {
            self.launched.load(Ordering::SeqCst)
        }
    }

    impl Launch for Arc<TestLaunch> {
        fn launch(&self) -> io::Result<Child> {
            let n = self.launched.fetch_add(1, Ordering::SeqCst);
            let mut cmd = serve_command(&self.exe);
            cmd.env_remove("SAIIFE_EVAL_FAULT");
            if let Some((_, f)) = self.faulty.iter().find(|(i, _)| *i == n) {
                cmd.env("SAIIFE_EVAL_FAULT", f);
            }
            let child = cmd.spawn()?;
            self.pids.lock().unwrap().push(child.id());
            Ok(child)
        }
    }

    const PASSWD: &str =
        "me:x:4242:4242::/home/other:/bin/sh\nstrict:x:4343:4343::/home/strict:/bin/sh\n";
    const GROUP: &str = "me:x:4242:\nstrict:x:4343:\n";

    struct Setup {
        dir: tempfile::TempDir,
    }

    impl Setup {
        fn new(extra: &str) -> Setup {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join("etc")).unwrap();
            let text = format!(
                "version = 2\nlocked = true\n\n[daemon]\nuser = \"me\"\nsocket_dir = {:?}\n\n[audit]\ndir = {:?}\n\n{extra}",
                dir.path().join("run").display().to_string(),
                dir.path().join("audit").display().to_string(),
            );
            std::fs::write(dir.path().join("etc/config.toml"), text).unwrap();
            Setup { dir }
        }
        fn config(&self) -> PathBuf {
            self.dir.path().join("etc/config.toml")
        }
        fn pool(&self, launch: &Arc<TestLaunch>, limits: Limits) -> Pool {
            Pool::with(
                Box::new(launch.clone()),
                Box::new(HostAccounts::from_files(PASSWD, GROUP)),
                self.config(),
                limits,
            )
            .unwrap()
        }
    }

    fn fixture(name: &str) -> String {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/claude")
            .join(name);
        std::fs::read_to_string(p).unwrap()
    }

    fn bash(cwd: &str, command: &str) -> String {
        serde_json::json!({
            "session_id": "c-1", "cwd": cwd, "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": command}, "tool_use_id": "toolu_01"
        })
        .to_string()
    }

    fn ask(pool: &Pool, uid: u32, payload: &str) -> RejudgeAnswer {
        ask_by(pool, uid, payload, Instant::now() + Duration::from_secs(10))
    }

    fn ask_by(pool: &Pool, uid: u32, payload: &str, deadline: Instant) -> RejudgeAnswer {
        pool.judge(RejudgeRequest {
            payload: Bytes::from(payload.to_string()),
            principal: Principal::Uid(uid),
            groups: Vec::new(),
            deadline,
            cancel: Cancel::new(),
        })
    }

    fn one() -> Limits {
        Limits {
            workers: 1,
            ..Limits::default()
        }
    }

    #[test]
    fn allow_fixture_allows() {
        let s = Setup::new("");
        let pool = s.pool(&TestLaunch::new(vec![]), Limits::default());
        assert_eq!(pool.workers(), REJUDGE_POOL);
        assert_eq!(
            ask(&pool, 4242, &fixture("bash-allow.json")),
            RejudgeAnswer::Allow
        );
    }

    #[test]
    fn deny_fixture_denies_with_the_rule() {
        let s = Setup::new("");
        let pool = s.pool(&TestLaunch::new(vec![]), one());
        let payload = fixture("bash-deny.json");
        // The hook's own answer: the same packs, judged on the host.
        let cfg = load_locked(&s.config()).unwrap();
        let hook = eval::judge_with(
            &payload,
            &cfg.guard.packs,
            Duration::from_millis(cfg.guard.budget_ms),
            None,
            &[],
            Some("claude"),
        );
        assert_eq!(hook.verdict, Verdict::Deny);
        match ask(&pool, 4242, &payload) {
            RejudgeAnswer::Deny {
                pack, rule, input, ..
            } => {
                assert_eq!((pack, rule), (hook.pack, hook.rule));
                assert_eq!(input, "rm -rf /");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn vars_come_from_the_principal_record() {
        let s = Setup::new("");
        let pool = s.pool(&TestLaunch::new(vec![]), one());
        // uid 4242's record says /home/other: `~` is that home. The rule
        // named here is anchored at `~` (core.secrets).
        for cmd in [
            "cat /home/other/.claude/.credentials.json",
            "cat ~/.claude/.credentials.json",
            "cat ~/.ssh/id_rsa",
        ] {
            assert!(
                matches!(
                    ask(&pool, 4242, &bash("/home/other/app", cmd)),
                    RejudgeAnswer::Deny { .. }
                ),
                "{cmd}"
            );
        }
        // Another user's home is not uid 4242's `~`; for uid 4343 it is.
        let theirs = bash("/tmp", "cat /home/strict/.claude/.credentials.json");
        assert_eq!(ask(&pool, 4242, &theirs), RejudgeAnswer::Allow);
        assert!(matches!(
            ask(&pool, 4343, &theirs),
            RejudgeAnswer::Deny { .. }
        ));
        // No record, no judgment.
        assert!(matches!(
            ask(&pool, 99, &fixture("bash-allow.json")),
            RejudgeAnswer::Failed(_)
        ));
    }

    #[test]
    fn scope_packs_follow_the_principal() {
        let s = Setup::new(
            "[environments.strict.guard]\npacks = [\"container.docker\"]\n\n\
             [environments.loose.guard]\npacks = []\n\n\
             [[scope]]\nname = \"strict\"\nusers = [\"strict\"]\nenv = \"strict\"\n\n\
             [[scope]]\nname = \"loose\"\nusers = [\"me\"]\nenv = \"loose\"\n",
        );
        let pool = s.pool(&TestLaunch::new(vec![]), one());
        let payload = bash("/tmp", "docker volume rm data");
        assert_eq!(ask(&pool, 4242, &payload), RejudgeAnswer::Allow);
        match ask(&pool, 4343, &payload) {
            RejudgeAnswer::Deny { pack, .. } => {
                assert_eq!(pack.as_deref(), Some("container.docker"))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn project_config_is_not_read() {
        let s = Setup::new("");
        let project = s.dir.path().join("proj");
        std::fs::create_dir_all(project.join(".saiife")).unwrap();
        std::fs::write(
            project.join(".saiife/config.toml"),
            "[guard]\npacks = [\"container.docker\"]\n",
        )
        .unwrap();
        let pool = s.pool(&TestLaunch::new(vec![]), one());
        let payload = bash(project.to_str().unwrap(), "docker volume rm data");
        // The hook, which reads the project config, denies it.
        let packs = load_locked(&s.config()).unwrap().guard.packs;
        let mut with_project = packs.clone();
        with_project.push("container.docker".into());
        let hook = eval::judge_with(
            &payload,
            &with_project,
            Duration::from_secs(1),
            None,
            &[],
            Some("claude"),
        );
        assert_eq!(hook.verdict, Verdict::Deny);
        // The pool judges with the system packs alone.
        assert_eq!(ask(&pool, 4242, &payload), RejudgeAnswer::Allow);
        // And its preparation opens nothing under the project: the request
        // has no project and the guard's view is lexical.
        let req = pool
            .prepare(&RejudgeRequest {
                payload: Bytes::from(payload.clone()),
                principal: Principal::Uid(4242),
                groups: Vec::new(),
                deadline: Instant::now() + Duration::from_secs(5),
                cancel: Cancel::new(),
            })
            .unwrap();
        assert_eq!(req.view, View::Lexical);
        assert!(!req.packs.contains(&"container.docker".to_string()));
        let before = saiifeguard::canon::fs_calls_made();
        let answer = eval::answer(&req, None);
        assert_eq!(saiifeguard::canon::fs_calls_made(), before);
        assert_eq!(answer.verdict, Verdict::Allow);
    }

    #[test]
    fn crashed_worker_is_replaced() {
        let s = Setup::new("");
        let launch = TestLaunch::new(vec![(0, "abort")]);
        let pool = s.pool(&launch, one());
        let payload = fixture("bash-allow.json");
        assert!(matches!(
            ask(&pool, 4242, &payload),
            RejudgeAnswer::Failed(_)
        ));
        assert_eq!(launch.launched(), 2, "replaced at once");
        assert_eq!(pool.workers(), 1);
        assert_eq!(ask(&pool, 4242, &payload), RejudgeAnswer::Allow);
    }

    #[test]
    fn hung_worker_times_out() {
        let s = Setup::new("");
        let launch = TestLaunch::new(vec![(0, "hang")]);
        let pool = s.pool(&launch, one());
        let payload = fixture("bash-allow.json");
        let start = Instant::now();
        let answer = ask_by(&pool, 4242, &payload, start + Duration::from_millis(700));
        let took = start.elapsed();
        assert!(matches!(answer, RejudgeAnswer::Failed(_)), "{answer:?}");
        assert!(took >= Duration::from_millis(700), "{took:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
        // The hung worker was killed and reaped.
        let hung = launch.pids.lock().unwrap()[0];
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{hung}")).exists());
        let _ = hung;
        assert_eq!(ask(&pool, 4242, &payload), RejudgeAnswer::Allow);
    }

    #[test]
    fn worker_is_replaced_after_max_uses() {
        let s = Setup::new("");
        let launch = TestLaunch::new(vec![]);
        let pool = s.pool(
            &launch,
            Limits {
                max_uses: 3,
                ..one()
            },
        );
        let payload = fixture("bash-allow.json");
        for _ in 0..7 {
            assert_eq!(ask(&pool, 4242, &payload), RejudgeAnswer::Allow);
        }
        // Workers 1 and 2 served 3 each; the third serves the 7th.
        assert_eq!(launch.launched(), 3);
        assert_eq!(pool.workers(), 1);
    }

    #[test]
    fn mcp_tool_uses_the_system_allow_list() {
        let payload = fixture("mcp-tool.json");
        let unlisted = Setup::new("");
        let pool = unlisted.pool(&TestLaunch::new(vec![]), one());
        match ask(&pool, 4242, &payload) {
            RejudgeAnswer::Deny { reason, .. } => assert!(reason.contains("docs"), "{reason}"),
            other => panic!("{other:?}"),
        }
        let listed = Setup::new("[guard.mcp]\nallow_servers = [\"docs\"]\n");
        let pool = listed.pool(&TestLaunch::new(vec![]), one());
        assert_eq!(ask(&pool, 4242, &payload), RejudgeAnswer::Allow);
    }

    /// Waits until `cond` holds of the pool's state. The bound only stops a
    /// hung test; it is never a test of speed.
    fn wait_for_state(pool: &Pool, cond: impl Fn(&State) -> bool) {
        let guard = Instant::now() + Duration::from_secs(120);
        while !cond(&pool.lock()) {
            assert!(Instant::now() < guard, "the pool never got there");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// One principal's calls are judged `REJUDGE_PER_PRINCIPAL` at once
    /// (parallel sessions of one user are not serialized), and never on
    /// every worker: another user's call is judged while they run, and the
    /// principal's next call waits for its own share.
    #[test]
    fn one_principal_takes_its_share_and_no_more() {
        let s = Setup::new("");
        // Workers are taken last started first: the three taken first hang.
        let launch = TestLaunch::new(vec![(1, "hang"), (2, "hang"), (3, "hang")]);
        // The hung calls hold their workers to their deadline: long enough
        // for the checks below on a loaded host.
        let hold = Duration::from_secs(8);
        let limits = Limits {
            timeout: hold,
            ..Limits::default()
        };
        let pool = Arc::new(s.pool(&launch, limits));
        assert_eq!(pool.workers(), REJUDGE_POOL);
        let payload = fixture("bash-allow.json");
        let hung: Vec<_> = (0..REJUDGE_PER_PRINCIPAL)
            .map(|_| {
                let (pool, payload) = (pool.clone(), payload.clone());
                std::thread::spawn(move || ask_by(&pool, 4242, &payload, Instant::now() + hold))
            })
            .collect();
        // All of uid 4242's calls are judged at once.
        wait_for_state(&pool, |st| {
            st.busy.get(&Principal::Uid(4242)) == Some(&REJUDGE_PER_PRINCIPAL)
        });
        // Another user's call still finds a worker.
        assert_eq!(ask(&pool, 4343, &payload), RejudgeAnswer::Allow);
        // Uid 4242's next call waits for its share, not for a free worker.
        let cancel = Cancel::new();
        let next = {
            let (pool, payload, cancel) = (pool.clone(), payload.clone(), cancel.clone());
            std::thread::spawn(move || {
                pool.judge(RejudgeRequest {
                    payload: Bytes::from(payload),
                    principal: Principal::Uid(4242),
                    groups: Vec::new(),
                    deadline: Instant::now() + Duration::from_secs(60),
                    cancel,
                })
            })
        };
        wait_for_state(&pool, |st| st.waiting == 1);
        {
            let st = pool.lock();
            assert!(!st.idle.is_empty(), "a worker is free all the same");
            assert_eq!(st.busy[&Principal::Uid(4242)], REJUDGE_PER_PRINCIPAL);
        }
        cancel.cancel();
        assert_eq!(next.join().unwrap(), RejudgeAnswer::Failed(GONE.into()));
        for h in hung {
            assert!(matches!(h.join().unwrap(), RejudgeAnswer::Failed(_)));
        }
    }

    /// Whole-branch review, F1: a full queue fails before any work is done
    /// for the request (here a body that is not UTF-8 is never looked at).
    #[test]
    fn a_full_queue_fails_before_the_request_is_built() {
        let s = Setup::new("");
        let pool = s.pool(
            &TestLaunch::new(vec![]),
            Limits {
                waiting: 0,
                ..one()
            },
        );
        let answer = pool.judge(RejudgeRequest {
            payload: Bytes::from_static(b"\xff"),
            principal: Principal::Uid(4242),
            groups: Vec::new(),
            deadline: Instant::now() + Duration::from_secs(5),
            cancel: Cancel::new(),
        });
        assert!(
            matches!(answer, RejudgeAnswer::Failed(ref w) if w.contains("waiting")),
            "{answer:?}"
        );
    }

    /// A request whose co-signed request is gone takes no place and starts
    /// nothing.
    #[test]
    fn a_cancelled_request_is_not_judged() {
        let s = Setup::new("");
        let launch = TestLaunch::new(vec![]);
        let pool = s.pool(&launch, one());
        let cancel = Cancel::new();
        cancel.cancel();
        let answer = pool.judge(RejudgeRequest {
            payload: Bytes::from(fixture("bash-allow.json")),
            principal: Principal::Uid(4242),
            groups: Vec::new(),
            deadline: Instant::now() + Duration::from_secs(5),
            cancel,
        });
        assert_eq!(answer, RejudgeAnswer::Failed(GONE.into()));
        assert_eq!(launch.launched(), 1);
        assert_eq!(pool.lock().waiting, 0);
        assert!(pool.lock().busy.is_empty());
    }

    /// A request waiting for a worker leaves as soon as its co-signed
    /// request is gone, long before its deadline, and gives up its place.
    #[test]
    fn a_request_gone_while_waiting_leaves_at_once() {
        let s = Setup::new("");
        let launch = TestLaunch::new(vec![(0, "hang")]);
        let pool = Arc::new(s.pool(&launch, one()));
        let payload = fixture("bash-allow.json");
        let hung = {
            let (pool, payload) = (pool.clone(), payload.clone());
            std::thread::spawn(move || {
                ask_by(
                    &pool,
                    4242,
                    &payload,
                    Instant::now() + Duration::from_secs(2),
                )
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        let cancel = Cancel::new();
        let waiter = {
            let (pool, cancel) = (pool.clone(), cancel.clone());
            std::thread::spawn(move || {
                let start = Instant::now();
                let answer = pool.judge(RejudgeRequest {
                    payload: Bytes::from(payload),
                    principal: Principal::Uid(4343),
                    groups: Vec::new(),
                    deadline: start + Duration::from_secs(10),
                    cancel,
                });
                (answer, start.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(pool.lock().waiting, 1);
        cancel.cancel();
        let (answer, took) = waiter.join().unwrap();
        assert_eq!(answer, RejudgeAnswer::Failed(GONE.into()));
        assert!(took < Duration::from_secs(1), "{took:?}");
        assert_eq!(pool.lock().waiting, 0);
        assert!(matches!(hung.join().unwrap(), RejudgeAnswer::Failed(_)));
    }

    #[test]
    fn the_config_is_loaded_again_when_it_changes() {
        let s = Setup::new("");
        let pool = s.pool(&TestLaunch::new(vec![]), one());
        let payload = bash("/tmp", "docker volume rm data");
        assert_eq!(ask(&pool, 4242, &payload), RejudgeAnswer::Allow);
        let text = std::fs::read_to_string(s.config()).unwrap();
        // A longer file: the stamp changes even within one mtime tick.
        let text = text.replace(
            "[daemon]",
            "[guard]\npacks = [\"container.docker\"]\n\n[daemon]",
        );
        std::fs::write(s.config(), text).unwrap();
        assert!(matches!(
            ask(&pool, 4242, &payload),
            RejudgeAnswer::Deny { .. }
        ));
    }

    /// What one burst of `n` calls of one principal got: each allowed
    /// call's time from its start to its answer, and the calls refused.
    struct Burst {
        took: Vec<Duration>,
        refused: Vec<RejudgeAnswer>,
    }

    /// `n` calls of uid 4242 at once (a barrier), each with the co-signer's
    /// own deadline, `REJUDGE_TIMEOUT` from its start.
    fn burst(pool: &Arc<Pool>, n: usize, payload: &str) -> Burst {
        let gate = Arc::new(std::sync::Barrier::new(n));
        let calls: Vec<_> = (0..n)
            .map(|_| {
                let (pool, gate, payload) = (pool.clone(), gate.clone(), payload.to_string());
                std::thread::spawn(move || {
                    gate.wait();
                    let start = Instant::now();
                    let answer = ask_by(&pool, 4242, &payload, start + REJUDGE_TIMEOUT);
                    (start.elapsed(), answer)
                })
            })
            .collect();
        let mut out = Burst {
            took: Vec::new(),
            refused: Vec::new(),
        };
        for c in calls {
            let (took, answer) = c.join().unwrap();
            if answer == RejudgeAnswer::Allow {
                out.took.push(took);
            } else {
                out.refused.push(answer);
            }
        }
        out
    }

    fn pct(sorted: &[Duration], p: usize) -> Duration {
        sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
    }

    /// The numbers behind the pool's bounds: bursts of `n` calls of one
    /// principal (parallel Claude Code sessions of one user), each allowed
    /// call's wait over the median of a lone call, and the calls refused.
    /// Prints, asserts nothing on the clock. `RJ_SIZES=4/3,2/1` names the
    /// pool sizes (workers/per principal; default the fixed values). Run with
    /// `cargo test -p saiife --bin saiife rejudge::tests::measure_bursts -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement: prints the numbers, asserts nothing"]
    fn measure_bursts() {
        let s = Setup::new("");
        let payload = fixture("bash-allow.json");
        let rounds = 20;
        let sizes: Vec<(usize, usize)> = std::env::var("RJ_SIZES")
            .unwrap_or_else(|_| format!("{REJUDGE_POOL}/{REJUDGE_PER_PRINCIPAL}"))
            .split(',')
            .filter_map(|p| p.split_once('/'))
            .map(|(w, p)| (w.parse().unwrap(), p.parse().unwrap()))
            .collect();
        for (workers, per_principal) in sizes {
            let limits = Limits {
                workers,
                per_principal,
                ..Limits::default()
            };
            let pool = Arc::new(s.pool(&TestLaunch::new(vec![]), limits));
            // Warm: the config cache and every worker's first judgment.
            for _ in 0..4 {
                burst(&pool, workers, &payload);
            }
            let mut lone: Vec<Duration> = (0..rounds * 4)
                .flat_map(|_| burst(&pool, 1, &payload).took)
                .collect();
            lone.sort();
            let base = pct(&lone, 50);
            println!(
                "\nworkers {workers}, per principal {per_principal}, waiting {}: lone call p50 {base:.1?}, p95 {:.1?}",
                limits.waiting,
                pct(&lone, 95)
            );
            println!("| N | allowed | p50 wait | p95 wait | max wait | refused |");
            println!("|---|---|---|---|---|---|");
            for n in [1, 4, 8, 16, 32, 48, 64, 96] {
                let mut wait = Vec::new();
                let mut refused = Vec::new();
                for _ in 0..rounds {
                    let b = burst(&pool, n, &payload);
                    wait.extend(b.took.iter().map(|t| t.saturating_sub(base)));
                    refused.extend(b.refused);
                }
                wait.sort();
                let mut why: Vec<String> = refused
                    .iter()
                    .map(|a| match a {
                        RejudgeAnswer::Failed(w) => w.clone(),
                        other => format!("{other:?}"),
                    })
                    .collect();
                why.sort();
                why.dedup();
                println!(
                    "| {n} | {} | {:.1?} | {:.1?} | {:.1?} | {} {why:?} |",
                    wait.len(),
                    pct(&wait, 50),
                    pct(&wait, 95),
                    wait[wait.len() - 1],
                    refused.len(),
                );
            }
        }
    }

    #[test]
    fn the_service_launcher_clears_the_environment() {
        let cmd = serve_command(Path::new("/x/saiife"));
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, ["__eval", "--serve"]);
        let set: Vec<_> = cmd
            .get_envs()
            .filter(|(k, v)| v.is_some() && *k != "SAIIFE_EVAL_FAULT")
            .collect();
        assert!(set.is_empty(), "{set:?}");
    }

    /// The hook judges with `PATH=/usr/bin:/bin` (`check_managed::account_env`), the
    /// re-judgment with no `PATH` at all. The only thing read from `PATH` is the
    /// `saiife` on it, an extra `$SAIIFE_BIN` value (`paths::path_vars_locked_env`): the
    /// guard expands no `$PATH` in a command and looks no command name up, so
    /// `command -v`, `which` and `$PATH` judge the same, and a write to the binary
    /// both judges run is denied by both. The hook can only deny more (a `saiife`
    /// on its `PATH` that is another file), never allow more, so the co-signer
    /// never denies an honest call the hook allowed.
    #[test]
    fn path_does_not_split_the_hook_and_the_rejudgment() {
        use std::os::unix::fs::PermissionsExt;
        let s = Setup::new("");
        let pool = s.pool(&TestLaunch::new(vec![]), one());
        // Another `saiife` the hook's `PATH` could find first.
        let bin = s.dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let other = bin.join("saiife");
        std::fs::write(&other, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
        let other = other.display().to_string();
        // Both judges run in one binary, as the hook and the service do in
        // locked mode (`/opt/saiife/bin/saiife`).
        let exe = std::env::current_exe().unwrap().display().to_string();
        let prepare = |command: &str| {
            pool.prepare(&RejudgeRequest {
                payload: Bytes::from(bash("/home/other/app", command)),
                principal: Principal::Uid(4242),
                groups: Vec::new(),
                deadline: Instant::now() + Duration::from_secs(5),
                cancel: Cancel::new(),
            })
            .unwrap()
        };
        let verdict = |req: &EvalRequest| eval::answer(req, None).verdict;
        // The hook's request: the re-judgment's, with `PATH` added.
        let with_path = |command: &str, path: &str, view: View| {
            let mut req = prepare(command);
            let vars = req.vars.as_mut().unwrap();
            assert!(vars.iter().all(|(k, _)| k != "PATH"), "{vars:?}");
            vars.push(("PATH".into(), path.into()));
            req.view = view;
            req
        };
        let system = "/usr/bin:/bin".to_string();
        let shadowed = format!("{}:/usr/bin:/bin", bin.display());
        // (command, the verdict both judges give)
        let same: Vec<(String, Verdict)> = [
            ("saiife status", Verdict::Allow),
            ("saiife audit verify", Verdict::Allow),
            (&format!("{exe} status"), Verdict::Allow),
            ("/opt/saiife/bin/saiife status", Verdict::Allow),
            ("command -v saiife", Verdict::Allow),
            ("which saiife", Verdict::Allow),
            ("type -p saiife", Verdict::Allow),
            ("echo $PATH", Verdict::Allow),
            ("printenv PATH", Verdict::Allow),
            ("ls $(dirname $(command -v saiife))", Verdict::Allow),
            ("export PATH=$PATH:/home/other/.local/bin", Verdict::Allow),
            ("PATH=$PATH:/home/other/bin cargo build", Verdict::Allow),
            ("$(command -v saiife) status", Verdict::Allow),
            ("saiife init --off", Verdict::Deny),
            ("/opt/saiife/bin/saiife init --off", Verdict::Deny),
            ("/usr/bin/saiife init --off", Verdict::Deny),
            // A command word that may expand to saiife is judged as saiife
            // by both (the same text, the same answer).
            ("$(which saiife) init --off", Verdict::Deny),
            ("PATH=/home/other/bin saiife status", Verdict::Deny),
            ("PATH=$PATH claude", Verdict::Deny),
            (&format!("rm {exe}"), Verdict::Deny),
            (&format!("cp /home/other/x {exe}"), Verdict::Deny),
        ]
        .into_iter()
        .map(|(c, v)| (c.to_string(), v))
        .collect();
        for (command, want) in &same {
            let req = prepare(command);
            assert_eq!(verdict(&req), *want, "re-judge: {command}");
            for path in [&system, &shadowed] {
                for view in [View::Lexical, View::Host] {
                    let hook = with_path(command, path, view);
                    assert_eq!(verdict(&hook), *want, "hook ({path}, {view:?}): {command}");
                }
            }
        }
        // The worker answers as judged here.
        for (command, want) in same.iter().filter(|(c, _)| !c.contains(&exe)) {
            let got = ask(&pool, 4242, &bash("/home/other/app", command));
            let allowed = got == RejudgeAnswer::Allow;
            assert_eq!(
                allowed,
                *want == Verdict::Allow,
                "worker: {command}: {got:?}"
            );
        }
        // Where `PATH` finds another `saiife`, only the hook guards it: the
        // co-signed call is denied, the hook's own answer.
        for command in [format!("rm {other}"), format!("cp /home/other/x {other}")] {
            let req = prepare(&command);
            assert_eq!(verdict(&req), Verdict::Allow, "re-judge: {command}");
            let hook = with_path(&command, &shadowed, View::Lexical);
            assert_eq!(verdict(&hook), Verdict::Deny, "hook: {command}");
            let hook = with_path(&command, &system, View::Lexical);
            assert_eq!(
                verdict(&hook),
                Verdict::Allow,
                "hook, system PATH: {command}"
            );
        }
    }
}
