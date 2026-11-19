//! The init's main loop: control.sock (host requests, one per connection) and
//! local.sock (in-guest helpers, one event per connection), and the agent.
#![cfg(target_os = "linux")]

use crate::env::{agent_env, GuestEnv, AGENT_ENV_FILE, SETUP_MARKER, WORK};
use crate::events::{self, DeadlineReader, Note, Signals};
use crate::pty;
use crate::setup;
use saiife_boxproto::frame::{read_msg, write_msg, FrameError};
use saiife_boxproto::msg::{Event, Reply, Request, Setup};
use saiife_boxproto::ports::{GUEST_CONTROL_SOCK, GUEST_LOCAL_SOCK, GUEST_SOCK_DIR};
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A local.sock event is one small frame.
const LOCAL_MAX: u64 = 4 * 1024;
/// At most this many local.sock connections are read at once; more are dropped.
const LOCAL_CONCURRENCY: usize = 16;
/// Typed text waiting for the PTY; a full queue means the agent is not reading.
const TYPE_QUEUE: usize = 64;
/// How long the agent's waiter lets the pump drain after the exit.
const DRAIN: Duration = Duration::from_secs(1);
/// How often the control loop looks for a fatal error while idle.
const IDLE: Duration = Duration::from_millis(50);

/// The running agent.
struct Agent {
    id: u64,
    master: Arc<OwnedFd>,
    typer: SyncSender<Vec<u8>>,
}

struct Init {
    env: GuestEnv,
    agent: Arc<Mutex<Option<Agent>>>,
    next_id: u64,
    notes: Sender<Note>,
    signals: Arc<Signals>,
    /// This process set up and spawned an agent (the re-hello's `set_up`).
    set_up: Arc<AtomicBool>,
}

/// What to do after the reply is sent.
enum After {
    Nothing,
    Poweroff,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Binds a socket under the socket dir: bound at a temporary name, given its
/// mode, then renamed into place, so it is never reachable with a wider mode.
fn bind(env: &GuestEnv, abs: &str, mode: u32) -> Result<UnixListener, String> {
    let dir = env.path(GUEST_SOCK_DIR);
    if !dir.is_dir() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("{GUEST_SOCK_DIR}: {e}"))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("{GUEST_SOCK_DIR}: {e}"))?;
    }
    let path = env.path(abs);
    let name = path
        .file_name()
        .ok_or_else(|| format!("{abs}: no name"))?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{name}.new"));
    remove_socket(&tmp)?;
    remove_socket(&path)?;
    let l = UnixListener::bind(&tmp).map_err(|e| format!("bind {abs}: {e}"))?;
    let placed = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
        .and_then(|()| std::fs::rename(&tmp, &path));
    if let Err(e) = placed {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{abs}: {e}"));
    }
    Ok(l)
}

/// Removes a stale socket; anything else at that name is an error.
fn remove_socket(p: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_socket() => {
            std::fs::remove_file(p).map_err(|e| format!("{}: {e}", p.display()))
        }
        Ok(_) => Err(format!("{}: exists and is not a socket", p.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

/// Runs a tool from the root, waiting for it.
fn run_tool(env: &GuestEnv, tool: &Path, args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let out = Command::new(tool)
        .args(args)
        .current_dir(&env.root)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", tool.display()))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(format!(
        "{} failed ({}): {}",
        tool.display(),
        out.status,
        err.lines().next().unwrap_or("")
    ))
}

/// The service main.
pub fn run(env: &GuestEnv) -> Result<(), String> {
    // Bound before the hello: the host sends Setup right after its Welcome,
    // and a connection that arrives before the loop below waits in the backlog.
    let control = bind(env, GUEST_CONTROL_SOCK, 0o600)?;
    let local = bind(env, GUEST_LOCAL_SOCK, 0o666)?;
    // Ruling R22: a fresh process has no agent (an earlier one died with
    // its process, a cold boot has none), so it always asks for the setup;
    // the marker only skips the first-time work. A re-hello within this
    // process, once its agent was spawned, says `set_up: true`.
    let set_up = Arc::new(AtomicBool::new(false));
    let conn = events::hello(env, false).map_err(|e| {
        let m = e.into_message();
        eprintln!("saiife-guest: {m}");
        m
    })?;
    let signals = Arc::new(Signals::default());
    let fatal = Arc::new(Mutex::new(None));
    let (notes, rx) = mpsc::channel();
    {
        let (env, signals, fatal) = (env.clone(), signals.clone(), fatal.clone());
        let set_up = set_up.clone();
        thread::Builder::new()
            .name("guest-events".into())
            .spawn(move || events::run(env, conn, set_up, rx, signals, fatal))
            .map_err(|e| format!("events thread: {e}"))?;
    }
    {
        let (env, signals) = (env.clone(), signals.clone());
        thread::Builder::new()
            .name("guest-local".into())
            .spawn(move || serve_local(&env, local, &signals))
            .map_err(|e| format!("local thread: {e}"))?;
    }
    let mut init = Init {
        env: env.clone(),
        agent: Arc::new(Mutex::new(None)),
        next_id: 0,
        notes,
        signals,
        set_up,
    };
    control
        .set_nonblocking(true)
        .map_err(|e| format!("control.sock: {e}"))?;
    loop {
        if let Some(e) = lock(&fatal).take() {
            eprintln!("saiife-guest: {e}");
            return Err(e);
        }
        match control.accept() {
            Ok((s, _)) => init.serve_control(s),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(IDLE),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("control.sock accept: {e}")),
        }
    }
}

/// local.sock: each connection on its own short-lived thread with a deadline;
/// only `turn_finished` and `guard_checks` (FU1) go on.
fn serve_local(env: &GuestEnv, l: UnixListener, signals: &Arc<Signals>) {
    let active = Arc::new(AtomicUsize::new(0));
    for s in l.incoming() {
        let Ok(s) = s else {
            // Out of fds or the like: do not spin.
            thread::sleep(IDLE);
            continue;
        };
        if active.fetch_add(1, Ordering::SeqCst) >= LOCAL_CONCURRENCY {
            active.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (done, signals, within) = (active.clone(), signals.clone(), env.timing.local_deadline);
        let spawned = thread::Builder::new()
            .name("guest-local-conn".into())
            .spawn(move || {
                let mut r = DeadlineReader::new(&s, within).take(LOCAL_MAX);
                match read_msg::<Event>(&mut r) {
                    Ok(Some(Event::TurnFinished)) => signals.turn_finished(),
                    Ok(Some(Event::GuardChecks { n })) => signals.guard_checks(n),
                    _ => {}
                }
                done.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Init {
    fn serve_control(&mut self, s: UnixStream) {
        if s.set_nonblocking(false).is_err()
            || s.set_write_timeout(Some(self.env.timing.control_deadline))
                .is_err()
        {
            return;
        }
        let req = {
            let mut r = DeadlineReader::new(&s, self.env.timing.control_deadline);
            read_msg::<Request>(&mut r)
        };
        let (reply, after) = match req {
            // The export's reply is the delta itself, frame after frame on
            // this connection, then the close (the host's `request_stream`).
            // A failure is one `Reply::Err` frame instead (before any delta
            // frame, unless the stream itself broke).
            Ok(Some(Request::Export { n })) => {
                let mut w = &s;
                if let Err(why) = crate::export::export(&self.env, n, &mut w) {
                    let _ = write_msg(&mut &s, &Reply::Err { why });
                }
                return;
            }
            Ok(Some(req)) => self.handle(req),
            Ok(None) => return,
            Err(FrameError::BadJson(e)) => (
                Reply::Err {
                    why: format!("bad request: {e}"),
                },
                After::Nothing,
            ),
            Err(_) => return,
        };
        let _ = write_msg(&mut &s, &reply);
        drop(s);
        match after {
            After::Nothing => {}
            After::Poweroff => {
                let args = ["poweroff", "--no-block"].map(std::ffi::OsStr::new);
                if let Err(e) = run_tool(&self.env, &self.env.tools.systemctl, &args) {
                    eprintln!("saiife-guest: {e}");
                }
            }
        }
    }

    fn handle(&mut self, req: Request) -> (Reply, After) {
        let err = |why: String| (Reply::Err { why }, After::Nothing);
        match req {
            Request::Setup(s) => match self.setup(&s) {
                Ok(()) => (Reply::Ok, After::Nothing),
                Err(e) => err(e),
            },
            Request::Type { text, enter } => {
                let typer = lock(&self.agent).as_ref().map(|a| a.typer.clone());
                let Some(typer) = typer else {
                    return err("the agent is not running".into());
                };
                let mut bytes = text.into_bytes();
                if enter {
                    bytes.push(b'\r');
                }
                match typer.try_send(bytes) {
                    Ok(()) => (Reply::Ok, After::Nothing),
                    Err(TrySendError::Full(_)) => err("the agent is not reading its input".into()),
                    Err(TrySendError::Disconnected(_)) => err("the agent is not running".into()),
                }
            }
            Request::Resize { rows, cols } => {
                if let Err(e) = pty::dims_ok(rows, cols) {
                    return err(e);
                }
                let master = lock(&self.agent).as_ref().map(|a| a.master.clone());
                let Some(master) = master else {
                    return err("the agent is not running".into());
                };
                match pty::resize(&master, rows, cols) {
                    Ok(()) => (Reply::Ok, After::Nothing),
                    Err(e) => err(format!("resize: {e}")),
                }
            }
            Request::Poweroff => (Reply::Ok, After::Poweroff),
            Request::Advance { n, paths } => {
                match crate::export::advance(&self.env, n, paths.as_deref()) {
                    Ok(()) => (Reply::Ok, After::Nothing),
                    Err(e) => err(e),
                }
            }
            // Answered as a stream in `serve_control`.
            Request::Export { .. } => err("export is a stream".into()),
        }
    }

    fn setup(&mut self, s: &Setup) -> Result<(), String> {
        pty::dims_ok(s.rows, s.cols)?;
        s.check()?;
        if lock(&self.agent).is_some() {
            return Err("already set up".into());
        }
        let env = &self.env;
        let ids = setup::agent_ids(env)?;
        for f in &s.files {
            setup::write_file(
                env,
                &f.path,
                f.text.as_bytes(),
                f.mode,
                ids,
                f.keep_existing,
            )?;
        }
        let vars = agent_env(&s.env);
        let mut text = String::new();
        for (k, v) in &vars {
            text.push_str(&format!("{k}={v}\n"));
        }
        setup::write_file(env, AGENT_ENV_FILE, text.as_bytes(), 0o600, ids, false)?;
        let marker = env.path(SETUP_MARKER);
        if !marker.exists() {
            let work = env.path(WORK);
            let args = [
                std::ffi::OsStr::new("-R"),
                std::ffi::OsStr::new("-P"),
                std::ffi::OsStr::new("agent:agent"),
                work.as_os_str(),
            ];
            run_tool(env, &env.tools.chown, &args)?;
            crate::export::init_base(env)?;
            if let Some(dir) = marker.parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{SETUP_MARKER}: {e}"))?;
            }
            std::fs::write(&marker, b"").map_err(|e| format!("{SETUP_MARKER}: {e}"))?;
        }
        self.spawn(s, &vars)?;
        self.set_up.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn spawn(&mut self, s: &Setup, vars: &[(String, String)]) -> Result<(), String> {
        let env = &self.env;
        let pair = pty::open(s.rows, s.cols).map_err(|e| format!("cannot open a pty: {e}"))?;
        let stdio = |fd: &OwnedFd| -> Result<Stdio, String> {
            fd.try_clone()
                .map(Stdio::from)
                .map_err(|e| format!("pty: {e}"))
        };
        let mut cmd = Command::new(&env.tools.setsid);
        cmd.arg("--ctty")
            .arg("--wait")
            .arg(&env.tools.runuser)
            .args(["-u", "agent", "--"])
            .args(&s.agent.command)
            .env_clear()
            .envs(vars.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .current_dir(env.path(&s.agent.cwd))
            .stdin(stdio(&pair.slave)?)
            .stdout(stdio(&pair.slave)?)
            .stderr(Stdio::from(pair.slave));
        let spawned = cmd.spawn();
        // The Command held the slave copies; the init keeps none, so the
        // master reads EIO once the agent side is gone.
        drop(cmd);
        let mut child = spawned.map_err(|e| format!("cannot start the agent: {e}"))?;
        let master = Arc::new(pair.master);
        let reader = master.try_clone().map_err(|e| format!("pty: {e}"));
        let writer = master.try_clone().map_err(|e| format!("pty: {e}"));
        let (reader, writer) = match (reader, writer) {
            (Ok(r), Ok(w)) => (r, w),
            (Err(e), _) | (_, Err(e)) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let (typer, typed) = mpsc::sync_channel::<Vec<u8>>(TYPE_QUEUE);
        self.next_id += 1;
        let id = self.next_id;
        *lock(&self.agent) = Some(Agent { id, master, typer });
        let _ = self.notes.send(Note::Spawned);
        let (drained_tx, drained) = mpsc::channel::<()>();
        {
            let (env, signals) = (env.clone(), self.signals.clone());
            thread::spawn(move || {
                pty::pump(&env, reader, &signals);
                let _ = drained_tx.send(());
            });
        }
        thread::spawn(move || {
            let mut w = std::fs::File::from(writer);
            for bytes in typed {
                if io::Write::write_all(&mut w, &bytes).is_err() {
                    break;
                }
            }
        });
        let (agent, notes) = (self.agent.clone(), self.notes.clone());
        thread::spawn(move || {
            let code = child.wait().ok().and_then(|st| st.code());
            let _ = drained.recv_timeout(DRAIN);
            {
                let mut a = lock(&agent);
                if a.as_ref().is_some_and(|a| a.id == id) {
                    *a = None;
                }
            }
            let _ = notes.send(Note::Exited(code));
        });
        Ok(())
    }
}

/// `saiife __guest event <name>`: one event to local.sock.
pub fn send_local(env: &GuestEnv, ev: &Event) -> Result<(), String> {
    let path: PathBuf = env.path(GUEST_LOCAL_SOCK);
    let mut s = UnixStream::connect(&path).map_err(|e| format!("{GUEST_LOCAL_SOCK}: {e}"))?;
    s.set_write_timeout(Some(env.timing.local_deadline))
        .map_err(|e| format!("{GUEST_LOCAL_SOCK}: {e}"))?;
    write_msg(&mut s, ev).map_err(|e| format!("{GUEST_LOCAL_SOCK}: {e}"))
}
