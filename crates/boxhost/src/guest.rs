//! The host end of the `saiife-guest/1` channel (plan 38).
//!
//! Per box run, two acceptor threads serve the host listeners the guest
//! connects to: events (hello, setup, then the event stream) and the PTY
//! (bytes fed to the headless terminal and the recording). Host requests go
//! out on a fresh control connection each through the multiplexer.
//!
//! The guest is untrusted: every read is bounded by the frame codec, the
//! hello has one overall deadline, text it sends is cleaned before it is
//! kept or logged, and the event queue is bounded. No lock is held across
//! socket or file I/O except the recorder's own per-box lock, which nothing
//! on the request path takes.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use saiife_boxes::guest::{GuestError, GuestEvent, GuestLink};
use saiife_boxproto::frame::{read_frame, read_msg, write_msg, Frame, FrameError};
use saiife_boxproto::msg::{Event, HostReply, Reply, Request, Setup, SetupFile};
use saiife_boxproto::{ports, PROTO};
use saiife_wire::source::{BoxId, DiffSummary, TermBatch};

use crate::paths::BoxPaths;
use crate::term::{clean_line, Recorder, Screen};
use crate::vmm::VmHooks;
use crate::vsock;

/// The first frame on an events connection must arrive within this, in all.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Writes of Welcome/Refuse.
const REPLY_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
/// The Setup request (the first setup runs `chown -R /work`; ruling R11).
const SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const PROMPT_TIMEOUT: Duration = Duration::from_secs(5);
const RESIZE_TIMEOUT: Duration = Duration::from_secs(5);
/// Events queued for the daemon, all boxes together.
const QUEUE_CAP: usize = 1024;
/// Acceptor poll period (stop flag, accept, terminal timer).
const POLL: Duration = Duration::from_millis(50);
/// A pending screen change is cut at most this long after the last cut (G4).
const FLUSH_MS: u64 = 200;
/// The recording is flushed this often while the box runs.
const RECORDER_FLUSH: Duration = Duration::from_secs(1);
/// after_off waits this long for the box's threads, then detaches them.
const JOIN_WAIT: Duration = Duration::from_secs(2);
/// Guest-derived error text kept or logged, in bytes.
const MAX_TEXT: usize = 512;
/// Connection handler threads per run (events and PTY together); above it a
/// new connection is accepted and closed at once.
const MAX_CONNS: usize = 8;
/// Pause after each accepted connection, refused or served: a reconnecting
/// guest cannot spin the acceptor.
const ACCEPT_THROTTLE: Duration = Duration::from_millis(20);
const SETUP_NONE: u8 = 0;
const SETUP_IN_FLIGHT: u8 = 1;
const SETUP_DONE: u8 = 2;
const ROWS: u16 = 40;
const COLS: u16 = 120;

/// Where the per-box setup comes from (the daemon's box records).
pub trait SetupSource: Send + Sync {
    fn setup_for(&self, id: &BoxId) -> Result<Setup, String>;
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Guest-derived text made printable and short.
fn sanitize(s: &str) -> String {
    let mut s = clean_line(s);
    if s.len() > MAX_TEXT {
        let mut n = MAX_TEXT;
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        s.truncate(n);
    }
    s
}

fn log(id: &BoxId, msg: &str) {
    eprintln!("saiife box {}: {}", id.as_str(), sanitize(msg));
}

fn unavailable(what: &str, e: impl std::fmt::Display) -> GuestError {
    GuestError::Unavailable(sanitize(&format!("{what}: {e}")))
}

/// Reads from `s` with one overall deadline: each read gets the time left.
struct DeadlineReader<'a> {
    s: &'a UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline passed"));
        }
        self.s.set_read_timeout(Some(left))?;
        match (&mut &*self.s).read(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                Err(io::Error::new(io::ErrorKind::TimedOut, "deadline passed"))
            }
            r => r,
        }
    }
}

/// The screen plus the 200 ms timer state and a dead flag (a panicking
/// emulator is contained, not fatal).
struct Term {
    screen: Screen,
    dead: bool,
    /// Mirrors the screen's own last cut time, so the timer cuts no sooner.
    last_cut: Option<u64>,
    pending: bool,
}

impl Term {
    fn new() -> Term {
        Term {
            screen: Screen::new(ROWS, COLS),
            dead: false,
            last_cut: None,
            pending: false,
        }
    }

    fn due(&self, now: u64) -> bool {
        self.last_cut
            .is_none_or(|t| now.saturating_sub(t) >= FLUSH_MS)
    }

    fn feed(&mut self, bytes: &[u8], now: u64) {
        if self.dead || bytes.is_empty() {
            return;
        }
        let due = self.due(now);
        let screen = &mut self.screen;
        if catch_unwind(AssertUnwindSafe(|| screen.feed(bytes, now))).is_err() {
            self.dead = true;
            return;
        }
        if due {
            self.last_cut = Some(now);
            self.pending = false;
        } else {
            self.pending = true;
        }
    }

    /// The timer: cut a pending change once 200 ms passed since the last cut.
    fn tick(&mut self, now: u64, force: bool) {
        if self.dead || !self.pending || !(force || self.due(now)) {
            return;
        }
        let screen = &mut self.screen;
        if catch_unwind(AssertUnwindSafe(|| screen.flush(now))).is_err() {
            self.dead = true;
            return;
        }
        self.last_cut = Some(now);
        self.pending = false;
    }

    fn resize(&mut self, rows: u16, cols: u16, now: u64) {
        if self.dead {
            return;
        }
        let screen = &mut self.screen;
        if catch_unwind(AssertUnwindSafe(|| screen.resize(rows, cols, now))).is_err() {
            self.dead = true;
            return;
        }
        self.last_cut = Some(now);
        self.pending = false;
    }
}

/// One box run: from before_boot to after_off.
struct Run {
    id: BoxId,
    paths: BoxPaths,
    start: Instant,
    /// after_off ran.
    stop: AtomicBool,
    /// The agent exited (an `exited` event).
    exited: AtomicBool,
    /// A hello was welcomed this run.
    welcomed: AtomicBool,
    /// Ready was queued this run (G3: once per run).
    ready_sent: AtomicBool,
    /// A `set_up: true` hello was welcomed this run (a restored guest, R14).
    restored: AtomicBool,
    /// SETUP_NONE, SETUP_IN_FLIGHT or SETUP_DONE: one setup at a time, once.
    setup: AtomicU8,
    /// Generation of the welcomed events session (0: none yet).
    events_gen: AtomicU64,
    /// Last generation handed to an accepted events connection.
    next_events_gen: AtomicU64,
    pty_gen: AtomicU64,
    /// Connection handler threads alive (events and PTY), capped at MAX_CONNS.
    conns: AtomicUsize,
    /// The cap was logged this run (once per run).
    cap_logged: AtomicBool,
    /// Clones of the current connections, kept to shut them down.
    events_conn: Mutex<Option<(u64, UnixStream)>>,
    /// Events connections still in their hello, by generation.
    hellos: Mutex<BTreeMap<u64, UnixStream>>,
    pty_conn: Mutex<Option<(u64, UnixStream)>>,
    /// Open control connections; a setup's carries its events generation and
    /// is shut when that session is replaced.
    controls: Mutex<BTreeMap<u64, (Option<u64>, UnixStream)>>,
    next_control: AtomicU64,
    term: Mutex<Term>,
    /// Ruling R12: the recording's file I/O runs under this lock. It is per
    /// box, only the PTY threads and after_off take it (never the request
    /// path), and the file is a fresh O_EXCL regular file of ours.
    recorder: Mutex<Option<Recorder>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    last_error: Mutex<Option<String>>,
}

impl Run {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
    fn set_error_if_empty(&self, msg: &str) {
        log(&self.id, msg);
        let mut e = lock(&self.last_error);
        if e.is_none() {
            *e = Some(sanitize(msg));
        }
    }
    fn set_error(&self, msg: &str) {
        log(&self.id, msg);
        *lock(&self.last_error) = Some(sanitize(msg));
    }

    /// Takes every connection clone out and shuts it down (outside the locks).
    fn shut_streams(&self) {
        let mut streams: Vec<UnixStream> = Vec::new();
        streams.extend(lock(&self.events_conn).take().map(|(_, s)| s));
        streams.extend(std::mem::take(&mut *lock(&self.hellos)).into_values());
        streams.extend(lock(&self.pty_conn).take().map(|(_, s)| s));
        streams.extend(
            std::mem::take(&mut *lock(&self.controls))
                .into_values()
                .map(|(_, s)| s),
        );
        for s in streams {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    /// A welcomed session becomes the current one: the old session and any
    /// setup it still has in flight are shut down.
    fn replace_events(&self, gen: u64, clone: UnixStream) {
        let old = {
            let mut slot = lock(&self.events_conn);
            self.events_gen.store(gen, Ordering::SeqCst);
            slot.replace((gen, clone))
        };
        let stale: Vec<UnixStream> = {
            let mut c = lock(&self.controls);
            let keys: Vec<u64> = c
                .iter()
                .filter(|(_, (tag, _))| tag.is_some_and(|t| t != gen))
                .map(|(k, _)| *k)
                .collect();
            keys.iter()
                .filter_map(|k| c.remove(k))
                .map(|(_, s)| s)
                .collect()
        };
        for s in old.map(|(_, s)| s).into_iter().chain(stale) {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    /// Replaces the current connection of a channel, shutting the old one.
    fn replace(slot: &Mutex<Option<(u64, UnixStream)>>, gen: u64, clone: UnixStream) {
        let old = lock(slot).replace((gen, clone));
        if let Some((_, old)) = old {
            let _ = old.shutdown(Shutdown::Both);
        }
    }

    /// A connection handler ends: drop its clone if it is still the current one.
    fn release(slot: &Mutex<Option<(u64, UnixStream)>>, gen: u64, s: &UnixStream) {
        let mine = {
            let mut g = lock(slot);
            if g.as_ref().is_some_and(|(g2, _)| *g2 == gen) {
                g.take()
            } else {
                None
            }
        };
        if let Some((_, c)) = mine {
            let _ = c.shutdown(Shutdown::Both);
        }
        let _ = s.shutdown(Shutdown::Both);
    }
}

/// Counts a live thread for as long as it is alive.
struct Live(Arc<AtomicUsize>);
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Counts a connection handler of a run for as long as it is alive.
struct ConnSlot(Arc<Run>);
impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.conns.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Deregisters a control connection when the exchange ends.
struct ControlGuard<'a> {
    run: &'a Run,
    key: u64,
}
impl Drop for ControlGuard<'_> {
    fn drop(&mut self) {
        let s = lock(&self.run.controls).remove(&self.key);
        drop(s);
    }
}

/// Where a box's terminal recording goes (ruling R15): the default is
/// `term.cast` in the box's runtime dir; the daemon points it at the box's
/// record dir (plan 35, R37), since the runtime dir is writable by the VMM.
pub type CastPath = Arc<dyn Fn(&BoxId, &BoxPaths) -> PathBuf + Send + Sync>;

/// The host end of `saiife-guest/1` for every box.
pub struct VsockGuest {
    me: Weak<VsockGuest>,
    setups: Arc<dyn SetupSource>,
    group_rw: bool,
    vmm_uid: u32,
    cast_path: CastPath,
    runs: Mutex<BTreeMap<BoxId, Arc<Run>>>,
    queue: Mutex<VecDeque<(BoxId, GuestEvent)>>,
    queue_cv: Condvar,
    live: Arc<AtomicUsize>,
}

impl VsockGuest {
    /// `group_rw`: the host listeners are 0660 (locked mode) instead of 0600.
    /// `vmm_uid`: the uid that must own each box's `vsock.sock`.
    /// The recording goes to `term.cast` in each box's runtime dir (tests;
    /// the daemon uses [`VsockGuest::with_cast_path`]).
    pub fn new(setups: Arc<dyn SetupSource>, group_rw: bool, vmm_uid: u32) -> Arc<VsockGuest> {
        let cast_path: CastPath = Arc::new(|_id: &BoxId, p: &BoxPaths| p.dir.join("term.cast"));
        Self::with_cast_path(setups, group_rw, vmm_uid, cast_path)
    }

    /// As `new`, with the recording at `cast_path(id, paths)` (its parent
    /// directory must exist; the file is created fresh, O_EXCL).
    pub fn with_cast_path(
        setups: Arc<dyn SetupSource>,
        group_rw: bool,
        vmm_uid: u32,
        cast_path: CastPath,
    ) -> Arc<VsockGuest> {
        Arc::new_cyclic(|me| VsockGuest {
            cast_path,
            me: me.clone(),
            setups,
            group_rw,
            vmm_uid,
            runs: Mutex::new(BTreeMap::new()),
            queue: Mutex::new(VecDeque::new()),
            queue_cv: Condvar::new(),
            live: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Waits up to `timeout` for events, then returns all queued ones.
    pub fn recv_events(&self, timeout: Duration) -> Vec<(BoxId, GuestEvent)> {
        let q = lock(&self.queue);
        let (mut q, _) = self
            .queue_cv
            .wait_timeout_while(q, timeout, |q| q.is_empty())
            .unwrap_or_else(|e| e.into_inner());
        q.drain(..).collect()
    }

    /// The last refused hello or failed setup of the box's current run.
    pub fn last_error(&self, id: &BoxId) -> Option<String> {
        let run = self.run(id)?;
        let e = lock(&run.last_error).clone();
        e
    }

    /// Drops a stopped box's entry (its last screen and error); `false`, and
    /// nothing changes, while its run is still on or the box is unknown.
    pub fn forget(&self, id: &BoxId) -> bool {
        let mut runs = lock(&self.runs);
        match runs.get(id) {
            Some(run) if run.stopped() => {
                runs.remove(id);
                true
            }
            _ => false,
        }
    }

    /// Ruling R14: the box's current run welcomed a `set_up: true` hello (a
    /// guest restored from a snapshot, which never says Ready) and the agent
    /// has not exited. Advisory: the guest's word, like `Started`.
    pub fn restored(&self, id: &BoxId) -> bool {
        self.run(id).is_some_and(|run| {
            !run.stopped()
                && run.restored.load(Ordering::SeqCst)
                && !run.exited.load(Ordering::SeqCst)
        })
    }

    /// Threads of all runs still alive (tests).
    #[doc(hidden)]
    pub fn live_threads(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn run(&self, id: &BoxId) -> Option<Arc<Run>> {
        lock(&self.runs).get(id).cloned()
    }

    /// A run that can take requests: booted, not off, welcomed.
    fn live_run(&self, id: &BoxId) -> Result<Arc<Run>, GuestError> {
        let run = self.run(id).ok_or(GuestError::NotConnected)?;
        if run.stopped() || !run.welcomed.load(Ordering::SeqCst) {
            return Err(GuestError::NotConnected);
        }
        Ok(run)
    }

    /// One request, one reply, within `timeout` overall.
    pub fn request(
        &self,
        id: &BoxId,
        req: &Request,
        timeout: Duration,
    ) -> Result<Reply, GuestError> {
        let run = self.live_run(id)?;
        self.exchange(&run, req, timeout, None)
    }

    /// One request, then frames until `on_frame` returns `Ok(false)` or the
    /// guest closes. Each frame must arrive within `timeout`.
    pub fn request_stream(
        &self,
        id: &BoxId,
        req: &Request,
        timeout: Duration,
        on_frame: &mut dyn FnMut(Frame) -> Result<bool, String>,
    ) -> Result<(), GuestError> {
        let run = self.live_run(id)?;
        let (s, _guard) = self.open_control(&run, req, timeout, None)?;
        loop {
            let mut r = DeadlineReader {
                s: &s,
                deadline: Instant::now() + timeout,
            };
            match read_frame(&mut r) {
                Ok(Some(f)) => match on_frame(f) {
                    Ok(true) => {}
                    Ok(false) => return Ok(()),
                    Err(m) => return Err(GuestError::Unavailable(m)),
                },
                Ok(None) => return Ok(()),
                Err(e) => return Err(unavailable("the guest stream failed", e)),
            }
        }
    }

    /// Sends the resize to the guest, then resizes the host screen.
    pub fn resize(&self, id: &BoxId, rows: u16, cols: u16) -> Result<(), GuestError> {
        let run = self.live_run(id)?;
        match self.exchange(&run, &Request::Resize { rows, cols }, RESIZE_TIMEOUT, None)? {
            Reply::Ok => {
                let now = run.now_ms();
                lock(&run.term).resize(rows, cols, now);
                Ok(())
            }
            Reply::Err { why } => Err(unavailable("the guest refused the resize", why)),
        }
    }

    /// Connects to the guest control port, registers the connection for
    /// after_off and writes `req`.
    fn open_control<'a>(
        &self,
        run: &'a Run,
        req: &Request,
        timeout: Duration,
        session: Option<u64>,
    ) -> Result<(UnixStream, ControlGuard<'a>), GuestError> {
        let deadline = Instant::now() + timeout;
        // A setup belongs to its events session: none once it was replaced.
        let gone = || run.stopped() || session.is_some_and(|g| !Self::current(run, g));
        if gone() {
            return Err(GuestError::NotConnected);
        }
        let s = vsock::connect(&run.paths, ports::CONTROL, timeout, self.vmm_uid)
            .map_err(|e| unavailable("the guest is not reachable", e))?;
        let key = run.next_control.fetch_add(1, Ordering::SeqCst);
        let clone = s
            .try_clone()
            .map_err(|e| unavailable("control connection", e))?;
        lock(&run.controls).insert(key, (session, clone));
        let guard = ControlGuard { run, key };
        if gone() {
            return Err(GuestError::NotConnected);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(GuestError::Unavailable(
                "the guest request timed out".into(),
            ));
        }
        s.set_write_timeout(Some(left))
            .map_err(|e| unavailable("control connection", e))?;
        write_msg(&mut &s, req).map_err(|e| unavailable("the request was not sent", e))?;
        Ok((s, guard))
    }

    fn exchange(
        &self,
        run: &Run,
        req: &Request,
        timeout: Duration,
        session: Option<u64>,
    ) -> Result<Reply, GuestError> {
        let deadline = Instant::now() + timeout;
        let (s, _guard) = self.open_control(run, req, timeout, session)?;
        let mut r = DeadlineReader { s: &s, deadline };
        match read_msg::<Reply>(&mut r) {
            Ok(Some(rep)) => Ok(rep),
            Ok(None) => Err(GuestError::Unavailable(
                "the guest closed the control connection".into(),
            )),
            Err(e) => Err(unavailable("no reply from the guest", e)),
        }
    }

    /// Queues an event; bounded and coalesced so a flooding guest cannot
    /// grow memory: per box at most one pending Activity, TurnFinished and
    /// Exited (the newest Activity/TurnFinished moves to the back).
    fn push(&self, id: &BoxId, ev: GuestEvent) {
        let mut q = lock(&self.queue);
        let same = |(b, e): &(BoxId, GuestEvent)| b == id && *e == ev;
        match ev {
            GuestEvent::Activity | GuestEvent::TurnFinished => {
                if let Some(i) = q.iter().position(same) {
                    q.remove(i);
                }
            }
            GuestEvent::Exited => {
                if q.iter().any(same) {
                    return;
                }
            }
            GuestEvent::Ready => {}
        }
        if q.len() >= QUEUE_CAP {
            let chatter =
                |e: &GuestEvent| matches!(e, GuestEvent::Activity | GuestEvent::TurnFinished);
            if let Some(i) = q.iter().position(|(_, e)| chatter(e)) {
                q.remove(i);
            } else if chatter(&ev) {
                return;
            } else {
                q.pop_front();
            }
        }
        q.push_back((id.clone(), ev));
        drop(q);
        self.queue_cv.notify_all();
    }

    fn spawn(&self, run: &Run, name: &str, f: impl FnOnce() + Send + 'static) -> io::Result<()> {
        self.live.fetch_add(1, Ordering::SeqCst);
        let live = Live(self.live.clone());
        let h = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let _live = live;
                f()
            })?;
        let mut t = lock(&run.threads);
        t.retain(|h| !h.is_finished());
        t.push(h);
        Ok(())
    }

    /// Stops a run: shut listeners (the acceptors see the stop flag) and
    /// streams, join with a bounded wait, flush the recording, unlink.
    fn stop_run(&self, run: &Run) {
        if run.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        let deadline = Instant::now() + JOIN_WAIT;
        let mut pending: Vec<JoinHandle<()>> = Vec::new();
        loop {
            // Again each round: an acceptor may have registered a late one.
            run.shut_streams();
            pending.append(&mut lock(&run.threads));
            let (done, rest): (Vec<_>, Vec<_>) = pending.into_iter().partition(|h| h.is_finished());
            for h in done {
                let _ = h.join();
            }
            pending = rest;
            if pending.is_empty() && lock(&run.threads).is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                log(
                    &run.id,
                    &format!(
                        "{} guest channel threads did not stop in time; detached",
                        pending.len()
                    ),
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let now = run.now_ms();
        lock(&run.term).tick(now, true);
        if let Some(mut rec) = lock(&run.recorder).take() {
            rec.flush();
        }
        vsock::unlink_all(&run.paths);
    }

    // ---- the events channel ----

    fn events_acceptor(me: Weak<VsockGuest>, run: Arc<Run>, l: UnixListener) {
        while !run.stopped() {
            match l.accept() {
                Ok((s, _)) => {
                    let Some(g) = me.upgrade() else { break };
                    if run.stopped() {
                        break;
                    }
                    let Some(slot) = Self::conn_slot(&run) else {
                        drop(s);
                        // Over the cap too: no faster than one per throttle.
                        std::thread::sleep(ACCEPT_THROTTLE);
                        continue;
                    };
                    let _ = s.set_nonblocking(false);
                    let gen = run.next_events_gen.fetch_add(1, Ordering::SeqCst) + 1;
                    let Ok(clone) = s.try_clone() else { continue };
                    lock(&run.hellos).insert(gen, clone);
                    let (me2, run2) = (me.clone(), run.clone());
                    if let Err(e) = g.spawn(&run, "saiife-guest-events", move || {
                        let _slot = slot;
                        VsockGuest::events_conn(me2, run2, gen, s)
                    }) {
                        let hello = lock(&run.hellos).remove(&gen);
                        drop(hello);
                        log(&run.id, &format!("events thread: {e}"));
                    }
                    // A reconnecting guest cannot make threads faster than this.
                    std::thread::sleep(ACCEPT_THROTTLE);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log(&run.id, &format!("events accept: {e}"));
                    std::thread::sleep(POLL);
                }
            }
        }
    }

    /// A handler slot under the per-run cap, or `None` (close the connection).
    fn conn_slot(run: &Arc<Run>) -> Option<ConnSlot> {
        if run.conns.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            run.conns.fetch_sub(1, Ordering::SeqCst);
            if !run.cap_logged.swap(true, Ordering::SeqCst) {
                log(
                    &run.id,
                    "too many guest connections; closing new ones (logged once per run)",
                );
            }
            return None;
        }
        Some(ConnSlot(run.clone()))
    }

    fn current(run: &Run, gen: u64) -> bool {
        !run.stopped() && run.events_gen.load(Ordering::SeqCst) == gen
    }

    /// Reads the hello: `Ok(set_up)` for a valid one, else why it is refused.
    fn read_hello(s: &UnixStream) -> Result<bool, String> {
        let mut r = DeadlineReader {
            s,
            deadline: Instant::now() + HELLO_TIMEOUT,
        };
        match read_msg::<Event>(&mut r) {
            Ok(Some(Event::Hello { proto, set_up, .. })) if proto == PROTO => Ok(set_up),
            Ok(Some(Event::Hello { proto, .. })) => {
                Err(format!("protocol {:?} is not {PROTO}", sanitize(&proto)))
            }
            Ok(Some(_)) => Err("the first message was not a hello".into()),
            Ok(None) => Err("the guest closed before its hello".into()),
            Err(FrameError::TooLarge(n)) => Err(format!("a hello frame of {n} bytes")),
            Err(FrameError::Io(e)) if e.kind() == io::ErrorKind::TimedOut => {
                Err("no hello within 10 s".into())
            }
            Err(e) => Err(format!("bad hello: {e}")),
        }
    }

    fn events_conn(me: Weak<VsockGuest>, run: Arc<Run>, gen: u64, s: UnixStream) {
        Self::events_session(&me, &run, gen, &s);
        let hello = lock(&run.hellos).remove(&gen);
        drop(hello);
        Run::release(&run.events_conn, gen, &s);
    }

    fn events_session(me: &Weak<VsockGuest>, run: &Run, gen: u64, s: &UnixStream) {
        let _ = s.set_write_timeout(Some(REPLY_WRITE_TIMEOUT));
        let set_up = match Self::read_hello(s) {
            Ok(set_up) => set_up,
            Err(why) => {
                if !run.stopped() {
                    let _ = write_msg(&mut &*s, &HostReply::Refuse { why: why.clone() });
                    // Never over an earlier error of this run (a failed
                    // setup is what the daemon must see).
                    run.set_error_if_empty(&format!("refused the guest hello: {why}"));
                }
                return;
            }
        };
        if run.stopped() {
            return;
        }
        // One setup per run, one at a time: a set_up:false hello while one is
        // in flight, or after it succeeded, is refused (it would not replace
        // the session, so the setup in flight is left alone).
        if !set_up {
            if let Err(state) = run.setup.compare_exchange(
                SETUP_NONE,
                SETUP_IN_FLIGHT,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                let why = if state == SETUP_DONE {
                    "already set up"
                } else {
                    "setup already in progress"
                };
                log(&run.id, &format!("refused a guest hello: {why}"));
                let _ = write_msg(&mut &*s, &HostReply::Refuse { why: why.into() });
                return;
            }
        }
        let unclaim = || {
            if !set_up {
                run.setup.store(SETUP_NONE, Ordering::SeqCst);
            }
        };
        let Some(clone) = lock(&run.hellos).remove(&gen) else {
            unclaim();
            return;
        };
        run.replace_events(gen, clone);
        if !Self::current(run, gen) {
            unclaim();
            return;
        }
        let welcome = HostReply::Welcome {
            proto: PROTO.into(),
        };
        if let Err(e) = write_msg(&mut &*s, &welcome) {
            log(&run.id, &format!("welcome not sent: {e}"));
            unclaim();
            return;
        }
        run.welcomed.store(true, Ordering::SeqCst);
        if set_up {
            run.restored.store(true, Ordering::SeqCst);
        }
        if !set_up {
            let Some(g) = me.upgrade() else {
                unclaim();
                return;
            };
            match g.do_setup(run, gen) {
                Ok(()) => run.setup.store(SETUP_DONE, Ordering::SeqCst),
                Err(e) => {
                    unclaim();
                    if Self::current(run, gen) {
                        run.set_error(&e);
                    }
                    return;
                }
            }
        }
        // An idle agent sends nothing for long: block, bounded by the codec;
        // after_off or a replacing connection shuts the stream to end this.
        let _ = s.set_read_timeout(None);
        loop {
            let ev = match read_msg::<Event>(&mut &*s) {
                Ok(Some(ev)) => ev,
                Ok(None) => return,
                Err(e) => {
                    if Self::current(run, gen) {
                        log(&run.id, &format!("events link closed: {e}"));
                    }
                    return;
                }
            };
            if !Self::current(run, gen) {
                return;
            }
            let out = match ev {
                Event::Hello { .. } => {
                    log(&run.id, "a second hello on the events link; closing it");
                    return;
                }
                Event::Started => {
                    if set_up || run.ready_sent.swap(true, Ordering::SeqCst) {
                        continue;
                    }
                    GuestEvent::Ready
                }
                Event::Activity => GuestEvent::Activity,
                Event::TurnFinished => GuestEvent::TurnFinished,
                Event::Exited { .. } => {
                    run.exited.store(true, Ordering::SeqCst);
                    GuestEvent::Exited
                }
            };
            let Some(g) = me.upgrade() else { return };
            g.push(&run.id, out);
        }
    }

    fn do_setup(&self, run: &Run, gen: u64) -> Result<(), String> {
        let setup = self
            .setups
            .setup_for(&run.id)
            .map_err(|e| format!("no setup for the box: {e}"))?;
        setup
            .check()
            .map_err(|e| format!("the box setup is not valid: {e}"))?;
        let (rows, cols) = (setup.rows, setup.cols);
        match self.exchange(run, &Request::Setup(setup), SETUP_TIMEOUT, Some(gen)) {
            Ok(Reply::Ok) => {}
            Ok(Reply::Err { why }) => return Err(format!("the guest setup failed: {why}")),
            Err(GuestError::Unavailable(m)) => return Err(format!("the guest setup failed: {m}")),
            Err(GuestError::NotConnected) => {
                return Err("the guest setup failed: the box stopped".into())
            }
        }
        if (rows, cols) != (ROWS, COLS) {
            let now = run.now_ms();
            lock(&run.term).resize(rows, cols, now);
        }
        Ok(())
    }

    // ---- the PTY channel ----

    fn pty_acceptor(me: Weak<VsockGuest>, run: Arc<Run>, l: UnixListener) {
        let mut last_rec_flush = Instant::now();
        while !run.stopped() {
            match l.accept() {
                Ok((s, _)) => {
                    let Some(g) = me.upgrade() else { break };
                    if run.stopped() {
                        break;
                    }
                    let Some(slot) = Self::conn_slot(&run) else {
                        drop(s);
                        // Over the cap too: no faster than one per throttle.
                        std::thread::sleep(ACCEPT_THROTTLE);
                        continue;
                    };
                    let _ = s.set_nonblocking(false);
                    let gen = run.pty_gen.fetch_add(1, Ordering::SeqCst) + 1;
                    let Ok(clone) = s.try_clone() else { continue };
                    Run::replace(&run.pty_conn, gen, clone);
                    let run2 = run.clone();
                    if let Err(e) = g.spawn(&run, "saiife-guest-pty", move || {
                        let _slot = slot;
                        VsockGuest::pty_conn(run2, gen, s)
                    }) {
                        log(&run.id, &format!("pty thread: {e}"));
                    }
                    std::thread::sleep(ACCEPT_THROTTLE);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log(&run.id, &format!("pty accept: {e}"));
                    std::thread::sleep(POLL);
                }
            }
            // The 200 ms frame timer and the periodic recording flush.
            let now = run.now_ms();
            lock(&run.term).tick(now, false);
            if last_rec_flush.elapsed() >= RECORDER_FLUSH {
                last_rec_flush = Instant::now();
                if let Some(rec) = lock(&run.recorder).as_mut() {
                    rec.flush();
                }
            }
        }
    }

    fn pty_conn(run: Arc<Run>, gen: u64, s: UnixStream) {
        let _ = s.set_read_timeout(None);
        loop {
            match read_frame(&mut &s) {
                Ok(Some(Frame::Bytes(b))) => {
                    if run.stopped() || run.pty_gen.load(Ordering::SeqCst) != gen {
                        break;
                    }
                    let now = run.now_ms();
                    lock(&run.term).feed(&b, now);
                    let t = run.start.elapsed().as_secs_f64();
                    if let Some(rec) = lock(&run.recorder).as_mut() {
                        rec.output(t, &b);
                    }
                }
                Ok(Some(Frame::Json(_))) => {
                    log(&run.id, "a json frame on the terminal stream; closing it");
                    break;
                }
                Ok(None) => break,
                Err(e) => {
                    if !run.stopped() {
                        log(&run.id, &format!("terminal stream closed: {e}"));
                    }
                    break;
                }
            }
        }
        Run::release(&run.pty_conn, gen, &s);
    }
}

impl VmHooks for VsockGuest {
    fn before_boot(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String> {
        let old = lock(&self.runs).get(id).cloned();
        if let Some(old) = old {
            self.stop_run(&old);
        }
        let run = Arc::new(Run {
            id: id.clone(),
            paths: paths.clone(),
            start: Instant::now(),
            stop: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            welcomed: AtomicBool::new(false),
            ready_sent: AtomicBool::new(false),
            restored: AtomicBool::new(false),
            setup: AtomicU8::new(SETUP_NONE),
            events_gen: AtomicU64::new(0),
            next_events_gen: AtomicU64::new(0),
            pty_gen: AtomicU64::new(0),
            conns: AtomicUsize::new(0),
            cap_logged: AtomicBool::new(false),
            events_conn: Mutex::new(None),
            hellos: Mutex::new(BTreeMap::new()),
            pty_conn: Mutex::new(None),
            controls: Mutex::new(BTreeMap::new()),
            next_control: AtomicU64::new(0),
            term: Mutex::new(Term::new()),
            recorder: Mutex::new(None),
            threads: Mutex::new(Vec::new()),
            last_error: Mutex::new(None),
        });
        let fail = |what: &str, e: io::Error| {
            vsock::unlink_all(paths);
            format!("{what}: {e}")
        };
        let bind = |port: u32| -> io::Result<UnixListener> {
            let l = vsock::listen(paths, port, self.group_rw)?;
            l.set_nonblocking(true)?;
            Ok(l)
        };
        let events = bind(ports::EVENTS).map_err(|e| fail("the events listener", e))?;
        let pty = bind(ports::PTY).map_err(|e| fail("the terminal listener", e))?;
        let unix_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let rec = Recorder::create(&(self.cast_path)(id, paths), ROWS, COLS, unix_now)
            .map_err(|e| fail("the terminal recording", e))?;
        *lock(&run.recorder) = Some(rec);
        lock(&self.runs).insert(id.clone(), run.clone());
        let (me, r) = (self.me.clone(), run.clone());
        let started = self
            .spawn(&run, "saiife-guest-accept-events", move || {
                VsockGuest::events_acceptor(me, r, events)
            })
            .and_then(|()| {
                let (me, r) = (self.me.clone(), run.clone());
                self.spawn(&run, "saiife-guest-accept-pty", move || {
                    VsockGuest::pty_acceptor(me, r, pty)
                })
            });
        if let Err(e) = started {
            self.stop_run(&run);
            return Err(format!("the guest channel threads: {e}"));
        }
        Ok(())
    }

    fn after_off(&self, id: &BoxId) {
        if let Some(run) = self.run(id) {
            self.stop_run(&run);
        }
    }
}

impl GuestLink for VsockGuest {
    fn prompt(&self, id: &BoxId, text: &str) -> Result<(), GuestError> {
        let req = Request::Type {
            text: text.into(),
            enter: true,
        };
        match self.request(id, &req, PROMPT_TIMEOUT)? {
            Reply::Ok => Ok(()),
            Reply::Err { why } => Err(unavailable("the guest refused the prompt", why)),
        }
    }

    fn terminal(&self, id: &BoxId, after: Option<u64>) -> Result<TermBatch, GuestError> {
        let run = self.run(id).ok_or(GuestError::NotConnected)?;
        let ended = run.stopped() || run.exited.load(Ordering::SeqCst);
        let t = lock(&run.term);
        if t.dead {
            return Err(GuestError::Unavailable("the terminal failed".into()));
        }
        Ok(t.screen.batch(after, ended))
    }

    fn diff(&self, _id: &BoxId) -> Result<DiffSummary, GuestError> {
        Err(GuestError::Unavailable(
            "the diff is read through the land book".into(),
        ))
    }

    fn last_error(&self, id: &BoxId) -> Option<String> {
        VsockGuest::last_error(self, id)
    }

    fn restored(&self, id: &BoxId) -> bool {
        VsockGuest::restored(self, id)
    }

    fn forget(&self, id: &BoxId) {
        let _ = VsockGuest::forget(self, id);
    }
}

/// `/home/agent/.claude/settings.json` for the agent in the box (G11): the
/// PreToolUse hook (advisory; the box is the boundary) and the Stop hook that
/// tells the host a turn finished. The matcher and timeout are the ones
/// `saiife init` writes for a project.
pub fn claude_settings() -> String {
    use saiife_agents::claude::{MATCHER, TIMEOUT_SECS};
    let v = serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": MATCHER,
                "hooks": [{
                    "type": "command",
                    "command": "/usr/local/bin/saiife check --hook-exit --agent claude --profile box",
                    "timeout": TIMEOUT_SECS,
                }]
            }],
            "Stop": [{
                "hooks": [{
                    "type": "command",
                    "command": "/usr/local/bin/saiife __guest event turn-finished",
                    "timeout": TIMEOUT_SECS,
                }]
            }]
        }
    });
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

/// The setup files for user packs: `(id, toml text)` to
/// `/home/agent/.config/saiife/packs/<id>.toml`, mode 0644. An id that is
/// not a valid user pack id is an error naming it (an id is a file name, so
/// it must never carry a path); nothing is dropped silently.
pub fn pack_files(packs: &[(String, String)]) -> Result<Vec<SetupFile>, String> {
    packs
        .iter()
        .map(|(id, text)| {
            if !saiife_policy::userpacks::valid_user_pack_id(id) {
                return Err(format!("{id:?} is not a valid user pack id"));
            }
            Ok(SetupFile {
                path: format!("/home/agent/.config/saiife/packs/{id}.toml"),
                mode: 0o644,
                text: text.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod settings_tests {
    use super::*;

    #[test]
    fn claude_settings_are_pinned() {
        let want = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/saiife check --hook-exit --agent claude --profile box",
            "timeout": 10
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/usr/local/bin/saiife __guest event turn-finished",
            "timeout": 10
          }
        ]
      }
    ]
  }
}"#;
        assert_eq!(claude_settings(), want);
    }

    #[test]
    fn pack_files_paths_and_bad_ids() {
        let good = vec![("user.mine".to_string(), "a = 1".to_string())];
        for bad in ["user.../../etc/x", "builtin.x", "user.-lead", "user."] {
            let mut packs = good.clone();
            packs.push((bad.to_string(), "bad".to_string()));
            let e = pack_files(&packs).unwrap_err();
            assert!(e.contains(bad), "{e}");
        }
        let f = pack_files(&good).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, "/home/agent/.config/saiife/packs/user.mine.toml");
        assert_eq!(f[0].mode, 0o644);
        assert_eq!(f[0].text, "a = 1");
        let s = Setup {
            agent: saiife_boxproto::msg::AgentSpec {
                command: vec!["/bin/true".into()],
                user: "agent".into(),
                cwd: "/work".into(),
            },
            env: vec![],
            files: f,
            rows: 40,
            cols: 120,
        };
        assert_eq!(s.check(), Ok(()));
    }
}
