//! The events connection to the host: the hello, and the thread that reports
//! `started` (G1), `activity` (G2), `turn_finished`, `guard_checks` (FU1) and
//! `exited`, re-helloing
//! (G3) when the connection goes away.
#![cfg(target_os = "linux")]

use crate::env::GuestEnv;
use saiife_boxproto::frame::{read_msg, write_msg, FrameError};
use saiife_boxproto::msg::{Event, HostReply};
use saiife_boxproto::ports::GUEST_EVENTS_SOCK;
use saiife_boxproto::PROTO;
use std::collections::VecDeque;
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How often the events thread wakes up with nothing to do.
const TICK: Duration = Duration::from_millis(50);
/// How often it checks that the host is still there.
const PROBE_EVERY: Duration = Duration::from_millis(500);
/// Unsent events kept across a lost link (they are few: activity is
/// throttled, turn_finished and guard_checks coalesced).
const MAX_PENDING: usize = 64;
/// Write deadline on the events connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// A reader with one overall deadline: each read gets the time that is left.
pub struct DeadlineReader<'a> {
    s: &'a UnixStream,
    until: Instant,
}

impl<'a> DeadlineReader<'a> {
    pub fn new(s: &'a UnixStream, within: Duration) -> Self {
        DeadlineReader {
            s,
            until: Instant::now() + within,
        }
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.s.set_read_timeout(Some(left))?;
        let mut s = self.s;
        s.read(buf)
    }
}

/// What the PTY pump and local.sock raise for the events thread. Flags and a
/// counter, not a queue: a flood of output, `turn_finished` or `guard_checks`
/// costs nothing.
#[derive(Default)]
pub struct Signals {
    output: AtomicBool,
    turn_finished: AtomicBool,
    /// FU1: guard checks reported since the last tick (saturating).
    guard_checks: AtomicU32,
}

impl Signals {
    pub fn output(&self) {
        self.output.store(true, Ordering::Relaxed);
    }
    pub fn turn_finished(&self) {
        self.turn_finished.store(true, Ordering::Relaxed);
    }
    /// Adds `n` guard checks (saturating at `u32::MAX`).
    pub fn guard_checks(&self, n: u32) {
        let mut c = self.guard_checks.load(Ordering::Relaxed);
        while let Err(now) = self.guard_checks.compare_exchange_weak(
            c,
            c.saturating_add(n),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            c = now;
        }
    }
    /// The guard checks since the last call, and zero again.
    pub fn take_guard_checks(&self) -> u32 {
        self.guard_checks.swap(0, Ordering::Relaxed)
    }
}

/// Queues an event; a `guard_checks` merges into one already pending
/// (saturating sum), so a flood never grows the queue.
fn push_pending(pending: &mut VecDeque<Event>, ev: Event) {
    if let Event::GuardChecks { n } = ev {
        for p in pending.iter_mut() {
            if let Event::GuardChecks { n: have } = p {
                *have = have.saturating_add(n);
                return;
            }
        }
    }
    pending.push_back(ev);
}

/// What the control side and the agent's waiter tell the events thread.
pub enum Note {
    /// A new agent was spawned: G1 starts over.
    Spawned,
    /// The agent exited.
    Exited(Option<i32>),
}

/// How a hello ended.
pub enum HelloError {
    /// The host said no: fatal.
    Refused(String),
    /// No host answered in time.
    Unreachable(String),
}

impl HelloError {
    pub fn into_message(self) -> String {
        match self {
            HelloError::Refused(m) | HelloError::Unreachable(m) => m,
        }
    }
}

fn uptime_ms(env: &GuestEnv) -> u64 {
    std::fs::read_to_string(env.path("/proc/uptime"))
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
        .map_or(0, |s| (s * 1000.0).round() as u64)
}

fn hello_once(env: &GuestEnv, set_up: bool) -> Result<UnixStream, Result<String, String>> {
    let s = UnixStream::connect(env.path(GUEST_EVENTS_SOCK))
        .map_err(|e| Ok(format!("connect events.sock: {e}")))?;
    s.set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|e| Ok(e.to_string()))?;
    let hello = Event::Hello {
        proto: PROTO.into(),
        guest: env.version.clone(),
        uptime_ms: uptime_ms(env),
        set_up,
    };
    write_msg(&mut &s, &hello).map_err(|e| Ok(format!("send hello: {e}")))?;
    let mut r = DeadlineReader::new(&s, env.timing.hello_reply);
    match read_msg::<HostReply>(&mut r) {
        Ok(Some(HostReply::Welcome { proto })) if proto == PROTO => Ok(s),
        Ok(Some(HostReply::Welcome { proto })) => {
            Err(Err(format!("the host speaks {proto:?}, not {PROTO}")))
        }
        Ok(Some(HostReply::Refuse { why })) => Err(Err(format!("the host refused: {why}"))),
        Ok(None) => Err(Ok("the host closed before welcome".into())),
        Err(FrameError::BadJson(e)) => Err(Err(format!("bad answer to hello: {e}"))),
        Err(e) => Err(Ok(format!("no answer to hello: {e}"))),
    }
}

/// Says hello, retrying `hello_tries` times, `hello_retry` apart. `set_up`:
/// this process has set up and spawned the agent (ruling R22: a fresh
/// process always says `false`, so the host sets it up again).
pub fn hello(env: &GuestEnv, set_up: bool) -> Result<UnixStream, HelloError> {
    let mut last = String::from("no hello tried");
    for i in 0..env.timing.hello_tries.max(1) {
        if i > 0 {
            std::thread::sleep(env.timing.hello_retry);
        }
        match hello_once(env, set_up) {
            Ok(s) => return Ok(s),
            Err(Err(fatal)) => return Err(HelloError::Refused(fatal)),
            Err(Ok(why)) => last = why,
        }
    }
    Err(HelloError::Unreachable(format!(
        "no hello after {} tries: {last}",
        env.timing.hello_tries
    )))
}

/// True while the host end is open (EOF means it went away). Anything the host
/// sends here is unexpected and dropped.
fn peer_open(s: &UnixStream) -> bool {
    use rustix::net::RecvFlags;
    let mut buf = [0u8; 512];
    loop {
        match rustix::net::recv(s, &mut buf, RecvFlags::DONTWAIT) {
            Ok((0, _)) => return false,
            Ok(_) => continue,
            Err(rustix::io::Errno::AGAIN) => return true,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return false,
        }
    }
}

struct Ready {
    spawned: Option<Instant>,
    started: bool,
    last_out: Option<Instant>,
    last_activity: Option<Instant>,
}

/// The events thread. Returns when `notes` closes, or on a fatal error, which
/// it stores in `fatal`.
pub fn run(
    env: GuestEnv,
    conn: UnixStream,
    set_up: Arc<AtomicBool>,
    notes: Receiver<Note>,
    signals: Arc<Signals>,
    fatal: Arc<Mutex<Option<String>>>,
) {
    let t = env.timing.clone();
    let mut conn = Some(conn);
    let mut st = Ready {
        spawned: None,
        started: false,
        last_out: None,
        last_activity: None,
    };
    let mut last_probe = Instant::now();
    // Events not yet written; kept across a lost link and sent after the
    // re-hello, oldest first.
    let mut pending: VecDeque<Event> = VecDeque::new();
    loop {
        let now = Instant::now();
        let wait = match (st.spawned, st.started) {
            (Some(at), false) => {
                let cap = (at + t.ready_max).saturating_duration_since(now);
                let quiet = st
                    .last_out
                    .map_or(TICK, |o| (o + t.ready_quiet).saturating_duration_since(now));
                cap.min(quiet).min(TICK)
            }
            _ => TICK,
        };
        let mut exited = None;
        match notes.recv_timeout(wait) {
            Ok(Note::Spawned) => {
                st = Ready {
                    spawned: Some(Instant::now()),
                    started: false,
                    last_out: None,
                    last_activity: None,
                };
            }
            Ok(Note::Exited(code)) => exited = Some(Event::Exited { code }),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let now = Instant::now();
        let mut out: Vec<Event> = Vec::new();
        let had_output = signals.output.swap(false, Ordering::Relaxed) && st.spawned.is_some();
        if had_output {
            st.last_out = Some(now);
        }
        if let (Some(at), false) = (st.spawned, st.started) {
            let quiet = st
                .last_out
                .is_some_and(|o| now.duration_since(o) >= t.ready_quiet);
            if quiet || now.duration_since(at) >= t.ready_max {
                st.started = true;
                out.push(Event::Started);
            }
        } else if had_output
            && st.started
            && st
                .last_activity
                .is_none_or(|a| now.duration_since(a) >= t.activity_every)
        {
            st.last_activity = Some(now);
            out.push(Event::Activity);
        }
        if signals.turn_finished.swap(false, Ordering::Relaxed) {
            out.push(Event::TurnFinished);
        }
        let checks = signals.take_guard_checks();
        if checks > 0 {
            out.push(Event::GuardChecks { n: checks });
        }
        if let Some(e) = exited {
            st.spawned = None;
            out.push(e);
        }
        for e in out {
            push_pending(&mut pending, e);
        }
        while pending.len() > MAX_PENDING {
            pending.pop_front();
        }
        if now.duration_since(last_probe) >= PROBE_EVERY {
            last_probe = now;
            if conn.as_ref().is_some_and(|c| !peer_open(c)) {
                conn = None;
            }
            if conn.is_none() {
                // Re-hello now (G3), even with nothing to say.
                match hello(&env, set_up.load(Ordering::SeqCst)) {
                    Ok(s) => conn = Some(s),
                    Err(e) => {
                        *fatal.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.into_message());
                        return;
                    }
                }
            }
        }
        while let (Some(c), Some(ev)) = (conn.as_mut(), pending.front()) {
            if write_msg(c, ev).is_err() {
                // Kept; the next probe says hello again and resends it.
                conn = None;
                break;
            }
            pending.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_checks_coalesce_in_the_pending_queue() {
        let mut q = VecDeque::new();
        push_pending(&mut q, Event::TurnFinished);
        for _ in 0..1000 {
            push_pending(&mut q, Event::GuardChecks { n: 2 });
        }
        push_pending(&mut q, Event::Exited { code: Some(0) });
        push_pending(&mut q, Event::GuardChecks { n: u32::MAX });
        assert_eq!(
            Vec::from(q),
            vec![
                Event::TurnFinished,
                Event::GuardChecks { n: u32::MAX },
                Event::Exited { code: Some(0) },
            ]
        );
    }

    #[test]
    fn guard_checks_signal_sums_and_saturates() {
        let s = Signals::default();
        assert_eq!(s.take_guard_checks(), 0);
        s.guard_checks(3);
        s.guard_checks(4);
        assert_eq!(s.take_guard_checks(), 7);
        assert_eq!(s.take_guard_checks(), 0);
        s.guard_checks(u32::MAX);
        s.guard_checks(9);
        assert_eq!(s.take_guard_checks(), u32::MAX);
    }
}
