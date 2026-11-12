#![cfg(feature = "fake")]
//! `VsockGuest` against a guest played with the protocol codec (plan 38, Task 4).
//! A fake multiplexer on `vsock.sock` forwards `CONNECT 1024` to a test-side
//! control server; the test connects to the host listeners as the guest would.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use saiife_boxes::guest::{GuestError, GuestEvent, GuestLink};
use saiife_boxhost::guest::{SetupSource, VsockGuest};
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::vmm::VmHooks;
use saiife_boxproto::frame::{read_msg, write_frame, write_msg, Frame, MAX_FRAME};
use saiife_boxproto::msg::{AgentSpec, Event, HostReply, Reply, Request, Setup};
use saiife_boxproto::ports;
use saiife_boxproto::PROTO;
use saiife_wire::source::{BoxId, TermFrame};

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn b1() -> BoxId {
    BoxId::parse("b1").unwrap()
}

fn setup() -> Setup {
    Setup {
        agent: AgentSpec {
            command: vec!["claude".into()],
            user: "agent".into(),
            cwd: "/work".into(),
        },
        env: vec![],
        files: vec![],
        rows: 40,
        cols: 120,
    }
}

struct Setups(Result<Setup, String>);
impl SetupSource for Setups {
    fn setup_for(&self, _id: &BoxId) -> Result<Setup, String> {
        self.0.clone()
    }
}

type Handler = dyn Fn(Request, &mut UnixStream) + Send + Sync;

/// The test world: a box dir, the fake multiplexer, the control server.
struct World {
    _t: tempfile::TempDir,
    paths: BoxPaths,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl World {
    fn new(handler: Arc<Handler>) -> World {
        let base = std::env::var_os("TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let t = tempfile::Builder::new()
            .prefix("g")
            .tempdir_in(base)
            .unwrap();
        let dir = t.path().join("b1");
        std::fs::create_dir(&dir).unwrap();
        let paths = BoxPaths::new(dir);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let l = UnixListener::bind(paths.vsock()).unwrap();
        l.set_nonblocking(true).unwrap();
        let (reqs, st) = (requests.clone(), stop.clone());
        thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                let s = match l.accept() {
                    Ok((s, _)) => s,
                    Err(_) => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };
                let (reqs, h) = (reqs.clone(), handler.clone());
                thread::spawn(move || mux_conn(s, reqs, h));
            }
        });
        World {
            _t: t,
            paths,
            requests,
            stop,
        }
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    fn guest(&self, setups: Result<Setup, String>) -> Arc<VsockGuest> {
        let g = VsockGuest::new(Arc::new(Setups(setups)), false, me());
        g.before_boot(&b1(), &self.paths).unwrap();
        g
    }

    fn connect(&self, port: u32) -> UnixStream {
        let s = UnixStream::connect(self.paths.vsock_port(port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        s
    }

    /// Says hello on a fresh events connection and expects Welcome.
    fn hello(&self, set_up: bool) -> UnixStream {
        let mut s = self.connect(ports::EVENTS);
        write_msg(&mut s, &hello_msg(PROTO, set_up)).unwrap();
        let r: HostReply = read_msg(&mut s).unwrap().unwrap();
        assert_eq!(
            r,
            HostReply::Welcome {
                proto: PROTO.into()
            }
        );
        s
    }
}

fn hello_msg(proto: &str, set_up: bool) -> Event {
    Event::Hello {
        proto: proto.into(),
        guest: "0.1".into(),
        uptime_ms: 5,
        set_up,
    }
}

/// One multiplexer connection: `CONNECT 1024\n` → `OK 1\n`, then one request.
fn mux_conn(mut s: UnixStream, reqs: Arc<Mutex<Vec<Request>>>, h: Arc<Handler>) {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while line.len() < 32 {
        if s.read(&mut b).unwrap_or(0) == 0 {
            return;
        }
        line.push(b[0]);
        if b[0] == b'\n' {
            break;
        }
    }
    if line != b"CONNECT 1024\n" {
        return;
    }
    s.write_all(b"OK 1\n").unwrap();
    let req: Request = match read_msg(&mut s) {
        Ok(Some(r)) => r,
        _ => return,
    };
    reqs.lock().unwrap().push(req.clone());
    h(req, &mut s);
}

fn ok_handler() -> Arc<Handler> {
    Arc::new(|_r, s| {
        let _ = write_msg(s, &Reply::Ok);
    })
}

/// Collects events for `b1` until `want` are seen or `within` passes.
fn events_until(g: &VsockGuest, want: usize, within: Duration) -> Vec<GuestEvent> {
    let end = Instant::now() + within;
    let mut out = Vec::new();
    while out.len() < want && Instant::now() < end {
        for (id, e) in g.recv_events(Duration::from_millis(100)) {
            assert_eq!(id, b1());
            out.push(e);
        }
    }
    out
}

fn wait_for(what: &str, within: Duration, f: impl Fn() -> bool) {
    let end = Instant::now() + within;
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

/// Reads until EOF (or error): the host closed the connection.
fn closed_by_host(s: &mut UnixStream) -> bool {
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return false,
            Err(_) => return true,
        }
    }
}

const T: Duration = Duration::from_secs(5);

#[test]
fn hello_setup_started_is_ready() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.hello(false);
    wait_for("setup", T, || !w.requests().is_empty());
    assert_eq!(w.requests(), vec![Request::Setup(setup())]);
    write_msg(&mut s, &Event::Started).unwrap();
    write_msg(&mut s, &Event::Activity).unwrap();
    write_msg(&mut s, &Event::TurnFinished).unwrap();
    write_msg(&mut s, &Event::Exited { code: Some(0) }).unwrap();
    let ev = events_until(&g, 4, T);
    assert_eq!(
        ev,
        vec![
            GuestEvent::Ready,
            GuestEvent::Activity,
            GuestEvent::TurnFinished,
            GuestEvent::Exited
        ]
    );
    assert_eq!(g.last_error(&b1()), None);
    g.after_off(&b1());
}

#[test]
fn second_started_is_not_ready_again() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.hello(false);
    write_msg(&mut s, &Event::Started).unwrap();
    write_msg(&mut s, &Event::Started).unwrap();
    write_msg(&mut s, &Event::Activity).unwrap();
    let ev = events_until(&g, 2, T);
    assert_eq!(ev, vec![GuestEvent::Ready, GuestEvent::Activity]);
    assert!(g.recv_events(Duration::from_millis(200)).is_empty());
    g.after_off(&b1());
}

#[test]
fn wrong_proto_is_refused() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.connect(ports::EVENTS);
    write_msg(&mut s, &hello_msg("saiife-guest/2", false)).unwrap();
    let r: HostReply = read_msg(&mut s).unwrap().unwrap();
    assert!(matches!(r, HostReply::Refuse { .. }), "{r:?}");
    assert!(closed_by_host(&mut s));
    let e = g.last_error(&b1()).expect("last error");
    assert!(e.contains("saiife-guest/2"), "{e}");
    assert!(w.requests().is_empty());
    g.after_off(&b1());
}

#[test]
fn oversized_first_frame_is_refused() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.connect(ports::EVENTS);
    let mut head = vec![0x01];
    head.extend_from_slice(&((MAX_FRAME as u32) + 1).to_be_bytes());
    s.write_all(&head).unwrap();
    let r: HostReply = read_msg(&mut s).unwrap().unwrap();
    assert!(matches!(r, HostReply::Refuse { .. }), "{r:?}");
    assert!(closed_by_host(&mut s));
    assert!(g.last_error(&b1()).is_some());
    g.after_off(&b1());
}

#[test]
fn slow_hello_times_out() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.connect(ports::EVENTS);
    let t0 = Instant::now();
    // A trickling guest: one byte of a valid hello every 500 ms.
    let mut buf = Vec::new();
    write_msg(&mut buf, &hello_msg(PROTO, false)).unwrap();
    let mut w2 = s.try_clone().unwrap();
    thread::spawn(move || {
        for b in buf {
            if w2.write_all(&[b]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    let took = t0.elapsed();
    assert!(took >= Duration::from_secs(9), "{took:?}");
    assert!(took < Duration::from_secs(13), "{took:?}");
    assert!(
        !got.windows(7).any(|w| w == b"welcome"),
        "a trickled hello was welcomed"
    );
    assert!(g.last_error(&b1()).is_some());
    assert!(w.requests().is_empty());
    g.after_off(&b1());
}

#[test]
fn events_before_hello_are_ignored() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.connect(ports::EVENTS);
    write_msg(&mut s, &Event::Started).unwrap();
    write_msg(&mut s, &Event::Activity).unwrap();
    let r: HostReply = read_msg(&mut s).unwrap().unwrap();
    assert!(matches!(r, HostReply::Refuse { .. }), "{r:?}");
    assert!(closed_by_host(&mut s));
    assert!(g.recv_events(Duration::from_millis(300)).is_empty());
    assert!(w.requests().is_empty());
    // A proper hello afterwards works.
    let mut s = w.hello(false);
    write_msg(&mut s, &Event::Started).unwrap();
    assert_eq!(events_until(&g, 1, T), vec![GuestEvent::Ready]);
    g.after_off(&b1());
}

#[test]
fn rehello_does_not_resetup() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s1 = w.hello(false);
    write_msg(&mut s1, &Event::Started).unwrap();
    assert_eq!(events_until(&g, 1, T), vec![GuestEvent::Ready]);
    // The guest reconnects: the old connection is replaced.
    let mut s2 = w.hello(true);
    assert!(closed_by_host(&mut s1), "old events connection still open");
    write_msg(&mut s2, &Event::Started).unwrap();
    write_msg(&mut s2, &Event::Activity).unwrap();
    assert_eq!(events_until(&g, 1, T), vec![GuestEvent::Activity]);
    assert!(g.recv_events(Duration::from_millis(200)).is_empty());
    assert_eq!(w.requests().len(), 1, "setup was sent again");
    g.after_off(&b1());
}

#[test]
fn restarted_guest_exited_is_queued() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.hello(true);
    write_msg(&mut s, &Event::Exited { code: None }).unwrap();
    assert_eq!(events_until(&g, 1, T), vec![GuestEvent::Exited]);
    assert!(w.requests().is_empty());
    g.after_off(&b1());
}

#[test]
fn setup_failure_is_kept() {
    let w = World::new(Arc::new(|_r, s| {
        let _ = write_msg(
            s,
            &Reply::Err {
                why: "chown of /work failed".into(),
            },
        );
    }));
    let g = w.guest(Ok(setup()));
    let mut s = w.hello(false);
    wait_for("setup error", T, || g.last_error(&b1()).is_some());
    let _ = write_msg(&mut s, &Event::Started);
    assert!(g.recv_events(Duration::from_millis(500)).is_empty());
    let e = g.last_error(&b1()).unwrap();
    assert!(e.contains("chown of /work failed"), "{e}");
    g.after_off(&b1());
}

#[test]
fn setup_source_failure_is_kept() {
    let w = World::new(ok_handler());
    let g = w.guest(Err("no such template".into()));
    let mut s = w.hello(false);
    wait_for("setup error", T, || g.last_error(&b1()).is_some());
    let _ = write_msg(&mut s, &Event::Started);
    assert!(g.recv_events(Duration::from_millis(500)).is_empty());
    assert!(g.last_error(&b1()).unwrap().contains("no such template"));
    assert!(w.requests().is_empty());
    g.after_off(&b1());
}

#[test]
fn invalid_frame_after_welcome_closes_the_link() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.hello(false);
    write_frame(&mut s, &Frame::Json(serde_json::json!({"t": "nope"}))).unwrap();
    let _ = write_msg(&mut s, &Event::Started);
    assert!(closed_by_host(&mut s));
    assert!(g.recv_events(Duration::from_millis(300)).is_empty());
    g.after_off(&b1());
}

#[test]
fn event_flood_is_bounded() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.hello(false);
    write_msg(&mut s, &Event::Started).unwrap();
    let mut buf = Vec::new();
    for i in 0..5000 {
        let e = if i % 2 == 0 {
            Event::Activity
        } else {
            Event::TurnFinished
        };
        write_msg(&mut buf, &e).unwrap();
    }
    for _ in 0..2000 {
        write_msg(&mut buf, &Event::Exited { code: Some(1) }).unwrap();
    }
    write_msg(&mut buf, &Event::Activity).unwrap();
    s.write_all(&buf).unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    // The host drops the connection once it read our EOF.
    assert!(closed_by_host(&mut s));
    let ev = g.recv_events(Duration::from_millis(200));
    assert!(ev.len() <= 8, "{} events queued: {ev:?}", ev.len());
    let ev: Vec<GuestEvent> = ev.into_iter().map(|(_, e)| e).collect();
    assert_eq!(ev.first(), Some(&GuestEvent::Ready));
    assert!(ev.contains(&GuestEvent::Exited));
    assert_eq!(ev.last(), Some(&GuestEvent::Activity));
    g.after_off(&b1());
}

#[test]
fn prompt_types_text_and_enter() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let _s = w.hello(false);
    wait_for("setup", T, || w.requests().len() == 1);
    g.prompt(&b1(), "fix the tests").unwrap();
    assert_eq!(
        w.requests()[1],
        Request::Type {
            text: "fix the tests".into(),
            enter: true
        }
    );
    assert_eq!(
        g.diff(&b1()),
        Err(GuestError::Unavailable(
            "the diff is read through the land book".into()
        ))
    );
    g.after_off(&b1());
}

#[test]
fn prompt_without_link_is_not_connected() {
    let w = World::new(ok_handler());
    let g = VsockGuest::new(Arc::new(Setups(Ok(setup()))), false, me());
    assert_eq!(g.prompt(&b1(), "x"), Err(GuestError::NotConnected));
    assert_eq!(g.terminal(&b1(), None), Err(GuestError::NotConnected));
    // Booted but no hello yet: still not connected.
    g.before_boot(&b1(), &w.paths).unwrap();
    assert_eq!(g.prompt(&b1(), "x"), Err(GuestError::NotConnected));
    assert!(w.requests().is_empty());
    g.after_off(&b1());
}

fn screen_text(g: &VsockGuest) -> String {
    let b = g.terminal(&b1(), None).unwrap();
    b.frames
        .iter()
        .flat_map(|f| match f {
            TermFrame::Snapshot { lines, .. } => lines.clone(),
            TermFrame::Delta { lines, .. } => lines.iter().map(|(_, l)| l.clone()).collect(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn terminal_serves_screen_frames() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut p = w.connect(ports::PTY);
    write_frame(&mut p, &Frame::Bytes(b"hello from the box".to_vec())).unwrap();
    wait_for("screen", T, || {
        screen_text(&g).contains("hello from the box")
    });
    // A second write within 200 ms still shows up (the flush timer).
    write_frame(&mut p, &Frame::Bytes(b"\r\nsecond line".to_vec())).unwrap();
    wait_for("flush", T, || {
        let b = g.terminal(&b1(), Some(0)).unwrap();
        b.frames.iter().any(|f| match f {
            TermFrame::Snapshot { lines, .. } => lines.iter().any(|l| l.contains("second line")),
            TermFrame::Delta { lines, .. } => lines.iter().any(|(_, l)| l.contains("second line")),
        })
    });
    assert!(!g.terminal(&b1(), None).unwrap().ended);
    g.after_off(&b1());
    assert!(g.terminal(&b1(), None).unwrap().ended);
}

#[test]
fn pty_json_frame_closes_and_reconnect_works() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut p = w.connect(ports::PTY);
    write_frame(&mut p, &Frame::Json(serde_json::json!({"t": "x"}))).unwrap();
    assert!(closed_by_host(&mut p));
    let mut p = w.connect(ports::PTY);
    write_frame(&mut p, &Frame::Bytes(b"back again".to_vec())).unwrap();
    wait_for("screen", T, || screen_text(&g).contains("back again"));
    g.after_off(&b1());
}

#[test]
fn request_stream_stops_on_false() {
    let w = World::new(Arc::new(|r, s| {
        if matches!(r, Request::Export { .. }) {
            for i in 0..5u8 {
                if write_frame(s, &Frame::Bytes(vec![i])).is_err() {
                    return;
                }
            }
        } else {
            let _ = write_msg(s, &Reply::Ok);
        }
    }));
    let g = w.guest(Ok(setup()));
    let _s = w.hello(false);
    wait_for("setup", T, || w.requests().len() == 1);
    let mut got = Vec::new();
    g.request_stream(&b1(), &Request::Export { n: 1 }, T, &mut |f| {
        got.push(f);
        Ok(got.len() < 2)
    })
    .unwrap();
    assert_eq!(got, vec![Frame::Bytes(vec![0]), Frame::Bytes(vec![1])]);
    // Until the guest closes: all five.
    let mut all = 0;
    g.request_stream(&b1(), &Request::Export { n: 1 }, T, &mut |_f| {
        all += 1;
        Ok(true)
    })
    .unwrap();
    assert_eq!(all, 5);
    // on_frame's error is the call's error.
    let e = g
        .request_stream(&b1(), &Request::Export { n: 1 }, T, &mut |_f| {
            Err("bad tar".into())
        })
        .unwrap_err();
    assert!(matches!(e, GuestError::Unavailable(m) if m.contains("bad tar")));
    g.after_off(&b1());
}

#[test]
fn request_times_out() {
    let w = World::new(Arc::new(|_r, _s| thread::sleep(Duration::from_secs(3))));
    let g = w.guest(Ok(setup()));
    let _s = w.hello(true);
    let t0 = Instant::now();
    let e = g
        .request(&b1(), &Request::Poweroff, Duration::from_millis(500))
        .unwrap_err();
    assert!(matches!(e, GuestError::Unavailable(_)), "{e:?}");
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    g.after_off(&b1());
}

#[test]
fn after_off_cleans_up() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.hello(false);
    let mut p = w.connect(ports::PTY);
    write_frame(&mut p, &Frame::Bytes(b"recorded output".to_vec())).unwrap();
    wait_for("screen", T, || screen_text(&g).contains("recorded output"));
    assert!(g.live_threads() > 0);
    let t0 = Instant::now();
    g.after_off(&b1());
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    assert_eq!(g.live_threads(), 0, "threads still running");
    assert!(!w.paths.vsock_port(ports::EVENTS).exists());
    assert!(!w.paths.vsock_port(ports::PTY).exists());
    assert!(w.paths.vsock().exists(), "vsock.sock belongs to the VMM");
    assert!(closed_by_host(&mut s));
    assert!(closed_by_host(&mut p));
    let cast = std::fs::read_to_string(w.paths.term_cast()).unwrap();
    assert!(
        cast.lines().next().unwrap().contains("\"version\":2"),
        "{cast}"
    );
    assert!(cast.contains("recorded output"), "{cast}");
    assert_eq!(g.prompt(&b1(), "x"), Err(GuestError::NotConnected));
    // A second after_off is harmless.
    g.after_off(&b1());
}

#[test]
fn recv_events_times_out_empty() {
    let g = VsockGuest::new(Arc::new(Setups(Ok(setup()))), false, me());
    let t0 = Instant::now();
    assert!(g.recv_events(Duration::from_millis(300)).is_empty());
    assert!(t0.elapsed() >= Duration::from_millis(290));
    assert!(t0.elapsed() < Duration::from_secs(2));
}

#[test]
fn resize_reaches_guest_and_screen() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let _s = w.hello(false);
    wait_for("setup", T, || w.requests().len() == 1);
    g.resize(&b1(), 30, 100).unwrap();
    assert_eq!(
        w.requests()[1],
        Request::Resize {
            rows: 30,
            cols: 100
        }
    );
    let b = g.terminal(&b1(), None).unwrap();
    assert!(
        b.frames.iter().any(|f| matches!(
            f,
            TermFrame::Snapshot {
                rows: 30,
                cols: 100,
                ..
            }
        )),
        "{b:?}"
    );
    g.after_off(&b1());
}

#[test]
fn reboot_resets_the_run() {
    let w = World::new(ok_handler());
    let g = w.guest(Ok(setup()));
    let mut s = w.hello(false);
    write_msg(&mut s, &Event::Started).unwrap();
    assert_eq!(events_until(&g, 1, T), vec![GuestEvent::Ready]);
    g.after_off(&b1());
    g.before_boot(&b1(), &w.paths).unwrap();
    let mut s = w.hello(false);
    write_msg(&mut s, &Event::Started).unwrap();
    assert_eq!(events_until(&g, 1, T), vec![GuestEvent::Ready]);
    assert_eq!(w.requests().len(), 2);
    g.after_off(&b1());
}
