//! The guest init against a tempdir root, with fake `setsid`, `runuser`,
//! `chown` and `systemctl`; the test plays the host on events.sock, pty.sock and
//! control.sock. The agent is a real `/bin/sh` or `/bin/cat` on a real PTY.
#![cfg(target_os = "linux")]

use saiife_boxproto::frame::{read_frame, read_msg, write_msg, Frame};
use saiife_boxproto::msg::{AgentSpec, Event, HostReply, Reply, Request, Setup, SetupFile};
use saiife_boxproto::ports::{GUEST_CONTROL_SOCK, GUEST_EVENTS_SOCK, GUEST_PTY_SOCK};
use saiife_boxproto::PROTO;
use saiife_guest::{GuestEnv, GuestTools, Timing};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(10);

/// The fake tools, written once before any test spawns anything (a script
/// still open for writing while another thread forks would be ETXTBSY).
fn tools() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let d = tempfile::Builder::new()
            .prefix("t")
            .tempdir()
            .unwrap()
            .keep();
        let w = |name: &str, body: &str| {
            let p = d.join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        w(
            "setsid",
            "#!/bin/sh\n[ \"$1\" = --ctty ] && [ \"$2\" = --wait ] || exit 97\nshift 2; exec \"$@\"\n",
        );
        w(
            "runuser",
            "#!/bin/sh\n[ \"$1\" = -u ] && [ \"$2\" = agent ] && [ \"$3\" = -- ] || exit 98\nshift 3; exec \"$@\"\n",
        );
        // Tools run with the root as their cwd, so the log lands in the test root.
        w("chown", "#!/bin/sh\nprintf '%s\\n' \"chown $*\" >> calls.log\n");
        w("systemctl", "#!/bin/sh\nprintf '%s\\n' \"systemctl $*\" >> calls.log\n");
        d
    })
}

fn fast() -> Timing {
    Timing {
        hello_tries: 30,
        hello_retry: Duration::from_millis(100),
        hello_reply: Duration::from_secs(5),
        ready_quiet: Duration::from_millis(400),
        ready_max: Duration::from_secs(5),
        activity_every: Duration::from_secs(1),
        control_deadline: Duration::from_secs(5),
        local_deadline: Duration::from_secs(2),
    }
}

struct Host {
    _dir: tempfile::TempDir,
    env: GuestEnv,
    events: UnixListener,
    pty: UnixListener,
}

fn host_with(timing: Timing, marker: bool) -> Host {
    let t = tools();
    let dir = tempfile::Builder::new().prefix("g").tempdir().unwrap();
    let root = dir.path().to_path_buf();
    for d in ["home/agent", "work", "run/saiife-guest", "proc", "etc"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("proc/uptime"), "12.34 56.78\n").unwrap();
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    std::fs::write(
        root.join("etc/passwd"),
        format!("root:x:0:0::/root:/bin/sh\nagent:x:{uid}:{gid}::/home/agent:/bin/sh\n"),
    )
    .unwrap();
    if marker {
        std::fs::create_dir_all(root.join("var/lib/saiife-guest")).unwrap();
        std::fs::write(root.join("var/lib/saiife-guest/setup-done"), "").unwrap();
    }
    let env = GuestEnv {
        root: root.clone(),
        tools: GuestTools {
            setsid: t.join("setsid"),
            runuser: t.join("runuser"),
            systemctl: t.join("systemctl"),
            chown: t.join("chown"),
            git: PathBuf::from("/usr/bin/git"),
        },
        version: "test-1".into(),
        timing,
    };
    let sock = env.path(GUEST_CONTROL_SOCK);
    assert!(
        sock.as_os_str().len() + 8 < 108,
        "socket path too long: {sock:?}"
    );
    let events = UnixListener::bind(env.path(GUEST_EVENTS_SOCK)).unwrap();
    let pty = UnixListener::bind(env.path(GUEST_PTY_SOCK)).unwrap();
    events.set_nonblocking(true).unwrap();
    pty.set_nonblocking(true).unwrap();
    Host {
        _dir: dir,
        env,
        events,
        pty,
    }
}

fn host() -> Host {
    host_with(fast(), false)
}

fn start(env: &GuestEnv) -> JoinHandle<Result<(), String>> {
    let env = env.clone();
    thread::spawn(move || saiife_guest::run_init(&env))
}

fn accept(l: &UnixListener, within: Duration) -> UnixStream {
    let until = Instant::now() + within;
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false).unwrap();
                return s;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

/// Accepts the events connection and reads its hello.
fn hello(h: &Host) -> (UnixStream, Event) {
    let mut s = accept(&h.events, T);
    s.set_read_timeout(Some(T)).unwrap();
    let ev: Event = read_msg(&mut s).unwrap().expect("hello");
    (s, ev)
}

/// Accepts the events connection, checks the hello, answers Welcome.
fn welcomed(h: &Host) -> UnixStream {
    let (mut s, ev) = hello(h);
    assert!(
        matches!(ev, Event::Hello { ref proto, .. } if proto == PROTO),
        "{ev:?}"
    );
    write_msg(
        &mut s,
        &HostReply::Welcome {
            proto: PROTO.into(),
        },
    )
    .unwrap();
    s
}

fn request(env: &GuestEnv, req: &Request) -> Reply {
    let until = Instant::now() + T;
    let mut s = loop {
        match UnixStream::connect(env.path(GUEST_CONTROL_SOCK)) {
            Ok(s) => break s,
            Err(_) if Instant::now() < until => thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("control connect: {e}"),
        }
    };
    s.set_read_timeout(Some(T)).unwrap();
    write_msg(&mut s, req).unwrap();
    read_msg(&mut s).unwrap().expect("reply")
}

/// The next event, or None at the deadline.
fn next_event(s: &mut UnixStream, within: Duration) -> Option<Event> {
    s.set_read_timeout(Some(within)).unwrap();
    match read_msg(s) {
        Ok(Some(e)) => Some(e),
        Ok(None) => None,
        Err(saiife_boxproto::frame::FrameError::Io(e))
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            None
        }
        Err(e) => panic!("event read: {e}"),
    }
}

/// Reads Bytes frames from pty.sock until `needle` shows up.
fn pty_until(s: &mut UnixStream, needle: &str, within: Duration) -> String {
    let until = Instant::now() + within;
    let mut got = Vec::new();
    while Instant::now() < until {
        s.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        match read_frame(s) {
            Ok(Some(Frame::Bytes(b))) => got.extend_from_slice(&b),
            Ok(Some(Frame::Json(v))) => panic!("json on pty: {v}"),
            Ok(None) => break,
            Err(_) => {}
        }
        if String::from_utf8_lossy(&got).contains(needle) {
            break;
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

fn setup(cmd: &[&str]) -> Setup {
    Setup {
        agent: AgentSpec {
            command: cmd.iter().map(|s| s.to_string()).collect(),
            user: "agent".into(),
            cwd: "/work".into(),
        },
        env: vec![("FOO".into(), "bar".into())],
        files: vec![],
        rows: 40,
        cols: 120,
    }
}

fn calls(env: &GuestEnv) -> String {
    std::fs::read_to_string(env.path("/calls.log")).unwrap_or_default()
}

fn wait_for(f: impl Fn() -> bool, within: Duration) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    f()
}

/// Running guest with its agent started from `cmd`; returns (events, pty).
fn running(h: &Host, cmd: &[&str]) -> (UnixStream, UnixStream) {
    let _init = start(&h.env);
    let ev = welcomed(h);
    assert_eq!(request(&h.env, &Request::Setup(setup(cmd))), Reply::Ok);
    let pty = accept(&h.pty, T);
    (ev, pty)
}

#[test]
fn hello_then_welcome() {
    let h = host();
    let _init = start(&h.env);
    let (mut s, ev) = hello(&h);
    assert_eq!(
        ev,
        Event::Hello {
            proto: PROTO.into(),
            guest: "test-1".into(),
            uptime_ms: 12340,
            set_up: false,
        }
    );
    write_msg(
        &mut s,
        &HostReply::Welcome {
            proto: PROTO.into(),
        },
    )
    .unwrap();
    // The control socket comes up (0600) and local.sock (0666).
    assert!(wait_for(|| h.env.path(GUEST_CONTROL_SOCK).exists(), T));
    let mode = |p: &str| std::fs::metadata(h.env.path(p)).unwrap().mode() & 0o777;
    assert_eq!(mode(GUEST_CONTROL_SOCK), 0o600);
    assert!(wait_for(
        || h.env
            .path(saiife_boxproto::ports::GUEST_LOCAL_SOCK)
            .exists(),
        T
    ));
    assert_eq!(mode(saiife_boxproto::ports::GUEST_LOCAL_SOCK), 0o666);
    // Export and Advance wait for plan 39.
    assert_eq!(
        request(&h.env, &Request::Export { n: 1 }),
        Reply::Err {
            why: "not in this version".into()
        }
    );
}

#[test]
fn hello_retries_until_the_host_listens() {
    let h = host();
    // Nobody accepts yet: the first hellos fail at connect.
    std::fs::remove_file(h.env.path(GUEST_EVENTS_SOCK)).unwrap();
    let _init = start(&h.env);
    thread::sleep(Duration::from_millis(350));
    let l = UnixListener::bind(h.env.path(GUEST_EVENTS_SOCK)).unwrap();
    l.set_nonblocking(true).unwrap();
    let mut s = accept(&l, T);
    s.set_read_timeout(Some(T)).unwrap();
    let ev: Event = read_msg(&mut s).unwrap().unwrap();
    assert!(matches!(ev, Event::Hello { .. }));
}

#[test]
fn refuse_ends_init() {
    let h = host();
    let init = start(&h.env);
    let (mut s, _) = hello(&h);
    write_msg(
        &mut s,
        &HostReply::Refuse {
            why: "wrong proto".into(),
        },
    )
    .unwrap();
    let until = Instant::now() + T;
    while !init.is_finished() && Instant::now() < until {
        thread::sleep(Duration::from_millis(20));
    }
    let r = init.join().unwrap();
    assert!(r.unwrap_err().contains("wrong proto"));
}

#[test]
fn setup_writes_files_and_env() {
    let h = host();
    let _init = start(&h.env);
    let mut ev = welcomed(&h);
    let mut s = setup(&["/bin/sh", "-c", "env; echo END-OF-ENV; sleep 3"]);
    s.files = vec![
        SetupFile {
            path: "/home/agent/.claude/settings.json".into(),
            mode: 0o600,
            text: "{\"a\":1}".into(),
            keep_existing: false,
        },
        SetupFile {
            path: "/etc/saiife-guest/hook.json".into(),
            mode: 0o644,
            text: "x".into(),
            keep_existing: false,
        },
    ];
    assert_eq!(request(&h.env, &Request::Setup(s)), Reply::Ok);
    let f = h.env.path("/home/agent/.claude/settings.json");
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "{\"a\":1}");
    let m = std::fs::metadata(&f).unwrap();
    assert_eq!(m.mode() & 0o7777, 0o600);
    assert_eq!(m.uid(), rustix::process::getuid().as_raw());
    let d = std::fs::metadata(h.env.path("/home/agent/.claude")).unwrap();
    assert!(d.is_dir());
    assert_eq!(d.mode() & 0o777, 0o755);
    let e = h.env.path("/etc/saiife-guest/hook.json");
    assert_eq!(std::fs::metadata(&e).unwrap().mode() & 0o7777, 0o644);
    let envf = h.env.path("/etc/saiife-guest/agent.env");
    let text = std::fs::read_to_string(&envf).unwrap();
    assert!(text.starts_with("HOME=/home/agent\nUSER=agent\n"), "{text}");
    assert!(text.contains("HTTPS_PROXY=http://127.0.0.1:3128\n"));
    assert!(text.ends_with("FOO=bar\n"), "{text}");
    assert_eq!(std::fs::metadata(&envf).unwrap().mode() & 0o7777, 0o600);
    // First setup: /work handed to the agent (never following links), the marker set.
    let work = h.env.path("/work");
    assert!(
        calls(&h.env).contains(&format!("chown -R -P agent:agent {}", work.display())),
        "{}",
        calls(&h.env)
    );
    assert!(h.env.path("/var/lib/saiife-guest/setup-done").exists());
    // The agent got exactly the fixed env plus the setup's; nothing inherited.
    let mut pty = accept(&h.pty, T);
    // `env` prints in no fixed order: read up to the line after it
    let out = pty_until(&mut pty, "END-OF-ENV", T);
    for want in [
        "HOME=/home/agent",
        "USER=agent",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "TERM=xterm-256color",
        "LANG=C.UTF-8",
        "HTTP_PROXY=http://127.0.0.1:3128",
        "NO_PROXY=localhost,127.0.0.1",
        "FOO=bar",
    ] {
        assert!(out.contains(want), "{want} missing in {out}");
    }
    assert!(!out.contains("CARGO"), "inherited env: {out}");
    assert!(!out.contains("TMPDIR"), "inherited env: {out}");
    let _ = next_event(&mut ev, Duration::from_millis(10));
}

#[test]
fn setup_check_refuses_bad_paths() {
    let h = host();
    let _init = start(&h.env);
    let _ev = welcomed(&h);
    for p in ["/etc/shadow", "/home/agent/../x"] {
        let mut s = setup(&["/bin/true"]);
        s.files = vec![SetupFile {
            path: p.into(),
            mode: 0o644,
            text: "pwned".into(),
            keep_existing: false,
        }];
        assert!(
            matches!(request(&h.env, &Request::Setup(s)), Reply::Err { .. }),
            "{p}"
        );
    }
    assert!(!h.env.path("/etc/shadow").exists());
    assert!(!h.env.path("/home/x").exists());
    assert!(!h.env.path("/var/lib/saiife-guest/setup-done").exists());
    assert_eq!(calls(&h.env), "");
}

#[test]
fn setup_does_not_follow_planted_links() {
    let h = host();
    let outside = h.env.path("/outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("victim"), "keep").unwrap();
    // A planted directory link: the write is refused, nothing lands outside.
    std::os::unix::fs::symlink(&outside, h.env.path("/home/agent/.claude")).unwrap();
    // A planted file link: replaced by a regular file, its target untouched.
    std::os::unix::fs::symlink(outside.join("victim"), h.env.path("/home/agent/notes")).unwrap();
    let _init = start(&h.env);
    let _ev = welcomed(&h);
    let mut s = setup(&["/bin/true"]);
    s.files = vec![SetupFile {
        path: "/home/agent/.claude/settings.json".into(),
        mode: 0o644,
        text: "x".into(),
        keep_existing: false,
    }];
    assert!(matches!(
        request(&h.env, &Request::Setup(s)),
        Reply::Err { .. }
    ));
    assert!(!outside.join("settings.json").exists());
    let mut s = setup(&["/bin/sh", "-c", "sleep 2"]);
    s.files = vec![SetupFile {
        path: "/home/agent/notes".into(),
        mode: 0o644,
        text: "new".into(),
        keep_existing: false,
    }];
    assert_eq!(request(&h.env, &Request::Setup(s)), Reply::Ok);
    assert_eq!(
        std::fs::read_to_string(outside.join("victim")).unwrap(),
        "keep"
    );
    let notes = h.env.path("/home/agent/notes");
    assert!(std::fs::symlink_metadata(&notes).unwrap().is_file());
    assert_eq!(std::fs::read_to_string(&notes).unwrap(), "new");
}

#[test]
fn setup_refuses_bad_window_sizes() {
    let h = host();
    let _init = start(&h.env);
    let _ev = welcomed(&h);
    for (rows, cols) in [(0, 120), (40, 0), (1001, 120), (40, 1001)] {
        let mut s = setup(&["/bin/true"]);
        s.rows = rows;
        s.cols = cols;
        assert!(matches!(
            request(&h.env, &Request::Setup(s)),
            Reply::Err { .. }
        ));
    }
    assert!(matches!(
        request(&h.env, &Request::Resize { rows: 10, cols: 10 }),
        Reply::Err { .. }
    ));
}

#[test]
fn agent_runs_on_a_pty() {
    let h = host();
    let (_ev, mut pty) = running(&h, &["/bin/sh", "-c", "tty; stty size; echo hi; sleep 2"]);
    let out = pty_until(&mut pty, "hi", T);
    assert!(out.contains("/dev/pts/"), "{out}");
    assert!(out.contains("40 120"), "{out}");
    assert!(out.contains("hi"), "{out}");
}

#[test]
fn resize_changes_the_window() {
    let h = host();
    let (_ev, mut pty) = running(&h, &["/bin/sh", "-c", "sleep 1; stty size; sleep 3"]);
    assert_eq!(
        request(
            &h.env,
            &Request::Resize {
                rows: 30,
                cols: 100
            }
        ),
        Reply::Ok
    );
    for (rows, cols) in [(0, 100), (30, 0), (2000, 100)] {
        assert!(matches!(
            request(&h.env, &Request::Resize { rows, cols }),
            Reply::Err { .. }
        ));
    }
    let out = pty_until(&mut pty, "30 100", T);
    assert!(out.contains("30 100"), "{out}");
}

#[test]
fn started_after_quiet() {
    let h = host();
    let t0 = Instant::now();
    let (mut ev, _pty) = running(&h, &["/bin/sh", "-c", "echo a; sleep 3; echo b; sleep 5"]);
    let e = next_event(&mut ev, T).unwrap();
    let dt = t0.elapsed();
    assert_eq!(e, Event::Started);
    // Output, then 400 ms quiet: well before the second echo at 3 s.
    assert!(dt >= Duration::from_millis(400), "{dt:?}");
    assert!(dt < Duration::from_millis(2500), "{dt:?}");
}

#[test]
fn started_at_the_latest_after_ready_max() {
    let mut t = fast();
    t.ready_max = Duration::from_secs(2);
    let h = host_with(t, false);
    let t0 = Instant::now();
    let (mut ev, _pty) = running(
        &h,
        &[
            "/bin/sh",
            "-c",
            "for i in $(seq 1 40); do echo x; sleep 0.1; done",
        ],
    );
    let e = next_event(&mut ev, T).unwrap();
    let dt = t0.elapsed();
    assert_eq!(e, Event::Started);
    assert!(dt >= Duration::from_millis(1800), "{dt:?}");
    assert!(dt < Duration::from_secs(4), "{dt:?}");
}

#[test]
fn activity_is_throttled() {
    let h = host();
    let (mut ev, _pty) = running(
        &h,
        &[
            "/bin/sh",
            "-c",
            "echo a; sleep 1; for i in $(seq 1 100); do echo x; sleep 0.05; done",
        ],
    );
    assert_eq!(next_event(&mut ev, T), Some(Event::Started));
    let t0 = Instant::now();
    let mut at = Vec::new();
    while t0.elapsed() < Duration::from_millis(3500) {
        if let Some(e) = next_event(&mut ev, Duration::from_millis(200)) {
            assert_eq!(e, Event::Activity);
            at.push(Instant::now());
        }
    }
    assert!((3..=5).contains(&at.len()), "{} activities", at.len());
    for w in at.windows(2) {
        assert!(
            w[1] - w[0] >= Duration::from_millis(900),
            "{:?}",
            w[1] - w[0]
        );
    }
}

#[test]
fn type_writes_to_the_pty() {
    let h = host();
    let (_ev, mut pty) = running(&h, &["/bin/cat"]);
    assert_eq!(
        request(
            &h.env,
            &Request::Type {
                text: "abc".into(),
                enter: true
            }
        ),
        Reply::Ok
    );
    let out = pty_until(&mut pty, "abc", T);
    assert!(out.contains("abc"), "{out}");
}

#[test]
fn exited_reports_code() {
    let h = host();
    let (mut ev, _pty) = running(&h, &["/bin/sh", "-c", "echo bye; exit 3"]);
    let until = Instant::now() + T;
    let mut got = None;
    while Instant::now() < until {
        if let Some(Event::Exited { code }) = next_event(&mut ev, Duration::from_millis(200)) {
            got = Some(code);
            break;
        }
    }
    assert_eq!(got, Some(Some(3)));
    assert!(matches!(
        request(
            &h.env,
            &Request::Type {
                text: "x".into(),
                enter: false
            }
        ),
        Reply::Err { why } if why == "the agent is not running"
    ));
    // After the exit a new setup may start the agent again.
    assert_eq!(
        request(&h.env, &Request::Setup(setup(&["/bin/true"]))),
        Reply::Ok
    );
}

#[test]
fn second_setup_is_refused() {
    let h = host();
    let (_ev, _pty) = running(&h, &["/bin/sh", "-c", "sleep 5"]);
    assert_eq!(
        request(&h.env, &Request::Setup(setup(&["/bin/true"]))),
        Reply::Err {
            why: "already set up".into()
        }
    );
}

#[test]
fn type_without_agent_is_refused() {
    let h = host();
    let _init = start(&h.env);
    let _ev = welcomed(&h);
    assert_eq!(
        request(
            &h.env,
            &Request::Type {
                text: "x".into(),
                enter: true
            }
        ),
        Reply::Err {
            why: "the agent is not running".into()
        }
    );
}

#[test]
fn turn_finished_via_local_socket() {
    let h = host();
    let _init = start(&h.env);
    let mut ev = welcomed(&h);
    let local = h.env.path(saiife_boxproto::ports::GUEST_LOCAL_SOCK);
    assert!(wait_for(|| local.exists(), T));
    // Anything but TurnFinished is dropped.
    saiife_guest::send_local_event(&h.env, &Event::Started).unwrap();
    saiife_guest::send_local_event(&h.env, &Event::TurnFinished).unwrap();
    assert_eq!(next_event(&mut ev, T), Some(Event::TurnFinished));
    assert_eq!(next_event(&mut ev, Duration::from_millis(500)), None);
}

#[test]
fn slow_local_client_does_not_block() {
    let h = host();
    let _init = start(&h.env);
    let mut ev = welcomed(&h);
    let local = h.env.path(saiife_boxproto::ports::GUEST_LOCAL_SOCK);
    assert!(wait_for(|| local.exists(), T));
    // One client says nothing, another sends an oversized header, another garbage.
    let _silent = UnixStream::connect(&local).unwrap();
    let mut big = UnixStream::connect(&local).unwrap();
    big.write_all(&[0x01, 0x00, 0x10, 0x00, 0x00]).unwrap();
    let mut junk = UnixStream::connect(&local).unwrap();
    junk.write_all(b"\x01\x00\x00\x00\x02{]").unwrap();
    let t0 = Instant::now();
    saiife_guest::send_local_event(&h.env, &Event::TurnFinished).unwrap();
    assert_eq!(next_event(&mut ev, T), Some(Event::TurnFinished));
    assert!(
        t0.elapsed() < Duration::from_millis(1500),
        "{:?}",
        t0.elapsed()
    );
    // Control still answers.
    assert!(matches!(
        request(&h.env, &Request::Advance { n: 1, paths: None }),
        Reply::Err { .. }
    ));
}

#[test]
fn slow_control_client_times_out() {
    let mut t = fast();
    t.control_deadline = Duration::from_millis(500);
    let h = host_with(t, false);
    let _init = start(&h.env);
    let _ev = welcomed(&h);
    let until = Instant::now() + T;
    let silent = loop {
        if let Ok(s) = UnixStream::connect(h.env.path(GUEST_CONTROL_SOCK)) {
            break s;
        }
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(20));
    };
    let t0 = Instant::now();
    assert!(matches!(
        request(&h.env, &Request::Export { n: 1 }),
        Reply::Err { .. }
    ));
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    drop(silent);
}

#[test]
fn poweroff_replies_then_calls_systemctl() {
    let h = host();
    let _init = start(&h.env);
    let _ev = welcomed(&h);
    assert_eq!(request(&h.env, &Request::Poweroff), Reply::Ok);
    assert!(
        wait_for(
            || calls(&h.env).contains("systemctl poweroff --no-block\n"),
            T
        ),
        "{}",
        calls(&h.env)
    );
}

/// Ruling R22: a fresh init on a box set up before (a cold boot keeps the
/// disk and its marker) asks for the setup again; the second setup skips
/// the first-time chown of /work and spawns the agent.
#[test]
fn fresh_init_with_marker_asks_for_setup() {
    let h = host_with(fast(), true);
    let _init = start(&h.env);
    let (mut s, ev) = hello(&h);
    assert!(matches!(ev, Event::Hello { set_up: false, .. }), "{ev:?}");
    write_msg(
        &mut s,
        &HostReply::Welcome {
            proto: PROTO.into(),
        },
    )
    .unwrap();
    // No Exited: this process has no earlier agent to report.
    assert_eq!(next_event(&mut s, Duration::from_millis(300)), None);
    assert_eq!(
        request(
            &h.env,
            &Request::Setup(setup(&["/bin/sh", "-c", "echo up; sleep 3"]))
        ),
        Reply::Ok
    );
    let _pty = accept(&h.pty, T);
    assert_eq!(next_event(&mut s, T), Some(Event::Started));
    assert!(
        !calls(&h.env).contains("chown -R"),
        "the second setup ran chown: {}",
        calls(&h.env)
    );
}

#[test]
fn restarted_init_asks_for_setup() {
    let h = host();
    let (mut first, _pty) = running(&h, &["/bin/sh", "-c", "echo a; sleep 3"]);
    assert_eq!(next_event(&mut first, T), Some(Event::Started));
    // A second init against the same root (systemd restarted the service).
    let _second = start(&h.env);
    let (mut s, ev) = hello(&h);
    assert!(matches!(ev, Event::Hello { set_up: false, .. }), "{ev:?}");
    write_msg(
        &mut s,
        &HostReply::Welcome {
            proto: PROTO.into(),
        },
    )
    .unwrap();
    // Nothing follows from the new process until it is set up.
    assert_eq!(next_event(&mut s, Duration::from_millis(500)), None);
}

#[test]
fn setup_right_after_welcome() {
    let h = host();
    let _init = start(&h.env);
    let _ev = welcomed(&h);
    // No retry, no sleep: control.sock is up before the hello.
    let mut c = UnixStream::connect(h.env.path(GUEST_CONTROL_SOCK)).unwrap();
    c.set_read_timeout(Some(T)).unwrap();
    write_msg(
        &mut c,
        &Request::Setup(setup(&["/bin/sh", "-c", "sleep 1"])),
    )
    .unwrap();
    let r: Reply = read_msg(&mut c).unwrap().unwrap();
    assert_eq!(r, Reply::Ok);
}

#[test]
fn exited_survives_a_dropped_link() {
    let h = host();
    let (ev, _pty) = running(&h, &["/bin/sh", "-c", "sleep 1; exit 4"]);
    // The link drops just before the agent exits.
    drop(ev);
    thread::sleep(Duration::from_millis(900));
    let (mut s, e) = hello(&h);
    assert!(matches!(e, Event::Hello { set_up: true, .. }), "{e:?}");
    write_msg(
        &mut s,
        &HostReply::Welcome {
            proto: PROTO.into(),
        },
    )
    .unwrap();
    let until = Instant::now() + T;
    let mut got = None;
    while Instant::now() < until && got.is_none() {
        if let Some(Event::Exited { code }) = next_event(&mut s, Duration::from_millis(200)) {
            got = Some(code);
        }
    }
    assert_eq!(got, Some(Some(4)));
}

#[test]
fn reconnect_rehellos_with_set_up() {
    let h = host();
    let (ev, _pty) = running(&h, &["/bin/sh", "-c", "echo a; sleep 8"]);
    // The host side goes away (a restore): the guest says hello again, set up.
    drop(ev);
    let (mut s, e) = hello(&h);
    assert!(matches!(e, Event::Hello { set_up: true, .. }), "{e:?}");
    write_msg(
        &mut s,
        &HostReply::Welcome {
            proto: PROTO.into(),
        },
    )
    .unwrap();
    // Events flow on the new connection.
    saiife_guest::send_local_event(&h.env, &Event::TurnFinished).unwrap();
    let until = Instant::now() + T;
    let mut seen = false;
    while Instant::now() < until && !seen {
        seen = next_event(&mut s, Duration::from_millis(200)) == Some(Event::TurnFinished);
    }
    assert!(seen);
}

#[test]
fn units_are_as_fixed() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets/box/guest");
    let units = [
        (
            "saiife-guest.service",
            "/usr/local/bin/saiife __guest init",
        ),
        (
            "saiife-events.service",
            "/usr/bin/socat UNIX-LISTEN:/run/saiife-guest/events.sock,fork,mode=0600 VSOCK-CONNECT:2:5000",
        ),
        (
            "saiife-pty.service",
            "/usr/bin/socat UNIX-LISTEN:/run/saiife-guest/pty.sock,fork,mode=0600 VSOCK-CONNECT:2:5003",
        ),
        (
            "saiife-control.service",
            "/usr/bin/socat VSOCK-LISTEN:1024,reuseaddr,fork UNIX-CONNECT:/run/saiife-guest/control.sock",
        ),
        (
            "saiife-egress.service",
            "/usr/bin/socat TCP-LISTEN:3128,bind=0.0.0.0,reuseaddr,fork VSOCK-CONNECT:2:5001",
        ),
        (
            "saiife-model.service",
            "/usr/bin/socat TCP-LISTEN:3129,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:2:5002",
        ),
    ];
    let lines = |name: &str, key: &str| -> Vec<String> {
        let text = std::fs::read_to_string(base.join("units").join(name)).unwrap();
        text.lines()
            .filter_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_string))
            .collect()
    };
    for (name, exec) in units {
        assert_eq!(lines(name, "ExecStart"), vec![exec.to_string()], "{name}");
        assert_eq!(lines(name, "WantedBy"), vec!["multi-user.target"], "{name}");
        assert_eq!(lines(name, "Restart"), vec!["always"], "{name}");
        assert_eq!(lines(name, "RestartSec"), vec!["1"], "{name}");
        if name == "saiife-guest.service" {
            assert_eq!(
                lines(name, "After"),
                vec!["local-fs.target saiife-events.service saiife-control.service"]
            );
            // R22: restarts (a refused hello, the init-restart race) never
            // hit systemd's start limit and leave the unit failed.
            assert_eq!(lines(name, "StartLimitIntervalSec"), vec!["0"]);
            assert!(lines(name, "RuntimeDirectory").is_empty());
        } else {
            assert_eq!(
                lines(name, "RuntimeDirectory"),
                vec!["saiife-guest"],
                "{name}"
            );
            assert_eq!(
                lines(name, "RuntimeDirectoryPreserve"),
                vec!["yes"],
                "{name}"
            );
        }
    }
    let mut listed: Vec<String> = std::fs::read_to_string(base.join("enable.list"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    listed.sort();
    let mut want: Vec<String> = units.iter().map(|(n, _)| n.to_string()).collect();
    want.sort();
    assert_eq!(listed, want);
    let mut files: Vec<String> = std::fs::read_dir(base.join("units"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert_eq!(files, want);
}
