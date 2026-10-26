//! Blocking client for the control socket, used by the managed hook.
use crate::frame::{read_frame_max, write_frame, FrameError, MAX_ANSWER_FRAME};
use crate::msg::{OP_HELLO, PROTO, SOCKET_NAME};
use rustix::event::{poll, PollFd, PollFlags};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use serde_json::{Map, Value};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{}: {detail}", path.display())]
    Owner { path: PathBuf, detail: String },
    #[error("connect: {0}")]
    Connect(io::Error),
    #[error("timeout")]
    Timeout,
    #[error("frame: {0}")]
    Frame(FrameError),
    #[error("daemon refused ({code}): {message}")]
    Refused { code: String, message: String },
    #[error("protocol: {0}")]
    Protocol(String),
}

impl From<FrameError> for ClientError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Io(ref io)
                if matches!(
                    io.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                ClientError::Timeout
            }
            e => ClientError::Frame(e),
        }
    }
}

#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    next_id: u64,
    hello: Map<String, Value>,
    poisoned: bool,
}

fn owner_err(path: &Path, detail: impl Into<String>) -> ClientError {
    ClientError::Owner {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}

fn check_owner(dir: &Path, sock: &Path, uid: u32) -> Result<(), ClientError> {
    let dm = std::fs::symlink_metadata(dir).map_err(|e| owner_err(dir, e.to_string()))?;
    if !dm.file_type().is_dir() {
        return Err(owner_err(dir, "not a directory"));
    }
    // The daemon accepts a dir root created for it, so the client does too.
    if dm.uid() != uid && dm.uid() != 0 {
        return Err(owner_err(
            dir,
            format!("owned by uid {}, expected {uid} or root", dm.uid()),
        ));
    }
    if dm.mode() & 0o022 != 0 {
        return Err(owner_err(dir, "writable by group or others"));
    }
    let sm = std::fs::symlink_metadata(sock).map_err(|e| owner_err(sock, e.to_string()))?;
    if !sm.file_type().is_socket() {
        return Err(owner_err(sock, "not a socket"));
    }
    if sm.uid() != uid {
        return Err(owner_err(
            sock,
            format!("owned by uid {}, expected {uid}", sm.uid()),
        ));
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    (left >= Duration::from_millis(1)).then_some(left)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "deadline passed")
}

/// Stream wrapper that re-arms the socket timeouts from the deadline before
/// every read and write, so the deadline bounds the whole call even when the
/// peer sends one byte at a time.
struct Bounded<'a> {
    s: &'a UnixStream,
    deadline: Instant,
}

impl Read for Bounded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = remaining(self.deadline).ok_or_else(timed_out)?;
        self.s.set_read_timeout(Some(left))?;
        (&*self.s).read(buf)
    }
}

impl Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = remaining(self.deadline).ok_or_else(timed_out)?;
        self.s.set_write_timeout(Some(left))?;
        (&*self.s).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn errno_io(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

/// Non-blocking connect bounded by `deadline`; the returned stream is blocking.
fn connect_by(path: &Path, deadline: Instant) -> Result<UnixStream, ClientError> {
    let addr = SocketAddrUnix::new(path).map_err(|e| ClientError::Connect(errno_io(e)))?;
    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|e| ClientError::Connect(errno_io(e)))?;
    loop {
        let left = remaining(deadline).ok_or(ClientError::Timeout)?;
        match rustix::net::connect(&fd, &addr) {
            Ok(()) => break,
            // Listener backlog is full: retry until the deadline.
            Err(Errno::AGAIN) => std::thread::sleep(left.min(Duration::from_millis(2))),
            Err(Errno::INPROGRESS) => {
                let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
                let ts = rustix::event::Timespec {
                    tv_sec: left.as_secs() as _,
                    tv_nsec: left.subsec_nanos() as _,
                };
                let n = poll(&mut fds, Some(&ts)).map_err(|e| ClientError::Connect(errno_io(e)))?;
                if n == 0 {
                    return Err(ClientError::Timeout);
                }
                match rustix::net::sockopt::socket_error(&fd) {
                    Ok(Ok(())) => break,
                    Ok(Err(e)) | Err(e) => return Err(ClientError::Connect(errno_io(e))),
                }
            }
            Err(Errno::INTR) => {}
            Err(e) => return Err(ClientError::Connect(errno_io(e))),
        }
    }
    let s = UnixStream::from(fd);
    s.set_nonblocking(false).map_err(ClientError::Connect)?;
    Ok(s)
}

impl Client {
    pub fn connect(
        socket_dir: &Path,
        daemon_uid: u32,
        deadline: Instant,
    ) -> Result<Client, ClientError> {
        let sock = socket_dir.join(SOCKET_NAME);
        check_owner(socket_dir, &sock, daemon_uid)?;
        let stream = connect_by(&sock, deadline)?;
        // Closes the check-then-connect race: whoever answers must be the daemon.
        #[cfg(target_os = "linux")]
        {
            let pc = crate::peer::peer_cred(&stream).map_err(ClientError::Connect)?;
            if pc.uid != daemon_uid {
                return Err(owner_err(
                    &sock,
                    format!("peer is uid {}, expected {daemon_uid}", pc.uid),
                ));
            }
        }
        let mut c = Client {
            stream,
            next_id: 1,
            hello: Map::new(),
            poisoned: false,
        };
        let mut args = Map::new();
        args.insert("proto".into(), Value::from(PROTO));
        args.insert("client".into(), Value::from(env!("CARGO_PKG_VERSION")));
        let ans = c.call(OP_HELLO, args, deadline)?;
        if ans.get("proto").and_then(Value::as_u64) != Some(PROTO) {
            return Err(ClientError::Protocol("daemon speaks another proto".into()));
        }
        c.hello = ans;
        Ok(c)
    }

    pub fn call(
        &mut self,
        op: &str,
        args: Map<String, Value>,
        deadline: Instant,
    ) -> Result<Map<String, Value>, ClientError> {
        if self.poisoned {
            return Err(ClientError::Protocol(
                "connection unusable after an earlier error".into(),
            ));
        }
        let r = self.exchange(op, args, deadline, false);
        if let Err(e) = &r {
            // A refusal that answers our id leaves the stream in step.
            if !matches!(e, ClientError::Refused { .. }) || self.poisoned {
                self.poisoned = true;
            }
        }
        r
    }

    /// Like [`Client::call`], but a refusal that answers this call's id is
    /// returned as the whole answer (`ok: false` with its extra fields,
    /// such as `rule` or `limit`) instead of an error.
    pub fn call_answer(
        &mut self,
        op: &str,
        args: Map<String, Value>,
        deadline: Instant,
    ) -> Result<Map<String, Value>, ClientError> {
        if self.poisoned {
            return Err(ClientError::Protocol(
                "connection unusable after an earlier error".into(),
            ));
        }
        let r = self.exchange(op, args, deadline, true);
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }

    fn exchange(
        &mut self,
        op: &str,
        args: Map<String, Value>,
        deadline: Instant,
        keep_refusal: bool,
    ) -> Result<Map<String, Value>, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = crate::msg::Request {
            id,
            op: op.to_string(),
            args,
        };
        let mut io = Bounded {
            s: &self.stream,
            deadline,
        };
        write_frame(&mut io, &req.to_value())?;
        let ans = read_frame_max(&mut io, MAX_ANSWER_FRAME)?;
        let id_ok = ans.get("id").and_then(Value::as_u64) == Some(id);
        match ans.get("ok").and_then(Value::as_bool) {
            Some(false) if keep_refusal && id_ok => Ok(ans),
            Some(false) => {
                // Includes id-less answers such as the daemon's `bad_frame`.
                self.poisoned = !id_ok;
                let s = |k: &str| {
                    ans.get(k)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                };
                Err(ClientError::Refused {
                    code: s("error"),
                    message: s("message"),
                })
            }
            _ if !id_ok => Err(ClientError::Protocol(format!("answer id is not {id}"))),
            Some(true) => Ok(ans),
            None => Err(ClientError::Protocol("answer has no ok".into())),
        }
    }

    pub fn hello_answer(&self) -> &Map<String, Value> {
        &self.hello
    }
}

/// Uid of `name` in `/etc/passwd`-format text.
pub fn uid_by_name(passwd: &str, name: &str) -> Option<u32> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then_some(())?;
        f.nth(1)?.parse().ok()
    })
}

/// Reads `/etc/passwd` directly: the daemon user is a local system user, so
/// no NSS lookup (and no helper process) happens on the hook path.
pub fn system_uid(name: &str) -> Option<u32> {
    uid_by_name(&std::fs::read_to_string("/etc/passwd").ok()?, name)
}

/// One `/etc/passwd` line's name and home directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub home: PathBuf,
}

/// The entry for `uid` in `/etc/passwd`-format text (the first one).
pub fn entry_by_uid(passwd: &str, uid: u32) -> Option<PasswdEntry> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 || f[2].parse::<u32>().ok()? != uid || f[0].is_empty() {
            return None;
        }
        Some(PasswdEntry {
            name: f[0].to_string(),
            home: PathBuf::from(f[5]),
        })
    })
}

/// The entry for `name` in `/etc/passwd`-format text (the first one).
pub fn entry_by_name(passwd: &str, name: &str) -> Option<PasswdEntry> {
    if name.is_empty() {
        return None;
    }
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 || f[0] != name || f[2].parse::<u32>().is_err() {
            return None;
        }
        Some(PasswdEntry {
            name: f[0].to_string(),
            home: PathBuf::from(f[5]),
        })
    })
}

/// The `/etc/passwd` entry of `uid`, read directly as `system_uid` does.
pub fn system_entry(uid: u32) -> Option<PasswdEntry> {
    entry_by_uid(&std::fs::read_to_string("/etc/passwd").ok()?, uid)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::frame::{read_frame, write_frame};
    use serde_json::{json, Map, Value};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }
    fn dl(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }
    fn dir_0755() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        d
    }
    /// Fake daemon: answers hello, then runs `f` per later request.
    fn fake(
        d: &std::path::Path,
        f: impl Fn(Map<String, Value>) -> Option<Value> + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        let l = UnixListener::bind(d.join(SOCKET_NAME)).unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let h = read_frame(&mut s).unwrap();
            assert_eq!(h["op"], "hello");
            assert_eq!(h["proto"], 1);
            write_frame(
                &mut s,
                &json!({"id":h["id"],"ok":true,"proto":1,"extra":"x"}),
            )
            .unwrap();
            while let Ok(m) = read_frame(&mut s) {
                match f(m) {
                    Some(v) => write_frame(&mut s, &v).unwrap(),
                    None => std::thread::sleep(Duration::from_secs(2)),
                }
            }
        })
    }

    #[test]
    fn refuses_dir_owned_by_other_uid() {
        let d = dir_0755();
        let l = UnixListener::bind(d.path().join(SOCKET_NAME)).unwrap();
        l.set_nonblocking(true).unwrap();
        let r = Client::connect(d.path(), me() + 1, dl(500));
        assert!(matches!(r, Err(ClientError::Owner { .. })));
        assert!(l.accept().is_err(), "listener must never be connected to");
    }

    /// A root-owned socket dir is accepted, as the daemon accepts it (M2):
    /// the check gets past `/` to the (missing) socket.
    #[test]
    fn accepts_root_owned_dir() {
        // In a user namespace that maps only the current user
        // (scripts/test-offline.sh), root's files show the overflow uid:
        // there is no root-owned dir to test with.
        if std::fs::metadata("/").unwrap().uid() != 0 {
            eprintln!("skipped: / is not owned by uid 0 here (user namespace)");
            return;
        }
        let r = check_owner(Path::new("/"), &Path::new("/").join(SOCKET_NAME), me());
        match r {
            Err(ClientError::Owner { path, .. }) => assert_eq!(path, Path::new("/saiife.sock")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn refuses_group_writable_dir() {
        let d = dir_0755();
        let _l = UnixListener::bind(d.path().join(SOCKET_NAME)).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
        let r = Client::connect(d.path(), me(), dl(500));
        assert!(matches!(r, Err(ClientError::Owner { .. })));
    }

    #[test]
    fn refuses_regular_file_as_socket() {
        let d = dir_0755();
        std::fs::write(d.path().join(SOCKET_NAME), b"x").unwrap();
        let r = Client::connect(d.path(), me(), dl(500));
        assert!(matches!(r, Err(ClientError::Owner { .. })));
    }

    #[test]
    fn hello_then_call_round_trip() {
        let d = dir_0755();
        let h = fake(d.path(), |m| {
            Some(json!({"id":m["id"],"ok":true,"echo":m["op"]}))
        });
        let mut c = Client::connect(d.path(), me(), dl(2000)).unwrap();
        assert_eq!(c.hello_answer()["extra"], "x");
        let a = c.call("status", Map::new(), dl(2000)).unwrap();
        assert_eq!(a["echo"], "status");
        let a = c.call("status", Map::new(), dl(2000)).unwrap();
        assert_eq!(a["id"], 3);
        drop(c);
        h.join().unwrap();
    }

    #[test]
    fn answer_id_mismatch_is_protocol_error() {
        let d = dir_0755();
        let _h = fake(d.path(), |_| Some(json!({"id":99,"ok":true})));
        let mut c = Client::connect(d.path(), me(), dl(2000)).unwrap();
        let r = c.call("status", Map::new(), dl(2000));
        assert!(matches!(r, Err(ClientError::Protocol(_))));
    }

    #[test]
    fn silent_server_times_out() {
        let d = dir_0755();
        let _h = fake(d.path(), |_| None);
        let mut c = Client::connect(d.path(), me(), dl(2000)).unwrap();
        let t = Instant::now();
        let r = c.call("status", Map::new(), dl(200));
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn refused_answer_maps_code() {
        let d = dir_0755();
        let _h = fake(d.path(), |m| {
            Some(json!({"id":m["id"],"ok":false,"error":"busy","message":"m"}))
        });
        let mut c = Client::connect(d.path(), me(), dl(2000)).unwrap();
        match c.call("status", Map::new(), dl(2000)) {
            Err(ClientError::Refused { code, message }) => {
                assert_eq!((code.as_str(), message.as_str()), ("busy", "m"))
            }
            o => panic!("{o:?}"),
        }
    }

    /// Accepts one connection and answers hello with `reply`.
    fn fake_hello(d: &std::path::Path, reply: Value) {
        let l = UnixListener::bind(d.join(SOCKET_NAME)).unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let h = read_frame(&mut s).unwrap();
            let mut r = reply;
            r["id"] = h["id"].clone();
            let _ = write_frame(&mut s, &r);
            std::thread::sleep(Duration::from_millis(300));
        });
    }

    #[test]
    fn hello_proto_mismatch_is_protocol_error() {
        let d = dir_0755();
        fake_hello(d.path(), json!({"ok":true,"proto":2}));
        let r = Client::connect(d.path(), me(), dl(2000));
        assert!(matches!(r, Err(ClientError::Protocol(_))), "{r:?}");
    }

    #[test]
    fn refuses_symlinked_socket_dir() {
        let d = dir_0755();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _l = UnixListener::bind(real.join(SOCKET_NAME)).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let r = Client::connect(&link, me(), dl(500));
        assert!(matches!(r, Err(ClientError::Owner { .. })), "{r:?}");
    }

    #[test]
    fn refuses_symlinked_socket() {
        let d = dir_0755();
        let other = tempfile::tempdir().unwrap();
        let _l = UnixListener::bind(other.path().join("s")).unwrap();
        std::os::unix::fs::symlink(other.path().join("s"), d.path().join(SOCKET_NAME)).unwrap();
        let r = Client::connect(d.path(), me(), dl(500));
        assert!(matches!(r, Err(ClientError::Owner { .. })), "{r:?}");
    }

    #[test]
    fn refuses_world_writable_dir() {
        let d = dir_0755();
        let _l = UnixListener::bind(d.path().join(SOCKET_NAME)).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o757)).unwrap();
        let r = Client::connect(d.path(), me(), dl(500));
        assert!(matches!(r, Err(ClientError::Owner { .. })), "{r:?}");
    }

    #[test]
    fn slow_drip_server_cannot_outlast_the_deadline() {
        let d = dir_0755();
        let l = UnixListener::bind(d.path().join(SOCKET_NAME)).unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let h = read_frame(&mut s).unwrap();
            let b = crate::frame::encode(&json!({"id":h["id"],"ok":true,"proto":1})).unwrap();
            for byte in b {
                if s.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        let t = Instant::now();
        let r = Client::connect(d.path(), me(), dl(1000));
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(
            t.elapsed() < Duration::from_millis(1500),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn full_backlog_connect_times_out() {
        use rustix::net::{bind, listen, socket, AddressFamily, SocketAddrUnix, SocketType};
        let d = dir_0755();
        let path = d.path().join(SOCKET_NAME);
        let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None).unwrap();
        bind(&fd, &SocketAddrUnix::new(&path).unwrap()).unwrap();
        listen(&fd, 0).unwrap();
        // Fill the backlog with connections that are never accepted.
        let mut fillers = Vec::new();
        for _ in 0..8 {
            let f = rustix::net::socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                rustix::net::SocketFlags::NONBLOCK,
                None,
            )
            .unwrap();
            let _ = rustix::net::connect(&f, &SocketAddrUnix::new(&path).unwrap());
            fillers.push(f);
        }
        let t = Instant::now();
        let r = Client::connect(d.path(), me(), dl(300));
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn expired_deadline_times_out_before_connecting() {
        let d = dir_0755();
        let l = UnixListener::bind(d.path().join(SOCKET_NAME)).unwrap();
        l.set_nonblocking(true).unwrap();
        let r = Client::connect(d.path(), me(), Instant::now());
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(l.accept().is_err());
    }

    #[test]
    fn client_is_poisoned_after_timeout() {
        let d = dir_0755();
        let _h = fake(d.path(), |_| None);
        let mut c = Client::connect(d.path(), me(), dl(2000)).unwrap();
        assert!(matches!(
            c.call("status", Map::new(), dl(100)),
            Err(ClientError::Timeout)
        ));
        match c.call("status", Map::new(), dl(2000)) {
            Err(ClientError::Protocol(m)) => assert!(m.contains("unusable")),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn refusal_with_id_keeps_client_usable() {
        let d = dir_0755();
        let _h = fake(d.path(), |m| {
            Some(json!({"id":m["id"],"ok":false,"error":"busy","message":"m"}))
        });
        let mut c = Client::connect(d.path(), me(), dl(2000)).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                c.call("status", Map::new(), dl(2000)),
                Err(ClientError::Refused { .. })
            ));
        }
    }

    #[test]
    fn idless_refusal_maps_to_refused() {
        let d = dir_0755();
        let _h = fake(d.path(), |_| {
            Some(json!({"id":0,"ok":false,"error":"bad_frame","message":"nope"}))
        });
        let mut c = Client::connect(d.path(), me(), dl(2000)).unwrap();
        match c.call("status", Map::new(), dl(2000)) {
            Err(ClientError::Refused { code, message }) => {
                assert_eq!((code.as_str(), message.as_str()), ("bad_frame", "nope"))
            }
            o => panic!("{o:?}"),
        }
        assert!(matches!(
            c.call("status", Map::new(), dl(2000)),
            Err(ClientError::Protocol(_))
        ));
    }

    #[test]
    fn entry_by_uid_parses_passwd() {
        let p = "root:x:0:0::/root:/bin/sh\nbad:x:5\nme:x:1000:1000:Me:/home/me:/bin/bash\n";
        assert_eq!(
            entry_by_uid(p, 1000),
            Some(PasswdEntry {
                name: "me".into(),
                home: "/home/me".into()
            })
        );
        assert_eq!(entry_by_uid(p, 0).unwrap().home, PathBuf::from("/root"));
        assert_eq!(entry_by_uid(p, 5), None);
        assert_eq!(entry_by_uid(p, 4242), None);
    }

    #[test]
    fn entry_by_name_parses_passwd() {
        let p = "root:x:0:0::/root:/bin/sh\nbad:x:5\nme:x:1000:1000:Me:/home/me:/bin/bash\n\
                 me:x:1001:1001::/home/me2:/bin/sh\n";
        assert_eq!(
            entry_by_name(p, "me"),
            Some(PasswdEntry {
                name: "me".into(),
                home: "/home/me".into()
            })
        );
        assert_eq!(
            entry_by_name(p, "root").unwrap().home,
            PathBuf::from("/root")
        );
        assert_eq!(entry_by_name(p, "bad"), None);
        assert_eq!(entry_by_name(p, ""), None);
        assert_eq!(entry_by_name(p, "nobody"), None);
    }

    #[test]
    fn uid_by_name_parses_passwd() {
        let p = "root:x:0:0::/root:/bin/sh\nsaiife:x:991:991::/:/usr/sbin/nologin\n";
        assert_eq!(uid_by_name(p, "saiife"), Some(991));
        assert_eq!(uid_by_name(p, "nobody"), None);
    }
}
