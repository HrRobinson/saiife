//! Blocking client for the control socket, used by the managed hook.
use crate::frame::{read_frame, write_frame, FrameError};
use crate::msg::{OP_HELLO, PROTO, SOCKET_NAME};
use serde_json::{Map, Value};
use std::io;
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
    if dm.uid() != uid {
        return Err(owner_err(
            dir,
            format!("owned by uid {}, expected {uid}", dm.uid()),
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

fn set_timeouts(s: &UnixStream, deadline: Instant) -> Result<(), ClientError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left < Duration::from_millis(1) {
        return Err(ClientError::Timeout);
    }
    s.set_read_timeout(Some(left))
        .map_err(ClientError::Connect)?;
    s.set_write_timeout(Some(left))
        .map_err(ClientError::Connect)?;
    Ok(())
}

impl Client {
    pub fn connect(
        socket_dir: &Path,
        daemon_uid: u32,
        deadline: Instant,
    ) -> Result<Client, ClientError> {
        let sock = socket_dir.join(SOCKET_NAME);
        check_owner(socket_dir, &sock, daemon_uid)?;
        let stream = UnixStream::connect(&sock).map_err(ClientError::Connect)?;
        let mut c = Client {
            stream,
            next_id: 1,
            hello: Map::new(),
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
        set_timeouts(&self.stream, deadline)?;
        let id = self.next_id;
        self.next_id += 1;
        let req = crate::msg::Request {
            id,
            op: op.to_string(),
            args,
        };
        write_frame(&mut self.stream, &req.to_value())?;
        let ans = read_frame(&mut self.stream)?;
        if ans.get("id").and_then(Value::as_u64) != Some(id) {
            return Err(ClientError::Protocol(format!("answer id is not {id}")));
        }
        match ans.get("ok").and_then(Value::as_bool) {
            Some(true) => Ok(ans),
            Some(false) => {
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

    #[test]
    fn uid_by_name_parses_passwd() {
        let p = "root:x:0:0::/root:/bin/sh\nsaiife:x:991:991::/:/usr/sbin/nologin\n";
        assert_eq!(uid_by_name(p, "saiife"), Some(991));
        assert_eq!(uid_by_name(p, "nobody"), None);
    }
}
