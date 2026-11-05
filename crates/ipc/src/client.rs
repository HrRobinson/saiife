//! Blocking client for the control channel, used by the managed hook: a unix socket, or
//! a named pipe on Windows.
use crate::frame::{read_frame_max, write_frame, FrameError, MAX_ANSWER_FRAME};
#[cfg(unix)]
use crate::msg::SOCKET_NAME;
use crate::msg::{OP_HELLO, PROTO};
#[cfg(unix)]
use rustix::event::{poll, PollFd, PollFlags};
#[cfg(unix)]
use rustix::io::Errno;
#[cfg(unix)]
use rustix::net::{AddressFamily, SocketAddrUnix, SocketType};
use serde_json::{Map, Value};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
#[cfg(unix)]
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
enum Transport {
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(any(windows, test))]
    Pipe(pipe_io::PipeIo),
}

#[derive(Debug)]
pub struct Client {
    stream: Transport,
    next_id: u64,
    hello: Map<String, Value>,
    /// The first error that left the stream out of step, as text: every
    /// later call reports it.
    poisoned: Option<String>,
}

fn owner_err(path: &Path, detail: impl Into<String>) -> ClientError {
    ClientError::Owner {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}

#[cfg(unix)]
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

/// Stream wrapper that holds every read and write to the deadline, so it bounds the
/// whole call even when the peer sends one byte at a time: a socket's timeouts are
/// re-armed each time, and a pipe's I/O is waited for from outside.
struct Bounded<'a> {
    s: &'a mut Transport,
    deadline: Instant,
}

impl Read for Bounded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut *self.s {
            #[cfg(unix)]
            Transport::Unix(s) => {
                let left = remaining(self.deadline).ok_or_else(timed_out)?;
                s.set_read_timeout(Some(left))?;
                s.read(buf)
            }
            #[cfg(any(windows, test))]
            Transport::Pipe(p) => p.read(buf, self.deadline),
        }
    }
}

impl Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut *self.s {
            #[cfg(unix)]
            Transport::Unix(s) => {
                let left = remaining(self.deadline).ok_or_else(timed_out)?;
                s.set_write_timeout(Some(left))?;
                s.write(buf)
            }
            #[cfg(any(windows, test))]
            Transport::Pipe(p) => p.write(buf, self.deadline),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A pipe handle has no timeouts, so one thread does its I/O and the caller waits for
/// the answer until the deadline.
///
/// One thread, one operation at a time, on purpose. The handle is synchronous, and
/// Windows runs a file object's I/O one call at a time: a read pending on another thread
/// would hold every write back until an answer came, and no answer comes to a request
/// that was never sent. The protocol takes turns anyway.
#[cfg(any(windows, test))]
mod pipe_io {
    use super::{remaining, timed_out};
    use std::io::{self, Read, Write};
    use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
    use std::time::Instant;

    /// The most one read asks of the thread.
    const CHUNK: usize = 64 * 1024;

    enum Op {
        Read(usize),
        Write(Vec<u8>),
    }

    enum Done {
        Read(Vec<u8>),
        Wrote(usize),
    }

    pub(super) struct PipeIo {
        ops: Sender<Op>,
        done: Receiver<io::Result<Done>>,
        /// An operation outlived its deadline and may still be pending, so its answer
        /// would be taken for the next one's. Nothing more goes through.
        stuck: bool,
    }

    impl std::fmt::Debug for PipeIo {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PipeIo")
                .field("stuck", &self.stuck)
                .finish()
        }
    }

    impl PipeIo {
        /// Hands `stream` to its thread. The thread ends, and the stream closes, when
        /// this drops; if an operation is stuck by then, at process exit.
        pub(super) fn spawn<T: Read + Write + Send + 'static>(mut stream: T) -> io::Result<PipeIo> {
            let (ops, op_rx) = channel::<Op>();
            let (done_tx, done) = channel();
            std::thread::Builder::new()
                .name("saiife-pipe-io".into())
                .spawn(move || {
                    while let Ok(op) = op_rx.recv() {
                        let r = match op {
                            Op::Read(n) => {
                                let mut b = vec![0u8; n];
                                stream.read(&mut b).map(|got| {
                                    b.truncate(got);
                                    Done::Read(b)
                                })
                            }
                            Op::Write(b) => stream.write(&b).map(Done::Wrote),
                        };
                        if done_tx.send(r).is_err() {
                            break;
                        }
                    }
                })?;
            Ok(PipeIo {
                ops,
                done,
                stuck: false,
            })
        }

        fn run(&mut self, op: Op, deadline: Instant) -> io::Result<Done> {
            if self.stuck {
                return Err(timed_out());
            }
            let left = remaining(deadline).ok_or_else(timed_out)?;
            self.ops
                .send(op)
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            match self.done.recv_timeout(left) {
                Ok(r) => r,
                Err(RecvTimeoutError::Timeout) => {
                    self.stuck = true;
                    Err(timed_out())
                }
                Err(RecvTimeoutError::Disconnected) => {
                    Err(io::Error::from(io::ErrorKind::BrokenPipe))
                }
            }
        }

        pub(super) fn read(&mut self, buf: &mut [u8], deadline: Instant) -> io::Result<usize> {
            match self.run(Op::Read(buf.len().min(CHUNK)), deadline)? {
                Done::Read(b) => {
                    buf[..b.len()].copy_from_slice(&b);
                    Ok(b.len())
                }
                Done::Wrote(_) => Err(io::Error::other("a write's answer to a read")),
            }
        }

        pub(super) fn write(&mut self, buf: &[u8], deadline: Instant) -> io::Result<usize> {
            match self.run(Op::Write(buf.to_vec()), deadline)? {
                Done::Wrote(n) => Ok(n),
                Done::Read(_) => Err(io::Error::other("a read's answer to a write")),
            }
        }
    }
}

/// Opening a pipe and reading its owner, as Windows does it.
#[cfg(any(windows, test))]
trait PipeOpen {
    type Stream: Read + Write + Send + 'static;
    fn open(&self) -> io::Result<Self::Stream>;
    /// The owner of the pipe behind this very handle, as a SID.
    fn owner_sid(&self, stream: &Self::Stream) -> io::Result<String>;
}

/// How long to wait before opening a busy pipe again (W11).
#[cfg(any(windows, test))]
const PIPE_BUSY_RETRY: Duration = Duration::from_millis(10);

/// Opens the pipe, and sends the hello only once the owner of the instance it reached is
/// `expect_owner`. A name proves nothing, since anyone can create a free pipe name; what
/// a squatter never sees is a byte of ours. The owner is read from the open handle, so
/// nothing can swap the pipe between the check and the first write.
#[cfg(any(windows, test))]
fn connect_pipe_via<O: PipeOpen>(
    opener: &O,
    name: &str,
    expect_owner: &str,
    deadline: Instant,
) -> Result<Client, ClientError> {
    let path = Path::new(name);
    let stream = loop {
        let left = remaining(deadline).ok_or(ClientError::Timeout)?;
        match opener.open() {
            Ok(s) => break s,
            Err(e) if e.raw_os_error() == Some(saiife_win::pipe::ERROR_PIPE_BUSY) => {
                std::thread::sleep(left.min(PIPE_BUSY_RETRY));
            }
            Err(e) => return Err(ClientError::Connect(e)),
        }
    };
    let owner = opener
        .owner_sid(&stream)
        .map_err(|e| owner_err(path, format!("cannot read the pipe's owner: {e}")))?;
    saiife_win::pipe::check_owner(&owner, expect_owner).map_err(|d| owner_err(path, d))?;
    let io = pipe_io::PipeIo::spawn(stream).map_err(ClientError::Connect)?;
    Client::handshake(Transport::Pipe(io), deadline)
}

#[cfg(windows)]
struct RealPipe<'a>(&'a str);

#[cfg(windows)]
impl PipeOpen for RealPipe<'_> {
    type Stream = std::fs::File;

    fn open(&self) -> io::Result<std::fs::File> {
        saiife_win::ffi::pipe::open_client(self.0)
    }

    fn owner_sid(&self, stream: &std::fs::File) -> io::Result<String> {
        saiife_win::ffi::pipe::owner_sid(stream)
    }
}

/// The SID that owns the system daemon's pipe: the service's own (W10).
#[cfg(any(windows, test))]
pub fn system_sid() -> String {
    saiife_win::sid::service_sid("saiifed")
}

#[cfg(unix)]
fn errno_io(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

/// A close-on-exec, non-blocking unix stream socket.
#[cfg(all(unix, not(target_os = "macos")))]
fn nonblocking_stream() -> Result<OwnedFd, Errno> {
    rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
}

/// macOS has no `SOCK_CLOEXEC` or `SOCK_NONBLOCK`: the flags are set right
/// after `socket`, as std's own `UnixStream::connect` does there.
#[cfg(target_os = "macos")]
fn nonblocking_stream() -> Result<OwnedFd, Errno> {
    let fd = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    rustix::io::ioctl_fionbio(&fd, true)?;
    Ok(fd)
}

/// Non-blocking connect bounded by `deadline`; the returned stream is blocking.
#[cfg(unix)]
fn connect_by(path: &Path, deadline: Instant) -> Result<UnixStream, ClientError> {
    let addr = SocketAddrUnix::new(path).map_err(|e| ClientError::Connect(errno_io(e)))?;
    let fd = nonblocking_stream().map_err(|e| ClientError::Connect(errno_io(e)))?;
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
    #[cfg(unix)]
    pub fn connect(
        socket_dir: &Path,
        daemon_uid: u32,
        deadline: Instant,
    ) -> Result<Client, ClientError> {
        let sock = socket_dir.join(SOCKET_NAME);
        check_owner(socket_dir, &sock, daemon_uid)?;
        let stream = connect_by(&sock, deadline)?;
        // Closes the check-then-connect race: whoever answers must be the daemon.
        let pc = crate::peer::peer_cred(&stream).map_err(ClientError::Connect)?;
        if pc.uid != daemon_uid {
            return Err(owner_err(
                &sock,
                format!("peer is uid {}, expected {daemon_uid}", pc.uid),
            ));
        }
        Client::handshake(Transport::Unix(stream), deadline)
    }

    /// Connects to the named pipe `name`, which must be owned by `expect_owner`:
    /// [`system_sid`] for the system daemon, the user's own SID for the personal broker.
    /// Another owner is [`ClientError::Owner`], before a byte is sent. `ERROR_PIPE_BUSY`
    /// is retried until the deadline, which also bounds every read and write.
    #[cfg(windows)]
    pub fn connect_pipe(
        name: &str,
        expect_owner: &str,
        deadline: Instant,
    ) -> Result<Client, ClientError> {
        connect_pipe_via(&RealPipe(name), name, expect_owner, deadline)
    }

    /// The hello that every new connection starts with.
    fn handshake(stream: Transport, deadline: Instant) -> Result<Client, ClientError> {
        let mut c = Client {
            stream,
            next_id: 1,
            hello: Map::new(),
            poisoned: None,
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
        self.usable()?;
        let r = self.exchange(op, args, deadline, false);
        if let Err(e) = &r {
            // A refusal that answers our id leaves the stream in step
            // (`exchange` poisons on one that does not).
            if !matches!(e, ClientError::Refused { .. }) || self.poisoned.is_some() {
                self.poison(e);
            }
        }
        r
    }

    /// Whether an earlier error left this connection unusable.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    /// `Err` naming the first error once the connection is unusable.
    fn usable(&self) -> Result<(), ClientError> {
        match &self.poisoned {
            Some(first) => Err(ClientError::Protocol(format!(
                "connection unusable after an earlier error ({first})"
            ))),
            None => Ok(()),
        }
    }

    /// Mark the connection unusable; the first error is kept.
    fn poison(&mut self, e: &ClientError) {
        if self.poisoned.is_none() {
            self.poisoned = Some(e.to_string());
        }
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
        self.usable()?;
        let r = self.exchange(op, args, deadline, true);
        if let Err(e) = &r {
            self.poison(e);
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
            s: &mut self.stream,
            deadline,
        };
        write_frame(&mut io, &req.to_value())?;
        let ans = read_frame_max(&mut io, MAX_ANSWER_FRAME)?;
        let id_ok = ans.get("id").and_then(Value::as_u64) == Some(id);
        match ans.get("ok").and_then(Value::as_bool) {
            Some(false) if keep_refusal && id_ok => Ok(ans),
            Some(false) => {
                // Includes id-less answers such as the daemon's `bad_frame`.
                let s = |k: &str| {
                    ans.get(k)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                };
                let e = ClientError::Refused {
                    code: s("error"),
                    message: s("message"),
                };
                if !id_ok {
                    self.poison(&e);
                }
                Err(e)
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

/// Linux reads `/etc/passwd` directly: the daemon user is a local system
/// user, so no NSS lookup (and no helper process) happens on the hook path.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn system_uid(name: &str) -> Option<u32> {
    uid_by_name(&std::fs::read_to_string("/etc/passwd").ok()?, name)
}

/// macOS asks Directory Services (`getpwnam_r`): a user created with `dscl`
/// is not in `/etc/passwd`.
#[cfg(target_os = "macos")]
pub fn system_uid(name: &str) -> Option<u32> {
    if name.is_empty() {
        return None;
    }
    let u = nix::unistd::User::from_name(name).ok()??;
    Some(u.uid.as_raw())
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
#[cfg(all(unix, not(target_os = "macos")))]
pub fn system_entry(uid: u32) -> Option<PasswdEntry> {
    entry_by_uid(&std::fs::read_to_string("/etc/passwd").ok()?, uid)
}

/// The Directory Services entry of `uid` (`getpwuid_r`), as `system_uid`.
#[cfg(target_os = "macos")]
pub fn system_entry(uid: u32) -> Option<PasswdEntry> {
    let u = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()??;
    (u.uid.as_raw() == uid && !u.name.is_empty()).then_some(PasswdEntry {
        name: u.name,
        home: u.dir,
    })
}

/// The pipe's rules, against a scripted stream: they run on every OS.
#[cfg(test)]
mod pipe_tests {
    use super::*;
    use crate::frame::{encode, read_frame};
    use saiife_win::pipe::ERROR_PIPE_BUSY;
    use serde_json::json;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const NAME: &str = r"\\.\pipe\saiife";
    const AGENT: &str = "S-1-5-21-1-2-3-1001";

    fn dl(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    /// The server's side of a scripted pipe: what the client wrote, what it will read.
    #[derive(Default)]
    struct Script {
        written: Arc<Mutex<Vec<u8>>>,
        reply: Vec<u8>,
        /// Reads hang, as with a server that accepted and went silent.
        silent: bool,
        /// Writes hang, as with a server that never reads and a full buffer.
        write_hangs: bool,
        /// Sent a byte at a time, this far apart.
        drip: Option<Duration>,
    }

    struct Stream {
        written: Arc<Mutex<Vec<u8>>>,
        reply: VecDeque<u8>,
        silent: bool,
        write_hangs: bool,
        drip: Option<Duration>,
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.silent {
                std::thread::sleep(Duration::from_secs(30));
            }
            if let Some(gap) = self.drip {
                std::thread::sleep(gap);
                let Some(b) = self.reply.pop_front() else {
                    return Ok(0);
                };
                buf[0] = b;
                return Ok(1);
            }
            let n = buf.len().min(self.reply.len());
            for (slot, b) in buf.iter_mut().zip(self.reply.drain(..n)) {
                *slot = b;
            }
            Ok(n)
        }
    }

    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.write_hangs {
                std::thread::sleep(Duration::from_secs(30));
            }
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The pipe namespace, for one name.
    struct Fake {
        script: Script,
        owner: io::Result<String>,
        busy_for: Cell<u32>,
        opens: Cell<u32>,
        open_err: Option<i32>,
    }

    fn fake(owner: &str, reply: Vec<u8>) -> Fake {
        Fake {
            script: Script {
                reply,
                ..Script::default()
            },
            owner: Ok(owner.to_string()),
            busy_for: Cell::new(0),
            opens: Cell::new(0),
            open_err: None,
        }
    }

    impl PipeOpen for Fake {
        type Stream = Stream;

        fn open(&self) -> io::Result<Stream> {
            self.opens.set(self.opens.get() + 1);
            if let Some(code) = self.open_err {
                return Err(io::Error::from_raw_os_error(code));
            }
            if self.busy_for.get() > 0 {
                self.busy_for.set(self.busy_for.get() - 1);
                return Err(io::Error::from_raw_os_error(ERROR_PIPE_BUSY));
            }
            Ok(Stream {
                written: self.script.written.clone(),
                reply: self.script.reply.iter().copied().collect(),
                silent: self.script.silent,
                write_hangs: self.script.write_hangs,
                drip: self.script.drip,
            })
        }

        fn owner_sid(&self, _: &Stream) -> io::Result<String> {
            match &self.owner {
                Ok(o) => Ok(o.clone()),
                Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error().unwrap_or(5))),
            }
        }
    }

    fn hello_reply() -> Vec<u8> {
        encode(&json!({"id":1,"ok":true,"proto":PROTO,"extra":"x"})).unwrap()
    }

    fn sent(f: &Fake) -> Vec<u8> {
        f.script.written.lock().unwrap().clone()
    }

    #[test]
    fn hello_goes_to_the_right_owner_only() {
        let s = system_sid();
        let f = fake(&s, hello_reply());
        let c = connect_pipe_via(&f, NAME, &s, dl(2000)).unwrap();
        assert_eq!(c.hello_answer()["extra"], "x");
        assert!(!c.is_poisoned());
        let frame = read_frame(&mut sent(&f).as_slice()).unwrap();
        assert_eq!(frame["op"], "hello");
        assert_eq!(frame["proto"], PROTO);
    }

    /// The squatter: the right name, the agent's pipe. Not a byte reaches it.
    #[test]
    fn foreign_owner_is_refused_before_a_byte_is_sent() {
        let f = fake(AGENT, hello_reply());
        let r = connect_pipe_via(&f, NAME, &system_sid(), dl(2000));
        match r {
            Err(ClientError::Owner { path, detail }) => {
                assert_eq!(path, Path::new(NAME));
                assert!(detail.contains(AGENT), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        assert!(sent(&f).is_empty());
    }

    #[test]
    fn unreadable_owner_is_refused_before_a_byte_is_sent() {
        let mut f = fake(AGENT, hello_reply());
        f.owner = Err(io::Error::from_raw_os_error(5));
        let r = connect_pipe_via(&f, NAME, &system_sid(), dl(2000));
        assert!(matches!(r, Err(ClientError::Owner { .. })), "{r:?}");
        assert!(sent(&f).is_empty());
    }

    /// The personal broker's pipe is owned by the user: right for the user's own
    /// broker, wrong for the system daemon.
    #[test]
    fn same_name_different_expected_owner() {
        let f = fake(AGENT, hello_reply());
        connect_pipe_via(&f, NAME, AGENT, dl(2000)).unwrap();
        let f = fake(AGENT, hello_reply());
        assert!(matches!(
            connect_pipe_via(&f, NAME, &system_sid(), dl(2000)),
            Err(ClientError::Owner { .. })
        ));
        assert!(sent(&f).is_empty());
    }

    #[test]
    fn busy_pipe_is_retried() {
        let s = system_sid();
        let f = fake(&s, hello_reply());
        f.busy_for.set(3);
        connect_pipe_via(&f, NAME, &s, dl(2000)).unwrap();
        assert_eq!(f.opens.get(), 4);
    }

    #[test]
    fn busy_pipe_is_retried_until_the_deadline() {
        let s = system_sid();
        let f = fake(&s, hello_reply());
        f.busy_for.set(u32::MAX);
        let t = Instant::now();
        let r = connect_pipe_via(&f, NAME, &s, dl(100));
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(t.elapsed() < Duration::from_millis(500));
        // Every 10 ms, so a handful of tries, not a spin.
        assert!((2..=20).contains(&f.opens.get()), "{}", f.opens.get());
        assert!(sent(&f).is_empty());
    }

    /// A pipe that does not exist is no reason to wait: only a busy one is.
    #[test]
    fn missing_pipe_fails_at_once() {
        let s = system_sid();
        let mut f = fake(&s, hello_reply());
        f.open_err = Some(2);
        let r = connect_pipe_via(&f, NAME, &s, dl(2000));
        assert!(matches!(r, Err(ClientError::Connect(_))), "{r:?}");
        assert_eq!(f.opens.get(), 1);
    }

    #[test]
    fn expired_deadline_never_opens() {
        let s = system_sid();
        let f = fake(&s, hello_reply());
        let r = connect_pipe_via(&f, NAME, &s, Instant::now());
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert_eq!(f.opens.get(), 0);
    }

    #[test]
    fn silent_server_is_bounded() {
        let s = system_sid();
        let mut f = fake(&s, Vec::new());
        f.script.silent = true;
        let t = Instant::now();
        let r = connect_pipe_via(&f, NAME, &s, dl(200));
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    }

    #[test]
    fn server_that_never_reads_is_bounded() {
        let s = system_sid();
        let mut f = fake(&s, Vec::new());
        f.script.write_hangs = true;
        let t = Instant::now();
        let r = connect_pipe_via(&f, NAME, &s, dl(200));
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    }

    #[test]
    fn slow_drip_server_cannot_outlast_the_deadline() {
        let s = system_sid();
        let mut f = fake(&s, hello_reply());
        f.script.drip = Some(Duration::from_millis(100));
        let t = Instant::now();
        let r = connect_pipe_via(&f, NAME, &s, dl(300));
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    }

    /// After a timeout the operation may still be pending, so its late answer must not
    /// be taken for a later call's.
    #[test]
    fn pipe_io_stays_stuck_after_a_timeout() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut io = pipe_io::PipeIo::spawn(Stream {
            written: written.clone(),
            reply: VecDeque::new(),
            silent: true,
            write_hangs: false,
            drip: None,
        })
        .unwrap();
        let mut buf = [0u8; 4];
        let e = io.read(&mut buf, dl(50)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        // A long deadline changes nothing, and fails at once.
        let t = Instant::now();
        let e = io.write(b"late", dl(5000)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(t.elapsed() < Duration::from_millis(100));
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn client_over_a_pipe_is_poisoned_when_the_stream_ends() {
        let s = system_sid();
        // The reply answers the hello only; the next read finds the script empty.
        let f = fake(&s, hello_reply());
        let mut c = connect_pipe_via(&f, NAME, &s, dl(2000)).unwrap();
        // An error, and every later call names it.
        assert!(c.call("status", Map::new(), dl(2000)).is_err());
        assert!(c.is_poisoned());
        assert!(matches!(
            c.call("status", Map::new(), dl(2000)),
            Err(ClientError::Protocol(_))
        ));
    }

    #[test]
    fn hello_proto_mismatch_over_a_pipe_is_a_protocol_error() {
        let s = system_sid();
        let f = fake(&s, encode(&json!({"id":1,"ok":true,"proto":2})).unwrap());
        let r = connect_pipe_via(&f, NAME, &s, dl(2000));
        assert!(matches!(r, Err(ClientError::Protocol(_))), "{r:?}");
    }

    #[test]
    fn system_sid_is_the_saiifed_service() {
        assert_eq!(
            system_sid(),
            "S-1-5-80-1485410291-497971702-176010752-1662630379-411534723"
        );
    }
}

/// These run in CI on windows-latest, with no admin rights assumed: no Windows machine
/// builds this crate locally. Each server belongs to its test, with the runner's own SID
/// as the pipe's owner.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use crate::frame::{body_len, decode, encode};
    use saiife_win::ffi::pipe::create_server;
    use saiife_win::ffi::token;
    use saiife_win::sid::SYSTEM;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::NamedPipeServer;
    use tokio::task::spawn_blocking;

    fn unique_name(test: &str) -> String {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        format!(
            r"\\.\pipe\saiife-test-ipc-{}-{n}-{test}",
            std::process::id()
        )
    }

    fn me() -> String {
        token::current().unwrap().sid
    }

    /// The runner may add instances, as the service may on the control pipe.
    fn full_sddl(sid: &str) -> String {
        format!("O:{sid}G:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)")
    }

    /// As a client, the runner holds only what Users hold on the control pipe.
    fn users_sddl(sid: &str) -> String {
        format!("O:{sid}G:{sid}D:P(A;;0x12019b;;;{sid})(A;;GA;;;SY)")
    }

    fn dl(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    async fn read_one(s: &mut NamedPipeServer) -> Map<String, Value> {
        let mut h = [0u8; 4];
        s.read_exact(&mut h).await.unwrap();
        let mut body = vec![0u8; body_len(h).unwrap()];
        s.read_exact(&mut body).await.unwrap();
        decode(&body).unwrap()
    }

    /// Answers one hello; returns the identity it saw.
    async fn answer_hello(mut s: NamedPipeServer) -> (crate::peer::PeerCred, NamedPipeServer) {
        s.connect().await.unwrap();
        let peer = crate::peer::pipe_peer(&s).unwrap();
        let h = read_one(&mut s).await;
        assert_eq!(h["op"], "hello");
        let a = encode(&json!({"id":h["id"],"ok":true,"proto":PROTO})).unwrap();
        s.write_all(&a).await.unwrap();
        (peer, s)
    }

    /// With exactly the rights Users hold: this is the test that the client's open fits
    /// the control pipe's DACL.
    #[tokio::test(flavor = "multi_thread")]
    async fn pipe_roundtrip_hello() {
        let me = me();
        let name = unique_name("hello");
        let server = create_server(&name, &users_sddl(&me), true).unwrap();
        let task = tokio::spawn(async move {
            let (peer, mut s) = answer_hello(server).await;
            let req = read_one(&mut s).await;
            let a = encode(&json!({"id":req["id"],"ok":true,"echo":req["op"]})).unwrap();
            s.write_all(&a).await.unwrap();
            peer
        });
        let (n, o) = (name.clone(), me.clone());
        spawn_blocking(move || {
            let mut c = Client::connect_pipe(&n, &o, dl(5000)).unwrap();
            let a = c.call("status", Map::new(), dl(5000)).unwrap();
            assert_eq!(a["echo"], "status");
        })
        .await
        .unwrap();
        let peer = task.await.unwrap();
        assert_eq!(peer.sid.as_deref(), Some(me.as_str()));
        assert_eq!(peer.pid, std::process::id());
        assert_eq!(peer.gid, 0);
        assert!(!peer.group_sids.is_empty());
    }

    /// `client_refuses_foreign_pipe_owner`: the pipe's owner is not the SID expected. The
    /// client gives up without a write, so the server reads end of stream and no bytes.
    #[tokio::test(flavor = "multi_thread")]
    async fn client_refuses_foreign_pipe_owner() {
        let name = unique_name("foreign");
        let mut server = create_server(&name, &full_sddl(&me()), true).unwrap();
        let n = name.clone();
        let r = spawn_blocking(move || Client::connect_pipe(&n, SYSTEM, dl(5000)))
            .await
            .unwrap();
        assert!(matches!(r, Err(ClientError::Owner { .. })), "{r:?}");
        // The client has come and gone, which `connect` may report as an error.
        let _ = server.connect().await;
        let mut rest = Vec::new();
        let read = server.read_to_end(&mut rest);
        let _ = tokio::time::timeout(Duration::from_secs(5), read).await;
        assert!(rest.is_empty(), "{rest:?}");
    }

    /// The only instance is taken, so the pipe is busy, until a free one comes.
    #[tokio::test(flavor = "multi_thread")]
    async fn pipe_busy_retried_until_deadline() {
        let me = me();
        let name = unique_name("busy");
        let first = create_server(&name, &full_sddl(&me), true).unwrap();
        let _holder = saiife_win::ffi::pipe::open_client(&name).unwrap();
        first.connect().await.unwrap();

        // Nothing frees up: the deadline ends it.
        let (n, o) = (name.clone(), me.clone());
        let t = Instant::now();
        let r = spawn_blocking(move || Client::connect_pipe(&n, &o, dl(200)))
            .await
            .unwrap();
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());

        // A free instance turns up later: the retry finds it.
        let (n, o) = (name.clone(), me.clone());
        let client = spawn_blocking(move || Client::connect_pipe(&n, &o, dl(10_000)));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let second = create_server(&name, &full_sddl(&me), false).unwrap();
        let _server = answer_hello(second).await;
        client.await.unwrap().unwrap();
    }

    /// The server takes the connection and says nothing. The test drops it at the end.
    #[tokio::test(flavor = "multi_thread")]
    async fn deadline_bounds_a_silent_server() {
        let me = me();
        let name = unique_name("silent");
        let server = create_server(&name, &full_sddl(&me), true).unwrap();
        let (n, o) = (name.clone(), me.clone());
        let t = Instant::now();
        let r = spawn_blocking(move || Client::connect_pipe(&n, &o, dl(200)))
            .await
            .unwrap();
        assert!(matches!(r, Err(ClientError::Timeout)), "{r:?}");
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        drop(server);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn missing_pipe_is_a_connect_error() {
        let name = unique_name("missing");
        let r = Client::connect_pipe(&name, &me(), dl(1000));
        assert!(matches!(r, Err(ClientError::Connect(_))), "{r:?}");
    }

    #[test]
    fn remote_name_is_refused_without_opening() {
        let r = Client::connect_pipe(r"\\evil\pipe\saiife", &me(), dl(1000));
        match r {
            Err(ClientError::Connect(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
            other => panic!("{other:?}"),
        }
    }
}

#[cfg(all(test, unix))]
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

    /// Linux only: a full unix-socket backlog makes a non-blocking connect
    /// wait (`EAGAIN`) there, while BSD kernels refuse it at once.
    #[cfg(target_os = "linux")]
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
        assert!(c.is_poisoned());
        // Every later call names the first error, not only "unusable".
        for _ in 0..2 {
            match c.call("status", Map::new(), dl(2000)) {
                Err(ClientError::Protocol(m)) => {
                    assert_eq!(m, "connection unusable after an earlier error (timeout)")
                }
                o => panic!("{o:?}"),
            }
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
    fn system_uid_of_root_is_0() {
        assert_eq!(system_uid("root"), Some(0));
        assert_eq!(system_uid(""), None);
        assert_eq!(system_entry(0).unwrap().name, "root");
    }

    /// `/var` is a root-owned link to `private/var` on macOS: the owner
    /// check passes through either spelling, and a client connects through
    /// the `/var` one. The dir is made under `/private/var/tmp` explicitly
    /// (short name: the socket path stays under 104 bytes), so the test
    /// always runs, whatever `TMPDIR` is.
    #[cfg(target_os = "macos")]
    #[test]
    fn client_accepts_socket_dir_behind_var_link() {
        let d = tempfile::Builder::new()
            .prefix("p13-")
            .rand_bytes(6)
            .tempdir_in("/private/var/tmp")
            .unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let real = d.path().canonicalize().unwrap();
        let rest = real
            .strip_prefix("/private/var")
            .unwrap_or_else(|_| panic!("{} is not under /private/var", real.display()));
        let via_var = Path::new("/var").join(rest);
        assert_eq!(via_var.canonicalize().unwrap(), real);
        let h = fake(&real, |m| Some(json!({"id":m["id"],"ok":true})));
        for dir in [&via_var, &real] {
            check_owner(dir, &dir.join(SOCKET_NAME), me()).unwrap();
        }
        let mut c = Client::connect(&via_var, me(), dl(2000)).unwrap();
        c.call("status", Map::new(), dl(2000)).unwrap();
        drop(c);
        h.join().unwrap();
    }

    #[test]
    fn uid_by_name_parses_passwd() {
        let p = "root:x:0:0::/root:/bin/sh\nsaiife:x:991:991::/:/usr/sbin/nologin\n";
        assert_eq!(uid_by_name(p, "saiife"), Some(991));
        assert_eq!(uid_by_name(p, "nobody"), None);
    }
}
