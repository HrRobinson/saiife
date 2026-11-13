//! Host-side vsock through the Cloud Hypervisor multiplexer.
//!
//! Cloud Hypervisor exposes the guest's vsock as a unix socket in the box
//! directory: the host dials `vsock.sock` and sends `CONNECT <port>\n` to
//! reach a guest listener, and guest-initiated connections arrive on
//! `vsock.sock_<port>`, which the host binds itself. The box directory is
//! writable by the VMM and the guest is untrusted, so every path operation
//! is dirfd-relative and never follows or unlinks anything but a socket.

use crate::paths::BoxPaths;
use saiife_boxproto::ports;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

/// Longest multiplexer answer we accept, newline included.
const MAX_ANSWER: usize = 32;

fn bad_data(m: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}

/// Time left until `deadline`, or a `TimedOut` error.
fn remaining(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "vsock handshake timed out",
        ))
    } else {
        Ok(left)
    }
}

/// `OK <decimal u32>\n` exactly.
fn answer_ok(line: &[u8]) -> bool {
    let Some(num) = line
        .strip_prefix(b"OK ")
        .and_then(|r| r.strip_suffix(b"\n"))
    else {
        return false;
    };
    !num.is_empty()
        && num.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(num).is_ok_and(|n| n.parse::<u32>().is_ok())
}

/// Pin `name` in `dir` (O_PATH, no follow) and require a socket owned by
/// `uid`. Nothing is opened for I/O, so a FIFO cannot block. The returned fd
/// is the exact object that was checked.
fn open_checked(
    dir: &rustix::fd::OwnedFd,
    name: &std::ffi::OsStr,
    uid: u32,
) -> io::Result<rustix::fd::OwnedFd> {
    use rustix::fs::{fstat, openat, FileType, Mode, OFlags};
    let fd = openat(
        dir,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        if e == rustix::io::Errno::LOOP {
            bad_data("vsock.sock is a symlink")
        } else {
            e.into()
        }
    })?;
    let st = fstat(&fd)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Socket {
        return Err(bad_data("vsock.sock is not a socket"));
    }
    if st.st_uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "vsock.sock is not owned by the expected uid",
        ));
    }
    Ok(fd)
}

/// Connect a unix stream socket to the object `target` (an O_PATH fd, reached
/// as `/proc/self/fd/N`, so the path cannot be re-resolved to something else)
/// without ever blocking past `deadline`. A full accept backlog (a wedged
/// VMM) shows up as EAGAIN, which is retried until the deadline. The returned
/// stream is blocking again.
fn connect_fd(target: &rustix::fd::OwnedFd, deadline: Instant) -> io::Result<UnixStream> {
    use rustix::event::{poll, PollFd, PollFlags};
    use rustix::io::Errno;
    use rustix::net::{
        connect, socket_with, sockopt, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
    };
    use std::os::fd::AsRawFd;
    let addr = SocketAddrUnix::new(format!("/proc/self/fd/{}", target.as_raw_fd()))?;
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )?;
    loop {
        match connect(&fd, &addr) {
            Ok(()) => break,
            Err(Errno::INPROGRESS) => {
                let left = remaining(deadline)?;
                let ts = rustix::event::Timespec {
                    tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
                    tv_nsec: i64::from(left.subsec_nanos()),
                };
                let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
                match poll(&mut fds, Some(&ts)) {
                    Ok(_) | Err(Errno::INTR) => {}
                    Err(e) => return Err(e.into()),
                }
                if fds[0].revents().is_empty() {
                    continue;
                }
                sockopt::socket_error(&fd)?.map_err(io::Error::from)?;
                break;
            }
            Err(Errno::AGAIN) | Err(Errno::INTR) => {
                remaining(deadline)?;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e.into()),
        }
    }
    let s = UnixStream::from(fd);
    s.set_nonblocking(false)?;
    Ok(s)
}

/// Connect to a guest listener on `port` through the multiplexer.
///
/// The whole handshake (connect, request, answer) shares one deadline of
/// `HANDSHAKE_TIMEOUT_SECS`, so a peer that trickles bytes cannot extend it.
/// The answer is read byte by byte up to the newline and never past it.
///
/// `vmm_uid` is the uid that must own `vsock.sock` (the daemon's euid in
/// personal mode, the saiife-box uid in locked mode). The entry is pinned
/// with O_PATH|O_NOFOLLOW, checked, and connected to through that fd, so the
/// VMM swapping it for a symlink cannot redirect the connection.
pub fn connect(
    paths: &BoxPaths,
    port: u32,
    timeout: Duration,
    vmm_uid: u32,
) -> io::Result<UnixStream> {
    let deadline = Instant::now() + Duration::from_secs(ports::HANDSHAKE_TIMEOUT_SECS);
    let sock_path = paths.vsock();
    let (dir, name) = open_parent(&sock_path)?;
    let pinned = open_checked(&dir, name, vmm_uid)?;
    let mut s = connect_fd(&pinned, deadline)?;
    drop(pinned);
    s.set_write_timeout(Some(remaining(deadline)?))?;
    s.write_all(format!("CONNECT {port}\n").as_bytes())?;
    let mut buf = [0u8; MAX_ANSWER];
    let mut n = 0;
    loop {
        s.set_read_timeout(Some(remaining(deadline)?))?;
        let mut b = [0u8; 1];
        match s.read(&mut b) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vsock multiplexer closed during handshake",
                ))
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "vsock handshake timed out",
                ))
            }
            Err(e) => return Err(e),
        }
        buf[n] = b[0];
        n += 1;
        if b[0] == b'\n' {
            break;
        }
        if n == MAX_ANSWER {
            return Err(bad_data("vsock multiplexer answer too long"));
        }
    }
    if !answer_ok(&buf[..n]) {
        return Err(bad_data("unexpected vsock multiplexer answer"));
    }
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    Ok(s)
}

/// Open the parent directory (no symlinks, no following) and split off the name.
fn open_parent(path: &Path) -> io::Result<(rustix::fd::OwnedFd, &std::ffi::OsStr)> {
    use rustix::fs::{openat, Mode, OFlags, CWD};
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path has no name"))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir = openat(
        CWD,
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok((dir, name))
}

/// lstat by dirfd: `None` when absent, else whether it is a socket.
fn is_socket(dir: &rustix::fd::OwnedFd, name: &std::ffi::OsStr) -> io::Result<Option<bool>> {
    use rustix::fs::{statat, AtFlags, FileType};
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(
            FileType::from_raw_mode(st.st_mode) == FileType::Socket,
        )),
        Err(e) if e == rustix::io::Errno::NOENT => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Bind the host side of a guest-initiated port at `vsock_port(port)`.
///
/// A stale socket there is replaced; anything else (file, symlink, FIFO,
/// directory) is refused with `AlreadyExists` and left alone. The mode is
/// 0660 when `group_rw`, else 0600.
pub fn listen(paths: &BoxPaths, port: u32, group_rw: bool) -> io::Result<UnixListener> {
    use rustix::fs::{fstat, openat, unlinkat, AtFlags, FileType, Mode, OFlags};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    let path = paths.vsock_port(port);
    let (dir, name) = open_parent(&path)?;
    match is_socket(&dir, name)? {
        None => {}
        Some(true) => match unlinkat(&dir, name, AtFlags::empty()) {
            Ok(()) => {}
            Err(e) if e == rustix::io::Errno::NOENT => {}
            Err(e) => return Err(e.into()),
        },
        Some(false) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "vsock path exists and is not a socket; not removing it",
            ))
        }
    }
    // Bind relative to the dirfd we checked (via /proc, a short path), on a
    // socket whose mode is set first so it is never wider than wanted.
    let mode = if group_rw { 0o660 } else { 0o600 };
    let sock = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    rustix::fs::fchmod(&sock, Mode::from_raw_mode(mode))?;
    let mut rel = std::ffi::OsString::from(format!("/proc/self/fd/{}/", dir.as_raw_fd()));
    rel.push(name);
    rustix::net::bind(&sock, &rustix::net::SocketAddrUnix::new(&rel)?)?;
    rustix::net::listen(&sock, 128)?;
    let listener = UnixListener::from(sock);
    // Pin what is at the name now (O_PATH, no follow) and check it is our
    // fresh socket before chmod, so a swap by the VMM cannot redirect it.
    let fd = openat(
        &dir,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let st = fstat(&fd)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Socket
        || st.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "vsock path is not a socket of ours after bind",
        ));
    }
    // The umask can only have narrowed the pre-bind mode; set it exactly.
    std::fs::set_permissions(
        format!("/proc/self/fd/{}", fd.as_raw_fd()),
        std::fs::Permissions::from_mode(mode),
    )?;
    Ok(listener)
}

/// Remove the host-bound sockets of every guest-initiated port. Only
/// sockets are unlinked; `vsock.sock` itself belongs to the VMM.
pub fn unlink_all(paths: &BoxPaths) {
    unlink_ports(paths, &ports::ALL_HOST_PORTS);
}

/// Remove the host-bound sockets of `ports` only (each owner of listeners
/// unlinks its own). Only sockets are unlinked, never followed.
pub fn unlink_ports(paths: &BoxPaths, ports: &[u32]) {
    use rustix::fs::{unlinkat, AtFlags};
    for &port in ports {
        let path = paths.vsock_port(port);
        let Ok((dir, name)) = open_parent(&path) else {
            continue;
        };
        if let Ok(Some(true)) = is_socket(&dir, name) {
            let _ = unlinkat(&dir, name, AtFlags::empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::{symlink, FileTypeExt, PermissionsExt};
    use std::thread;

    fn setup() -> (tempfile::TempDir, BoxPaths) {
        let t = tempfile::Builder::new().prefix("v").tempdir().unwrap();
        let dir = t.path().join("b1");
        std::fs::create_dir(&dir).unwrap();
        (t, BoxPaths::new(dir))
    }

    /// A fake multiplexer: accepts one connection, reads the request line,
    /// then runs `act` on the stream. Returns the request line.
    fn fake_mux<F>(paths: &BoxPaths, act: F) -> thread::JoinHandle<String>
    where
        F: FnOnce(UnixStream) + Send + 'static,
    {
        let l = UnixListener::bind(paths.vsock()).unwrap();
        thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(s.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            act(s);
            line
        })
    }

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    const T: Duration = Duration::from_secs(5);

    #[test]
    fn connect_handshake_ok() {
        let (_t, p) = setup();
        let h = fake_mux(&p, |mut s| {
            s.write_all(b"OK 1073741824\nrest").unwrap();
            thread::sleep(Duration::from_millis(200));
        });
        let mut s = connect(&p, 5000, T, me()).unwrap();
        assert_eq!(s.read_timeout().unwrap(), Some(T));
        assert_eq!(s.write_timeout().unwrap(), Some(T));
        // Bytes after the newline belong to the stream.
        let mut b = [0u8; 4];
        s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"rest");
        assert_eq!(h.join().unwrap(), "CONNECT 5000\n");
    }

    #[test]
    fn connect_bad_answer_is_error() {
        for ans in [
            &b"garbage\n"[..],
            b"OK x\n",
            b"OK \n",
            b"OK 1 \n",
            b"ok 1\n",
        ] {
            let (_t, p) = setup();
            let h = fake_mux(&p, move |mut s| s.write_all(ans).unwrap());
            let e = connect(&p, 1024, T, me()).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{ans:?}");
            h.join().unwrap();
        }
    }

    #[test]
    fn connect_answer_too_long_is_error() {
        let (_t, p) = setup();
        let h = fake_mux(&p, |mut s| {
            let _ = s.write_all(&[b'A'; 200]);
            let _ = s.write_all(b"\n");
        });
        let e = connect(&p, 1024, T, me()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        h.join().unwrap();
    }

    #[test]
    fn connect_times_out() {
        let (_t, p) = setup();
        let h = fake_mux(&p, |_s| thread::sleep(Duration::from_millis(3000)));
        let t0 = Instant::now();
        let e = connect(&p, 1024, T, me()).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ),
            "{e:?}"
        );
        assert!(t0.elapsed() < Duration::from_millis(2600));
        h.join().unwrap();
    }

    #[test]
    fn connect_trickle_is_bounded() {
        let (_t, p) = setup();
        let h = fake_mux(&p, |mut s| {
            for b in b"OK 1073741824" {
                if s.write_all(&[*b]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(500));
            }
        });
        let t0 = Instant::now();
        let e = connect(&p, 1024, T, me()).unwrap_err();
        assert!(
            t0.elapsed() < Duration::from_millis(2600),
            "{:?}",
            t0.elapsed()
        );
        assert!(matches!(
            e.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        h.join().unwrap();
    }

    #[test]
    fn connect_full_backlog_times_out() {
        use rustix::net::{
            connect as rconnect, socket_with, AddressFamily, SocketAddrUnix, SocketFlags,
            SocketType,
        };
        let (_t, p) = setup();
        let _l = UnixListener::bind(p.vsock()).unwrap(); // never accepts
        let addr = SocketAddrUnix::new(p.vsock()).unwrap();
        let mut held = Vec::new();
        let mut full = false;
        for _ in 0..10_000 {
            let fd = socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
                None,
            )
            .unwrap();
            match rconnect(&fd, &addr) {
                Ok(()) => held.push(fd),
                Err(rustix::io::Errno::AGAIN) => {
                    full = true;
                    break;
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        assert!(full, "could not fill the backlog");
        let t0 = Instant::now();
        let e = connect(&p, 1024, T, me()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e:?}");
        assert!(
            t0.elapsed() < Duration::from_millis(2600),
            "{:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn connect_ignores_swapped_symlink() {
        let (t, p) = setup();
        let h = fake_mux(&p, |mut s| s.write_all(b"OK 1\n").unwrap());
        let decoy_path = t.path().join("decoy");
        let decoy = UnixListener::bind(&decoy_path).unwrap();
        decoy.set_nonblocking(true).unwrap();
        let sp = p.vsock();
        let (dir, name) = open_parent(&sp).unwrap();
        let pinned = open_checked(&dir, name, me()).unwrap();
        // The VMM swaps the entry for a symlink to another socket.
        std::fs::remove_file(p.vsock()).unwrap();
        symlink(&decoy_path, p.vsock()).unwrap();
        let mut s = connect_fd(&pinned, Instant::now() + T).unwrap();
        s.write_all(b"CONNECT 1\n").unwrap();
        assert_eq!(h.join().unwrap(), "CONNECT 1\n");
        assert!(decoy.accept().is_err(), "decoy got a connection");
        // And a fresh connect() refuses the symlink outright.
        let e = connect(&p, 1024, T, me()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(decoy.accept().is_err());
    }

    #[test]
    fn connect_refuses_wrong_owner() {
        let (_t, p) = setup();
        let _l = UnixListener::bind(p.vsock()).unwrap();
        let e = connect(&p, 1024, T, me() + 1).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn connect_refuses_fifo_without_blocking() {
        let (_t, p) = setup();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            p.vsock(),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let t0 = Instant::now();
        let e = connect(&p, 1024, T, me()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn connect_refuses_non_socket() {
        let (_t, p) = setup();
        std::fs::write(p.vsock(), b"x").unwrap();
        let e = connect(&p, 1024, T, me()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn listen_replaces_stale_socket() {
        let (_t, p) = setup();
        drop(UnixListener::bind(p.vsock_port(5000)).unwrap()); // stale
        let l = listen(&p, 5000, false).unwrap();
        let c = UnixStream::connect(p.vsock_port(5000)).unwrap();
        let (_s, _) = l.accept().unwrap();
        drop(c);
    }

    #[test]
    fn listen_fresh_when_absent() {
        let (_t, p) = setup();
        listen(&p, 5001, false).unwrap();
    }

    #[test]
    fn listen_refuses_to_unlink_a_regular_file() {
        let (_t, p) = setup();
        std::fs::write(p.vsock_port(5000), b"keep").unwrap();
        let e = listen(&p, 5000, false).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(p.vsock_port(5000)).unwrap(), b"keep");
    }

    #[test]
    fn listen_refuses_symlink() {
        let (t, p) = setup();
        let target = t.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        symlink(&target, p.vsock_port(5000)).unwrap();
        let e = listen(&p, 5000, false).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert!(std::fs::symlink_metadata(p.vsock_port(5000))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(target.exists());
    }

    #[test]
    fn listen_refuses_fifo() {
        let (_t, p) = setup();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            p.vsock_port(5000),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let e = listen(&p, 5000, false).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert!(std::fs::symlink_metadata(p.vsock_port(5000))
            .unwrap()
            .file_type()
            .is_fifo());
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn listen_mode_0660() {
        let (_t, p) = setup();
        let _l = listen(&p, 5000, true).unwrap();
        assert_eq!(mode_of(&p.vsock_port(5000)), 0o660);
    }

    #[test]
    fn listen_mode_0600() {
        let (_t, p) = setup();
        let _l = listen(&p, 5000, false).unwrap();
        assert_eq!(mode_of(&p.vsock_port(5000)), 0o600);
    }

    #[test]
    fn unlink_all_only_removes_sockets() {
        let (t, p) = setup();
        let _mux = UnixListener::bind(p.vsock()).unwrap();
        let _a = UnixListener::bind(p.vsock_port(ports::EVENTS)).unwrap();
        let _b = UnixListener::bind(p.vsock_port(ports::EGRESS)).unwrap();
        std::fs::write(p.vsock_port(ports::MODEL), b"f").unwrap();
        let target = t.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        symlink(&target, p.vsock_port(ports::PTY)).unwrap();
        unlink_all(&p);
        assert!(!p.vsock_port(ports::EVENTS).exists());
        assert!(!p.vsock_port(ports::EGRESS).exists());
        assert!(p.vsock_port(ports::MODEL).is_file());
        assert!(std::fs::symlink_metadata(p.vsock_port(ports::PTY)).is_ok());
        assert!(target.exists());
        assert!(std::fs::symlink_metadata(p.vsock())
            .unwrap()
            .file_type()
            .is_socket());
        // Idempotent with everything absent.
        unlink_all(&p);
    }

    #[test]
    fn unlink_ports_removes_only_the_named_ones() {
        let (_t, p) = setup();
        let all = ports::ALL_HOST_PORTS.map(|port| listen(&p, port, false).unwrap());
        unlink_ports(&p, &[ports::EVENTS, ports::PTY]);
        assert!(!p.vsock_port(ports::EVENTS).exists());
        assert!(!p.vsock_port(ports::PTY).exists());
        assert!(p.vsock_port(ports::EGRESS).exists());
        assert!(p.vsock_port(ports::MODEL).exists());
        unlink_ports(&p, &[ports::EGRESS, ports::MODEL]);
        assert!(!p.vsock_port(ports::EGRESS).exists());
        assert!(!p.vsock_port(ports::MODEL).exists());
        drop(all);
    }
}
