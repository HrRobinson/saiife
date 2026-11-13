//! File descriptors over the control socket (plan 37): one byte, [`FD_BYTE`],
//! carrying the descriptors as `SCM_RIGHTS`. Plain rustix, no runtime: the
//! daemon drives [`recv_fds`] from its own event loop.
//!
//! The byte is read with exactly one byte asked for, so nothing past it is
//! consumed: the next frame follows on the same stream.

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

/// The one data byte that carries the descriptors.
pub const FD_BYTE: u8 = 0x46;
/// The most descriptors one `box.fds` passes.
pub const MAX_FDS: usize = 4;

/// Room for more descriptors than any receipt takes, so one too many is
/// seen (and closed) rather than cut off unseen.
const RECV_ROOM: usize = MAX_FDS * 2;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_flags() -> SendFlags {
    SendFlags::NOSIGNAL
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn send_flags() -> SendFlags {
    SendFlags::empty()
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
fn recv_flags() -> RecvFlags {
    RecvFlags::CMSG_CLOEXEC
}
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
fn recv_flags() -> RecvFlags {
    RecvFlags::empty()
}

/// Sends [`FD_BYTE`] with `fds` attached (none is allowed: the byte alone).
/// A blocking socket blocks; a non-blocking one may answer `WouldBlock`.
pub fn send_fds(sock: impl AsFd, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    if fds.len() > RECV_ROOM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("at most {RECV_ROOM} descriptors per message"),
        ));
    }
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(RECV_ROOM))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(io::Error::other(
            "descriptors do not fit the control buffer",
        ));
    }
    let byte = [FD_BYTE];
    loop {
        match sendmsg(&sock, &[IoSlice::new(&byte)], &mut control, send_flags()) {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Reads exactly one byte, which must be [`FD_BYTE`], and the descriptors
/// that came with it. More than `max` descriptors, a cut-off control
/// message or another byte is `InvalidData`, with every received descriptor
/// closed. EOF is `UnexpectedEof`. A non-blocking socket with nothing in
/// is `WouldBlock`.
pub fn recv_fds(sock: impl AsFd, max: usize) -> io::Result<Vec<OwnedFd>> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(RECV_ROOM))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut byte = [0u8; 1];
    let got = loop {
        let mut iov = [IoSliceMut::new(&mut byte)];
        match recvmsg(&sock, &mut iov, &mut control, recv_flags()) {
            Ok(m) => break m,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    // Every descriptor that arrived is owned from here, so each early
    // return closes them all.
    let mut fds = Vec::new();
    for msg in control.drain() {
        if let RecvAncillaryMessage::ScmRights(it) = msg {
            fds.extend(it);
        }
    }
    let bad = |m: String| Err(io::Error::new(io::ErrorKind::InvalidData, m));
    if got.bytes == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if byte[0] != FD_BYTE {
        return bad(format!("expected the fd byte, got {:#04x}", byte[0]));
    }
    if got.flags.contains(ReturnFlags::CTRUNC) {
        return bad("the descriptors were cut off".into());
    }
    if fds.len() > max {
        return bad(format!("{} descriptors, at most {max}", fds.len()));
    }
    Ok(fds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    fn file_with(dir: &Path, name: &str, body: &str) -> File {
        let p = dir.join(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        File::open(&p).unwrap()
    }

    #[test]
    fn send_recv_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let a = file_with(d.path(), "a", "alpha");
        let b = file_with(d.path(), "b", "beta");
        let (tx, rx) = UnixStream::pair().unwrap();
        send_fds(&tx, &[a.as_fd(), b.as_fd()]).unwrap();
        // What follows the byte is left for the next read.
        (&tx).write_all(b"next").unwrap();
        let got = recv_fds(&rx, MAX_FDS).unwrap();
        assert_eq!(got.len(), 2);
        let mut texts = Vec::new();
        for fd in got {
            let mut f = File::from(fd);
            f.seek(SeekFrom::Start(0)).unwrap();
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap();
            texts.push(s);
        }
        assert_eq!(texts, ["alpha", "beta"]);
        let mut rest = [0u8; 4];
        (&rx).read_exact(&mut rest).unwrap();
        assert_eq!(&rest, b"next");
    }

    /// How many open descriptors of this process name a file in `dir`.
    /// Only this test's own files count, so descriptors that parallel
    /// tests open and close meanwhile cannot change the answer.
    fn open_in(dir: &Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .filter(|t| t.starts_with(dir))
            .count()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn too_many_fds_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().canonicalize().unwrap();
        let files: Vec<File> = (0..5)
            .map(|i| file_with(&dir, &format!("f{i}"), "x"))
            .collect();
        let fds: Vec<BorrowedFd<'_>> = files.iter().map(|f| f.as_fd()).collect();
        assert_eq!(open_in(&dir), 5);
        let (tx, rx) = UnixStream::pair().unwrap();
        send_fds(&tx, &fds).unwrap();
        // In flight, the kernel holds them; not yet ours.
        let e = recv_fds(&rx, 4).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        // Only the sender's own five are open: every received one is closed.
        assert_eq!(open_in(&dir), 5);
        drop(files);
        assert_eq!(open_in(&dir), 0);
    }

    #[test]
    fn no_fd_is_ok_empty() {
        let (tx, rx) = UnixStream::pair().unwrap();
        send_fds(&tx, &[]).unwrap();
        assert!(recv_fds(&rx, MAX_FDS).unwrap().is_empty());
    }

    #[test]
    fn another_byte_is_refused_and_eof_is_eof() {
        let (tx, rx) = UnixStream::pair().unwrap();
        (&tx).write_all(b"{").unwrap();
        let e = recv_fds(&rx, MAX_FDS).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        drop(tx);
        let e = recv_fds(&rx, MAX_FDS).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "{e}");
    }
}
