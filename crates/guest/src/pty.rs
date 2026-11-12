//! The agent's PTY: open a pair, size it, and pump the master to pty.sock.
#![cfg(target_os = "linux")]

use crate::env::GuestEnv;
use crate::events::Signals;
use rustix::fs::{Mode, OFlags};
use rustix::pty::OpenptFlags;
use rustix::termios::Winsize;
use saiife_boxproto::frame::{write_frame, Frame};
use saiife_boxproto::ports::GUEST_PTY_SOCK;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// PTY output is read in chunks of this size.
pub const CHUNK: usize = 16 * 1024;
/// Window sizes outside 1..=MAX_DIM are refused.
pub const MAX_DIM: u16 = 1000;

/// A fresh PTY pair: the master stays with the init, the slave becomes the
/// agent's stdio.
pub struct Pair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

/// Checks a window size.
pub fn dims_ok(rows: u16, cols: u16) -> Result<(), String> {
    if rows == 0 || cols == 0 || rows > MAX_DIM || cols > MAX_DIM {
        return Err(format!(
            "window size {rows}x{cols} is outside 1..={MAX_DIM}"
        ));
    }
    Ok(())
}

/// Opens a PTY pair sized `rows` x `cols`.
pub fn open(rows: u16, cols: u16) -> io::Result<Pair> {
    let master =
        rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
    rustix::pty::grantpt(&master)?;
    rustix::pty::unlockpt(&master)?;
    let name = rustix::pty::ptsname(&master, Vec::new())?;
    resize(&master, rows, cols)?;
    let slave = rustix::fs::open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(Pair { master, slave })
}

/// Sets the window size on the master.
pub fn resize(master: &OwnedFd, rows: u16, cols: u16) -> io::Result<()> {
    rustix::termios::tcsetwinsize(
        master,
        Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )?;
    Ok(())
}

/// Reads the master until the slave side is gone (EIO), sending each read as a
/// `Bytes` frame to pty.sock. Output is dropped while pty.sock is not
/// connected; a reconnect is tried at most once a second.
pub fn pump(env: &GuestEnv, master: OwnedFd, signals: &Arc<Signals>) {
    let connect = || -> Option<UnixStream> {
        let s = UnixStream::connect(env.path(GUEST_PTY_SOCK)).ok()?;
        s.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
        Some(s)
    };
    let mut master = std::fs::File::from(master);
    let mut buf = vec![0u8; CHUNK];
    let mut last_try = Instant::now();
    let mut conn = connect();
    loop {
        let n = match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        signals.output();
        if conn.is_none() && last_try.elapsed() >= Duration::from_secs(1) {
            last_try = Instant::now();
            conn = connect();
        }
        if let Some(c) = conn.as_mut() {
            if write_frame(c, &Frame::Bytes(buf[..n].to_vec())).is_err() {
                // A frame cut by a timeout leaves the stream unusable.
                conn = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dims_are_bounded() {
        assert!(dims_ok(40, 120).is_ok());
        assert!(dims_ok(1, 1).is_ok());
        assert!(dims_ok(1000, 1000).is_ok());
        assert!(dims_ok(0, 1).is_err());
        assert!(dims_ok(1, 0).is_err());
        assert!(dims_ok(1001, 1).is_err());
        assert!(dims_ok(1, 1001).is_err());
    }
}
