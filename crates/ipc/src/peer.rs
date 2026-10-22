//! Peer credentials of a unix socket (Linux).
use rustix::fd::AsFd;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

pub fn peer_cred(sock: impl AsFd) -> io::Result<PeerCred> {
    let c = rustix::net::sockopt::socket_peercred(sock)?;
    Ok(PeerCred {
        uid: c.uid.as_raw(),
        gid: c.gid.as_raw(),
        pid: c.pid.as_raw_nonzero().get() as u32,
    })
}

/// `/proc/<pid>/comm`, trimmed, at most 16 chars.
pub fn comm(pid: u32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(s.trim().chars().take(16).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn peer_cred_of_socketpair_is_self() {
        let (a, _b) = UnixStream::pair().unwrap();
        let c = peer_cred(&a).unwrap();
        assert_eq!(c.uid, rustix::process::getuid().as_raw());
        assert_eq!(c.pid, std::process::id());
        assert!(comm(c.pid).is_some());
    }
}
