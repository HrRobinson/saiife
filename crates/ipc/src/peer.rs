//! Peer credentials of a unix socket.
//!
//! Linux: `SO_PEERCRED` and `/proc/<pid>/comm`. macOS: `LOCAL_PEERCRED`
//! (uid and primary gid) and `LOCAL_PEERPID` through nix's safe API, and the
//! name from `sysctl(KERN_PROC_PID)` through `saiife-darwin`. Other unix
//! targets have neither: `peer_cred` is an error there, so a caller that
//! checks the peer fails closed.
use std::io;
use std::os::fd::AsFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

#[cfg(target_os = "linux")]
pub fn peer_cred(sock: impl AsFd) -> io::Result<PeerCred> {
    let c = rustix::net::sockopt::socket_peercred(sock)?;
    Ok(PeerCred {
        uid: c.uid.as_raw(),
        gid: c.gid.as_raw(),
        pid: c.pid.as_raw_nonzero().get() as u32,
    })
}

#[cfg(target_os = "macos")]
pub fn peer_cred(sock: impl AsFd) -> io::Result<PeerCred> {
    use nix::sys::socket::{getsockopt, sockopt};
    let c = getsockopt(&sock, sockopt::LocalPeerCred).map_err(io::Error::from)?;
    let pid = getsockopt(&sock, sockopt::LocalPeerPid).map_err(io::Error::from)?;
    mac_cred(c.uid(), c.groups(), pid)
}

/// The macOS answer from its parts: `cr_groups[0]` is the peer's effective
/// gid, and the pid must be positive.
#[cfg(any(target_os = "macos", test))]
fn mac_cred(uid: u32, groups: &[u32], pid: i32) -> io::Result<PeerCred> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
    let gid = *groups.first().ok_or_else(|| bad("peer has no group"))?;
    let pid = u32::try_from(pid)
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| bad("peer pid is not positive"))?;
    Ok(PeerCred { uid, gid, pid })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn peer_cred(sock: impl AsFd) -> io::Result<PeerCred> {
    let _ = sock.as_fd();
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credentials need Linux or macOS",
    ))
}

/// The process name, at most 16 chars: `/proc/<pid>/comm`, trimmed.
#[cfg(target_os = "linux")]
pub fn comm(pid: u32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(s.trim().chars().take(16).collect())
}

/// The process name, at most 16 chars: `p_comm` from `sysctl(KERN_PROC_PID)`.
#[cfg(target_os = "macos")]
pub fn comm(pid: u32) -> Option<String> {
    let p = saiife_darwin::proc_info(pid)?;
    Some(p.comm.trim().chars().take(16).collect())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn comm(pid: u32) -> Option<String> {
    let _ = pid;
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_cred_takes_first_group_and_positive_pid() {
        assert_eq!(
            mac_cred(501, &[20, 12, 61], 4242).unwrap(),
            PeerCred {
                uid: 501,
                gid: 20,
                pid: 4242
            }
        );
        assert!(mac_cred(501, &[], 4242).is_err());
        assert!(mac_cred(501, &[20], 0).is_err());
        assert!(mac_cred(501, &[20], -1).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn peer_cred_of_socketpair_is_self() {
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().unwrap();
        let c = peer_cred(&a).unwrap();
        assert_eq!(c.uid, rustix::process::getuid().as_raw());
        assert_eq!(c.gid, rustix::process::getegid().as_raw());
        assert_eq!(c.pid, std::process::id());
        assert!(comm(c.pid).is_some());
    }
}
