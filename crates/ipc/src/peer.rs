//! Who is on the other end of the control channel.
//!
//! Linux: `SO_PEERCRED` and `/proc/<pid>/comm`. macOS: `LOCAL_PEERCRED`
//! (uid and primary gid) and `LOCAL_PEERPID` through nix's safe API, and the
//! name from `sysctl(KERN_PROC_PID)` through `saiife-darwin`. Other unix
//! targets have neither: `peer_cred` is an error there, so a caller that
//! checks the peer fails closed. Windows: the named pipe client's token, through
//! `saiife-win` ([`pipe_peer`]).
use std::io;
#[cfg(unix)]
use std::os::fd::AsFd;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCred {
    /// On unix, the identity. On Windows, a label from `uid_of`, and two SIDs can share
    /// one: never decide access on it there.
    pub uid: u32,
    pub gid: u32,
    /// For attribution only on Windows.
    pub pid: u32,
    /// Windows: the token's user, which is the identity. `None` on unix.
    pub sid: Option<String>,
    /// Windows: the token's enabled groups. Empty on unix.
    pub group_sids: Vec<String>,
}

#[cfg(target_os = "linux")]
pub fn peer_cred(sock: impl AsFd) -> io::Result<PeerCred> {
    let c = rustix::net::sockopt::socket_peercred(sock)?;
    Ok(PeerCred {
        uid: c.uid.as_raw(),
        gid: c.gid.as_raw(),
        pid: c.pid.as_raw_nonzero().get() as u32,
        sid: None,
        group_sids: Vec::new(),
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
    Ok(PeerCred {
        uid,
        gid,
        pid,
        sid: None,
        group_sids: Vec::new(),
    })
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub fn peer_cred(sock: impl AsFd) -> io::Result<PeerCred> {
    let _ = sock.as_fd();
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credentials need Linux or macOS",
    ))
}

/// The client on a connected server instance of a named pipe, from its token. Any handle
/// to the instance will do, tokio's `NamedPipeServer` among them, so this crate needs no
/// tokio. Synchronous: call it with no `.await` in between, right after `connect()`.
#[cfg(windows)]
pub fn pipe_peer(server: &impl std::os::windows::io::AsRawHandle) -> io::Result<PeerCred> {
    saiife_win::ffi::pipe::client_facts(server).map(cred_of_client)
}

#[cfg(any(windows, test))]
fn cred_of_client(client: saiife_win::pipe::PipeClient) -> PeerCred {
    let facts = client.facts;
    PeerCred {
        uid: saiife_win::sid::peer_uid(&facts.sid, facts.elevated_admin),
        gid: 0,
        pid: client.pid,
        sid: Some(facts.sid),
        group_sids: facts.group_sids,
    }
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
    use saiife_win::pipe::{peer_facts, PeerToken, PipeClient};
    use saiife_win::sid::{
        uid_of, TokenFacts, ADMINISTRATORS, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY, SYSTEM,
        USERS,
    };

    #[test]
    fn mac_cred_takes_first_group_and_positive_pid() {
        assert_eq!(
            mac_cred(501, &[20, 12, 61], 4242).unwrap(),
            PeerCred {
                uid: 501,
                gid: 20,
                pid: 4242,
                sid: None,
                group_sids: Vec::new(),
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn peer_cred_unix_has_no_sid() {
        use std::os::unix::net::UnixStream;
        let (a, _b) = UnixStream::pair().unwrap();
        let c = peer_cred(&a).unwrap();
        assert_eq!(c.sid, None);
        assert!(c.group_sids.is_empty());
        let m = mac_cred(501, &[20], 1).unwrap();
        assert_eq!(m.sid, None);
        assert!(m.group_sids.is_empty());
    }

    fn cred(sid: &str, groups: &[(&str, u32)]) -> PeerCred {
        let groups = groups.iter().map(|(g, a)| (g.to_string(), *a)).collect();
        cred_of_client(PipeClient {
            facts: TokenFacts::from_groups(sid.to_string(), groups),
            pid: 77,
        })
    }

    #[test]
    fn pipe_cred_keeps_the_sid_and_labels_the_uid() {
        let sid = "S-1-5-21-1-2-3-1001";
        let c = cred(sid, &[(USERS, SE_GROUP_ENABLED)]);
        assert_eq!(c.sid.as_deref(), Some(sid));
        assert_eq!(c.group_sids, [USERS]);
        assert_eq!(c.uid, uid_of(sid, false));
        assert_ne!(c.uid, 0);
        assert_eq!(c.gid, 0);
        assert_eq!(c.pid, 77);
    }

    /// Admin rights only count when elevated: a filtered admin token is that user's own
    /// label, not 0, and `Administrators` is not among its groups.
    #[test]
    fn pipe_cred_of_a_filtered_admin_is_not_root() {
        let sid = "S-1-5-21-1-2-3-500";
        let c = cred(
            sid,
            &[
                (ADMINISTRATORS, SE_GROUP_USE_FOR_DENY_ONLY),
                (USERS, SE_GROUP_ENABLED),
            ],
        );
        assert_ne!(c.uid, 0);
        assert_eq!(c.group_sids, [USERS]);
    }

    /// A SYSTEM token as the pipe reads it, through `peer_facts`. A real one holds
    /// `Administrators` enabled at System integrity.
    fn system_cred(integrity: &str, restricted_sids: usize) -> PeerCred {
        let facts = TokenFacts::from_groups(
            SYSTEM.to_string(),
            vec![(ADMINISTRATORS.to_string(), SE_GROUP_ENABLED)],
        );
        cred_of_client(PipeClient {
            facts: peer_facts(PeerToken {
                facts,
                integrity_sid: integrity.to_string(),
                restricted_sids,
            }),
            pid: 77,
        })
    }

    /// Two elevated admins and SYSTEM share uid 0, and their SIDs still tell them apart.
    #[test]
    fn pipe_cred_of_root_equivalents_keeps_them_apart() {
        let admin = cred("S-1-5-21-1-2-3-500", &[(ADMINISTRATORS, SE_GROUP_ENABLED)]);
        let other = cred("S-1-5-21-1-2-3-501", &[(ADMINISTRATORS, SE_GROUP_ENABLED)]);
        let system = system_cred("S-1-16-16384", 0);
        assert_eq!((admin.uid, other.uid, system.uid), (0, 0, 0));
        assert_ne!(admin.sid, other.sid);
        assert_ne!(admin.sid, system.sid);
        assert_ne!(admin, other);
    }

    /// A low-integrity or restricted child of SYSTEM cannot use what SYSTEM holds, so on
    /// a pipe it is not uid 0. Its SID still says SYSTEM.
    #[test]
    fn pipe_cred_of_a_lowered_system_token_is_not_root() {
        for lowered in [
            system_cred("S-1-16-4096", 0),
            system_cred("S-1-16-16384", 1),
        ] {
            assert_ne!(lowered.uid, 0);
            assert_eq!(lowered.sid.as_deref(), Some(SYSTEM));
            assert!(lowered.group_sids.is_empty());
        }
        // No enabled Administrators at all: elevated_admin is false, so not 0 either.
        assert_ne!(cred(SYSTEM, &[]).uid, 0);
    }

    /// The daemon's admin checks (`peer_is_admin`, `peer_may_read_all`) decide on the same
    /// facts: a lowered SYSTEM token is no admin, though its SID says SYSTEM, and a real
    /// one is.
    #[test]
    fn a_lowered_system_token_is_not_an_admin() {
        use saiife_win::sid::token_is_admin;
        for lowered in [
            system_cred("S-1-16-4096", 0),
            system_cred("S-1-16-8192", 0),
            system_cred("S-1-16-16384", 1),
        ] {
            assert!(!token_is_admin(&lowered.group_sids), "{lowered:?}");
        }
        assert!(token_is_admin(&system_cred("S-1-16-16384", 0).group_sids));
        assert!(!token_is_admin(&cred(SYSTEM, &[]).group_sids));
        // An elevated admin is one; a filtered one is not.
        let admin = cred("S-1-5-21-1-2-3-500", &[(ADMINISTRATORS, SE_GROUP_ENABLED)]);
        assert!(token_is_admin(&admin.group_sids));
        let filtered = cred(
            "S-1-5-21-1-2-3-500",
            &[(ADMINISTRATORS, SE_GROUP_USE_FOR_DENY_ONLY)],
        );
        assert!(!token_is_admin(&filtered.group_sids));
    }
}
