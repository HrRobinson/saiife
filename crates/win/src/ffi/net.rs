//! Sockets (plan 20): the Claude Code co-signer's listener takes its address for
//! itself, so no process of another user can bind `127.0.0.1:7433` beside it.
//! Plan 21: the co-signer finds the pid that owns a client's end of a connection.
//!
//! FFI calls: `setsockopt`, `GetExtendedTcpTable`.

use std::io;
use std::net::SocketAddrV4;
use std::os::windows::io::RawSocket;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::{
    setsockopt, AF_INET, SOCKET, SOCKET_ERROR, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
};

/// Set `SO_EXCLUSIVEADDRUSE` on `sock`, before it is bound. Once bound, no other
/// socket can bind the same address and port, `SO_REUSEADDR` or not.
pub fn exclusive_addr_use(sock: RawSocket) -> io::Result<()> {
    let on: i32 = 1;
    let handle = SOCKET::try_from(sock)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a socket handle out of range"))?;
    // SAFETY: `handle` is the caller's open socket; `optval` points to `on`, an `i32`
    // that lives for the call, and `optlen` is its size. The call only reads it.
    let r = unsafe {
        setsockopt(
            handle,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&on as *const i32).cast::<u8>(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    if r == SOCKET_ERROR {
        // Winsock keeps its error in the thread's last-error value, which
        // `last_os_error` reads (as `WSAGetLastError` does).
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// How often a table that grew between the size query and the read is asked again.
const TABLE_RETRIES: usize = 3;

/// The pid that owns the IPv4 TCP connection whose own end is `local` and whose
/// other end is `remote` (`GetExtendedTcpTable`, `TCP_TABLE_OWNER_PID_CONNECTIONS`:
/// no listeners). The co-signer passes the client's address (the accepted
/// socket's peer) as `local` and its own as `remote`. `Ok(None)` when no row
/// matches, or two owners do. No privilege is needed. Which row matches is
/// [`crate::tcp::owner_pid`]'s choice.
pub fn tcp_owner_pid(local: SocketAddrV4, remote: SocketAddrV4) -> io::Result<Option<u32>> {
    let words = tcp_table()?;
    let rows = crate::tcp::rows(&words).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "a TCP table shorter than its count",
        )
    })?;
    Ok(crate::tcp::owner_pid(&rows, local, remote))
}

/// The table's words: the size first, then the read, again (with the new size)
/// while the table grew in between.
fn tcp_table() -> io::Result<Vec<u32>> {
    let mut size: u32 = 0;
    // SAFETY: a null table with `size` 0 only asks for the size, which the call
    // writes to `size`, a `u32` that lives for the call.
    let r = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    };
    if r != ERROR_INSUFFICIENT_BUFFER && r != NO_ERROR {
        return Err(io::Error::from_raw_os_error(r as i32));
    }
    for _ in 0..TABLE_RETRIES {
        // `u32` words: the table's alignment, rounded up to whole words.
        let mut buf = vec![0u32; (size as usize).div_ceil(4).max(1)];
        let mut have = (buf.len() * 4) as u32;
        // SAFETY: `buf` is writable for `have` bytes and aligned for the table's
        // `u32` fields; `have` is a `u32` that lives for the call. The call writes
        // at most `have` bytes, or none and the size it needs.
        let r = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut have,
                0,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        match r {
            NO_ERROR => return Ok(buf),
            ERROR_INSUFFICIENT_BUFFER => size = have,
            e => return Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
    Err(io::Error::other("the TCP table kept growing"))
}

/// These run in CI on windows-latest, with no admin rights assumed.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddr, TcpListener, TcpStream};

    fn v4(a: SocketAddr) -> SocketAddrV4 {
        match a {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => panic!("an IPv4 test socket"),
        }
    }

    #[test]
    fn owner_pid_of_own_connection() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = v4(l.local_addr().unwrap());
        let c = TcpStream::connect(server).unwrap();
        let (_s, peer) = l.accept().unwrap();
        assert_eq!(v4(c.local_addr().unwrap()), v4(peer));
        assert_eq!(
            tcp_owner_pid(v4(peer), server).unwrap(),
            Some(std::process::id())
        );
    }

    #[test]
    fn unknown_connection_is_none() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = v4(l.local_addr().unwrap());
        let _c = TcpStream::connect(server).unwrap();
        let (_s, _peer) = l.accept().unwrap();
        // A client end nobody holds.
        let nobody: SocketAddrV4 = "127.0.0.1:1".parse().unwrap();
        assert_eq!(tcp_owner_pid(nobody, server).unwrap(), None);
        // A listener is not a connection: no row has it as its own end.
        let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = v4(l2.local_addr().unwrap());
        assert_eq!(tcp_owner_pid(other, server).unwrap(), None);
    }
}
