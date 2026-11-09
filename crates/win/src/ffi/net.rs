//! Sockets (plan 20): the Claude Code co-signer's listener takes its address for
//! itself, so no process of another user can bind `127.0.0.1:7433` beside it.

use std::io;
use std::os::windows::io::RawSocket;
use windows_sys::Win32::Networking::WinSock::{
    setsockopt, SOCKET, SOCKET_ERROR, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
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
