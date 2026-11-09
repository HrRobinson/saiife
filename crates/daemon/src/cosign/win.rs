//! Who asks, on Windows (plan 21, Task 4): the pid that owns the client's end of
//! a co-sign connection, from the TCP table. The service cannot open that
//! process's token (D2), so the pid is all it learns here; `HookTable::wait`
//! then ties it to the hook that bound the call (`saiife_win::proc::is_descendant`).
//! Compiled everywhere so the callers need no `cfg`; off Windows nothing is found.

use super::Asker;
use std::net::SocketAddr;

/// The pid that owns the client end of the connection the co-signer accepted
/// (`local` is the co-signer's end, `peer` the client's). IPv4 only: the
/// co-signer listens on `127.0.0.1`.
#[cfg(windows)]
pub(super) fn owner_pid(local: SocketAddr, peer: SocketAddr) -> Option<u32> {
    let (SocketAddr::V4(local), SocketAddr::V4(peer)) = (local, peer) else {
        return None;
    };
    // The table row of the client's socket has the client as its own end.
    saiife_win::ffi::net::tcp_owner_pid(peer, local)
        .ok()
        .flatten()
}

#[cfg(not(windows))]
pub(super) fn owner_pid(local: SocketAddr, peer: SocketAddr) -> Option<u32> {
    let _ = (local, peer);
    None
}

/// [`Asker::Process`] of the client's pid, looked up on a blocking thread before
/// the body is read; [`Asker::Unknown`] (a deny) when no row names it.
pub(super) async fn asker(local: Option<SocketAddr>, peer: SocketAddr) -> Asker {
    let Some(local) = local else {
        return Asker::Unknown;
    };
    tokio::task::spawn_blocking(move || owner_pid(local, peer))
        .await
        .ok()
        .flatten()
        .map_or(Asker::Unknown, Asker::Process)
}
