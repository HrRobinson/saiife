//! systemd readiness: one `READY=1` datagram to `NOTIFY_SOCKET`.

use std::ffi::OsStr;
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

/// Send `READY=1` when `NOTIFY_SOCKET` is set; otherwise do nothing.
pub fn ready() {
    let v = std::env::var_os("NOTIFY_SOCKET");
    if let Err(e) = ready_to(v.as_deref()) {
        eprintln!("saiifed: warning: readiness notification failed: {e}");
    }
}

/// `READY=1` to `socket` (a path, or `@name` for an abstract socket).
pub fn ready_to(socket: Option<&OsStr>) -> io::Result<()> {
    let Some(socket) = socket.filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let tx = UnixDatagram::unbound()?;
    match socket.as_bytes().strip_prefix(b"@") {
        Some(name) => {
            let addr = SocketAddr::from_abstract_name(name)?;
            tx.send_to_addr(b"READY=1", &addr)?;
        }
        None => {
            tx.send_to(b"READY=1", socket)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn ready_sends_ready_1() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("notify.sock");
        let rx = UnixDatagram::bind(&p).unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        ready_to(Some(p.as_os_str())).unwrap();
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
    }

    #[test]
    fn ready_sends_to_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("saiife-test-{}", std::process::id());
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let rx = UnixDatagram::bind_addr(&addr).unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        ready_to(Some(OsStr::new(&format!("@{name}")))).unwrap();
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
    }

    #[test]
    fn no_socket_is_a_no_op() {
        ready_to(None).unwrap();
        ready_to(Some(OsStr::new(""))).unwrap();
    }
}
