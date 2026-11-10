//! The IPv4 TCP table (plan 21, Task 4), free of Windows calls so Linux tests can
//! use it. `ffi::net::tcp_owner_pid` fills the words from `GetExtendedTcpTable`
//! (`TCP_TABLE_OWNER_PID_CONNECTIONS`) and asks [`owner_pid`] which row is the
//! client's.

use std::net::{Ipv4Addr, SocketAddrV4};

/// The `u32` words of one `MIB_TCPROW_OWNER_PID`: state, local address, local
/// port, remote address, remote port, owning pid.
pub const ROW_WORDS: usize = 6;

/// One row of the table, as it names a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRow {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub pid: u32,
}

/// An address word as the table stores it: the four bytes in network order, in
/// memory.
fn addr_of(word: u32) -> Ipv4Addr {
    Ipv4Addr::from(word.to_ne_bytes())
}

/// A port word as the table stores it: the low 16 bits, in network byte order in
/// memory. The upper bits are undefined and ignored.
fn port_of(word: u32) -> u16 {
    u16::from_be_bytes((word as u16).to_ne_bytes())
}

/// The rows of a `MIB_TCPTABLE_OWNER_PID` held in `words`: the entry count, then
/// [`ROW_WORDS`] words per row. `None` when the count claims more rows than the
/// buffer holds.
pub fn rows(words: &[u32]) -> Option<Vec<TcpRow>> {
    let (n, body) = words.split_first()?;
    let n = usize::try_from(*n).ok()?;
    let body = body.get(..n.checked_mul(ROW_WORDS)?)?;
    Some(
        body.as_chunks::<ROW_WORDS>()
            .0
            .iter()
            .map(|r| TcpRow {
                local: SocketAddrV4::new(addr_of(r[1]), port_of(r[2])),
                remote: SocketAddrV4::new(addr_of(r[3]), port_of(r[4])),
                pid: r[5],
            })
            .collect(),
    )
}

/// The pid that owns the connection whose own end is `local` and whose other end
/// is `remote`. The co-signer asks with the client's address as `local` and its
/// own as `remote`, so the row of its own accepted socket (the reverse) never
/// matches. Rows with pid 0 (a connection in `TIME_WAIT` has no owner) are
/// skipped. Two different owners of the same pair is `None`: no guess.
pub fn owner_pid(rows: &[TcpRow], local: SocketAddrV4, remote: SocketAddrV4) -> Option<u32> {
    let mut found = None;
    for r in rows
        .iter()
        .filter(|r| r.pid != 0 && r.local == local && r.remote == remote)
    {
        match found {
            None => found = Some(r.pid),
            Some(p) if p == r.pid => {}
            Some(_) => return None,
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The words Windows writes for a row, on this host's byte order.
    fn words(local: SocketAddrV4, remote: SocketAddrV4, pid: u32) -> [u32; ROW_WORDS] {
        let addr = |a: &SocketAddrV4| u32::from_ne_bytes(a.ip().octets());
        // The port's two bytes in network order at the start of the word in
        // memory, junk above them.
        let port = |a: &SocketAddrV4| {
            let [hi, lo] = a.port().to_be_bytes();
            let mut b = 0xdead_beef_u32.to_ne_bytes();
            if cfg!(target_endian = "little") {
                b[0] = hi;
                b[1] = lo;
            } else {
                b[2] = hi;
                b[3] = lo;
            }
            u32::from_ne_bytes(b)
        };
        [
            5,
            addr(&local),
            port(&local),
            addr(&remote),
            port(&remote),
            pid,
        ]
    }

    fn table(rs: &[(SocketAddrV4, SocketAddrV4, u32)]) -> Vec<u32> {
        let mut out = vec![rs.len() as u32];
        for (l, r, p) in rs {
            out.extend(words(*l, *r, *p));
        }
        out
    }

    fn a(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    #[test]
    fn rows_read_addresses_and_ports_in_network_order() {
        let t = table(&[(a("127.0.0.1:50123"), a("127.0.0.1:7433"), 4321)]);
        assert_eq!(
            rows(&t).unwrap(),
            vec![TcpRow {
                local: a("127.0.0.1:50123"),
                remote: a("127.0.0.1:7433"),
                pid: 4321
            }]
        );
        let t = table(&[(a("10.1.2.3:1"), a("192.168.0.254:65535"), 7)]);
        let r = rows(&t).unwrap();
        assert_eq!(r[0].local, a("10.1.2.3:1"));
        assert_eq!(r[0].remote, a("192.168.0.254:65535"));
    }

    #[test]
    fn rows_refuse_a_count_past_the_buffer() {
        let mut t = table(&[(a("127.0.0.1:1"), a("127.0.0.1:2"), 3)]);
        t[0] = 2;
        assert_eq!(rows(&t), None);
        t[0] = u32::MAX;
        assert_eq!(rows(&t), None);
        assert_eq!(rows(&[]), None);
        assert_eq!(rows(&[0]), Some(vec![]));
        // Words past the count are ignored.
        let mut t = table(&[(a("127.0.0.1:1"), a("127.0.0.1:2"), 3)]);
        t.extend([9; ROW_WORDS]);
        assert_eq!(rows(&t).unwrap().len(), 1);
    }

    #[test]
    fn owner_is_the_client_end_not_the_server_end() {
        let client = a("127.0.0.1:50123");
        let server = a("127.0.0.1:7433");
        let t = rows(&table(&[
            (server, client, 111), // the co-signer's accepted socket
            (client, server, 222), // the asker's socket
            (a("127.0.0.1:50124"), server, 333),
        ]))
        .unwrap();
        assert_eq!(owner_pid(&t, client, server), Some(222));
        assert_eq!(owner_pid(&t, server, client), Some(111));
        assert_eq!(owner_pid(&t, a("127.0.0.1:50125"), server), None);
    }

    #[test]
    fn ownerless_and_ambiguous_rows() {
        let client = a("127.0.0.1:50123");
        let server = a("127.0.0.1:7433");
        let t = rows(&table(&[(client, server, 0), (client, server, 222)])).unwrap();
        assert_eq!(owner_pid(&t, client, server), Some(222));
        let t = rows(&table(&[(client, server, 0)])).unwrap();
        assert_eq!(owner_pid(&t, client, server), None);
        let t = rows(&table(&[(client, server, 222), (client, server, 222)])).unwrap();
        assert_eq!(owner_pid(&t, client, server), Some(222));
        let t = rows(&table(&[(client, server, 222), (client, server, 333)])).unwrap();
        assert_eq!(owner_pid(&t, client, server), None);
    }
}
