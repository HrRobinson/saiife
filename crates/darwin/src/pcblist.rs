//! A parser for the `net.inet.tcp.pcblist_n` sysctl's output (plan 21,
//! Task 5): which uid owns the client end of one TCP connection.
//!
//! Pure and compiled on every target, so the Linux tests run it; only the
//! read itself ([`crate::tcp_peer_uid`]) is macOS code.
//!
//! The records are XNU's private `struct xinpgen`, `xinpcb_n`, `xsocket_n`
//! and their siblings (`bsd/netinet/in_pcb.h`, `bsd/sys/socketvar.h`, all
//! under `#pragma pack(4)`; filled by `get_pcblist_n` in
//! `bsd/netinet/in_pcblist.c`). They are no stable ABI, so the parser is
//! strict: a header, record or field it does not know is
//! [`ParseError::Layout`], and the caller denies. The layout below is the
//! same in xnu-10002.1.13 (macOS 14), xnu-11215.1.10 (macOS 15) and `main`
//! (read 2026-11-09), and its offsets were checked with a C compiler against
//! the structs of those headers.
//!
//! The buffer is:
//! - one `xinpgen` (24 bytes) with the pcb count;
//! - per connection, one fixed group of records, each at an offset rounded
//!   up to 8 bytes: `XSO_INPCB`, `XSO_SOCKET`, `XSO_RCVBUF`, `XSO_SNDBUF`,
//!   `XSO_STATS` and `XSO_TCPCB`;
//! - a closing `xinpgen` (absent when the count is 0).
//!
//! Integers are little-endian (every macOS target is); ports and addresses
//! are in network byte order, as the kernel holds them.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Why a buffer gave no answer. The caller treats each as "the asker is
/// unknown" and denies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The buffer ends inside the header, a record, or before the closing
    /// header.
    Truncated,
    /// A header, record size, record kind or record order this parser does
    /// not know: a macOS whose private layout changed.
    Layout(String),
    /// Two sockets of different uids claim the same connection.
    Ambiguous,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Truncated => f.write_str("pcblist_n: truncated buffer"),
            ParseError::Layout(why) => write!(f, "pcblist_n: unknown record layout: {why}"),
            ParseError::Ambiguous => f.write_str("pcblist_n: two owners for one connection"),
        }
    }
}

impl std::error::Error for ParseError {}

/// `sizeof(struct xinpgen)`.
pub const XINPGEN_LEN: u32 = 24;
/// The `sizeof(struct xinpcb_n)` values this parser knows.
pub const KNOWN_XINPCB_N_LEN: &[u32] = &[104];
/// The `sizeof(struct xsocket_n)` values this parser knows.
pub const KNOWN_XSOCKET_N_LEN: &[u32] = &[104];

/// The record kinds (`XSO_*` in `bsd/sys/socketvar.h`).
pub const XSO_SOCKET: u32 = 0x001;
pub const XSO_RCVBUF: u32 = 0x002;
pub const XSO_SNDBUF: u32 = 0x004;
pub const XSO_STATS: u32 = 0x008;
pub const XSO_INPCB: u32 = 0x010;
pub const XSO_TCPCB: u32 = 0x020;

/// `inp_vflag` bits.
const INP_IPV4: u8 = 0x1;
const INP_IPV6: u8 = 0x2;
const IPPROTO_TCP: u32 = 6;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 30;

/// Field offsets in `struct xinpcb_n` (pack 4).
mod inp {
    pub const INPP: usize = 8;
    pub const FPORT: usize = 16;
    pub const LPORT: usize = 18;
    pub const VFLAG: usize = 44;
    /// The foreign address union: `in6_addr`, or `in_addr_4in6` whose
    /// IPv4 address is its last 4 bytes.
    pub const FADDR: usize = 48;
    pub const LADDR: usize = 64;
}

/// Field offsets in `struct xsocket_n` (pack 4).
mod so {
    pub const SO: usize = 8;
    pub const PCB: usize = 28;
    pub const PROTOCOL: usize = 36;
    pub const FAMILY: usize = 40;
    pub const UID: usize = 64;
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(w)
}

fn port_at(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn round8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// The uid of the socket whose local end is `peer` and whose foreign end is
/// `local`: the client of a connection that a server at `local` accepted
/// from `peer`.
///
/// `Ok(None)` when no socket matches, or when the matching record has no
/// kernel socket behind it (a user-space flow, a pcb without a socket):
/// such a record carries no real uid. Every record is size- and
/// kind-checked before any field is read.
pub fn parse_pcblist_n(
    buf: &[u8],
    local: SocketAddr,
    peer: SocketAddr,
) -> Result<Option<u32>, ParseError> {
    let (local, peer) = (unmap(local), unmap(peer));
    if buf.len() < XINPGEN_LEN as usize {
        return Err(ParseError::Truncated);
    }
    let head_len = u32_at(buf, 0);
    if head_len != XINPGEN_LEN {
        return Err(ParseError::Layout(format!("xinpgen length {head_len}")));
    }
    let count = u32_at(buf, 4);
    let mut at = round8(XINPGEN_LEN as usize);
    if count == 0 && at == buf.len() {
        // The kernel writes no closing header for an empty list.
        return Ok(None);
    }
    let mut group: Option<Group> = None;
    let mut found: Option<u32> = None;
    loop {
        if buf.len() - at < 8 {
            return Err(ParseError::Truncated);
        }
        let len = u32_at(buf, at) as usize;
        if len == XINPGEN_LEN as usize {
            // The closing header: it must end the buffer.
            if buf.len() - at < len {
                return Err(ParseError::Truncated);
            }
            if at + len != buf.len() {
                return Err(ParseError::Layout(format!(
                    "{} bytes after the closing xinpgen",
                    buf.len() - at - len
                )));
            }
            if let Some(g) = group.take() {
                g.finish(local, peer, &mut found)?;
            }
            return Ok(found);
        }
        let kind = u32_at(buf, at + 4);
        if len < 8 {
            return Err(ParseError::Layout(format!("record length {len}")));
        }
        if buf.len() - at < len {
            return Err(ParseError::Truncated);
        }
        let rec = &buf[at..at + len];
        match kind {
            XSO_INPCB => {
                if !KNOWN_XINPCB_N_LEN.contains(&(len as u32)) {
                    return Err(ParseError::Layout(format!("xinpcb_n length {len}")));
                }
                if let Some(g) = group.take() {
                    g.finish(local, peer, &mut found)?;
                }
                group = Some(Group {
                    inp: rec,
                    sock: None,
                });
            }
            XSO_SOCKET => {
                if !KNOWN_XSOCKET_N_LEN.contains(&(len as u32)) {
                    return Err(ParseError::Layout(format!("xsocket_n length {len}")));
                }
                match group.as_mut() {
                    Some(g) if g.sock.is_none() => g.sock = Some(rec),
                    _ => return Err(ParseError::Layout("xsocket_n without its xinpcb_n".into())),
                }
            }
            XSO_RCVBUF | XSO_SNDBUF | XSO_STATS | XSO_TCPCB => match group.as_ref() {
                Some(g) if g.sock.is_some() => {}
                _ => {
                    return Err(ParseError::Layout(format!(
                        "record kind {kind:#x} outside a connection"
                    )))
                }
            },
            _ => return Err(ParseError::Layout(format!("record kind {kind:#x}"))),
        }
        at += round8(len);
        if at > buf.len() {
            return Err(ParseError::Truncated);
        }
    }
}

/// One connection's `xinpcb_n` and `xsocket_n`, both size-checked.
struct Group<'a> {
    inp: &'a [u8],
    sock: Option<&'a [u8]>,
}

impl Group<'_> {
    fn finish(
        self,
        local: SocketAddr,
        peer: SocketAddr,
        found: &mut Option<u32>,
    ) -> Result<(), ParseError> {
        let Some(sock) = self.sock else {
            return Err(ParseError::Layout("xinpcb_n without its xsocket_n".into()));
        };
        let inp = self.inp;
        let ends = (port_at(inp, inp::LPORT), port_at(inp, inp::FPORT));
        if ends != (peer.port(), local.port()) {
            return Ok(());
        }
        let vflag = inp[inp::VFLAG];
        let addrs = |ip: &SocketAddr| match ip.ip() {
            IpAddr::V4(_) if vflag & INP_IPV4 != 0 => {
                Some((v4_at(inp, inp::LADDR), v4_at(inp, inp::FADDR)))
            }
            IpAddr::V6(_) if vflag & INP_IPV4 == 0 && vflag & INP_IPV6 != 0 => {
                Some((v6_at(inp, inp::LADDR), v6_at(inp, inp::FADDR)))
            }
            _ => None,
        };
        if addrs(&peer) != Some((peer.ip(), local.ip())) {
            return Ok(());
        }
        // A kernel socket of this pcb: a user-space flow (Skywalk) or a pcb
        // without a socket has zero handles and a zero uid, which is no
        // owner.
        let pcb = u64_at(inp, inp::INPP);
        let real = pcb != 0
            && u64_at(sock, so::SO) != 0
            && u64_at(sock, so::PCB) == pcb
            && u32_at(sock, so::PROTOCOL) == IPPROTO_TCP
            && matches!(u32_at(sock, so::FAMILY), AF_INET | AF_INET6);
        if !real {
            return Ok(());
        }
        let uid = u32_at(sock, so::UID);
        match *found {
            Some(u) if u != uid => Err(ParseError::Ambiguous),
            _ => {
                *found = Some(uid);
                Ok(())
            }
        }
    }
}

fn v4_at(b: &[u8], at: usize) -> IpAddr {
    Ipv4Addr::new(b[at + 12], b[at + 13], b[at + 14], b[at + 15]).into()
}

fn v6_at(b: &[u8], at: usize) -> IpAddr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[at..at + 16]);
    Ipv6Addr::from(a).into()
}

/// An IPv4-mapped IPv6 address as the IPv4 address it maps: the kernel
/// keeps such a connection as IPv4.
fn unmap(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => a,
        },
        SocketAddr::V4(_) => a,
    }
}

#[cfg(test)]
mod tests {
    //! Hand-built fixtures: the buffers below are written field by field
    //! from the XNU layout (the offsets above), as `get_pcblist_n` writes
    //! them. No captured buffer: there is no Mac here. The live check is
    //! `own_connection_has_own_uid` on the macOS CI runners.
    use super::*;

    const SERVER: &str = "127.0.0.1:7433";
    const CLIENT: &str = "127.0.0.1:50123";
    const SOCKBUF_LEN: usize = 32;
    const SOCKSTAT_LEN: usize = 136;
    const TCPCB_LEN: usize = 208;
    /// The stride of an `xinpcb_n` or `xsocket_n` record: 104 bytes, a
    /// multiple of 8, so no padding follows.
    const REC: usize = 104;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn xinpgen(count: u32) -> Vec<u8> {
        let mut b = vec![0u8; XINPGEN_LEN as usize];
        put32(&mut b, 0, XINPGEN_LEN);
        put32(&mut b, 4, count);
        put64(&mut b, 8, 77);
        b
    }

    /// One pcb as `get_pcblist_n` writes it.
    #[derive(Clone)]
    struct Conn {
        local: SocketAddr,
        foreign: SocketAddr,
        uid: u32,
        handle: u64,
        /// No kernel socket (a Skywalk user-space flow).
        userland: bool,
        inp_len: usize,
        so_len: usize,
    }

    impl Conn {
        fn new(local: &str, foreign: &str, uid: u32, handle: u64) -> Conn {
            Conn {
                local: sa(local),
                foreign: sa(foreign),
                uid,
                handle,
                userland: false,
                inp_len: 104,
                so_len: 104,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            let mut inp = vec![0u8; self.inp_len];
            put32(&mut inp, 0, self.inp_len as u32);
            put32(&mut inp, 4, XSO_INPCB);
            if !self.userland {
                put64(&mut inp, inp::INPP, self.handle);
            }
            inp[inp::FPORT..inp::FPORT + 2].copy_from_slice(&self.foreign.port().to_be_bytes());
            inp[inp::LPORT..inp::LPORT + 2].copy_from_slice(&self.local.port().to_be_bytes());
            let mut v6 = false;
            for (addr, at) in [(self.foreign, inp::FADDR), (self.local, inp::LADDR)] {
                match addr.ip() {
                    IpAddr::V4(a) => inp[at + 12..at + 16].copy_from_slice(&a.octets()),
                    IpAddr::V6(a) => {
                        v6 = true;
                        inp[at..at + 16].copy_from_slice(&a.octets());
                    }
                }
            }
            inp[inp::VFLAG] = if v6 { INP_IPV6 } else { INP_IPV4 };

            let mut so = vec![0u8; self.so_len];
            put32(&mut so, 0, self.so_len as u32);
            put32(&mut so, 4, XSO_SOCKET);
            put32(&mut so, so::PROTOCOL, IPPROTO_TCP);
            if !self.userland {
                put64(&mut so, so::SO, self.handle ^ 0xffff);
                put64(&mut so, so::PCB, self.handle);
                put32(&mut so, so::FAMILY, if v6 { AF_INET6 } else { AF_INET });
                put32(&mut so, so::UID, self.uid);
            }

            let mut out = Vec::new();
            let mut push = |rec: Vec<u8>| {
                let n = round8(rec.len());
                out.extend_from_slice(&rec);
                out.resize(out.len() + n - rec.len(), 0);
            };
            push(inp);
            push(so);
            for (kind, len) in [
                (XSO_RCVBUF, SOCKBUF_LEN),
                (XSO_SNDBUF, SOCKBUF_LEN),
                (XSO_STATS, SOCKSTAT_LEN),
                (XSO_TCPCB, TCPCB_LEN),
            ] {
                let mut r = vec![0u8; len];
                put32(&mut r, 0, len as u32);
                put32(&mut r, 4, kind);
                push(r);
            }
            out
        }
    }

    fn list(conns: &[Conn]) -> Vec<u8> {
        let mut b = xinpgen(conns.len() as u32);
        for c in conns {
            b.extend_from_slice(&c.bytes());
        }
        b.extend_from_slice(&xinpgen(conns.len() as u32));
        b
    }

    /// A listener, the server's accepted end, and the client's end.
    fn three(client_uid: u32) -> Vec<Conn> {
        vec![
            Conn::new(SERVER, "0.0.0.0:0", 0, 0x1000),
            Conn::new(SERVER, CLIENT, 0, 0x2000),
            Conn::new(CLIENT, SERVER, client_uid, 0x3000),
        ]
    }

    fn ask(buf: &[u8]) -> Result<Option<u32>, ParseError> {
        parse_pcblist_n(buf, sa(SERVER), sa(CLIENT))
    }

    #[test]
    fn finds_the_client_uid() {
        assert_eq!(ask(&list(&three(501))), Ok(Some(501)));
        // Order does not matter.
        let mut c = three(501);
        c.reverse();
        assert_eq!(ask(&list(&c)), Ok(Some(501)));
    }

    #[test]
    fn ignores_the_listening_socket() {
        let only_listener = [Conn::new(SERVER, "0.0.0.0:0", 0, 0x1000)];
        assert_eq!(ask(&list(&only_listener)), Ok(None));
        // A listener on the client's port is not the client either.
        let decoy = [
            Conn::new(CLIENT, "0.0.0.0:0", 0, 0x1000),
            Conn::new(CLIENT, SERVER, 501, 0x3000),
        ];
        assert_eq!(ask(&list(&decoy)), Ok(Some(501)));
    }

    #[test]
    fn the_server_end_is_not_the_client() {
        // Only the accepted end (local = server, foreign = client): no
        // answer, and certainly not the daemon's own uid.
        let c = [Conn::new(SERVER, CLIENT, 0, 0x2000)];
        assert_eq!(ask(&list(&c)), Ok(None));
    }

    #[test]
    fn other_connections_do_not_match() {
        let c = [
            Conn::new("127.0.0.1:50124", SERVER, 600, 0x4000),
            Conn::new(CLIENT, "127.0.0.1:7434", 601, 0x5000),
            Conn::new("127.0.0.2:50123", SERVER, 602, 0x6000),
        ];
        assert_eq!(ask(&list(&c)), Ok(None));
    }

    #[test]
    fn a_user_space_flow_is_no_owner() {
        // Skywalk flows carry the 4-tuple but zero handles and uid 0.
        let mut flow = Conn::new(CLIENT, SERVER, 0, 0);
        flow.userland = true;
        assert_eq!(ask(&list(&[flow.clone()])), Ok(None));
        let mut c = three(501);
        c.push(flow);
        assert_eq!(ask(&list(&c)), Ok(Some(501)));
    }

    #[test]
    fn a_socket_of_another_pcb_is_no_owner() {
        let mut c = Conn::new(CLIENT, SERVER, 501, 0x3000);
        let mut b = list(std::slice::from_ref(&c));
        // so_pcb names another pcb.
        let at = XINPGEN_LEN as usize + REC + so::PCB;
        put64(&mut b, at, 0x9999);
        assert_eq!(ask(&b), Ok(None));
        c.uid = 502;
        assert_eq!(ask(&list(&[c])), Ok(Some(502)));
    }

    #[test]
    fn two_owners_are_ambiguous() {
        let c = [
            Conn::new(CLIENT, SERVER, 501, 0x3000),
            Conn::new(CLIENT, SERVER, 502, 0x7000),
        ];
        assert_eq!(ask(&list(&c)), Err(ParseError::Ambiguous));
        // The same owner twice (a TIME_WAIT twin) is that owner.
        let c = [
            Conn::new(CLIENT, SERVER, 501, 0x3000),
            Conn::new(CLIENT, SERVER, 501, 0x7000),
        ];
        assert_eq!(ask(&list(&c)), Ok(Some(501)));
    }

    #[test]
    fn ipv6_and_mapped_addresses() {
        let c = [Conn::new("[::1]:50123", "[::1]:7433", 501, 0x3000)];
        assert_eq!(
            parse_pcblist_n(&list(&c), sa("[::1]:7433"), sa("[::1]:50123")),
            Ok(Some(501))
        );
        // A v4 query does not match a v6 pcb.
        assert_eq!(ask(&list(&c)), Ok(None));
        // A mapped query matches the IPv4 pcb.
        assert_eq!(
            parse_pcblist_n(
                &list(&three(501)),
                sa("[::ffff:127.0.0.1]:7433"),
                sa("[::ffff:127.0.0.1]:50123")
            ),
            Ok(Some(501))
        );
    }

    #[test]
    fn empty_list() {
        assert_eq!(ask(&xinpgen(0)), Ok(None));
        assert_eq!(ask(&list(&[])), Ok(None));
    }

    #[test]
    fn unknown_record_size_is_layout_error() {
        for (inp_len, so_len) in [(112, 104), (96, 104), (104, 112), (104, 100)] {
            let mut c = Conn::new(CLIENT, SERVER, 501, 0x3000);
            c.inp_len = inp_len;
            c.so_len = so_len;
            assert!(
                matches!(ask(&list(&[c])), Err(ParseError::Layout(_))),
                "{inp_len} {so_len}"
            );
        }
        // A header of another size.
        let mut b = list(&three(501));
        put32(&mut b, 0, 32);
        assert!(matches!(ask(&b), Err(ParseError::Layout(_))));
        // A record shorter than its own length and kind.
        let mut b = xinpgen(1);
        b.extend_from_slice(&[4, 0, 0, 0, 0x10, 0, 0, 0]);
        b.extend_from_slice(&xinpgen(1));
        assert!(matches!(ask(&b), Err(ParseError::Layout(_))));
    }

    #[test]
    fn unknown_kind_or_order_is_layout_error() {
        let one = Conn::new(CLIENT, SERVER, 501, 0x3000).bytes();
        // An unknown kind.
        let mut b = list(&three(501));
        let at = XINPGEN_LEN as usize + 2 * REC;
        put32(&mut b, at + 4, 0x400);
        assert!(matches!(ask(&b), Err(ParseError::Layout(_))));
        // A socket record first, with no pcb before it.
        let mut b = xinpgen(1);
        b.extend_from_slice(&one[REC..]);
        b.extend_from_slice(&xinpgen(1));
        assert!(matches!(ask(&b), Err(ParseError::Layout(_))));
        // A pcb with no socket record.
        let mut b = xinpgen(1);
        b.extend_from_slice(&one[..REC]);
        b.extend_from_slice(&xinpgen(1));
        assert!(matches!(ask(&b), Err(ParseError::Layout(_))));
        // Two socket records for one pcb.
        let mut b = xinpgen(1);
        b.extend_from_slice(&one[..2 * REC]);
        b.extend_from_slice(&one[REC..]);
        b.extend_from_slice(&xinpgen(1));
        assert!(matches!(ask(&b), Err(ParseError::Layout(_))));
        // Bytes after the closing header.
        let mut b = list(&three(501));
        b.extend_from_slice(&[0u8; 8]);
        assert!(matches!(ask(&b), Err(ParseError::Layout(_))));
    }

    #[test]
    fn truncated_buffer_is_error() {
        let full = list(&three(501));
        // Every cut short of the whole buffer is an error, never an answer.
        for n in 0..full.len() {
            let r = ask(&full[..n]);
            assert!(
                matches!(r, Err(ParseError::Truncated) | Err(ParseError::Layout(_))),
                "cut at {n}: {r:?}"
            );
        }
        // Cut at a record boundary, before the closing header.
        assert_eq!(
            ask(&full[..full.len() - XINPGEN_LEN as usize]),
            Err(ParseError::Truncated)
        );
        // A record whose length runs past the end.
        assert_eq!(
            ask(&full[..XINPGEN_LEN as usize + 50]),
            Err(ParseError::Truncated)
        );
        // A header that claims pcbs but nothing follows.
        assert_eq!(ask(&xinpgen(1)), Err(ParseError::Truncated));
    }
}
