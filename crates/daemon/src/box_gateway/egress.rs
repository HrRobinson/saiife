//! The allow-listed CONNECT proxy on a box's `vsock.sock_5001` (spec §7.4,
//! plan 38 G6–G10). The guest is untrusted: the head is bounded in size and
//! time, the name must be on the box template's allow-list, every resolved
//! address must be public, and the tunnel goes to the checked address
//! itself. Only host, port, address, byte counts, time, outcome and reason
//! are ever recorded: never the head, its request line or its headers.

use super::{deny, BoxRun, GatewayShared, Slot};
use saiife_boxes::template::EgressRule;
use saiife_boxes::BoxId;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// [`parse_connect`]'s error for a well-formed request that is not CONNECT.
pub const NOT_CONNECT: &str = "not a CONNECT request";
/// [`parse_connect`]'s error for an IP address as the target.
pub const IP_LITERAL: &str = "an IP literal";

/// G6.
pub const PLAIN_HTTP: &str = "only CONNECT to allowed hosts: plain http is not available in boxes";
const IP_LITERAL_MSG: &str = "IP literals are refused: CONNECT to an allowed host name";
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
/// How long a refusal answer may take to write.
const ANSWER_SECS: u64 = 5;
/// The copy buffer of each tunnel direction.
const COPY_BYTES: usize = 16 * 1024;

/// HTTP `tchar` (RFC 9110 §5.6.2).
fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The target of `CONNECT host:port HTTP/1.x`, from a whole head ending in
/// CRLFCRLF: the host lowercased with one trailing dot removed, and the
/// port. Lines end in CRLF only (no bare CR or LF, no NUL, no obs-fold);
/// the request line is printable ASCII with single spaces; header names are
/// tokens. A well-formed request with another method is [`NOT_CONNECT`]; an
/// IPv4 or IPv6 address in any spelling is [`IP_LITERAL`].
pub fn parse_connect(head: &[u8]) -> Result<(String, u16), &'static str> {
    let body = head
        .strip_suffix(b"\r\n\r\n")
        .ok_or("the head does not end with CRLFCRLF")?;
    if body.contains(&0) {
        return Err("NUL in the head");
    }
    let mut lines = Vec::new();
    let mut rest = body;
    loop {
        match rest.windows(2).position(|w| w == b"\r\n") {
            Some(i) => {
                lines.push(&rest[..i]);
                rest = &rest[i + 2..];
            }
            None => {
                lines.push(rest);
                break;
            }
        }
    }
    for l in &lines {
        if l.contains(&b'\r') || l.contains(&b'\n') {
            return Err("bare CR or LF in the head");
        }
    }
    let req = lines[0];
    if !req.iter().all(|b| (0x20..0x7f).contains(b)) {
        return Err("the request line is not printable ASCII");
    }
    let parts: Vec<&[u8]> = req.split(|b| *b == b' ').collect();
    let [method, target, version] = parts[..] else {
        return Err("the request line is not METHOD target HTTP/1.x");
    };
    if method.is_empty() || !method.iter().all(|b| tchar(*b)) {
        return Err("bad method");
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return Err("not HTTP/1.x");
    }
    for l in &lines[1..] {
        match l.first() {
            None => return Err("data after the end of the head"),
            Some(b' ' | b'\t') => return Err("obs-fold in the head"),
            Some(_) => {}
        }
        let colon = l
            .iter()
            .position(|b| *b == b':')
            .ok_or("a header line without a colon")?;
        if colon == 0 || !l[..colon].iter().all(|b| tchar(*b)) {
            return Err("bad header name");
        }
        if !l[colon + 1..]
            .iter()
            .all(|b| *b == b'\t' || (0x20..0x7f).contains(b) || *b >= 0x80)
        {
            return Err("a control character in a header");
        }
    }
    if method != b"CONNECT" {
        return Err(NOT_CONNECT);
    }
    // Printable ASCII, checked above.
    let target = std::str::from_utf8(target).map_err(|_| "bad target")?;
    parse_target(target)
}

fn parse_target(t: &str) -> Result<(String, u16), &'static str> {
    if t.starts_with('[') {
        return Err(IP_LITERAL);
    }
    let (h, p) = t.rsplit_once(':').ok_or("the target is not host:port")?;
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err("bad port");
    }
    let port = p.parse::<u32>().map_err(|_| "bad port")?;
    let port = u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .ok_or("bad port")?;
    if h.contains(':') {
        return Err(IP_LITERAL);
    }
    Ok((host_name(h)?, port))
}

/// A label that makes a WHATWG URL parser read the name as IPv4: decimal,
/// or `0x` hex (octal is decimal digits).
fn numeric_label(l: &str) -> bool {
    let hex = l
        .strip_prefix("0x")
        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    hex || (!l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
}

/// `h` as a DNS name: lowercased, one trailing dot removed, labels of 1..=63
/// `[a-z0-9-]` not starting or ending with `-`, at most 253 bytes. Anything
/// an address parser would take (dotted, short, decimal, hex or octal IPv4,
/// IPv6) is [`IP_LITERAL`].
pub(crate) fn host_name(h: &str) -> Result<String, &'static str> {
    let mut h = h.to_ascii_lowercase();
    if h.ends_with('.') {
        h.pop();
    }
    if h.is_empty() {
        return Err("empty host");
    }
    if h.parse::<Ipv4Addr>().is_ok() || h.parse::<Ipv6Addr>().is_ok() || h.contains(':') {
        return Err(IP_LITERAL);
    }
    if h.rsplit('.').next().is_some_and(numeric_label) {
        return Err(IP_LITERAL);
    }
    if h.len() > 253 {
        return Err("host name too long");
    }
    for label in h.split('.') {
        let b = label.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 63
            && b[0] != b'-'
            && b[b.len() - 1] != b'-'
            && b.iter()
                .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'));
        if !ok {
            return Err("bad host name");
        }
    }
    Ok(h)
}

fn rule_matches(rule: &str, host: &str) -> bool {
    match rule.strip_prefix("*.") {
        Some(suffix) => {
            let Ok(s) = host_name(suffix) else {
                return false;
            };
            // `*.com` allows nothing: the suffix needs two labels.
            s.split('.').count() >= 2
                && host.len() > s.len() + 1
                && host.ends_with(s.as_str())
                && host.as_bytes()[host.len() - s.len() - 1] == b'.'
        }
        None => host_name(rule).is_ok_and(|r| r == host),
    }
}

/// Whether `host:port` is on the allow-list: an exact name, or
/// `*.<suffix>` (a suffix of at least two labels) for a name with at least
/// one more label; the port equal. Rules are checked again here, so a
/// malformed one allows nothing.
pub fn allowed(rules: &[EgressRule], host: &str, port: u16) -> bool {
    let Ok(host) = host_name(host) else {
        return false;
    };
    rules
        .iter()
        .any(|r| r.port == port && rule_matches(&r.host, &host))
}

fn in_v4(n: u32, base: u32, len: u32) -> bool {
    len == 0 || (n >> (32 - len)) == (base >> (32 - len))
}

fn in_v6(n: u128, base: u128, len: u32) -> bool {
    len == 0 || (n >> (128 - len)) == (base >> (128 - len))
}

/// IPv4 ranges that are not public (G7).
const V4_BLOCKED: [(u32, u32); 16] = [
    (0x0000_0000, 8),  // 0/8 this network
    (0x0a00_0000, 8),  // 10/8
    (0x6440_0000, 10), // 100.64/10 CGNAT
    (0x7f00_0000, 8),  // 127/8
    (0xa9fe_0000, 16), // 169.254/16 link-local
    (0xac10_0000, 12), // 172.16/12
    (0xc000_0000, 24), // 192.0.0/24 IETF protocol assignments
    (0xc000_0200, 24), // 192.0.2/24 TEST-NET-1
    (0xc058_6300, 24), // 192.88.99/24 6to4 relay anycast
    (0xc0a8_0000, 16), // 192.168/16
    (0xc612_0000, 15), // 198.18/15 benchmarking
    (0xc633_6400, 24), // 198.51.100/24 TEST-NET-2
    (0xcb00_7100, 24), // 203.0.113/24 TEST-NET-3
    (0xe000_0000, 4),  // 224/4 multicast
    (0xf000_0000, 4),  // 240/4 reserved
    (0xffff_ffff, 32), // broadcast
];

const fn v6(hi: u64) -> u128 {
    (hi as u128) << 64
}

/// IPv6 ranges that are not public (G7). The forms that embed an IPv4
/// address are checked by that address in [`public`] first.
const V6_BLOCKED: [(u128, u32); 9] = [
    (0, 96),                         // ::/96: ::, ::1 and IPv4-compatible
    (v6(0x0064_ff9b_0001_0000), 48), // 64:ff9b:1::/48 local-use NAT64
    (v6(0x0100_0000_0000_0000), 64), // 100::/64 discard
    (v6(0x2001_0000_0000_0000), 23), // 2001::/23 IETF protocol assignments (Teredo)
    (v6(0x2001_0db8_0000_0000), 32), // 2001:db8::/32 documentation
    (v6(0xfc00_0000_0000_0000), 7),  // fc00::/7 ULA
    (v6(0xfe80_0000_0000_0000), 10), // fe80::/10 link-local
    (v6(0xfec0_0000_0000_0000), 10), // fec0::/10 site-local
    (v6(0xff00_0000_0000_0000), 8),  // ff00::/8 multicast
];

fn public_v4(a: Ipv4Addr) -> bool {
    let n = u32::from(a);
    !V4_BLOCKED.iter().any(|(b, l)| in_v4(n, *b, *l))
}

fn public_v6(a: &Ipv6Addr) -> bool {
    let n = u128::from(*a);
    let low32 = Ipv4Addr::from((n & 0xffff_ffff) as u32);
    // ::ffff:0:0/96 mapped, ::ffff:0:0:0/96 translated, 64:ff9b::/96 NAT64.
    if in_v6(n, 0xffff << 32, 96) || in_v6(n, 0xffff << 48, 96) || in_v6(n, 0x0064_ff9b << 96, 96) {
        return public_v4(low32);
    }
    // 2002::/16 6to4: the IPv4 address is bits 16..48.
    if in_v6(n, 0x2002 << 112, 16) {
        return public_v4(Ipv4Addr::from(((n >> 80) & 0xffff_ffff) as u32));
    }
    !V6_BLOCKED.iter().any(|(b, l)| in_v6(n, *b, *l))
}

/// Whether `ip` is a public address (G7): not unspecified, loopback,
/// RFC 1918, CGNAT, link-local, ULA, site-local, multicast, documentation,
/// benchmarking or reserved, and not an IPv4-mapped, translated, NAT64 or
/// 6to4 form of one.
pub fn public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => public_v4(*a),
        IpAddr::V6(a) => public_v6(a),
    }
}

/// A refused connection: the answer and its `egress_denied` record.
pub(crate) struct Refusal {
    pub code: u16,
    pub msg: String,
    pub reason: &'static str,
    pub host: Option<String>,
    pub port: Option<u16>,
}

impl Refusal {
    pub(crate) fn new(code: u16, msg: impl Into<String>, reason: &'static str) -> Refusal {
        Refusal {
            code,
            msg: msg.into(),
            reason,
            host: None,
            port: None,
        }
    }

    fn to(mut self, host: &str, port: u16) -> Refusal {
        self.host = Some(host.to_string());
        self.port = Some(port);
        self
    }
}

/// Write a short `text/plain` answer and close the write side, within 5 s.
pub(crate) async fn answer<S: AsyncWrite + Unpin>(s: &mut S, code: u16, msg: &str) {
    let reason = match code {
        400 => "Bad Request",
        403 => "Forbidden",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let body = format!("{msg}\n");
    let text = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::time::timeout(Duration::from_secs(ANSWER_SECS), async {
        s.write_all(text.as_bytes()).await?;
        s.shutdown().await
    })
    .await;
}

enum HeadRead {
    /// The head is `buf[..end]`; the rest was sent after it.
    Done {
        buf: Vec<u8>,
        end: usize,
    },
    Malformed,
    TooLarge,
    Closed,
}

/// Read up to `max` bytes until CRLFCRLF. A NUL, bare LF or bare CR ends
/// the read at once (the head is refused, not waited for).
async fn read_head<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> HeadRead {
    let mut buf = vec![0u8; max];
    let mut len = 0;
    loop {
        if len == max {
            return HeadRead::TooLarge;
        }
        let n = match r.read(&mut buf[len..]).await {
            Ok(0) | Err(_) => return HeadRead::Closed,
            Ok(n) => n,
        };
        for i in len..len + n {
            let b = buf[i];
            let prev = if i > 0 { buf[i - 1] } else { 0 };
            if b == 0 || (b == b'\n' && prev != b'\r') || (prev == b'\r' && b != b'\n') {
                return HeadRead::Malformed;
            }
            if i >= 3 && &buf[i - 3..=i] == b"\r\n\r\n" {
                buf.truncate(len + n);
                return HeadRead::Done { buf, end: i + 1 };
            }
        }
        len += n;
    }
}

/// What a connection needs once every check passed.
struct Ready {
    upstream: TcpStream,
    leftover: Vec<u8>,
    host: String,
    port: u16,
    addr: SocketAddr,
    session: String,
}

/// The head, then every check of G6–G9, then the upstream connection.
/// `Ok(None)`: the guest closed before sending a head (nothing to answer).
async fn prepare(
    stream: &mut UnixStream,
    run: &BoxRun,
    gw: &GatewayShared,
) -> Result<Option<Ready>, Refusal> {
    let lim = &gw.limits;
    let read = tokio::time::timeout(
        Duration::from_secs(lim.head_secs),
        read_head(stream, lim.head_bytes),
    )
    .await
    .map_err(|_| {
        Refusal::new(
            408,
            "the request head did not arrive in time",
            "head_timeout",
        )
    })?;
    let (buf, end) = match read {
        HeadRead::Done { buf, end } => (buf, end),
        HeadRead::Closed => return Ok(None),
        HeadRead::TooLarge => {
            return Err(Refusal::new(
                400,
                "bad CONNECT request: request head too large",
                "head_too_large",
            ))
        }
        HeadRead::Malformed => {
            return Err(Refusal::new(
                400,
                "bad CONNECT request: bare CR, LF or NUL in the head",
                "bad_request",
            ))
        }
    };
    let (host, port) = parse_connect(&buf[..end]).map_err(|e| match e {
        NOT_CONNECT => Refusal::new(403, PLAIN_HTTP, "plain_http"),
        IP_LITERAL => Refusal::new(403, IP_LITERAL_MSG, "ip_literal"),
        other => Refusal::new(400, format!("bad CONNECT request: {other}"), "bad_request"),
    })?;
    let leftover = buf[end..].to_vec();
    drop(buf);
    let locked = || {
        gw.locked().then(|| {
            Refusal::new(503, "saiife lockdown is on: egress is refused", "lockdown")
                .to(&host, port)
        })
    };
    if let Some(r) = locked() {
        return Err(r);
    }
    let unknown = || Refusal::new(403, "this box is not known", "unknown_box").to(&host, port);
    let Some(ctx) = gw.ctx() else {
        return Err(
            Refusal::new(503, "saiife is stopping: egress is refused", "stopping").to(&host, port),
        );
    };
    let Some(mgr) = ctx.box_manager.clone() else {
        return Err(unknown());
    };
    drop(ctx);
    // The template's rules are read once per connection.
    let id = run.id.clone();
    let found = tokio::task::spawn_blocking(move || {
        let r = mgr.get(&id).ok()?;
        let rules = mgr
            .templates()
            .into_iter()
            .find(|t| t.name == r.template)
            .map(|t| t.egress)
            .unwrap_or_default();
        Some((r.session, rules))
    })
    .await
    .ok()
    .flatten();
    let Some((session, rules)) = found else {
        return Err(unknown());
    };
    if !allowed(&rules, &host, port) {
        return Err(Refusal::new(
            403,
            format!("{host}:{port} is not in this box's allow-list"),
            "not_allowed",
        )
        .to(&host, port));
    }
    let answers = resolve_checked(&host, port, run, gw).await?;
    let first = answers[0];
    // The checked address itself, never the name again.
    let upstream = tokio::time::timeout(
        Duration::from_secs(lim.connect_secs),
        TcpStream::connect(first),
    )
    .await
    .map_err(|_| {
        Refusal::new(
            504,
            format!("{host}:{port} did not answer in time"),
            "connect_timeout",
        )
        .to(&host, port)
    })?
    .map_err(|_| {
        Refusal::new(
            502,
            format!("cannot connect to {host}:{port}"),
            "connect_failed",
        )
        .to(&host, port)
    })?;
    if let Some(r) = locked() {
        return Err(r);
    }
    Ok(Some(Ready {
        upstream,
        leftover,
        host,
        port,
        addr: first,
        session,
    }))
}

/// A lookup's refusal that the box's negative cache remembers for
/// [`super::NEG_TTL_MS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Neg {
    /// No answer (NXDOMAIN, empty, or a resolver error).
    NoAddress,
    Timeout,
    Private,
}

impl Neg {
    fn refusal(self, host: &str, port: u16) -> Refusal {
        let r = match self {
            Neg::NoAddress => Refusal::new(502, format!("{host} did not resolve"), "no_address"),
            Neg::Timeout => Refusal::new(
                504,
                format!("{host} did not resolve in time"),
                "resolve_timeout",
            ),
            Neg::Private => Refusal::new(
                403,
                format!("{host} resolves to a private address"),
                "private_address",
            ),
        };
        r.to(host, port)
    }
}

/// The answers for `host`, every one public (G7), on `port`.
///
/// A refusal remembered in the box's negative cache is answered again
/// without a permit or a lookup. Otherwise the lookup takes one of the
/// box's permits, then one of the gateway's (none free: `503 lookup_busy`,
/// for this box only when it is the box's own cap), and gets
/// `resolve_secs`. The permits go to the resolver in a [`super::LookupHold`]:
/// an async resolver drops them with its future at the deadline, and
/// [`super::SystemResolve`] keeps them until its thread really ends, so a
/// box's stuck `getaddrinfo` threads count against that box.
async fn resolve_checked(
    host: &str,
    port: u16,
    run: &BoxRun,
    gw: &GatewayShared,
) -> Result<Vec<SocketAddr>, Refusal> {
    if let Some(neg) = run.neg_get(host, (gw.clock)()) {
        return Err(neg.refusal(host, port));
    }
    let busy =
        || Refusal::new(503, "too many name lookups in progress", "lookup_busy").to(host, port);
    let Ok(mine) = Arc::clone(&run.lookups).try_acquire_owned() else {
        return Err(busy());
    };
    let Ok(all) = Arc::clone(&gw.lookups).try_acquire_owned() else {
        return Err(busy());
    };
    let hold = super::LookupHold {
        _permits: vec![mine, all],
    };
    let looked = tokio::time::timeout(
        Duration::from_secs(gw.limits.resolve_secs),
        gw.resolve.lookup(host, port, hold),
    )
    .await;
    let found = match looked {
        Err(_) => Err(Neg::Timeout),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => return Err(busy()),
        Ok(Err(_)) => Err(Neg::NoAddress),
        Ok(Ok(v)) => {
            // The port is the one asked for, never the resolver's.
            let v: Vec<SocketAddr> = v
                .into_iter()
                .take(super::MAX_ANSWERS)
                .map(|a| SocketAddr::new(a.ip(), port))
                .collect();
            if v.is_empty() {
                Err(Neg::NoAddress)
            } else if !v.iter().all(|a| gw.address_ok(&a.ip())) {
                Err(Neg::Private)
            } else {
                Ok(v)
            }
        }
    };
    found.map_err(|neg| {
        run.neg_put(host, neg, (gw.clock)());
        neg.refusal(host, port)
    })
}

/// Copy `r` to `w` until EOF (then shut `w`), counting bytes into `n` and
/// stamping `last` (ms since `t0`) on each chunk.
async fn pump<R, W>(
    r: &mut R,
    w: &mut W,
    n: &AtomicU64,
    last: &AtomicU64,
    t0: Instant,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BYTES];
    loop {
        let k = r.read(&mut buf).await?;
        if k == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..k]).await?;
        n.fetch_add(k as u64, Ordering::Relaxed);
        last.store(ms_since(t0), Ordering::Relaxed);
    }
}

fn ms_since(t0: Instant) -> u64 {
    u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Ends once `idle` passed with no byte either way.
async fn idle_watch(last: &AtomicU64, t0: Instant, idle: Duration) {
    let idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX);
    loop {
        let since = ms_since(t0).saturating_sub(last.load(Ordering::Relaxed));
        if since >= idle_ms {
            return;
        }
        tokio::time::sleep(Duration::from_millis(idle_ms - since)).await;
    }
}

/// Ends once a lockdown that blocks connectors is on (checked every 5 s).
async fn lockdown_watch(gw: &GatewayShared) {
    let mut every = tokio::time::interval(Duration::from_secs(super::LOCKDOWN_CHECK_SECS));
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        if gw.locked() {
            return;
        }
    }
}

/// The open tunnel: the 200, the bytes sent after the head, then both
/// directions until both ends close, an error, the idle timeout, lockdown
/// or the box going off. Returns (bytes up, bytes down, outcome).
async fn tunnel(
    stream: &mut UnixStream,
    ready: &mut Ready,
    gw: &GatewayShared,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) -> (u64, u64, &'static str) {
    let t0 = Instant::now();
    let up = AtomicU64::new(0);
    let down = AtomicU64::new(0);
    let last = AtomicU64::new(0);
    let idle = Duration::from_secs(gw.limits.idle_secs);
    let leftover = std::mem::take(&mut ready.leftover);
    let (mut cr, mut cw) = stream.split();
    let (mut ur, mut uw) = ready.upstream.split();
    let both = async {
        cw.write_all(ESTABLISHED).await?;
        if !leftover.is_empty() {
            uw.write_all(&leftover).await?;
            up.fetch_add(leftover.len() as u64, Ordering::Relaxed);
            last.store(ms_since(t0), Ordering::Relaxed);
        }
        tokio::try_join!(
            pump(&mut cr, &mut uw, &up, &last, t0),
            pump(&mut ur, &mut cw, &down, &last, t0)
        )
    };
    let outcome = tokio::select! {
        r = both => if r.is_ok() { "closed" } else { "error" },
        () = super::stopped(stop) => "stopped",
        () = lockdown_watch(gw) => "lockdown",
        () = idle_watch(&last, t0, idle) => "idle",
    };
    (
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed),
        outcome,
    )
}

/// Serve one guest connection on the egress port of box `id` (nothing when
/// the box has no gateway run).
pub async fn serve(stream: UnixStream, id: BoxId, gw: Arc<GatewayShared>) {
    let Some(run) = gw.run(&id) else {
        return;
    };
    serve_run(stream, run, gw).await;
}

pub(crate) async fn serve_run(mut stream: UnixStream, run: Arc<BoxRun>, gw: Arc<GatewayShared>) {
    let t0 = Instant::now();
    let mut stop = run.stop.subscribe();
    if *stop.borrow_and_update() {
        return;
    }
    if !run.take_token((gw.clock)(), &gw.limits) {
        let r = Refusal::new(
            429,
            "too many new connections from this box",
            "rate_limited",
        );
        answer(&mut stream, r.code, &r.msg).await;
        deny(&gw, &run.id, r).await;
        return;
    }
    let Some(slot) = Slot::take(&run, gw.limits.tunnels) else {
        let r = Refusal::new(
            429,
            "too many open tunnels from this box",
            "too_many_tunnels",
        );
        answer(&mut stream, r.code, &r.msg).await;
        deny(&gw, &run.id, r).await;
        return;
    };
    let prepared = tokio::select! {
        p = prepare(&mut stream, &run, &gw) => p,
        () = super::stopped(&mut stop) => return,
    };
    let mut ready = match prepared {
        Ok(Some(r)) => r,
        Ok(None) => return,
        Err(r) => {
            answer(&mut stream, r.code, &r.msg).await;
            drop(stream);
            drop(slot);
            deny(&gw, &run.id, r).await;
            return;
        }
    };
    let (up, down, outcome) = tunnel(&mut stream, &mut ready, &gw, &mut stop).await;
    drop(stream);
    let Ready {
        upstream,
        host,
        port,
        addr,
        session,
        ..
    } = ready;
    drop(upstream);
    drop(slot);
    let ms = ms_since(t0);
    let Some(ctx) = gw.ctx() else {
        eprintln!("saiifed: boxes: an egress record was not written: saiife is stopping");
        return;
    };
    let mut rec = ctx.record("egress", &format!("{host}:{port}"));
    rec.session = Some(session);
    let x = &mut rec.extra;
    x.insert("box".into(), run.id.as_str().into());
    x.insert("dest_host".into(), host.into());
    x.insert("port".into(), port.into());
    x.insert("addr".into(), addr.to_string().into());
    x.insert("bytes_up".into(), up.into());
    x.insert("bytes_down".into(), down.into());
    x.insert("ms".into(), ms.into());
    x.insert("outcome".into(), outcome.into());
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiifed: warning: cannot write an egress record: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_rules() {
        for s in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.5",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:0:10.0.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b:1::8.8.8.8",
            "100::1",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:1ff::1",
            "2001:db8::1",
            "2002:0a00:0001::1",
            "2002:7f00:0001::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "::8.8.8.8",
            "::10.0.0.1",
        ] {
            assert!(!public(&ip(s)), "{s} should not be public");
        }
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.0.1.1",
            "198.17.255.255",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
            "64:ff9b::8.8.8.8",
            "2002:0808:0808::1",
        ] {
            assert!(public(&ip(s)), "{s} should be public");
        }
    }

    fn head(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn parse_connect_accepts_connect() {
        assert_eq!(
            parse_connect(&head(
                "CONNECT Example.Test.:443 HTTP/1.1\r\nHost: x\r\nUser-Agent: a\tb\r\n\r\n"
            )),
            Ok(("example.test".into(), 443))
        );
        assert_eq!(
            parse_connect(&head("CONNECT a-b.c9.test:0443 HTTP/1.0\r\n\r\n")),
            Ok(("a-b.c9.test".into(), 443))
        );
        assert_eq!(
            parse_connect(&head("CONNECT x.test:65535 HTTP/1.1\r\n\r\n")),
            Ok(("x.test".into(), 65535))
        );
    }

    #[test]
    fn parse_connect_refusals() {
        assert_eq!(
            parse_connect(&head("GET http://x.test/ HTTP/1.1\r\nHost: x\r\n\r\n")),
            Err(NOT_CONNECT)
        );
        for t in [
            "127.0.0.1:443",
            "[::1]:443",
            "::1:443",
            "2130706433:443",
            "0x7f.1:443",
            "127.1:443",
            "0177.0.0.1:443",
            "foo.0x:443",
            "8.8.8.8.:443",
        ] {
            assert_eq!(
                parse_connect(&head(&format!("CONNECT {t} HTTP/1.1\r\n\r\n"))),
                Err(IP_LITERAL),
                "{t}"
            );
        }
        let bad = [
            "CONNECT x.test:443 HTTP/1.1\r\n",
            "CONNECT x.test:443 HTTP/1.1\n\r\n\r\n",
            "CONNECT x.test:443 HTTP/1.1\r\nA: b\r\n c\r\n\r\n",
            "CONNECT x.test:443 HTTP/1.1\r\nA: b\rc\r\n\r\n",
            "CONNECT x.test:443 HTTP/1.1\r\nA b\r\n\r\n",
            "CONNECT x.test:443 HTTP/1.1\r\n: b\r\n\r\n",
            "CONNECT x.test:443 HTTP/1.1\r\nA: \x01\r\n\r\n",
            "CONNECT x.test:443 HTTP/1.1\r\n\r\nA: b\r\n\r\n",
            "CONNECT x.test:443 HTTP/1.1 \r\n\r\n",
            "CONNECT  x.test:443 HTTP/1.1\r\n\r\n",
            "CONNECT x.test:443 HTTP/2\r\n\r\n",
            "CONNECT x.test:0 HTTP/1.1\r\n\r\n",
            "CONNECT x.test:65536 HTTP/1.1\r\n\r\n",
            "CONNECT x.test:100000 HTTP/1.1\r\n\r\n",
            "CONNECT x.test:+443 HTTP/1.1\r\n\r\n",
            "CONNECT x.test: HTTP/1.1\r\n\r\n",
            "CONNECT x.test HTTP/1.1\r\n\r\n",
            "CONNECT :443 HTTP/1.1\r\n\r\n",
            "CONNECT .:443 HTTP/1.1\r\n\r\n",
            "CONNECT -x.test:443 HTTP/1.1\r\n\r\n",
            "CONNECT x-.test:443 HTTP/1.1\r\n\r\n",
            "CONNECT x..test:443 HTTP/1.1\r\n\r\n",
            "CONNECT x_y.test:443 HTTP/1.1\r\n\r\n",
            "CONNECT x.test..:443 HTTP/1.1\r\n\r\n",
            "CONNECT user@x.test:443 HTTP/1.1\r\n\r\n",
            "C@NNECT x.test:443 HTTP/1.1\r\n\r\n",
        ];
        for h in bad {
            let r = parse_connect(&head(h));
            assert!(
                r.is_err() && r != Err(NOT_CONNECT) && r != Err(IP_LITERAL),
                "{h:?}: {r:?}"
            );
        }
        let long = format!("CONNECT {}.test:443 HTTP/1.1\r\n\r\n", "a".repeat(64));
        assert!(parse_connect(long.as_bytes()).is_err());
        let name = format!("{}.test", vec!["a".repeat(60); 5].join("."));
        assert!(name.len() > 253);
        let long = format!("CONNECT {name}:443 HTTP/1.1\r\n\r\n");
        assert!(parse_connect(long.as_bytes()).is_err());
        assert!(parse_connect(b"CONNECT x\0.test:443 HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_connect(b"CONNECT x\xc3\xa9.test:443 HTTP/1.1\r\n\r\n").is_err());
        // obs-text in a header value is allowed (and never looked at).
        assert!(parse_connect(b"CONNECT x.test:443 HTTP/1.1\r\nA: \xc3\xa9\r\n\r\n").is_ok());
    }

    fn rules(r: &[(&str, u16)]) -> Vec<EgressRule> {
        r.iter()
            .map(|(h, p)| EgressRule {
                host: (*h).into(),
                port: *p,
            })
            .collect()
    }

    #[test]
    fn allowed_rules() {
        let r = rules(&[
            ("example.test", 443),
            ("*.crates.test", 443),
            ("*.com", 443),
            ("*.Upper.Test.", 443),
            ("bad_rule.test", 443),
            ("*.*.x.test", 443),
            ("*", 443),
            ("127.0.0.1", 443),
        ]);
        assert!(allowed(&r, "example.test", 443));
        assert!(allowed(&r, "EXAMPLE.test.", 443));
        assert!(!allowed(&r, "example.test", 80));
        assert!(!allowed(&r, "a.example.test", 443));
        assert!(allowed(&r, "a.crates.test", 443));
        assert!(allowed(&r, "a.b.crates.test", 443));
        assert!(!allowed(&r, "crates.test", 443));
        assert!(!allowed(&r, "evilcrates.test", 443));
        assert!(!allowed(&r, "a.crates.test.evil", 443));
        assert!(!allowed(&r, "a.com", 443));
        assert!(!allowed(&r, "google.com", 443));
        assert!(allowed(&r, "a.upper.test", 443));
        assert!(!allowed(&r, "bad_rule.test", 443));
        assert!(!allowed(&r, "a.b.x.test", 443));
        assert!(!allowed(&r, "127.0.0.1", 443));
        assert!(!allowed(&r, "anything", 443));
        assert!(!allowed(&[], "example.test", 443));
    }
}
