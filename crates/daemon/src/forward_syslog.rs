//! The `syslog` forwarding target (plan 12 decision 3): RFC 5424 messages
//! whose MSG is the exact JSONL line.
//!
//! Each message is `<PRI>1 TIMESTAMP HOSTNAME saiife - KIND SD MSG`:
//!
//! - PRI is the facility (`local0` unless `facility` says otherwise) times
//!   8 plus the severity: `warning` (4) for a record whose decision is
//!   `deny`, `error_allowed` or `error_denied`, else `info` (6).
//! - TIMESTAMP is the record's `ts` (already RFC 3339 UTC with
//!   milliseconds); a line without a well-formed one gets the send time.
//! - HOSTNAME is the kernel host name (`-` when it is not printable ASCII).
//! - KIND (the MSGID) is the record's `kind`, `guard` when absent, `-` for
//!   a line that is not a JSON object.
//! - SD is `[saiife@32473 seq="N"]` in the `rfc5424` format (`-` for a line
//!   without a `seq`), always `-` in `rfc5424-json`.
//! - MSG is the line, byte for byte, without a BOM.
//!
//! Local (`unix:<path>`, normally [`DEFAULT_SOCKET`]): one datagram per record. A
//! message over [`MAX_DATAGRAM`] (8 KiB; 2 KiB on macOS) is cut at a character boundary and ends with
//! `…[truncated]` (that line cannot be verified from the copy). When the
//! socket is a stream socket, every message goes over it with octet-counting
//! framing instead, uncut.
//!
//! Remote (`tls://host:port`, RFC 5425): one TCP+TLS connection per batch,
//! no ALPN, the certificate checked against the configured host name,
//! octet-counting framing (`LEN SP MSG`, RFC 6587), the whole batch within
//! 30 s. Syslog has no acknowledgement: a batch counts as delivered once it
//! was written, flushed and the TLS session closed cleanly.

use crate::forwarder::{SendError, SendFuture, TargetClient, Transport, SEND_TIMEOUT};
use bytes::Bytes;
use rustls::pki_types::ServerName;
use saiife_policy::SyslogFormat;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UnixDatagram, UnixStream};

/// The largest local datagram; a longer message is cut.
#[cfg(not(target_os = "macos"))]
pub const MAX_DATAGRAM: usize = 8192;
/// The largest local datagram; a longer message is cut. 2 KiB on macOS:
/// its local datagram sockets refuse a larger one (`EMSGSIZE`, "Message
/// too long": `net.local.dgram.maxdgram` is 2048), and 2048 octets is
/// what RFC 5424 §6.1 asks every receiver to take.
#[cfg(target_os = "macos")]
pub const MAX_DATAGRAM: usize = 2048;
/// Ends a cut message.
pub const TRUNCATED_MARK: &str = "…[truncated]";
/// Records per batch.
pub const MAX_RECORDS: usize = 500;
/// Bytes per batch.
pub const MAX_BYTES: usize = 1 << 20;

const SEV_WARNING: u8 = 4;
const SEV_INFO: u8 = 6;

/// The host's local syslog socket: `/dev/log` on Linux, `/var/run/syslog`
/// on macOS.
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_SOCKET: &str = "/dev/log";
/// The host's local syslog socket: `/dev/log` on Linux, `/var/run/syslog`
/// on macOS.
#[cfg(target_os = "macos")]
pub const DEFAULT_SOCKET: &str = "/var/run/syslog";

/// Where the messages go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dest {
    /// A local socket (`unix:/dev/log`, `unix:/var/run/syslog`).
    Unix(PathBuf),
    /// `tls://host:port`; `host` without IPv6 brackets.
    Tls { host: String, port: u16 },
}

impl Dest {
    /// A validated `address` (`unix:/path` or `tls://host:port`).
    pub fn parse(address: &str) -> Result<Dest, String> {
        if let Some(p) = address.strip_prefix("unix:") {
            return Ok(Dest::Unix(PathBuf::from(p)));
        }
        let bad = || format!("syslog address {address:?} is not unix:/path or tls://host:port");
        let hp = address.strip_prefix("tls://").ok_or_else(bad)?;
        let (host, port) = hp.rsplit_once(':').ok_or_else(bad)?;
        let port: u16 = port.parse().map_err(|_| bad())?;
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() {
            return Err(bad());
        }
        Ok(Dest::Tls {
            host: host.to_string(),
            port,
        })
    }
}

/// Sends RFC 5424 messages to a local socket or a TLS syslog server.
pub struct SyslogTransport {
    dest: Dest,
    format: SyslogFormat,
    facility: u8,
    hostname: String,
    client: TargetClient,
    /// The whole batch, local or remote, ends within this ([`SEND_TIMEOUT`]):
    /// a local socket nobody reads blocks a send, it never fails it.
    timeout: std::time::Duration,
}

impl std::fmt::Debug for SyslogTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyslogTransport")
            .field("dest", &self.dest)
            .field("format", &self.format)
            .field("facility", &self.facility)
            .finish()
    }
}

/// Printable ASCII without spaces, at most `max` bytes, else `-`.
fn header_field(s: &str, max: usize) -> String {
    if !s.is_empty() && s.len() <= max && s.bytes().all(|b| (33..=126).contains(&b)) {
        s.to_string()
    } else {
        "-".to_string()
    }
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`, the shape every record's `ts` has.
fn well_formed_ts(ts: &str) -> bool {
    let b = ts.as_bytes();
    let shape = b"dddd-dd-ddTdd:dd:dd.dddZ";
    b.len() == shape.len()
        && b.iter().zip(shape).all(|(c, s)| match s {
            b'd' => c.is_ascii_digit(),
            s => c == s,
        })
}

fn now_ts() -> String {
    let f = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    time::OffsetDateTime::now_utc()
        .format(f)
        .unwrap_or_else(|_| "-".into())
}

impl SyslogTransport {
    /// `facility` is the code (`facility_code`); `hostname` goes in the
    /// header; `client` is the TLS client of a `tls://` destination.
    pub fn new(
        dest: Dest,
        format: SyslogFormat,
        facility: u8,
        hostname: String,
        client: TargetClient,
    ) -> SyslogTransport {
        SyslogTransport {
            dest,
            format,
            facility,
            hostname: header_field(&hostname, 255),
            client,
            timeout: SEND_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_send_timeout(mut self, t: std::time::Duration) -> Self {
        self.timeout = t;
        self
    }

    /// The whole RFC 5424 message of one line.
    pub fn message(&self, line: &[u8]) -> Vec<u8> {
        let v: Option<serde_json::Map<String, serde_json::Value>> =
            serde_json::from_slice(line).ok();
        let field = |k: &str| v.as_ref().and_then(|m| m.get(k));
        let warn = matches!(
            field("decision").and_then(|d| d.as_str()),
            Some("deny" | "error_allowed" | "error_denied")
        );
        let pri =
            u16::from(self.facility) * 8 + u16::from(if warn { SEV_WARNING } else { SEV_INFO });
        let ts = field("ts")
            .and_then(|t| t.as_str())
            .filter(|t| well_formed_ts(t))
            .map_or_else(now_ts, str::to_string);
        let kind = match (&v, field("kind")) {
            (None, _) => "-".to_string(),
            (Some(_), None) => "guard".to_string(),
            (Some(_), Some(k)) => header_field(k.as_str().unwrap_or(""), 32),
        };
        let sd = match (self.format, field("seq").and_then(|s| s.as_u64())) {
            (SyslogFormat::Rfc5424, Some(seq)) => format!("[saiife@32473 seq=\"{seq}\"]"),
            _ => "-".to_string(),
        };
        let mut out = format!("<{pri}>1 {ts} {} saiife - {kind} {sd} ", self.hostname).into_bytes();
        out.extend_from_slice(line);
        out
    }

    async fn send_unix(&self, path: &std::path::Path, lines: &[Bytes]) -> Result<(), SendError> {
        let retry = |e: std::io::Error| SendError::Retry(format!("{}: {e}", path.display()));
        let sock = UnixDatagram::unbound().map_err(retry)?;
        match sock.connect(path) {
            Ok(()) => {
                for line in lines {
                    let msg = truncate(self.message(line));
                    sock.send(&msg).await.map_err(retry)?;
                }
                Ok(())
            }
            // A stream socket: octet-counting, nothing cut.
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::PROTOTYPE.raw_os_error()) => {
                let mut s = UnixStream::connect(path).await.map_err(retry)?;
                s.write_all(&self.framed(lines)).await.map_err(retry)?;
                s.flush().await.map_err(retry)?;
                s.shutdown().await.map_err(retry)
            }
            Err(e) => Err(retry(e)),
        }
    }

    /// The batch with octet-counting framing (`LEN SP MSG`).
    fn framed(&self, lines: &[Bytes]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in lines {
            let msg = self.message(line);
            out.extend_from_slice(format!("{} ", msg.len()).as_bytes());
            out.extend_from_slice(&msg);
        }
        out
    }

    async fn send_tls(&self, host: &str, port: u16, lines: &[Bytes]) -> Result<(), String> {
        let up = self.client.get()?;
        let resolver = up.resolver();
        let h = host.to_string();
        let addrs: Vec<SocketAddr> =
            tokio::task::spawn_blocking(move || resolver.resolve(&h, port))
                .await
                .map_err(|e| format!("resolve {host}: {e}"))?
                .map_err(|e| format!("resolve {host}: {e}"))?;
        let mut tcp = None;
        let mut last = "no address".to_string();
        for a in addrs {
            match TcpStream::connect(a).await {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = e.to_string(),
            }
        }
        let tcp = tcp.ok_or_else(|| format!("connect {host}:{port}: {last}"))?;
        let _ = tcp.set_nodelay(true);
        let name = ServerName::try_from(host.to_string())
            .map_err(|e| format!("TLS server name {host}: {e}"))?;
        // No ALPN: a syslog server is not an HTTP server.
        let mut tls = up
            .tls_connector_with_alpn(&[])
            .connect(name, tcp)
            .await
            .map_err(|e| format!("TLS {host}: {e}"))?;
        let w = |e: std::io::Error| format!("send to {host}:{port}: {e}");
        tls.write_all(&self.framed(lines)).await.map_err(w)?;
        tls.flush().await.map_err(w)?;
        tls.shutdown().await.map_err(w)
    }
}

/// A datagram of at most [`MAX_DATAGRAM`] bytes: a longer message is cut at
/// a character boundary and marked.
fn truncate(mut msg: Vec<u8>) -> Vec<u8> {
    if msg.len() <= MAX_DATAGRAM {
        return msg;
    }
    let mut cut = MAX_DATAGRAM - TRUNCATED_MARK.len();
    while cut > 0 && (msg[cut] & 0xC0) == 0x80 {
        cut -= 1;
    }
    msg.truncate(cut);
    msg.extend_from_slice(TRUNCATED_MARK.as_bytes());
    msg
}

impl Transport for SyslogTransport {
    fn send<'a>(&'a self, lines: &'a [Bytes]) -> SendFuture<'a> {
        Box::pin(async move {
            match &self.dest {
                Dest::Unix(p) => {
                    match tokio::time::timeout(self.timeout, self.send_unix(p, lines)).await {
                        Ok(r) => r,
                        Err(_) => Err(SendError::Retry(format!(
                            "{}: timed out (nobody reads the socket)",
                            p.display()
                        ))),
                    }
                }
                Dest::Tls { host, port } => {
                    match tokio::time::timeout(self.timeout, self.send_tls(host, *port, lines))
                        .await
                    {
                        Ok(r) => r.map_err(SendError::Retry),
                        Err(_) => Err(SendError::Retry(format!("{host}:{port}: timed out"))),
                    }
                }
            }
        })
    }

    fn max_batch(&self) -> (usize, usize) {
        (MAX_RECORDS, MAX_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward_https::testing::{acceptor, pki, upstream, Pki, TEST_HOST};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    const LINE: &str = concat!(
        r#"{"v":1,"seq":42,"prev":"ab","ts":"2026-10-27T10:11:12.345Z","kind":"connector","#,
        r#""input":"say \"hi\" ü \\u0000","decision":"allow","saiife":"0.2.0"}"#
    );
    const DENY: &str = r#"{"v":1,"seq":43,"ts":"2026-10-27T10:11:13.000Z","decision":"deny"}"#;

    fn local(path: PathBuf, format: SyslogFormat) -> SyslogTransport {
        SyslogTransport::new(
            Dest::Unix(path),
            format,
            16,
            "box1".into(),
            TargetClient::new(|| Err("no TLS for a local socket".into())),
        )
    }

    #[test]
    fn default_socket_per_platform() {
        if cfg!(target_os = "macos") {
            assert_eq!(DEFAULT_SOCKET, "/var/run/syslog");
        } else {
            assert_eq!(DEFAULT_SOCKET, "/dev/log");
        }
        assert_eq!(
            Dest::parse(&format!("unix:{DEFAULT_SOCKET}")).unwrap(),
            Dest::Unix(PathBuf::from(DEFAULT_SOCKET))
        );
    }

    #[test]
    fn addresses_parse() {
        assert_eq!(
            Dest::parse("unix:/dev/log").unwrap(),
            Dest::Unix(PathBuf::from("/dev/log"))
        );
        assert_eq!(
            Dest::parse("tls://logs.example.test:6514").unwrap(),
            Dest::Tls {
                host: "logs.example.test".into(),
                port: 6514
            }
        );
        assert_eq!(
            Dest::parse("tls://[::1]:6514").unwrap(),
            Dest::Tls {
                host: "::1".into(),
                port: 6514
            }
        );
        assert!(Dest::parse("udp://x:1").is_err());
    }

    #[tokio::test]
    async fn syslog_local_datagram_header_and_exact_msg() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("log");
        let server = UnixDatagram::bind(&path).unwrap();
        let json = local(path.clone(), SyslogFormat::Rfc5424Json);
        let lines = [
            Bytes::from_static(LINE.as_bytes()),
            Bytes::from_static(DENY.as_bytes()),
        ];
        json.send(&lines).await.unwrap();
        let mut buf = vec![0u8; 65536];
        let n = server.recv(&mut buf).await.unwrap();
        let want = format!("<134>1 2026-10-27T10:11:12.345Z box1 saiife - connector - {LINE}");
        assert_eq!(&buf[..n], want.as_bytes());
        // The MSG is the line itself, byte for byte.
        assert!(buf[..n].ends_with(LINE.as_bytes()));
        let n = server.recv(&mut buf).await.unwrap();
        // A deny is a warning; no kind is `guard`.
        let want = format!("<132>1 2026-10-27T10:11:13.000Z box1 saiife - guard - {DENY}");
        assert_eq!(&buf[..n], want.as_bytes());

        // `rfc5424`: the same MSG, plus the seq as structured data.
        let plain = SyslogTransport::new(
            Dest::Unix(path.clone()),
            SyslogFormat::Rfc5424,
            saiife_policy::facility_code(Some("local3")).unwrap(),
            "box 1".into(),
            TargetClient::new(|| Err("unused".into())),
        );
        plain.send(&lines[..1]).await.unwrap();
        let n = server.recv(&mut buf).await.unwrap();
        let want = format!(
            "<158>1 2026-10-27T10:11:12.345Z - saiife - connector [saiife@32473 seq=\"42\"] {LINE}"
        );
        assert_eq!(&buf[..n], want.as_bytes());

        // A line that is not JSON: MSGID `-`, send time, still exact.
        json.send(&[Bytes::from_static(b"not json")]).await.unwrap();
        let n = server.recv(&mut buf).await.unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.starts_with("<134>1 2"), "{got}");
        assert!(got.ends_with(" box1 saiife - - - not json"), "{got}");

        // Over 8 KiB: cut at a character boundary and marked.
        let big = format!(r#"{{"seq":1,"input":"{}"}}"#, "ü".repeat(5000));
        json.send(&[Bytes::from(big.clone())]).await.unwrap();
        let n = server.recv(&mut buf).await.unwrap();
        assert!(n <= MAX_DATAGRAM, "{n}");
        let got = std::str::from_utf8(&buf[..n]).expect("cut at a char boundary");
        assert!(got.ends_with(TRUNCATED_MARK));
        // No listener: a retry, not a fatal error.
        drop(server);
        assert!(matches!(json.send(&lines).await, Err(SendError::Retry(_))));
    }

    #[tokio::test]
    async fn syslog_local_stream_socket_uses_octet_counting_uncut() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("log");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let got = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut all = Vec::new();
            s.read_to_end(&mut all).await.unwrap();
            all
        });
        let t = local(path, SyslogFormat::Rfc5424Json);
        let big = format!(r#"{{"seq":1,"input":"{}"}}"#, "x".repeat(10_000));
        t.send(&[
            Bytes::from(big.clone()),
            Bytes::from_static(LINE.as_bytes()),
        ])
        .await
        .unwrap();
        let all = got.await.unwrap();
        let frames = split_frames(&all);
        assert_eq!(frames.len(), 2);
        assert!(frames[0].ends_with(big.as_bytes()));
        assert!(frames[1].ends_with(LINE.as_bytes()));
    }

    #[tokio::test]
    async fn syslog_local_socket_nobody_reads_times_out() {
        let d = tempfile::tempdir().unwrap();
        // A datagram socket that never reads: its queue fills, sends block.
        let path = d.path().join("dgram");
        let _server = UnixDatagram::bind(&path).unwrap();
        let t = local(path, SyslogFormat::Rfc5424Json)
            .with_send_timeout(std::time::Duration::from_millis(200));
        let line = Bytes::from(format!(r#"{{"seq":1,"input":"{}"}}"#, "x".repeat(4000)));
        let lines = vec![line; 5000];
        let err = t.send(&lines).await.unwrap_err();
        // macOS does not block a send to a full local datagram queue: it
        // fails at once (`ENOBUFS`). A retry either way.
        let full = |w: &str| {
            w.contains("timed out")
                || (cfg!(target_os = "macos") && w.contains("No buffer space available"))
        };
        assert!(matches!(&err, SendError::Retry(w) if full(w)), "{err:?}");
        // A stream socket that accepts and never reads.
        let path = d.path().join("stream");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let held = tokio::spawn(async move { listener.accept().await.map(|(s, _)| s) });
        let t = local(path, SyslogFormat::Rfc5424Json)
            .with_send_timeout(std::time::Duration::from_millis(200));
        let err = t.send(&lines).await.unwrap_err();
        assert!(
            matches!(&err, SendError::Retry(w) if w.contains("timed out")),
            "{err:?}"
        );
        drop(held);
    }

    /// `LEN SP MSG` frames.
    fn split_frames(mut b: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while !b.is_empty() {
            let sp = b.iter().position(|&c| c == b' ').expect("a length");
            let len: usize = std::str::from_utf8(&b[..sp]).unwrap().parse().unwrap();
            out.push(b[sp + 1..sp + 1 + len].to_vec());
            b = &b[sp + 1 + len..];
        }
        out
    }

    /// A TLS syslog server: every connection's plaintext (or the handshake
    /// error), and the ALPN the client offered.
    async fn tls_server(
        p: &Pki,
    ) -> (
        u16,
        tokio::sync::mpsc::UnboundedReceiver<Result<(Vec<u8>, Option<Vec<u8>>), String>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // A server that would refuse a client offering any other protocol
        // (`http/1.1`, say): one offering none is accepted.
        let acc = acceptor(p, &[b"x-syslog"]);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acc = acc.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match acc.accept(tcp).await {
                        Ok(mut s) => {
                            let alpn = s.get_ref().1.alpn_protocol().map(|a| a.to_vec());
                            let mut all = Vec::new();
                            let _ = s.read_to_end(&mut all).await;
                            let _ = tx.send(Ok((all, alpn)));
                        }
                        Err(e) => {
                            let _ = tx.send(Err(e.to_string()));
                        }
                    }
                });
            }
        });
        (port, rx)
    }

    fn remote(port: u16, client: TargetClient) -> SyslogTransport {
        SyslogTransport::new(
            Dest::Tls {
                host: TEST_HOST.into(),
                port,
            },
            SyslogFormat::Rfc5424Json,
            16,
            "box1".into(),
            client,
        )
    }

    #[tokio::test]
    async fn syslog_tls_octet_counting_framing() {
        let p = pki();
        let (port, mut rx) = tls_server(&p).await;
        // The target's own `ca` file, over a base client that trusts nothing.
        let d = tempfile::tempdir().unwrap();
        let ca = d.path().join("siem.pem");
        std::fs::write(&ca, &p.ca_pem).unwrap();
        let base = upstream(rustls::RootCertStore::empty());
        let t = remote(
            port,
            TargetClient::new(move || {
                base.with_ca_file(&ca, SEND_TIMEOUT)
                    .map_err(|e| e.to_string())
            }),
        );
        let lines = [
            Bytes::from_static(LINE.as_bytes()),
            Bytes::from_static(DENY.as_bytes()),
        ];
        t.send(&lines).await.unwrap();
        let (all, alpn) = rx.recv().await.unwrap().unwrap();
        assert_eq!(alpn, None, "no ALPN for syslog");
        let frames = split_frames(&all);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], t.message(LINE.as_bytes()));
        assert_eq!(frames[1], t.message(DENY.as_bytes()));
        let first = format!("{} ", frames[0].len());
        assert!(all.starts_with(first.as_bytes()));
        assert!(frames[0].ends_with(LINE.as_bytes()));
    }

    #[tokio::test]
    async fn syslog_tls_untrusted_cert_refused() {
        let p = pki();
        let other = pki();
        let (port, mut rx) = tls_server(&p).await;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(other.ca.clone()).unwrap();
        let base = upstream(roots);
        let t = remote(
            port,
            TargetClient::new(move || Ok(base.with_timeout(SEND_TIMEOUT))),
        );
        let err = t
            .send(&[Bytes::from_static(LINE.as_bytes())])
            .await
            .unwrap_err();
        assert!(
            matches!(&err, SendError::Retry(w) if w.contains("TLS")),
            "{err:?}"
        );
        // The server never got a byte of plaintext.
        assert!(rx.recv().await.unwrap().is_err());

        // A name the certificate does not hold is refused too (host pinning).
        let mut roots = rustls::RootCertStore::empty();
        roots.add(p.ca.clone()).unwrap();
        let base = upstream(roots);
        let t = SyslogTransport::new(
            Dest::Tls {
                host: "other.example.test".into(),
                port,
            },
            SyslogFormat::Rfc5424Json,
            16,
            "box1".into(),
            TargetClient::new(move || Ok(base.with_timeout(SEND_TIMEOUT))),
        );
        assert!(t
            .send(&[Bytes::from_static(LINE.as_bytes())])
            .await
            .is_err());
        assert!(rx.recv().await.unwrap().is_err());
    }
}
