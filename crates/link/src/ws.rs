//! The WebSocket client to the hub (plan 29, Task 8): a small RFC 6455
//! client over any `AsyncRead + AsyncWrite` stream (Task 9 supplies
//! tokio-rustls). No extensions, no subprotocols.
//!
//! Keepalive (driven by the caller, normally in a `select!` with `recv`):
//! call [`WsClient::ping`] every [`PING_INTERVAL`] (25 s) and close the
//! connection when [`WsClient::pong_overdue`] is true (no pong, or other
//! proof of life from a pong, for [`PONG_TIMEOUT`] = 60 s). `recv` answers
//! the server's pings itself and records pongs. `recv` is cancel-safe up to
//! the point where it replies to a ping or close; drop the client after any
//! error.
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha1::{Digest, Sha1};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame payload and largest reassembled message.
pub const MAX_PAYLOAD: usize = 2 * 1024 * 1024;
/// How often the caller should send a ping.
pub const PING_INTERVAL: Duration = Duration::from_secs(25);
/// Close after this long without a pong.
pub const PONG_TIMEOUT: Duration = Duration::from_secs(60);
/// Cap on an HTTP head (handshake request or response).
const MAX_HEAD: usize = 8 * 1024;
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BIN: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// base64(SHA-1(key ‖ GUID)), RFC 6455 §4.2.2.
pub fn accept_key(sec_websocket_key: &str) -> String {
    let mut h = Sha1::new();
    h.update(sec_websocket_key.as_bytes());
    h.update(GUID.as_bytes());
    STANDARD.encode(h.finalize())
}

/// A data message; ping and pong are handled inside.
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Close(Option<u16>),
}

#[derive(Debug)]
pub enum WsError {
    Handshake(String),
    Protocol(String),
    TooLarge,
    Closed,
    Io(std::io::Error),
}

impl std::fmt::Display for WsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WsError::Handshake(m) => write!(f, "websocket handshake failed: {m}"),
            WsError::Protocol(m) => write!(f, "websocket protocol error: {m}"),
            WsError::TooLarge => write!(f, "websocket message too large"),
            WsError::Closed => write!(f, "websocket closed"),
            WsError::Io(e) => write!(f, "websocket i/o error: {e}"),
        }
    }
}

impl std::error::Error for WsError {}

impl From<std::io::Error> for WsError {
    fn from(e: std::io::Error) -> Self {
        WsError::Io(e)
    }
}

fn random<const N: usize>() -> Result<[u8; N], WsError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| WsError::Io(std::io::Error::other(e.to_string())))?;
    Ok(b)
}

fn proto<T>(m: &str) -> Result<T, WsError> {
    Err(WsError::Protocol(m.to_string()))
}

/// One decoded frame (payload already unmasked).
struct RawFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    mask: Option<[u8; 4]>,
}

struct Header {
    fin: bool,
    opcode: u8,
    mask: Option<[u8; 4]>,
    len: usize,
    hdr_len: usize,
}

/// Parse a frame header from `buf`; `Ok(None)` = need more bytes. Every
/// check that needs only the bytes seen so far runs as soon as they arrive,
/// and the length limit is enforced here, before any payload is read.
fn parse_header(buf: &[u8], expect_masked: bool) -> Result<Option<Header>, WsError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let (b0, b1) = (buf[0], buf[1]);
    if b0 & 0x70 != 0 {
        return proto("reserved bits set");
    }
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0F;
    if !matches!(
        opcode,
        OP_CONT | OP_TEXT | OP_BIN | OP_CLOSE | OP_PING | OP_PONG
    ) {
        return proto("unknown opcode");
    }
    let masked = b1 & 0x80 != 0;
    if masked != expect_masked {
        return proto(if expect_masked {
            "unmasked client frame"
        } else {
            "masked server frame"
        });
    }
    let (len, mut hdr_len) = match b1 & 0x7F {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let mut a = [0u8; 8];
            a.copy_from_slice(&buf[2..10]);
            let l = u64::from_be_bytes(a);
            if l >> 63 != 0 {
                return proto("64-bit length with the top bit set");
            }
            (l, 10)
        }
        n => (u64::from(n), 2),
    };
    if opcode & 0x8 != 0 && (!fin || len > 125) {
        return proto("control frame fragmented or longer than 125 bytes");
    }
    if len > MAX_PAYLOAD as u64 {
        return Err(WsError::TooLarge);
    }
    let mask = if masked {
        if buf.len() < hdr_len + 4 {
            return Ok(None);
        }
        let m = [
            buf[hdr_len],
            buf[hdr_len + 1],
            buf[hdr_len + 2],
            buf[hdr_len + 3],
        ];
        hdr_len += 4;
        Some(m)
    } else {
        None
    };
    Ok(Some(Header {
        fin,
        opcode,
        mask,
        len: len as usize,
        hdr_len,
    }))
}

/// Read one frame. Parsing works on `buf` only, so a cancelled call loses
/// nothing. EOF is `Closed`.
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    expect_masked: bool,
) -> Result<RawFrame, WsError> {
    loop {
        if let Some(h) = parse_header(buf, expect_masked)? {
            let total = h.hdr_len + h.len;
            if buf.len() >= total {
                let mut payload = buf[h.hdr_len..total].to_vec();
                buf.drain(..total);
                if let Some(m) = h.mask {
                    for (i, b) in payload.iter_mut().enumerate() {
                        *b ^= m[i % 4];
                    }
                }
                return Ok(RawFrame {
                    fin: h.fin,
                    opcode: h.opcode,
                    payload,
                    mask: h.mask,
                });
            }
        }
        if stream.read_buf(buf).await? == 0 {
            return Err(WsError::Closed);
        }
    }
}

fn encode_frame(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(u8::from(fin) << 7 | opcode);
    let m = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(m | n as u8),
        n if n <= 0xFFFF => {
            out.push(m | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(m | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(k) => {
            out.extend_from_slice(&k);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

fn close_payload(code: Option<u16>) -> Vec<u8> {
    code.map(|c| c.to_be_bytes().to_vec()).unwrap_or_default()
}

fn parse_close(payload: &[u8]) -> Result<Option<u16>, WsError> {
    match payload.len() {
        0 => Ok(None),
        1 => proto("close frame with a one-byte payload"),
        _ => Ok(Some(u16::from_be_bytes([payload[0], payload[1]]))),
    }
}

/// Split a head into the first line and lower-cased-name headers.
fn parse_head(head: &str) -> (&str, Vec<(String, String)>) {
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    (first, headers)
}

fn has_token(headers: &[(String, String)], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|(n, _)| n == name)
        .flat_map(|(_, v)| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Read until the blank line that ends an HTTP head (cap `MAX_HEAD`); the
/// head is removed from `buf`, anything after it stays.
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> Result<String, WsError> {
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if p + 4 > MAX_HEAD {
                break;
            }
            let head = String::from_utf8(buf[..p].to_vec())
                .map_err(|_| WsError::Handshake("head is not utf-8".into()))?;
            buf.drain(..p + 4);
            return Ok(head);
        }
        if buf.len() >= MAX_HEAD {
            break;
        }
        if stream.read_buf(buf).await? == 0 {
            return Err(WsError::Handshake(
                "connection closed in the handshake".into(),
            ));
        }
    }
    Err(WsError::Handshake("http head too large".into()))
}

fn no_crlf(s: &str) -> Result<(), WsError> {
    if s.contains(['\r', '\n']) {
        return Err(WsError::Handshake("CR or LF in a request value".into()));
    }
    Ok(())
}

/// A client-side WebSocket connection.
pub struct WsClient<S> {
    stream: S,
    buf: Vec<u8>,
    closed: bool,
    last_pong: Instant,
    /// `(is_text, bytes so far)` of an open fragmented message.
    frag: Option<(bool, Vec<u8>)>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsClient<S> {
    /// GET `path` with Host, Upgrade, Connection, Sec-WebSocket-Key (16
    /// random bytes), Sec-WebSocket-Version: 13 and the extra headers;
    /// checks 101, the upgrade headers and the accept key.
    pub async fn handshake(
        mut stream: S,
        host: &str,
        path: &str,
        headers: &[(&str, String)],
    ) -> Result<WsClient<S>, WsError> {
        no_crlf(host)?;
        no_crlf(path)?;
        let key = STANDARD.encode(random::<16>()?);
        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );
        for (n, v) in headers {
            no_crlf(n)?;
            no_crlf(v)?;
            req.push_str(&format!("{n}: {v}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = Vec::new();
        let head = read_head(&mut stream, &mut buf).await?;
        let (status, h) = parse_head(&head);
        let mut parts = status.split_whitespace();
        if parts.next() != Some("HTTP/1.1") || parts.next() != Some("101") {
            return Err(WsError::Handshake(format!("not a 101 answer: {status}")));
        }
        if !has_token(&h, "upgrade", "websocket") || !has_token(&h, "connection", "upgrade") {
            return Err(WsError::Handshake(
                "missing Upgrade/Connection headers".into(),
            ));
        }
        if header(&h, "sec-websocket-extensions").is_some() {
            return Err(WsError::Handshake("unrequested extension".into()));
        }
        if header(&h, "sec-websocket-protocol").is_some() {
            return Err(WsError::Handshake("unrequested subprotocol".into()));
        }
        if header(&h, "sec-websocket-accept") != Some(accept_key(&key).as_str()) {
            return Err(WsError::Handshake("wrong Sec-WebSocket-Accept".into()));
        }
        Ok(WsClient {
            stream,
            buf, // bytes after the head belong to the first frame
            closed: false,
            last_pong: Instant::now(),
            frag: None,
        })
    }

    async fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), WsError> {
        let f = encode_frame(true, opcode, payload, Some(random::<4>()?));
        self.stream.write_all(&f).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Client frames are always masked with a fresh random key.
    pub async fn send(&mut self, m: Message) -> Result<(), WsError> {
        if self.closed {
            return Err(WsError::Closed);
        }
        match m {
            Message::Text(t) => {
                if t.len() > MAX_PAYLOAD {
                    return Err(WsError::TooLarge);
                }
                self.write_frame(OP_TEXT, t.as_bytes()).await
            }
            Message::Binary(b) => {
                if b.len() > MAX_PAYLOAD {
                    return Err(WsError::TooLarge);
                }
                self.write_frame(OP_BIN, &b).await
            }
            Message::Close(c) => {
                self.closed = true;
                self.write_frame(OP_CLOSE, &close_payload(c)).await
            }
        }
    }

    /// Send a ping (call every [`PING_INTERVAL`]).
    pub async fn ping(&mut self) -> Result<(), WsError> {
        if self.closed {
            return Err(WsError::Closed);
        }
        self.write_frame(OP_PING, b"").await
    }

    /// When the last pong arrived (the handshake counts as one).
    pub fn last_pong(&self) -> Instant {
        self.last_pong
    }

    /// True when no pong has arrived for [`PONG_TIMEOUT`]; close then.
    pub fn pong_overdue(&self) -> bool {
        self.pong_overdue_at(Instant::now())
    }

    pub fn pong_overdue_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_pong) > PONG_TIMEOUT
    }

    /// Best-effort close with `code` after a violation, then give back `e`.
    async fn fail(&mut self, code: u16, e: WsError) -> WsError {
        if !self.closed {
            self.closed = true;
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                self.write_frame(OP_CLOSE, &code.to_be_bytes()),
            )
            .await;
        }
        e
    }

    /// The next data message. Reassembles fragments, answers pings, notes
    /// pongs, answers a Close with a Close and returns `Message::Close`;
    /// afterwards every call is `Closed`.
    pub async fn recv(&mut self) -> Result<Message, WsError> {
        loop {
            if self.closed {
                return Err(WsError::Closed);
            }
            let f = match read_frame(&mut self.stream, &mut self.buf, false).await {
                Ok(f) => f,
                Err(e @ WsError::TooLarge) => return Err(self.fail(1009, e).await),
                Err(e @ WsError::Protocol(_)) => return Err(self.fail(1002, e).await),
                Err(e) => {
                    self.closed = true;
                    return Err(e);
                }
            };
            match self.step(f).await {
                Ok(Some(m)) => return Ok(m),
                Ok(None) => {}
                Err(e @ WsError::TooLarge) => return Err(self.fail(1009, e).await),
                Err(e @ WsError::Protocol(_)) => return Err(self.fail(1002, e).await),
                Err(e) => return Err(e),
            }
        }
    }

    async fn step(&mut self, f: RawFrame) -> Result<Option<Message>, WsError> {
        match f.opcode {
            OP_PING => {
                self.write_frame(OP_PONG, &f.payload).await?;
                Ok(None)
            }
            OP_PONG => {
                self.last_pong = Instant::now();
                Ok(None)
            }
            OP_CLOSE => {
                let code = parse_close(&f.payload)?;
                self.closed = true;
                // Echo the code; failure to deliver the echo is not an error.
                let _ = self.write_frame(OP_CLOSE, &close_payload(code)).await;
                Ok(Some(Message::Close(code)))
            }
            OP_TEXT | OP_BIN => {
                if self.frag.is_some() {
                    return proto("new data frame inside a fragmented message");
                }
                if f.fin {
                    finish(f.opcode == OP_TEXT, f.payload).map(Some)
                } else {
                    self.frag = Some((f.opcode == OP_TEXT, f.payload));
                    Ok(None)
                }
            }
            _ => {
                let Some((text, mut acc)) = self.frag.take() else {
                    return proto("continuation without a start");
                };
                if acc.len() + f.payload.len() > MAX_PAYLOAD {
                    return Err(WsError::TooLarge);
                }
                acc.extend_from_slice(&f.payload);
                if f.fin {
                    finish(text, acc).map(Some)
                } else {
                    self.frag = Some((text, acc));
                    Ok(None)
                }
            }
        }
    }
}

fn finish(text: bool, bytes: Vec<u8>) -> Result<Message, WsError> {
    if text {
        String::from_utf8(bytes)
            .map(Message::Text)
            .or_else(|_| proto("invalid utf-8 in a text message"))
    } else {
        Ok(Message::Binary(bytes))
    }
}

/// The server half of the protocol, for tests and Task 9's fake hub. Not
/// part of the product surface.
#[doc(hidden)]
pub mod server_side {
    use super::*;

    /// Knobs to provoke the client's refusals.
    #[derive(Default)]
    pub struct AcceptOpts {
        /// Answer with a wrong `Sec-WebSocket-Accept`.
        pub bad_accept: bool,
        /// Add a `Sec-WebSocket-Extensions` header with this value.
        pub extension: Option<String>,
    }

    /// A decoded client frame (payload unmasked).
    pub struct Frame {
        pub fin: bool,
        pub opcode: u8,
        pub payload: Vec<u8>,
        pub mask: Option<[u8; 4]>,
    }

    pub struct ServerWs<S> {
        stream: S,
        buf: Vec<u8>,
    }

    /// Accept a handshake: read the GET, check Upgrade, Connection and
    /// version 13, answer 101. Returns the connection and the request path.
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        opts: AcceptOpts,
    ) -> Result<(ServerWs<S>, String), WsError> {
        let mut buf = Vec::new();
        let head = read_head(&mut stream, &mut buf).await?;
        let (first, h) = parse_head(&head);
        let mut parts = first.split_whitespace();
        let (m, path, v) = (parts.next(), parts.next(), parts.next());
        if m != Some("GET") || v != Some("HTTP/1.1") {
            return Err(WsError::Handshake(format!("bad request line: {first}")));
        }
        if !has_token(&h, "upgrade", "websocket")
            || !has_token(&h, "connection", "upgrade")
            || header(&h, "sec-websocket-version") != Some("13")
        {
            return Err(WsError::Handshake("not a websocket upgrade".into()));
        }
        let key = header(&h, "sec-websocket-key")
            .ok_or_else(|| WsError::Handshake("no Sec-WebSocket-Key".into()))?;
        if STANDARD.decode(key).map(|k| k.len()).ok() != Some(16) {
            return Err(WsError::Handshake("bad Sec-WebSocket-Key".into()));
        }
        let accept = if opts.bad_accept {
            accept_key("not the key")
        } else {
            accept_key(key)
        };
        let mut resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
        );
        if let Some(e) = opts.extension {
            resp.push_str(&format!("Sec-WebSocket-Extensions: {e}\r\n"));
        }
        resp.push_str("\r\n");
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        let path = path.unwrap_or("/").to_string();
        Ok((ServerWs { stream, buf }, path))
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> ServerWs<S> {
        /// Send one unmasked frame.
        pub async fn send_frame(
            &mut self,
            fin: bool,
            opcode: u8,
            payload: &[u8],
        ) -> Result<(), WsError> {
            self.send_raw(&encode_frame(fin, opcode, payload, None))
                .await
        }

        /// Write bytes as they are (malformed-frame tests).
        pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<(), WsError> {
            self.stream.write_all(bytes).await?;
            self.stream.flush().await?;
            Ok(())
        }

        /// Send a data or close message as one unmasked frame.
        pub async fn send(&mut self, m: Message) -> Result<(), WsError> {
            match m {
                Message::Text(t) => self.send_frame(true, OP_TEXT, t.as_bytes()).await,
                Message::Binary(b) => self.send_frame(true, OP_BIN, &b).await,
                Message::Close(c) => self.send_frame(true, OP_CLOSE, &close_payload(c)).await,
            }
        }

        /// The next client frame, whatever its opcode; unmasked ones are refused.
        pub async fn recv_frame(&mut self) -> Result<Frame, WsError> {
            let f = read_frame(&mut self.stream, &mut self.buf, true).await?;
            Ok(Frame {
                fin: f.fin,
                opcode: f.opcode,
                payload: f.payload,
                mask: f.mask,
            })
        }

        /// The next unfragmented text, binary or close message; pongs and
        /// pings are skipped.
        pub async fn recv(&mut self) -> Result<Message, WsError> {
            loop {
                let f = self.recv_frame().await?;
                match f.opcode {
                    OP_PING | OP_PONG => {}
                    OP_TEXT => return finish(true, f.payload),
                    OP_BIN => return Ok(Message::Binary(f.payload)),
                    OP_CLOSE => return Ok(Message::Close(parse_close(&f.payload)?)),
                    _ => return proto("fragmented frames are not supported by ServerWs::recv"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::server_side::{accept, AcceptOpts, ServerWs};
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    async fn pair_with(
        opts: AcceptOpts,
    ) -> (
        Result<WsClient<DuplexStream>, WsError>,
        Result<ServerWs<DuplexStream>, WsError>,
    ) {
        let (c, s) = duplex(8 * 1024 * 1024);
        let hdrs = [("Authorization", "x".to_string())];
        let (cl, sv) = tokio::join!(
            WsClient::handshake(c, "hub.example", "/v1/link", &hdrs),
            accept(s, opts)
        );
        (cl, sv.map(|(w, _)| w))
    }

    async fn pair() -> (WsClient<DuplexStream>, ServerWs<DuplexStream>) {
        let (c, s) = pair_with(AcceptOpts::default()).await;
        (c.unwrap(), s.unwrap())
    }

    #[test]
    fn accept_key_rfc_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn handshake_sends_the_request_we_expect() {
        let (c, mut s) = duplex(64 * 1024);
        let h = tokio::spawn(async move {
            WsClient::handshake(c, "hub.example", "/v1/link", &[("X-Test", "1".to_string())])
                .await
                .map(|_| ())
        });
        let mut got = Vec::new();
        let mut b = [0u8; 1024];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut b).await.unwrap();
            got.extend_from_slice(&b[..n]);
        }
        let t = String::from_utf8(got).unwrap();
        assert!(t.starts_with("GET /v1/link HTTP/1.1\r\n"), "{t}");
        for want in [
            "Host: hub.example",
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Key: ",
            "X-Test: 1",
        ] {
            assert!(t.contains(want), "{want} in {t}");
        }
        drop(s);
        assert!(h.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn header_injection_is_refused() {
        let (c, _s) = duplex(1024);
        let r = WsClient::handshake(c, "h", "/x", &[("X", "a\r\nEvil: 1".to_string())]).await;
        assert!(matches!(r, Err(WsError::Handshake(_))));
    }

    #[tokio::test]
    async fn roundtrip_text_and_binary() {
        let (mut c, mut s) = pair().await;
        c.send(Message::Text("héllo".into())).await.unwrap();
        c.send(Message::Binary(vec![0, 1, 2, 255])).await.unwrap();
        assert!(matches!(s.recv().await.unwrap(), Message::Text(t) if t == "héllo"));
        assert!(matches!(s.recv().await.unwrap(), Message::Binary(b) if b == [0, 1, 2, 255]));
        s.send(Message::Text("back".into())).await.unwrap();
        s.send(Message::Binary(vec![9; 70_000])).await.unwrap(); // 64-bit length form
        assert!(matches!(c.recv().await.unwrap(), Message::Text(t) if t == "back"));
        assert!(matches!(c.recv().await.unwrap(), Message::Binary(b) if b.len() == 70_000));
    }

    #[tokio::test]
    async fn client_frames_are_masked() {
        let (mut c, mut s) = pair().await;
        c.send(Message::Text("masked".into())).await.unwrap();
        // The server half refuses unmasked client frames, so a successful
        // recv_frame proves the mask bit was set; check the key is fresh too.
        let f = s.recv_frame().await.unwrap();
        assert_eq!(f.payload, b"masked");
        assert!(f.mask.is_some());
        c.send(Message::Text("masked".into())).await.unwrap();
        let g = s.recv_frame().await.unwrap();
        assert_ne!(f.mask, g.mask, "mask keys must not repeat");
    }

    #[tokio::test]
    async fn server_refuses_unmasked_client_frame() {
        let (mut raw, s) = duplex(64 * 1024);
        let srv = tokio::spawn(async move { accept(s, AcceptOpts::default()).await });
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let req = format!("GET /v1/link HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n");
        raw.write_all(req.as_bytes()).await.unwrap();
        raw.write_all(&[0x81, 0x01, b'x']).await.unwrap();
        let (mut ws, _) = srv.await.unwrap().unwrap();
        assert!(matches!(ws.recv_frame().await, Err(WsError::Protocol(_))));
    }

    #[tokio::test]
    async fn fragments_reassemble() {
        let (mut c, mut s) = pair().await;
        s.send_frame(false, 0x1, b"hel").await.unwrap();
        s.send_frame(true, 0x9, b"p").await.unwrap(); // control frame between fragments
        s.send_frame(false, 0x0, b"lo ").await.unwrap();
        s.send_frame(true, 0x0, b"world").await.unwrap();
        assert!(matches!(c.recv().await.unwrap(), Message::Text(t) if t == "hello world"));
        assert_eq!(s.recv_frame().await.unwrap().opcode, 0xA);
    }

    #[tokio::test]
    async fn ping_is_answered() {
        let (mut c, mut s) = pair().await;
        s.send_frame(true, 0x9, b"hi").await.unwrap();
        s.send(Message::Text("x".into())).await.unwrap();
        assert!(matches!(c.recv().await.unwrap(), Message::Text(t) if t == "x"));
        let f = s.recv_frame().await.unwrap();
        assert_eq!((f.opcode, f.payload.as_slice()), (0xA, &b"hi"[..]));
    }

    #[tokio::test]
    async fn pong_updates_last_pong_and_ping_is_sent() {
        let (mut c, mut s) = pair().await;
        let before = c.last_pong();
        assert!(!c.pong_overdue());
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        c.ping().await.unwrap();
        let f = s.recv_frame().await.unwrap();
        assert_eq!(f.opcode, 0x9);
        s.send_frame(true, 0xA, &f.payload).await.unwrap();
        s.send(Message::Text("x".into())).await.unwrap();
        c.recv().await.unwrap();
        assert!(c.last_pong() > before);
    }

    #[tokio::test]
    async fn pong_overdue_after_sixty_seconds() {
        let (c, _s) = pair().await;
        let now = Instant::now();
        assert!(!c.pong_overdue_at(now));
        assert!(!c.pong_overdue_at(now + PONG_TIMEOUT - std::time::Duration::from_secs(1)));
        assert!(c.pong_overdue_at(now + PONG_TIMEOUT + std::time::Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn close_is_echoed_and_then_closed() {
        let (mut c, mut s) = pair().await;
        s.send_frame(true, 0x8, &1001u16.to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(
            c.recv().await.unwrap(),
            Message::Close(Some(1001))
        ));
        let f = s.recv_frame().await.unwrap();
        assert_eq!((f.opcode, f.payload), (0x8, 1001u16.to_be_bytes().to_vec()));
        assert!(matches!(c.recv().await, Err(WsError::Closed)));
        assert!(matches!(
            c.send(Message::Text("x".into())).await,
            Err(WsError::Closed)
        ));
    }

    #[tokio::test]
    async fn client_close_then_closed() {
        let (mut c, mut s) = pair().await;
        c.send(Message::Close(Some(1000))).await.unwrap();
        assert!(matches!(
            s.recv().await.unwrap(),
            Message::Close(Some(1000))
        ));
        assert!(matches!(
            c.send(Message::Binary(vec![])).await,
            Err(WsError::Closed)
        ));
        assert!(matches!(c.recv().await, Err(WsError::Closed)));
    }

    #[tokio::test]
    async fn eof_is_closed() {
        let (mut c, s) = pair().await;
        drop(s);
        assert!(matches!(c.recv().await, Err(WsError::Closed)));
    }

    #[tokio::test]
    async fn oversize_frame_closes() {
        let (mut c, mut s) = pair().await;
        // Header only: 127 form, length MAX_PAYLOAD + 1, no payload follows.
        let mut h = vec![0x82, 127];
        h.extend_from_slice(&((MAX_PAYLOAD as u64) + 1).to_be_bytes());
        s.send_raw(&h).await.unwrap();
        assert!(matches!(c.recv().await, Err(WsError::TooLarge)));
        assert!(matches!(c.recv().await, Err(WsError::Closed)));
        assert_eq!(s.recv_frame().await.unwrap().opcode, 0x8);
    }

    #[tokio::test]
    async fn exactly_max_payload_is_accepted() {
        let (mut c, mut s) = pair().await;
        s.send(Message::Binary(vec![1; MAX_PAYLOAD])).await.unwrap();
        assert!(matches!(c.recv().await.unwrap(), Message::Binary(b) if b.len() == MAX_PAYLOAD));
        assert!(matches!(
            c.send(Message::Binary(vec![0; MAX_PAYLOAD + 1])).await,
            Err(WsError::TooLarge)
        ));
    }

    #[tokio::test]
    async fn reassembled_message_over_limit_is_refused() {
        let (mut c, mut s) = pair().await;
        let half = vec![7u8; MAX_PAYLOAD / 2 + 1];
        s.send_frame(false, 0x2, &half).await.unwrap();
        s.send_frame(true, 0x0, &half).await.unwrap();
        assert!(matches!(c.recv().await, Err(WsError::TooLarge)));
    }

    async fn refused(raw: &[u8]) -> WsError {
        let (mut c, mut s) = pair().await;
        s.send_raw(raw).await.unwrap();
        c.recv().await.unwrap_err()
    }

    #[tokio::test]
    async fn malformed_frames_are_protocol_errors() {
        // masked server frame
        assert!(matches!(
            refused(&[0x81, 0x81, 1, 2, 3, 4, b'x' ^ 1]).await,
            WsError::Protocol(_)
        ));
        // RSV1
        assert!(matches!(
            refused(&[0xC1, 0x01, b'x']).await,
            WsError::Protocol(_)
        ));
        // unknown opcode 3
        assert!(matches!(refused(&[0x83, 0x00]).await, WsError::Protocol(_)));
        // control frame > 125
        let mut big = vec![0x89, 126, 0, 126];
        big.extend_from_slice(&[0u8; 126]);
        assert!(matches!(refused(&big).await, WsError::Protocol(_)));
        // fragmented control frame
        assert!(matches!(refused(&[0x09, 0x00]).await, WsError::Protocol(_)));
        // continuation without a start
        assert!(matches!(
            refused(&[0x80, 0x01, b'x']).await,
            WsError::Protocol(_)
        ));
        // 64-bit length with the top bit set
        let mut t = vec![0x82, 127];
        t.extend_from_slice(&(1u64 << 63).to_be_bytes());
        assert!(matches!(refused(&t).await, WsError::Protocol(_)));
        // a new data frame while a fragmented message is open
        assert!(matches!(
            refused(&[0x01, 0x01, b'a', 0x81, 0x01, b'b']).await,
            WsError::Protocol(_)
        ));
        // one-byte close payload
        assert!(matches!(
            refused(&[0x88, 0x01, 0x03]).await,
            WsError::Protocol(_)
        ));
    }

    #[tokio::test]
    async fn bad_utf8_is_refused() {
        assert!(matches!(
            refused(&[0x81, 0x02, 0xC3, 0x28]).await,
            WsError::Protocol(_)
        ));
    }

    #[tokio::test]
    async fn extension_in_answer_is_refused() {
        let (c, _) = pair_with(AcceptOpts {
            extension: Some("permessage-deflate".into()),
            ..Default::default()
        })
        .await;
        assert!(matches!(c, Err(WsError::Handshake(_))));
    }

    #[tokio::test]
    async fn wrong_accept_is_refused() {
        let (c, _) = pair_with(AcceptOpts {
            bad_accept: true,
            ..Default::default()
        })
        .await;
        assert!(matches!(c, Err(WsError::Handshake(_))));
    }

    #[tokio::test]
    async fn non_101_and_oversize_head_are_refused() {
        for answer in [
            b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".to_vec(), // no Connection/accept
            vec![b'a'; 9000],
        ] {
            let (c, mut s) = duplex(64 * 1024);
            let h = tokio::spawn(
                async move { WsClient::handshake(c, "h", "/", &[]).await.map(|_| ()) },
            );
            let mut b = [0u8; 1024];
            let _ = s.read(&mut b).await.unwrap();
            s.write_all(&answer).await.unwrap();
            assert!(matches!(h.await.unwrap(), Err(WsError::Handshake(_))));
        }
    }

    #[tokio::test]
    async fn bytes_after_the_101_head_are_kept() {
        let (c, mut s) = duplex(64 * 1024);
        let h = tokio::spawn(async move { WsClient::handshake(c, "h", "/", &[]).await });
        let mut got = Vec::new();
        let mut b = [0u8; 1024];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut b).await.unwrap();
            got.extend_from_slice(&b[..n]);
        }
        let t = String::from_utf8(got).unwrap();
        let key = t
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap();
        let mut resp = format!("HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\nCONNECTION: keep-alive, Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", accept_key(key)).into_bytes();
        resp.extend_from_slice(&[0x81, 0x02, b'o', b'k']); // first frame, same write
        s.write_all(&resp).await.unwrap();
        let mut ws = h.await.unwrap().unwrap();
        assert!(matches!(ws.recv().await.unwrap(), Message::Text(t) if t == "ok"));
    }
}
