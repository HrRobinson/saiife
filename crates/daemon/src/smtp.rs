//! A minimal SMTP client for notifications (plan 11, decision 9): implicit
//! TLS (port 465) or STARTTLS (587, 25), then `EHLO`, `AUTH PLAIN`, `MAIL`,
//! `RCPT`, `DATA`. Each step has its own 10 s timeout. Nothing is sent
//! before TLS: a server that does not offer STARTTLS is refused, and the
//! credentials never travel in the clear. No other auth method exists.

use base64::Engine as _;
use rustls::pki_types::ServerName;
use saiife_broker::upstream::Resolver;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

/// The timeout of each protocol step.
pub const STEP: Duration = Duration::from_secs(10);
/// A reply line longer than this, or a reply of more lines, is refused.
const MAX_LINE: usize = 1024;
const MAX_LINES: usize = 64;

/// One message to send.
pub struct Mail<'a> {
    pub host: &'a str,
    pub port: u16,
    /// `false`: implicit TLS. `true`: STARTTLS (required, never optional).
    pub starttls: bool,
    pub from: &'a str,
    pub to: &'a [String],
    pub user: &'a str,
    pub password: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Stream = BufReader<Pin<Box<dyn Io>>>;

fn boxed<T: Io + 'static>(t: T) -> Stream {
    BufReader::new(Box::pin(t) as Pin<Box<dyn Io>>)
}

async fn step<T>(
    what: &str,
    f: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    match tokio::time::timeout(STEP, f).await {
        Ok(r) => r.map_err(|e| format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: timed out")),
    }
}

/// One reply: its code and the text of its lines.
async fn reply(s: &mut Stream) -> Result<(u16, Vec<String>), String> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let n = (&mut *s)
            .take(MAX_LINE as u64 + 1)
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("the server closed the connection".into());
        }
        if line.len() > MAX_LINE || lines.len() >= MAX_LINES {
            return Err("reply too long".into());
        }
        let line = line.trim_end_matches(['\r', '\n']);
        let code: u16 = line
            .get(..3)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| "malformed reply".to_string())?;
        let more = line.as_bytes().get(3) == Some(&b'-');
        lines.push(line.get(4..).unwrap_or("").to_string());
        if !more {
            return Ok((code, lines));
        }
    }
}

async fn expect(s: &mut Stream, ok: &[u16]) -> Result<Vec<String>, String> {
    let (code, text) = reply(s).await?;
    if ok.contains(&code) {
        Ok(text)
    } else {
        Err(format!(
            "unexpected reply {code} {}",
            text.first().map_or("", |t| t.as_str())
        ))
    }
}

async fn cmd(s: &mut Stream, line: &str, ok: &[u16]) -> Result<Vec<String>, String> {
    s.write_all(line.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    s.write_all(b"\r\n").await.map_err(|e| e.to_string())?;
    s.flush().await.map_err(|e| e.to_string())?;
    expect(s, ok).await
}

fn name_of(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string()).map_err(|e| format!("TLS server name: {e}"))
}

/// Text that is safe in a header or a body line: ASCII printable and tab,
/// anything else (including CR and LF) a space.
pub fn plain(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || (' '..='~').contains(&c) {
                c
            } else {
                ' '
            }
        })
        .collect()
}

/// `body` as the DATA section: lines ended CRLF, a leading `.` doubled.
fn data_section(m: &Mail<'_>) -> String {
    let mut out = String::new();
    out.push_str(&format!("From: <{}>\r\n", m.from));
    let to: Vec<String> = m.to.iter().map(|t| format!("<{t}>")).collect();
    out.push_str(&format!("To: {}\r\n", to.join(", ")));
    out.push_str(&format!("Subject: {}\r\n", plain(m.subject)));
    out.push_str("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n");
    for line in m.body.replace("\r\n", "\n").split('\n') {
        let line = plain(line);
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(&line);
        out.push_str("\r\n");
    }
    out.push_str(".\r\n");
    out
}

fn address(a: &str) -> Result<&str, String> {
    if a.is_empty() || a.contains(['\r', '\n', '<', '>', ' ']) {
        return Err(format!("bad address {a:?}"));
    }
    Ok(a)
}

/// Sends `m`. `tls` carries the client's roots; `resolver` maps the host.
/// Errors are one line and never hold the credentials.
pub async fn send(
    tls: TlsConnector,
    resolver: Arc<dyn Resolver>,
    m: &Mail<'_>,
) -> Result<(), String> {
    let from = address(m.from)?;
    for t in m.to {
        address(t)?;
    }
    let host = m.host.to_string();
    let port = m.port;
    let addrs: Vec<SocketAddr> = step("resolve", async {
        let r = resolver;
        tokio::task::spawn_blocking(move || r.resolve(&host, port))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    })
    .await?;
    let tcp = step("connect", async {
        let mut last = "no address".to_string();
        for a in addrs {
            match TcpStream::connect(a).await {
                Ok(s) => return Ok(s),
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    })
    .await?;
    let _ = tcp.set_nodelay(true);

    let mut s: Stream;
    if m.starttls {
        s = boxed(tcp);
        step("greeting", expect(&mut s, &[220])).await?;
        let caps = step("EHLO", cmd(&mut s, "EHLO saiife", &[250])).await?;
        if !caps.iter().any(|c| c.eq_ignore_ascii_case("STARTTLS")) {
            return Err("the server does not offer STARTTLS; plain-text SMTP is refused".into());
        }
        step("STARTTLS", cmd(&mut s, "STARTTLS", &[220])).await?;
        // Nothing may sit buffered between the plaintext and the TLS layer.
        if !s.buffer().is_empty() {
            return Err("the server sent data before the TLS handshake".into());
        }
        let raw = s.into_inner();
        let name = name_of(m.host)?;
        let t = step("TLS", async {
            tls.connect(name, raw).await.map_err(|e| e.to_string())
        })
        .await?;
        s = boxed(t);
    } else {
        let name = name_of(m.host)?;
        let t = step("TLS", async {
            tls.connect(name, tcp).await.map_err(|e| e.to_string())
        })
        .await?;
        s = boxed(t);
        step("greeting", expect(&mut s, &[220])).await?;
    }

    step("EHLO", cmd(&mut s, "EHLO saiife", &[250])).await?;
    let auth = Zeroizing::new(format!(
        "AUTH PLAIN {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("\0{}\0{}", m.user, m.password).as_bytes())
    ));
    step("AUTH", cmd(&mut s, &auth, &[235])).await?;
    step("MAIL", cmd(&mut s, &format!("MAIL FROM:<{from}>"), &[250])).await?;
    for t in m.to {
        step("RCPT", cmd(&mut s, &format!("RCPT TO:<{t}>"), &[250, 251])).await?;
    }
    step("DATA", cmd(&mut s, "DATA", &[354])).await?;
    step("message", async {
        s.write_all(data_section(m).as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        s.flush().await.map_err(|e| e.to_string())?;
        expect(&mut s, &[250]).await
    })
    .await?;
    let _ = step("QUIT", cmd(&mut s, "QUIT", &[221])).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_is_dot_stuffed_ascii_crlf() {
        let to = vec!["a@b.test".to_string()];
        let m = Mail {
            host: "h",
            port: 1,
            starttls: false,
            from: "x@y.test",
            to: &to,
            user: "u",
            password: "p",
            subject: "s\r\nBcc: evil@x",
            body: "one\n.two\r\nth\u{e9}",
        };
        let d = data_section(&m);
        assert!(d.contains("Subject: s  Bcc: evil@x\r\n"), "{d}");
        assert!(d.contains("\r\n..two\r\n"), "{d}");
        assert!(d.contains("th \r\n"), "{d}");
        assert!(d.ends_with("\r\n.\r\n"));
        assert!(!d.contains("\r\nBcc:"));
    }
}
