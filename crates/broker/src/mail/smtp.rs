//! A minimal SMTP client (plan 11, decision 9; moved from the daemon in
//! plan 14, Task 6): implicit TLS (port 465) or STARTTLS (587, 25), then
//! `EHLO`, `AUTH PLAIN`, `MAIL`, `RCPT`, `DATA`. Each step has its own
//! 10 s timeout. Nothing is sent before TLS: a server that does not offer
//! STARTTLS is refused, and the credentials never travel in the clear. No
//! other auth method exists.
//!
//! The daemon's notifier uses [`send`] (ASCII text to its configured
//! recipients); the `mail.send` connector operation uses [`send_data`]
//! with a message from [`super::message::compose`] and one recipient.

use super::{boxed, connect, name_of, read_line, step, Stream};
use base64::Engine as _;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::upstream::Resolver;

/// The timeout of each protocol step.
pub const STEP: Duration = Duration::from_secs(10);
/// A reply of more lines than this is refused.
const MAX_LINES: usize = 64;

/// One notification to send.
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

/// Where a ready DATA section goes, and the login.
pub struct Envelope<'a> {
    pub host: &'a str,
    pub port: u16,
    /// `false`: implicit TLS. `true`: STARTTLS (required, never optional).
    pub starttls: bool,
    pub from: &'a str,
    pub to: &'a [String],
    pub user: &'a str,
    pub password: &'a str,
}

impl std::fmt::Debug for Envelope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("starttls", &self.starttls)
            .field("recipients", &self.to.len())
            .finish()
    }
}

/// One reply: its code and the text of its lines.
async fn reply(s: &mut Stream) -> Result<(u16, Vec<String>), String> {
    let mut lines = Vec::new();
    loop {
        let raw = read_line(s).await.map_err(|e| {
            if e == "line too long" {
                "reply too long".to_string()
            } else {
                e
            }
        })?;
        if lines.len() >= MAX_LINES {
            return Err("reply too long".into());
        }
        let line = String::from_utf8_lossy(&raw);
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
            reply_text(text.first().map_or("", |t| t.as_str()))
        ))
    }
}

/// The server's words for a failure: printable ASCII, at most 80 characters.
fn reply_text(t: &str) -> String {
    plain(t).chars().take(80).collect()
}

async fn send_line(s: &mut Stream, line: &str) -> Result<(), String> {
    s.write_all(line.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    s.write_all(b"\r\n").await.map_err(|e| e.to_string())?;
    s.flush().await.map_err(|e| e.to_string())
}

async fn cmd(s: &mut Stream, line: &str, ok: &[u16]) -> Result<Vec<String>, String> {
    send_line(s, line).await?;
    expect(s, ok).await
}

/// For the AUTH line: the reply text is never shown (a server may echo the
/// credentials), only the code.
async fn cmd_quiet(s: &mut Stream, line: &str, ok: u16) -> Result<(), String> {
    send_line(s, line).await?;
    let (code, _) = reply(s).await?;
    if code == ok {
        Ok(())
    } else {
        Err(format!("authentication refused (reply {code})"))
    }
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
    if !saiife_policy::valid_address(a) {
        return Err("an address is not plain printable ASCII".into());
    }
    Ok(a)
}

/// Sends the notification `m`. `tls` carries the client's roots;
/// `resolver` maps the host. Errors are one line and never hold the
/// credentials.
pub async fn send(
    tls: TlsConnector,
    resolver: Arc<dyn Resolver>,
    m: &Mail<'_>,
) -> Result<(), String> {
    let env = Envelope {
        host: m.host,
        port: m.port,
        starttls: m.starttls,
        from: m.from,
        to: m.to,
        user: m.user,
        password: m.password,
    };
    send_data(tls, resolver, &env, &data_section(m)).await
}

/// Sends `data`, a DATA section already dot-stuffed and ended with
/// `.\r\n`, to every recipient of `e`. Errors are one line and never hold
/// the credentials.
pub async fn send_data(
    tls: TlsConnector,
    resolver: Arc<dyn Resolver>,
    e: &Envelope<'_>,
    data: &str,
) -> Result<(), String> {
    let from = address(e.from)?;
    for t in e.to {
        address(t)?;
    }
    if !data.ends_with("\r\n.\r\n") && data != ".\r\n" {
        return Err("the message is not a DATA section".into());
    }
    let tcp = connect(resolver, e.host, e.port).await?;

    let mut s: Stream;
    if e.starttls {
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
        let name = name_of(e.host)?;
        let t = step("TLS", async {
            tls.connect(name, raw).await.map_err(|e| e.to_string())
        })
        .await?;
        s = boxed(t);
    } else {
        let name = name_of(e.host)?;
        let t = step("TLS", async {
            tls.connect(name, tcp).await.map_err(|e| e.to_string())
        })
        .await?;
        s = boxed(t);
        step("greeting", expect(&mut s, &[220])).await?;
    }

    step("EHLO", cmd(&mut s, "EHLO saiife", &[250])).await?;
    let plain_auth = Zeroizing::new(format!("\0{}\0{}", e.user, e.password));
    let b64 =
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(plain_auth.as_bytes()));
    let auth = Zeroizing::new(format!("AUTH PLAIN {}", b64.as_str()));
    step("AUTH", cmd_quiet(&mut s, &auth, 235)).await?;
    step("MAIL", cmd(&mut s, &format!("MAIL FROM:<{from}>"), &[250])).await?;
    for t in e.to {
        step("RCPT", cmd(&mut s, &format!("RCPT TO:<{t}>"), &[250, 251])).await?;
    }
    step("DATA", cmd(&mut s, "DATA", &[354])).await?;
    step("message", async {
        s.write_all(data.as_bytes())
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
    fn reply_text_is_short_printable_ascii() {
        let t = reply_text(&format!("bad\r\nthing \u{e9} {}", "x".repeat(200)));
        assert_eq!(t.chars().count(), 80);
        assert!(t.chars().all(|c| (' '..='~').contains(&c)));
    }

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

    #[test]
    fn envelope_debug_hides_the_login() {
        let to = vec!["a@b.test".to_string()];
        let e = Envelope {
            host: "h",
            port: 1,
            starttls: true,
            from: "x@y.test",
            to: &to,
            user: "mailbox-user",
            password: "hunter2-mail-pw",
        };
        let d = format!("{e:?}");
        assert!(!d.contains("hunter2") && !d.contains("mailbox-user"), "{d}");
    }
}
