//! Messages in and out (plan 14, Task 6).
//!
//! - [`compose`] writes the `mail.send` DATA section: RFC 5322 headers, a
//!   UTF-8 `text/plain` body in quoted-printable, dot-stuffed, ended with
//!   `.\r\n`. A CR, LF or other control character in a header value is
//!   refused, never folded into a new header.
//! - [`get_json`] turns a fetched message into the `mail.get` answer with
//!   mail-parser: `{uid, from, to, cc, subject, date, text, html,
//!   attachments: [{name, type, size}]}`. Attachment content never leaves.

use base64::Engine as _;
use mail_parser::{Address, MessageParser, MimeHeaders};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// The longest line of quoted-printable output, the `=` of a soft break
/// included (RFC 2045 §6.7).
const QP_LINE: usize = 76;
/// The longest UTF-8 run in one encoded word: its base64 is 56 characters,
/// so `=?UTF-8?B?...?=` is 68, within 75 (RFC 2047 §2), and the first line,
/// `Subject: ` included, within 78 (RFC 5322 §2.1.1).
const WORD_BYTES: usize = 42;

/// One outgoing message.
pub struct Outgoing<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub date: OffsetDateTime,
}

/// The DATA section of `o`, or why it cannot be sent (no value in the
/// reason).
pub fn compose(o: &Outgoing<'_>) -> Result<String, String> {
    for (name, v) in [("from", o.from), ("to", o.to)] {
        if !super::address_ok(v) {
            return Err(format!("{name} is not one plain address"));
        }
    }
    if o.subject.chars().any(char::is_control) {
        return Err("the subject has a control character".into());
    }
    let date = o
        .date
        .format(&time::format_description::well_known::Rfc2822)
        .map_err(|_| "the date cannot be formatted".to_string())?;
    let domain = o.from.rsplit('@').next().unwrap_or("saiife.invalid");
    let mut out = String::new();
    out.push_str(&format!("From: <{}>\r\n", o.from));
    out.push_str(&format!("To: <{}>\r\n", o.to));
    out.push_str(&format!("Subject: {}\r\n", subject(o.subject)));
    out.push_str(&format!("Date: {date}\r\n"));
    out.push_str(&format!(
        "Message-ID: <{}.saiife@{domain}>\r\n",
        message_id(o)
    ));
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    for line in quoted_printable(o.body).split_inclusive("\r\n") {
        // Dot-stuffing (RFC 5321 §4.5.2).
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
    }
    out.push_str(".\r\n");
    Ok(out)
}

/// A unique-enough id from the time and the message.
fn message_id(o: &Outgoing<'_>) -> String {
    let mut h = Sha256::new();
    h.update(o.date.unix_timestamp_nanos().to_be_bytes());
    for part in [o.from, o.to, o.subject, o.body] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    h.finalize()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The `Subject` value: as is when it is short printable ASCII, else
/// UTF-8 encoded words folded one per line.
fn subject(s: &str) -> String {
    if s.len() <= 66 && s.bytes().all(|b| (0x20..0x7f).contains(&b)) && !s.contains("=?") {
        return s.to_string();
    }
    let mut words = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if cur.len() + c.len_utf8() > WORD_BYTES {
            words.push(std::mem::take(&mut cur));
        }
        cur.push(c);
    }
    if !cur.is_empty() || words.is_empty() {
        words.push(cur);
    }
    words
        .iter()
        .map(|w| {
            format!(
                "=?UTF-8?B?{}?=",
                base64::engine::general_purpose::STANDARD.encode(w.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join("\r\n ")
}

/// `body` as quoted-printable UTF-8 with CRLF line ends: a line break of
/// the text (LF or CRLF) is a hard break, a lone CR is `=0D`, and lines are
/// cut with soft breaks at [`QP_LINE`].
pub fn quoted_printable(body: &str) -> String {
    let mut out = String::with_capacity(body.len() + body.len() / 8);
    let text = body.replace("\r\n", "\n");
    for line in text.split('\n') {
        let bytes = line.as_bytes();
        let mut col = 0;
        for (i, &b) in bytes.iter().enumerate() {
            let last = i + 1 == bytes.len();
            let lit = match b {
                b' ' | b'\t' => !last,
                b'=' => false,
                33..=126 => true,
                _ => false,
            };
            let enc = if lit {
                (b as char).to_string()
            } else {
                format!("={b:02X}")
            };
            if col + enc.len() > QP_LINE - 1 {
                out.push_str("=\r\n");
                col = 0;
            }
            out.push_str(&enc);
            col += enc.len();
        }
        out.push_str("\r\n");
    }
    out
}

/// `[{name, address}]` of a header's addresses (groups flattened).
fn addresses(a: Option<&Address<'_>>) -> Value {
    let Some(a) = a else {
        return json!([]);
    };
    Value::Array(
        a.iter()
            .map(|x| json!({ "name": x.name(), "address": x.address() }))
            .collect(),
    )
}

/// The `mail.get` answer for message `uid`, from its raw bytes.
pub fn get_json(uid: u32, raw: &[u8]) -> Value {
    let Some(msg) = MessageParser::default().parse(raw) else {
        return json!({
            "uid": uid, "from": [], "to": [], "cc": [], "subject": null,
            "date": null, "text": null, "html": null, "attachments": [],
        });
    };
    let text = msg
        .text_bodies()
        .find(|p| !p.is_text_html())
        .and_then(|p| p.text_contents())
        .map(str::to_string);
    let html = msg
        .html_bodies()
        .find(|p| p.is_text_html())
        .and_then(|p| p.text_contents())
        .map(str::to_string);
    let attachments: Vec<Value> = msg
        .attachments()
        .map(|p| {
            let ty = p.content_type().map(|c| match &c.c_subtype {
                Some(sub) => format!("{}/{sub}", c.c_type),
                None => c.c_type.to_string(),
            });
            json!({ "name": p.attachment_name(), "type": ty, "size": p.len() })
        })
        .collect();
    json!({
        "uid": uid,
        "from": addresses(msg.from()),
        "to": addresses(msg.to()),
        "cc": addresses(msg.cc()),
        "subject": msg.subject(),
        "date": msg.date().map(|d| d.to_rfc3339()),
        "text": text,
        "html": html,
        "attachments": attachments,
    })
}

/// Decodes RFC 2047 encoded words in a header value from an IMAP envelope
/// (a subject or a display name), lossily.
pub fn header_text(raw: &[u8]) -> String {
    let mut doc = b"Subject: ".to_vec();
    doc.extend(
        raw.iter()
            .map(|&b| if b == b'\r' || b == b'\n' { b' ' } else { b }),
    );
    doc.extend_from_slice(b"\r\n\r\n");
    MessageParser::default()
        .parse(&doc)
        .and_then(|m| m.subject().map(str::to_string))
        .unwrap_or_else(|| String::from_utf8_lossy(raw).into_owned())
}

/// An envelope date as RFC 3339, or `None` when it does not parse.
pub fn header_date(raw: &[u8]) -> Option<String> {
    let mut doc = b"Date: ".to_vec();
    doc.extend(
        raw.iter()
            .map(|&b| if b == b'\r' || b == b'\n' { b' ' } else { b }),
    );
    doc.extend_from_slice(b"\r\n\r\n");
    let m = MessageParser::default().parse(&doc)?;
    m.date().map(|d| d.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(subject: &str, body: &str) -> Result<String, String> {
        compose(&Outgoing {
            from: "bot@acme.com",
            to: "a@acme.com",
            subject,
            body,
            date: OffsetDateTime::UNIX_EPOCH,
        })
    }

    #[test]
    fn crlf_in_a_header_is_refused() {
        assert!(out("hi\r\nBcc: evil@x", "b").is_err());
        assert!(out("hi\nBcc: evil@x", "b").is_err());
        assert!(compose(&Outgoing {
            from: "bot@acme.com",
            to: "a@acme.com\r\nBcc: b@evil.test",
            subject: "s",
            body: "b",
            date: OffsetDateTime::UNIX_EPOCH,
        })
        .is_err());
    }

    #[test]
    fn body_is_quoted_printable_and_dot_stuffed() {
        let d = out("hi", "one\n.two\r\nth\u{e9} = x \n").unwrap();
        assert!(
            d.contains("\r\n\r\none\r\n..two\r\nth=C3=A9 =3D x=20\r\n\r\n.\r\n"),
            "{d}"
        );
        assert!(d.contains("Content-Transfer-Encoding: quoted-printable\r\n"));
        assert!(
            d.contains("Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"),
            "{d}"
        );
    }

    #[test]
    fn long_lines_get_soft_breaks() {
        let qp = quoted_printable(&"\u{e9}".repeat(100));
        for l in qp.split("\r\n") {
            assert!(l.len() <= QP_LINE, "{l}");
        }
        assert!(qp.contains("=\r\n"));
    }

    #[test]
    fn utf8_subject_is_encoded_words() {
        let d = out("Grüße aus Århus", "b").unwrap();
        assert!(d.contains("Subject: =?UTF-8?B?"), "{d}");
        let parsed = MessageParser::default().parse(d.as_bytes()).unwrap();
        assert_eq!(parsed.subject(), Some("Grüße aus Århus"));
        let long = "ä".repeat(300);
        let d = out(&long, "b").unwrap();
        let parsed = MessageParser::default().parse(d.as_bytes()).unwrap();
        assert_eq!(parsed.subject(), Some(long.as_str()));
        for l in d.split("\r\n") {
            assert!(l.len() <= 78, "{l}");
        }
    }

    #[test]
    fn composed_body_round_trips() {
        let body = "line one\n.leading dot\ntrailing space \nünïcödé = yes";
        let d = out("s", body).unwrap();
        // Undo the dot-stuffing and the terminator, as a server does.
        let msg: String = d
            .strip_suffix(".\r\n")
            .unwrap()
            .split_inclusive("\r\n")
            .map(|l| l.strip_prefix('.').unwrap_or(l))
            .collect();
        let parsed = MessageParser::default().parse(msg.as_bytes()).unwrap();
        let text = parsed.body_text(0).unwrap();
        assert_eq!(text.replace("\r\n", "\n").trim_end(), body);
    }

    #[test]
    fn header_text_decodes_encoded_words() {
        assert_eq!(header_text(b"=?UTF-8?B?R3LDvMOfZQ==?="), "Grüße");
        assert_eq!(header_text(b"plain"), "plain");
    }
}
