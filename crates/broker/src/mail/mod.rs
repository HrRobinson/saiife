//! The `transport = "mail"` backend (plan 14, decision 9): `mail.send`
//! over SMTP, and `folders.list`, `mail.list` and `mail.get` over a
//! read-only IMAP session.
//!
//! - SMTP sends to exactly one recipient per call; `From` is the admin's
//!   `from` param. The body is plain UTF-8 text, at most [`MAX_BODY`].
//! - IMAP opens folders with `EXAMINE` only (never `SELECT`) and fetches
//!   with `BODY.PEEK[]`, so a read never sets `\Seen` or changes the
//!   mailbox. There are no delete, move or flag operations.
//! - Both use the broker's TLS roots with no ALPN, implicit TLS or a
//!   required STARTTLS, and send credentials only over TLS.
//! - Every protocol step has a [`smtp::STEP`] timeout, and the whole
//!   exchange the upstream timeout. A reply line is at most [`MAX_LINE`].
//!
//! [`run`] answers with a synthetic `application/json` response, which the
//! pipeline masks like any other (step 10).

pub mod imap;
pub mod message;
pub mod smtp;

use crate::manifest::{Manifest, OpKind, Operation, Pagination, Transport};
use crate::mask::Masker;
use crate::request::{bare_hostname, AuthMaterial};
use crate::upstream::{Resolver, Upstream, UpstreamResponse};
use crate::BrokerError;
use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderValue};
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader};
use tokio::net::TcpStream;

/// The operations a mail manifest may declare.
pub const OPS: &[&str] = &["mail.send", "folders.list", "mail.list", "mail.get"];
/// The service params every mail manifest declares.
pub const SERVICE_PARAMS: &[&str] = &[
    "smtp_host",
    "smtp_port",
    "smtp_tls",
    "imap_host",
    "imap_port",
    "imap_tls",
    "from",
];
/// The `hosts` of a mail manifest, in any order.
pub const HOSTS: &[&str] = &["{smtp_host}", "{imap_host}"];
/// The type of `smtp_tls` and `imap_tls`.
pub const TLS_TYPE: &str = "enum:implicit,starttls";
/// The type of `smtp_port` and `imap_port`.
pub const PORT_TYPE: &str = "int:1..65535";
/// The largest `mail.send` body, in bytes.
pub const MAX_BODY: usize = 256 * 1024;
/// The longest reply line (SMTP) or response line (IMAP), CRLF included.
pub const MAX_LINE: usize = 8 * 1024;
/// A server's words in an error are cut to this many bytes.
pub const REPLY_MAX: usize = 200;
/// `mail.list` returns this many messages unless `limit` says otherwise.
pub const DEFAULT_LIMIT: usize = 20;
/// The most `mail.list` returns.
pub const MAX_LIMIT: usize = 100;
/// The longest folder name.
const MAX_FOLDER: usize = 1024;

/// The structural checks of a `transport = "mail"` manifest, called by
/// [`Manifest::check`]: no `base_url`, the two host placeholders, the
/// service params, `basic` auth, no agent or fixed headers, and only the
/// four mail operations, with no method, path or built body.
pub(crate) fn check_manifest(m: &Manifest) -> Result<(), String> {
    if !m.base_url.is_empty() {
        return Err("a mail manifest has no base_url".into());
    }
    let mut hosts: Vec<&str> = m.hosts.iter().map(String::as_str).collect();
    hosts.sort_unstable();
    let mut want = HOSTS.to_vec();
    want.sort_unstable();
    if hosts != want {
        return Err("a mail manifest has hosts = [\"{smtp_host}\", \"{imap_host}\"]".into());
    }
    for p in SERVICE_PARAMS {
        let spec = m
            .params
            .get(*p)
            .ok_or_else(|| format!("a mail manifest declares the param {p}"))?;
        let ok = match *p {
            "smtp_host" | "imap_host" => {
                spec.required
                    && spec
                        .pattern
                        .as_deref()
                        .is_some_and(|pat| pat.starts_with('^') && pat.ends_with('$'))
            }
            "smtp_port" | "imap_port" => spec.ty == PORT_TYPE,
            "smtp_tls" | "imap_tls" => spec.ty == TLS_TYPE,
            _ => spec.ty == "string" || spec.ty.starts_with("string:"),
        };
        if !ok {
            return Err(format!(
                "mail param {p}: hosts are required with an anchored pattern, ports {PORT_TYPE}, \
                 TLS modes {TLS_TYPE}, from a string"
            ));
        }
    }
    if !m.request_headers.is_empty() || !m.headers.is_empty() {
        return Err("a mail manifest has no request_headers or headers".into());
    }
    if m.auth.len() != 1 || m.auth[0].kind != "basic" {
        return Err("a mail manifest has exactly one auth, of kind basic".into());
    }
    for op in &m.operation {
        check_op(op).map_err(|e| format!("operation {}: {e}", op.id))?;
    }
    Ok(())
}

fn check_op(op: &Operation) -> Result<(), String> {
    if !OPS.contains(&op.id.as_str()) {
        return Err(format!("a mail operation is one of {}", OPS.join(", ")));
    }
    if !op.method.is_empty() || !op.path.is_empty() || !op.path_params.is_empty() {
        return Err("a mail operation has no method, path or path_params".into());
    }
    if op.builds_body() || op.amount.is_some() {
        return Err("a mail operation has no built body or amount".into());
    }
    let send = op.id == "mail.send";
    match (send, op.kind, op.body.as_deref()) {
        (true, OpKind::Write, Some("text")) | (false, OpKind::Read, None) => {}
        _ => {
            return Err(
                "mail.send is kind write with body = \"text\"; reads are kind read with no body"
                    .into(),
            )
        }
    }
    match &op.pagination {
        None => {}
        Some(Pagination::Cursor { param, next, more })
            if op.id == "mail.list"
                && param == "before_uid"
                && next == "next_before_uid"
                && more.is_none() => {}
        Some(_) => {
            return Err(
                "only mail.list paginates, with cursor { param = \"before_uid\", next = \"next_before_uid\" }"
                    .into(),
            )
        }
    }
    Ok(())
}

fn bad_value(name: &str, reason: &str) -> BrokerError {
    BrokerError::BadValue {
        name: name.to_string(),
        reason: reason.to_string(),
    }
}

/// One server, from the service params.
#[derive(Debug, Clone)]
pub(crate) struct Server {
    pub host: String,
    pub port: u16,
    pub starttls: bool,
}

fn server(svc: &BTreeMap<String, String>, proto: &str) -> Result<Server, BrokerError> {
    let hk = format!("{proto}_host");
    let host = svc
        .get(&hk)
        .filter(|h| bare_hostname(h))
        .ok_or_else(|| bad_value(&hk, "not a bare lower-case hostname"))?;
    let tk = format!("{proto}_tls");
    let starttls = match svc.get(&tk).map(String::as_str) {
        None | Some("implicit") => false,
        Some("starttls") => true,
        Some(_) => return Err(bad_value(&tk, "not implicit or starttls")),
    };
    let pk = format!("{proto}_port");
    let port = match svc.get(&pk) {
        None => match (proto, starttls) {
            ("smtp", false) => 465,
            ("smtp", true) => 587,
            (_, false) => 993,
            (_, true) => 143,
        },
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| bad_value(&pk, "not a port"))?,
    };
    Ok(Server {
        host: host.clone(),
        port,
        starttls,
    })
}

/// An address for an envelope and a header: one `@`, a non-empty local
/// part and domain, printable ASCII without space, `,`, `;`, `"`, `<` or
/// `>` (so no CR, LF or second recipient can ride along).
pub(crate) fn address_ok(a: &str) -> bool {
    saiife_policy::valid_address(a)
        && a.split('@').count() == 2
        && a.split('@').all(|p| !p.is_empty())
}

/// Text without any control character (CR and LF included).
fn no_controls(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

/// What `op` needs from the call, checked before anything connects:
/// `mail.send` its one `to`, `subject` and text body; the reads their
/// folder, uid and list params; every operation the server params.
pub fn check_call(
    op: &Operation,
    svc: &BTreeMap<String, String>,
    params: &BTreeMap<String, String>,
    body: Option<&Bytes>,
) -> Result<(), BrokerError> {
    let get = |k: &str| params.get(k).map(String::as_str);
    match op.id.as_str() {
        "mail.send" => {
            server(svc, "smtp")?;
            let from = svc.get("from").map(String::as_str).unwrap_or("");
            if !address_ok(from) {
                return Err(bad_value("from", "not one plain address"));
            }
            let to = get("to").ok_or_else(|| BrokerError::MissingParam("to".into()))?;
            if !address_ok(to) {
                return Err(bad_value("to", "not one plain address"));
            }
            let subject = get("subject").unwrap_or("");
            if !no_controls(subject) || subject.chars().count() > 998 {
                return Err(bad_value(
                    "subject",
                    "has a control character or is too long",
                ));
            }
            let body = body.map(|b| b.as_ref()).unwrap_or(b"");
            if body.len() > MAX_BODY {
                return Err(bad_value("body", "larger than 256 KiB"));
            }
            if std::str::from_utf8(body).is_err() {
                return Err(bad_value("body", "not UTF-8 text"));
            }
        }
        "folders.list" => {
            server(svc, "imap")?;
        }
        "mail.list" | "mail.get" => {
            server(svc, "imap")?;
            let folder = get("folder").unwrap_or("INBOX");
            folder_ok(folder)?;
            if op.id == "mail.get" {
                let uid = get("uid").ok_or_else(|| BrokerError::MissingParam("uid".into()))?;
                uid_of(uid).ok_or_else(|| bad_value("uid", "not a message uid"))?;
            } else {
                list_query(params)?;
            }
        }
        _ => return Err(BrokerError::UnknownOperation(op.id.clone())),
    }
    if body.is_some_and(|b| !b.is_empty()) && op.id != "mail.send" {
        return Err(BrokerError::UnknownParam("body".into()));
    }
    Ok(())
}

/// A folder name as IMAP sends it (modified UTF-7 is ASCII): printable
/// ASCII, at most 1 KiB.
fn folder_ok(f: &str) -> Result<(), BrokerError> {
    if f.is_empty() || f.len() > MAX_FOLDER || !f.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(bad_value("folder", "not a printable ASCII folder name"));
    }
    Ok(())
}

pub(crate) fn uid_of(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>().ok().filter(|u| *u > 0)
}

/// The `mail.list` query, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListQuery {
    pub before_uid: Option<u32>,
    /// `d-Mon-yyyy`, the IMAP date of `since`.
    pub since: Option<String>,
    pub unseen: bool,
    pub limit: usize,
}

pub(crate) fn list_query(params: &BTreeMap<String, String>) -> Result<ListQuery, BrokerError> {
    let before_uid = match params.get("before_uid") {
        None => None,
        Some(v) => Some(uid_of(v).ok_or_else(|| bad_value("before_uid", "not a message uid"))?),
    };
    let since = match params.get("since") {
        None => None,
        Some(v) => Some(imap_date(v).ok_or_else(|| bad_value("since", "not a date-time"))?),
    };
    let unseen = match params.get("unseen").map(String::as_str) {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(bad_value("unseen", "not true or false")),
    };
    let limit = match params.get("limit") {
        None => DEFAULT_LIMIT,
        Some(v) => v
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=MAX_LIMIT).contains(n))
            .ok_or_else(|| bad_value("limit", "not 1 to 100"))?,
    };
    Ok(ListQuery {
        before_uid,
        since,
        unseen,
        limit,
    })
}

/// `YYYY-MM-DD...` as the IMAP `SINCE` date `D-Mon-YYYY` (IMAP compares
/// dates only, so the time of day is dropped).
fn imap_date(v: &str) -> Option<String> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let b = v.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let s = v.get(r)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(format!("{d}-{}-{y:04}", MONTHS[(m - 1) as usize]))
}

/// Runs a mail operation (pipeline step 9) and answers with a synthetic
/// `application/json` response. A failure is [`BrokerError::Upstream`]
/// with the server's words cut to [`REPLY_MAX`] bytes and masked with
/// every value of the credential, or [`BrokerError::Timeout`].
#[allow(clippy::too_many_arguments)]
pub async fn run(
    up: &Upstream,
    m: &Manifest,
    op: &Operation,
    svc: &BTreeMap<String, String>,
    params: &BTreeMap<String, String>,
    body: Option<Bytes>,
    auth: &AuthMaterial,
    read_limit: usize,
) -> Result<UpstreamResponse, BrokerError> {
    if m.transport != Transport::Mail {
        return Err(BrokerError::Manifest(format!(
            "{}: not a mail connector",
            m.id
        )));
    }
    check_call(op, svc, params, body.as_ref())?;
    if auth.kind != "basic" {
        return Err(BrokerError::Manifest(format!(
            "{}: the mail credential must be of kind basic",
            m.id
        )));
    }
    let field = |n: &str| {
        auth.fields.get(n).map(|v| v.as_str()).ok_or_else(|| {
            BrokerError::Manifest(format!("{}: the secret has no field {n:?}", m.id))
        })
    };
    let creds = Creds {
        user: field("username")?,
        password: field("password")?,
    };
    let values = auth.values();
    let refs: Vec<&str> = values.iter().map(|v| v.as_str()).collect();
    let masker = Masker::new(&refs);
    let fut = async {
        match op.id.as_str() {
            "mail.send" => {
                let srv = server(svc, "smtp")?;
                let from = svc.get("from").map(String::as_str).unwrap_or("");
                let to = params.get("to").map(String::as_str).unwrap_or("");
                let subject = params.get("subject").map(String::as_str).unwrap_or("");
                let text = body
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default();
                let data = message::compose(&message::Outgoing {
                    from,
                    to,
                    subject,
                    body: &text,
                    date: time::OffsetDateTime::now_utc(),
                })
                .map_err(|e| bad_value("message", &e))?;
                // Exactly one recipient per call.
                let rcpt = [to.to_string()];
                let env = smtp::Envelope {
                    host: &srv.host,
                    port: srv.port,
                    starttls: srv.starttls,
                    from,
                    to: &rcpt,
                    user: creds.user,
                    password: creds.password,
                };
                smtp::send_data(up.tls_connector_with_alpn(&[]), up.resolver(), &env, &data)
                    .await
                    .map_err(MailError::Server)?;
                Ok::<_, MailError>((200, json!({ "sent": true, "to": to })))
            }
            _ => {
                let srv = server(svc, "imap")?;
                imap::run(up, &srv, op, params, &creds, read_limit)
                    .await
                    .map_err(MailError::Server)
            }
        }
    };
    let out: Result<(u16, Value), MailError> = match tokio::time::timeout(up.timeout(), fut).await {
        Ok(r) => r,
        Err(_) => return Err(BrokerError::Timeout),
    };
    match out {
        Ok((status, v)) => {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let body = serde_json::to_vec(&v).map_err(|e| BrokerError::Upstream(e.to_string()))?;
            Ok(UpstreamResponse {
                status,
                headers,
                body: Bytes::from(body),
                truncated: false,
            })
        }
        Err(MailError::Broker(e)) => Err(e),
        Err(MailError::Server(e)) => Err(BrokerError::Upstream(server_words(&masker, &e))),
    }
}

/// A failure of [`run`]: a check of ours, or the server's.
enum MailError {
    Broker(BrokerError),
    Server(String),
}

impl From<BrokerError> for MailError {
    fn from(e: BrokerError) -> Self {
        MailError::Broker(e)
    }
}

/// The mailbox login: never in an error, a log line or `Debug`.
pub(crate) struct Creds<'a> {
    pub user: &'a str,
    pub password: &'a str,
}

impl std::fmt::Debug for Creds<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Creds")
    }
}

/// `e` masked with the credential's values and the v1 patterns, then cut
/// to [`REPLY_MAX`] bytes on a char boundary.
fn server_words(masker: &Masker, e: &str) -> String {
    let masked = masker.mask_text(e);
    let mut end = masked.len().min(REPLY_MAX);
    while !masked.is_char_boundary(end) {
        end -= 1;
    }
    masked[..end].to_string()
}

// ------------------------------------------------------------ shared IO

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type Stream = BufReader<Pin<Box<dyn Io>>>;

pub(crate) fn boxed<T: Io + 'static>(t: T) -> Stream {
    BufReader::new(Box::pin(t) as Pin<Box<dyn Io>>)
}

/// `f` within [`smtp::STEP`]; the error names the step.
pub(crate) async fn step<T>(
    what: &str,
    f: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    match tokio::time::timeout(smtp::STEP, f).await {
        Ok(r) => r.map_err(|e| format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: timed out")),
    }
}

/// Resolves `host` with `resolver` and connects to the first address that
/// answers, each within a step.
pub(crate) async fn connect(
    resolver: Arc<dyn Resolver>,
    host: &str,
    port: u16,
) -> Result<TcpStream, String> {
    let h = host.to_string();
    let addrs: Vec<SocketAddr> = step("resolve", async move {
        tokio::task::spawn_blocking(move || resolver.resolve(&h, port))
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
    Ok(tcp)
}

pub(crate) fn name_of(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string()).map_err(|e| format!("TLS server name: {e}"))
}

/// One line, CRLF included, of at most [`MAX_LINE`] bytes. A longer line
/// is refused once [`MAX_LINE`] bytes are read, whatever follows.
pub(crate) async fn read_line(s: &mut Stream) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    let n = (&mut *s)
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("the server closed the connection".into());
    }
    if line.len() > MAX_LINE {
        return Err("line too long".into());
    }
    if !line.ends_with(b"\n") {
        return Err("the server closed the connection".into());
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imap_date_from_rfc3339() {
        assert_eq!(
            imap_date("2026-03-07T10:00:00Z").as_deref(),
            Some("7-Mar-2026")
        );
        assert_eq!(imap_date("2026-13-07T10:00:00Z"), None);
        assert_eq!(imap_date("x"), None);
    }

    #[test]
    fn addresses_are_one_plain_address() {
        assert!(address_ok("a@acme.com"));
        for bad in [
            "a@acme.com,b@evil.test",
            "a@acme.com\r\nBcc: b@evil.test",
            "a@acme.com b@evil.test",
            "<a@acme.com>",
            "a@b@c",
            "@acme.com",
            "a@",
            "",
        ] {
            assert!(!address_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn server_words_are_masked_and_cut() {
        let m = Masker::new(&["hunter2-mail-pw"]);
        let e = format!("NO bad hunter2-mail-pw {}", "x".repeat(400));
        let w = server_words(&m, &e);
        assert!(w.len() <= REPLY_MAX);
        assert!(!w.contains("hunter2-mail-pw"));
    }
}
