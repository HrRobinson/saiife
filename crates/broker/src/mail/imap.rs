//! A read-only IMAP session (plan 14, decision 9), hand-written over the
//! broker's TLS with `imap-proto` as the parser.
//!
//! - Implicit TLS (993) or a **required** STARTTLS (143): a server that
//!   does not offer STARTTLS is refused before anything else is sent, and
//!   the capabilities from before TLS are thrown away.
//! - Auth is `AUTHENTICATE PLAIN` (with SASL-IR when offered), or `LOGIN`,
//!   always after TLS. The server's words on an auth failure are never
//!   shown (a server may echo what it was sent).
//! - Folders are opened with `EXAMINE`, never `SELECT`, and messages are
//!   fetched with `BODY.PEEK[]`, so a read never sets `\Seen`.
//! - A response line is at most [`super::MAX_LINE`] bytes; a literal is
//!   refused from its announced size, before it is read, when it is over
//!   the read limit. Every read has a [`super::smtp::STEP`] timeout.

use super::message;
use super::{boxed, connect, list_query, name_of, read_line, step, uid_of, Creds, Server, Stream};
use crate::manifest::Operation;
use crate::mask::Masker;
use crate::upstream::Upstream;
use base64::Engine as _;
use imap_proto::types::{
    Address, AttributeValue, Capability, MailboxDatum, NameAttribute, Response, ResponseCode,
    Status,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

/// Bytes a session may read on top of the read limit (envelopes, lists,
/// protocol chatter).
const SLACK: usize = 1024 * 1024;
/// How long `LOGOUT` may take.
const LOGOUT_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
/// The deepest parenthesis nesting a response may have. imap-proto's
/// parsers (BODYSTRUCTURE above all) recurse without a limit, so a deeper
/// response is refused before it is parsed.
const MAX_DEPTH: usize = 64;
/// `mail.list` searches descending UID windows of this many UIDs. A
/// window's `* SEARCH` line (at most 500 UIDs of 10 digits and a space)
/// stays below the 8 KiB line limit.
const WINDOW: u32 = 500;
/// The most windows one `mail.list` searches (100,000 UIDs); past them it
/// answers with what it found and a `next_before_uid` to go on from.
const MAX_WINDOWS: usize = 200;
/// The most untagged responses before the `+` of `AUTHENTICATE`.
const MAX_BEFORE_CONTINUE: usize = 64;

/// `{n}\r\n` (or `{n+}\r\n`) at the start of `s`: `(n, header length)`.
fn literal_at(s: &[u8]) -> Option<(usize, usize)> {
    let close = s.iter().take(16).position(|&b| b == b'}')?;
    let digits = &s[1..close];
    let digits = digits.strip_suffix(b"+").unwrap_or(digits);
    if digits.is_empty() || digits.len() > 12 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if s.get(close + 1..close + 3) != Some(b"\r\n") {
        return None;
    }
    let n: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some((n, close + 3))
}

/// Whether `buf` may be handed to imap-proto: its parenthesis depth stays
/// within [`MAX_DEPTH`], counted outside quoted strings and literal bodies.
/// A quoted string with an escape imap-proto would not take, or one not
/// closed on its line, is refused too, so this scan and the parser agree
/// on what is a string.
fn depth_ok(buf: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut i = 0;
    while i < buf.len() {
        let b = buf[i];
        if quoted {
            match b {
                b'\\' => match buf.get(i + 1) {
                    Some(b'"' | b'\\') => i += 1,
                    _ => return false,
                },
                b'"' => quoted = false,
                b'\r' | b'\n' => return false,
                _ => {}
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => quoted = true,
            b'(' => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return false;
                }
            }
            b')' => depth = depth.saturating_sub(1),
            b'{' => {
                if let Some((n, head)) = literal_at(&buf[i..]) {
                    i = i.saturating_add(head).saturating_add(n);
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    !quoted
}

/// The only way into imap-proto: the depth guard, then the parser. The
/// error never holds the server's words.
fn parse(raw: &[u8]) -> Result<Response<'_>, &'static str> {
    if !depth_ok(raw) {
        return Err("response refused: nested too deep or malformed");
    }
    imap_proto::parser::parse_response(raw)
        .map(|(_, r)| r)
        .map_err(|_| "malformed response")
}

/// What `EXAMINE` said about the folder.
#[derive(Debug, Default)]
struct Examined {
    exists: Option<u32>,
    uid_next: Option<u32>,
}

/// One IMAP session.
struct Session {
    s: Stream,
    tag: u32,
    /// The largest literal.
    read_limit: usize,
    /// What is left of the bytes this session may read.
    budget: usize,
}

/// The capabilities of a response, upper-cased (`AUTH=PLAIN`, `STARTTLS`).
fn caps_of(c: &[Capability<'_>]) -> BTreeSet<String> {
    c.iter()
        .map(|c| match c {
            Capability::Imap4rev1 => "IMAP4REV1".to_string(),
            Capability::Auth(a) => format!("AUTH={}", a.to_ascii_uppercase()),
            Capability::Atom(a) => a.to_ascii_uppercase(),
        })
        .collect()
}

/// `{n}` or `{n+}` closing a line (before its CRLF): the literal size.
fn literal_len(line: &[u8]) -> Option<Result<usize, String>> {
    let body = line
        .strip_suffix(b"\r\n")
        .or_else(|| line.strip_suffix(b"\n"))?;
    let body = body.strip_suffix(b"}")?;
    let open = body.iter().rposition(|&b| b == b'{')?;
    let digits = &body[open + 1..];
    let digits = digits.strip_suffix(b"+").unwrap_or(digits);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if digits.len() > 12 {
        return Some(Err("a literal is too large".into()));
    }
    let n: u64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some(usize::try_from(n).map_err(|_| "a literal is too large".to_string()))
}

/// `s` as an IMAP quoted string: printable ASCII only, `\` and `"`
/// escaped.
fn quoted(s: &str) -> Result<String, String> {
    if !s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err("a quoted string must be printable ASCII".into());
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// A server's free text for an error (the caller masks and cuts it).
fn info(i: &Option<std::borrow::Cow<'_, str>>) -> String {
    i.as_deref()
        .unwrap_or("")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

impl Session {
    fn new(s: Stream, read_limit: usize) -> Session {
        Session {
            s,
            tag: 0,
            read_limit,
            budget: read_limit.saturating_add(SLACK),
        }
    }

    fn take(&mut self, n: usize) -> Result<(), String> {
        self.budget = self
            .budget
            .checked_sub(n)
            .ok_or_else(|| "the server sent more than the read limit".to_string())?;
        Ok(())
    }

    /// One whole response: its lines and literals. A literal is refused
    /// from its announced size, before any of it is read.
    async fn read_response(&mut self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        loop {
            let line = step("read", read_line(&mut self.s)).await?;
            self.take(line.len())?;
            let lit = literal_len(&line);
            buf.extend_from_slice(&line);
            let Some(n) = lit else {
                return Ok(buf);
            };
            let n = n?;
            if n > self.read_limit {
                return Err(format!(
                    "a literal of {n} bytes is over the read limit of {} bytes",
                    self.read_limit
                ));
            }
            self.take(n)?;
            let start = buf.len();
            buf.resize(start + n, 0);
            let s = &mut self.s;
            step("read", async {
                s.read_exact(&mut buf[start..])
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .await?;
        }
    }

    async fn write_line(&mut self, line: &str) -> Result<(), String> {
        let s = &mut self.s;
        step("write", async {
            s.write_all(line.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            s.write_all(b"\r\n").await.map_err(|e| e.to_string())?;
            s.flush().await.map_err(|e| e.to_string())
        })
        .await
    }

    fn next_tag(&mut self) -> String {
        self.tag += 1;
        format!("s{}", self.tag)
    }

    /// Sends `tag cmd` and reads to its tagged answer. Each untagged
    /// response goes to `each`. `quiet`: a refusal never shows the
    /// server's words.
    async fn run(
        &mut self,
        cmd: &str,
        quiet: bool,
        mut each: impl FnMut(Response<'_>) -> Result<(), String>,
    ) -> Result<(), String> {
        let tag = self.next_tag();
        let verb = cmd.split(' ').take(2).collect::<Vec<_>>().join(" ");
        let verb = if quiet {
            cmd.split(' ').next().unwrap_or("").to_string()
        } else {
            verb
        };
        self.write_line(&format!("{tag} {cmd}")).await?;
        self.finish(&tag, &verb, quiet, &mut each).await
    }

    /// Reads to the tagged answer of `tag`.
    async fn finish(
        &mut self,
        tag: &str,
        verb: &str,
        quiet: bool,
        each: &mut impl FnMut(Response<'_>) -> Result<(), String>,
    ) -> Result<(), String> {
        loop {
            let raw = self.read_response().await?;
            let resp = parse(&raw).map_err(|e| format!("{verb}: {e}"))?;
            match resp {
                Response::Done {
                    tag: t,
                    status,
                    information,
                    ..
                } if t.0 == tag => {
                    return match status {
                        Status::Ok => Ok(()),
                        _ if quiet => Err(format!("{verb}: refused")),
                        _ => Err(format!("{verb}: refused: {}", info(&information))),
                    }
                }
                Response::Done { .. } => return Err(format!("{verb}: unexpected tagged answer")),
                Response::Data {
                    status: Status::Bye,
                    information,
                    ..
                } => {
                    return Err(if quiet {
                        format!("{verb}: the server closed the session")
                    } else {
                        format!(
                            "{verb}: the server closed the session: {}",
                            info(&information)
                        )
                    })
                }
                Response::Continue { .. } => {
                    return Err(format!("{verb}: unexpected continuation"))
                }
                other => each(other)?,
            }
        }
    }

    /// `CAPABILITY`.
    async fn capabilities(&mut self) -> Result<BTreeSet<String>, String> {
        let mut caps = BTreeSet::new();
        self.run("CAPABILITY", false, |r| {
            if let Response::Capabilities(c) = r {
                caps.extend(caps_of(&c));
            }
            Ok(())
        })
        .await?;
        Ok(caps)
    }

    /// The greeting: `Ok(true)` for PREAUTH. Its capabilities, if any, go
    /// to `caps`.
    async fn greeting(&mut self, caps: &mut BTreeSet<String>) -> Result<bool, String> {
        let raw = self.read_response().await?;
        let resp = parse(&raw).map_err(|e| format!("greeting: {e}"))?;
        match resp {
            Response::Data { status, code, .. } => {
                if let Some(ResponseCode::Capabilities(c)) = &code {
                    caps.extend(caps_of(c));
                }
                match status {
                    Status::Ok => Ok(false),
                    Status::PreAuth => Ok(true),
                    _ => Err("greeting: the server refused the session".into()),
                }
            }
            _ => Err("greeting: not an IMAP greeting".into()),
        }
    }

    /// Logs in over TLS: `AUTHENTICATE PLAIN` when offered, else `LOGIN`.
    async fn login(&mut self, caps: &BTreeSet<String>, c: &Creds<'_>) -> Result<(), String> {
        if caps.contains("AUTH=PLAIN") {
            let plain = Zeroizing::new(format!("\0{}\0{}", c.user, c.password));
            let b64 =
                Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(plain.as_bytes()));
            if caps.contains("SASL-IR") {
                let line = Zeroizing::new(format!("AUTHENTICATE PLAIN {}", b64.as_str()));
                return self.run(&line, true, |_| Ok(())).await;
            }
            let tag = self.next_tag();
            self.write_line(&format!("{tag} AUTHENTICATE PLAIN"))
                .await?;
            // Untagged responses may come before the `+`.
            let mut seen = 0;
            loop {
                let raw = self.read_response().await?;
                match parse(&raw) {
                    Ok(Response::Continue { .. }) => break,
                    Ok(Response::Data {
                        status: Status::Bye,
                        ..
                    }) => return Err("AUTHENTICATE: the server closed the session".into()),
                    Ok(Response::Done { .. }) => return Err("AUTHENTICATE: refused".into()),
                    Err(e) => return Err(format!("AUTHENTICATE: {e}")),
                    Ok(_) => {
                        seen += 1;
                        if seen > MAX_BEFORE_CONTINUE {
                            return Err("AUTHENTICATE: no continuation".into());
                        }
                    }
                }
            }
            self.write_line(&b64).await?;
            return self
                .finish(&tag, "AUTHENTICATE", true, &mut |_| Ok(()))
                .await;
        }
        if caps.contains("LOGINDISABLED") {
            return Err("the server offers neither AUTH=PLAIN nor LOGIN".into());
        }
        let user = quoted(c.user).map_err(|_| "LOGIN: the user name is not ASCII".to_string())?;
        let pass = Zeroizing::new(
            quoted(c.password).map_err(|_| "LOGIN: the password is not ASCII".to_string())?,
        );
        let line = Zeroizing::new(format!("LOGIN {user} {}", pass.as_str()));
        self.run(&line, true, |_| Ok(())).await
    }

    /// `EXAMINE` (read-only); never `SELECT`.
    async fn examine(&mut self, folder: &str) -> Result<Examined, String> {
        let f = quoted(folder)?;
        let mut ex = Examined::default();
        self.run(&format!("EXAMINE {f}"), false, |r| {
            match r {
                Response::Data {
                    code: Some(ResponseCode::UidNext(n)),
                    ..
                } => ex.uid_next = Some(n),
                Response::MailboxData(MailboxDatum::Exists(n)) => ex.exists = Some(n),
                _ => {}
            }
            Ok(())
        })
        .await?;
        Ok(ex)
    }

    /// The UID of the last message (`FETCH * (UID)`), for a server whose
    /// `EXAMINE` gave no `UIDNEXT`.
    async fn last_uid(&mut self) -> Result<Option<u32>, String> {
        let mut last = None;
        self.run("FETCH * (UID)", false, |r| {
            if let Response::Fetch(_, attrs) = r {
                for a in attrs {
                    if let AttributeValue::Uid(u) = a {
                        last = Some(last.map_or(u, |l: u32| l.max(u)));
                    }
                }
            }
            Ok(())
        })
        .await?;
        Ok(last)
    }

    async fn logout(&mut self) {
        let tag = self.next_tag();
        if self.write_line(&format!("{tag} LOGOUT")).await.is_err() {
            return;
        }
        // BYE, then the tagged OK; any failure is the end anyway.
        for _ in 0..4 {
            match self.read_response().await {
                Ok(raw) if raw.starts_with(tag.as_bytes()) => return,
                Ok(_) => {}
                Err(_) => return,
            }
        }
    }
}

/// Connects, secures and logs in.
async fn open(
    up: &Upstream,
    srv: &Server,
    c: &Creds<'_>,
    read_limit: usize,
) -> Result<Session, String> {
    let tls = up.tls_connector_with_alpn(&[]);
    let tcp = connect(up.resolver(), &srv.host, srv.port).await?;
    let mut caps = BTreeSet::new();
    let (mut sess, preauth) = if srv.starttls {
        let mut plain = Session::new(boxed(tcp), read_limit);
        if plain.greeting(&mut caps).await? {
            return Err("PREAUTH before TLS; plain-text IMAP is refused".into());
        }
        if !caps.contains("STARTTLS") {
            caps = plain.capabilities().await?;
        }
        if !caps.contains("STARTTLS") {
            return Err("the server does not offer STARTTLS; plain-text IMAP is refused".into());
        }
        plain.run("STARTTLS", false, |_| Ok(())).await?;
        // Nothing may sit buffered between the plaintext and the TLS layer.
        if !plain.s.buffer().is_empty() {
            return Err("the server sent data before the TLS handshake".into());
        }
        let tag = plain.tag;
        let budget = plain.budget;
        let raw = plain.s.into_inner();
        let name = name_of(&srv.host)?;
        let t = step("TLS", async {
            tls.connect(name, raw).await.map_err(|e| e.to_string())
        })
        .await?;
        let mut sess = Session::new(boxed(t), read_limit);
        sess.tag = tag;
        sess.budget = budget;
        // What the server said before TLS is not trusted.
        caps = sess.capabilities().await?;
        (sess, false)
    } else {
        let name = name_of(&srv.host)?;
        let t = step("TLS", async {
            tls.connect(name, tcp).await.map_err(|e| e.to_string())
        })
        .await?;
        let mut sess = Session::new(boxed(t), read_limit);
        let preauth = sess.greeting(&mut caps).await?;
        if caps.is_empty() {
            caps = sess.capabilities().await?;
        }
        (sess, preauth)
    };
    if !preauth {
        sess.login(&caps, c).await?;
    }
    Ok(sess)
}

/// Runs one read operation and answers `(status, json)`.
pub(crate) async fn run(
    up: &Upstream,
    srv: &Server,
    op: &Operation,
    params: &BTreeMap<String, String>,
    c: &Creds<'_>,
    read_limit: usize,
    masker: &Masker,
) -> Result<(u16, Value), String> {
    let mut sess = open(up, srv, c, read_limit).await?;
    let out = match op.id.as_str() {
        "folders.list" => folders(&mut sess).await,
        "mail.list" => list(&mut sess, params).await,
        "mail.get" => get(&mut sess, params, masker).await,
        other => Err(format!("{other} is not an IMAP operation")),
    };
    // A clean goodbye after a success, briefly; after a failure the
    // session's state is unknown and nothing more is sent.
    if out.is_ok() {
        let _ = tokio::time::timeout(LOGOUT_WAIT, sess.logout()).await;
    }
    out
}

fn attr_name(a: &NameAttribute<'_>) -> String {
    match a {
        NameAttribute::NoInferiors => "\\Noinferiors".into(),
        NameAttribute::NoSelect => "\\Noselect".into(),
        NameAttribute::Marked => "\\Marked".into(),
        NameAttribute::Unmarked => "\\Unmarked".into(),
        NameAttribute::All => "\\All".into(),
        NameAttribute::Archive => "\\Archive".into(),
        NameAttribute::Drafts => "\\Drafts".into(),
        NameAttribute::Flagged => "\\Flagged".into(),
        NameAttribute::Junk => "\\Junk".into(),
        NameAttribute::Sent => "\\Sent".into(),
        NameAttribute::Trash => "\\Trash".into(),
        NameAttribute::Extension(e) => e.to_string(),
        other => format!("{other:?}"),
    }
}

async fn folders(sess: &mut Session) -> Result<(u16, Value), String> {
    let mut out = Vec::new();
    sess.run("LIST \"\" \"*\"", false, |r| {
        if let Response::MailboxData(MailboxDatum::List {
            name_attributes,
            delimiter,
            name,
        }) = r
        {
            out.push(json!({
                "name": name,
                "delimiter": delimiter,
                "attributes": name_attributes.iter().map(attr_name).collect::<Vec<_>>(),
            }));
        }
        Ok(())
    })
    .await?;
    Ok((200, json!({ "folders": out })))
}

fn addrs(a: &Option<Vec<Address<'_>>>) -> Value {
    let Some(list) = a else {
        return json!([]);
    };
    Value::Array(
        list.iter()
            // A group marker (no host) is not an address.
            .filter(|x| x.mailbox.is_some() && x.host.is_some())
            .map(|x| {
                let lossy = |b: &Option<std::borrow::Cow<'_, [u8]>>| {
                    b.as_deref()
                        .map(|b| String::from_utf8_lossy(b).into_owned())
                };
                let address = match (lossy(&x.mailbox), lossy(&x.host)) {
                    (Some(m), Some(h)) => Some(format!("{m}@{h}")),
                    _ => None,
                };
                json!({
                    "name": x.name.as_deref().map(message::header_text),
                    "address": address,
                })
            })
            .collect(),
    )
}

async fn list(
    sess: &mut Session,
    params: &BTreeMap<String, String>,
) -> Result<(u16, Value), String> {
    let q = list_query(params).map_err(|e| e.to_string())?;
    let folder = params.get("folder").map(String::as_str).unwrap_or("INBOX");
    let empty = || {
        Ok((
            200,
            json!({ "folder": folder, "messages": [], "next_before_uid": null }),
        ))
    };
    let ex = sess.examine(folder).await?;
    if ex.exists == Some(0) {
        return empty();
    }
    // The highest UID to look at: below UIDNEXT, and below `before_uid`.
    let mut top = match ex.uid_next {
        Some(n) => n.saturating_sub(1),
        None => match sess.last_uid().await? {
            Some(u) => u,
            None => return empty(),
        },
    };
    if let Some(b) = q.before_uid {
        top = top.min(b.saturating_sub(1));
    }
    if top == 0 {
        return empty();
    }
    let mut extra = Vec::new();
    if let Some(d) = &q.since {
        extra.push(format!(" SINCE {d}"));
    }
    if q.unseen {
        extra.push(" UNSEEN".into());
    }
    let extra = extra.concat();
    // Descending UID windows until `limit` hits, UID 1, or MAX_WINDOWS.
    let mut uids: Vec<u32> = Vec::new();
    let mut hi = top;
    let mut lo;
    let mut windows = 0;
    loop {
        lo = hi.saturating_sub(WINDOW - 1).max(1);
        let mut hits: Vec<u32> = Vec::new();
        let mut over = false;
        sess.run(&format!("UID SEARCH UID {lo}:{hi}{extra}"), false, |r| {
            if let Response::MailboxData(MailboxDatum::Search(v)) = r {
                hits.extend(v.into_iter().filter(|u| (lo..=hi).contains(u)));
                over |= hits.len() > WINDOW as usize;
            }
            Ok(())
        })
        .await?;
        if over {
            return Err("UID SEARCH: more results than UIDs searched".into());
        }
        uids.extend(hits);
        windows += 1;
        if uids.len() >= q.limit || lo == 1 || windows >= MAX_WINDOWS {
            break;
        }
        hi = lo - 1;
    }
    uids.sort_unstable_by(|a, b| b.cmp(a));
    uids.dedup();
    let found_n = uids.len();
    uids.truncate(q.limit);
    // A full page goes on below its last UID while anything may be left
    // below it; a short page stopped by MAX_WINDOWS goes on below the last
    // window searched.
    let next = if found_n > q.limit || (found_n == q.limit && lo > 1) {
        uids.last().copied().filter(|u| *u > 1)
    } else if found_n < q.limit && lo > 1 {
        Some(lo)
    } else {
        None
    };
    let mut found: BTreeMap<u32, Map<String, Value>> = BTreeMap::new();
    if !uids.is_empty() {
        let set: Vec<String> = uids.iter().map(u32::to_string).collect();
        let wanted: BTreeSet<u32> = uids.iter().copied().collect();
        sess.run(
            &format!(
                "UID FETCH {} (UID FLAGS RFC822.SIZE ENVELOPE)",
                set.join(",")
            ),
            false,
            |r| {
                if let Response::Fetch(_, attrs) = r {
                    let mut e = Map::new();
                    let mut uid = None;
                    for a in attrs {
                        match a {
                            AttributeValue::Uid(u) => uid = Some(u),
                            AttributeValue::Flags(f) => {
                                e.insert("flags".into(), json!(f));
                            }
                            AttributeValue::Rfc822Size(s) => {
                                e.insert("size".into(), json!(s));
                            }
                            AttributeValue::Envelope(env) => {
                                e.insert("from".into(), addrs(&env.from));
                                e.insert("to".into(), addrs(&env.to));
                                e.insert("cc".into(), addrs(&env.cc));
                                e.insert(
                                    "subject".into(),
                                    json!(env.subject.as_deref().map(message::header_text)),
                                );
                                e.insert(
                                    "date".into(),
                                    json!(env.date.as_deref().map(|d| {
                                        message::header_date(d).unwrap_or_else(|| {
                                            String::from_utf8_lossy(d).into_owned()
                                        })
                                    })),
                                );
                            }
                            _ => {}
                        }
                    }
                    if let Some(u) = uid.filter(|u| wanted.contains(u)) {
                        e.insert("uid".into(), json!(u));
                        found.entry(u).or_default().extend(e);
                    }
                }
                Ok(())
            },
        )
        .await?;
    }
    let messages: Vec<Value> = uids
        .iter()
        .filter_map(|u| found.remove(u).map(Value::Object))
        .collect();
    Ok((
        200,
        json!({ "folder": folder, "messages": messages, "next_before_uid": next }),
    ))
}

async fn get(
    sess: &mut Session,
    params: &BTreeMap<String, String>,
    masker: &Masker,
) -> Result<(u16, Value), String> {
    let folder = params.get("folder").map(String::as_str).unwrap_or("INBOX");
    let uid = params
        .get("uid")
        .and_then(|u| uid_of(u))
        .ok_or_else(|| "uid: not a message uid".to_string())?;
    sess.examine(folder).await?;
    let mut raw: Option<Vec<u8>> = None;
    sess.run(&format!("UID FETCH {uid} (UID BODY.PEEK[])"), false, |r| {
        if let Response::Fetch(_, attrs) = r {
            let mut this = None;
            let mut data = None;
            for a in attrs {
                match a {
                    AttributeValue::Uid(u) => this = Some(u),
                    AttributeValue::BodySection {
                        section: None,
                        data: Some(d),
                        ..
                    } => data = Some(d.into_owned()),
                    _ => {}
                }
            }
            if this == Some(uid) && data.is_some() {
                raw = data;
            }
        }
        Ok(())
    })
    .await?;
    Ok(match raw {
        // The answer fits in the service's `max_response_bytes` (the read
        // limit less the pipeline's slack).
        Some(r) => (
            200,
            message::get_json(
                uid,
                &r,
                sess.read_limit.saturating_sub(crate::pipeline::READ_SLACK),
                masker,
            ),
        ),
        None => (
            404,
            json!({ "error": "no message with this uid in the folder", "uid": uid }),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_sizes() {
        assert_eq!(literal_len(b"* 1 FETCH (BODY[] {12}\r\n"), Some(Ok(12)));
        assert_eq!(literal_len(b"* 1 FETCH (BODY[] {12+}\r\n"), Some(Ok(12)));
        assert_eq!(literal_len(b"* OK done\r\n"), None);
        assert_eq!(literal_len(b"* OK {x}\r\n"), None);
        assert!(matches!(
            literal_len(b"* 1 FETCH (BODY[] {99999999999999999999}\r\n"),
            Some(Err(_))
        ));
    }

    #[test]
    fn depth_guard() {
        let deep = format!("* 1 FETCH (BODYSTRUCTURE {}\r\n", "(".repeat(65));
        assert!(!depth_ok(deep.as_bytes()));
        assert!(parse(deep.as_bytes()).is_err());
        let ok = format!("* 1 FETCH (X {}{}\r\n", "(".repeat(63), ")".repeat(64));
        assert!(depth_ok(ok.as_bytes()));
        // Parentheses in quoted strings and literals do not count.
        let quoted = format!("* 1 FETCH (X \"{}\\\"\")\r\n", "(".repeat(100));
        assert!(depth_ok(quoted.as_bytes()), "{quoted}");
        let lit = format!("* 1 FETCH (BODY[] {{100}}\r\n{})\r\n", "(".repeat(100));
        assert!(depth_ok(lit.as_bytes()));
        // A literal's size does not hide what follows it.
        let after = format!("* 1 FETCH (BODY[] {{2}}\r\nab {}\r\n", "(".repeat(100));
        assert!(!depth_ok(after.as_bytes()));
        // An escape imap-proto would refuse, or a string left open.
        assert!(!depth_ok(b"* OK \"a\\x\"\r\n"));
        assert!(!depth_ok(b"* OK \"open\r\n"));
    }

    #[test]
    fn quoting() {
        assert_eq!(quoted("a\"b\\c").unwrap(), "\"a\\\"b\\\\c\"");
        assert!(quoted("a\r\nb").is_err());
        assert!(quoted("\u{e9}").is_err());
    }
}
