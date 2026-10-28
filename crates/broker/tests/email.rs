//! Email connector (plan 14, Task 13): the built-in `email` manifest through
//! the whole pipeline against the loopback SMTP and IMAP mocks of the mail
//! transport tests (copied from mail_transport.rs). Nothing leaves 127.0.0.1.
#![allow(dead_code)]

use base64::Engine as _;
use bytes::Bytes;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::limits::Limiter;
use saiife_broker::manifest::{AuthSpec, Manifest, OpKind};
use saiife_broker::pipeline::{
    record, run, ApprovalFuture, Call, Env, OpRef, Outcome, PendingCall, PolicySnapshot, Pools,
    Trace, Via,
};
use saiife_broker::request::AuthMaterial;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::Catalog;
use saiife_policy::{Mode, PolicyError, Scope, SystemConfig};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

const USER: &str = "mailbox-user";
/// The mailbox password; built at runtime, never a literal of one piece.
fn pass() -> String {
    concat!("mail", "-pw-", "7Qx", "9s3cr3t").to_string()
}
fn auth_b64() -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("\0{USER}\0{}", pass()))
}

// ------------------------------------------------------------------ PKI

struct Pki {
    acceptor: TlsAcceptor,
    roots: RootCertStore,
}

fn pki() -> Pki {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![
        "smtp.mail.test".to_string(),
        "imap.mail.test".to_string(),
    ])
    .unwrap()
    .signed_by(&leaf_key, &ca)
    .unwrap();
    let leaf_der: CertificateDer<'static> = leaf.der().clone();
    let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf_der], PrivateKeyDer::Pkcs8(key))
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    Pki {
        acceptor: TlsAcceptor::from(Arc::new(cfg)),
        roots,
    }
}

/// `*.mail.test` is 127.0.0.1 at the port asked for.
struct Loopback;

impl Resolver for Loopback {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if host.ends_with(".mail.test") {
            Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
        }
    }
}

fn upstream(p: &Pki, timeout: Duration) -> Upstream {
    Upstream::with_roots(p.roots.clone(), Arc::new(Loopback), timeout)
}

// ------------------------------------------------------------- servers

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type S = BufReader<Box<dyn Io>>;

fn wrap<T: Io + 'static>(t: T) -> S {
    BufReader::new(Box::new(t) as Box<dyn Io>)
}

async fn line(s: &mut S) -> Option<String> {
    let mut l = String::new();
    match s.read_line(&mut l).await {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(l.trim_end_matches(['\r', '\n']).to_string()),
    }
}

async fn put(s: &mut S, text: &str) {
    let _ = s.write_all(text.as_bytes()).await;
    let _ = s.flush().await;
}

/// What a mock saw.
#[derive(Default)]
struct Log {
    conns: AtomicUsize,
    /// Every line the client sent, in order (DATA content included).
    lines: Mutex<Vec<String>>,
    select_seen: AtomicBool,
}

impl Log {
    fn push(&self, l: &str) {
        self.lines.lock().unwrap().push(l.to_string());
    }
    fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
    fn any(&self, f: impl Fn(&str) -> bool) -> bool {
        self.lines().iter().any(|l| f(l))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Smtp {
    Implicit,
    StartTls,
    NoStartTls,
    /// `MAIL FROM` is refused with the password in the reply.
    EchoPassword,
}

async fn smtp_server(p: &Pki, mode: Smtp) -> (u16, Arc<Log>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Log::default());
    let (acc, l2) = (p.acceptor.clone(), log.clone());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            l2.conns.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(smtp_session(tcp, acc.clone(), mode, l2.clone()));
        }
    });
    (port, log)
}

async fn smtp_session(tcp: TcpStream, acc: TlsAcceptor, mode: Smtp, log: Arc<Log>) {
    let mut s = if mode == Smtp::StartTls || mode == Smtp::NoStartTls {
        let mut s = wrap(tcp);
        put(&mut s, "220 smtp.mail.test ESMTP\r\n").await;
        let Some(l) = line(&mut s).await else { return };
        log.push(&l);
        if mode == Smtp::NoStartTls {
            put(&mut s, "250-smtp.mail.test\r\n250 AUTH PLAIN\r\n").await;
            // Whatever comes now came in the clear.
            while let Some(l) = line(&mut s).await {
                log.push(&l);
                put(&mut s, "250 ok\r\n").await;
            }
            return;
        }
        put(
            &mut s,
            "250-smtp.mail.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
        )
        .await;
        let Some(l) = line(&mut s).await else { return };
        log.push(&l);
        put(&mut s, "220 go ahead\r\n").await;
        let tcp: Box<dyn Io> = s.into_inner();
        let Ok(t) = acc.accept(tcp).await else { return };
        wrap(t)
    } else {
        let Ok(t) = acc.accept(tcp).await else { return };
        let mut s = wrap(t);
        put(&mut s, "220 smtp.mail.test ESMTP\r\n").await;
        s
    };
    while let Some(l) = line(&mut s).await {
        log.push(&l);
        let verb = l
            .split([' ', ':'])
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        match verb.as_str() {
            "EHLO" => put(&mut s, "250-smtp.mail.test\r\n250 AUTH PLAIN\r\n").await,
            "AUTH" => {
                if l == format!("AUTH PLAIN {}", auth_b64()) {
                    put(&mut s, "235 ok\r\n").await
                } else {
                    put(&mut s, "535 no\r\n").await
                }
            }
            "MAIL" if mode == Smtp::EchoPassword => {
                put(&mut s, &format!("550 refused for {USER} {}\r\n", pass())).await
            }
            "MAIL" | "RCPT" => put(&mut s, "250 ok\r\n").await,
            "DATA" => {
                put(&mut s, "354 go\r\n").await;
                while let Some(d) = line(&mut s).await {
                    log.push(&d);
                    if d == "." {
                        break;
                    }
                }
                put(&mut s, "250 queued\r\n").await;
            }
            "QUIT" => {
                put(&mut s, "221 bye\r\n").await;
                return;
            }
            _ => put(&mut s, "500 what\r\n").await,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Imap {
    Implicit,
    StartTls,
    NoStartTls,
    /// `mail.get` announces a 2 GiB literal.
    HugeLiteral,
    /// The greeting never ends.
    EndlessLine,
    /// Says nothing at all after TLS.
    Silent,
    /// Refuses the login, and `EXAMINE`, with the password in the text.
    EchoPassword,
    /// `mail.get` answers with a BODYSTRUCTURE nested 1000 deep.
    DeepNest,
    /// Message 104's text holds the mailbox password.
    SecretBody,
    /// `mail.get` first gets an unasked-for, valid BODYSTRUCTURE this many
    /// parentheses deep, then the message.
    Nest(usize),
    /// 5,000 messages (UIDs 1 to 5000, unseen 3, 7 and 4990), and an
    /// `EXAMINE` without `UIDNEXT`.
    Big,
}

const BIG_UNSEEN: [u32; 3] = [3, 7, 4990];

/// The UIDs of the mailbox and its unseen ones.
fn mailbox(mode: Imap) -> (Vec<u32>, Vec<u32>) {
    if mode == Imap::Big {
        ((1..=5000).collect(), BIG_UNSEEN.to_vec())
    } else {
        (UIDS.to_vec(), vec![])
    }
}

/// The test mailbox: UIDs 101 to 105 in INBOX (sequence numbers 1 to 5).
const UIDS: [u32; 5] = [101, 102, 103, 104, 105];
const ATTACHMENT_B64: &str = "JVBERi0xLjQKc2FpaWZlLWF0dGFjaG1lbnQtYm9keQo=";

fn message_104() -> String {
    format!(
        "From: Alice <alice@acme.com>\r\n\
         To: Bob <bob@acme.com>\r\n\
         Cc: carol@acme.com\r\n\
         Subject: =?UTF-8?B?UXVhcnRhbHNiZXJpY2h0IMOcYmVyc2ljaHQ=?=\r\n\
         Date: Mon, 2 Mar 2026 10:00:00 +0000\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
         \r\n\
         --outer\r\n\
         Content-Type: multipart/alternative; boundary=\"alt\"\r\n\
         \r\n\
         --alt\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         Hello Bob, the report is attached.\r\n\
         --alt\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         \r\n\
         <p>Hello Bob, the <b>report</b> is attached.</p>\r\n\
         --alt--\r\n\
         --outer\r\n\
         Content-Type: application/pdf; name=\"report.pdf\"\r\n\
         Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {ATTACHMENT_B64}\r\n\
         --outer--\r\n"
    )
}

fn envelope(uid: u32) -> String {
    format!(
        "(\"Mon, 2 Mar 2026 10:00:00 +0000\" \"Report {uid}\" ((\"Alice\" NIL \"alice\" \"acme.com\")) \
         NIL NIL ((\"Bob\" NIL \"bob\" \"acme.com\")) NIL NIL NIL \"<m{uid}@acme.com>\")"
    )
}

async fn imap_server(p: &Pki, mode: Imap) -> (u16, Arc<Log>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Log::default());
    let (acc, l2) = (p.acceptor.clone(), log.clone());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            l2.conns.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(imap_session(tcp, acc.clone(), mode, l2.clone()));
        }
    });
    (port, log)
}

async fn imap_session(tcp: TcpStream, acc: TlsAcceptor, mode: Imap, log: Arc<Log>) {
    let starttls = matches!(mode, Imap::StartTls | Imap::NoStartTls);
    let mut s = if starttls {
        let mut s = wrap(tcp);
        put(&mut s, "* OK IMAP ready\r\n").await;
        loop {
            let Some(l) = line(&mut s).await else { return };
            log.push(&l);
            let (tag, cmd) = l.split_once(' ').unwrap_or((&l, ""));
            match cmd.to_ascii_uppercase().as_str() {
                "CAPABILITY" if mode == Imap::NoStartTls => {
                    put(
                        &mut s,
                        &format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n{tag} OK done\r\n"),
                    )
                    .await
                }
                "CAPABILITY" => {
                    put(
                        &mut s,
                        &format!(
                            "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n{tag} OK done\r\n"
                        ),
                    )
                    .await
                }
                "STARTTLS" if mode == Imap::StartTls => {
                    put(&mut s, &format!("{tag} OK begin TLS\r\n")).await;
                    break;
                }
                // Anything else in the clear: answer, the test checks it never comes.
                _ => put(&mut s, &format!("{tag} OK fine\r\n")).await,
            }
        }
        let tcp: Box<dyn Io> = s.into_inner();
        let Ok(t) = acc.accept(tcp).await else { return };
        wrap(t)
    } else {
        let Ok(t) = acc.accept(tcp).await else { return };
        let mut s = wrap(t);
        match mode {
            Imap::Silent => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }
            Imap::EndlessLine => {
                put(&mut s, "* OK ").await;
                let chunk = "a".repeat(4096);
                for _ in 0..10_000 {
                    if s.write_all(chunk.as_bytes()).await.is_err() {
                        return;
                    }
                }
                return;
            }
            _ => {
                put(
                    &mut s,
                    "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN SASL-IR] IMAP ready\r\n",
                )
                .await
            }
        }
        s
    };
    while let Some(l) = line(&mut s).await {
        log.push(&l);
        let (tag, cmd) = l.split_once(' ').unwrap_or((&l, ""));
        let tag = tag.to_string();
        let upper = cmd.to_ascii_uppercase();
        if upper == "CAPABILITY" {
            // After STARTTLS: no SASL-IR, so AUTHENTICATE takes two steps.
            put(
                &mut s,
                &format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n{tag} OK done\r\n"),
            )
            .await;
        } else if upper.starts_with("AUTHENTICATE PLAIN") {
            let given = match cmd.split(' ').nth(2) {
                Some(b) => b.to_string(),
                None => {
                    // Untagged chatter before the continuation.
                    put(
                        &mut s,
                        "* OK [ALERT] hello\r\n* CAPABILITY IMAP4rev1\r\n+ \r\n",
                    )
                    .await;
                    let Some(b) = line(&mut s).await else { return };
                    log.push(&b);
                    b
                }
            };
            if mode == Imap::EchoPassword {
                put(
                    &mut s,
                    &format!("{tag} NO [AUTHENTICATIONFAILED] {given} {}\r\n", pass()),
                )
                .await;
            } else if given == auth_b64() {
                put(&mut s, &format!("{tag} OK logged in\r\n")).await;
            } else {
                put(&mut s, &format!("{tag} NO [AUTHENTICATIONFAILED] no\r\n")).await;
            }
        } else if upper.starts_with("SELECT") {
            log.select_seen.store(true, Ordering::SeqCst);
            put(&mut s, &format!("{tag} BAD SELECT is not for saiife\r\n")).await;
        } else if upper.starts_with("EXAMINE") {
            let (uids, _) = mailbox(mode);
            let next = if mode == Imap::Big {
                String::new()
            } else {
                format!("* OK [UIDNEXT {}] next\r\n", uids.last().unwrap() + 1)
            };
            put(
                &mut s,
                &format!(
                    "* {} EXISTS\r\n* FLAGS (\\Seen \\Answered)\r\n* OK [UIDVALIDITY 7] ok\r\n\
                     {next}{tag} OK [READ-ONLY] EXAMINE done\r\n",
                    uids.len()
                ),
            )
            .await;
        } else if upper == "FETCH * (UID)" {
            let (uids, _) = mailbox(mode);
            let last = uids.last().unwrap();
            put(
                &mut s,
                &format!(
                    "* {} FETCH (UID {last})\r\n{tag} OK FETCH done\r\n",
                    uids.len()
                ),
            )
            .await;
        } else if upper.starts_with("LIST") {
            put(
                &mut s,
                &format!(
                    "* LIST (\\HasNoChildren) \"/\" INBOX\r\n\
                     * LIST (\\HasNoChildren \\Sent) \"/\" Sent\r\n{tag} OK LIST done\r\n"
                ),
            )
            .await;
        } else if upper.starts_with("UID SEARCH") {
            let words: Vec<&str> = upper.split(' ').collect();
            let (lo, hi) = words[1..]
                .windows(2)
                .find(|w| w[0] == "UID")
                .and_then(|w| w[1].split_once(':'))
                .and_then(|(a, b)| Some((a.parse::<u32>().ok()?, b.parse::<u32>().ok()?)))
                .unwrap_or((1, u32::MAX));
            let unseen_only = words.contains(&"UNSEEN");
            let (uids, unseen) = mailbox(mode);
            let hits: Vec<String> = uids
                .iter()
                .filter(|u| (lo..=hi).contains(*u))
                .filter(|u| !unseen_only || unseen.contains(u))
                .map(u32::to_string)
                .collect();
            put(
                &mut s,
                &format!("* SEARCH {}\r\n{tag} OK SEARCH done\r\n", hits.join(" ")),
            )
            .await;
        } else if upper.starts_with("UID FETCH") && upper.contains("ENVELOPE") {
            let set = cmd.split(' ').nth(2).unwrap_or("");
            let mut out = String::new();
            for u in set.split(',').filter_map(|u| u.parse::<u32>().ok()) {
                let seq = mailbox(mode).0.iter().position(|x| *x == u).unwrap() + 1;
                out.push_str(&format!(
                    "* {seq} FETCH (UID {u} FLAGS (\\Seen) RFC822.SIZE {} ENVELOPE {})\r\n",
                    1000 + u,
                    envelope(u)
                ));
            }
            put(&mut s, &format!("{out}{tag} OK FETCH done\r\n")).await;
        } else if upper.starts_with("UID FETCH") {
            if let Imap::Nest(depth) = mode {
                // Multiparts around one text part; the FETCH list is one level.
                let mut b = "(\"text\" \"plain\" NIL NIL NIL \"7bit\" 1 1)".to_string();
                for _ in 0..depth - 2 {
                    b = format!("({b} \"mixed\")");
                }
                put(&mut s, &format!("* 4 FETCH (BODYSTRUCTURE {b})\r\n")).await;
            }
            if mode == Imap::DeepNest {
                put(
                    &mut s,
                    &format!("* 4 FETCH (BODYSTRUCTURE {}\r\n", "(".repeat(1000)),
                )
                .await;
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }
            if mode == Imap::HugeLiteral {
                put(&mut s, "* 4 FETCH (UID 104 BODY[] {2147483648}\r\n").await;
                let _ = s.write_all(&[b'x'; 4096]).await;
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }
            let uid: u32 = cmd.split(' ').nth(2).unwrap_or("").parse().unwrap_or(0);
            if uid == 104 {
                let m = if mode == Imap::SecretBody {
                    format!(
                        "From: a@acme.com\r\nSubject: s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
                         {}{}{}\r\n",
                        "a".repeat(300),
                        pass(),
                        "b".repeat(300)
                    )
                } else {
                    message_104()
                };
                put(
                    &mut s,
                    &format!(
                        "* 4 FETCH (UID 104 BODY[] {{{}}}\r\n{m})\r\n{tag} OK FETCH done\r\n",
                        m.len()
                    ),
                )
                .await;
            } else {
                put(&mut s, &format!("{tag} OK FETCH done\r\n")).await;
            }
        } else if upper == "LOGOUT" {
            put(
                &mut s,
                &format!("* BYE see you\r\n{tag} OK LOGOUT done\r\n"),
            )
            .await;
            return;
        } else {
            put(&mut s, &format!("{tag} BAD unknown\r\n")).await;
        }
    }
}

// ------------------------------------------------------------- pipeline

struct FakeEnv {
    pools: Pools,
}

impl Env for FakeEnv {
    fn lockdown(&self) -> Option<saiife_broker::pipeline::Lockdown> {
        None
    }
    fn scope(&self, _user: &str) -> Result<Option<Scope>, PolicyError> {
        Ok(Some(Scope {
            name: "mail-agents".into(),
            users: vec!["agent".into()],
            projects: vec![],
            services: vec!["mail".into()],
            env: None,
        }))
    }
    fn secret(
        &self,
        _name: &str,
        _service: &str,
        auth: &[AuthSpec],
    ) -> Result<AuthMaterial, &'static str> {
        let fields = [
            ("username".to_string(), Zeroizing::new(USER.to_string())),
            ("password".to_string(), Zeroizing::new(pass())),
        ]
        .into();
        Ok(AuthMaterial::from_spec(&auth[0], fields))
    }
    fn secret_values(&self, _name: &str) -> Option<Vec<Zeroizing<String>>> {
        Some(vec![Zeroizing::new(USER.into()), Zeroizing::new(pass())])
    }
    fn pool(&self, service: &str) -> Arc<Semaphore> {
        self.pools.get(service)
    }
    fn create_approval<'a>(&'a self, _p: &'a PendingCall) -> ApprovalFuture<'a> {
        Box::pin(async move { Ok(42) })
    }
}

fn snapshot(smtp: (u16, &str), imap: (u16, &str)) -> PolicySnapshot {
    snapshot_with(smtp, imap, "")
}

/// The snapshot with `extra` appended to the service table.
fn snapshot_with(smtp: (u16, &str), imap: (u16, &str), extra: &str) -> PolicySnapshot {
    snapshot_allow(
        smtp,
        imap,
        r#"["mail:write", "mail:read", "folders:read"]"#,
        extra,
    )
}

fn snapshot_allow(
    smtp: (u16, &str),
    imap: (u16, &str),
    allow: &str,
    extra: &str,
) -> PolicySnapshot {
    let text = format!(
        r#"version = 2
locked = true
[services.mail]
connector = "email"
secret = "mailbox"
params = {{ smtp_host = "smtp.mail.test", smtp_port = "{}", smtp_tls = "{}", imap_host = "imap.mail.test", imap_port = "{}", imap_tls = "{}", from = "bot@acme.com" }}
allow = {}
{}
"#,
        smtp.0, smtp.1, imap.0, imap.1, allow, extra
    );
    let config: SystemConfig = toml::from_str(&text).unwrap();
    PolicySnapshot {
        config,
        hash: "sha256:test".into(),
        mode: Mode::Locked,
        env: None,
    }
}

/// The built-in catalog: the `email` manifest as shipped.
fn catalog() -> Catalog {
    Catalog::new(saiife_broker::manifest::builtin(), Vec::new())
}

fn email() -> &'static Manifest {
    saiife_broker::manifest::builtin()
        .iter()
        .find(|m| m.id == "email")
        .expect("email is a built-in manifest")
}

fn call(op: &str, params: &[(&str, &str)], body: Option<&str>) -> Call {
    Call {
        uid: 1001,
        user: "agent".into(),
        session: Some("sess-1".into()),
        project: "/srv/mail".into(),
        service: "mail".into(),
        op: OpRef::Named(op.into()),
        params: params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: body.map(|b| Bytes::from(b.to_string())),
        headers: vec![],
        overlay: None,
        via: Via::Cli,
        collection: None,
    }
}

async fn go(c: &Call, snap: &PolicySnapshot, cat: &Catalog, up: &Upstream) -> (Outcome, Trace) {
    go_with(c, snap, cat, up, &Limiter::new()).await
}

async fn go_with(
    c: &Call,
    snap: &PolicySnapshot,
    cat: &Catalog,
    up: &Upstream,
    lim: &Limiter,
) -> (Outcome, Trace) {
    let env = FakeEnv {
        pools: Pools::new(),
    };
    run(c, snap, cat, lim, &env, Some(up)).await
}

fn done(o: &Outcome) -> (u16, serde_json::Value) {
    match o {
        Outcome::Done { finished, .. } => (
            finished.status,
            serde_json::from_slice(&finished.body).unwrap(),
        ),
        other => panic!("expected done, got {other:?}"),
    }
}

fn failed(o: &Outcome) -> &str {
    match o {
        Outcome::UpstreamFailed { reason } => reason,
        other => panic!("expected upstream failure, got {other:?}"),
    }
}

fn rule(o: &Outcome) -> &str {
    match o {
        Outcome::Denied { rule } => rule,
        other => panic!("expected a deny, got {other:?}"),
    }
}

/// The record and the outcome hold no credential in any form.
fn assert_no_secret(c: &Call, snap: &PolicySnapshot, tr: &Trace, o: &Outcome) {
    let rec = serde_json::to_string(&record(c, snap, tr, o, "", "0.2.0")).unwrap();
    let out = format!("{o:?}");
    for v in [pass(), auth_b64()] {
        assert!(!rec.contains(&v), "record holds a secret: {rec}");
        assert!(!out.contains(&v), "outcome holds a secret: {out}");
    }
}

// ---------------------------------------------------------------- tests

#[test]
fn manifest_shape() {
    let m = email();
    assert_eq!(m.transport, saiife_broker::manifest::Transport::Mail);
    assert!(m.base_url.is_empty());
    assert_eq!(m.hosts, ["{smtp_host}", "{imap_host}"]);
    assert_eq!(m.auth.len(), 1);
    assert_eq!(m.auth[0].kind, "basic");
    for p in [
        "smtp_host",
        "smtp_port",
        "smtp_tls",
        "imap_host",
        "imap_port",
        "imap_tls",
        "from",
    ] {
        assert!(m.params.contains_key(p), "no service param {p}");
    }
    let want = [
        ("mail.send", "mail:write", OpKind::Write),
        ("folders.list", "folders:read", OpKind::Read),
        ("mail.list", "mail:read", OpKind::Read),
        ("mail.get", "mail:read", OpKind::Read),
    ];
    let ids: Vec<&str> = m.operation.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(ids, want.map(|w| w.0));
    for (id, cap, kind) in want {
        let op = m.operation.iter().find(|o| o.id == id).unwrap();
        assert_eq!((op.capability.as_str(), op.kind), (cap, kind), "{id}");
        assert!(op.method.is_empty() && op.path.is_empty(), "{id}");
    }
}

#[tokio::test]
async fn send_and_list_end_to_end() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let (ip, _) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((sp, "implicit"), (ip, "implicit"));
    let cat = catalog();
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "Weekly report")],
        Some("Hello\n"),
    );
    let (o, tr) = go(&c, &snap, &cat, &up).await;
    assert_eq!(
        done(&o).1,
        serde_json::json!({ "sent": true, "to": "a@acme.com" })
    );
    assert_eq!(tr.capability.as_deref(), Some("mail:write:to=a@acme.com"));
    assert!(
        log.any(|l| l == "MAIL FROM:<bot@acme.com>"),
        "{:?}",
        log.lines()
    );
    assert_no_secret(&c, &snap, &tr, &o);

    let (o, tr) = go(&call("folders.list", &[], None), &snap, &cat, &up).await;
    assert_eq!(done(&o).1["folders"][0]["name"], "INBOX");
    assert_eq!(tr.capability.as_deref(), Some("folders:read"));
    let (o, tr) = go(
        &call("mail.list", &[("folder", "INBOX"), ("limit", "2")], None),
        &snap,
        &cat,
        &up,
    )
    .await;
    assert_eq!(tr.capability.as_deref(), Some("mail:read:folder=INBOX"));
    match &o {
        Outcome::Done { next, .. } => {
            let n = next.as_ref().expect("a next page");
            assert_eq!(n.get("before_uid").map(String::as_str), Some("104"));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn send_only_to_allowed_domain() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot_allow(
        (sp, "implicit"),
        (1, "implicit"),
        r#"["mail:read"]"#,
        "[[services.mail.rule]]\ncapability = \"mail:write\"\nwhen = { to = \"*@acme.com\" }\naction = \"allow\"",
    );
    let cat = catalog();
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    let (o, _) = go(&c, &snap, &cat, &up).await;
    assert_eq!(done(&o).0, 200);
    assert_eq!(log.conns.load(Ordering::SeqCst), 1);

    for to in ["a@evil.test", "a@acme.com.evil.test", "a@sub.acme.com"] {
        let c = call("mail.send", &[("to", to), ("subject", "s")], Some("b"));
        let (o, _) = go(&c, &snap, &cat, &up).await;
        assert!(matches!(o, Outcome::Denied { .. }), "{to}: {o:?}");
    }
    assert_eq!(
        log.conns.load(Ordering::SeqCst),
        1,
        "a denied send connects nowhere"
    );
}

#[tokio::test]
async fn reads_leave_seen_flag_unset() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (ip, log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let cat = catalog();
    for c in [
        call("folders.list", &[], None),
        call("mail.list", &[("folder", "INBOX")], None),
        call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None),
    ] {
        let (o, _) = go(&c, &snap, &cat, &up).await;
        assert_eq!(done(&o).0, 200);
    }
    let lines = log.lines();
    assert!(!log.select_seen.load(Ordering::SeqCst), "{lines:?}");
    // Every message read is a PEEK; nothing stores flags.
    assert!(lines.iter().any(|l| l.contains("BODY.PEEK[]")), "{lines:?}");
    assert!(
        !lines.iter().any(|l| {
            let u = l.to_ascii_uppercase();
            u.contains(" STORE ")
                || u.contains(" SELECT ")
                || u.contains("BODY[")
                || u.contains("RFC822)")
                || u.contains(" COPY ")
                || u.contains(" EXPUNGE")
        }),
        "{lines:?}"
    );
    assert_eq!(
        lines.iter().filter(|l| l.contains(" EXAMINE ")).count(),
        2,
        "{lines:?}"
    );
}

#[tokio::test]
async fn writes_per_hour_caps_send() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot_with(
        (sp, "implicit"),
        (1, "implicit"),
        "[services.mail.limits]\nwrites_per_hour = 2",
    );
    let cat = catalog();
    let lim = Limiter::new();
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    for _ in 0..2 {
        let (o, _) = go_with(&c, &snap, &cat, &up, &lim).await;
        assert_eq!(done(&o).0, 200);
    }
    let (o, tr) = go_with(&c, &snap, &cat, &up, &lim).await;
    assert!(
        matches!(
            o,
            Outcome::Limited {
                limit: "writes_per_hour"
            }
        ),
        "{o:?}"
    );
    assert!(!tr.sent);
    assert_eq!(log.conns.load(Ordering::SeqCst), 2);
}
