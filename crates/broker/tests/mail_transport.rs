//! The mail transport (plan 14, Task 6): `mail.send` over SMTP and the
//! read-only IMAP operations, through the whole pipeline, against loopback
//! SMTP and IMAP mock servers with rcgen certificates, scripted line by
//! line. Nothing leaves 127.0.0.1.

use base64::Engine as _;
use bytes::Bytes;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_broker::limits::Limiter;
use saiife_broker::manifest::{AuthSpec, Manifest};
use saiife_broker::pipeline::{
    record, run, ApprovalFuture, Call, Env, OpRef, Outcome, PendingCall, PolicySnapshot, Pools,
    Trace, Via,
};
use saiife_broker::request::AuthMaterial;
use saiife_broker::upstream::{Resolver, Upstream};
use saiife_broker::Catalog;
use saiife_policy::{Mode, PolicyError, Scope, SystemConfig};
use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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

const MANIFEST: &str = r#"
id = "test-mail"
version = 1
title = "Test mail"
hosts = ["{smtp_host}", "{imap_host}"]
transport = "mail"
auth = [{ kind = "basic" }]

[params.smtp_host]
type = "string"
pattern = '^[a-z0-9.-]+$'
required = true

[params.smtp_port]
type = "int:1..65535"

[params.smtp_tls]
type = "enum:implicit,starttls"

[params.imap_host]
type = "string"
pattern = '^[a-z0-9.-]+$'
required = true

[params.imap_port]
type = "int:1..65535"

[params.imap_tls]
type = "enum:implicit,starttls"

[params.from]
type = "string"
required = true

[[operation]]
id = "mail.send"
capability = "mail:write"
qualifier = "to={to}"
kind = "write"
body = "text"
query = { to = 'string:[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253}', subject = "string:.{1,998}" }

[[operation]]
id = "folders.list"
capability = "folders:read"
kind = "read"

[[operation]]
id = "mail.list"
capability = "mail:read"
qualifier = "folder={folder}"
kind = "read"
query = { folder = "string", since = "datetime", unseen = "bool", limit = "int:1..100", before_uid = "int" }
pagination = { cursor = { param = "before_uid", next = "next_before_uid" } }

[[operation]]
id = "mail.get"
capability = "mail:read"
qualifier = "folder={folder}"
kind = "read"
query = { folder = "string", uid = "int" }
"#;

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
    let text = format!(
        r#"version = 2
locked = true
[services.mail]
connector = "test-mail"
secret = "mailbox"
params = {{ smtp_host = "smtp.mail.test", smtp_port = "{}", smtp_tls = "{}", imap_host = "imap.mail.test", imap_port = "{}", imap_tls = "{}", from = "bot@acme.com" }}
allow = ["mail:write", "mail:read", "folders:read"]
"#,
        smtp.0, smtp.1, imap.0, imap.1
    );
    let config: SystemConfig = toml::from_str(&text).unwrap();
    PolicySnapshot {
        config,
        hash: "sha256:test".into(),
        mode: Mode::Locked,
        env: None,
    }
}

fn catalog_of(text: &str) -> Catalog {
    Catalog::new(&[], vec![Manifest::parse(text).unwrap()])
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
    let env = FakeEnv {
        pools: Pools::new(),
    };
    run(c, snap, cat, &Limiter::new(), &env, Some(up)).await
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

#[tokio::test]
async fn smtp_send_one_recipient_golden_transcript() {
    let p = pki();
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot((sp, "implicit"), (1, "implicit"));
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "Weekly report")],
        Some("Hello,\n.this line starts with a dot\nGrüße = regards \n"),
    );
    let (o, tr) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    let (status, v) = done(&o);
    assert_eq!(status, 200);
    assert_eq!(v, serde_json::json!({ "sent": true, "to": "a@acme.com" }));
    assert_eq!(tr.capability.as_deref(), Some("mail:write:to=a@acme.com"));
    assert_no_secret(&c, &snap, &tr, &o);

    // The transcript, with the login, the date and the message id normalized.
    let lines = log.lines();
    assert!(lines.contains(&format!("AUTH PLAIN {}", auth_b64())));
    let got: String = lines
        .iter()
        .map(|l| {
            if l.starts_with("AUTH PLAIN ") {
                "AUTH PLAIN [login]".to_string()
            } else if l.starts_with("Date: ") {
                "Date: [date]".to_string()
            } else if l.starts_with("Message-ID: ") {
                assert!(l.ends_with(".saiife@acme.com>"), "{l}");
                "Message-ID: [id]".to_string()
            } else {
                l.clone()
            }
        })
        .map(|l| l + "\n")
        .collect();
    let golden = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/mail_send.smtp"
    ))
    .unwrap();
    assert_eq!(got, golden);
    assert_eq!(lines.iter().filter(|l| l.starts_with("RCPT")).count(), 1);
}

#[tokio::test]
async fn smtp_starttls_then_send() {
    let p = pki();
    let (sp, log) = smtp_server(&p, Smtp::StartTls).await;
    let snap = snapshot((sp, "starttls"), (1, "implicit"));
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    assert_eq!(done(&o).0, 200);
    let lines = log.lines();
    assert_eq!(&lines[..3], ["EHLO saiife", "STARTTLS", "EHLO saiife"]);
}

#[tokio::test]
async fn starttls_missing_refused_before_auth() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    // SMTP.
    let (sp, log) = smtp_server(&p, Smtp::NoStartTls).await;
    let snap = snapshot((sp, "starttls"), (1, "implicit"));
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    let (o, tr) = go(&c, &snap, &catalog_of(MANIFEST), &up).await;
    assert!(failed(&o).contains("STARTTLS"), "{o:?}");
    assert_eq!(log.lines(), ["EHLO saiife"]);
    assert_no_secret(&c, &snap, &tr, &o);
    // IMAP.
    let (ip, log) = imap_server(&p, Imap::NoStartTls).await;
    let snap = snapshot((1, "implicit"), (ip, "starttls"));
    let c = call("folders.list", &[], None);
    let (o, tr) = go(&c, &snap, &catalog_of(MANIFEST), &up).await;
    assert!(failed(&o).contains("STARTTLS"), "{o:?}");
    assert!(
        !log.any(|l| {
            let u = l.to_ascii_uppercase();
            u.contains("AUTHENTICATE") || u.contains("LOGIN")
        }),
        "{:?}",
        log.lines()
    );
    assert_no_secret(&c, &snap, &tr, &o);
}

#[tokio::test]
async fn imap_starttls_two_step_authenticate() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::StartTls).await;
    let snap = snapshot((1, "implicit"), (ip, "starttls"));
    let c = call("folders.list", &[], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    let (status, v) = done(&o);
    assert_eq!(status, 200);
    assert_eq!(v["folders"][1]["name"], "Sent");
    assert_eq!(v["folders"][1]["attributes"][1], "\\Sent");
    let lines = log.lines();
    // The plaintext capabilities are asked again after TLS.
    assert_eq!(lines[0], "s1 CAPABILITY");
    assert_eq!(lines[1], "s2 STARTTLS");
    assert_eq!(lines[2], "s3 CAPABILITY");
    assert_eq!(lines[3], "s4 AUTHENTICATE PLAIN");
    assert_eq!(lines[4], auth_b64());
}

#[tokio::test]
async fn crlf_in_subject_rejected() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let (sp, log) = smtp_server(&p, Smtp::Implicit).await;
    let snap = snapshot((sp, "implicit"), (1, "implicit"));
    let cat = catalog_of(MANIFEST);
    for params in [
        [("to", "a@acme.com"), ("subject", "hi\r\nBcc: b@evil.test")],
        [("to", "a@acme.com"), ("subject", "hi\nBcc: b@evil.test")],
        [("to", "a@acme.com\r\nBcc: b@evil.test"), ("subject", "hi")],
        [("to", "a@acme.com,b@evil.test"), ("subject", "hi")],
    ] {
        let (o, _) = go(&call("mail.send", &params, Some("b")), &snap, &cat, &up).await;
        assert_eq!(rule(&o), "bad_param", "{params:?}");
    }
    // A manifest with loose types: the transport still refuses before
    // connecting.
    let loose = MANIFEST.replace(
        r#"query = { to = 'string:[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253}', subject = "string:.{1,998}" }"#,
        r#"query = { to = "string", subject = "string" }"#,
    );
    assert_ne!(loose, MANIFEST);
    let cat = catalog_of(&loose);
    for to in [
        "a@acme.com,b@evil.test",
        "a@acme.com b@evil.test",
        "<a@acme.com>",
    ] {
        let (o, _) = go(
            &call("mail.send", &[("to", to), ("subject", "hi")], Some("b")),
            &snap,
            &cat,
            &up,
        )
        .await;
        assert_eq!(rule(&o), "bad_param", "{to}");
    }
    assert_eq!(log.conns.load(Ordering::SeqCst), 0, "nothing may connect");
}

#[tokio::test]
async fn examine_never_select() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let up = upstream(&p, Duration::from_secs(5));
    let cat = catalog_of(MANIFEST);
    for c in [
        call("mail.list", &[("folder", "INBOX")], None),
        call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None),
    ] {
        let (o, _) = go(&c, &snap, &cat, &up).await;
        assert_eq!(done(&o).0, 200);
    }
    assert!(!log.select_seen.load(Ordering::SeqCst), "{:?}", log.lines());
    assert_eq!(
        log.lines()
            .iter()
            .filter(|l| l.contains("EXAMINE \"INBOX\""))
            .count(),
        2
    );
}

#[tokio::test]
async fn fetch_uses_body_peek() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    assert_eq!(done(&o).0, 200);
    let fetches: Vec<String> = log
        .lines()
        .into_iter()
        .filter(|l| l.contains("FETCH"))
        .collect();
    assert_eq!(fetches.len(), 1);
    assert!(
        fetches[0].ends_with("UID FETCH 104 (UID BODY.PEEK[])"),
        "{fetches:?}"
    );
    assert!(!log.any(|l| l.contains("BODY[") || l.contains("RFC822)") || l.contains("STORE")));
}

#[tokio::test]
async fn missing_uid_is_404() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "999")], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    assert_eq!(done(&o).0, 404);
}

#[tokio::test]
async fn literal_over_limit_refused() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::HugeLiteral).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let started = Instant::now();
    let (o, tr) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(20)),
    )
    .await;
    let r = failed(&o);
    assert!(
        r.contains("2147483648") && r.contains("over the read limit"),
        "{r}"
    );
    // Refused from the announced size, not after reading or a timeout.
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(tr.sent);
}

#[tokio::test]
async fn endless_line_times_out_or_cuts() {
    let p = pki();
    let cat = catalog_of(MANIFEST);
    // A line that never ends is cut at 8 KiB.
    let (ip, _log) = imap_server(&p, Imap::EndlessLine).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let started = Instant::now();
    let (o, _) = go(
        &call("folders.list", &[], None),
        &snap,
        &cat,
        &upstream(&p, Duration::from_secs(20)),
    )
    .await;
    assert!(failed(&o).contains("line too long"), "{o:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // A server that says nothing runs into the timeout.
    let (ip, _log) = imap_server(&p, Imap::Silent).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let started = Instant::now();
    let (o, _) = go(
        &call("folders.list", &[], None),
        &snap,
        &cat,
        &upstream(&p, Duration::from_millis(800)),
    )
    .await;
    assert!(failed(&o).contains("timeout"), "{o:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn mail_list_next_before_uid() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let up = upstream(&p, Duration::from_secs(5));
    let cat = catalog_of(MANIFEST);
    let page = |o: &Outcome| -> (Vec<u64>, Option<BTreeMap<String, String>>) {
        match o {
            Outcome::Done { finished, next } => {
                let v: serde_json::Value = serde_json::from_slice(&finished.body).unwrap();
                let uids = v["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| m["uid"].as_u64().unwrap())
                    .collect();
                (uids, next.clone())
            }
            other => panic!("{other:?}"),
        }
    };
    let (o, _) = go(
        &call("mail.list", &[("folder", "INBOX"), ("limit", "2")], None),
        &snap,
        &cat,
        &up,
    )
    .await;
    let (uids, next) = page(&o);
    assert_eq!(uids, [105, 104]);
    let next = next.expect("a next page");
    assert_eq!(next.get("before_uid").map(String::as_str), Some("104"));
    // The first message carries its envelope.
    if let Outcome::Done { finished, .. } = &o {
        let v: serde_json::Value = serde_json::from_slice(&finished.body).unwrap();
        let m = &v["messages"][0];
        assert_eq!(m["subject"], "Report 105");
        assert_eq!(m["from"][0]["address"], "alice@acme.com");
        assert_eq!(m["to"][0]["name"], "Bob");
        assert_eq!(m["size"], 1105);
        assert_eq!(m["flags"][0], "\\Seen");
        assert_eq!(m["date"], "2026-03-02T10:00:00Z");
    }
    let p2: Vec<(&str, &str)> = next.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (o, _) = go(&call("mail.list", &p2, None), &snap, &cat, &up).await;
    let (uids, next) = page(&o);
    assert_eq!(uids, [103, 102]);
    let next = next.expect("a next page");
    assert_eq!(next.get("before_uid").map(String::as_str), Some("102"));
    let p3: Vec<(&str, &str)> = next.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (o, _) = go(&call("mail.list", &p3, None), &snap, &cat, &up).await;
    let (uids, next) = page(&o);
    assert_eq!(uids, [101]);
    assert!(next.is_none());
    assert!(
        log.any(|l| l.ends_with("UID SEARCH UID 1:103")),
        "{:?}",
        log.lines()
    );
    assert!(log.any(|l| l.ends_with("UID FETCH 105,104 (UID FLAGS RFC822.SIZE ENVELOPE)")));
}

#[tokio::test]
async fn message_json_text_html_attachments_meta() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    let (status, v) = done(&o);
    assert_eq!(status, 200);
    assert_eq!(v["uid"], 104);
    assert_eq!(
        v["from"],
        serde_json::json!([{ "name": "Alice", "address": "alice@acme.com" }])
    );
    assert_eq!(v["to"][0]["address"], "bob@acme.com");
    assert_eq!(v["cc"][0]["address"], "carol@acme.com");
    assert_eq!(v["subject"], "Quartalsbericht Übersicht");
    assert_eq!(v["date"], "2026-03-02T10:00:00Z");
    assert_eq!(
        v["text"].as_str().unwrap().trim(),
        "Hello Bob, the report is attached."
    );
    assert!(v["html"].as_str().unwrap().contains("<b>report</b>"));
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(ATTACHMENT_B64)
        .unwrap();
    assert_eq!(
        v["attachments"],
        serde_json::json!([{ "name": "report.pdf", "type": "application/pdf", "size": decoded.len() }])
    );
    // No attachment content, in either form.
    let body = match &o {
        Outcome::Done { finished, .. } => String::from_utf8_lossy(&finished.body).into_owned(),
        _ => unreachable!(),
    };
    assert!(!body.contains(ATTACHMENT_B64));
    assert!(!body.contains("saiife-attachment-body"));
}

#[tokio::test]
async fn password_never_in_error_or_record() {
    let p = pki();
    let up = upstream(&p, Duration::from_secs(5));
    let cat = catalog_of(MANIFEST);
    // An IMAP server that echoes the login on a refusal.
    let (ip, _log) = imap_server(&p, Imap::EchoPassword).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let c = call("folders.list", &[], None);
    let (o, tr) = go(&c, &snap, &cat, &up).await;
    assert_eq!(failed(&o), "upstream: AUTHENTICATE: refused");
    assert_no_secret(&c, &snap, &tr, &o);
    // An SMTP server that puts the password in a reply that is shown.
    let (sp, _log) = smtp_server(&p, Smtp::EchoPassword).await;
    let snap = snapshot((sp, "implicit"), (1, "implicit"));
    let c = call(
        "mail.send",
        &[("to", "a@acme.com"), ("subject", "s")],
        Some("b"),
    );
    let (o, tr) = go(&c, &snap, &cat, &up).await;
    let r = failed(&o);
    assert!(r.contains("550") && r.contains("[MASKED]"), "{r}");
    assert!(r.len() <= 200);
    assert_no_secret(&c, &snap, &tr, &o);
}

#[tokio::test]
async fn mail_proxy_path_unknown_operation() {
    let p = pki();
    let (sp, slog) = smtp_server(&p, Smtp::Implicit).await;
    let (ip, ilog) = imap_server(&p, Imap::Implicit).await;
    let snap = snapshot((sp, "implicit"), (ip, "implicit"));
    let cat = catalog_of(MANIFEST);
    let up = upstream(&p, Duration::from_secs(5));
    for (method, path) in [
        ("POST", "/mail.send"),
        ("GET", "/folders.list"),
        ("GET", "/"),
    ] {
        let mut c = call("x", &[], None);
        c.op = OpRef::Proxy {
            method: method.into(),
            path: path.into(),
        };
        let (o, _) = go(&c, &snap, &cat, &up).await;
        assert_eq!(rule(&o), "unknown_operation", "{method} {path}");
    }
    assert_eq!(slog.conns.load(Ordering::SeqCst), 0);
    assert_eq!(ilog.conns.load(Ordering::SeqCst), 0);
}

#[test]
fn mail_manifest_shape() {
    assert!(Manifest::parse(MANIFEST).is_ok());
    let bad = [
        // A base_url.
        MANIFEST.replace(
            "transport = \"mail\"",
            "transport = \"mail\"\nbase_url = \"https://x.test\"",
        ),
        // Other hosts.
        MANIFEST.replace(
            "hosts = [\"{smtp_host}\", \"{imap_host}\"]",
            "hosts = [\"{smtp_host}\"]",
        ),
        // A method or path on an operation.
        MANIFEST.replace(
            "id = \"folders.list\"",
            "id = \"folders.list\"\nmethod = \"GET\"\npath = \"/f\"",
        ),
        // An operation that is not one of the four.
        MANIFEST.replace("id = \"folders.list\"", "id = \"mail.delete\""),
        // A write without a text body, a read with one.
        MANIFEST.replace("body = \"text\"", ""),
        MANIFEST.replace(
            "id = \"folders.list\"\ncapability = \"folders:read\"",
            "id = \"folders.list\"\nbody = \"text\"\ncapability = \"folders:read\"",
        ),
        // An auth other than basic.
        MANIFEST.replace(
            "auth = [{ kind = \"basic\" }]",
            "auth = [{ kind = \"bearer\", secret_field = \"token\" }]",
        ),
        // A host param without an anchored pattern.
        MANIFEST.replacen("pattern = '^[a-z0-9.-]+$'\n", "", 1),
        // Fixed headers.
        MANIFEST.replace(
            "transport = \"mail\"",
            "transport = \"mail\"\nheaders = { X = \"y\" }",
        ),
    ];
    for (i, text) in bad.iter().enumerate() {
        assert_ne!(text, MANIFEST, "case {i} did not change the manifest");
        assert!(Manifest::parse(text).is_err(), "case {i} parsed");
    }
}

#[test]
fn host_params_must_be_bare_hostnames() {
    let cat = catalog_of(MANIFEST);
    let mut snap = snapshot((1, "implicit"), (1, "implicit"));
    assert!(saiife_broker::catalog::validate(&snap.config, &cat).is_ok());
    let svc = snap.config.services.get_mut("mail").unwrap();
    svc.params.insert("imap_host".into(), "127.0.0.1".into());
    assert!(saiife_broker::catalog::validate(&snap.config, &cat).is_err());
}

#[test]
fn deep_bodystructure_refused_on_a_small_stack() {
    // 2 MiB, the stack of a tokio worker thread in the daemon (and set
    // explicitly, whatever RUST_MIN_STACK says). Without the depth guard
    // imap-proto's recursion over 1000 parentheses overflows it and aborts
    // the process (checked by hand); a smaller stack does not fit the
    // unoptimized pipeline itself.
    let h = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(Box::pin(async {
                let p = pki();
                let (ip, _log) = imap_server(&p, Imap::DeepNest).await;
                let snap = snapshot((1, "implicit"), (ip, "implicit"));
                let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
                let (o, tr) = Box::pin(go(
                    &c,
                    &snap,
                    &catalog_of(MANIFEST),
                    &upstream(&p, Duration::from_secs(5)),
                ))
                .await;
                let r = failed(&o).to_string();
                assert!(r.contains("nested too deep"), "{r}");
                assert!(!r.contains("BODYSTRUCTURE"), "no server text: {r}");
                assert_no_secret(&c, &snap, &tr, &o);
            }));
        })
        .unwrap();
    h.join().expect("the call fails cleanly");
}

#[tokio::test]
async fn mail_list_windows_over_5000_uids() {
    let p = pki();
    let (ip, log) = imap_server(&p, Imap::Big).await;
    let snap = snapshot((1, "implicit"), (ip, "implicit"));
    let up = upstream(&p, Duration::from_secs(10));
    let cat = catalog_of(MANIFEST);
    let page = |o: &Outcome| -> (Vec<u64>, Option<String>) {
        let (status, v) = done(o);
        assert_eq!(status, 200);
        let uids = v["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["uid"].as_u64().unwrap())
            .collect();
        let next = match o {
            Outcome::Done { next, .. } => next.as_ref().and_then(|n| n.get("before_uid").cloned()),
            _ => None,
        };
        (uids, next)
    };
    let searches = |log: &Log| -> Vec<String> {
        log.lines()
            .into_iter()
            .filter(|l| l.contains("UID SEARCH"))
            .collect()
    };
    // The newest page: one window.
    let (o, _) = go(
        &call("mail.list", &[("limit", "3")], None),
        &snap,
        &cat,
        &up,
    )
    .await;
    assert_eq!(page(&o), (vec![5000, 4999, 4998], Some("4998".into())));
    assert_eq!(searches(&log).len(), 1);
    assert!(
        searches(&log)[0].ends_with("UID SEARCH UID 4501:5000"),
        "{:?}",
        searches(&log)
    );
    // Unseen: windows down to UID 1 until two hits are found.
    let (o, _) = go(
        &call("mail.list", &[("unseen", "true"), ("limit", "2")], None),
        &snap,
        &cat,
        &up,
    )
    .await;
    assert_eq!(page(&o), (vec![4990, 7], Some("7".into())));
    let s = searches(&log);
    assert_eq!(s.len(), 1 + 10, "{s:?}");
    assert!(
        s.last().unwrap().ends_with("UID SEARCH UID 1:500 UNSEEN"),
        "{s:?}"
    );
    for l in &s {
        let range = l.split(' ').nth(4).unwrap();
        let (a, b) = range.split_once(':').unwrap();
        let (a, b): (u32, u32) = (a.parse().unwrap(), b.parse().unwrap());
        assert!(b >= a && b - a < 500, "{l}");
    }
    // The page below 7: the last unseen one, and no next page.
    let (o, _) = go(
        &call(
            "mail.list",
            &[("unseen", "true"), ("limit", "2"), ("before_uid", "7")],
            None,
        ),
        &snap,
        &cat,
        &up,
    )
    .await;
    assert_eq!(page(&o), (vec![3], None));
    // The UIDNEXT fallback was used, never a search of the whole folder.
    assert!(log.any(|l| l.ends_with("FETCH * (UID)")));
    assert!(!log.any(|l| l.ends_with("UID SEARCH ALL") || l.ends_with("UID SEARCH UNSEEN")));
}

#[tokio::test]
async fn mail_get_is_cut_to_max_response_bytes() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::Implicit).await;
    let mut snap = snapshot((1, "implicit"), (ip, "implicit"));
    let max = 400;
    snap.config
        .services
        .get_mut("mail")
        .unwrap()
        .limits
        .max_response_bytes = Some(max);
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let (o, _) = go(
        &c,
        &snap,
        &catalog_of(MANIFEST),
        &upstream(&p, Duration::from_secs(5)),
    )
    .await;
    match &o {
        Outcome::Done { finished, .. } => {
            assert!(
                finished.body.len() <= max as usize,
                "{}",
                finished.body.len()
            );
            assert!(!finished.truncated, "cut by mail.get, not by step 10");
            let v: serde_json::Value = serde_json::from_slice(&finished.body).unwrap();
            assert_eq!(v["truncated"], true);
            assert_eq!(v["uid"], 104);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn mail_get_cut_inside_the_password_leaks_no_prefix() {
    let p = pki();
    let (ip, _log) = imap_server(&p, Imap::SecretBody).await;
    let up = upstream(&p, Duration::from_secs(5));
    let cat = catalog_of(MANIFEST);
    let secret = pass();
    let c = call("mail.get", &[("folder", "INBOX"), ("uid", "104")], None);
    let mut lengths = std::collections::BTreeSet::new();
    // Limits that cut the text before, inside and after the password.
    for max in (400..900).step_by(2) {
        let mut snap = snapshot((1, "implicit"), (ip, "implicit"));
        snap.config
            .services
            .get_mut("mail")
            .unwrap()
            .limits
            .max_response_bytes = Some(max);
        let (o, tr) = go(&c, &snap, &cat, &up).await;
        let Outcome::Done { finished, .. } = &o else {
            panic!("{o:?}")
        };
        let out = String::from_utf8_lossy(&finished.body).into_owned();
        for n in 4..=secret.len() {
            assert!(
                !out.contains(&secret[..n]),
                "max {max} leaks {:?}: {out}",
                &secret[..n]
            );
        }
        let v: serde_json::Value = serde_json::from_slice(&finished.body).unwrap();
        lengths.insert(v["text"].as_str().map_or(0, str::len));
        assert_no_secret(&c, &snap, &tr, &o);
    }
    // The cut moved across the whole password.
    assert!(lengths.len() > 100, "{}", lengths.len());
}
