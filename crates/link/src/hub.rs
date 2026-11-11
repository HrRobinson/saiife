//! The hub client (plan 29, Task 9): one outbound WSS connection to the
//! hub, a machine-signed hello, up to [`MAX_SESSIONS`] sealed browser
//! sessions relayed to the daemon's `link.sock`, keepalive and reconnect
//! backoff.
//!
//! Everything a session carries after its handshake is sealed end to end
//! between the browser and this machine (plan 28 [`Channel`]). The hub sees
//! the machine id, the machine's public key, its challenge signature and
//! ciphertext; it can neither read nor forge a frame. Link holds the
//! session keys but never the machine key: the daemon signs
//! (`workspace.sign`).
//!
//! # Hub protocol v1
//!
//! URL: `wss://host[:port]/v1/link`. Only `wss://` (a `ws://` URL is a
//! configuration error, not a retry); the path must be `/v1/link`, and an
//! empty path (or `/`) means `/v1/link`. TLS with the ring provider and the
//! configured roots (production: the platform's), SNI = the URL's host,
//! ALPN `http/1.1`. Every message is a WebSocket text message holding one
//! JSON object; binary messages are ignored. `b64u` = base64url without
//! padding.
//!
//! Connection (the whole of it bounded by [`CONNECT_TIMEOUT`]):
//! - hub → link `{"t":"challenge","nonce":b64u}` (16..=64 bytes);
//! - link → hub `{"t":"hello","v":1,"machine_id","machine_pub",
//!   "challenge_sig"}`, `challenge_sig` = the machine key's signature
//!   (daemon `workspace.sign {purpose: "hub_hello"}`, domain
//!   `saiife_wire::seal::HUB_HELLO_DOMAIN`) over
//!   `seal::hub_hello_msg(nonce, machine_id)` = nonce ‖ machine_id (ASCII).
//!
//! One hub link per machine (v3.0): the hub routes sessions by
//! `machine_id`, and a second valid hello for the same `machine_id`
//! replaces the older connection (latest wins; the hub closes the old one),
//! so a reconnect after a network drop wins over a half-dead socket.
//!
//! Sessions (`S` is the hub's string id for one browser connection):
//! - hub → link `{"t":"open","session":S}`, `{"t":"msg","session":S,
//!   "data":b64u}`, `{"t":"close","session":S}`;
//! - link → hub `{"t":"msg","session":S,"data":b64u}`,
//!   `{"t":"close","session":S}`.
//!
//! An `open` beyond [`MAX_SESSIONS`] (or for a session that is open), or
//! over the rate ([`RATE_PER_SEC`] a second, bursts of [`RATE_BURST`]), is
//! answered `close`. A `msg` for an unknown session is dropped. A message
//! that is not one of the above, but names a session, closes that session;
//! one that names none is dropped. The link connection stays in every case.
//!
//! Inside `data`, per session (the browser ↔ machine handshake, plaintext
//! JSON, bounded by [`SESSION_HANDSHAKE_TIMEOUT`] from `open` to the
//! channel being ready; a session still in its handshake then is closed):
//! 1. browser → machine `{"t":"seal_hello","browser_eph":b64u,
//!    "device_id"|"pair_id"}`: exactly one of `device_id` (a paired
//!    device) and `pair_id` (an open pairing offer: a pairing-only
//!    session); a `seal_hello` over the rate ([`RATE_PER_SEC`] a second,
//!    bursts of [`RATE_BURST`], counted apart from `open`) closes its
//!    session before the daemon signs anything;
//! 2. machine → browser `{"t":"seal_hello","machine_eph":b64u,
//!    "session_id":b64u,"machine_sig":b64u}`, `machine_sig` = the machine
//!    key over `seal::machine_hello_msg(session_id, machine_eph, binding)`
//!    (domain `MACHINE_HELLO_DOMAIN`): the browser checks it against the
//!    `machine_pub` it paired with and its own device id or pair id;
//! 3. device sessions only: browser → machine `{"t":"seal_auth","sig":b64u}`,
//!    the device key over session_id ‖ machine_eph ‖ browser_eph (domain
//!    `HANDSHAKE_DOMAIN`), checked with the device's paired key.
//!
//! Then every `data` is one sealed message (u64 BE counter ‖ AES-256-GCM
//! ciphertext ‖ tag, plaintext ≤ 1 MiB). Plaintexts browser → machine:
//! - device session: `{"t":"frame","body","sig","touch"?}` (a signed frame,
//!   passed to the daemon as is with `via: "hub"` and the session's device
//!   as `channel_device`; link never reads `body`) and `{"t":"hello"}`;
//! - pairing session: `{"t":"pair","pair_id","device_pub","label","proof"}`
//!   (a `PairRequest`; `pair_id` must be the session's) and nothing else.
//!
//! Each gets one sealed answer, in order: `{"t":"result","ok":true,
//! "result":…}` (a frame's result; `workspace.hello`'s machine_id,
//! machine_pub, epoch, frame_version; a pairing's device_id and
//! short_code), or `{"t":"result","ok":false,"error":string,
//! "rule":string|null,"message":string}` (the daemon's refusal; `error:
//! "unreachable"` and `rule: null` when the daemon does not answer), the
//! shape of the local server's `/api/hello`, `/api/frame` and `/api/pair`.
//!
//! Anything else — a malformed or out-of-order handshake message, a failed
//! signature or seal, a daemon refusal during the handshake, a message
//! that does not open, a plaintext the session may not send — closes that
//! session (link → hub `close`); the link connection and the other
//! sessions go on. A session's messages are handled one at a time, at most
//! [`SESSION_QUEUE`] waiting; a session that floods is closed.
//!
//! Keepalive: a ping every `ws::PING_INTERVAL`; the connection is dropped
//! as soon as no pong came for `ws::PONG_TIMEOUT` (a deadline, not checked
//! only on the ping tick), on any WebSocket error, or when the hub closes,
//! and made again after [`Backoff`].
//!
//! Logs name what failed, never a session's contents, keys or signatures.

use crate::ws::{Message, WsClient, PING_INTERVAL, PONG_TIMEOUT};
use crate::{Daemon, HubConfig, HubOpts, LinkError, Rate};
use rustls::pki_types::ServerName;
use saiife_ipc::msg::{
    OP_WORKSPACE_FRAME, OP_WORKSPACE_HELLO, OP_WORKSPACE_PAIR_FINISH, OP_WORKSPACE_SIGN,
};
use saiife_wire::b64;
use saiife_wire::seal::{hub_hello_msg, Channel, MachineHandshake};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// The hub's path for machines.
pub const HUB_PATH: &str = "/v1/link";
/// Sealed sessions at once on one connection.
pub const MAX_SESSIONS: usize = 8;
/// TCP connect, TLS, the WebSocket handshake, the challenge and the hello.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// From `open` to a sealed channel.
pub const SESSION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Messages of one session waiting to be handled.
pub const SESSION_QUEUE: usize = 4;
/// Hub `open`s accepted a second, and (counted apart) `seal_hello`s: a
/// hostile hub cannot churn sessions into the daemon faster.
pub const RATE_PER_SEC: f64 = 10.0;
/// The burst the rate allows.
pub const RATE_BURST: f64 = 20.0;
/// A write to the hub that takes longer drops the connection.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Answers of all sessions waiting to be written.
const OUT_QUEUE: usize = 64;
/// Accepted challenge nonce sizes (the daemon's `workspace.sign` bound).
const NONCE_LEN: std::ops::RangeInclusive<usize> = 16..=64;

/// Reconnect delays: 1 s doubling to 60 s, ±20 % jitter; back to 1 s after
/// a connection that stayed up 60 s.
#[derive(Debug, Clone)]
pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Backoff {
        Backoff::new()
    }
}

impl Backoff {
    pub const INITIAL: Duration = Duration::from_secs(1);
    pub const MAX: Duration = Duration::from_secs(60);
    pub const RESET_AFTER: Duration = Duration::from_secs(60);
    pub const JITTER: f64 = 0.2;

    pub fn new() -> Backoff {
        Backoff {
            next: Backoff::INITIAL,
        }
    }

    /// The next delay. `rng` gives a number in `[0, 1]`; 0.5 is no jitter,
    /// 0 is −20 %, 1 is +20 %.
    pub fn next(&mut self, rng: &mut dyn FnMut() -> f64) -> Duration {
        let base = self.next;
        self.next = (base * 2).min(Backoff::MAX);
        let r = rng();
        let r = if r.is_finite() {
            r.clamp(0.0, 1.0)
        } else {
            0.5
        };
        base.mul_f64(1.0 + Backoff::JITTER * (2.0 * r - 1.0))
    }

    /// A connection ended after `d`: a long one resets the delay.
    pub fn connected_for(&mut self, d: Duration) {
        if d >= Backoff::RESET_AFTER {
            self.next = Backoff::INITIAL;
        }
    }
}

/// A uniform number in `[0, 1)` from the OS.
fn jitter() -> f64 {
    let mut b = [0u8; 8];
    if getrandom::fill(&mut b).is_err() {
        return 0.5;
    }
    (u64::from_le_bytes(b) >> 11) as f64 / (1u64 << 53) as f64
}

impl Default for HubOpts {
    fn default() -> HubOpts {
        HubOpts {
            ping_interval: PING_INTERVAL,
            pong_timeout: PONG_TIMEOUT,
            handshake_timeout: SESSION_HANDSHAKE_TIMEOUT,
            opens: Rate {
                per_sec: RATE_PER_SEC,
                burst: RATE_BURST,
            },
            seal_hellos: Rate {
                per_sec: RATE_PER_SEC,
                burst: RATE_BURST,
            },
        }
    }
}

/// A token bucket: `burst` tokens, refilled at `rate` a second.
#[derive(Debug)]
pub(crate) struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    pub(crate) fn new(r: Rate, now: Instant) -> Bucket {
        Bucket {
            rate: r.per_sec,
            burst: r.burst,
            tokens: r.burst,
            last: now,
        }
    }

    /// Takes a token at `now`; false when none is left.
    pub(crate) fn take_at(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = self.last.max(now);
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn take(&mut self) -> bool {
        self.take_at(Instant::now())
    }
}

/// The rate limits of one link, kept across reconnects.
struct Limits {
    opens: Bucket,
    seal_hellos: Arc<Mutex<Bucket>>,
}

/// Where the hub is, from its URL.
#[derive(Debug, Clone)]
pub struct HubTarget {
    /// For DNS and SNI (an IPv6 literal without brackets).
    pub host: String,
    pub port: u16,
    /// The `Host` header.
    pub host_header: String,
    server_name: ServerName<'static>,
}

/// Parses `wss://host[:port][/v1/link]`. `ws://`, another scheme, user
/// info, a query, a fragment or another path is a configuration error.
pub fn parse_url(url: &str) -> Result<HubTarget, String> {
    let lower = url.get(..6).map(str::to_ascii_lowercase);
    let rest = match lower.as_deref() {
        Some("wss://") => &url[6..],
        _ if url.to_ascii_lowercase().starts_with("ws://") => {
            return Err(format!(
                "the hub URL must use wss:// (got {url:?}; plain ws:// is not allowed)"
            ))
        }
        _ => {
            return Err(format!(
                "the hub URL must be wss://host[:port]{HUB_PATH}, got {url:?}"
            ))
        }
    };
    let (auth, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if !matches!(path, "" | "/" | HUB_PATH) {
        return Err(format!(
            "the hub URL's path must be {HUB_PATH} (got {path:?})"
        ));
    }
    let bad = || format!("the hub URL has no valid host[:port]: {url:?}");
    if auth.is_empty() || auth.contains('@') {
        return Err(bad());
    }
    let (host, port, v6) = if let Some(r) = auth.strip_prefix('[') {
        let (h, after) = r.split_once(']').ok_or_else(bad)?;
        match after {
            "" => (h, None, true),
            p => (h, Some(p.strip_prefix(':').ok_or_else(bad)?), true),
        }
    } else {
        match auth.split_once(':') {
            Some((h, p)) => (h, Some(p), false),
            None => (auth, None, false),
        }
    };
    let ok_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '.' || (v6 && c == ':');
    if host.is_empty() || !host.chars().all(ok_char) {
        return Err(bad());
    }
    let port = match port {
        None => 443,
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n != 0 && p.chars().all(|c| c.is_ascii_digit()) => n,
            _ => return Err(bad()),
        },
    };
    let server_name = ServerName::try_from(host.to_string()).map_err(|_| bad())?;
    let shown = if v6 {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let host_header = if port == 443 {
        shown
    } else {
        format!("{shown}:{port}")
    };
    Ok(HubTarget {
        host: host.to_string(),
        port,
        host_header,
        server_name,
    })
}

fn client_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig, String> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS setup: {e}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

type Ws = WsClient<TlsStream<TcpStream>>;

/// Connects to the hub and relays, forever. Returns only on a
/// configuration error (a bad URL).
pub async fn run(cfg: HubConfig, daemon: Daemon) -> Result<(), String> {
    let target = parse_url(&cfg.url)?;
    let tls = TlsConnector::from(Arc::new(client_config(cfg.roots)?));
    let opts = cfg.opts;
    let now = Instant::now();
    let mut limits = Limits {
        opens: Bucket::new(opts.opens, now),
        seal_hellos: Arc::new(Mutex::new(Bucket::new(opts.seal_hellos, now))),
    };
    let mut backoff = Backoff::new();
    loop {
        match connect(&target, cfg.connect, &tls, &daemon).await {
            Ok(ws) => {
                let up = Instant::now();
                eprintln!("saiife: workspace hub connected");
                let why = serve(ws, &daemon, &opts, &mut limits).await;
                backoff.connected_for(up.elapsed());
                eprintln!("saiife: warning: workspace hub connection ended: {why}");
            }
            Err(e) => eprintln!("saiife: warning: workspace hub: {e}"),
        }
        tokio::time::sleep(backoff.next(&mut jitter)).await;
    }
}

fn daemon_err(e: LinkError) -> String {
    match e {
        LinkError::Unreachable(m) => format!("daemon unreachable: {m}"),
        LinkError::Refused { error, rule, .. } => {
            format!("daemon refused ({error}, {})", rule.unwrap_or_default())
        }
    }
}

fn str_field(m: &Map<String, Value>, k: &str) -> Option<String> {
    m.get(k).and_then(Value::as_str).map(str::to_string)
}

/// TCP, TLS, WebSocket, challenge, hello; all within [`CONNECT_TIMEOUT`].
async fn connect(
    t: &HubTarget,
    addr: Option<SocketAddr>,
    tls: &TlsConnector,
    daemon: &Daemon,
) -> Result<Ws, String> {
    let go = async {
        let hello = daemon
            .call(OP_WORKSPACE_HELLO, Map::new())
            .await
            .map_err(daemon_err)?;
        let (Some(machine_id), Some(machine_pub)) = (
            str_field(&hello, "machine_id"),
            str_field(&hello, "machine_pub"),
        ) else {
            return Err("the daemon's hello has no machine id".to_string());
        };
        let tcp = match addr {
            Some(a) => TcpStream::connect(a).await,
            None => TcpStream::connect((t.host.as_str(), t.port)).await,
        }
        .map_err(|e| format!("cannot connect to {}: {e}", t.host_header))?;
        let _ = tcp.set_nodelay(true);
        let stream = tls
            .connect(t.server_name.clone(), tcp)
            .await
            .map_err(|e| format!("TLS with {}: {e}", t.host_header))?;
        let mut ws = WsClient::handshake(stream, &t.host_header, HUB_PATH, &[])
            .await
            .map_err(|e| e.to_string())?;
        let nonce = match ws.recv().await.map_err(|e| e.to_string())? {
            Message::Text(s) => parse_challenge(&s),
            _ => None,
        }
        .ok_or("the hub did not send a challenge")?;
        let data = hub_hello_msg(&nonce, &machine_id);
        let mut a = Map::new();
        a.insert("purpose".into(), "hub_hello".into());
        a.insert("data".into(), b64::enc(&data).into());
        let ans = daemon
            .call(OP_WORKSPACE_SIGN, a)
            .await
            .map_err(daemon_err)?;
        let sig = str_field(&ans, "sig").ok_or("the daemon's signature is missing")?;
        let hello = json!({
            "t": "hello", "v": 1, "machine_id": machine_id,
            "machine_pub": machine_pub, "challenge_sig": sig,
        });
        ws.send(Message::Text(hello.to_string()))
            .await
            .map_err(|e| e.to_string())?;
        Ok(ws)
    };
    tokio::time::timeout(CONNECT_TIMEOUT, go)
        .await
        .map_err(|_| "connecting to the hub timed out".to_string())?
}

/// `{"t":"challenge","nonce"}` -> the nonce.
fn parse_challenge(s: &str) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_str(s).ok()?;
    let m = v.as_object()?;
    if m.len() != 2 || m.get("t")?.as_str()? != "challenge" {
        return None;
    }
    let n = b64::dec(m.get("nonce")?.as_str()?).ok()?;
    NONCE_LEN.contains(&n.len()).then_some(n)
}

/// A hub message, parsed.
enum HubMsg {
    Open(String),
    Msg(String, Vec<u8>),
    Close(String),
}

/// `Err(Some(S))`: not a valid message, but it names session `S`.
fn parse_hub(s: &str) -> Result<HubMsg, Option<String>> {
    let Ok(Value::Object(m)) = serde_json::from_str::<Value>(s) else {
        return Err(None);
    };
    let session = m.get("session").and_then(Value::as_str).map(str::to_string);
    let Some(sid) = session.clone() else {
        return Err(None);
    };
    let keys = |want: &[&str]| m.len() == want.len() && want.iter().all(|k| m.contains_key(*k));
    match m.get("t").and_then(Value::as_str) {
        Some("open") if keys(&["t", "session"]) => Ok(HubMsg::Open(sid)),
        Some("close") if keys(&["t", "session"]) => Ok(HubMsg::Close(sid)),
        Some("msg") if keys(&["t", "session", "data"]) => {
            match m.get("data").and_then(Value::as_str).map(b64::dec) {
                Some(Ok(d)) => Ok(HubMsg::Msg(sid, d)),
                _ => Err(session),
            }
        }
        _ => Err(session),
    }
}

/// What a session task asks the connection to write.
enum Out {
    Msg {
        session: String,
        gen: u64,
        data: Vec<u8>,
    },
    Close {
        session: String,
        gen: u64,
    },
}

/// A session's task, aborted when its entry goes.
struct Session {
    gen: u64,
    tx: mpsc::Sender<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn send_json(ws: &mut Ws, v: Value) -> Result<(), String> {
    match tokio::time::timeout(SEND_TIMEOUT, ws.send(Message::Text(v.to_string()))).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("a write to the hub timed out".into()),
    }
}

fn close_msg(session: &str) -> Value {
    json!({"t": "close", "session": session})
}

/// Relays until the connection fails; returns why. Dropping `sessions`
/// aborts every session task (their daemon calls still hold their permits
/// until they end: see [`crate::daemon`]).
async fn serve(mut ws: Ws, daemon: &Daemon, opts: &HubOpts, limits: &mut Limits) -> String {
    let (out_tx, mut out_rx) = mpsc::channel::<Out>(OUT_QUEUE);
    let mut sessions: HashMap<String, Session> = HashMap::new();
    let mut gen: u64 = 0;
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + opts.ping_interval,
        opts.ping_interval,
    );
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    enum Ev {
        In(Result<Message, crate::ws::WsError>),
        Out(Out),
        Tick,
        PongDeadline,
    }
    loop {
        // Re-armed every turn from the last pong; `recv` notes pongs
        // without returning, so the deadline is checked again when it fires.
        let pong_deadline = tokio::time::Instant::from_std(ws.last_pong() + opts.pong_timeout);
        // `recv`, `mpsc::recv`, `tick` and `sleep_until` are cancel-safe;
        // writes happen outside the select.
        let ev = tokio::select! {
            m = ws.recv() => Ev::In(m),
            Some(o) = out_rx.recv() => Ev::Out(o),
            _ = tick.tick() => Ev::Tick,
            () = tokio::time::sleep_until(pong_deadline) => Ev::PongDeadline,
        };
        let r = match ev {
            Ev::In(Err(e)) => return e.to_string(),
            Ev::In(Ok(Message::Close(_))) => return "the hub closed the connection".into(),
            Ev::In(Ok(Message::Binary(_))) => Ok(()),
            Ev::In(Ok(Message::Text(t))) => match parse_hub(&t) {
                Ok(HubMsg::Open(s)) => {
                    if sessions.contains_key(&s) {
                        sessions.remove(&s);
                        send_json(&mut ws, close_msg(&s)).await
                    } else if sessions.len() >= MAX_SESSIONS || !limits.opens.take() {
                        send_json(&mut ws, close_msg(&s)).await
                    } else {
                        gen += 1;
                        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
                        let task = tokio::spawn(session(
                            daemon.clone(),
                            rx,
                            out_tx.clone(),
                            s.clone(),
                            gen,
                            SessionCfg {
                                handshake_timeout: opts.handshake_timeout,
                                seal_hellos: Arc::clone(&limits.seal_hellos),
                            },
                        ));
                        sessions.insert(s, Session { gen, tx, task });
                        Ok(())
                    }
                }
                Ok(HubMsg::Msg(s, data)) => match sessions.get(&s) {
                    // Unknown session: dropped.
                    None => Ok(()),
                    Some(x) => match x.tx.try_send(data) {
                        Ok(()) => Ok(()),
                        // Flooding (or already ending): closed.
                        Err(_) => {
                            sessions.remove(&s);
                            send_json(&mut ws, close_msg(&s)).await
                        }
                    },
                },
                Ok(HubMsg::Close(s)) => {
                    sessions.remove(&s);
                    Ok(())
                }
                Err(Some(s)) => {
                    if sessions.remove(&s).is_some() {
                        send_json(&mut ws, close_msg(&s)).await
                    } else {
                        Ok(())
                    }
                }
                Err(None) => Ok(()),
            },
            Ev::Out(Out::Msg { session, gen, data }) => {
                if sessions.get(&session).is_some_and(|x| x.gen == gen) {
                    let v = json!({"t": "msg", "session": session, "data": b64::enc(&data)});
                    send_json(&mut ws, v).await
                } else {
                    Ok(())
                }
            }
            Ev::Out(Out::Close { session, gen }) => {
                if sessions.get(&session).is_some_and(|x| x.gen == gen) {
                    sessions.remove(&session);
                    send_json(&mut ws, close_msg(&session)).await
                } else {
                    Ok(())
                }
            }
            Ev::PongDeadline => {
                if Instant::now() >= ws.last_pong() + opts.pong_timeout {
                    return "no pong from the hub".into();
                }
                Ok(())
            }
            Ev::Tick => match tokio::time::timeout(SEND_TIMEOUT, ws.ping()).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("a ping to the hub timed out".into()),
            },
        };
        if let Err(e) = r {
            return e;
        }
    }
}

/// Why a session closed (never sent; the hub only learns `close`).
type Closed = ();

/// What a session task needs from its connection.
struct SessionCfg {
    handshake_timeout: Duration,
    seal_hellos: Arc<Mutex<Bucket>>,
}

/// One session: handshake, then sealed request/answer pairs, then `close`.
async fn session(
    daemon: Daemon,
    mut rx: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<Out>,
    id: String,
    gen: u64,
    cfg: SessionCfg,
) {
    let _ = run_session(&daemon, &mut rx, &out, &id, gen, &cfg).await;
    let _ = out.send(Out::Close { session: id, gen }).await;
}

/// A sealed session's state.
struct Sealed {
    channel: Channel,
    /// The offer of a pairing session.
    pair_id: Option<String>,
}

async fn run_session(
    daemon: &Daemon,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    out: &mpsc::Sender<Out>,
    id: &str,
    gen: u64,
    cfg: &SessionCfg,
) -> Result<(), Closed> {
    let send = |data: Vec<u8>| {
        out.send(Out::Msg {
            session: id.to_string(),
            gen,
            data,
        })
    };
    let hs = handshake(daemon, rx, &send, &cfg.seal_hellos);
    let mut s = tokio::time::timeout(cfg.handshake_timeout, hs)
        .await
        .map_err(|_| ())??;
    while let Some(sealed) = rx.recv().await {
        let plain = s.channel.open(&sealed).map_err(|_| ())?;
        let answer = handle(daemon, &s, &plain).await?;
        let sealed = s
            .channel
            .seal(answer.to_string().as_bytes())
            .map_err(|_| ())?;
        send(sealed).await.map_err(|_| ())?;
    }
    Ok(())
}

/// A JSON object with exactly `required` (strings) and at most `optional`.
fn object(
    bytes: &[u8],
    t: &str,
    required: &[&str],
    optional: &[&str],
) -> Result<Map<String, Value>, Closed> {
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(bytes) else {
        return Err(());
    };
    let ok = m.get("t").and_then(Value::as_str) == Some(t)
        && required
            .iter()
            .all(|k| m.get(*k).is_some_and(Value::is_string))
        && m.keys()
            .all(|k| k == "t" || required.contains(&k.as_str()) || optional.contains(&k.as_str()));
    if ok {
        Ok(m)
    } else {
        Err(())
    }
}

fn get_str<'a>(m: &'a Map<String, Value>, k: &str) -> Result<&'a str, Closed> {
    m.get(k).and_then(Value::as_str).ok_or(())
}

/// Steps 1–3 of the session handshake (see the module docs).
async fn handshake<F, Fut>(
    daemon: &Daemon,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    send: &F,
    seal_hellos: &Mutex<Bucket>,
) -> Result<Sealed, Closed>
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<(), mpsc::error::SendError<Out>>>,
{
    let first = rx.recv().await.ok_or(())?;
    let m = object(
        &first,
        "seal_hello",
        &["browser_eph"],
        &["device_id", "pair_id"],
    )?;
    let browser_eph = b64::dec_n::<65>(get_str(&m, "browser_eph")?).map_err(|_| ())?;
    let opt = |k: &str| -> Result<Option<String>, Closed> {
        match m.get(k) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(()),
        }
    };
    let (device_id, pair_id) = (opt("device_id")?, opt("pair_id")?);
    // Over the rate: closed before the daemon is asked to sign.
    if !seal_hellos.lock().is_ok_and(|mut b| b.take()) {
        return Err(());
    }
    let mh = MachineHandshake::new(&ring::rand::SystemRandom::new()).map_err(|_| ())?;
    let mut data = mh.session_id().to_vec();
    data.extend_from_slice(&mh.eph_pub());
    let mut a = Map::new();
    a.insert("purpose".into(), "seal".into());
    a.insert("data".into(), b64::enc(&data).into());
    match (&device_id, &pair_id) {
        (Some(d), None) => a.insert("device_id".into(), d.clone().into()),
        (None, Some(p)) => a.insert("pair_id".into(), p.clone().into()),
        _ => return Err(()),
    };
    let ans = daemon.call(OP_WORKSPACE_SIGN, a).await.map_err(|_| ())?;
    let machine_sig = get_str(&ans, "sig")?.to_string();
    let device_pub = match device_id {
        Some(_) => Some(b64::dec_n::<65>(get_str(&ans, "device_pub")?).map_err(|_| ())?),
        None => None,
    };
    let reply = json!({
        "t": "seal_hello",
        "machine_eph": b64::enc(&mh.eph_pub()),
        "session_id": b64::enc(&mh.session_id()),
        "machine_sig": machine_sig,
    });
    send(reply.to_string().into_bytes()).await.map_err(|_| ())?;
    let channel = match device_pub {
        None => mh.finish(&browser_eph, None, None).map_err(|_| ())?,
        Some(pk) => {
            let third = rx.recv().await.ok_or(())?;
            let m = object(&third, "seal_auth", &["sig"], &[])?;
            let sig = b64::dec_n::<64>(get_str(&m, "sig")?).map_err(|_| ())?;
            let ch = mh
                .finish(&browser_eph, Some(&sig), Some(&pk))
                .map_err(|_| ())?;
            // The daemon's key is for the device the browser named.
            if ch.device_id() != device_id.as_deref() {
                return Err(());
            }
            ch
        }
    };
    Ok(Sealed { channel, pair_id })
}

/// A daemon answer as the browser reads it.
fn result(r: Result<Value, LinkError>) -> Value {
    match r {
        Ok(v) => json!({"t": "result", "ok": true, "result": v}),
        Err(LinkError::Refused {
            error,
            rule,
            message,
        }) => json!({"t": "result", "ok": false, "error": error, "rule": rule, "message": message}),
        Err(LinkError::Unreachable(_)) => json!({
            "t": "result", "ok": false, "error": "unreachable", "rule": null,
            "message": "the saiife daemon is not reachable",
        }),
    }
}

/// One opened plaintext -> its answer, or `Err` to close the session.
async fn handle(daemon: &Daemon, s: &Sealed, plain: &[u8]) -> Result<Value, Closed> {
    let t = match serde_json::from_slice::<Value>(plain) {
        Ok(Value::Object(m)) => m.get("t").and_then(Value::as_str).map(str::to_string),
        _ => None,
    };
    match (t.as_deref(), s.channel.device_id()) {
        (Some("frame"), Some(dev)) => {
            let mut m = object(plain, "frame", &["body", "sig"], &["touch"])?;
            m.remove("t");
            m.insert("via".into(), "hub".into());
            m.insert("channel_device".into(), dev.into());
            let r = daemon.call(OP_WORKSPACE_FRAME, m).await;
            Ok(result(
                r.map(|m| m.get("result").cloned().unwrap_or(Value::Null)),
            ))
        }
        (Some("hello"), Some(_)) => {
            object(plain, "hello", &[], &[])?;
            let r = daemon.call(OP_WORKSPACE_HELLO, Map::new()).await;
            Ok(result(r.map(|mut m| {
                m.remove("id");
                m.remove("ok");
                Value::Object(m)
            })))
        }
        (Some("pair"), None) => {
            let mut m = object(
                plain,
                "pair",
                &["pair_id", "device_pub", "label", "proof"],
                &[],
            )?;
            if s.pair_id.as_deref() != Some(get_str(&m, "pair_id")?) {
                return Err(());
            }
            m.remove("t");
            let r = daemon.call(OP_WORKSPACE_PAIR_FINISH, m).await;
            Ok(result(r.map(
                |m| json!({"device_id": m.get("device_id"), "short_code": m.get("short_code")}),
            )))
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let t = parse_url("wss://hub.test/v1/link").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("hub.test", 443));
        assert_eq!(t.host_header, "hub.test");
        let t = parse_url("wss://hub.test:8443").unwrap();
        assert_eq!((t.port, t.host_header.as_str()), (8443, "hub.test:8443"));
        let t = parse_url("WSS://[::1]:9/").unwrap();
        assert_eq!(
            (t.host.as_str(), t.host_header.as_str()),
            ("::1", "[::1]:9")
        );
        for bad in [
            "ws://hub.test/v1/link",
            "https://hub.test/v1/link",
            "wss://hub.test/v2/link",
            "wss://hub.test/v1/link?x=1",
            "wss://u@hub.test/v1/link",
            "wss://hub.test:0/v1/link",
            "wss://hub.test:+1/v1/link",
            "wss://:443/v1/link",
            "wss://hub test/v1/link",
            "wss://",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hub_messages() {
        assert!(matches!(
            parse_hub(r#"{"t":"open","session":"a"}"#),
            Ok(HubMsg::Open(s)) if s == "a"
        ));
        assert!(matches!(
            parse_hub(r#"{"t":"msg","session":"a","data":"AAE"}"#),
            Ok(HubMsg::Msg(s, d)) if s == "a" && d == [0, 1]
        ));
        assert!(
            matches!(parse_hub(r#"{"t":"msg","session":"a","data":"=="}"#), Err(Some(s)) if s == "a")
        );
        assert!(matches!(
            parse_hub(r#"{"t":"open","session":"a","x":1}"#),
            Err(Some(_))
        ));
        assert!(matches!(parse_hub(r#"{"t":"open"}"#), Err(None)));
        assert!(matches!(parse_hub("nope"), Err(None)));
    }

    #[test]
    fn bucket_allows_the_burst_then_the_rate() {
        let t0 = Instant::now();
        let r = Rate {
            per_sec: RATE_PER_SEC,
            burst: RATE_BURST,
        };
        let mut b = Bucket::new(r, t0);
        let taken = (0..30).filter(|_| b.take_at(t0)).count();
        assert_eq!(taken, RATE_BURST as usize);
        // 100 ms later: one more (10 a second).
        assert!(b.take_at(t0 + Duration::from_millis(100)));
        assert!(!b.take_at(t0 + Duration::from_millis(100)));
        // A long pause refills to the burst, never beyond.
        let later = t0 + Duration::from_secs(3600);
        let taken = (0..30).filter(|_| b.take_at(later)).count();
        assert_eq!(taken, RATE_BURST as usize);
        // A clock that goes back adds nothing.
        assert!(!b.take_at(t0));
    }

    #[test]
    fn challenges() {
        let ok = format!(r#"{{"t":"challenge","nonce":"{}"}}"#, b64::enc(&[7u8; 16]));
        assert_eq!(parse_challenge(&ok), Some(vec![7u8; 16]));
        let short = format!(r#"{{"t":"challenge","nonce":"{}"}}"#, b64::enc(&[7u8; 15]));
        assert_eq!(parse_challenge(&short), None);
        let long = format!(r#"{{"t":"challenge","nonce":"{}"}}"#, b64::enc(&[7u8; 65]));
        assert_eq!(parse_challenge(&long), None);
    }
}
