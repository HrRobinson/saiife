//! The hub client against a fake hub: an rcgen CA and a leaf for
//! `hub.test`, a `TlsAcceptor` on 127.0.0.1:0, Task 8's `server_side`, and
//! `HubConfig::connect` in place of DNS. The fake hub plays the browser with
//! plan 28's `TestBrowserEnd`; the daemon is the in-process one of
//! `common`.
#![cfg(unix)]

mod common;

use common::{args, control, me, world, World};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use saiife_ipc::msg::{
    LINK_SOCKET_NAME, OP_WORKSPACE_PAIR_BEGIN, OP_WORKSPACE_PAIR_CONFIRM, OP_WORKSPACE_PAIR_FINISH,
};
use saiife_link::hub::{self, Backoff, HUB_PATH, MAX_SESSIONS};
use saiife_link::ws::server_side::{accept, AcceptOpts, ServerWs};
use saiife_link::ws::Message;
use saiife_link::{Daemon, HubConfig, HubOpts, Rate, MAX_DAEMON_CALLS};
use saiife_wire::frame::{Frame, SignedFrame};
use saiife_wire::seal::{BrowserChannel, SealBinding, TestBrowserEnd};
use saiife_wire::sig::{verify_p256_domain, TestDevice};
use saiife_wire::{b64, pair};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;

const WAIT: Duration = Duration::from_secs(10);

/// A CA and its root store.
struct Ca {
    issuer: CertifiedIssuer<'static, KeyPair>,
    roots: RootCertStore,
}

fn ca() -> Ca {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let issuer = CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(issuer.der().clone()).unwrap();
    Ca { issuer, roots }
}

/// One link connection as the fake hub sees it after the hello.
struct Conn {
    ws: ServerWs<TlsStream<TcpStream>>,
    path: String,
    sni: Option<String>,
    alpn: Option<Vec<u8>>,
    nonce: Vec<u8>,
    hello: Value,
    /// Every `data` relayed either way, decoded.
    relayed: Arc<Mutex<Vec<Vec<u8>>>>,
}

struct FakeHub {
    addr: SocketAddr,
    /// TCP connections accepted.
    attempts: Arc<AtomicUsize>,
    conns: mpsc::Receiver<Conn>,
}

impl FakeHub {
    /// A hub whose leaf for `hub.test` is signed by `signer`.
    async fn start(signer: &Ca) -> FakeHub {
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["hub.test".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &signer.issuer)
            .unwrap();
        let leaf_der: CertificateDer<'static> = leaf.der().clone();
        let key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf_der], PrivateKeyDer::Pkcs8(key))
        .unwrap();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (tx, conns) = mpsc::channel(4);
        let n = Arc::clone(&attempts);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                n.fetch_add(1, Ordering::SeqCst);
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let (_, sc) = tls.get_ref();
                    let sni = sc.server_name().map(str::to_string);
                    let alpn = sc.alpn_protocol().map(<[u8]>::to_vec);
                    let Ok((mut ws, path)) = accept(tls, AcceptOpts::default()).await else {
                        return;
                    };
                    let mut nonce = vec![0u8; 32];
                    getrandom::fill(&mut nonce).unwrap();
                    let ch = json!({"t": "challenge", "nonce": b64::enc(&nonce)});
                    ws.send(Message::Text(ch.to_string())).await.unwrap();
                    let Ok(Message::Text(h)) = ws.recv().await else {
                        return;
                    };
                    let _ = tx
                        .send(Conn {
                            ws,
                            path,
                            sni,
                            alpn,
                            nonce,
                            hello: serde_json::from_str(&h).unwrap(),
                            relayed: Arc::default(),
                        })
                        .await;
                });
            }
        });
        FakeHub {
            addr,
            attempts,
            conns,
        }
    }

    async fn next(&mut self) -> Conn {
        tokio::time::timeout(WAIT, self.conns.recv())
            .await
            .expect("no link connection")
            .unwrap()
    }

    fn config(&self, roots: &RootCertStore, opts: HubOpts) -> HubConfig {
        HubConfig {
            url: "wss://hub.test/v1/link".into(),
            roots: roots.clone(),
            connect: Some(self.addr),
            opts,
        }
    }
}

impl Conn {
    async fn send(&mut self, v: Value) {
        self.ws.send(Message::Text(v.to_string())).await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let m = tokio::time::timeout(WAIT, self.ws.recv())
            .await
            .expect("link sent nothing")
            .unwrap();
        let Message::Text(t) = m else {
            panic!("not text: {m:?}");
        };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["t"] == "msg" {
            let d = b64::dec(v["data"].as_str().unwrap()).unwrap();
            self.relayed.lock().unwrap().push(d);
        }
        v
    }

    async fn open(&mut self, s: &str) {
        self.send(json!({"t": "open", "session": s})).await;
    }

    async fn send_raw(&mut self, s: &str, data: &[u8]) {
        self.relayed.lock().unwrap().push(data.to_vec());
        self.send(json!({"t": "msg", "session": s, "data": b64::enc(data)}))
            .await;
    }

    async fn send_data(&mut self, s: &str, v: Value) {
        self.send_raw(s, v.to_string().as_bytes()).await;
    }

    /// The next message must be a `msg` for `s`.
    async fn from(&mut self, s: &str) -> Vec<u8> {
        let v = self.recv().await;
        assert_eq!(v["t"], "msg", "{v}");
        assert_eq!(v["session"], s, "{v}");
        b64::dec(v["data"].as_str().unwrap()).unwrap()
    }

    async fn expect_close(&mut self, s: &str) {
        let v = self.recv().await;
        assert_eq!(v, json!({"t": "close", "session": s}));
    }

    /// Nothing arrives for a moment.
    async fn quiet(&mut self) {
        let r = tokio::time::timeout(Duration::from_millis(300), self.ws.recv()).await;
        assert!(r.is_err(), "unexpected: {r:?}");
    }

    /// The machine's seal_hello for `binding` on session `s`, started with
    /// `be`; returns (machine_eph, session_id, machine_sig).
    async fn seal_hello(
        &mut self,
        s: &str,
        be: &TestBrowserEnd<'_>,
        binding: &SealBinding,
    ) -> ([u8; 65], [u8; 16], [u8; 64]) {
        self.open(s).await;
        let mut h = json!({"t": "seal_hello", "browser_eph": b64::enc(&be.eph_pub())});
        match binding {
            SealBinding::Device(d) => h["device_id"] = d.clone().into(),
            SealBinding::Pair(p) => h["pair_id"] = p.clone().into(),
        }
        self.send_data(s, h).await;
        let r: Value = serde_json::from_slice(&self.from(s).await).unwrap();
        assert_eq!(r["t"], "seal_hello", "{r}");
        assert_eq!(r.as_object().unwrap().len(), 4, "{r}");
        (
            b64::dec_n::<65>(r["machine_eph"].as_str().unwrap()).unwrap(),
            b64::dec_n::<16>(r["session_id"].as_str().unwrap()).unwrap(),
            b64::dec_n::<64>(r["machine_sig"].as_str().unwrap()).unwrap(),
        )
    }

    /// A full device session on `s`.
    async fn device_session(&mut self, w: &World, s: &str, d: &TestDevice) -> BrowserChannel {
        let be = TestBrowserEnd::new(Some(d));
        let binding = SealBinding::Device(d.device_id());
        let (meph, sid, msig) = self.seal_hello(s, &be, &binding).await;
        let sig = be.sign_handshake(&sid, &meph).unwrap();
        self.send_data(s, json!({"t": "seal_auth", "sig": b64::enc(&sig)}))
            .await;
        be.finish(&meph, &sid, &msig, &machine_pub(w), &binding)
            .unwrap()
    }

    /// A pairing session on `s` for `pair_id`.
    async fn pair_session(&mut self, w: &World, s: &str, pair_id: &str) -> BrowserChannel {
        let be = TestBrowserEnd::new(None);
        let binding = SealBinding::Pair(pair_id.into());
        let (meph, sid, msig) = self.seal_hello(s, &be, &binding).await;
        be.finish(&meph, &sid, &msig, &machine_pub(w), &binding)
            .unwrap()
    }

    /// One sealed request and its sealed answer.
    async fn ask(&mut self, s: &str, bc: &mut BrowserChannel, v: Value) -> Value {
        let sealed = bc.seal(v.to_string().as_bytes()).unwrap();
        self.send_raw(s, &sealed).await;
        let a = self.from(s).await;
        serde_json::from_slice(&bc.open(&a).unwrap()).unwrap()
    }

    /// One sealed message that must close the session.
    async fn refused(&mut self, s: &str, bc: &mut BrowserChannel, v: Value) {
        let sealed = bc.seal(v.to_string().as_bytes()).unwrap();
        self.send_raw(s, &sealed).await;
        self.expect_close(s).await;
    }
}

fn machine_pub(w: &World) -> [u8; 65] {
    b64::dec_n::<65>(w.ctx.workspace.hello()["machine_pub"].as_str().unwrap()).unwrap()
}

fn frame_for(w: &World, d: &TestDevice, action: &str) -> SignedFrame {
    let h = w.ctx.workspace.hello();
    let now = saiife_daemon::workspace::now_secs();
    let mut n = [0u8; 16];
    getrandom::fill(&mut n).unwrap();
    d.frame(&Frame {
        v: 1,
        machine_id: h["machine_id"].as_str().unwrap().into(),
        epoch: h["epoch"].as_str().unwrap().into(),
        device_id: d.device_id(),
        action: action.into(),
        args: Default::default(),
        nonce: b64::enc(&n),
        issued_at: now,
        expires_at: now + 60,
    })
}

fn frame_msg(sf: &SignedFrame) -> Value {
    json!({"t": "frame", "body": sf.body, "sig": sf.sig})
}

/// An open offer: (pair_id, secret).
async fn offer(w: &World) -> (String, [u8; 32]) {
    let b = control(w, OP_WORKSPACE_PAIR_BEGIN, json!({"label": "phone"})).await;
    assert_eq!(b["ok"], true, "{b}");
    let (pair_id, secret, _, _) = pair::parse_fragment(b["fragment"].as_str().unwrap()).unwrap();
    (pair_id, secret)
}

fn pair_request(pair_id: &str, secret: &[u8; 32], d: &TestDevice) -> Value {
    let pk = d.public_raw();
    json!({
        "t": "pair",
        "pair_id": pair_id,
        "device_pub": b64::enc(&pk),
        "label": "phone",
        "proof": b64::enc(&pair::proof(secret, pair_id, &pk)),
    })
}

/// A device paired over link.sock and confirmed on the control side.
async fn paired(w: &World) -> TestDevice {
    let (pair_id, secret) = offer(w).await;
    let d = TestDevice::generate();
    let mut req = pair_request(&pair_id, &secret, &d);
    req.as_object_mut().unwrap().remove("t");
    let daemon = Daemon::new(w.run.clone(), me());
    daemon
        .call(OP_WORKSPACE_PAIR_FINISH, args(req))
        .await
        .unwrap();
    let c = control(
        w,
        OP_WORKSPACE_PAIR_CONFIRM,
        json!({"pair_id": pair_id, "accept": true}),
    )
    .await;
    assert_eq!(c["ok"], true, "{c}");
    d
}

/// A world, a fake hub and the link connected to it.
async fn up() -> (World, FakeHub, Conn) {
    let (w, hub, conn, _) = up_with(HubOpts::default()).await;
    (w, hub, conn)
}

/// [`up`] with `opts`; also the link's `Daemon` (its call counters).
async fn up_with(opts: HubOpts) -> (World, FakeHub, Conn, Daemon) {
    let w = world().await;
    let ca = ca();
    let mut hub = FakeHub::start(&ca).await;
    let daemon = Daemon::new(w.run.clone(), me());
    tokio::spawn(hub::run(hub.config(&ca.roots, opts), daemon.clone()));
    let conn = hub.next().await;
    (w, hub, conn, daemon)
}

/// No rate limit worth the name.
const UNLIMITED: Rate = Rate {
    per_sec: 1e9,
    burst: 1e9,
};

#[tokio::test]
async fn hello_is_signed_by_the_machine_key() {
    // No device yet: the personal broker's user may pair, so it may connect.
    let (w, _hub, c) = up().await;
    assert_eq!(c.path, HUB_PATH);
    assert_eq!(c.sni.as_deref(), Some("hub.test"));
    assert_eq!(c.alpn.as_deref(), Some(&b"http/1.1"[..]));
    let h = c.hello.as_object().unwrap();
    assert_eq!(h.len(), 5, "{h:?}");
    assert_eq!(h["t"], "hello");
    assert_eq!(h["v"], 1);
    let mid = w.ctx.workspace.machine_id();
    assert_eq!(h["machine_id"], mid.as_str());
    let mpub = b64::dec_n::<65>(h["machine_pub"].as_str().unwrap()).unwrap();
    assert_eq!(mpub, machine_pub(&w));
    let sig = b64::dec_n::<64>(h["challenge_sig"].as_str().unwrap()).unwrap();
    assert!(verify_p256_domain(
        &mpub,
        saiife_wire::seal::HUB_HELLO_DOMAIN,
        &saiife_wire::seal::hub_hello_msg(&c.nonce, &mid),
        &sig
    ));
    // Not over another nonce.
    let mut other = vec![0u8; 32];
    other.extend_from_slice(mid.as_bytes());
    assert!(!verify_p256_domain(
        &mpub,
        saiife_wire::seal::HUB_HELLO_DOMAIN,
        &other,
        &sig
    ));
}

/// The device session of `sealed_frame_roundtrip`; returns the relayed data.
async fn overview_over_the_hub() -> Vec<Vec<u8>> {
    let (w, _hub, mut c) = up().await;
    let d = paired(&w).await;
    let mut bc = c.device_session(&w, "s1", &d).await;
    let a = c
        .ask("s1", &mut bc, frame_msg(&frame_for(&w, &d, "box.overview")))
        .await;
    assert_eq!(a["t"], "result", "{a}");
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"]["boxes"].as_array().unwrap().len(), 4, "{a}");
    let a = c.ask("s1", &mut bc, json!({"t": "hello"})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(
        a["result"]["machine_id"],
        w.ctx.workspace.machine_id().as_str()
    );
    assert!(a["result"].get("id").is_none(), "{a}");
    // A refusal keeps its rule (box.land is touch-level).
    let a = c
        .ask("s1", &mut bc, frame_msg(&frame_for(&w, &d, "box.land")))
        .await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["rule"], "touch_required", "{a}");
    let r = c.relayed.lock().unwrap().clone();
    r
}

#[tokio::test]
async fn sealed_frame_roundtrip() {
    let relayed = overview_over_the_hub().await;
    assert!(relayed.len() >= 9, "{}", relayed.len());
}

#[tokio::test]
async fn hub_sees_no_plaintext() {
    let relayed = overview_over_the_hub().await;
    for d in &relayed {
        let s = String::from_utf8_lossy(d);
        for needle in ["box.overview", "b-run", "boxes", "frame", "machine_id"] {
            assert!(!s.contains(needle), "{needle} in {s}");
        }
    }
}

#[tokio::test]
async fn pairing_channel_is_pair_only() {
    let (w, _hub, mut c) = up().await;
    let known = paired(&w).await;
    let sf = frame_for(&w, &known, "box.overview");
    let (pair_id, secret) = offer(&w).await;

    let mut bc = c.pair_session(&w, "p1", &pair_id).await;
    c.refused("p1", &mut bc, frame_msg(&sf)).await;
    let mut bc = c.pair_session(&w, "p2", &pair_id).await;
    c.refused("p2", &mut bc, json!({"t": "hello"})).await;
    // A PairRequest for another offer than the session's.
    let (other_id, other_secret) = offer(&w).await;
    let d = TestDevice::generate();
    let mut bc = c.pair_session(&w, "p3", &pair_id).await;
    c.refused("p3", &mut bc, pair_request(&other_id, &other_secret, &d))
        .await;
    // The pairing itself.
    let mut bc = c.pair_session(&w, "p4", &pair_id).await;
    let a = c
        .ask("p4", &mut bc, pair_request(&pair_id, &secret, &d))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["result"]["device_id"], d.device_id(), "{a}");
    assert_eq!(a["result"]["short_code"].as_str().unwrap().len(), 7, "{a}");
    // A device channel takes no pair message.
    let mut bc = c.device_session(&w, "d1", &known).await;
    c.refused("d1", &mut bc, pair_request(&pair_id, &secret, &d))
        .await;
    // Nothing above reached the daemon as a frame: `sf` still runs once.
    let mut bc = c.device_session(&w, "d2", &known).await;
    let a = c.ask("d2", &mut bc, frame_msg(&sf)).await;
    assert_eq!(a["ok"], true, "{a}");
}

#[tokio::test]
async fn bad_seal_drops_the_session_not_the_link() {
    let (w, hub, mut c) = up().await;
    let d = paired(&w).await;
    let other = TestDevice::generate();

    // seal_auth signed by another key.
    let be = TestBrowserEnd::new(Some(&other));
    let (meph, sid, _) = c
        .seal_hello("s1", &be, &SealBinding::Device(d.device_id()))
        .await;
    let sig = be.sign_handshake(&sid, &meph).unwrap();
    c.send_data("s1", json!({"t": "seal_auth", "sig": b64::enc(&sig)}))
        .await;
    c.expect_close("s1").await;
    // Not JSON, then both bindings, then an unknown device, then an extra key.
    let be = TestBrowserEnd::new(None);
    let eph = b64::enc(&be.eph_pub());
    for (s, first) in [
        ("s2", b"not json".to_vec()),
        (
            "s3",
            json!({"t": "seal_hello", "browser_eph": eph, "device_id": d.device_id(), "pair_id": "x"})
                .to_string()
                .into_bytes(),
        ),
        (
            "s4",
            json!({"t": "seal_hello", "browser_eph": eph, "device_id": other.device_id()})
                .to_string()
                .into_bytes(),
        ),
        (
            "s5",
            json!({"t": "seal_hello", "browser_eph": eph, "device_id": d.device_id(), "x": 1})
                .to_string()
                .into_bytes(),
        ),
        (
            "s6",
            json!({"t": "seal_hello", "browser_eph": "AAAA", "device_id": d.device_id()})
                .to_string()
                .into_bytes(),
        ),
    ] {
        c.open(s).await;
        c.send_raw(s, &first).await;
        c.expect_close(s).await;
    }
    // Unsealed data after the handshake, and a tampered sealed message.
    let mut bc = c.device_session(&w, "s7", &d).await;
    c.send_raw("s7", br#"{"t":"hello"}"#).await;
    c.expect_close("s7").await;
    let _ = c.device_session(&w, "s8", &d).await;
    let mut bad = bc.seal(br#"{"t":"hello"}"#).unwrap();
    bad[10] ^= 1;
    c.send_raw("s8", &bad).await;
    c.expect_close("s8").await;
    // Hub junk: dropped; a msg for an unknown session: dropped; a bad msg
    // for an open session closes it.
    c.send(json!({"t": "nope"})).await;
    c.ws.send(Message::Text("[".into())).await.unwrap();
    c.send_raw("ghost", b"x").await;
    c.quiet().await;
    c.open("s9").await;
    c.send(json!({"t": "msg", "session": "s9", "data": "!!"}))
        .await;
    c.expect_close("s9").await;

    // The link connection is the same and still serves.
    let mut bc = c.device_session(&w, "ok", &d).await;
    let a = c
        .ask("ok", &mut bc, frame_msg(&frame_for(&w, &d, "box.overview")))
        .await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(hub.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ninth_session_is_refused() {
    // s1..s7 never finish their handshake: a long timeout keeps them open
    // however slow the machine is.
    let opts = HubOpts {
        handshake_timeout: Duration::from_secs(600),
        ..HubOpts::default()
    };
    let (w, _hub, mut c, _) = up_with(opts).await;
    let d = paired(&w).await;
    for i in 0..MAX_SESSIONS {
        c.open(&format!("s{i}")).await;
    }
    c.open("s9").await;
    c.expect_close("s9").await;
    // An open that is already open closes it.
    c.open("s0").await;
    c.expect_close("s0").await;
    // One slot is free again (s0): a session runs in it.
    let mut bc = c.device_session(&w, "s10", &d).await;
    let a = c.ask("s10", &mut bc, json!({"t": "hello"})).await;
    assert_eq!(a["ok"], true, "{a}");
    c.open("s11").await;
    c.expect_close("s11").await;
    // The hub closes one: its slot frees.
    c.send(json!({"t": "close", "session": "s1"})).await;
    let mut bc = c.device_session(&w, "s12", &d).await;
    let a = c.ask("s12", &mut bc, json!({"t": "hello"})).await;
    assert_eq!(a["ok"], true, "{a}");
}

#[tokio::test]
async fn hub_frame_carries_channel_device() {
    let (w, _hub, mut c) = up().await;
    let a_dev = paired(&w).await;
    let b_dev = paired(&w).await;
    let mut bc = c.device_session(&w, "a", &a_dev).await;
    let a = c
        .ask(
            "a",
            &mut bc,
            frame_msg(&frame_for(&w, &b_dev, "box.overview")),
        )
        .await;
    assert_eq!(a["ok"], false, "{a}");
    assert_eq!(a["error"], "forbidden", "{a}");
    assert_eq!(a["rule"], "wrong_device", "{a}");
    // B's own channel runs it.
    let mut bc = c.device_session(&w, "b", &b_dev).await;
    let a = c
        .ask(
            "b",
            &mut bc,
            frame_msg(&frame_for(&w, &b_dev, "box.overview")),
        )
        .await;
    assert_eq!(a["ok"], true, "{a}");
}

#[tokio::test]
async fn seal_signature_names_the_device() {
    let (w, _hub, mut c) = up().await;
    let a_dev = paired(&w).await;
    let b_dev = paired(&w).await;
    for (s, expect) in [
        ("s1", SealBinding::Device(b_dev.device_id())),
        ("s2", SealBinding::Pair("p-any".into())),
    ] {
        let be = TestBrowserEnd::new(Some(&a_dev));
        let (meph, sid, msig) = c
            .seal_hello(s, &be, &SealBinding::Device(a_dev.device_id()))
            .await;
        assert!(be
            .finish(&meph, &sid, &msig, &machine_pub(&w), &expect)
            .is_err());
    }
}

#[tokio::test]
async fn ws_url_is_refused() {
    let w = world().await;
    for url in [
        "ws://hub.test/v1/link",
        "https://hub.test/v1/link",
        "wss://hub.test/v2/link",
    ] {
        let cfg = HubConfig {
            url: url.into(),
            roots: RootCertStore::empty(),
            connect: None,
            opts: HubOpts::default(),
        };
        let r = tokio::time::timeout(
            Duration::from_secs(1),
            hub::run(cfg, Daemon::new(w.run.clone(), me())),
        )
        .await
        .expect("a config error returns at once");
        assert!(r.is_err(), "{url}");
    }
    let e = hub::parse_url("ws://hub.test/v1/link").unwrap_err();
    assert!(e.contains("wss://"), "{e}");
}

#[test]
fn reconnect_backs_off() {
    let mut b = Backoff::new();
    let mut mid = || 0.5;
    let got: Vec<u64> = (0..9)
        .map(|_| b.next(&mut mid).as_millis() as u64)
        .collect();
    assert_eq!(
        got,
        [1000, 2000, 4000, 8000, 16000, 32000, 60000, 60000, 60000]
    );
    b.connected_for(Duration::from_secs(59));
    assert_eq!(b.next(&mut mid), Duration::from_secs(60));
    b.connected_for(Duration::from_secs(60));
    assert_eq!(b.next(&mut mid), Duration::from_secs(1));
    assert_eq!(b.next(&mut mid), Duration::from_secs(2));
    // Jitter: ±20 %.
    let mut b = Backoff::new();
    assert_eq!(b.next(&mut || 0.0), Duration::from_millis(800));
    assert_eq!(b.next(&mut || 1.0), Duration::from_millis(2400));
}

#[tokio::test]
async fn reconnects_after_the_hub_closes() {
    let (_w, mut hub, mut c) = up().await;
    let t = Instant::now();
    c.ws.send(Message::Close(Some(1000))).await.unwrap();
    let c2 = hub.next().await;
    // After the first backoff (1 s ± 20 %).
    assert!(
        t.elapsed() >= Duration::from_millis(750),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(c2.hello["t"], "hello");
    assert_eq!(hub.attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn hub_cert_must_chain() {
    let w = world().await;
    let (trusted, other) = (ca(), ca());
    let mut hub = FakeHub::start(&other).await;
    tokio::spawn(hub::run(
        hub.config(&trusted.roots, HubOpts::default()),
        Daemon::new(w.run.clone(), me()),
    ));
    let t = Instant::now();
    // A first attempt, then one more after the backoff; never a hello.
    while hub.attempts.load(Ordering::SeqCst) < 2 {
        assert!(t.elapsed() < WAIT, "no retry");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        t.elapsed() >= Duration::from_millis(750),
        "{:?}",
        t.elapsed()
    );
    assert!(hub.conns.try_recv().is_err(), "a connection got through");
}

/// A session that never finishes its handshake is closed after the
/// handshake timeout; the link and its other sessions go on.
#[tokio::test]
async fn unfinished_handshake_is_closed_after_the_timeout() {
    let opts = HubOpts {
        handshake_timeout: Duration::from_secs(2),
        ..HubOpts::default()
    };
    let (w, hub, mut c, _) = up_with(opts).await;
    let d = paired(&w).await;
    let mut ready = c.device_session(&w, "ready", &d).await;
    // One sends nothing; one stops after the machine's seal_hello.
    let t = Instant::now();
    c.open("idle").await;
    let be = TestBrowserEnd::new(Some(&d));
    let _ = c
        .seal_hello("half", &be, &SealBinding::Device(d.device_id()))
        .await;
    let mut closed = vec![
        c.recv().await["session"].as_str().unwrap().to_string(),
        c.recv().await["session"].as_str().unwrap().to_string(),
    ];
    closed.sort();
    assert_eq!(closed, ["half", "idle"]);
    assert!(
        t.elapsed() >= Duration::from_millis(1900),
        "{:?}",
        t.elapsed()
    );
    // The ready session still answers, on the same connection.
    let a = c.ask("ready", &mut ready, json!({"t": "hello"})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(hub.attempts.load(Ordering::SeqCst), 1);
}

/// A hub that stops answering pings is dropped at the pong deadline, not
/// at the next ping tick, and the link connects again.
#[tokio::test]
async fn missing_pong_closes_and_reconnects() {
    let opts = HubOpts {
        // Far beyond the test: only the pong deadline can end the link.
        ping_interval: Duration::from_secs(60),
        pong_timeout: Duration::from_millis(500),
        ..HubOpts::default()
    };
    let (_w, mut hub, mut c, _) = up_with(opts).await;
    let t = Instant::now();
    // The fake hub sees the link go.
    let end = tokio::time::timeout(WAIT, c.ws.recv())
        .await
        .expect("still up");
    assert!(matches!(end, Ok(Message::Close(_)) | Err(_)), "{end:?}");
    let c2 = hub.next().await;
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    assert_eq!(c2.hello["t"], "hello");
    assert_eq!(hub.attempts.load(Ordering::SeqCst), 2);
}

/// A hub that answers pings keeps the link past many pong timeouts.
#[tokio::test]
async fn answered_pings_keep_the_link() {
    let opts = HubOpts {
        ping_interval: Duration::from_millis(100),
        pong_timeout: Duration::from_millis(600),
        ..HubOpts::default()
    };
    let (_w, mut hub, mut c, _) = up_with(opts).await;
    let pongs = tokio::spawn(async move {
        let mut n = 0usize;
        while let Ok(f) = c.ws.recv_frame().await {
            if f.opcode == 0x9 {
                n += 1;
                if c.ws.send_frame(true, 0xA, &f.payload).await.is_err() {
                    break;
                }
            }
        }
        n
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(hub.attempts.load(Ordering::SeqCst), 1);
    assert!(hub.conns.try_recv().is_err(), "the link reconnected");
    assert!(!pongs.is_finished(), "the link closed");
    pongs.abort();
}

/// `open`s over the rate are answered `close`, even with free slots.
#[tokio::test]
async fn opens_over_the_rate_are_closed() {
    let opts = HubOpts {
        opens: Rate {
            per_sec: 0.001,
            burst: 2.0,
        },
        handshake_timeout: Duration::from_secs(600),
        ..HubOpts::default()
    };
    let (_w, hub, mut c, _) = up_with(opts).await;
    c.open("a").await;
    c.open("b").await;
    c.quiet().await;
    c.open("c").await;
    c.expect_close("c").await;
    // A free slot does not refill the bucket.
    c.send(json!({"t": "close", "session": "a"})).await;
    c.open("d").await;
    c.expect_close("d").await;
    assert_eq!(hub.attempts.load(Ordering::SeqCst), 1);
}

/// A `seal_hello` over the rate closes its session before the daemon
/// signs; the link and the sessions already sealed go on.
#[tokio::test]
async fn seal_hellos_over_the_rate_close_the_session() {
    let opts = HubOpts {
        opens: UNLIMITED,
        seal_hellos: Rate {
            per_sec: 0.001,
            burst: 1.0,
        },
        ..HubOpts::default()
    };
    let (w, hub, mut c, _) = up_with(opts).await;
    let d = paired(&w).await;
    let mut ready = c.device_session(&w, "ready", &d).await;
    let be = TestBrowserEnd::new(Some(&d));
    c.open("over").await;
    c.send_data(
        "over",
        json!({"t": "seal_hello", "browser_eph": b64::enc(&be.eph_pub()), "device_id": d.device_id()}),
    )
    .await;
    c.expect_close("over").await;
    let a = c.ask("ready", &mut ready, json!({"t": "hello"})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(hub.attempts.load(Ordering::SeqCst), 1);
}

/// A `link.sock` in a dir of its own that forwards each connection to
/// `w`'s after `delay`: a slow daemon.
async fn slow_link_sock(w: &World, delay: Duration) -> tempfile::TempDir {
    let dir = common::scratch();
    let l = tokio::net::UnixListener::bind(dir.path().join(LINK_SOCKET_NAME)).unwrap();
    let real = w.run.join(LINK_SOCKET_NAME);
    tokio::spawn(async move {
        while let Ok((mut a, _)) = l.accept().await {
            let real = real.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if let Ok(mut b) = tokio::net::UnixStream::connect(&real).await {
                    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                }
            });
        }
    });
    dir
}

/// A hub churning sessions (open, seal_hello, close soon after, so each
/// session task is aborted while its daemon call runs) against a slow
/// daemon never has more than `MAX_DAEMON_CALLS` daemon calls in flight,
/// and the link stays up.
#[tokio::test]
async fn session_churn_stays_within_the_daemon_permits() {
    let opts = HubOpts {
        opens: UNLIMITED,
        seal_hellos: UNLIMITED,
        ..HubOpts::default()
    };
    let w = world().await;
    let slow = slow_link_sock(&w, Duration::from_millis(200)).await;
    let ca = ca();
    let mut hub = FakeHub::start(&ca).await;
    let daemon = Daemon::new(slow.path().to_path_buf(), me());
    tokio::spawn(hub::run(hub.config(&ca.roots, opts), daemon.clone()));
    let mut c = hub.next().await;
    let d = paired(&w).await;
    let be = TestBrowserEnd::new(Some(&d));
    let hello = json!({
        "t": "seal_hello", "browser_eph": b64::enc(&be.eph_pub()), "device_id": d.device_id(),
    });
    // 500 sessions, a full table at a time: each batch's calls start, then
    // the hub closes the batch while they wait on the slow daemon.
    for batch in 0..500 / MAX_SESSIONS + 1 {
        let ids: Vec<String> = (0..MAX_SESSIONS).map(|i| format!("c{batch}-{i}")).collect();
        for s in &ids {
            c.open(s).await;
            c.send_data(s, hello.clone()).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        for s in &ids {
            c.send(json!({"t": "close", "session": s})).await;
        }
    }
    // Whatever the link still sends for them; then quiet.
    loop {
        match tokio::time::timeout(Duration::from_secs(1), c.ws.recv()).await {
            Err(_) => break,
            Ok(Ok(Message::Text(_))) => {}
            Ok(other) => panic!("the link went: {other:?}"),
        }
    }
    let peak = daemon.peak_calls();
    assert!(peak >= 1, "no daemon call was made");
    assert!(peak <= MAX_DAEMON_CALLS, "{peak} calls at once");
    // Still the same connection, and it serves.
    let mut bc = c.device_session(&w, "after", &d).await;
    let a = c.ask("after", &mut bc, json!({"t": "hello"})).await;
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(hub.attempts.load(Ordering::SeqCst), 1);
}
