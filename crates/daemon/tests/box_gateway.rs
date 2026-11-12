//! The per-box gateway (plan 38, Task 6; spec §7.4): the allow-listed
//! CONNECT proxy on `vsock.sock_5001` and the model port on
//! `vsock.sock_5002`, driven through the real listeners in a tempdir box
//! directory. The resolver is a fixed map and every upstream is a loopback
//! echo server: no test touches the network, and no VM is ever started.
#![cfg(all(unix, feature = "fake-vmm", debug_assertions))]

use saiife_audit::{ChainWriter, WriterOptions};
use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::guest::fake::FakeGuest;
use saiife_boxes::guest::GuestLink;
use saiife_boxes::manager::{Manager, ManagerInit, SpawnArgs};
use saiife_boxes::store::Store;
use saiife_boxes::template::{self, EgressRule, Size};
use saiife_boxes::vmm::fake::FakeVmm;
use saiife_boxes::BoxId;
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::vmm::VmHooks;
use saiife_boxproto::ports;
use saiife_broker::pipeline::{LockScope, Lockdown};
use saiife_daemon::box_gateway::{GatewayConfig, GatewayHooks, Limits, Resolve};
use saiife_daemon::box_ops;
use saiife_daemon::ops::{Ctx, CtxInit, Mode};
use saiife_daemon::writer::{self, WriterConfig};
use saiife_policy::{Directory, Fsync};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};

const OK_200: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const T0: u64 = 1_000_000;

fn scratch() -> tempfile::TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    std::fs::create_dir_all(&base).unwrap();
    tempfile::Builder::new()
        .prefix("g")
        .tempdir_in(base)
        .unwrap()
}

/// A fixed name -> answers map; a missing name has no answers.
struct FakeResolve(HashMap<String, Vec<SocketAddr>>);

impl Resolve for FakeResolve {
    fn lookup(
        &self,
        host: &str,
        _port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + '_>> {
        let v = self.0.get(host).cloned().unwrap_or_default();
        Box::pin(async move { Ok(v) })
    }
}

/// A loopback echo upstream: echoes until EOF, then closes its side.
async fn echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    a
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

struct W {
    ctx: Arc<Ctx>,
    gw: Arc<GatewayHooks>,
    id: BoxId,
    session: String,
    paths: BoxPaths,
    clock: Arc<AtomicU64>,
    audit: PathBuf,
    _tmp: tempfile::TempDir,
}

struct Opts {
    limits: Limits,
    loopback: bool,
    names: Vec<(&'static str, Vec<SocketAddr>)>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            limits: Limits::default(),
            loopback: true,
            names: Vec::new(),
        }
    }
}

fn host_facts() -> HostFacts {
    HostFacts {
        mem_total_mib: 8192 + 2 * capacity::charge_mib(&Size::default()),
        mem_avail_mib: 4096,
        threads: 12,
        disk_free_mib: 1024 * 1024,
        cpu_pct: None,
    }
}

fn rule(h: &str, port: u16) -> EgressRule {
    EgressRule {
        host: h.into(),
        port,
    }
}

async fn world(o: Opts) -> W {
    let tmp = scratch();
    let audit = tmp.path().join("audit");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let cw = ChainWriter::open(
        &audit,
        WriterOptions {
            mode: "locked".into(),
            saiife: "test".into(),
            key: None,
        },
    )
    .unwrap();
    let cfg = WriterConfig {
        checkpoint_every: 1000,
        checkpoint_interval: Duration::from_secs(900),
        fsync: Fsync::Always,
    };
    let (handle, _join) = writer::spawn(cw, cfg, None).unwrap();
    let dirs: Arc<dyn Directory + Send + Sync> = Arc::new(
        saiife_policy::FixedDirectory::from_text("saiife:x:999:999::/var/lib/saiife:/bin/sh\n", ""),
    );
    let mut t = template::builtin().remove(0);
    t.name = "egress-test".into();
    t.egress = vec![
        rule("example.test", 443),
        rule("*.crates.test", 443),
        rule("*.com", 443),
        rule("*.private.test", 443),
    ];
    let host = host_facts();
    let guest: Arc<dyn GuestLink> = Arc::new(FakeGuest::new());
    let mgr = Manager::open(ManagerInit {
        store: Store::open(box_ops::dir_in(&state)).unwrap(),
        vmm: Arc::new(FakeVmm::new()),
        guest,
        templates: vec![t],
        host: Arc::new(move || host),
        clock: Arc::new(|| T0),
    })
    .unwrap()
    .manager;
    let rec = mgr
        .spawn(&SpawnArgs {
            template: "egress-test".into(),
            repo: "shop".into(),
            repo_dir: None,
            task: String::new(),
            start: saiife_wire::source::Start::Queue,
            owner_uid: 2000,
            repo_image: None,
            base_manifest: None,
        })
        .unwrap();
    let base = CtxInit::minimal(handle, cfg, dirs, &state);
    let ctx = Arc::new(Ctx::new(CtxInit {
        audit_dir: audit.clone(),
        own_user: "saiife".into(),
        own_uid: 999,
        mode: Mode::Locked,
        box_manager: Some(Arc::new(mgr)),
        ..base
    }));
    let clock = Arc::new(AtomicU64::new(T0));
    let c = Arc::clone(&clock);
    let resolve = Arc::new(FakeResolve(
        o.names
            .into_iter()
            .map(|(n, a)| (n.to_string(), a))
            .collect(),
    ));
    let gw = GatewayHooks::new(
        Arc::clone(&ctx),
        tokio::runtime::Handle::current(),
        resolve,
        GatewayConfig {
            limits: o.limits,
            allow_loopback_for_tests: o.loopback,
            clock: Arc::new(move || c.load(Ordering::SeqCst)),
        },
    );
    let dir = tmp.path().join("b");
    std::fs::create_dir(&dir).unwrap();
    let paths = BoxPaths::new(dir);
    gw.before_boot(&rec.id, &paths).unwrap();
    W {
        ctx,
        gw,
        id: rec.id,
        session: rec.session,
        paths,
        clock,
        audit,
        _tmp: tmp,
    }
}

/// Everything until EOF (or a reset after the answer), within 15 s.
async fn read_all(s: &mut UnixStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(15), async {
        let mut b = [0u8; 4096];
        loop {
            match s.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&b[..n]),
            }
        }
    })
    .await;
    out
}

fn status(answer: &[u8]) -> u16 {
    let t = String::from_utf8_lossy(answer);
    t.strip_prefix("HTTP/1.1 ")
        .and_then(|r| r.get(..3))
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status in {t:?}"))
}

impl W {
    async fn dial(&self, port: u32) -> UnixStream {
        UnixStream::connect(self.paths.vsock_port(port))
            .await
            .unwrap()
    }

    /// Send `head` and read the whole (refusal) answer.
    async fn ask(&self, head: &[u8]) -> (u16, String) {
        let mut s = self.dial(ports::EGRESS).await;
        let _ = s.write_all(head).await;
        let a = read_all(&mut s).await;
        (status(&a), String::from_utf8_lossy(&a).into_owned())
    }

    async fn connect(&self, target: &str) -> (u16, String) {
        self.ask(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
    }

    /// An open tunnel to `target` (asserts the 200).
    async fn tunnel(&self, target: &str) -> UnixStream {
        let mut s = self.dial(ports::EGRESS).await;
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut b = vec![0u8; OK_200.len()];
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b, OK_200, "{}", String::from_utf8_lossy(&b));
        s
    }

    fn all_records(&self) -> Vec<Value> {
        let mut files: Vec<_> = std::fs::read_dir(&self.audit)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        files
            .iter()
            .flat_map(|f| {
                std::fs::read_to_string(f)
                    .unwrap()
                    .lines()
                    .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn records(&self, kind: &str) -> Vec<Value> {
        self.all_records()
            .into_iter()
            .filter(|r| r["kind"] == kind)
            .collect()
    }

    /// The `kind` records once there are at least `n` (waits up to 10 s).
    async fn wait_records(&self, kind: &str, n: usize) -> Vec<Value> {
        let t0 = Instant::now();
        loop {
            let r = self.records(kind);
            if r.len() >= n || t0.elapsed() > Duration::from_secs(10) {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn lockdown(&self, scope: LockScope) {
        self.ctx
            .lockdown
            .set(Some(Lockdown {
                scope,
                reason: "test".into(),
                by_uid: 0,
                since: "2026-11-12T00:00:00.000Z".into(),
            }))
            .unwrap();
    }
}

fn extra(r: &Value, k: &str) -> Value {
    r[k].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_tunnels_bytes_both_ways() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        ..Opts::default()
    })
    .await;
    let mut s = w.dial(ports::EGRESS).await;
    // Bytes after the head in the same write go upstream after the 200.
    s.write_all(b"CONNECT Example.Test.:443 HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic c2VjcmV0\r\n\r\nearly")
        .await
        .unwrap();
    let mut b = vec![0u8; OK_200.len() + 5];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b[..OK_200.len()], OK_200);
    assert_eq!(&b[OK_200.len()..], b"early");
    s.write_all(b"hello world").await.unwrap();
    let mut b = [0u8; 11];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"hello world");
    s.shutdown().await.unwrap();
    assert!(read_all(&mut s).await.is_empty());
    let recs = w.wait_records("egress", 1).await;
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!(extra(r, "box"), w.id.as_str());
    assert_eq!(extra(r, "session"), w.session.as_str());
    assert_eq!(extra(r, "dest_host"), "example.test");
    assert_eq!(extra(r, "port"), 443);
    assert_eq!(extra(r, "addr"), up.to_string());
    assert_eq!(extra(r, "bytes_up"), 16);
    assert_eq!(extra(r, "bytes_down"), 16);
    assert_eq!(extra(r, "outcome"), "closed");
    assert!(extra(r, "ms").is_u64());
    // Never the head or its headers.
    let text = serde_json::to_string(&w.all_records()).unwrap();
    assert!(!text.contains("c2VjcmV0"), "{text}");
    assert!(!text.contains("Proxy-Authorization"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_allowed_is_403_and_audited() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("other.test", vec![up])],
        ..Opts::default()
    })
    .await;
    let (code, body) = w.connect("other.test:443").await;
    assert_eq!(code, 403);
    assert!(
        body.contains("other.test:443 is not in this box's allow-list"),
        "{body}"
    );
    let recs = w.wait_records("egress_denied", 1).await;
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(extra(r, "box"), w.id.as_str());
    assert_eq!(extra(r, "dest_host"), "other.test");
    assert_eq!(extra(r, "port"), 443);
    assert_eq!(extra(r, "reason"), "not_allowed");
    assert!(w.records("egress").is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wildcard_rules() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![
            ("a.crates.test", vec![up]),
            ("a.b.crates.test", vec![up]),
            ("crates.test", vec![up]),
            ("evilcrates.test", vec![up]),
            ("a.com", vec![up]),
        ],
        ..Opts::default()
    })
    .await;
    drop(w.tunnel("a.crates.test:443").await);
    drop(w.tunnel("a.b.crates.test:443").await);
    assert_eq!(w.connect("crates.test:443").await.0, 403);
    assert_eq!(w.connect("evilcrates.test:443").await.0, 403);
    // A `*.com` rule allows nothing.
    assert_eq!(w.connect("a.com:443").await.0, 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn port_must_match() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        ..Opts::default()
    })
    .await;
    let (code, body) = w.connect("example.test:80").await;
    assert_eq!(code, 403);
    assert!(body.contains("example.test:80 is not in this box's allow-list"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_answers_are_refused() {
    let names = vec![
        ("a.private.test", vec![sa("127.0.0.1:443")]),
        ("b.private.test", vec![sa("10.0.0.5:443")]),
        ("c.private.test", vec![sa("[::1]:443")]),
        ("d.private.test", vec![sa("[::ffff:192.168.1.1]:443")]),
        ("e.private.test", vec![sa("100.64.0.1:443")]),
        ("f.private.test", vec![sa("[fe80::1]:443")]),
    ];
    let hosts: Vec<_> = names.iter().map(|(n, _)| *n).collect();
    let w = world(Opts {
        names,
        loopback: false,
        ..Opts::default()
    })
    .await;
    for h in &hosts {
        let (code, body) = w.connect(&format!("{h}:443")).await;
        assert_eq!(code, 403, "{h}");
        assert!(
            body.contains(&format!("{h} resolves to a private address")),
            "{body}"
        );
    }
    let recs = w.wait_records("egress_denied", hosts.len()).await;
    assert!(recs.iter().all(|r| r["reason"] == "private_address"));
    assert_eq!(recs.len(), hosts.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_answers_are_refused() {
    let w = world(Opts {
        names: vec![(
            "m.private.test",
            vec![sa("8.8.8.8:443"), sa("10.0.0.5:443")],
        )],
        loopback: false,
        ..Opts::default()
    })
    .await;
    let (code, body) = w.connect("m.private.test:443").await;
    assert_eq!(code, 403);
    assert!(body.contains("m.private.test resolves to a private address"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_answers_is_502() {
    let w = world(Opts::default()).await;
    let (code, body) = w.connect("example.test:443").await;
    assert_eq!(code, 502);
    assert!(body.contains("example.test did not resolve"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ip_literal_is_refused() {
    let up = echo().await;
    let w = world(Opts::default()).await;
    for t in [
        up.to_string(),
        "127.0.0.1:443".into(),
        "[::1]:443".into(),
        "2130706433:443".into(),
        "0x7f.1:443".into(),
        "127.1:443".into(),
    ] {
        let (code, body) = w.connect(&t).await;
        assert_eq!(code, 403, "{t}: {body}");
        assert!(body.contains("IP literals are refused"), "{t}: {body}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_is_refused() {
    let w = world(Opts::default()).await;
    let (code, body) = w
        .ask(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await;
    assert_eq!(code, 403);
    assert!(
        body.contains("only CONNECT to allowed hosts: plain http is not available in boxes"),
        "{body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_heads_are_400() {
    let w = world(Opts::default()).await;
    for h in [
        &b"CONNECT example.test:443 HTTP/1.1\n\n"[..],
        b"CONNECT example.test:443 HTTP/1.1\r\nX: a\r\n b\r\n\r\n",
        b"CONNECT example.test:0 HTTP/1.1\r\n\r\n",
        b"CONNECT example.test:65536 HTTP/1.1\r\n\r\n",
        b"CONNECT example.test:+443 HTTP/1.1\r\n\r\n",
        b"CONNECT example.test HTTP/1.1\r\n\r\n",
        b"CONNECT -bad.test:443 HTTP/1.1\r\n\r\n",
        b"CONNECT ex\0ample.test:443 HTTP/1.1\r\n\r\n",
        b"CONNECT ex\xc3\xa9.test:443 HTTP/1.1\r\n\r\n",
        b"CONNECT example.test:443 HTTP/2.0\r\n\r\n",
    ] {
        let (code, body) = w.ask(h).await;
        assert_eq!(code, 400, "{:?}: {body}", String::from_utf8_lossy(h));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_head_is_refused() {
    let w = world(Opts::default()).await;
    let mut h = b"CONNECT example.test:443 HTTP/1.1\r\nX-Pad: ".to_vec();
    h.extend(std::iter::repeat_n(b'a', 9000));
    h.extend_from_slice(b"\r\n\r\n");
    let (code, body) = w.ask(&h).await;
    assert_eq!(code, 400);
    assert!(body.contains("request head too large"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_head_times_out() {
    let w = world(Opts {
        limits: Limits {
            head_secs: 1,
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    let mut s = w.dial(ports::EGRESS).await;
    let t0 = Instant::now();
    s.write_all(b"CONNECT exa").await.unwrap();
    // Trickling does not extend the deadline.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let _ = s.write_all(b"m").await;
    }
    let a = read_all(&mut s).await;
    assert_eq!(status(&a), 408, "{}", String::from_utf8_lossy(&a));
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denied_records_are_rate_limited() {
    let w = world(Opts::default()).await;
    for _ in 0..5 {
        assert_eq!(w.connect("other.test:443").await.0, 403);
    }
    // A different host is its own key.
    assert_eq!(w.connect("another.test:443").await.0, 403);
    let recs = w.wait_records("egress_denied", 2).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let recs2 = w.records("egress_denied");
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(recs2.len(), 2, "{recs2:?}");
    assert!(recs.iter().all(|r| r.get("suppressed").is_none()));
    w.clock.fetch_add(60_000, Ordering::SeqCst);
    assert_eq!(w.connect("other.test:443").await.0, 403);
    let recs = w.wait_records("egress_denied", 3).await;
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[2]["dest_host"], "other.test");
    assert_eq!(recs[2]["suppressed"], 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lockdown_refuses_new_tunnels() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        ..Opts::default()
    })
    .await;
    w.lockdown(LockScope::Connectors);
    let (code, _) = w.connect("example.test:443").await;
    assert_eq!(code, 503);
    let recs = w.wait_records("egress_denied", 1).await;
    assert_eq!(recs[0]["reason"], "lockdown");
    w.ctx.lockdown.set(None).unwrap();
    drop(w.tunnel("example.test:443").await);
    w.lockdown(LockScope::All);
    assert_eq!(w.connect("example.test:443").await.0, 503);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lockdown_closes_open_tunnels() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        ..Opts::default()
    })
    .await;
    let mut s = w.tunnel("example.test:443").await;
    w.lockdown(LockScope::Connectors);
    let t0 = Instant::now();
    let _ = read_all(&mut s).await;
    assert!(t0.elapsed() < Duration::from_secs(6), "{:?}", t0.elapsed());
    let recs = w.wait_records("egress", 1).await;
    assert_eq!(recs[0]["outcome"], "lockdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_cap() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        limits: Limits {
            new_per_sec: 10_000,
            new_burst: 10_000,
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    let mut open = Vec::new();
    for _ in 0..64 {
        open.push(w.tunnel("example.test:443").await);
    }
    let (code, body) = w.connect("example.test:443").await;
    assert_eq!(code, 429);
    assert!(body.contains("too many open tunnels"), "{body}");
    // Closing one frees its slot.
    let mut one = open.pop().unwrap();
    one.shutdown().await.unwrap();
    let _ = read_all(&mut one).await;
    drop(one);
    let t0 = Instant::now();
    loop {
        let mut s = w.dial(ports::EGRESS).await;
        s.write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut b = vec![0u8; 12];
        s.read_exact(&mut b).await.unwrap();
        if b.starts_with(b"HTTP/1.1 200") {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(5), "slot never freed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_rate_is_limited() {
    let w = world(Opts::default()).await;
    for _ in 0..20 {
        assert_eq!(w.connect("other.test:443").await.0, 403);
    }
    let (code, body) = w.connect("other.test:443").await;
    assert_eq!(code, 429);
    assert!(
        body.contains("too many new connections from this box"),
        "{body}"
    );
    // 10 per second refill.
    w.clock.fetch_add(1_000, Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(w.connect("other.test:443").await.0, 403);
    }
    assert_eq!(w.connect("other.test:443").await.0, 429);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_tunnel_closes() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        limits: Limits {
            idle_secs: 1,
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    let mut s = w.tunnel("example.test:443").await;
    // Traffic keeps it open past the idle time.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        s.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        s.read_exact(&mut b).await.unwrap();
    }
    let t0 = Instant::now();
    let _ = read_all(&mut s).await;
    assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
    let recs = w.wait_records("egress", 1).await;
    assert_eq!(recs[0]["outcome"], "idle");
    assert_eq!(recs[0]["bytes_up"], 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_after_off_closes_tunnels() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        ..Opts::default()
    })
    .await;
    let mut s = w.tunnel("example.test:443").await;
    // A connection still sending its head ends too.
    let mut half = w.dial(ports::EGRESS).await;
    half.write_all(b"CONNECT exa").await.unwrap();
    let t0 = Instant::now();
    w.gw.after_off(&w.id);
    assert!(t0.elapsed() < Duration::from_millis(500));
    let _ = read_all(&mut s).await;
    let _ = read_all(&mut half).await;
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    assert!(!w.paths.vsock_port(ports::EGRESS).exists());
    assert!(!w.paths.vsock_port(ports::MODEL).exists());
    assert!(UnixStream::connect(w.paths.vsock_port(ports::EGRESS))
        .await
        .is_err());
    let recs = w.wait_records("egress", 1).await;
    assert_eq!(recs[0]["outcome"], "stopped");
    // Only the two sockets were ever made in the box dir.
    let left: Vec<_> = std::fs::read_dir(&w.paths.dir).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_box_is_403() {
    let w = world(Opts::default()).await;
    let other = BoxId::parse("nobox").unwrap();
    let dir = w.paths.dir.parent().unwrap().join("n");
    std::fs::create_dir(&dir).unwrap();
    let p = BoxPaths::new(dir);
    w.gw.before_boot(&other, &p).unwrap();
    let mut s = UnixStream::connect(p.vsock_port(ports::EGRESS))
        .await
        .unwrap();
    s.write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(status(&read_all(&mut s).await), 403);
    w.gw.after_off(&other);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn model_port_is_503_until_plan_40() {
    let w = world(Opts::default()).await;
    let mut s = w.dial(ports::MODEL).await;
    let _ = s
        .write_all(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;
    let a = read_all(&mut s).await;
    let t = String::from_utf8_lossy(&a);
    assert!(t.starts_with("HTTP/1.1 503 Service Unavailable\r\n"), "{t}");
    assert!(t.ends_with("model access is not set up yet"), "{t}");
    use std::os::unix::fs::PermissionsExt;
    for port in [ports::EGRESS, ports::MODEL] {
        let m = std::fs::symlink_metadata(w.paths.vsock_port(port)).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o660);
    }
}
