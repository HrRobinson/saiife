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
use saiife_daemon::box_gateway::{GatewayConfig, GatewayHooks, Limits, LookupHold, Resolve};
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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

/// A fixed name -> answers map; a missing name has no answers. Every
/// answer carries port 9, so a tunnel that works shows the gateway used the
/// port asked for, not the resolver's. With `hang`, no lookup ever ends.
struct FakeResolve {
    names: HashMap<String, Vec<SocketAddr>>,
    hang: bool,
    calls: Arc<AtomicUsize>,
}

impl Resolve for FakeResolve {
    fn lookup(
        &self,
        host: &str,
        _port: u16,
        hold: LookupHold,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + '_>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Names starting with `hang` (or all, with `hang`) never resolve;
        // the permits stay held until the gateway drops the future.
        if self.hang || host.starts_with("hang") {
            return Box::pin(async move {
                let _hold = hold;
                std::future::pending().await
            });
        }
        drop(hold);
        let v = self
            .names
            .get(host)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|a| SocketAddr::new(a.ip(), 9))
            .collect();
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
    /// A second box with the same template.
    id2: BoxId,
    paths2: BoxPaths,
    calls: Arc<AtomicUsize>,
    port: u16,
    clock: Arc<AtomicU64>,
    audit: PathBuf,
    _tmp: tempfile::TempDir,
}

struct Opts {
    limits: Limits,
    loopback: bool,
    names: Vec<(&'static str, Vec<SocketAddr>)>,
    /// The upstream's port: every rule is allowed on it as well as on 443.
    port: u16,
    hang: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            limits: Limits::default(),
            loopback: true,
            names: Vec::new(),
            port: 443,
            hang: false,
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
    t.egress = ["example.test", "*.crates.test", "*.com", "*.private.test"]
        .into_iter()
        .flat_map(|h| [rule(h, 443), rule(h, o.port)])
        .collect();
    let host = host_facts();
    let guest: Arc<dyn GuestLink> = Arc::new(FakeGuest::new());
    let mgr = Manager::open(ManagerInit {
        store: Store::open(box_ops::dir_in(&state)).unwrap(),
        vmm: Arc::new(FakeVmm::new()),
        guest,
        templates: vec![t],
        host: Arc::new(move || host),
        clock: Arc::new(|| T0),
        disk_place: box_ops::disk_place(),
    })
    .unwrap()
    .manager;
    let spawn = || {
        mgr.spawn(&SpawnArgs {
            template: "egress-test".into(),
            repo: "shop".into(),
            repo_dir: None,
            task: String::new(),
            start: saiife_wire::source::Start::Queue,
            owner_uid: 2000,
            repo_image: None,
            base_manifest: None,
        })
        .unwrap()
    };
    let rec = spawn();
    let rec2 = spawn();
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
    let resolve = Arc::new(FakeResolve {
        names: o
            .names
            .into_iter()
            .map(|(n, a)| (n.to_string(), a))
            .collect(),
        hang: o.hang,
        calls: Arc::new(AtomicUsize::new(0)),
    });
    let calls = Arc::clone(&resolve.calls);
    let gw = GatewayHooks::new(
        Arc::clone(&ctx),
        tokio::runtime::Handle::current(),
        resolve,
        GatewayConfig {
            limits: o.limits,
            allow_loopback_for_tests: o.loopback,
            clock: Arc::new(move || c.load(Ordering::SeqCst)),
            model: Default::default(),
        },
    );
    let dir = tmp.path().join("b");
    std::fs::create_dir(&dir).unwrap();
    let paths = BoxPaths::new(dir);
    gw.before_boot(&rec.id, &paths).unwrap();
    let dir2 = tmp.path().join("b2");
    std::fs::create_dir(&dir2).unwrap();
    let paths2 = BoxPaths::new(dir2);
    gw.before_boot(&rec2.id, &paths2).unwrap();
    W {
        ctx,
        gw,
        id: rec.id,
        session: rec.session,
        paths,
        id2: rec2.id,
        paths2,
        calls,
        port: o.port,
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
    /// `host:<upstream port>`.
    fn t(&self, host: &str) -> String {
        format!("{host}:{}", self.port)
    }

    /// A CONNECT on box 2's egress port; the whole answer.
    async fn connect2(&self, target: &str) -> (u16, String) {
        let mut s = UnixStream::connect(self.paths2.vsock_port(ports::EGRESS))
            .await
            .unwrap();
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        // Up to the end of the answer's head: a tunnel stays open.
        let mut a = Vec::new();
        let mut b = [0u8; 256];
        while !a.windows(4).any(|w| w == b"\r\n\r\n") {
            match tokio::time::timeout(Duration::from_secs(10), s.read(&mut b)).await {
                Ok(Ok(n)) if n > 0 => a.extend_from_slice(&b[..n]),
                _ => break,
            }
        }
        (status(&a), String::from_utf8_lossy(&a).into_owned())
    }

    /// `n` CONNECTs to `target` left waiting on their lookups.
    async fn hold_lookups(&self, target: &str, n: usize) -> Vec<UnixStream> {
        let before = self.calls.load(Ordering::SeqCst);
        let mut held = Vec::new();
        for _ in 0..n {
            let mut s = self.dial(ports::EGRESS).await;
            s.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
                .await
                .unwrap();
            held.push(s);
        }
        // Every one has reached its lookup.
        let t0 = Instant::now();
        while self.calls.load(Ordering::SeqCst) < before + n {
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "lookups never started"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        held
    }

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
        port: up.port(),
        ..Opts::default()
    })
    .await;
    let mut s = w.dial(ports::EGRESS).await;
    // Bytes after the head in the same write go upstream after the 200.
    s.write_all(
        format!(
            "CONNECT Example.Test.:{} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic c2VjcmV0\r\n\r\nearly",
            up.port()
        )
        .as_bytes(),
    )
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
    assert_eq!(extra(r, "port"), up.port());
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
        port: up.port(),
        ..Opts::default()
    })
    .await;
    drop(w.tunnel(&w.t("a.crates.test")).await);
    drop(w.tunnel(&w.t("a.b.crates.test")).await);
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
        port: up.port(),
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
    let (code, body) = w.connect(&w.t("example.test")).await;
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
        port: up.port(),
        ..Opts::default()
    })
    .await;
    w.lockdown(LockScope::Connectors);
    let (code, _) = w.connect(&w.t("example.test")).await;
    assert_eq!(code, 503);
    let recs = w.wait_records("egress_denied", 1).await;
    assert_eq!(recs[0]["reason"], "lockdown");
    w.ctx.lockdown.set(None).unwrap();
    drop(w.tunnel(&w.t("example.test")).await);
    w.lockdown(LockScope::All);
    assert_eq!(w.connect(&w.t("example.test")).await.0, 503);
}

async fn lockdown_closes_open_tunnels_of(scope: LockScope) {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        port: up.port(),
        ..Opts::default()
    })
    .await;
    let mut s = w.tunnel(&w.t("example.test")).await;
    w.lockdown(scope);
    let t0 = Instant::now();
    let _ = read_all(&mut s).await;
    assert!(t0.elapsed() < Duration::from_secs(6), "{:?}", t0.elapsed());
    let recs = w.wait_records("egress", 1).await;
    assert_eq!(recs[0]["outcome"], "lockdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lockdown_closes_open_tunnels() {
    lockdown_closes_open_tunnels_of(LockScope::Connectors).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lockdown_all_closes_open_tunnels() {
    lockdown_closes_open_tunnels_of(LockScope::All).await;
}

/// The test flag lets plain loopback through and nothing else: not other
/// private answers, not an IPv4-mapped loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_flag_is_only_plain_loopback() {
    let w = world(Opts {
        names: vec![
            ("a.private.test", vec![sa("10.0.0.5:443")]),
            ("b.private.test", vec![sa("[::ffff:127.0.0.1]:443")]),
            (
                "c.private.test",
                vec![sa("127.0.0.1:443"), sa("10.0.0.5:443")],
            ),
        ],
        loopback: true,
        ..Opts::default()
    })
    .await;
    for h in ["a.private.test", "b.private.test", "c.private.test"] {
        let (code, body) = w.connect(&format!("{h}:443")).await;
        assert_eq!(code, 403, "{h}: {body}");
        assert!(body.contains("resolves to a private address"), "{body}");
    }
}

/// Lookups that never end hold at most LOOKUP_PERMITS slots; the rest are
/// refused at once instead of piling up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lookups_are_bounded() {
    use saiife_daemon::box_gateway::LOOKUP_PERMITS;
    let w = world(Opts {
        hang: true,
        limits: Limits {
            new_per_sec: 10_000,
            new_burst: 10_000,
            // The gateway-wide cap is what this test exercises.
            lookups_per_box: 1_000,
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    let mut held = Vec::new();
    for _ in 0..LOOKUP_PERMITS {
        let mut s = w.dial(ports::EGRESS).await;
        s.write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        held.push(s);
    }
    // Every held lookup has started (their records cannot exist yet).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let t0 = Instant::now();
    for _ in 0..3 {
        let (code, body) = w.connect("example.test:443").await;
        assert_eq!(code, 503, "{body}");
        assert!(body.contains("too many name lookups in progress"), "{body}");
    }
    assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
    let recs = w.wait_records("egress_denied", 1).await;
    assert_eq!(recs[0]["reason"], "lookup_busy");
    // The held ones time out after RESOLVE_SECS and free their permits.
    for mut s in held {
        let a = read_all(&mut s).await;
        assert_eq!(status(&a), 504);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    // A new name (example.test's timeout is cached now) takes a permit again.
    assert_eq!(w.connect("other.crates.test:443").await.0, 504);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tunnel_cap() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        port: up.port(),
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
        open.push(w.tunnel(&w.t("example.test")).await);
    }
    let (code, body) = w.connect(&w.t("example.test")).await;
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
        s.write_all(format!("CONNECT {} HTTP/1.1\r\n\r\n", w.t("example.test")).as_bytes())
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
        port: up.port(),
        limits: Limits {
            idle_secs: 1,
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    let mut s = w.tunnel(&w.t("example.test")).await;
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
        port: up.port(),
        ..Opts::default()
    })
    .await;
    let mut s = w.tunnel(&w.t("example.test")).await;
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

/// m5: the gateway's after_off unlinks only its own listeners (egress,
/// model); the guest channel's (events, pty) are left to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_after_off_leaves_the_guest_channels_sockets() {
    let w = world(Opts::default()).await;
    let ev = saiife_boxhost::vsock::listen(&w.paths, ports::EVENTS, false).unwrap();
    let pty = saiife_boxhost::vsock::listen(&w.paths, ports::PTY, false).unwrap();
    w.gw.after_off(&w.id);
    assert!(!w.paths.vsock_port(ports::EGRESS).exists());
    assert!(!w.paths.vsock_port(ports::MODEL).exists());
    assert!(w.paths.vsock_port(ports::EVENTS).exists());
    assert!(w.paths.vsock_port(ports::PTY).exists());
    drop((ev, pty));
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
async fn model_port_refuses_a_box_without_its_placeholder() {
    // The model forwarder itself is tests/box_model.rs (plan 40); here no
    // placeholder was made for the box, so nothing passes.
    let w = world(Opts::default()).await;
    let mut s = w.dial(ports::MODEL).await;
    let _ = s
        .write_all(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        .await;
    let a = read_all(&mut s).await;
    let t = String::from_utf8_lossy(&a);
    assert!(t.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{t}");
    assert!(
        t.ends_with("this box's model credential is not valid\n"),
        "{t}"
    );
    use std::os::unix::fs::PermissionsExt;
    for port in [ports::EGRESS, ports::MODEL] {
        let m = std::fs::symlink_metadata(w.paths.vsock_port(port)).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o660);
    }
}

/// Box A's hung lookups take only A's permits: box B still resolves and
/// tunnels.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_box_cannot_starve_lookups() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        port: up.port(),
        ..Opts::default()
    })
    .await;
    let names = ["hang1", "hang2", "hang3", "hang4"];
    let mut held = Vec::new();
    for (i, n) in names.iter().enumerate() {
        held.extend(w.hold_lookups(&format!("{n}.crates.test:443"), 1).await);
        assert!(w.calls.load(Ordering::SeqCst) > i);
    }
    let (code, _) = w.connect2(&w.t("example.test")).await;
    // B's tunnel to the echo upstream opens (the 200), then closes with us.
    assert_eq!(code, 200);
    let recs = w.wait_records("egress", 1).await;
    assert_eq!(recs[0]["box"], w.id2.as_str());
    drop(held);
}

/// The 5th concurrent lookup of one box is `503 lookup_busy`, for that box
/// only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_box_lookup_cap() {
    let up = echo().await;
    let w = world(Opts {
        names: vec![("example.test", vec![up])],
        port: up.port(),
        ..Opts::default()
    })
    .await;
    let mut held = Vec::new();
    for i in 0..4 {
        held.extend(w.hold_lookups(&format!("hang{i}.crates.test:443"), 1).await);
    }
    let calls = w.calls.load(Ordering::SeqCst);
    let t0 = Instant::now();
    let (code, body) = w.connect("hang9.crates.test:443").await;
    assert_eq!(code, 503, "{body}");
    assert!(body.contains("too many name lookups in progress"));
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert_eq!(w.calls.load(Ordering::SeqCst), calls, "no lookup was made");
    let recs = w.wait_records("egress_denied", 1).await;
    assert_eq!(recs[0]["reason"], "lookup_busy");
    assert_eq!(recs[0]["box"], w.id.as_str());
    // Box B is not affected.
    let (code, _) = w.connect2(&w.t("example.test")).await;
    assert_eq!(code, 200);
    drop(held);
}

/// A refused lookup (no answer, timeout) is answered from the box's
/// negative cache for 30 s of the clock: no permit, no resolver call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negative_cache_takes_no_permit() {
    let w = world(Opts {
        limits: Limits {
            resolve_secs: 1,
            ..Limits::default()
        },
        ..Opts::default()
    })
    .await;
    // No answer.
    assert_eq!(w.connect("example.test:443").await.0, 502);
    assert_eq!(w.calls.load(Ordering::SeqCst), 1);
    for _ in 0..3 {
        let (code, body) = w.connect("example.test:443").await;
        assert_eq!(code, 502);
        assert!(body.contains("example.test did not resolve"));
    }
    assert_eq!(w.calls.load(Ordering::SeqCst), 1);
    // A timeout.
    assert_eq!(w.connect("hang.crates.test:443").await.0, 504);
    assert_eq!(w.calls.load(Ordering::SeqCst), 2);
    let t0 = Instant::now();
    assert_eq!(w.connect("hang.crates.test:443").await.0, 504);
    assert!(
        t0.elapsed() < Duration::from_millis(900),
        "answered from the cache"
    );
    assert_eq!(w.calls.load(Ordering::SeqCst), 2);
    // Another box has its own cache.
    assert_eq!(w.connect2("example.test:443").await.0, 502);
    assert_eq!(w.calls.load(Ordering::SeqCst), 3);
    // Refusals from the cache are still recorded (and rate-limited).
    let recs = w.wait_records("egress_denied", 3).await;
    assert_eq!(recs.len(), 3, "{recs:?}");
    // Just inside 30 s: still cached.
    w.clock.fetch_add(29_999, Ordering::SeqCst);
    assert_eq!(w.connect("example.test:443").await.0, 502);
    assert_eq!(w.calls.load(Ordering::SeqCst), 3);
    // At 30 s the resolver is asked again (the record window is 60 s, so
    // that refusal is still held back).
    w.clock.fetch_add(1, Ordering::SeqCst);
    assert_eq!(w.connect("example.test:443").await.0, 502);
    assert_eq!(w.calls.load(Ordering::SeqCst), 4);
    // At 60 s: asked again, and the record says what it held back.
    w.clock.fetch_add(30_000, Ordering::SeqCst);
    assert_eq!(w.connect("example.test:443").await.0, 502);
    assert_eq!(w.calls.load(Ordering::SeqCst), 5);
    let recs = w.wait_records("egress_denied", 4).await;
    assert_eq!(recs.len(), 4, "{recs:?}");
    assert_eq!(recs[3]["dest_host"], "example.test");
    assert_eq!(recs[3]["suppressed"], 5);
}
