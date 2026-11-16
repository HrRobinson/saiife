//! The per-box gateway (spec §7.4, plan 38 Task 6): every byte a box sends
//! off the guest goes through the host listeners this binds in the box
//! directory before boot, `vsock.sock_5001` (the allow-listed CONNECT proxy,
//! [`egress`]) and `vsock.sock_5002` (the model route, [`model`]).
//!
//! The guest is untrusted. Per box: at most [`Limits::tunnels`] open
//! connections (`429` above), new connections through a token bucket
//! (10/s, burst 20; `429` "too many new connections from this box"), and
//! every connection ends when the box goes off. Refusals are recorded as
//! `egress_denied`, at most once per (box, host, reason) per 60 s with a
//! `suppressed` count on the next. The gateway makes no files in the box
//! directory besides its two sockets; records go through the daemon's
//! audit writer only.
//!
//! [`GatewayHooks`] is a [`VmHooks`]: its methods run on the VMM's thread
//! and never block on the runtime; the listeners and connections run as
//! tasks on the runtime handle it was given.

pub mod egress;
pub mod model;

use crate::ops::{Ctx, Mode};
use saiife_audit::DecisionKind;
use saiife_boxes::BoxId;
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::vmm::VmHooks;
use saiife_boxhost::vsock;
use saiife_boxproto::ports;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio::runtime::Handle;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

/// How often an open tunnel checks for lockdown (G8).
pub const LOCKDOWN_CHECK_SECS: u64 = 5;
/// The name lookup's deadline.
pub const RESOLVE_SECS: u64 = 5;
/// At most this many answers of a lookup are checked (and only those are
/// ever connected to).
pub const MAX_ANSWERS: usize = 16;
/// One `egress_denied` record per (box, host, reason) per window.
pub const DENIED_WINDOW_MS: u64 = 60_000;
/// The rate limiter's keys; past it the host is dropped from new keys.
const MAX_DENIED_KEYS: usize = 1024;
/// The same, per box, so one box cannot crowd out the others' records.
const MAX_DENIED_KEYS_PER_BOX: usize = 128;

/// Name resolution, injected: [`SystemResolve`] in production, a fixed map
/// in the tests.
///
/// `hold` carries the lookup permits (the box's and the gateway's). A
/// resolver keeps it until its lookup has really ended: an async one just
/// holds it in its future, one that runs on a thread moves it there.
pub trait Resolve: Send + Sync {
    fn lookup(
        &self,
        host: &str,
        port: u16,
        hold: LookupHold,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + '_>>;
}

/// The permits one lookup holds; dropping it frees them.
pub struct LookupHold {
    /// Never read: held only to be dropped.
    pub(crate) _permits: Vec<OwnedSemaphorePermit>,
}

/// Concurrent name lookups per box: past it that box (only) gets
/// `503 lookup_busy`. 8 boxes at their cap use every gateway-wide permit
/// ([`LOOKUP_PERMITS`]); with more than 8 boxes looking up names at once
/// the global cap is oversubscribed, and a busy host's boxes can see
/// `lookup_busy` from it, at most 4 lookups' worth per box.
pub const LOOKUP_PERMITS_PER_BOX: usize = 4;
/// A box's refused lookups (no answer, timeout, private answer) are
/// answered from its negative cache for this long, without a permit or a
/// lookup.
pub const NEG_TTL_MS: u64 = 30_000;
/// Negative cache entries per box; the oldest goes first.
pub const NEG_ENTRIES_PER_BOX: usize = 256;

/// Name lookups in flight at once, gateway-wide (every box together).
/// Past it a CONNECT gets `503` "too many name lookups in progress" at
/// once. `getaddrinfo` cannot be cancelled: a lookup that outlives
/// [`RESOLVE_SECS`] keeps its thread, and with it its [`LookupHold`] (the
/// box's and the gateway's permits) and [`SystemResolve`]'s own permit, until
/// it ends, so this also bounds the threads a dead resolver can hold, and
/// keeps them from starving the daemon's other `spawn_blocking` work.
pub const LOOKUP_PERMITS: usize = 32;

/// `std::net::ToSocketAddrs` on the blocking pool, at most
/// [`LOOKUP_PERMITS`] threads at once. The permit moves into the thread and
/// is released only when `getaddrinfo` returns, not when the gateway stops
/// waiting. No permit free: `WouldBlock`, and nothing is spawned.
pub struct SystemResolve {
    permits: Arc<Semaphore>,
}

impl SystemResolve {
    pub fn new() -> SystemResolve {
        SystemResolve::with_permits(LOOKUP_PERMITS)
    }

    pub fn with_permits(n: usize) -> SystemResolve {
        SystemResolve {
            permits: Arc::new(Semaphore::new(n)),
        }
    }
}

impl Default for SystemResolve {
    fn default() -> SystemResolve {
        SystemResolve::new()
    }
}

impl Resolve for SystemResolve {
    fn lookup(
        &self,
        host: &str,
        port: u16,
        hold: LookupHold,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + '_>> {
        let host = host.to_string();
        let permit = Arc::clone(&self.permits).try_acquire_owned();
        Box::pin(async move {
            let permit = permit
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "too many name lookups"))?;
            tokio::task::spawn_blocking(move || {
                // Every permit lives as long as getaddrinfo does.
                let _permits = (permit, hold);
                use std::net::ToSocketAddrs;
                Ok((host.as_str(), port)
                    .to_socket_addrs()?
                    .take(MAX_ANSWERS)
                    .collect())
            })
            .await
            .map_err(|e| io::Error::other(format!("name lookup did not finish: {e}")))?
        })
    }
}

/// G9, plus ruling R3's new-connection bucket.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Open connections per box.
    pub tunnels: usize,
    pub head_bytes: usize,
    /// One deadline for the whole head.
    pub head_secs: u64,
    pub connect_secs: u64,
    pub idle_secs: u64,
    /// New connections per second per box (the bucket's refill).
    pub new_per_sec: u64,
    /// The bucket's size.
    pub new_burst: u64,
    /// Name lookups in flight, gateway-wide ([`LOOKUP_PERMITS`]).
    pub lookups: usize,
    /// Name lookups in flight per box ([`LOOKUP_PERMITS_PER_BOX`]).
    pub lookups_per_box: usize,
    /// Each lookup's deadline ([`RESOLVE_SECS`]).
    pub resolve_secs: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            tunnels: 64,
            head_bytes: 8 * 1024,
            head_secs: 10,
            connect_secs: 10,
            idle_secs: 300,
            new_per_sec: 10,
            new_burst: 20,
            lookups: LOOKUP_PERMITS,
            lookups_per_box: LOOKUP_PERMITS_PER_BOX,
            resolve_secs: RESOLVE_SECS,
        }
    }
}

/// Milliseconds on a monotonic clock (any epoch).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub struct GatewayConfig {
    pub limits: Limits,
    /// Debug builds only: resolved loopback addresses pass the address
    /// rule (every other private answer is still refused). Release builds
    /// have no such field.
    #[cfg(debug_assertions)]
    pub allow_loopback_for_tests: bool,
    /// The rate limits' clock (the denied-record window and the bucket).
    pub clock: Clock,
    /// The model forwarder's limits (plan 40, C5).
    pub model: model::ModelConfig,
}

impl Default for GatewayConfig {
    fn default() -> GatewayConfig {
        let t0 = Instant::now();
        GatewayConfig {
            limits: Limits::default(),
            #[cfg(debug_assertions)]
            allow_loopback_for_tests: false,
            clock: Arc::new(move || u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)),
            model: model::ModelConfig::default(),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A token bucket in thousandths of a connection.
struct Bucket {
    milli: u64,
    at_ms: u64,
}

impl Bucket {
    fn take(&mut self, now: u64, l: &Limits) -> bool {
        let cap = l.new_burst.saturating_mul(1000);
        let elapsed = now.saturating_sub(self.at_ms);
        self.milli = self
            .milli
            .saturating_add(elapsed.saturating_mul(l.new_per_sec))
            .min(cap);
        self.at_ms = self.at_ms.max(now);
        if self.milli >= 1000 {
            self.milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// One box's run: from `before_boot` to `after_off`.
pub struct BoxRun {
    pub(crate) id: BoxId,
    paths: BoxPaths,
    /// `true` once the box is off: every task of the run ends.
    pub(crate) stop: watch::Sender<bool>,
    open: AtomicUsize,
    bucket: Mutex<Bucket>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// [`Limits::lookups_per_box`], taken before the gateway's.
    pub(crate) lookups: Arc<Semaphore>,
    neg: Mutex<NegCache>,
}

/// A box's remembered lookup refusals, by host.
#[derive(Default)]
struct NegCache(HashMap<String, (u64, egress::Neg)>);

impl NegCache {
    fn get(&mut self, host: &str, now: u64) -> Option<egress::Neg> {
        match self.0.get(host) {
            Some((at, n)) if now.saturating_sub(*at) < NEG_TTL_MS => Some(*n),
            Some(_) => {
                self.0.remove(host);
                None
            }
            None => None,
        }
    }

    fn put(&mut self, host: &str, neg: egress::Neg, now: u64) {
        if !self.0.contains_key(host) && self.0.len() >= NEG_ENTRIES_PER_BOX {
            let oldest = self
                .0
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(h, _)| h.clone());
            if let Some(h) = oldest {
                self.0.remove(&h);
            }
        }
        self.0.insert(host.to_string(), (now, neg));
    }
}

impl BoxRun {
    pub(crate) fn take_token(&self, now: u64, l: &Limits) -> bool {
        lock(&self.bucket).take(now, l)
    }

    pub(crate) fn neg_get(&self, host: &str, now: u64) -> Option<egress::Neg> {
        lock(&self.neg).get(host, now)
    }

    pub(crate) fn neg_put(&self, host: &str, neg: egress::Neg, now: u64) {
        lock(&self.neg).put(host, neg, now);
    }

    fn halt(&self) {
        self.stop.send_replace(true);
        for t in lock(&self.tasks).drain(..) {
            t.abort();
        }
    }
}

/// One of a box's open connections; dropping it frees the slot on every
/// exit path.
pub(crate) struct Slot(Arc<BoxRun>);

impl Slot {
    pub(crate) fn take(run: &Arc<BoxRun>, cap: usize) -> Option<Slot> {
        let mut n = run.open.load(Ordering::SeqCst);
        loop {
            if n >= cap {
                return None;
            }
            match run
                .open
                .compare_exchange(n, n + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Some(Slot(Arc::clone(run))),
                Err(now) => n = now,
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

type DeniedKey = (BoxId, Option<String>, &'static str);

/// When each denied key last wrote a record, and how many it held back since.
#[derive(Default)]
struct Denied(HashMap<DeniedKey, (u64, u64)>);

impl Denied {
    /// `Some(suppressed)` when a record is due.
    fn admit(&mut self, mut key: DeniedKey, now: u64) -> Option<u64> {
        if !self.0.contains_key(&key) {
            let per_box =
                |m: &HashMap<DeniedKey, (u64, u64)>| m.keys().filter(|k| k.0 == key.0).count();
            if self.0.len() >= MAX_DENIED_KEYS || per_box(&self.0) >= MAX_DENIED_KEYS_PER_BOX {
                self.0
                    .retain(|_, (at, _)| now.saturating_sub(*at) < DENIED_WINDOW_MS);
            }
            if self.0.len() >= MAX_DENIED_KEYS || per_box(&self.0) >= MAX_DENIED_KEYS_PER_BOX {
                // Bounded: one key per (box, reason) from here.
                key.1 = None;
            }
        }
        match self.0.get_mut(&key) {
            Some((at, n)) if now.saturating_sub(*at) < DENIED_WINDOW_MS => {
                *n += 1;
                None
            }
            Some((at, n)) => {
                let held = *n;
                (*at, *n) = (now, 0);
                Some(held)
            }
            None => {
                self.0.insert(key, (now, 0));
                Some(0)
            }
        }
    }
}

/// What every connection task shares.
pub struct GatewayShared {
    /// Weak: the context holds the manager, which holds the VMM, which holds
    /// this gateway as a hook; a strong reference would be a cycle that
    /// keeps the context (and its vault key) alive forever.
    ctx: Weak<Ctx>,
    pub(crate) resolve: Arc<dyn Resolve>,
    pub(crate) limits: Limits,
    allow_loopback: bool,
    pub(crate) clock: Clock,
    denied: Mutex<Denied>,
    runs: Mutex<BTreeMap<BoxId, Arc<BoxRun>>>,
    /// [`LOOKUP_PERMITS`] around every [`Resolve::lookup`], whatever the
    /// resolver.
    pub(crate) lookups: Arc<Semaphore>,
    /// The model forwarder's limits.
    pub(crate) model: model::ModelConfig,
}

impl GatewayShared {
    pub(crate) fn run(&self, id: &BoxId) -> Option<Arc<BoxRun>> {
        lock(&self.runs).get(id).cloned()
    }

    /// The daemon context, while the daemon runs.
    pub(crate) fn ctx(&self) -> Option<Arc<Ctx>> {
        self.ctx.upgrade()
    }

    /// Any lockdown blocks connectors, and so egress (G8). A daemon that is
    /// going away blocks it too.
    pub(crate) fn locked(&self) -> bool {
        self.ctx().is_none_or(|c| c.lockdown.get().is_some())
    }

    /// The address rule (G7), with the debug-only loopback exception. Only
    /// a plain loopback address (127/8, `::1`) is excepted: an IPv4-mapped
    /// `::ffff:127.0.0.1` is not (`Ipv6Addr::is_loopback` is `::1` only).
    pub(crate) fn address_ok(&self, ip: &IpAddr) -> bool {
        egress::public(ip) || (self.allow_loopback && ip.is_loopback())
    }
}

/// Write the `egress_denied` record of `r` unless its key wrote one in the
/// last 60 s.
pub(crate) async fn deny(gw: &GatewayShared, id: &BoxId, r: egress::Refusal) {
    let key = (id.clone(), r.host.clone(), r.reason);
    let Some(suppressed) = lock(&gw.denied).admit(key, (gw.clock)()) else {
        return;
    };
    let input = match (&r.host, r.port) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        _ => "-".to_string(),
    };
    let Some(ctx) = gw.ctx() else { return };
    let mut rec = ctx.record("egress_denied", &input);
    rec.decision = DecisionKind::Deny;
    rec.reason = Some(r.reason.to_string());
    rec.session = Some(format!("box-{}", id.as_str()));
    let x = &mut rec.extra;
    x.insert("box".into(), id.as_str().into());
    x.insert(
        "dest_host".into(),
        r.host.map_or(serde_json::Value::Null, Into::into),
    );
    x.insert(
        "port".into(),
        r.port.map_or(serde_json::Value::Null, Into::into),
    );
    if suppressed > 0 {
        x.insert("suppressed".into(), suppressed.into());
    }
    if let Err(e) = ctx.writer.append(rec).await {
        eprintln!("saiifed: warning: cannot write an egress_denied record: {e}");
    }
}

/// Ends once the run is stopped (or its sender is gone).
pub(crate) async fn stopped(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

#[derive(Clone, Copy)]
enum Port {
    Egress,
    Model,
}

async fn accept_loop(l: UnixListener, run: Arc<BoxRun>, gw: Arc<GatewayShared>, port: Port) {
    let mut stop = run.stop.subscribe();
    loop {
        tokio::select! {
            r = l.accept() => match r {
                Ok((s, _)) => {
                    let (run, gw) = (Arc::clone(&run), Arc::clone(&gw));
                    tokio::spawn(async move {
                        match port {
                            Port::Egress => egress::serve_run(s, run, gw).await,
                            Port::Model => model::serve_run(s, run, gw).await,
                        }
                    });
                }
                Err(e) => {
                    eprintln!(
                        "saiifed: warning: box {} gateway accept failed: {e}",
                        run.id.as_str()
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            () = stopped(&mut stop) => return,
        }
    }
}

/// The gateway as the VMM's hook: binds the box's listeners before boot,
/// ends everything after it is off.
pub struct GatewayHooks {
    shared: Arc<GatewayShared>,
    rt: Handle,
    /// Locked mode: the listeners are 0660 (the VMM user's group), else 0600.
    group_rw: bool,
}

impl GatewayHooks {
    pub fn new(
        ctx: Arc<Ctx>,
        rt: Handle,
        resolve: Arc<dyn Resolve>,
        cfg: GatewayConfig,
    ) -> Arc<GatewayHooks> {
        #[cfg(debug_assertions)]
        let allow_loopback = cfg.allow_loopback_for_tests;
        #[cfg(not(debug_assertions))]
        let allow_loopback = false;
        let group_rw = ctx.mode == Mode::Locked;
        let lookups = Arc::new(Semaphore::new(cfg.limits.lookups));
        Arc::new(GatewayHooks {
            shared: Arc::new(GatewayShared {
                ctx: Arc::downgrade(&ctx),
                resolve,
                limits: cfg.limits,
                allow_loopback,
                clock: cfg.clock,
                denied: Mutex::new(Denied::default()),
                runs: Mutex::new(BTreeMap::new()),
                lookups,
                model: cfg.model,
            }),
            rt,
            group_rw,
        })
    }

    /// What the connection tasks share (for [`egress::serve`]).
    pub fn shared(&self) -> Arc<GatewayShared> {
        Arc::clone(&self.shared)
    }

    fn bind(&self, paths: &BoxPaths, port: u32) -> io::Result<UnixListener> {
        let l = vsock::listen(paths, port, self.group_rw)?;
        l.set_nonblocking(true)?;
        let _rt = self.rt.enter();
        UnixListener::from_std(l)
    }
}

/// The host listeners the gateway binds (the guest channel binds the others).
const OUR_PORTS: [u32; 2] = [ports::EGRESS, ports::MODEL];

impl VmHooks for GatewayHooks {
    fn before_boot(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String> {
        // A run left over (no after_off seen) ends first.
        if let Some(old) = lock(&self.shared.runs).remove(id) {
            old.halt();
        }
        let fail = |what: &str, e: io::Error| {
            vsock::unlink_ports(paths, &OUR_PORTS);
            format!("the box gateway's {what} listener: {e}")
        };
        let egress = self
            .bind(paths, ports::EGRESS)
            .map_err(|e| fail("egress", e))?;
        let model = self
            .bind(paths, ports::MODEL)
            .map_err(|e| fail("model", e))?;
        let (stop, _) = watch::channel(false);
        let run = Arc::new(BoxRun {
            id: id.clone(),
            paths: paths.clone(),
            stop,
            open: AtomicUsize::new(0),
            bucket: Mutex::new(Bucket {
                milli: self.shared.limits.new_burst.saturating_mul(1000),
                at_ms: (self.shared.clock)(),
            }),
            tasks: Mutex::new(Vec::new()),
            lookups: Arc::new(Semaphore::new(self.shared.limits.lookups_per_box)),
            neg: Mutex::new(NegCache::default()),
        });
        lock(&self.shared.runs).insert(id.clone(), Arc::clone(&run));
        let tasks = [(egress, Port::Egress), (model, Port::Model)].map(|(l, port)| {
            self.rt.spawn(accept_loop(
                l,
                Arc::clone(&run),
                Arc::clone(&self.shared),
                port,
            ))
        });
        lock(&run.tasks).extend(tasks);
        Ok(())
    }

    fn after_off(&self, id: &BoxId) {
        let run = lock(&self.shared.runs).remove(id);
        if let Some(run) = run {
            run.halt();
            // Only ours: the guest channel's listeners are its own.
            vsock::unlink_ports(&run.paths, &OUR_PORTS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_refills() {
        let l = Limits::default();
        let mut b = Bucket {
            milli: 20_000,
            at_ms: 0,
        };
        for _ in 0..20 {
            assert!(b.take(0, &l));
        }
        assert!(!b.take(0, &l));
        assert!(!b.take(99, &l));
        assert!(b.take(100, &l));
        // A clock that goes back never adds tokens.
        assert!(!b.take(50, &l));
        // Never more than the burst.
        for _ in 0..20 {
            assert!(b.take(1_000_000, &l));
        }
        assert!(!b.take(1_000_000, &l));
    }

    #[test]
    fn denied_window_and_bound() {
        let id = BoxId::parse("b1").unwrap();
        let mut d = Denied::default();
        let k = |h: &str| (id.clone(), Some(h.to_string()), "not_allowed");
        assert_eq!(d.admit(k("a"), 0), Some(0));
        for _ in 0..4 {
            assert_eq!(d.admit(k("a"), 10), None);
        }
        assert_eq!(d.admit(k("b"), 10), Some(0));
        assert_eq!(d.admit(k("a"), DENIED_WINDOW_MS), Some(4));
        assert_eq!(d.admit(k("a"), DENIED_WINDOW_MS + 1), None);
        // The global bound: 16 boxes of 64 keys each.
        let mut d = Denied::default();
        let kb = |b: usize, h: &str| {
            (
                BoxId::parse(&format!("g{b}")).unwrap(),
                Some(h.to_string()),
                "not_allowed",
            )
        };
        for i in 0..MAX_DENIED_KEYS {
            assert_eq!(d.admit(kb(i % 16, &i.to_string()), 0), Some(0));
        }
        assert_eq!(d.admit(kb(0, "new"), 0), Some(0));
        assert_eq!(d.admit(kb(0, "newer"), 0), None);
        assert!(d.0.len() <= MAX_DENIED_KEYS + 1);
        // One box's keys never crowd out another's.
        let mut d = Denied::default();
        for i in 0..MAX_DENIED_KEYS_PER_BOX {
            assert_eq!(d.admit(k(&i.to_string()), 0), Some(0));
        }
        assert_eq!(d.admit(k("more"), 0), Some(0));
        assert_eq!(d.admit(k("more2"), 0), None);
        let other = BoxId::parse("b2").unwrap();
        let k2 = |h: &str| (other.clone(), Some(h.to_string()), "not_allowed");
        assert_eq!(d.admit(k2("x"), 0), Some(0));
        assert_eq!(d.admit(k2("y"), 0), Some(0));
        // Expired keys of the box make room again.
        assert_eq!(d.admit(k("late"), DENIED_WINDOW_MS), Some(0));
    }

    #[tokio::test]
    async fn system_resolve_without_a_permit_spawns_nothing() {
        let r = SystemResolve::with_permits(0);
        let e = r
            .lookup(
                "localhost",
                443,
                LookupHold {
                    _permits: Vec::new(),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn negative_cache_ttl_and_bound() {
        use egress::Neg;
        let mut c = NegCache::default();
        c.put("a.test", Neg::NoAddress, 0);
        assert_eq!(c.get("a.test", NEG_TTL_MS - 1), Some(Neg::NoAddress));
        assert_eq!(c.get("a.test", NEG_TTL_MS), None);
        assert!(c.0.is_empty());
        for i in 0..NEG_ENTRIES_PER_BOX as u64 {
            c.put(&format!("h{i}.test"), Neg::Timeout, i);
        }
        c.put("new.test", Neg::Private, 1_000);
        assert_eq!(c.0.len(), NEG_ENTRIES_PER_BOX);
        // The oldest went.
        assert_eq!(c.get("h0.test", 1_000), None);
        assert_eq!(c.get("h1.test", 1_000), Some(Neg::Timeout));
        assert_eq!(c.get("new.test", 1_000), Some(Neg::Private));
    }
}
