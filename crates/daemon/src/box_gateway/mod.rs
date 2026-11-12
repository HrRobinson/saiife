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
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio::runtime::Handle;
use tokio::sync::watch;
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

/// Name resolution, injected: [`SystemResolve`] in production, a fixed map
/// in the tests.
pub trait Resolve: Send + Sync {
    fn lookup(
        &self,
        host: &str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + '_>>;
}

/// `tokio::net::lookup_host` (the gateway bounds it with [`RESOLVE_SECS`]).
pub struct SystemResolve;

impl Resolve for SystemResolve {
    fn lookup(
        &self,
        host: &str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + '_>> {
        let host = host.to_string();
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host.as_str(), port))
                .await?
                .take(MAX_ANSWERS)
                .collect())
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
}

impl Default for GatewayConfig {
    fn default() -> GatewayConfig {
        let t0 = Instant::now();
        GatewayConfig {
            limits: Limits::default(),
            #[cfg(debug_assertions)]
            allow_loopback_for_tests: false,
            clock: Arc::new(move || u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)),
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
}

impl BoxRun {
    pub(crate) fn take_token(&self, now: u64, l: &Limits) -> bool {
        lock(&self.bucket).take(now, l)
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
        if !self.0.contains_key(&key) && self.0.len() >= MAX_DENIED_KEYS {
            self.0
                .retain(|_, (at, _)| now.saturating_sub(*at) < DENIED_WINDOW_MS);
            if self.0.len() >= MAX_DENIED_KEYS {
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
    pub(crate) ctx: Arc<Ctx>,
    pub(crate) resolve: Arc<dyn Resolve>,
    pub(crate) limits: Limits,
    allow_loopback: bool,
    pub(crate) clock: Clock,
    denied: Mutex<Denied>,
    runs: Mutex<BTreeMap<BoxId, Arc<BoxRun>>>,
}

impl GatewayShared {
    pub(crate) fn run(&self, id: &BoxId) -> Option<Arc<BoxRun>> {
        lock(&self.runs).get(id).cloned()
    }

    /// Any lockdown blocks connectors, and so egress (G8).
    pub(crate) fn locked(&self) -> bool {
        self.ctx.lockdown.get().is_some()
    }

    /// The address rule (G7), with the debug-only loopback exception.
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
    let mut rec = gw.ctx.record("egress_denied", &input);
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
    if let Err(e) = gw.ctx.writer.append(rec).await {
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
        Arc::new(GatewayHooks {
            shared: Arc::new(GatewayShared {
                ctx,
                resolve,
                limits: cfg.limits,
                allow_loopback,
                clock: cfg.clock,
                denied: Mutex::new(Denied::default()),
                runs: Mutex::new(BTreeMap::new()),
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

impl VmHooks for GatewayHooks {
    fn before_boot(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String> {
        // A run left over (no after_off seen) ends first.
        if let Some(old) = lock(&self.shared.runs).remove(id) {
            old.halt();
        }
        let fail = |what: &str, e: io::Error| {
            vsock::unlink_all(paths);
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
            vsock::unlink_all(&run.paths);
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
        let mut d = Denied::default();
        for i in 0..MAX_DENIED_KEYS {
            assert_eq!(d.admit(k(&i.to_string()), 0), Some(0));
        }
        assert_eq!(d.admit(k("new"), 0), Some(0));
        assert_eq!(d.admit(k("newer"), 0), None);
        assert!(d.0.len() <= MAX_DENIED_KEYS + 1);
    }
}
