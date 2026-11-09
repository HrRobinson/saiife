//! The daemon's hook table (plan 20): it follows each control connection
//! that said `hook.begin`, and notices a hook that ends without a verdict.
//!
//! - `hook.begin` starts tracking the connection, and an overrun timer
//!   ([`HOOK_OVERRUN`]). `hook.bind` names the call ([`HookKey`]). The
//!   connection's `audit.append` is its verdict.
//! - A connection that ends without a verdict (EOF, an error, or the
//!   overrun close) is recorded as a `hook` record with decision
//!   `no_verdict`. A bound one first waits [`RECONNECT_GRACE`] for a verdict
//!   on the same key from another connection (the approval step's
//!   reconnect); an unbound one is recorded at once.
//! - [`HookTable::wait`] lets the co-signer wait for the verdict on a key.
//!
//! Record only: nothing here locks anything down (owner ruling 2026-11-06).
//! One `Mutex` over the whole state, never held across an `.await`; each key
//! has its own `Notify`, and a key not seen yet is waited for on one shared
//! `Notify` that every new key fires.

use saiife_audit::{DecisionKind, NewRecord, Record};
use saiife_ipc::hookkey::HookKey;
use saiife_ipc::peer::PeerCred;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio::time::Instant;

/// How long a bound hook connection that ended without a verdict waits for
/// a verdict on its key from another connection.
pub const RECONNECT_GRACE: Duration = Duration::from_secs(5);
/// A hook connection with no verdict this long after `hook.begin` is closed
/// by the daemon and recorded.
pub const HOOK_OVERRUN: Duration = Duration::from_secs(10);
/// How long a key and its verdict are kept.
pub const VERDICT_TTL: Duration = Duration::from_secs(60);
/// The most keys kept; the oldest is dropped first.
pub const MAX_KEYS: usize = 4096;
/// The `reason` of a `no_verdict` record.
pub const NO_VERDICT_REASON: &str =
    "the hook ended without a verdict (killed, crashed or timed out)";

/// One control connection, handed out by `server.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// What [`HookTable::wait`] saw for a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waited {
    /// The hook recorded an `allow` (or an `approved`).
    Allow,
    /// The hook recorded any other decision.
    Deny,
    /// The hook ended without a verdict, and no other connection gave one.
    NoVerdict,
    /// Nothing by the deadline.
    Timeout,
}

/// The facts of one hook that ended without a verdict, for its record.
#[derive(Debug, Clone)]
pub struct NoVerdict {
    pub peer: PeerCred,
    pub agent: String,
    /// The `event` of `hook.begin` (`PreToolUse`, ...), when it sent one.
    pub hook_event: Option<String>,
    /// The bound key; `None` when the hook never bound one.
    pub key: Option<HookKey>,
    /// The tool, when `hook.bind` named it.
    pub tool: Option<String>,
    /// From `hook.begin` to the end of the connection.
    pub elapsed_ms: u64,
    /// The daemon closed the connection at [`HOOK_OVERRUN`].
    pub overrun: bool,
    /// When it was recorded (the record's `ts`).
    pub ts: String,
}

/// Where the table sends a hook without a verdict; called without the
/// table's lock held, from a tokio task or a connection's end.
pub type Sink = Box<dyn Fn(NoVerdict) + Send + Sync>;

/// The `hook` record of `nv`, with the peer's `user` name. `mode` is the
/// daemon's record mode.
pub fn no_verdict_record(nv: &NoVerdict, mode: &str, user: Option<String>, saiife: &str) -> Record {
    let key = nv.key.as_ref();
    let mut r = Record::new(
        NewRecord {
            agent: &nv.agent,
            project: "",
            session: key.and_then(|k| k.session.as_deref()),
            tool: nv.tool.as_deref().unwrap_or(""),
            input: "",
            decision: DecisionKind::NoVerdict,
            pack: None,
            rule: None,
            reason: Some(NO_VERDICT_REASON),
            mode,
            policy: None,
            permission_mode: None,
        },
        saiife,
    );
    r.ts = nv.ts.clone();
    r.kind = Some("hook".into());
    r.uid = Some(nv.peer.uid);
    r.sid = nv.peer.sid.clone();
    r.user = user;
    let x = &mut r.extra;
    x.insert("event".into(), "no_verdict".into());
    x.insert("bound".into(), key.is_some().into());
    x.insert(
        "tool_use_id".into(),
        json!(key.and_then(|k| k.tool_use_id.as_deref())),
    );
    x.insert(
        "input_sha256".into(),
        json!(key.map(|k| k.input_sha256.as_str())),
    );
    x.insert("elapsed_ms".into(), nv.elapsed_ms.into());
    x.insert("pid".into(), nv.peer.pid.into());
    if let Some(e) = &nv.hook_event {
        x.insert("hook_event".into(), Value::String(e.clone()));
    }
    if nv.overrun {
        x.insert("overrun".into(), true.into());
    }
    r
}

/// A tracked hook connection.
struct Open {
    peer: PeerCred,
    agent: String,
    hook_event: Option<String>,
    began: Instant,
    key: Option<HookKey>,
    tool: Option<String>,
    /// A verdict came, or the overrun already ended it.
    done: bool,
    /// Fired at the overrun: the connection's server closes it.
    close: Option<Arc<Notify>>,
    overrun: Option<AbortHandle>,
}

/// What is known about one key.
struct Slot {
    outcome: Option<Waited>,
    /// Verdicts given on this key, so a grace period sees a later one.
    verdicts: u64,
    at: Instant,
    notify: Arc<Notify>,
}

#[derive(Default)]
struct State {
    conns: HashMap<ConnId, Open>,
    keys: HashMap<HookKey, Slot>,
    /// Keys in the order they were added; a key is in `keys` only while it
    /// is in here.
    order: VecDeque<HookKey>,
    no_verdict: u64,
    last_ts: Option<String>,
}

impl State {
    /// Drop keys older than [`VERDICT_TTL`] and those over [`MAX_KEYS`],
    /// oldest first; their waiters wake and see the key gone.
    fn prune(&mut self, now: Instant) {
        while let Some(front) = self.order.front() {
            let old = self
                .keys
                .get(front)
                .is_none_or(|s| now.saturating_duration_since(s.at) >= VERDICT_TTL);
            if !old && self.keys.len() <= MAX_KEYS {
                break;
            }
            let k = self.order.pop_front().expect("front exists");
            if let Some(s) = self.keys.remove(&k) {
                s.notify.notify_waiters();
            }
        }
    }
}

struct Inner {
    state: Mutex<State>,
    sink: Sink,
    /// Fired whenever a key is added, for waiters on a key not seen yet.
    added: Arc<Notify>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Count a hook without a verdict and send it to the sink; settles the
    /// key's waiters on `NoVerdict` unless a verdict came after `seen`.
    fn record(&self, mut nv: NoVerdict, seen: Option<u64>) {
        {
            let mut st = self.lock();
            if let (Some(k), Some(seen)) = (&nv.key, seen) {
                if st.keys.get(k).is_some_and(|s| s.verdicts > seen) {
                    return;
                }
            }
            if let Some(slot) = nv.key.as_ref().and_then(|k| st.keys.get_mut(k)) {
                slot.outcome = Some(Waited::NoVerdict);
                slot.notify.notify_waiters();
            }
            nv.ts = crate::ops::now_ts();
            st.no_verdict += 1;
            st.last_ts = Some(nv.ts.clone());
        }
        (self.sink)(nv);
    }

    /// A connection that ended (or overran) without a verdict: recorded at
    /// once when unbound, after [`RECONNECT_GRACE`] when bound.
    fn ended_without_verdict(self: &Arc<Self>, st: MutexGuard<'_, State>, o: Open, overrun: bool) {
        let seen = o
            .key
            .as_ref()
            .map(|k| st.keys.get(k).map_or(0, |s| s.verdicts));
        drop(st);
        let nv = NoVerdict {
            elapsed_ms: u64::try_from(o.began.elapsed().as_millis()).unwrap_or(u64::MAX),
            peer: o.peer,
            agent: o.agent,
            hook_event: o.hook_event,
            key: o.key,
            tool: o.tool,
            overrun,
            ts: String::new(),
        };
        if nv.key.is_none() {
            return self.record(nv, None);
        }
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                let inner = Arc::clone(self);
                h.spawn(async move {
                    tokio::time::sleep(RECONNECT_GRACE).await;
                    inner.record(nv, seen);
                });
            }
            // No runtime (a shutdown): record without the grace.
            Err(_) => self.record(nv, seen),
        }
    }

    /// The overrun of `conn`: close it and record it.
    fn overrun(self: &Arc<Self>, conn: ConnId) {
        let mut st = self.lock();
        let Some(o) = st.conns.get_mut(&conn) else {
            return;
        };
        if o.done {
            return;
        }
        o.done = true;
        o.overrun = None;
        if let Some(c) = &o.close {
            c.notify_one();
        }
        let copy = Open {
            peer: o.peer.clone(),
            agent: o.agent.clone(),
            hook_event: o.hook_event.clone(),
            began: o.began,
            key: o.key.clone(),
            tool: o.tool.clone(),
            done: true,
            close: None,
            overrun: None,
        };
        self.ended_without_verdict(st, copy, true);
    }
}

/// The hook connections and the verdicts on their keys.
pub struct HookTable {
    inner: Arc<Inner>,
}

impl HookTable {
    pub fn new(sink: Sink) -> HookTable {
        HookTable {
            inner: Arc::new(Inner {
                state: Mutex::default(),
                sink,
                added: Arc::new(Notify::new()),
            }),
        }
    }

    /// `hook.begin` on `conn`; `false` when the connection already sent it.
    pub fn begin(&self, conn: ConnId, peer: &PeerCred, agent: &str, event: Option<&str>) -> bool {
        self.begin_closing(conn, peer, agent, event, None)
    }

    /// [`HookTable::begin`], with the signal that closes the connection at
    /// its overrun.
    pub fn begin_closing(
        &self,
        conn: ConnId,
        peer: &PeerCred,
        agent: &str,
        event: Option<&str>,
        close: Option<Arc<Notify>>,
    ) -> bool {
        let mut st = self.inner.lock();
        if st.conns.contains_key(&conn) {
            return false;
        }
        let began = Instant::now();
        let overrun = tokio::runtime::Handle::try_current().ok().map(|h| {
            let inner = Arc::clone(&self.inner);
            h.spawn(async move {
                tokio::time::sleep_until(began + HOOK_OVERRUN).await;
                inner.overrun(conn);
            })
            .abort_handle()
        });
        st.conns.insert(
            conn,
            Open {
                peer: peer.clone(),
                agent: agent.to_string(),
                hook_event: event.map(str::to_string),
                began,
                key: None,
                tool: None,
                done: false,
                close,
                overrun,
            },
        );
        true
    }

    /// `hook.bind` on `conn`; `false` when it did not begin, or already
    /// ended.
    pub fn bind(&self, conn: ConnId, key: HookKey) -> bool {
        self.bind_tool(conn, key, None)
    }

    /// [`HookTable::bind`], naming the tool for the record.
    pub fn bind_tool(&self, conn: ConnId, key: HookKey, tool: Option<String>) -> bool {
        let mut st = self.inner.lock();
        match st.conns.get_mut(&conn) {
            Some(o) if !o.done => {
                o.key = Some(key.clone());
                if tool.is_some() {
                    o.tool = tool;
                }
            }
            _ => return false,
        }
        let now = Instant::now();
        if !st.keys.contains_key(&key) {
            st.keys.insert(
                key.clone(),
                Slot {
                    outcome: None,
                    verdicts: 0,
                    at: now,
                    notify: Arc::new(Notify::new()),
                },
            );
            st.order.push_back(key);
            self.inner.added.notify_waiters();
        }
        st.prune(now);
        true
    }

    /// The verdict of `conn`, called once its `audit.append` is written.
    /// `allow` and `approved` settle its key as [`Waited::Allow`]; every
    /// other decision as [`Waited::Deny`].
    pub fn verdict(&self, conn: ConnId, decision: DecisionKind) {
        let mut st = self.inner.lock();
        let Some(o) = st.conns.get_mut(&conn) else {
            return;
        };
        if o.done {
            return;
        }
        o.done = true;
        if let Some(a) = o.overrun.take() {
            a.abort();
        }
        let Some(key) = o.key.clone() else {
            return;
        };
        let outcome = match decision {
            DecisionKind::Allow | DecisionKind::Approved => Waited::Allow,
            _ => Waited::Deny,
        };
        if let Some(slot) = st.keys.get_mut(&key) {
            slot.outcome = Some(outcome);
            slot.verdicts += 1;
            slot.notify.notify_waiters();
        }
    }

    /// The end of `conn` (every connection calls it; an untracked one is
    /// ignored).
    pub fn ended(&self, conn: ConnId) {
        let mut st = self.inner.lock();
        let Some(mut o) = st.conns.remove(&conn) else {
            return;
        };
        if let Some(a) = o.overrun.take() {
            a.abort();
        }
        if o.done {
            return;
        }
        self.inner.ended_without_verdict(st, o, false);
    }

    /// The verdict on `key`, waiting for it until `until` (tokio's clock).
    pub async fn wait(&self, key: &HookKey, until: Instant) -> Waited {
        loop {
            let notify = {
                let st = self.inner.lock();
                match st.keys.get(key) {
                    Some(Slot {
                        outcome: Some(o), ..
                    }) => return *o,
                    Some(s) => Arc::clone(&s.notify),
                    None => Arc::clone(&self.inner.added),
                }
            };
            let woken = notify.notified();
            tokio::pin!(woken);
            {
                // Every notify is sent under the lock: enabled here, no
                // change after this check is missed.
                let st = self.inner.lock();
                woken.as_mut().enable();
                match st.keys.get(key) {
                    Some(Slot {
                        outcome: Some(o), ..
                    }) => return *o,
                    Some(s) if Arc::ptr_eq(&s.notify, &notify) => {}
                    None if Arc::ptr_eq(&self.inner.added, &notify) => {}
                    _ => continue,
                }
            }
            if tokio::time::timeout_at(until, woken).await.is_err() {
                let st = self.inner.lock();
                return st
                    .keys
                    .get(key)
                    .and_then(|s| s.outcome)
                    .unwrap_or(Waited::Timeout);
            }
        }
    }

    /// Hooks without a verdict since the daemon started, and the `ts` of
    /// the last one.
    pub fn no_verdict_count(&self) -> (u64, Option<String>) {
        let st = self.inner.lock();
        (st.no_verdict, st.last_ts.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Seen = Arc<Mutex<Vec<NoVerdict>>>;

    fn table() -> (HookTable, Seen) {
        let seen: Seen = Arc::default();
        let s = Arc::clone(&seen);
        let t = HookTable::new(Box::new(move |nv| s.lock().unwrap().push(nv)));
        (t, seen)
    }

    fn peer() -> PeerCred {
        PeerCred {
            uid: 4242,
            gid: 4242,
            pid: 777,
            sid: None,
            group_sids: Vec::new(),
        }
    }

    fn key(n: usize) -> HookKey {
        HookKey {
            agent: "claude".into(),
            session: Some("c-1".into()),
            tool_use_id: Some(format!("toolu_{n}")),
            input_sha256: "ab".repeat(32),
        }
    }

    fn got(seen: &Seen) -> Vec<NoVerdict> {
        seen.lock().unwrap().clone()
    }

    /// Let spawned tasks run, with no time passing.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn verdict_then_end_writes_nothing() {
        let (t, seen) = table();
        assert!(t.begin(ConnId(1), &peer(), "claude", Some("PreToolUse")));
        assert!(t.bind(ConnId(1), key(1)));
        t.verdict(ConnId(1), DecisionKind::Allow);
        t.ended(ConnId(1));
        tokio::time::sleep(HOOK_OVERRUN + RECONNECT_GRACE * 2).await;
        assert!(got(&seen).is_empty());
        assert_eq!(t.no_verdict_count(), (0, None));
        let until = Instant::now() + Duration::from_secs(1);
        assert_eq!(t.wait(&key(1), until).await, Waited::Allow);
    }

    #[tokio::test(start_paused = true)]
    async fn end_without_verdict_writes_one_record() {
        let (t, seen) = table();
        t.begin(ConnId(1), &peer(), "claude", Some("PreToolUse"));
        assert!(t.bind_tool(ConnId(1), key(1), Some("Bash".into())));
        tokio::time::sleep(Duration::from_millis(250)).await;
        t.ended(ConnId(1));
        settle().await;
        assert!(got(&seen).is_empty(), "the grace comes first");
        tokio::time::sleep(RECONNECT_GRACE).await;
        settle().await;
        let all = got(&seen);
        assert_eq!(all.len(), 1);
        let nv = &all[0];
        assert_eq!(nv.elapsed_ms, 250);
        assert!(!nv.overrun);
        let r = no_verdict_record(nv, "locked", Some("alice".into()), "9.9.9");
        assert_eq!(r.kind.as_deref(), Some("hook"));
        assert_eq!(r.decision, DecisionKind::NoVerdict);
        assert_eq!(r.agent, "claude");
        assert_eq!(r.uid, Some(4242));
        assert_eq!(r.sid, None);
        assert_eq!(r.user.as_deref(), Some("alice"));
        assert_eq!(r.session.as_deref(), Some("c-1"));
        assert_eq!(r.tool, "Bash");
        assert_eq!(r.input, "");
        assert_eq!(r.mode.as_deref(), Some("locked"));
        assert_eq!(r.reason.as_deref(), Some(NO_VERDICT_REASON));
        assert_eq!(r.ts, nv.ts);
        assert_eq!(r.extra["event"], "no_verdict");
        assert_eq!(r.extra["bound"], true);
        assert_eq!(r.extra["tool_use_id"], "toolu_1");
        assert_eq!(r.extra["input_sha256"], "ab".repeat(32).as_str());
        assert_eq!(r.extra["elapsed_ms"], 250);
        assert_eq!(r.extra["pid"], 777);
        assert_eq!(r.extra["hook_event"], "PreToolUse");
        assert!(!r.extra.contains_key("overrun"));
        assert_eq!(t.no_verdict_count(), (1, Some(nv.ts.clone())));
        let until = Instant::now() + Duration::from_secs(1);
        assert_eq!(t.wait(&key(1), until).await, Waited::NoVerdict);
    }

    #[tokio::test(start_paused = true)]
    async fn unbound_end_writes_bound_false() {
        let (t, seen) = table();
        t.begin(ConnId(1), &peer(), "codex", None);
        t.ended(ConnId(1));
        // No grace without a key.
        let all = got(&seen);
        assert_eq!(all.len(), 1);
        let r = no_verdict_record(&all[0], "locked", None, "9.9.9");
        assert_eq!(r.extra["bound"], false);
        assert_eq!(r.extra["tool_use_id"], Value::Null);
        assert_eq!(r.extra["input_sha256"], Value::Null);
        assert_eq!(r.session, None);
        assert_eq!(r.tool, "");
        assert_eq!(r.agent, "codex");
        assert!(!r.extra.contains_key("hook_event"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_reconnect_append_is_not_no_verdict() {
        let (t, seen) = table();
        t.begin(ConnId(1), &peer(), "claude", None);
        t.bind(ConnId(1), key(1));
        t.ended(ConnId(1));
        let start = Instant::now();
        let waiter = async { t.wait(&key(1), start + Duration::from_secs(8)).await };
        let reconnect = async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert!(t.begin(ConnId(2), &peer(), "claude", None));
            assert!(t.bind(ConnId(2), key(1)));
            t.verdict(ConnId(2), DecisionKind::Allow);
            t.ended(ConnId(2));
        };
        let (w, ()) = tokio::join!(waiter, reconnect);
        assert_eq!(w, Waited::Allow);
        assert_eq!(start.elapsed(), Duration::from_secs(2), "woken at once");
        tokio::time::sleep(RECONNECT_GRACE * 2).await;
        settle().await;
        assert!(got(&seen).is_empty());
        assert_eq!(t.no_verdict_count().0, 0);
        assert_eq!(
            t.wait(&key(1), Instant::now() + Duration::from_secs(1))
                .await,
            Waited::Allow
        );
    }

    #[tokio::test(start_paused = true)]
    async fn grace_expires_into_no_verdict() {
        let (t, seen) = table();
        t.begin(ConnId(1), &peer(), "claude", None);
        t.bind(ConnId(1), key(1));
        t.ended(ConnId(1));
        let start = Instant::now();
        let w = t.wait(&key(1), start + Duration::from_secs(8)).await;
        assert_eq!(w, Waited::NoVerdict);
        assert_eq!(start.elapsed(), RECONNECT_GRACE);
        assert_eq!(got(&seen).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn overrun_is_closed_and_recorded() {
        let (t, seen) = table();
        let close = Arc::new(Notify::new());
        let start = Instant::now();
        assert!(t.begin_closing(ConnId(1), &peer(), "claude", None, Some(Arc::clone(&close))));
        t.bind(ConnId(1), key(1));
        close.notified().await;
        assert_eq!(start.elapsed(), HOOK_OVERRUN);
        // A late verdict is too late; the end after the close adds nothing.
        t.verdict(ConnId(1), DecisionKind::Allow);
        t.ended(ConnId(1));
        let w = t.wait(&key(1), start + Duration::from_secs(60)).await;
        assert_eq!(w, Waited::NoVerdict);
        assert_eq!(start.elapsed(), HOOK_OVERRUN + RECONNECT_GRACE);
        let all = got(&seen);
        assert_eq!(all.len(), 1);
        assert!(all[0].overrun);
        assert_eq!(all[0].elapsed_ms, 10_000);
        let r = no_verdict_record(&all[0], "locked", None, "9.9.9");
        assert_eq!(r.extra["overrun"], true);
    }

    #[tokio::test(start_paused = true)]
    async fn cli_connections_are_not_tracked() {
        let (t, seen) = table();
        // No begin: bind is refused, a verdict and the end are ignored.
        assert!(!t.bind(ConnId(1), key(1)));
        t.verdict(ConnId(1), DecisionKind::Allow);
        t.ended(ConnId(1));
        tokio::time::sleep(HOOK_OVERRUN * 2).await;
        assert!(got(&seen).is_empty());
        let start = Instant::now();
        let w = t.wait(&key(1), start + Duration::from_secs(1)).await;
        assert_eq!(w, Waited::Timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn second_begin_refused() {
        let (t, seen) = table();
        assert!(t.begin(ConnId(1), &peer(), "claude", None));
        assert!(!t.begin(ConnId(1), &peer(), "claude", None));
        assert!(t.begin(ConnId(2), &peer(), "claude", None));
        t.verdict(ConnId(1), DecisionKind::Deny);
        t.verdict(ConnId(2), DecisionKind::Deny);
        t.ended(ConnId(1));
        t.ended(ConnId(2));
        assert!(got(&seen).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn deny_and_other_decisions_settle_deny() {
        let (t, _seen) = table();
        for (n, d, w) in [
            (1, DecisionKind::Deny, Waited::Deny),
            (2, DecisionKind::ErrorDenied, Waited::Deny),
            (3, DecisionKind::Ask, Waited::Deny),
            (4, DecisionKind::Approved, Waited::Allow),
        ] {
            t.begin(ConnId(n as u64), &peer(), "claude", None);
            t.bind(ConnId(n as u64), key(n));
            t.verdict(ConnId(n as u64), d);
            let until = Instant::now() + Duration::from_secs(1);
            assert_eq!(t.wait(&key(n), until).await, w, "{d:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn table_is_bounded() {
        let (t, _seen) = table();
        for n in 0..=MAX_KEYS {
            let c = ConnId(n as u64);
            t.begin(c, &peer(), "claude", None);
            t.bind(c, key(n));
            t.verdict(c, DecisionKind::Allow);
            t.ended(c);
        }
        assert_eq!(t.inner.lock().keys.len(), MAX_KEYS);
        let start = Instant::now();
        let until = start + Duration::from_secs(3);
        assert_eq!(t.wait(&key(0), until).await, Waited::Timeout);
        assert_eq!(start.elapsed(), Duration::from_secs(3));
        assert_eq!(t.wait(&key(1), until).await, Waited::Allow);
    }

    #[tokio::test(start_paused = true)]
    async fn keys_expire_after_the_ttl() {
        let (t, _seen) = table();
        t.begin(ConnId(1), &peer(), "claude", None);
        t.bind(ConnId(1), key(1));
        t.verdict(ConnId(1), DecisionKind::Allow);
        tokio::time::sleep(VERDICT_TTL).await;
        // The next bind prunes it.
        t.begin(ConnId(2), &peer(), "claude", None);
        t.bind(ConnId(2), key(2));
        let until = Instant::now() + Duration::from_secs(1);
        assert_eq!(t.wait(&key(1), until).await, Waited::Timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn a_waiter_before_the_bind_sees_the_verdict() {
        let (t, _seen) = table();
        let start = Instant::now();
        let waiter = async { t.wait(&key(1), start + Duration::from_secs(8)).await };
        let hook = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            t.begin(ConnId(1), &peer(), "claude", None);
            t.bind(ConnId(1), key(1));
            tokio::time::sleep(Duration::from_millis(100)).await;
            t.verdict(ConnId(1), DecisionKind::Allow);
        };
        let (w, ()) = tokio::join!(waiter, hook);
        assert_eq!(w, Waited::Allow);
        assert_eq!(start.elapsed(), Duration::from_millis(400));
    }

    #[tokio::test(start_paused = true)]
    async fn status_counts_no_verdict() {
        let (t, _seen) = table();
        for n in 1..=3 {
            t.begin(ConnId(n), &peer(), "claude", None);
            t.ended(ConnId(n));
        }
        let (n, ts) = t.no_verdict_count();
        assert_eq!(n, 3);
        assert!(ts.is_some_and(|s| s.ends_with('Z')));
    }
}
