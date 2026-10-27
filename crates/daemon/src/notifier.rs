//! Notifications (spec §6.10.3, plan 11 decisions 9 and 10): webhook, SMTP
//! and command targets. `send` never blocks: events go into a queue of 256
//! (the oldest is dropped, counted and recorded when it is full) and one
//! delivery task works through it. A notification carries the request id,
//! service, operation, uid, host and a masked one-line summary; never a
//! secret, a body or a link that approves anything.
//!
//! Limits: at most one send per target per event kind per 60 s, except
//! `approval_created`. One immediate retry per delivery. Every outcome is a
//! `notify` record: `sent`, `failed` or `dropped`.

use crate::ops::Ctx;
use crate::vault::{Kind, VaultState};
use saiife_audit::Record;
use saiife_broker::mask::Masker;
use saiife_broker::request::Built;
use saiife_broker::upstream::Upstream;
use saiife_policy::{CommandCfg, Event, NotifyCfg, SmtpCfg, TargetCfg, WebhookCfg};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

/// Events held before the oldest is dropped.
pub const QUEUE: usize = 256;
/// One send per target per event kind in this window (not `approval_created`).
pub const RATE_WINDOW: Duration = Duration::from_secs(60);
/// A delivery attempt (webhook, command) takes at most this long.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// The summary is cut to this many characters.
pub const SUMMARY_MAX: usize = 200;

#[derive(Debug, Clone, PartialEq)]
pub struct NotifyEvent {
    pub event: Event,
    pub id: Option<u64>,
    pub service: Option<String>,
    pub operation: Option<String>,
    pub uid: Option<u32>,
    pub host: String,
    /// Masked, on one line and cut to [`SUMMARY_MAX`] characters before it
    /// leaves the daemon (the delivery task does it, so `send` stays cheap).
    pub summary: String,
}

impl NotifyEvent {
    fn payload(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("event".into(), self.event.as_str().into());
        if let Some(v) = self.id {
            m.insert("id".into(), v.into());
        }
        if let Some(v) = &self.service {
            m.insert("service".into(), v.clone().into());
        }
        if let Some(v) = &self.operation {
            m.insert("operation".into(), v.clone().into());
        }
        if let Some(v) = self.uid {
            m.insert("uid".into(), v.into());
        }
        m.insert("host".into(), self.host.clone().into());
        m.insert("summary".into(), self.summary.clone().into());
        Value::Object(m)
    }
}

/// A vault secret as the notifier reads it.
pub struct Secret {
    pub kind: Kind,
    pub fields: BTreeMap<String, Zeroizing<String>>,
}

impl Secret {
    fn field(&self, k: &str) -> Option<&str> {
        self.fields.get(k).map(|v| v.as_str())
    }
}

/// What delivery needs from the daemon.
pub trait Env: Send + Sync + 'static {
    /// The `[notify]` section in force.
    fn cfg(&self) -> NotifyCfg;
    fn secret(&self, name: &str) -> Option<Secret>;
    fn upstream(&self) -> Result<&Upstream, String>;
    /// A fresh `notify` record (policy hash, own uid), to be filled in.
    fn new_record(&self, input: &str) -> Record;
    /// Hands the record to the audit writer without waiting.
    fn append(&self, rec: Record);
}

impl Env for Ctx {
    fn cfg(&self) -> NotifyCfg {
        self.policy()
            .system
            .map(|s| s.notify.clone())
            .unwrap_or_default()
    }

    fn secret(&self, name: &str) -> Option<Secret> {
        let g = self.vault.lock();
        let VaultState::Ready(v) = &*g else {
            return None;
        };
        let e = v.get(name)?;
        Some(Secret {
            kind: e.kind,
            fields: e.fields.clone(),
        })
    }

    fn upstream(&self) -> Result<&Upstream, String> {
        self.upstream.as_ref().map_err(|e| e.clone())
    }

    fn new_record(&self, input: &str) -> Record {
        self.record("notify", input)
    }

    fn append(&self, rec: Record) {
        let w = self.writer.clone();
        tokio::spawn(async move {
            if let Err(e) = w.append(rec).await {
                eprintln!("saiife: warning: notify record not written: {e}");
            }
        });
    }
}

/// Who must own a command and its parents: root. A debug build can name
/// another owner (the test seam, like plan 10's CA owner); then only the
/// program and its directory are checked, as the test tree sits under a
/// home directory.
#[derive(Clone, Copy)]
struct Trust {
    owner: u32,
    whole_chain: bool,
}

struct Inner {
    queue: Mutex<VecDeque<NotifyEvent>>,
    wake: tokio::sync::Notify,
    dropped: Mutex<BTreeMap<Event, u64>>,
    dropped_total: AtomicU64,
    trust: Trust,
}

#[derive(Clone)]
pub struct Notifier {
    inner: Arc<Inner>,
}

impl Default for Notifier {
    fn default() -> Self {
        Notifier::new()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Notifier {
    pub fn new() -> Notifier {
        Notifier::with_trust(Trust {
            owner: 0,
            whole_chain: true,
        })
    }

    fn with_trust(trust: Trust) -> Notifier {
        Notifier {
            inner: Arc::new(Inner {
                queue: Mutex::new(VecDeque::new()),
                wake: tokio::sync::Notify::new(),
                dropped: Mutex::new(BTreeMap::new()),
                dropped_total: AtomicU64::new(0),
                trust,
            }),
        }
    }

    /// Debug builds only: commands owned by `uid` are trusted (the program
    /// and its directory are checked, not the parents above). A release
    /// build has no such seam.
    #[cfg(debug_assertions)]
    pub fn with_trusted_owner(uid: u32) -> Notifier {
        Notifier::with_trust(Trust {
            owner: uid,
            whole_chain: false,
        })
    }

    /// Queue `ev`; never blocks and never fails. A full queue drops its
    /// oldest event (counted, and recorded by the delivery task).
    pub fn send(&self, ev: NotifyEvent) {
        let mut q = lock(&self.inner.queue);
        if q.len() >= QUEUE {
            if let Some(old) = q.pop_front() {
                *lock(&self.inner.dropped).entry(old.event).or_default() += 1;
                self.inner.dropped_total.fetch_add(1, Ordering::Relaxed);
            }
        }
        q.push_back(ev);
        drop(q);
        self.inner.wake.notify_one();
    }

    /// Events dropped because the queue was full, since start.
    pub fn dropped(&self) -> u64 {
        self.inner.dropped_total.load(Ordering::Relaxed)
    }

    /// Events waiting for delivery.
    pub fn queued(&self) -> usize {
        lock(&self.inner.queue).len()
    }

    /// Starts the delivery task on the current runtime. It ends when `env`
    /// is gone.
    pub fn start<E: Env>(&self, env: Weak<E>) -> tokio::task::JoinHandle<()> {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(delivery(inner, env))
    }
}

fn cut(s: &str, max: usize) -> String {
    let one_line: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if one_line.chars().count() <= max {
        return one_line;
    }
    let mut t: String = one_line.chars().take(max - 1).collect();
    t.push('…');
    t
}

async fn delivery<E: Env>(inner: Arc<Inner>, env: Weak<E>) {
    let mut last_sent: HashMap<(String, Event), Instant> = HashMap::new();
    loop {
        let ev = lock(&inner.queue).pop_front();
        let Some(mut ev) = ev else {
            inner.wake.notified().await;
            continue;
        };
        // Masked here, off the caller's thread (the mask patterns compile
        // on first use); only masked text leaves this task.
        ev.summary = cut(&saiife_audit::mask::mask(&ev.summary), SUMMARY_MAX);
        let Some(env) = env.upgrade() else {
            return;
        };
        flush_dropped(&inner, &*env);
        let cfg = env.cfg();
        if !cfg.on.contains(&ev.event) {
            continue;
        }
        let mut set = JoinSet::new();
        for (name, target) in cfg.targets {
            if ev.event != Event::ApprovalCreated {
                let now = Instant::now();
                let key = (name.clone(), ev.event);
                if last_sent
                    .get(&key)
                    .is_some_and(|t| now.duration_since(*t) < RATE_WINDOW)
                {
                    env.append(notify_record(
                        &*env,
                        &ev,
                        &name,
                        "dropped",
                        Some("rate_limited"),
                    ));
                    continue;
                }
                last_sent.insert(key, now);
            }
            let env = Arc::clone(&env);
            let ev = ev.clone();
            let trust = inner.trust;
            set.spawn(async move {
                let r = deliver(&*env, &target, &ev, trust).await;
                let (result, reason) = match &r {
                    Ok(()) => ("sent", None),
                    Err(why) => ("failed", Some(why.as_str())),
                };
                env.append(notify_record(&*env, &ev, &name, result, reason));
            });
        }
        while set.join_next().await.is_some() {}
    }
}

/// One `dropped` record per event kind lost to a full queue since the last
/// flush, with the count.
fn flush_dropped(inner: &Inner, env: &dyn Env) {
    let drops = std::mem::take(&mut *lock(&inner.dropped));
    for (event, n) in drops {
        let mut r = env.new_record(&format!("notify {}", event.as_str()));
        r.extra.insert("event".into(), event.as_str().into());
        r.extra.insert("target".into(), "*".into());
        r.extra.insert("result".into(), "dropped".into());
        r.extra.insert("count".into(), n.into());
        r.reason = Some("queue_full".into());
        env.append(r);
    }
}

fn notify_record(
    env: &dyn Env,
    ev: &NotifyEvent,
    target: &str,
    result: &str,
    reason: Option<&str>,
) -> Record {
    let mut r = env.new_record(&format!("notify {} -> {target}", ev.event.as_str()));
    r.extra.insert("event".into(), ev.event.as_str().into());
    r.extra.insert("target".into(), target.into());
    r.extra.insert("result".into(), result.into());
    if let Some(id) = ev.id {
        r.extra.insert("approval".into(), id.into());
    }
    if let Some(s) = &ev.service {
        r.extra.insert("service".into(), s.clone().into());
    }
    if let Some(o) = &ev.operation {
        r.extra.insert("operation".into(), o.clone().into());
    }
    if let Some(reason) = reason {
        r.reason = Some(saiife_audit::mask::mask(reason));
    }
    r
}

/// Delivers `ev` to `target`, with one immediate retry of a transient
/// failure. `Err` is a one-line reason without secrets.
async fn deliver(
    env: &dyn Env,
    target: &TargetCfg,
    ev: &NotifyEvent,
    trust: Trust,
) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..2 {
        match attempt(env, target, ev, trust).await {
            Ok(()) => return Ok(()),
            Err(Fail::Permanent(why)) => return Err(why),
            Err(Fail::Transient(why)) => last = why,
        }
    }
    Err(last)
}

enum Fail {
    /// Retrying cannot help (configuration, trust).
    Permanent(String),
    Transient(String),
}

async fn attempt(
    env: &dyn Env,
    target: &TargetCfg,
    ev: &NotifyEvent,
    trust: Trust,
) -> Result<(), Fail> {
    match target {
        TargetCfg::Webhook(w) => webhook(env, w, ev).await,
        TargetCfg::Smtp(s) => smtp(env, s, ev).await,
        TargetCfg::Command(c) => command(c, ev, trust).await,
    }
}

async fn webhook(env: &dyn Env, w: &WebhookCfg, ev: &NotifyEvent) -> Result<(), Fail> {
    use Fail::*;
    let secret;
    let url: Zeroizing<String> = match (&w.url, &w.url_secret) {
        (Some(u), None) => Zeroizing::new(u.clone()),
        (None, Some(name)) => {
            secret = env
                .secret(name)
                .ok_or_else(|| Permanent(format!("secret {name} is not available")))?;
            let v = secret
                .field("token")
                .or_else(|| secret.field("value"))
                .ok_or_else(|| Permanent(format!("secret {name} holds no URL")))?;
            Zeroizing::new(v.to_string())
        }
        _ => return Err(Permanent("set exactly one of url and url_secret".into())),
    };
    // Whatever goes wrong, the URL (it may hold a token) stays out of the text.
    let masker = Masker::new(&[url.as_str()]);
    let clean = |e: String| masker.mask_text(&e);
    let uri: http::Uri = url
        .parse()
        .map_err(|_| Permanent("the webhook URL is not a valid URL".into()))?;
    let up = env.upstream().map_err(|e| Permanent(clean(e)))?;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    let body = serde_json::to_vec(&ev.payload()).unwrap_or_default();
    let built = Built {
        method: http::Method::POST,
        uri,
        headers,
        body: Some(bytes::Bytes::from(body)),
    };
    match tokio::time::timeout(TIMEOUT, up.send(built, 4096)).await {
        Err(_) => Err(Transient("the webhook timed out".into())),
        Ok(Err(e)) => Err(Transient(clean(e.to_string()))),
        Ok(Ok(r)) if (200..300).contains(&r.status) => Ok(()),
        // A redirect is an error `send` already made; any other status is a no.
        Ok(Ok(r)) => Err(Transient(format!("the webhook answered {}", r.status))),
    }
}

async fn smtp(env: &dyn Env, s: &SmtpCfg, ev: &NotifyEvent) -> Result<(), Fail> {
    use Fail::*;
    let secret = env
        .secret(&s.secret)
        .ok_or_else(|| Permanent(format!("secret {} is not available", s.secret)))?;
    if secret.kind != Kind::Basic {
        return Err(Permanent(format!(
            "secret {} must be of kind basic",
            s.secret
        )));
    }
    let (Some(user), Some(pass)) = (secret.field("username"), secret.field("password")) else {
        return Err(Permanent(format!(
            "secret {} lacks username or password",
            s.secret
        )));
    };
    let up = env.upstream().map_err(Permanent)?;
    let subject = format!("[saiife] {}", ev.event.as_str());
    let mut body = String::new();
    for (k, v) in [
        ("event", Some(ev.event.as_str().to_string())),
        ("request", ev.id.map(|i| i.to_string())),
        ("service", ev.service.clone()),
        ("operation", ev.operation.clone()),
        ("uid", ev.uid.map(|u| u.to_string())),
        ("host", Some(ev.host.clone())),
        ("summary", Some(ev.summary.clone())),
    ] {
        if let Some(v) = v {
            body.push_str(&format!("{k}: {v}\n"));
        }
    }
    let mail = crate::smtp::Mail {
        host: &s.host,
        port: s.port,
        starttls: s.starttls,
        from: &s.from,
        to: &s.to,
        user,
        password: pass,
        subject: &subject,
        body: &body,
    };
    let masker = Masker::new(&[user, pass]);
    crate::smtp::send(up.tls_connector(), up.resolver(), &mail)
        .await
        .map_err(|e| Transient(masker.mask_text(&e)))
}

/// `path` must be a regular file, not a symlink, owned by the trusted owner
/// and not writable by others, with the same true of every parent.
fn check_command(path: &Path, trust: Trust) -> Result<(), String> {
    if trust.whole_chain {
        saiife_system::fsops::root_owned_chain(path)?;
    } else {
        for p in [Some(path), path.parent()].into_iter().flatten() {
            let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
            if m.file_type().is_symlink() {
                return Err(format!("{}: is a symlink", p.display()));
            }
            if let Some(why) = saiife_system::fsops::root_owned_problems(&m, trust.owner)
                .into_iter()
                .next()
            {
                return Err(format!("{}: {why}", p.display()));
            }
        }
    }
    let m = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    Ok(())
}

async fn command(c: &CommandCfg, ev: &NotifyEvent, trust: Trust) -> Result<(), Fail> {
    use Fail::*;
    check_command(&c.path, trust)
        .map_err(|why| Permanent(format!("command refused, not root-owned: {why}")))?;
    let mut child = tokio::process::Command::new(&c.path)
        .env_clear()
        .current_dir("/")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| Permanent(format!("cannot run the command: {e}")))?;
    let mut stdin = child.stdin.take();
    let json = serde_json::to_vec(&ev.payload()).unwrap_or_default();
    let run = async {
        if let Some(mut si) = stdin.take() {
            // A program that does not read stdin closes it; that is its right.
            let _ = si.write_all(&json).await;
            let _ = si.write_all(b"\n").await;
            drop(si);
        }
        child.wait().await
    };
    match tokio::time::timeout(TIMEOUT, run).await {
        Err(_) => Err(Transient("the command timed out".into())),
        Ok(Err(e)) => Err(Transient(format!("the command failed: {e}"))),
        Ok(Ok(st)) if st.success() => Ok(()),
        Ok(Ok(st)) => Err(Transient(format!("the command exited with {st}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_is_one_line_and_cut() {
        assert_eq!(cut("a\nb\tc", 10), "a b c");
        let long = "x".repeat(500);
        let c = cut(&long, SUMMARY_MAX);
        assert_eq!(c.chars().count(), SUMMARY_MAX);
        assert!(c.ends_with('…'));
    }
}
