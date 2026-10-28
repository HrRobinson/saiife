//! OAuth2 access tokens (plan 14, decision 8): refreshed by the daemon from
//! the vault's refresh token and kept in memory only, never on disk, in a
//! record, a log line or `Debug` output.
//!
//! - A token is refreshed on first use, when it is older than its
//!   `expires_in` (15 min when absent) minus 60 s, and when the pipeline
//!   asks with `force` after an upstream 401.
//! - Refreshes are single-flight per secret: one `tokio` mutex per secret,
//!   held across the refresh, so concurrent cold calls share one.
//! - A rotated refresh token is written to the vault before the new access
//!   token is used. When that write fails, both stay in memory, the call is
//!   denied `vault_unavailable`, and the next call writes it again first.
//! - A failed refresh starts a backoff: for [`BACKOFF_FIRST`], doubled with
//!   each failure up to [`BACKOFF_MAX`], calls get the stored failure and no
//!   token POST is made. A success or [`TokenCache::forget`] ends it.
//! - A failure is a `secret`/`refresh_failed` record (name, service, reason;
//!   never a body), one per backoff window, and a `refresh_failed`
//!   notification, at most once per secret per hour.
//! - A refresh (POST, parse, persist) runs as its own task holding the
//!   secret's lock, so a caller that goes away does not cut it short, and
//!   shutdown waits for it ([`TokenCache::drain`]). A rotated refresh token
//!   that still cannot be written is lost when the daemon stops; the
//!   recovery is `saiife secret rotate` with a freshly issued token.
//!
//! Plan 15 moves this behind a general credential hook; this module keeps
//! to the one cache and the one entry point ([`access_token`]).

use crate::ops::Ctx;
use crate::vault::{Kind, VaultState};
use saiife_broker::manifest::{AuthSpec, Manifest};
use saiife_broker::oauth2::{self, RefreshError};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// At most one `refresh_failed` notification per secret this often.
pub const NOTIFY_EVERY: Duration = Duration::from_secs(3600);
/// No token POST for this long after a failed refresh; doubled with each
/// failure in a row.
pub const BACKOFF_FIRST: Duration = Duration::from_secs(5);
/// The longest backoff.
pub const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// How long shutdown waits for the refreshes in flight.
pub const DRAIN: Duration = Duration::from_secs(5);

/// The access tokens of the `oauth2` secrets in use, by secret name.
#[derive(Default)]
pub struct TokenCache {
    slots: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Slot>>>>,
    notified: Mutex<HashMap<String, Instant>>,
    /// Refresh tasks running.
    in_flight: Arc<AtomicUsize>,
}

/// One refresh task counted in [`TokenCache::in_flight`] until dropped.
struct Flight(Arc<AtomicUsize>);

impl Flight {
    fn enter(n: &Arc<AtomicUsize>) -> Flight {
        n.fetch_add(1, Ordering::SeqCst);
        Flight(Arc::clone(n))
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenCache")
            .field("secrets", &lock(&self.slots).keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Default)]
struct Slot {
    cached: Option<Cached>,
    /// A rotated refresh token the vault does not hold yet.
    pending_refresh: Option<Pending>,
    /// The last refresh failed: when, why, and the backoff from then.
    failed: Option<(Instant, RefreshError, Duration)>,
}

/// The backoff after `prev` (none: the first failure).
fn next_backoff(prev: Option<Duration>) -> Duration {
    prev.map_or(BACKOFF_FIRST, |d| d.saturating_mul(2).min(BACKOFF_MAX))
}

struct Cached {
    access: Zeroizing<String>,
    obtained: Instant,
    ttl: Duration,
}

struct Pending {
    /// The refresh token it replaces (what the vault holds).
    prev: Zeroizing<String>,
    new: Zeroizing<String>,
}

/// What a call needs a token for.
pub struct Want<'a> {
    pub secret: &'a str,
    pub service: &'a str,
    pub spec: &'a AuthSpec,
    pub manifest: &'a Manifest,
    pub svc_params: &'a BTreeMap<String, String>,
    /// Refresh even when the cached token looks fresh (after a 401),
    /// unless another call refreshed it while this one waited.
    pub force: bool,
}

/// Why there is no token: the call's deny rule, and the `refresh_failed`
/// reason when a refresh failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub rule: &'static str,
    pub reason: Option<RefreshError>,
    /// A failure of this call's own attempt, to be recorded; `false` for
    /// the stored failure returned during a backoff.
    pub fresh: bool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn plain(rule: &'static str) -> Failure {
    Failure {
        rule,
        reason: None,
        fresh: true,
    }
}

fn refresh(e: RefreshError) -> Failure {
    Failure {
        rule: if e == RefreshError::Persist {
            "vault_unavailable"
        } else {
            "refresh_failed"
        },
        reason: Some(e),
        fresh: true,
    }
}

/// What a refresh task needs, owned (it outlives the caller's borrows).
struct Job {
    ctx: Arc<Ctx>,
    secret: String,
    service: String,
    spec: AuthSpec,
    manifest: Manifest,
    svc_params: BTreeMap<String, String>,
    force: bool,
    asked: Instant,
}

/// The answer the slot gives without a refresh: the cached token while it
/// is fresh, or the stored failure inside its backoff. `None` when a
/// rotated refresh token waits to be written (that comes first).
fn ready(s: &Slot, force: bool, asked: Instant) -> Option<Result<Zeroizing<String>, Failure>> {
    if s.pending_refresh.is_some() {
        return None;
    }
    if let Some(c) = &s.cached {
        let fresh = !oauth2::due(c.obtained.elapsed(), c.ttl);
        // After a 401: a token another call got while this one waited is
        // new enough.
        if (!force && fresh) || (force && c.obtained > asked) {
            return Some(Ok(c.access.clone()));
        }
    }
    if let Some((at, e, window)) = s.failed {
        if at.elapsed() < window {
            let mut f = refresh(e);
            f.fresh = false;
            return Some(Err(f));
        }
    }
    None
}

/// Tells the admin on stderr (the name only) that the daemon holds the
/// only copy of a rotated refresh token.
fn warn_not_persisted(secret: &str) {
    eprintln!(
        "saiifed: warning: {secret}: rotated refresh token not persisted; do not restart the daemon"
    );
}

impl TokenCache {
    fn slot(&self, secret: &str) -> Arc<tokio::sync::Mutex<Slot>> {
        Arc::clone(lock(&self.slots).entry(secret.to_string()).or_default())
    }

    /// Drops what is held for `secret` (`secret rotate`/`remove`), its
    /// backoff included. A refresh in flight finishes on the dropped entry;
    /// it never writes over the new vault value (see [`persist`]).
    pub fn forget(&self, secret: &str) {
        lock(&self.slots).remove(secret);
    }

    /// Refresh tasks running now.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Waits until no refresh task runs, at most `max` (shutdown, before
    /// the runtime is dropped). `false` when some still ran.
    pub async fn drain(&self, max: Duration) -> bool {
        let end = Instant::now() + max;
        while self.in_flight() > 0 {
            if Instant::now() >= end {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    /// `true` at most once per secret per [`NOTIFY_EVERY`].
    pub fn notify_due(&self, secret: &str, now: Instant) -> bool {
        let mut m = lock(&self.notified);
        match m.get(secret) {
            Some(t) if now.saturating_duration_since(*t) < NOTIFY_EVERY => false,
            _ => {
                m.insert(secret.to_string(), now);
                true
            }
        }
    }

    /// The access token for `w`: the cached one while it is fresh, the
    /// stored failure during a backoff, else a refresh (one at a time per
    /// secret, in its own task).
    pub async fn token(&self, ctx: &Arc<Ctx>, w: &Want<'_>) -> Result<Zeroizing<String>, Failure> {
        let asked = Instant::now();
        let s = self.slot(w.secret).lock_owned().await;
        if let Some(r) = ready(&s, w.force, asked) {
            return r;
        }
        let job = Job {
            ctx: Arc::clone(ctx),
            secret: w.secret.to_string(),
            service: w.service.to_string(),
            spec: w.spec.clone(),
            manifest: w.manifest.clone(),
            svc_params: w.svc_params.clone(),
            force: w.force,
            asked,
        };
        // Detached: the refresh and the write of a rotated token finish
        // even when this caller is dropped, and shutdown waits for them.
        let flight = Flight::enter(&self.in_flight);
        tokio::spawn(async move {
            let _flight = flight;
            job.run(s).await
        })
        .await
        .unwrap_or_else(|_| Err(plain("vault_unavailable")))
    }
}

impl Job {
    async fn run(
        self,
        mut s: tokio::sync::OwnedMutexGuard<Slot>,
    ) -> Result<Zeroizing<String>, Failure> {
        let ctx = &self.ctx;
        // A rotated refresh token the vault does not hold yet goes there
        // first: until it does, no token from that refresh is used.
        if let Some(p) = &s.pending_refresh {
            match persist(ctx, &self.secret, &p.prev, &p.new).await {
                Ok(true) => s.pending_refresh = None,
                Ok(false) => {
                    *s = Slot::default();
                    return Err(plain("secret_missing"));
                }
                Err(()) => {
                    warn_not_persisted(&self.secret);
                    return Err(refresh(RefreshError::Persist));
                }
            }
        }
        if let Some(r) = ready(&s, self.force, self.asked) {
            return r;
        }
        s.cached = None;

        let fields = self.read_fields()?;
        let used = fields
            .get("refresh_token")
            .cloned()
            .ok_or(plain("secret_missing"))?;
        let built = oauth2::token_request(&self.spec, &self.manifest, &self.svc_params, &fields)
            .map_err(|_| plain("policy_invalid"))?;
        drop(fields);
        if self.ctx.upstream.is_err() {
            return Err(plain("upstream_unavailable"));
        }
        let tok = match self.post(built).await {
            Ok(t) => {
                s.failed = None;
                t
            }
            Err(e) => {
                let prev = s.failed.map(|(_, _, d)| d);
                s.failed = Some((Instant::now(), e, next_backoff(prev)));
                return Err(refresh(e));
            }
        };
        s.cached = Some(Cached {
            access: tok.access.clone(),
            obtained: Instant::now(),
            ttl: tok.ttl,
        });
        if let Some(new) = tok.refresh.filter(|r| **r != *used) {
            let prev = used.clone();
            s.pending_refresh = Some(Pending {
                prev: used,
                new: new.clone(),
            });
            match persist(ctx, &self.secret, &prev, &new).await {
                Ok(true) => s.pending_refresh = None,
                Ok(false) => {
                    // Rotated or removed by the admin meanwhile: nothing
                    // from the old credential is kept or used.
                    *s = Slot::default();
                    return Err(plain("secret_missing"));
                }
                Err(()) => {
                    warn_not_persisted(&self.secret);
                    return Err(refresh(RefreshError::Persist));
                }
            }
        }
        Ok(tok.access)
    }

    /// Sends the token request and parses the answer.
    async fn post(
        &self,
        built: saiife_broker::request::Built,
    ) -> Result<oauth2::Token, RefreshError> {
        let host = built.uri.host().unwrap_or_default().to_string();
        let up = self
            .ctx
            .upstream
            .as_ref()
            .map_err(|_| RefreshError::Network)?;
        let resp = up
            .send(built, oauth2::MAX_RESPONSE)
            .await
            .map_err(|_| RefreshError::Network)?;
        if resp.status != 200 {
            return Err(RefreshError::Http(resp.status));
        }
        if resp.truncated {
            return Err(RefreshError::BadResponse);
        }
        oauth2::parse_token(&resp.body, &host, oauth2::instance_required(&self.manifest))
    }

    /// The vault fields of the call's secret: an `oauth2` secret that
    /// serves the service.
    fn read_fields(&self) -> Result<BTreeMap<String, Zeroizing<String>>, Failure> {
        let g = self.ctx.vault.lock();
        let VaultState::Ready(v) = &*g else {
            return Err(plain("vault_unavailable"));
        };
        let e = v.get(&self.secret).ok_or(plain("secret_missing"))?;
        if e.kind != Kind::OAuth2 {
            return Err(plain("secret_missing"));
        }
        if !e.allowed_services.contains(&self.service) {
            return Err(plain("secret_not_allowed_for_service"));
        }
        Ok(e.fields.clone())
    }
}

/// Writes `new` as the refresh token of `secret` when the vault still
/// holds `prev` (compare and set, under the vault's one writer, off the
/// runtime thread). `Ok(false)`: the secret changed or is gone, nothing
/// written. `Err`: the write failed.
async fn persist(
    ctx: &Arc<Ctx>,
    secret: &str,
    prev: &Zeroizing<String>,
    new: &Zeroizing<String>,
) -> Result<bool, ()> {
    let (c, name, prev, new) = (
        Arc::clone(ctx),
        secret.to_string(),
        prev.clone(),
        new.clone(),
    );
    tokio::task::spawn_blocking(move || {
        let mut w = c.vault.writer();
        let entry = {
            let g = w.lock();
            let VaultState::Ready(v) = &*g else {
                return Err(());
            };
            match v.get(&name) {
                Some(e)
                    if e.kind == Kind::OAuth2
                        && e.fields.get("refresh_token").map(|r| r.as_str())
                            == Some(prev.as_str()) =>
                {
                    let mut e = e.clone();
                    e.fields.insert("refresh_token".into(), new);
                    e
                }
                _ => return Ok(false),
            }
        };
        w.put(entry).map(|()| true).map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

/// [`TokenCache::token`] for a connector call, with the failure recorded
/// (`secret`/`refresh_failed`) and notified (at most once per secret per
/// hour). The deny rule on failure.
pub async fn access_token(ctx: &Arc<Ctx>, w: Want<'_>) -> Result<Zeroizing<String>, &'static str> {
    match ctx.oauth.token(ctx, &w).await {
        Ok(t) => Ok(t),
        Err(f) => {
            // One record per failed attempt; none for the stored failure
            // returned during its backoff.
            if let (Some(e), true) = (f.reason, f.fresh) {
                refresh_failed(ctx, &w, e).await;
            }
            Err(f.rule)
        }
    }
}

async fn refresh_failed(ctx: &Arc<Ctx>, w: &Want<'_>, e: RefreshError) {
    let reason = e.reason();
    let mut r = ctx.record("secret", &format!("refresh_failed {}", w.secret));
    r.decision = saiife_audit::DecisionKind::Deny;
    r.reason = Some(format!("oauth2 refresh failed: {reason}"));
    r.extra.insert("event".into(), "refresh_failed".into());
    r.extra.insert("name".into(), w.secret.into());
    r.extra.insert("service".into(), w.service.into());
    r.extra.insert("reason".into(), reason.clone().into());
    if let Err(err) = ctx.writer.append(r).await {
        eprintln!("saiifed: warning: cannot write a refresh_failed record: {err}");
    }
    if ctx.oauth.notify_due(w.secret, Instant::now()) {
        ctx.notifier.send(crate::notifier::NotifyEvent {
            event: saiife_policy::Event::RefreshFailed,
            id: None,
            service: Some(w.service.to_string()),
            operation: None,
            uid: None,
            host: crate::signals::hostname(),
            summary: crate::signals::clean(&format!(
                "oauth2 refresh failed for secret {} ({reason})",
                w.secret
            )),
            reason: Some(reason),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_at_most_once_per_secret_per_hour() {
        let c = TokenCache::default();
        let t0 = Instant::now();
        assert!(c.notify_due("sf", t0));
        assert!(!c.notify_due("sf", t0 + Duration::from_secs(10)));
        assert!(!c.notify_due("sf", t0 + Duration::from_secs(3599)));
        assert!(c.notify_due("other", t0 + Duration::from_secs(10)));
        assert!(c.notify_due("sf", t0 + Duration::from_secs(3600)));
        assert!(!c.notify_due("sf", t0 + Duration::from_secs(3601)));
    }

    #[test]
    fn failures_name_their_rule() {
        assert_eq!(refresh(RefreshError::Persist).rule, "vault_unavailable");
        assert_eq!(refresh(RefreshError::Http(400)).rule, "refresh_failed");
        assert_eq!(plain("secret_missing").reason, None);
    }

    #[test]
    fn backoff_doubles_to_five_minutes() {
        let mut d = next_backoff(None);
        assert_eq!(d, Duration::from_secs(5));
        let mut seen = vec![d];
        for _ in 0..8 {
            d = next_backoff(Some(d));
            seen.push(d);
        }
        let secs: Vec<u64> = seen.iter().map(|d| d.as_secs()).collect();
        assert_eq!(secs, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
    }

    #[test]
    fn stored_failure_inside_its_window_only() {
        let now = Instant::now();
        let mut s = Slot {
            failed: Some((now, RefreshError::Http(400), Duration::from_secs(60))),
            ..Slot::default()
        };
        let f = ready(&s, false, now).unwrap().unwrap_err();
        assert_eq!(f.rule, "refresh_failed");
        assert_eq!(f.reason, Some(RefreshError::Http(400)));
        assert!(!f.fresh, "a stored failure is not recorded again");
        s.failed = Some((
            now - Duration::from_secs(61),
            RefreshError::Http(400),
            Duration::from_secs(60),
        ));
        assert!(ready(&s, false, now).is_none());
    }
}
