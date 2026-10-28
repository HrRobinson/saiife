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
//! - A failure is a `secret`/`refresh_failed` record (name, service, reason;
//!   never a body) and a `refresh_failed` notification, at most once per
//!   secret per hour.
//!
//! Plan 15 moves this behind a general credential hook; this module keeps
//! to the one cache and the one entry point ([`access_token`]).

use crate::ops::Ctx;
use crate::vault::{Kind, VaultState};
use saiife_broker::manifest::{AuthSpec, Manifest};
use saiife_broker::oauth2::{self, RefreshError};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// At most one `refresh_failed` notification per secret this often.
pub const NOTIFY_EVERY: Duration = Duration::from_secs(3600);

/// The access tokens of the `oauth2` secrets in use, by secret name.
#[derive(Default)]
pub struct TokenCache {
    slots: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Slot>>>>,
    notified: Mutex<HashMap<String, Instant>>,
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
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn plain(rule: &'static str) -> Failure {
    Failure { rule, reason: None }
}

fn refresh(e: RefreshError) -> Failure {
    Failure {
        rule: if e == RefreshError::Persist {
            "vault_unavailable"
        } else {
            "refresh_failed"
        },
        reason: Some(e),
    }
}

impl TokenCache {
    fn slot(&self, secret: &str) -> Arc<tokio::sync::Mutex<Slot>> {
        Arc::clone(lock(&self.slots).entry(secret.to_string()).or_default())
    }

    /// Drops what is held for `secret` (`secret rotate`/`remove`). A
    /// refresh in flight finishes on the dropped entry; it never writes over
    /// the new vault value (see [`persist`]).
    pub fn forget(&self, secret: &str) {
        lock(&self.slots).remove(secret);
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

    /// The access token for `w`: the cached one while it is fresh, else a
    /// refresh (one at a time per secret).
    pub async fn token(&self, ctx: &Arc<Ctx>, w: &Want<'_>) -> Result<Zeroizing<String>, Failure> {
        let asked = Instant::now();
        let slot = self.slot(w.secret);
        let mut s = slot.lock().await;

        // A rotated refresh token the vault does not hold yet goes there
        // first: until it does, no token from that refresh is used.
        if let Some(p) = &s.pending_refresh {
            match persist(ctx, w.secret, &p.prev, &p.new).await {
                Ok(true) => s.pending_refresh = None,
                Ok(false) => {
                    *s = Slot::default();
                    return Err(plain("secret_missing"));
                }
                Err(()) => return Err(refresh(RefreshError::Persist)),
            }
        }
        if let Some(c) = &s.cached {
            let fresh = !oauth2::due(c.obtained.elapsed(), c.ttl);
            // After a 401: a token another call got while this one waited
            // is new enough.
            if (!w.force && fresh) || (w.force && c.obtained > asked) {
                return Ok(c.access.clone());
            }
        }
        s.cached = None;

        let fields = read_fields(ctx, w)?;
        let used = fields
            .get("refresh_token")
            .cloned()
            .ok_or(plain("secret_missing"))?;
        let built = oauth2::token_request(w.spec, w.manifest, w.svc_params, &fields)
            .map_err(|_| plain("policy_invalid"))?;
        drop(fields);
        let host = built.uri.host().unwrap_or_default().to_string();
        let up = ctx
            .upstream
            .as_ref()
            .map_err(|_| plain("upstream_unavailable"))?;
        let resp = up
            .send(built, oauth2::MAX_RESPONSE)
            .await
            .map_err(|_| refresh(RefreshError::Network))?;
        if resp.status != 200 {
            return Err(refresh(RefreshError::Http(resp.status)));
        }
        if resp.truncated {
            return Err(refresh(RefreshError::BadResponse));
        }
        let tok = oauth2::parse_token(&resp.body, &host).map_err(refresh)?;
        drop(resp);
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
            match persist(ctx, w.secret, &prev, &new).await {
                Ok(true) => s.pending_refresh = None,
                Ok(false) => {
                    // Rotated or removed by the admin meanwhile: nothing
                    // from the old credential is kept or used.
                    *s = Slot::default();
                    return Err(plain("secret_missing"));
                }
                Err(()) => return Err(refresh(RefreshError::Persist)),
            }
        }
        Ok(tok.access)
    }
}

/// The vault fields of the call's secret: an `oauth2` secret that serves
/// the service.
fn read_fields(ctx: &Ctx, w: &Want<'_>) -> Result<BTreeMap<String, Zeroizing<String>>, Failure> {
    let g = ctx.vault.lock();
    let VaultState::Ready(v) = &*g else {
        return Err(plain("vault_unavailable"));
    };
    let e = v.get(w.secret).ok_or(plain("secret_missing"))?;
    if e.kind != Kind::OAuth2 {
        return Err(plain("secret_missing"));
    }
    if !e.allowed_services.iter().any(|s| s == w.service) {
        return Err(plain("secret_not_allowed_for_service"));
    }
    Ok(e.fields.clone())
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
            if let Some(e) = f.reason {
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
}
