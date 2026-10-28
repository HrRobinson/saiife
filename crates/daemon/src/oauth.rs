//! The credentials the daemon holds for connector calls, in memory only,
//! never on disk, in a record, a log line or `Debug` output: OAuth2 access
//! tokens (plan 14, decision 8), and the cloud tokens and assumed-role
//! session credentials of plan 15 (decision 7). One cache, keyed by
//! `(secret, scope)`: the scope is `""` for oauth2, the manifest's `scope`
//! for `gcp_sa` and `azure_sp`, and `sts:<role_arn>` for a role that sign
//! mode assumes (decision 8). AWS keys used as they are come from the vault
//! on every call and are not cached.
//!
//! - A credential is fetched on first use, and again when it is older than
//!   its lifetime (`expires_in`, 15 min when absent; the STS expiry) minus
//!   60 s. An oauth2 token is also refreshed when the pipeline asks with
//!   `force` after an upstream 401.
//! - Fetches are single-flight per `(secret, scope)`: one `tokio` mutex per
//!   key, held across the fetch, so concurrent cold calls share one.
//! - oauth2: a rotated refresh token is written to the vault before the new
//!   access token is used. When that write fails, both stay in memory, the
//!   call is denied `vault_unavailable`, and the next call writes it again
//!   first.
//! - oauth2: a failed refresh starts a backoff: for [`BACKOFF_FIRST`],
//!   doubled with each failure up to [`BACKOFF_MAX`], calls get the stored
//!   failure and no token POST is made. A success or [`TokenCache::forget`]
//!   ends it.
//! - Cloud: a failed mint or assume is never cached: the next call tries
//!   again. The call is denied `token_mint_failed`.
//! - A failure is a `secret`/`refresh_failed` record (name, service,
//!   reason; never a body or an error description), one per oauth2 backoff
//!   window and one per failed cloud mint, and a `refresh_failed`
//!   notification, at most once per secret per hour.
//! - A fetch (POST, parse, persist) runs as its own task holding the key's
//!   lock, so a caller that goes away does not cut it short, and shutdown
//!   waits for it ([`TokenCache::drain`]). A rotated refresh token that
//!   still cannot be written is lost when the daemon stops; the recovery is
//!   `saiife secret rotate` with a freshly issued token.
//!
//! The single entry point is [`credential`], behind the pipeline's
//! `Env::credential`.

use crate::ops::Ctx;
use crate::vault::{Kind, VaultState};
use saiife_broker::cloud::sigv4::AwsCreds;
use saiife_broker::cloud::{jwt, sts, token, CloudError};
use saiife_broker::manifest::{AuthSpec, Manifest};
use saiife_broker::oauth2::{self, RefreshError};
use saiife_broker::pipeline::Cred;
use saiife_broker::upstream::Upstream;
use saiife_policy::ServiceCfg;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
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
/// The lifetime of a role sign mode assumes (decision 8).
pub const SIGN_ROLE_SECONDS: u32 = 3600;
/// The deny rule of a failed cloud mint or assume.
pub const MINT_FAILED: &str = "token_mint_failed";

/// One cache entry's key: the secret's name and the scope.
type Key = (String, String);

/// The credentials in use, by `(secret, scope)`.
#[derive(Default)]
pub struct TokenCache {
    slots: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<Slot>>>>,
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
        // Names and scopes only.
        f.debug_struct("TokenCache")
            .field("secrets", &lock(&self.slots).keys().collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Default)]
struct Slot {
    cached: Option<Cached>,
    /// A rotated refresh token the vault does not hold yet (oauth2).
    pending_refresh: Option<Pending>,
    /// The last refresh failed: when, why, and the backoff from then
    /// (oauth2; a failed cloud mint is never kept).
    failed: Option<(Instant, RefreshError, Duration)>,
}

/// The backoff after `prev` (none: the first failure).
fn next_backoff(prev: Option<Duration>) -> Duration {
    prev.map_or(BACKOFF_FIRST, |d| d.saturating_mul(2).min(BACKOFF_MAX))
}

/// A credential and when it was obtained; due at `ttl` minus 60 s
/// ([`oauth2::due`]).
struct Cached {
    cred: Arc<Cred>,
    obtained: Instant,
    ttl: Duration,
}

struct Pending {
    /// The refresh token it replaces (what the vault holds).
    prev: Zeroizing<String>,
    new: Zeroizing<String>,
}

/// What a call needs a credential for. Everything here is the manifest's
/// or the admin's: no agent input picks a scope, a role or an endpoint.
pub struct Want<'a> {
    pub secret: &'a str,
    pub service: &'a str,
    pub spec: &'a AuthSpec,
    pub manifest: &'a Manifest,
    pub svc: &'a ServiceCfg,
    /// Refresh even when the cached token looks fresh (after a 401),
    /// unless another call refreshed it while this one waited.
    pub force: bool,
}

/// Why there is no credential: the call's deny rule, and the
/// `refresh_failed` reason when a refresh or a mint failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub rule: &'static str,
    /// An oauth2 refresh failure.
    pub reason: Option<RefreshError>,
    /// A cloud mint or assume failure (`endpoint:<code>`, `network`,
    /// `bad_response`, `bad_key`).
    pub mint: Option<String>,
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
        mint: None,
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
        mint: None,
        fresh: true,
    }
}

/// The record reason of a failed mint or assume: the sanitized endpoint
/// code only (decision 18), never a message.
fn mint_reason(e: &CloudError) -> String {
    match e {
        CloudError::Endpoint { code } => format!("endpoint:{code}"),
        CloudError::Transport(_) => "network".into(),
        CloudError::Response(_) | CloudError::TooLarge => "bad_response".into(),
        CloudError::Key(_) | CloudError::Unrepresentable { .. } => "bad_key".into(),
    }
}

fn mint_failed(e: &CloudError) -> Failure {
    Failure {
        rule: MINT_FAILED,
        reason: None,
        mint: Some(mint_reason(e)),
        fresh: true,
    }
}

/// The vault kind that fills an auth entry the daemon holds or mints for.
fn kind_for(auth_kind: &str) -> Option<Kind> {
    match auth_kind {
        "oauth2" => Some(Kind::OAuth2),
        "aws_sigv4" => Some(Kind::Aws),
        "gcp_sa" => Some(Kind::GcpSa),
        "azure_sp" => Some(Kind::AzureSp),
        _ => None,
    }
}

/// The cache scope of `w` (decision 7), from the manifest and the service
/// config only. `None`: AWS keys used as they are (not cached).
fn scope_of(w: &Want<'_>) -> Result<Option<String>, Failure> {
    match w.spec.kind.as_str() {
        "oauth2" => Ok(Some(String::new())),
        "gcp_sa" | "azure_sp" => match w.spec.scope.as_deref() {
            Some(s) if !s.is_empty() => Ok(Some(s.to_string())),
            _ => Err(plain("policy_invalid")),
        },
        "aws_sigv4" => Ok(w.svc.cloud.role_arn.as_ref().map(|a| format!("sts:{a}"))),
        _ => Err(plain("secret_missing")),
    }
}

/// What a refresh task needs, owned (it outlives the caller's borrows).
struct Job {
    ctx: Arc<Ctx>,
    secret: String,
    service: String,
    scope: String,
    spec: AuthSpec,
    manifest: Manifest,
    svc: ServiceCfg,
    force: bool,
    asked: Instant,
}

/// The answer the slot gives without a refresh: the cached credential
/// while it is fresh, or the stored failure inside its backoff. `None`
/// when a rotated refresh token waits to be written (that comes first).
fn ready(s: &Slot, force: bool, asked: Instant) -> Option<Result<Arc<Cred>, Failure>> {
    if s.pending_refresh.is_some() {
        return None;
    }
    if let Some(c) = &s.cached {
        let fresh = !oauth2::due(c.obtained.elapsed(), c.ttl);
        // After a 401: a token another call got while this one waited is
        // new enough.
        if (!force && fresh) || (force && c.obtained > asked) {
            return Some(Ok(Arc::clone(&c.cred)));
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

/// The vault fields of `secret`: an entry of `kind` that serves `service`.
fn vault_fields(
    ctx: &Ctx,
    secret: &str,
    service: &str,
    kind: Kind,
) -> Result<BTreeMap<String, Zeroizing<String>>, Failure> {
    let g = ctx.vault.lock();
    let VaultState::Ready(v) = &*g else {
        return Err(plain("vault_unavailable"));
    };
    let e = v.get(secret).ok_or(plain("secret_missing"))?;
    if e.kind != kind {
        return Err(plain("secret_missing"));
    }
    if !e.allowed_services.iter().any(|s| s == service) {
        return Err(plain("secret_not_allowed_for_service"));
    }
    Ok(e.fields.clone())
}

/// The AWS keys of an `aws` secret's fields.
fn aws_keys(fields: &BTreeMap<String, Zeroizing<String>>) -> Result<AwsCreds, Failure> {
    let get = |n: &str| {
        fields
            .get(n)
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or(plain("secret_missing"))
    };
    Ok(AwsCreds {
        access_key_id: get("access_key_id")?,
        secret_access_key: get("secret_access_key")?,
        session_token: fields
            .get("session_token")
            .filter(|v| !v.is_empty())
            .cloned(),
    })
}

impl TokenCache {
    fn slot(&self, secret: &str, scope: &str) -> Arc<tokio::sync::Mutex<Slot>> {
        Arc::clone(
            lock(&self.slots)
                .entry((secret.to_string(), scope.to_string()))
                .or_default(),
        )
    }

    /// Drops what is held for `secret` (`secret rotate`/`remove`), in every
    /// scope, its backoff included. A refresh in flight finishes on the
    /// dropped entry; it never writes over the new vault value (see
    /// [`persist`]).
    pub fn forget(&self, secret: &str) {
        lock(&self.slots).retain(|(s, _), _| s != secret);
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

    /// The credential for `w`: the cached one while it is fresh, the
    /// stored failure during an oauth2 backoff, else a refresh or mint (one
    /// at a time per `(secret, scope)`, in its own task). AWS keys used as
    /// they are come from the vault.
    pub async fn get(&self, ctx: &Arc<Ctx>, w: &Want<'_>) -> Result<Arc<Cred>, Failure> {
        let Some(scope) = scope_of(w)? else {
            let fields = vault_fields(ctx, w.secret, w.service, Kind::Aws)?;
            return Ok(Arc::new(Cred::Aws(aws_keys(&fields)?)));
        };
        let asked = Instant::now();
        let s = self.slot(w.secret, &scope).lock_owned().await;
        if let Some(r) = ready(&s, w.force, asked) {
            return r;
        }
        let job = Job {
            ctx: Arc::clone(ctx),
            secret: w.secret.to_string(),
            service: w.service.to_string(),
            scope,
            spec: w.spec.clone(),
            manifest: w.manifest.clone(),
            svc: w.svc.clone(),
            force: w.force,
            asked,
        };
        // Detached: the refresh and the write of a rotated token finish
        // even when this caller is dropped, and shutdown waits for them.
        let flight = Flight::enter(&self.in_flight);
        tokio::spawn(async move {
            let _flight = flight;
            if job.spec.kind == "oauth2" {
                job.run(s).await
            } else {
                job.mint(s).await
            }
        })
        .await
        .unwrap_or_else(|_| Err(plain("vault_unavailable")))
    }
}

impl Job {
    /// An oauth2 refresh (plan 14).
    async fn run(self, mut s: tokio::sync::OwnedMutexGuard<Slot>) -> Result<Arc<Cred>, Failure> {
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

        let fields = vault_fields(ctx, &self.secret, &self.service, Kind::OAuth2)?;
        let used = fields
            .get("refresh_token")
            .cloned()
            .ok_or(plain("secret_missing"))?;
        let built = oauth2::token_request(&self.spec, &self.manifest, &self.svc.params, &fields)
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
        let cred = Arc::new(Cred::Bearer(tok.access));
        s.cached = Some(Cached {
            cred: Arc::clone(&cred),
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
        Ok(cred)
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

    /// A cloud mint (GCP, Azure) or a sign-mode `AssumeRole` (AWS). A
    /// failure is not kept: the next call tries again.
    async fn mint(self, mut s: tokio::sync::OwnedMutexGuard<Slot>) -> Result<Arc<Cred>, Failure> {
        if let Some(r) = ready(&s, false, self.asked) {
            return r;
        }
        s.cached = None;
        let kind = kind_for(&self.spec.kind).ok_or(plain("secret_missing"))?;
        let fields = vault_fields(&self.ctx, &self.secret, &self.service, kind)?;
        let up = self
            .ctx
            .upstream
            .as_ref()
            .map_err(|_| plain("upstream_unavailable"))?;
        let now = OffsetDateTime::now_utc();
        let got = match kind {
            Kind::GcpSa => self.gcp(up, &fields, now).await,
            Kind::AzureSp => self.azure(up, &fields).await,
            Kind::Aws => self.assume(up, aws_keys(&fields)?, now).await?,
            _ => return Err(plain("secret_missing")),
        };
        drop(fields);
        let (cred, ttl) = got.map_err(|e| mint_failed(&e))?;
        let cred = Arc::new(cred);
        s.cached = Some(Cached {
            cred: Arc::clone(&cred),
            obtained: Instant::now(),
            ttl,
        });
        Ok(cred)
    }

    async fn gcp(
        &self,
        up: &Upstream,
        fields: &BTreeMap<String, Zeroizing<String>>,
        now: OffsetDateTime,
    ) -> Result<(Cred, Duration), CloudError> {
        let key = jwt::parse_gcp_key(fields)?;
        let req = token::gcp_request(&key, &self.scope, now)?;
        drop(key);
        let t = token::mint(up, req).await?;
        Ok((Cred::Bearer(t.access), t.ttl))
    }

    async fn azure(
        &self,
        up: &Upstream,
        fields: &BTreeMap<String, Zeroizing<String>>,
    ) -> Result<(Cred, Duration), CloudError> {
        let req = token::azure_request(
            fields,
            self.svc.cloud.authority_host.as_deref(),
            &self.scope,
        )?;
        let t = token::mint(up, req).await?;
        Ok((Cred::Bearer(t.access), t.ttl))
    }

    /// Sign mode with `role_arn` (decision 8): `AssumeRole` with the vault
    /// keys, for [`SIGN_ROLE_SECONDS`], without a session policy, in the
    /// service's region.
    async fn assume(
        &self,
        up: &Upstream,
        base: AwsCreds,
        now: OffsetDateTime,
    ) -> Result<Result<(Cred, Duration), CloudError>, Failure> {
        let region = self
            .svc
            .params
            .get("region")
            .ok_or(plain("policy_invalid"))?;
        let role_arn = self
            .svc
            .cloud
            .role_arn
            .as_deref()
            .ok_or(plain("policy_invalid"))?;
        let p = sts::AssumeRole {
            role_arn,
            session_name: sts::session_name(self.ctx.own_uid),
            duration_s: SIGN_ROLE_SECONDS,
            policy: None,
            external_id: self.svc.cloud.external_id.as_deref(),
        };
        Ok(sts::assume(up, &base, region, &p, now)
            .await
            .map(|(creds, exp)| {
                let ttl = Duration::try_from(exp - now).unwrap_or(Duration::ZERO);
                (Cred::Aws(creds), ttl)
            }))
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

/// [`TokenCache::get`] for a connector call, with the failure recorded
/// (`secret`/`refresh_failed`) and notified (at most once per secret per
/// hour). The deny rule on failure.
pub async fn credential(ctx: &Arc<Ctx>, w: Want<'_>) -> Result<Arc<Cred>, &'static str> {
    match ctx.oauth.get(ctx, &w).await {
        Ok(c) => Ok(c),
        Err(f) => {
            // One record per failed attempt; none for the stored failure
            // returned during its backoff.
            if f.fresh {
                if let Some(e) = f.reason {
                    refresh_failed(ctx, &w, "oauth2 refresh failed", e.reason()).await;
                } else if let Some(reason) = f.mint {
                    refresh_failed(ctx, &w, "cloud credential mint failed", reason).await;
                }
            }
            Err(f.rule)
        }
    }
}

async fn refresh_failed(ctx: &Arc<Ctx>, w: &Want<'_>, what: &str, reason: String) {
    let mut r = ctx.record("secret", &format!("refresh_failed {}", w.secret));
    r.decision = saiife_audit::DecisionKind::Deny;
    r.reason = Some(format!("{what}: {reason}"));
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
            summary: crate::signals::clean(&format!("{what} for secret {} ({reason})", w.secret)),
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

    #[test]
    fn mint_reasons_hold_codes_only() {
        let e = CloudError::Endpoint {
            code: "invalid_grant".into(),
        };
        assert_eq!(mint_reason(&e), "endpoint:invalid_grant");
        assert_eq!(
            mint_reason(&CloudError::Response("a message".into())),
            "bad_response"
        );
        assert_eq!(mint_reason(&CloudError::TooLarge), "bad_response");
        assert_eq!(
            mint_reason(&CloudError::Transport(
                saiife_broker::BrokerError::RedirectRefused
            )),
            "network"
        );
        assert_eq!(mint_reason(&CloudError::Key("x".into())), "bad_key");
        let f = mint_failed(&e);
        assert_eq!(f.rule, MINT_FAILED);
        assert!(f.reason.is_none() && f.fresh);
    }

    #[test]
    fn forget_drops_every_scope_of_the_secret() {
        let c = TokenCache::default();
        let _ = c.slot("g", "https://a/.default");
        let _ = c.slot("g", "https://b/.default");
        let _ = c.slot("other", "");
        c.forget("g");
        let keys: Vec<Key> = lock(&c.slots).keys().cloned().collect();
        assert_eq!(keys, vec![("other".to_string(), String::new())]);
    }
}
