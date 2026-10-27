//! Producers of notifications (spec §6.10.3, plan 11 task 10): the small
//! in-memory state that decides when an event is worth sending, and the
//! helpers the daemon's other modules call. Every summary is masked and
//! one line; never a parameter, a body or a secret.

use crate::notifier::{NotifyEvent, SUMMARY_MAX};
use crate::ops::Ctx;
use saiife_policy::Event;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `error_denied` records from one uid in this window make a burst...
pub const BURST_WINDOW: Duration = Duration::from_secs(60);
/// ...this many of them...
pub const BURST_COUNT: usize = 10;
/// ...and at most one notification per uid in this long.
pub const BURST_QUIET: Duration = Duration::from_secs(600);

const MAX_KEYS: usize = 4096;

#[derive(Default)]
struct Burst {
    hits: VecDeque<Instant>,
    last_sent: Option<Instant>,
}

/// State behind the `limit_reached` and `error_denied_burst` producers.
#[derive(Default)]
pub struct Signals {
    limits: Mutex<HashMap<(u32, String, String), Instant>>,
    bursts: Mutex<HashMap<u32, Burst>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// How long a limit stays "already announced": its own window.
pub fn window_of(limit: &str) -> Duration {
    match limit {
        "writes_per_hour" => Duration::from_secs(3600),
        "deletes_per_day" | "amount_per_day" | "bulk_per_session" => Duration::from_secs(86_400),
        _ => Duration::from_secs(60),
    }
}

impl Signals {
    /// Whether (`uid`, `service`, `limit`) is the first in its window.
    pub fn limit_due(&self, uid: u32, service: &str, limit: &str, now: Instant) -> bool {
        let mut m = lock(&self.limits);
        let key = (uid, service.to_string(), limit.to_string());
        let w = window_of(limit);
        if m.get(&key).is_some_and(|at| now.duration_since(*at) < w) {
            return false;
        }
        if m.len() >= MAX_KEYS {
            m.retain(|(_, _, l), at| now.duration_since(*at) < window_of(l));
        }
        if m.len() < MAX_KEYS {
            m.insert(key, now);
        }
        true
    }

    /// Counts one `error_denied` of `uid`; true when it completes a burst
    /// that has not been announced in the last [`BURST_QUIET`].
    pub fn burst_due(&self, uid: u32, now: Instant) -> bool {
        let mut m = lock(&self.bursts);
        if m.len() >= MAX_KEYS && !m.contains_key(&uid) {
            m.retain(|_, b| {
                b.hits
                    .back()
                    .is_some_and(|t| now.duration_since(*t) < BURST_WINDOW)
                    || b.last_sent
                        .is_some_and(|t| now.duration_since(t) < BURST_QUIET)
            });
            if m.len() >= MAX_KEYS {
                return false;
            }
        }
        let b = m.entry(uid).or_default();
        while b
            .hits
            .front()
            .is_some_and(|t| now.duration_since(*t) >= BURST_WINDOW)
        {
            b.hits.pop_front();
        }
        b.hits.push_back(now);
        if b.hits.len() < BURST_COUNT {
            return false;
        }
        if b.last_sent
            .is_some_and(|t| now.duration_since(t) < BURST_QUIET)
        {
            return false;
        }
        b.last_sent = Some(now);
        b.hits.clear();
        true
    }
}

fn hostname() -> String {
    static HOST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOST.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".into())
    })
    .clone()
}

/// Masked, one line, at most [`SUMMARY_MAX`] characters.
pub fn clean(s: &str) -> String {
    saiife_audit::mask::mask(s)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(SUMMARY_MAX)
        .collect()
}

impl Ctx {
    /// Queue a notification (never blocks, never fails).
    pub fn notify(
        &self,
        event: Event,
        id: Option<u64>,
        service: Option<&str>,
        operation: Option<&str>,
        uid: Option<u32>,
        summary: &str,
    ) {
        self.notifier.send(NotifyEvent {
            event,
            id,
            service: service.map(str::to_string),
            operation: operation.map(str::to_string),
            uid,
            host: hostname(),
            summary: clean(summary),
        });
    }

    /// `limit_reached`, the first per window per (uid, service, limit).
    pub fn notify_limit(&self, uid: u32, service: &str, operation: &str, limit: &str) {
        if self.signals.limit_due(uid, service, limit, Instant::now()) {
            self.notify(
                Event::LimitReached,
                None,
                Some(service),
                Some(operation),
                Some(uid),
                &format!("limit reached: {limit} ({service} {operation})"),
            );
        }
    }

    /// `error_denied_burst`: called for each `error_denied` guard record.
    pub fn note_error_denied(&self, uid: u32) {
        if self.signals.burst_due(uid, Instant::now()) {
            self.notify(
                Event::ErrorDeniedBurst,
                None,
                None,
                None,
                Some(uid),
                &format!(
                    "{BURST_COUNT} or more error_denied guard records from uid {uid} within {}s",
                    BURST_WINDOW.as_secs()
                ),
            );
        }
    }

    /// `chain_break`: the start-time chain check failed.
    pub fn notify_chain_break(&self, detail: &str) {
        self.notify(
            Event::ChainBreak,
            None,
            None,
            None,
            None,
            &format!("audit chain check failed at start: {detail}"),
        );
    }
}
