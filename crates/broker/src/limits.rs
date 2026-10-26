//! Sliding-window rate, blast-radius and amount limits (spec §6.9.2, §6.9.4).
//! Counts requests that were sent upstream. Check and reserve happen under
//! one lock; a `Reservation` is committed once the request was sent.

use crate::amount::exponent;
use crate::manifest::OpKind;
use saiife_policy::LimitsCfg;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

const DAY: i64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub uid: u32,
    pub service: String,
    pub session: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub at: OffsetDateTime,
    pub key: Key,
    pub kind: OpKind,
    pub amount_minor: Option<(u64, String)>,
}

struct Entry {
    id: u64,
    ev: Event,
}

/// The (uid, service) bucket an event counts in; the session bucket is
/// the part of it with the same session.
type BucketKey = (u32, String);

/// Every this many checks, buckets nobody asked about lately are pruned.
const SWEEP_EVERY: u64 = 1024;

#[derive(Default)]
struct State {
    next_id: u64,
    /// Committed and still-pending (reserved) events alike: both hold a
    /// slot. Indexed by bucket, so a check reads only its own events.
    buckets: HashMap<BucketKey, Vec<Entry>>,
    checks: u64,
}

impl State {
    fn push(&mut self, ev: Event) -> (BucketKey, u64) {
        let id = self.next_id;
        self.next_id += 1;
        let key = (ev.key.uid, ev.key.service.clone());
        self.buckets
            .entry(key.clone())
            .or_default()
            .push(Entry { id, ev });
        (key, id)
    }

    /// Drop every event at or before `cutoff`, and the buckets left empty.
    fn sweep(&mut self, cutoff: OffsetDateTime) {
        self.buckets.retain(|_, b| {
            b.retain(|e| e.ev.at > cutoff);
            !b.is_empty()
        });
    }
}

pub struct Limiter {
    state: Arc<Mutex<State>>,
    /// Set when the rebuild could not read every record of the window:
    /// until then the limits are not known and calls are denied.
    unavailable_until: Option<OffsetDateTime>,
}

impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
}

/// A slot held until `commit`; dropping it uncommitted releases the slot.
#[must_use = "commit the reservation once the request was sent"]
pub struct Reservation {
    state: Arc<Mutex<State>>,
    slot: (BucketKey, u64),
    committed: bool,
}

fn lock(s: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    s.lock().unwrap_or_else(|p| p.into_inner())
}

impl Reservation {
    /// The request was sent: the slot stays taken.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let (key, id) = &self.slot;
        if let Some(b) = lock(&self.state).buckets.get_mut(key) {
            b.retain(|e| e.id != *id);
        }
    }
}

fn is_write(k: OpKind) -> bool {
    k == OpKind::Write
}

fn cap_minor(max_major: u64, currency: &str) -> Option<u128> {
    Some(u128::from(max_major) * 10u128.pow(exponent(currency)?))
}

impl Limiter {
    pub fn new() -> Limiter {
        Limiter {
            state: Arc::new(Mutex::new(State::default())),
            unavailable_until: None,
        }
    }

    /// Rebuild from audit records; events older than 24 h are dropped.
    pub fn rebuild(records: impl Iterator<Item = Event>, now: OffsetDateTime) -> Limiter {
        let cutoff = now - Duration::seconds(DAY);
        let mut st = State::default();
        for ev in records.filter(|e| e.at > cutoff) {
            st.push(ev);
        }
        Limiter {
            state: Arc::new(Mutex::new(st)),
            unavailable_until: None,
        }
    }

    /// [`Limiter::rebuild`] from records known to be incomplete (a file
    /// or line of the window could not be read): fail closed. Calls are
    /// denied ([`Limiter::unavailable`]) until a full window has passed
    /// since `now`, after which every event that counts is one this
    /// limiter saw.
    pub fn rebuild_incomplete(
        records: impl Iterator<Item = Event>,
        now: OffsetDateTime,
    ) -> Limiter {
        Limiter {
            unavailable_until: Some(now + Duration::seconds(DAY)),
            ..Limiter::rebuild(records, now)
        }
    }

    /// The limits cannot be checked at `now` (see
    /// [`Limiter::rebuild_incomplete`]): deny with `limits_unavailable`.
    pub fn unavailable(&self, now: OffsetDateTime) -> bool {
        self.unavailable_until.is_some_and(|t| now < t)
    }

    /// Check every configured limit against the (uid, service) bucket and
    /// the (uid, service, session) bucket, and reserve a slot. Errs with the
    /// name of the limit hit. Callers pass `amount_required = op.amount.is_some()`;
    /// a required but absent amount is denied (`amount_missing`). An unknown
    /// request or cap currency is denied (`amount_currency`).
    pub fn check_and_commit(
        &self,
        k: &Key,
        kind: OpKind,
        amount: Option<(u64, &str)>,
        amount_required: bool,
        cfg: &LimitsCfg,
        now: OffsetDateTime,
    ) -> Result<Reservation, &'static str> {
        if amount_required && amount.is_none() {
            return Err("amount_missing");
        }
        let mut st = lock(&self.state);
        let cutoff = now - Duration::seconds(DAY);
        st.checks += 1;
        if st.checks % SWEEP_EVERY == 0 {
            st.sweep(cutoff);
        }
        let bucket_key: BucketKey = (k.uid, k.service.clone());
        if let Some(b) = st.buckets.get_mut(&bucket_key) {
            b.retain(|e| e.ev.at > cutoff);
        }

        let amount = amount.map(|(m, c)| (m, c.to_ascii_uppercase()));
        if let Some((m, c)) = &amount {
            if exponent(c).is_none() {
                return Err("amount_currency");
            }
            for cap in [&cfg.amount_per_request, &cfg.amount_per_day]
                .into_iter()
                .flatten()
            {
                if !cap.currency.eq_ignore_ascii_case(c) || exponent(&cap.currency).is_none() {
                    return Err("amount_currency");
                }
            }
            if let Some(cap) = &cfg.amount_per_request {
                if Some(u128::from(*m)) > cap_minor(cap.max, &cap.currency) {
                    return Err("amount_per_request");
                }
            }
        }

        let in_win = |e: &Entry, secs: i64| e.ev.at > now - Duration::seconds(secs);
        // Only this (uid, service)'s events: the uid bucket is all of them,
        // the session bucket those with the same session.
        let events: &[Entry] = st.buckets.get(&bucket_key).map_or(&[], |b| b.as_slice());
        let uid_bucket = |_: &Entry| true;
        let session_bucket = |e: &Entry| e.ev.key.session == k.session;
        let buckets: [&dyn Fn(&Entry) -> bool; 2] = [&uid_bucket, &session_bucket];
        for b in buckets {
            let count = |secs: i64, f: &dyn Fn(OpKind) -> bool| -> u64 {
                events
                    .iter()
                    .filter(|e| b(e) && in_win(e, secs) && f(e.ev.kind))
                    .count() as u64
            };
            if let Some(l) = cfg.requests_per_minute {
                if count(60, &|_| true) + 1 > u64::from(l) {
                    return Err("requests_per_minute");
                }
            }
            if is_write(kind) {
                if let Some(l) = cfg.writes_per_hour {
                    if count(3600, &is_write) + 1 > u64::from(l) {
                        return Err("writes_per_hour");
                    }
                }
            }
            if kind == OpKind::Delete {
                if let Some(l) = cfg.deletes_per_day {
                    if count(DAY, &|x| x == OpKind::Delete) + 1 > u64::from(l) {
                        return Err("deletes_per_day");
                    }
                }
            }
            if kind == OpKind::Bulk {
                if let Some(l) = cfg.bulk_per_session {
                    if count(DAY, &|x| x == OpKind::Bulk) + 1 > u64::from(l) {
                        return Err("bulk_per_session");
                    }
                }
            }
            if let (Some(cap), Some((m, c))) = (&cfg.amount_per_day, &amount) {
                let sum: u128 = events
                    .iter()
                    .filter(|e| b(e) && in_win(e, DAY))
                    .filter_map(|e| e.ev.amount_minor.as_ref())
                    .filter(|(_, ec)| ec.eq_ignore_ascii_case(c))
                    .map(|(a, _)| u128::from(*a))
                    .sum();
                if Some(sum + u128::from(*m)) > cap_minor(cap.max, &cap.currency) {
                    return Err("amount_per_day");
                }
            }
        }

        // Recorded even when no counting limit is configured: a reload
        // that adds one must see the calls already made in its window.
        let slot = st.push(Event {
            at: now,
            key: k.clone(),
            kind,
            amount_minor: amount,
        });
        Ok(Reservation {
            state: Arc::clone(&self.state),
            slot,
            committed: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AmountSpec, Unit};
    use saiife_policy::AmountCap;
    use serde_json::json;

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }
    fn key(uid: u32, s: Option<&str>) -> Key {
        Key {
            uid,
            service: "stripe".into(),
            session: s.map(String::from),
        }
    }
    fn cap(max: u64, c: &str) -> Option<AmountCap> {
        Some(AmountCap {
            max,
            currency: c.into(),
        })
    }
    fn go(
        l: &Limiter,
        k: &Key,
        kind: OpKind,
        a: Option<(u64, &str)>,
        c: &LimitsCfg,
        now: OffsetDateTime,
    ) -> Result<(), &'static str> {
        l.check_and_commit(k, kind, a, false, c, now)
            .map(|r| r.commit())
    }

    #[test]
    fn rpm_61st_denied_then_ok_after_window() {
        let l = Limiter::new();
        let c = LimitsCfg {
            requests_per_minute: Some(60),
            ..Default::default()
        };
        let k = key(1, Some("s"));
        for _ in 0..60 {
            go(&l, &k, OpKind::Read, None, &c, t0()).unwrap();
        }
        assert_eq!(
            go(&l, &k, OpKind::Read, None, &c, t0()),
            Err("requests_per_minute")
        );
        go(&l, &k, OpKind::Read, None, &c, t0() + Duration::seconds(61)).unwrap();
    }

    #[test]
    fn session_bucket_and_uid_bucket_both_apply() {
        let l = Limiter::new();
        let c = LimitsCfg {
            requests_per_minute: Some(2),
            ..Default::default()
        };
        go(&l, &key(1, Some("a")), OpKind::Read, None, &c, t0()).unwrap();
        go(&l, &key(1, Some("b")), OpKind::Read, None, &c, t0()).unwrap();
        assert_eq!(
            go(&l, &key(1, Some("c")), OpKind::Read, None, &c, t0()),
            Err("requests_per_minute")
        );
        go(&l, &key(2, Some("a")), OpKind::Read, None, &c, t0()).unwrap();
    }

    #[test]
    fn null_session_is_one_bucket() {
        let l = Limiter::new();
        let c = LimitsCfg {
            bulk_per_session: Some(1),
            ..Default::default()
        };
        go(&l, &key(1, None), OpKind::Bulk, None, &c, t0()).unwrap();
        assert_eq!(
            go(&l, &key(1, None), OpKind::Bulk, None, &c, t0()),
            Err("bulk_per_session")
        );
    }

    #[test]
    fn deletes_zero_means_never() {
        let l = Limiter::new();
        let c = LimitsCfg {
            deletes_per_day: Some(0),
            ..Default::default()
        };
        assert_eq!(
            go(&l, &key(1, None), OpKind::Delete, None, &c, t0()),
            Err("deletes_per_day")
        );
        go(&l, &key(1, None), OpKind::Read, None, &c, t0()).unwrap();
    }

    #[test]
    fn amount_per_day_sums_minor_units() {
        let l = Limiter::new();
        let c = LimitsCfg {
            amount_per_day: cap(500, "EUR"),
            ..Default::default()
        };
        let k = key(1, None);
        go(&l, &k, OpKind::Write, Some((20_000, "EUR")), &c, t0()).unwrap();
        go(&l, &k, OpKind::Write, Some((25_000, "EUR")), &c, t0()).unwrap();
        assert_eq!(
            go(&l, &k, OpKind::Write, Some((10_000, "EUR")), &c, t0()),
            Err("amount_per_day")
        );
    }

    #[test]
    fn amount_per_request_is_single_request() {
        let l = Limiter::new();
        let c = LimitsCfg {
            amount_per_request: cap(100, "EUR"),
            ..Default::default()
        };
        let k = key(1, None);
        go(&l, &k, OpKind::Write, Some((10_000, "EUR")), &c, t0()).unwrap();
        go(&l, &k, OpKind::Write, Some((10_000, "EUR")), &c, t0()).unwrap();
        assert_eq!(
            go(&l, &k, OpKind::Write, Some((10_001, "EUR")), &c, t0()),
            Err("amount_per_request")
        );
    }

    #[test]
    fn split_refund_still_capped() {
        let l = Limiter::new();
        let c = LimitsCfg {
            amount_per_day: cap(500, "EUR"),
            ..Default::default()
        };
        let k = key(1, None);
        let ok = (0..600)
            .filter(|_| go(&l, &k, OpKind::Write, Some((100, "EUR")), &c, t0()).is_ok())
            .count();
        assert_eq!(ok, 500);
    }

    #[test]
    fn amount_currency_mismatch_denied() {
        let l = Limiter::new();
        let c = LimitsCfg {
            amount_per_day: cap(500, "EUR"),
            ..Default::default()
        };
        assert_eq!(
            go(
                &l,
                &key(1, None),
                OpKind::Write,
                Some((100, "USD")),
                &c,
                t0()
            ),
            Err("amount_currency")
        );
    }

    #[test]
    fn jpy_exponent_zero() {
        let l = Limiter::new();
        let c = LimitsCfg {
            amount_per_request: cap(500, "JPY"),
            ..Default::default()
        };
        let k = key(1, None);
        go(&l, &k, OpKind::Write, Some((500, "JPY")), &c, t0()).unwrap();
        assert_eq!(
            go(&l, &k, OpKind::Write, Some((501, "JPY")), &c, t0()),
            Err("amount_per_request")
        );
    }

    #[test]
    fn extract_sums_array_path() {
        use crate::amount::extract;
        let spec = AmountSpec {
            field: "refund.transactions[].amount".into(),
            currency_field: "refund.currency".into(),
            unit: Unit::Major,
        };
        let body = json!({"refund":{"currency":"eur","transactions":[{"amount":"1.50"},{"amount":2},{"amount":0.25}]}});
        assert_eq!(extract(&spec, &body).unwrap(), (375, "EUR".to_string()));
        for bad in [
            json!({"refund":{"currency":"EUR","transactions":[{"amount":-1}]}}),
            json!({"refund":{"currency":"EUR","transactions":[{"amount":"1.234"}]}}),
            json!({"refund":{"currency":"EUR","transactions":[{"amount":"x"}]}}),
            json!({"refund":{"currency":"EUR","transactions":[]}}),
            json!({"refund":{"currency":"EUR"}}),
            json!({"refund":{"transactions":[{"amount":1}]}}),
        ] {
            assert!(extract(&spec, &bad).is_err(), "{bad}");
        }
        let minor = AmountSpec {
            unit: Unit::Minor,
            ..spec.clone()
        };
        let b = json!({"refund":{"currency":"JPY","transactions":[{"amount":300}]}});
        assert_eq!(extract(&minor, &b).unwrap(), (300, "JPY".to_string()));
        let b = json!({"refund":{"currency":"EUR","transactions":[{"amount":"3.5"}]}});
        assert!(extract(&minor, &b).is_err());
    }

    #[test]
    fn concurrent_last_slot_once() {
        let l = Arc::new(Limiter::new());
        let c = LimitsCfg {
            requests_per_minute: Some(1),
            ..Default::default()
        };
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let (l, c) = (l.clone(), c.clone());
                std::thread::spawn(move || {
                    l.check_and_commit(&key(1, None), OpKind::Read, None, false, &c, t0())
                        .map(|r| {
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            r.commit()
                        })
                        .is_ok()
                })
            })
            .collect();
        let ok = handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>();
        assert_eq!(ok, 1);
    }

    #[test]
    fn writes_per_hour_counts_only_write() {
        let l = Limiter::new();
        let c = LimitsCfg {
            writes_per_hour: Some(1),
            ..Default::default()
        };
        let k = key(1, None);
        go(&l, &k, OpKind::Delete, None, &c, t0()).unwrap();
        go(&l, &k, OpKind::Bulk, None, &c, t0()).unwrap();
        go(&l, &k, OpKind::Write, None, &c, t0()).unwrap();
        assert_eq!(
            go(&l, &k, OpKind::Write, None, &c, t0()),
            Err("writes_per_hour")
        );
        go(&l, &k, OpKind::Delete, None, &c, t0()).unwrap();
    }

    #[test]
    fn event_exactly_60s_old_is_out() {
        let l = Limiter::new();
        let c = LimitsCfg {
            requests_per_minute: Some(1),
            ..Default::default()
        };
        let k = key(1, None);
        go(&l, &k, OpKind::Read, None, &c, t0()).unwrap();
        assert!(go(&l, &k, OpKind::Read, None, &c, t0() + Duration::seconds(59)).is_err());
        go(&l, &k, OpKind::Read, None, &c, t0() + Duration::seconds(60)).unwrap();
    }

    #[test]
    fn amount_per_day_ignores_other_currency_history() {
        let l = Limiter::new();
        let k = key(1, None);
        let none = LimitsCfg::default();
        go(&l, &k, OpKind::Write, Some((90_000, "USD")), &none, t0()).unwrap();
        let c = LimitsCfg {
            amount_per_day: cap(500, "EUR"),
            ..Default::default()
        };
        go(&l, &k, OpKind::Write, Some((50_000, "EUR")), &c, t0()).unwrap();
        assert_eq!(
            go(&l, &k, OpKind::Write, Some((1, "EUR")), &c, t0()),
            Err("amount_per_day")
        );
    }

    #[test]
    fn extract_refuses_missing_branches() {
        use crate::amount::extract;
        let spec = AmountSpec {
            field: "t[].amount".into(),
            currency_field: "t[].cur".into(),
            unit: Unit::Minor,
        };
        for bad in [
            json!({"t":[{"amount":100,"cur":"EUR"},{"note":"x","cur":"EUR"}]}),
            json!({"t":[{"amount":100,"cur":"EUR"},{"amount":5}]}),
            json!({"t":[{"amount":100,"cur":"EUR"},{"amount":5,"cur":"USD"}]}),
        ] {
            assert!(extract(&spec, &bad).is_err(), "{bad}");
        }
        let ok = json!({"t":[{"amount":100,"cur":"EUR"},{"amount":5,"cur":"eur"}]});
        assert_eq!(extract(&spec, &ok).unwrap(), (105, "EUR".to_string()));
    }

    #[test]
    fn unknown_currency_denied_and_exponents() {
        use crate::amount::exponent;
        assert_eq!(exponent("JPY"), Some(0));
        assert_eq!(exponent("KWD"), Some(3));
        assert_eq!(exponent("EUR"), Some(2));
        assert_eq!(exponent("XYZ"), None);
        let l = Limiter::new();
        let k = key(1, None);
        let c = LimitsCfg {
            amount_per_day: cap(500, "EUR"),
            ..Default::default()
        };
        assert_eq!(
            go(&l, &k, OpKind::Write, Some((1, "XYZ")), &c, t0()),
            Err("amount_currency")
        );
        let c = LimitsCfg {
            amount_per_day: cap(500, "XYZ"),
            ..Default::default()
        };
        assert_eq!(
            go(&l, &k, OpKind::Write, Some((1, "XYZ")), &c, t0()),
            Err("amount_currency")
        );
    }

    #[test]
    fn missing_amount_fails_closed() {
        let l = Limiter::new();
        let k = key(1, None);
        let c = LimitsCfg::default();
        assert_eq!(
            l.check_and_commit(&k, OpKind::Write, None, true, &c, t0())
                .err(),
            Some("amount_missing")
        );
        assert!(l
            .check_and_commit(&k, OpKind::Write, None, false, &c, t0())
            .is_ok());
    }

    fn remembered(l: &Limiter) -> usize {
        lock(&l.state).buckets.values().map(Vec::len).sum()
    }

    #[test]
    fn buckets_are_indexed_and_old_ones_swept() {
        let l = Limiter::new();
        let c = LimitsCfg {
            requests_per_minute: Some(1),
            ..Default::default()
        };
        // Another service and another uid do not count against uid 1's
        // `stripe` bucket.
        let other = Key {
            uid: 1,
            service: "erp".into(),
            session: None,
        };
        go(&l, &other, OpKind::Read, None, &c, t0()).unwrap();
        go(&l, &key(2, None), OpKind::Read, None, &c, t0()).unwrap();
        go(&l, &key(1, None), OpKind::Read, None, &c, t0()).unwrap();
        assert_eq!(remembered(&l), 3);
        // A day later the sweep drops buckets nobody asked about again.
        let later = t0() + Duration::seconds(DAY + 1);
        for _ in 0..SWEEP_EVERY {
            go(
                &l,
                &key(1, None),
                OpKind::Read,
                None,
                &LimitsCfg::default(),
                later,
            )
            .unwrap();
        }
        // Only uid 1's `stripe` bucket is left, with the new calls.
        let st = lock(&l.state);
        assert_eq!(st.buckets.len(), 1);
        assert_eq!(
            st.buckets[&(1, "stripe".to_string())].len() as u64,
            SWEEP_EVERY
        );
    }

    #[test]
    fn reload_that_adds_a_limit_counts_calls_already_made() {
        let l = Limiter::new();
        let k = key(1, Some("s"));
        // No limit configured: every call is still remembered.
        for _ in 0..3 {
            go(&l, &k, OpKind::Read, None, &LimitsCfg::default(), t0()).unwrap();
        }
        assert_eq!(remembered(&l), 3);
        // A reload adds `requests_per_minute = 4`: the window already
        // holds 3, so one more call is allowed and the next is not.
        let c = LimitsCfg {
            requests_per_minute: Some(4),
            ..Default::default()
        };
        let soon = t0() + Duration::seconds(10);
        go(&l, &k, OpKind::Read, None, &c, soon).unwrap();
        assert_eq!(
            go(&l, &k, OpKind::Read, None, &c, soon),
            Err("requests_per_minute")
        );
    }

    #[test]
    fn dropped_reservation_releases() {
        let l = Limiter::new();
        let c = LimitsCfg {
            requests_per_minute: Some(1),
            ..Default::default()
        };
        let k = key(1, None);
        drop(
            l.check_and_commit(&k, OpKind::Read, None, false, &c, t0())
                .unwrap(),
        );
        go(&l, &k, OpKind::Read, None, &c, t0()).unwrap();
    }

    #[test]
    fn rebuild_from_records_keeps_window() {
        let k = key(1, None);
        let ev = |secs: i64| Event {
            at: t0() - Duration::seconds(secs),
            key: k.clone(),
            kind: OpKind::Delete,
            amount_minor: None,
        };
        let l = Limiter::rebuild(vec![ev(10), ev(DAY + 5)].into_iter(), t0());
        let c = LimitsCfg {
            deletes_per_day: Some(2),
            ..Default::default()
        };
        go(&l, &k, OpKind::Delete, None, &c, t0()).unwrap();
        assert_eq!(
            go(&l, &k, OpKind::Delete, None, &c, t0()),
            Err("deletes_per_day")
        );
    }
}
