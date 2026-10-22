//! Per-uid back-pressure (spec §6.2): at most 64 requests in flight and a
//! token bucket of 1 000 per second (burst 1 000). Over either, `busy`.

use saiife_ipc::msg::ErrorCode;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const MAX_IN_FLIGHT: u32 = 64;
pub const RATE_PER_SEC: f64 = 1000.0;
pub const BURST: f64 = 1000.0;

#[derive(Debug)]
struct PerUid {
    in_flight: u32,
    tokens: f64,
    refilled: Instant,
}

#[derive(Debug, Clone, Default)]
pub struct Limits {
    inner: Arc<Mutex<HashMap<u32, PerUid>>>,
}

/// One request in flight for a uid; the count goes down when it drops.
#[derive(Debug)]
pub struct InFlight {
    inner: Arc<Mutex<HashMap<u32, PerUid>>>,
    uid: u32,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = m.get_mut(&self.uid) {
            e.in_flight = e.in_flight.saturating_sub(1);
        }
    }
}

impl Limits {
    pub fn new() -> Limits {
        Limits::default()
    }

    /// Admit one request of `uid` at `now`, or `Busy`.
    pub fn try_begin(&self, uid: u32, now: Instant) -> Result<InFlight, ErrorCode> {
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let e = m.entry(uid).or_insert(PerUid {
            in_flight: 0,
            tokens: BURST,
            refilled: now,
        });
        if let Some(dt) = now.checked_duration_since(e.refilled) {
            e.tokens = (e.tokens + dt.as_secs_f64() * RATE_PER_SEC).min(BURST);
            e.refilled = now;
        }
        if e.in_flight >= MAX_IN_FLIGHT || e.tokens < 1.0 {
            return Err(ErrorCode::Busy);
        }
        e.tokens -= 1.0;
        e.in_flight += 1;
        Ok(InFlight {
            inner: Arc::clone(&self.inner),
            uid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rate_bucket_allows_1000_per_second_then_busy() {
        let l = Limits::new();
        let t0 = Instant::now();
        for i in 0..1000 {
            assert!(l.try_begin(7, t0).is_ok(), "request {i}");
        }
        assert_eq!(l.try_begin(7, t0).unwrap_err(), ErrorCode::Busy);
        // Another uid has its own bucket.
        assert!(l.try_begin(8, t0).is_ok());
        // 1 ms refills one token, no more.
        let t1 = t0 + Duration::from_millis(1);
        assert!(l.try_begin(7, t1).is_ok());
        assert_eq!(l.try_begin(7, t1).unwrap_err(), ErrorCode::Busy);
        // A full second refills the burst, capped at 1000.
        let t2 = t1 + Duration::from_secs(5);
        for i in 0..1000 {
            assert!(l.try_begin(7, t2).is_ok(), "request {i} after refill");
        }
        assert_eq!(l.try_begin(7, t2).unwrap_err(), ErrorCode::Busy);
    }

    #[test]
    fn inflight_cap_is_64_per_uid() {
        let l = Limits::new();
        let t = Instant::now();
        let mut held: Vec<InFlight> = (0..64).map(|_| l.try_begin(1, t).unwrap()).collect();
        assert_eq!(l.try_begin(1, t).unwrap_err(), ErrorCode::Busy);
        let other = l.try_begin(2, t);
        assert!(other.is_ok());
        held.pop();
        let again = l.try_begin(1, t);
        assert!(again.is_ok());
        assert_eq!(l.try_begin(1, t).unwrap_err(), ErrorCode::Busy);
    }
}
