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

/// Open connections per uid.
pub const MAX_CONNS_PER_UID: u32 = 32;
/// File descriptors kept free of connections for logs, keys and the like.
const FD_RESERVE: u64 = 64;

/// Open-connection caps, checked at accept: per uid and in total.
#[derive(Debug, Clone)]
pub struct ConnLimits {
    inner: Arc<Mutex<Conns>>,
}

#[derive(Debug)]
struct Conns {
    per_uid: HashMap<u32, u32>,
    total: u64,
    max_total: u64,
}

/// One open connection; released on drop.
#[derive(Debug)]
pub struct ConnSlot {
    inner: Arc<Mutex<Conns>>,
    uid: u32,
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        let mut c = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        c.total = c.total.saturating_sub(1);
        if let Some(n) = c.per_uid.get_mut(&self.uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                c.per_uid.remove(&self.uid);
            }
        }
    }
}

/// The global cap for a soft `RLIMIT_NOFILE` of `nofile`: that minus a
/// reserve of 64, and at least 64.
pub fn total_cap(nofile: u64) -> u64 {
    nofile.saturating_sub(FD_RESERVE).max(64)
}

impl ConnLimits {
    pub fn new(max_total: u64) -> ConnLimits {
        ConnLimits {
            inner: Arc::new(Mutex::new(Conns {
                per_uid: HashMap::new(),
                total: 0,
                max_total,
            })),
        }
    }

    /// From the process's soft `RLIMIT_NOFILE`.
    pub fn from_rlimit() -> ConnLimits {
        let soft = rustix::process::getrlimit(rustix::process::Resource::Nofile)
            .current
            .unwrap_or(u64::MAX);
        ConnLimits::new(total_cap(soft))
    }

    /// Connections `uid` has open now.
    pub fn open_for(&self, uid: u32) -> u32 {
        let c = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        c.per_uid.get(&uid).copied().unwrap_or(0)
    }

    pub fn try_open(&self, uid: u32) -> Result<ConnSlot, ErrorCode> {
        let mut c = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mine = c.per_uid.get(&uid).copied().unwrap_or(0);
        if mine >= MAX_CONNS_PER_UID || c.total >= c.max_total {
            return Err(ErrorCode::Busy);
        }
        c.per_uid.insert(uid, mine + 1);
        c.total += 1;
        Ok(ConnSlot {
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

    #[test]
    fn connection_cap_is_32_per_uid_and_global() {
        let l = ConnLimits::new(40);
        let mut a: Vec<ConnSlot> = (0..32).map(|_| l.try_open(1).unwrap()).collect();
        assert_eq!(l.try_open(1).unwrap_err(), ErrorCode::Busy);
        let b: Vec<ConnSlot> = (0..8).map(|_| l.try_open(2).unwrap()).collect();
        // Global cap of 40 reached.
        assert_eq!(l.try_open(3).unwrap_err(), ErrorCode::Busy);
        a.pop();
        assert!(l.try_open(3).is_ok());
        drop(b);
        let again = l.try_open(1);
        assert!(again.is_ok());
    }

    #[test]
    fn total_cap_keeps_a_reserve_and_a_floor() {
        assert_eq!(total_cap(1024), 960);
        assert_eq!(total_cap(100), 64);
        assert_eq!(total_cap(0), 64);
        assert_eq!(total_cap(u64::MAX), u64::MAX - 64);
    }
}
