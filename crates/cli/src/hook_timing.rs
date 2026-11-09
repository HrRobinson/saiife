//! `SAIIFE_HOOK_TIMING=1`: the managed hook says how long each of its steps took, on
//! stderr, one `saiife-timing <step> <ms>` line each, as it ends; its worker adds its own
//! (`worker.*`). Debug builds only, which the `ci-locked` CI build is: a release build
//! reads no variable and prints nothing, and every call here is then a no-op. For the
//! CI benches (`bench_managed` in scripts/locked-windows/lib.ps1).
//!
//! Steps on other threads overlap the main thread's: only the main thread's add up.

use std::time::Instant;

/// The variable that turns the trace on (`1`).
pub const VAR: &str = "SAIIFE_HOOK_TIMING";
/// For the worker only: when the hook asked for it, in microseconds since the Unix
/// epoch, so the worker can say how long it took to start.
pub const SPAWNED_VAR: &str = "SAIIFE_HOOK_TIMING_SPAWNED";

#[cfg(debug_assertions)]
mod imp {
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static ON: OnceLock<bool> = OnceLock::new();
    static STEPS: Mutex<Vec<(&'static str, Duration)>> = Mutex::new(Vec::new());

    /// Whether the trace is on.
    pub fn on() -> bool {
        *ON.get_or_init(|| std::env::var_os(super::VAR).is_some_and(|v| v == "1"))
    }

    /// `name` took `d`.
    pub fn add(name: &'static str, d: Duration) {
        if on() {
            STEPS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((name, d));
        }
    }

    /// Now, in microseconds since the Unix epoch (0 if the clock is before it).
    pub fn now_us() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_micros())
    }

    /// The time since `us` (from [`now_us`], maybe in another process) as `name`.
    pub fn add_since_us(name: &'static str, us: u128) {
        let gap = now_us().saturating_sub(us);
        add(
            name,
            Duration::from_micros(u64::try_from(gap).unwrap_or(u64::MAX)),
        );
    }

    /// Writes the steps to stderr, in one write, and forgets them.
    pub fn flush() {
        if !on() {
            return;
        }
        let steps = std::mem::take(&mut *STEPS.lock().unwrap_or_else(|p| p.into_inner()));
        let text: String = steps
            .iter()
            .map(|(name, d)| format!("saiife-timing {name} {:.3}\n", d.as_secs_f64() * 1000.0))
            .collect();
        let _ = std::io::stderr().write_all(text.as_bytes());
    }
}

#[cfg(not(debug_assertions))]
mod imp {
    use std::time::Duration;

    #[inline(always)]
    pub fn on() -> bool {
        false
    }
    #[inline(always)]
    pub fn add(_name: &'static str, _d: Duration) {}
    #[inline(always)]
    pub fn now_us() -> u128 {
        0
    }
    #[inline(always)]
    pub fn add_since_us(_name: &'static str, _us: u128) {}
    #[inline(always)]
    pub fn flush() {}
}

pub use imp::{add, add_since_us, flush, now_us, on};

/// `f`, timed as `name`.
pub fn time<T>(name: &'static str, f: impl FnOnce() -> T) -> T {
    if !on() {
        return f();
    }
    let t = Instant::now();
    let r = f();
    add(name, t.elapsed());
    r
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    #[test]
    fn off_unless_asked() {
        // The test process never sets the variable.
        if std::env::var_os(VAR).is_none() {
            assert!(!on());
            assert_eq!(time("x", || 7), 7);
        }
    }

    #[test]
    fn the_clock_moves_forward() {
        let a = now_us();
        assert!(a > 0);
        assert!(now_us() >= a);
    }
}
