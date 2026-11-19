//! A debug-build seam for the tests that run a real hook or CLI process under load.
//!
//! Some deadlines are fixed in the hook and in the CLI (the managed hook's worker, connect
//! and ack deadlines; the `api` connect deadline). They are the product's latency contract,
//! so a release build never changes them. A debug build, which only tests run, multiplies
//! them by `SAIIFE_TEST_DEADLINE_SCALE` (a whole number, 1 to 100) when it is set: a test
//! that is about what the hook decides, not how fast, makes the deadlines generous so a
//! loaded machine cannot fail it. Unset, or in a release build, a deadline is its value.
//!
//! A test-build-only lever, like `SAIIFE_EVAL_FAULT`: the `ci-locked` profile also has debug
//! assertions and is installed as a locked system build in CI, where an environment the agent
//! controls could scale the watchdog past the agents' 10 s hook timeout. Never for production
//! (a release build ignores it).

use std::time::Duration;

/// The variable: a whole number, 1 to 100.
#[cfg(debug_assertions)]
pub const VAR: &str = "SAIIFE_TEST_DEADLINE_SCALE";

/// `d`, times the scale in a debug build that sets one.
#[cfg(debug_assertions)]
pub fn scaled(d: Duration) -> Duration {
    match std::env::var(VAR).ok().and_then(|v| v.parse::<u32>().ok()) {
        Some(n) if (1..=100).contains(&n) => d * n,
        _ => d,
    }
}

/// `d`: a release build reads no variable.
#[cfg(not(debug_assertions))]
pub fn scaled(d: Duration) -> Duration {
    d
}
