//! saiifeguard — the command guard engine for saiife.
//!
//! A pure sidecar: it decides whether a proposed shell command is safe to run,
//! blocking known-destructive commands (`git reset --hard`, `rm -rf /`, …)
//! while staying out of the way of everything else. No network, no coupling to
//! the saiife app.
//!
//! Pipeline: parse -> normalize -> pre-filter -> match (allow before deny) ->
//! decide. It **fails open**: on any malfunction (bad payload, oversize input,
//! regex timeout, pack-load failure) it ALLOWs and warns — a guard that wedges
//! autonomous agents gets disabled, so continuity wins.

#![forbid(unsafe_code)]

pub mod builtins;
pub mod canon;
mod cdtrack;
pub mod engine;
pub mod getopt;
pub mod lexer;
pub mod normalize;
pub mod operands;
pub mod pack;
pub mod pathrule;
pub mod payload;
pub mod prefilter;
pub mod profile;
pub mod subst;
pub mod wrappers;

pub use engine::{AllowTrace, Decision, Engine};
pub use pack::{Pack, PackWarning};

/// Words and bytes the segment-stripping path has touched, so a test can pin
/// how the work grows without reading a clock.
#[cfg(test)]
pub(crate) mod work {
    use std::cell::Cell;

    thread_local! {
        static WORK: Cell<usize> = const { Cell::new(0) };
    }

    pub(crate) fn add(n: usize) {
        WORK.with(|w| w.set(w.get() + n));
    }

    pub(crate) fn take() -> usize {
        WORK.with(|w| w.replace(0))
    }
}
