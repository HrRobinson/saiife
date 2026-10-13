//! saiife audit log: one masked JSONL record per guard decision.
//!
//! Records are written best-effort — the audit log is observability, never
//! enforcement, and a failed write must never change a guard verdict.

#![forbid(unsafe_code)]

pub mod mask;
pub mod record;

pub use record::{DecisionKind, NewRecord, Record};
