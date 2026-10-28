//! saiife audit log: one masked JSONL record per guard decision.
//!
//! Records are written best-effort — the audit log is observability, never
//! enforcement, and a failed write must never change a guard verdict.

#![forbid(unsafe_code)]

pub mod chain;
pub mod mask;
pub mod record;
pub mod sign;
pub mod store;
pub mod text;
pub mod verify;

pub use chain::{ChainWriter, StartupCheck, WriterOptions};
pub use record::{DecisionKind, NewRecord, Record};
pub use verify::{
    verify, verify_external, Break, BreakKind, ExternalReport, HeadMismatch, VerifyReport,
};
