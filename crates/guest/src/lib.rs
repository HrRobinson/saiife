//! The guest agent that runs inside the box VM. Tokio-free by design; Linux in
//! practice, but every module compiles on all targets.
#![forbid(unsafe_code)]

pub mod control;
pub mod env;
pub mod events;
pub mod export;
pub mod pty;
pub mod setup;
