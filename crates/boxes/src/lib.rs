//! The boxes control plane (spec §7.7): templates, capacity, the box store,
//! the state machine and the manager. Tokio-free by design.
#![forbid(unsafe_code)]

pub mod capacity;
pub mod error;
pub mod guest;
pub mod manager;
pub mod source;
pub mod state;
pub mod store;
pub mod template;
pub mod vmm;

pub use error::BoxesError;
pub use saiife_wire::source::{BoxError, BoxId, BoxState};
