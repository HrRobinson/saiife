//! The Windows pieces of saiife (plan 19a, decision W1).
//!
//! The pure parts run on every OS, so Linux tests cover them: service SIDs,
//! the uid mapping and token facts in [`sid`], SDDL text in [`sddl`], and the
//! one home and data-dir lookup in [`profile`].
//!
//! `ffi` is the one place in saiife, besides `saiife-darwin`, allowed `unsafe`.
//! It exists on Windows only. Off Windows the crate forbids `unsafe`; on Windows
//! it is denied, and allowed by one attribute at the top of `ffi/mod.rs`.
//! `scripts/check-unsafe.sh` keeps all of this in place.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![cfg_attr(windows, deny(unsafe_code))]
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]

pub mod cred;
pub mod display;
pub mod open_rules;
pub mod pipe;
pub mod proc;
pub mod profile;
pub mod sddl;
pub mod sid;

#[cfg(windows)]
pub mod ffi;
