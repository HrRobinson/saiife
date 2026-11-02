//! The Windows pieces of saiife (plan 19a, decision W1).
//!
//! Everything here so far is pure, so Linux tests run it: service SIDs and
//! the uid mapping in [`sid`], SDDL text in [`sddl`]. `ffi` is empty, so the
//! crate forbids `unsafe` on every target. Plan 19b relaxes that to
//! `#![cfg_attr(not(windows), forbid(unsafe_code))]` when it adds the FFI
//! calls, and `scripts/check-unsafe.sh` changes with it.
#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]

pub mod sddl;
pub mod sid;

#[cfg(windows)]
pub mod ffi;
