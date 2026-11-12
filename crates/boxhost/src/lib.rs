//! The box host side: Cloud Hypervisor driver, disks, images, vsock and
//! terminal. Tokio-free by design.
#![forbid(unsafe_code)]

pub mod bake;
pub mod ch;
pub mod disk;
pub mod guest;
pub mod image;
pub mod launch;
pub mod layout;
pub mod paths;
pub mod pins;
pub mod preflight;
pub mod review;
pub mod snapshot;
pub mod term;
pub mod tools;
pub mod vault;
pub mod vmm;
pub mod vsock;
