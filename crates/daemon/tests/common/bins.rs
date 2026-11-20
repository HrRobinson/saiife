//! Binaries the workspace build puts in the profile dir (`target/debug`),
//! found from this test binary. Shared by the Data Shield tests through
//! `#[path]`.
//!
//! Cargo's old layout runs a test from `target/debug/deps/`; the new build
//! dir layout (the default from Rust 1.100) from
//! `target/debug/build/<package>/<hash>/out/`. Either way the profile dir
//! is the parent of the nearest `deps` or `build` above the test binary.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// `target/<profile>/<name>`, asserted to exist; `how` says how to build it.
pub fn built(name: &str, how: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile = exe
        .ancestors()
        .find(|d| {
            matches!(
                d.file_name().and_then(|n| n.to_str()),
                Some("deps" | "build")
            )
        })
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("no target profile dir above {}", exe.display()));
    let p = profile.join(name);
    assert!(p.is_file(), "{} is missing: run `{how}` first", p.display());
    p
}

/// The debug `saiife`.
pub fn saiife() -> PathBuf {
    built("saiife", "cargo build -p saiife")
}

/// plan 46's fake name detector.
pub fn fake_ner() -> PathBuf {
    built(
        "saiife-fake-ner",
        "cargo build -p saiife-shield-ner --features fake --bin saiife-fake-ner",
    )
}
