//! Short temp dirs for tests; compiled on every platform.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// The longest path under a test dir that becomes a socket address:
/// `/<prefix+6 random>/run/gateway.sock`.
const SOCKET_TAIL: usize = 25;
/// `sockaddr_un.sun_path` holds 108 bytes, with the terminating NUL.
const SUN_PATH_MAX: usize = 108;

/// A temp dir for a test, under a short base so unix socket paths fit in
/// 108 bytes: `$SAIIFE_TEST_TMP`, else `$CARGO_TARGET_TMPDIR`, else
/// `<repo>/target/t`. Never `/tmp`.
pub fn short_tempdir() -> TempDir {
    let base = std::env::var_os("SAIIFE_TEST_TMP")
        .or_else(|| std::env::var_os("CARGO_TARGET_TMPDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/t"));
    fs::create_dir_all(&base).unwrap_or_else(|e| panic!("cannot create {}: {e}", base.display()));
    let base = fs::canonicalize(&base).unwrap();
    assert!(
        base.as_os_str().len() + SOCKET_TAIL < SUN_PATH_MAX,
        "the test temp base {} is too long for unix socket paths (108 bytes); \
         set SAIIFE_TEST_TMP to a short directory",
        base.display()
    );
    tempfile::Builder::new()
        .prefix("s")
        .tempdir_in(&base)
        .unwrap_or_else(|e| panic!("cannot create a temp dir in {}: {e}", base.display()))
}
