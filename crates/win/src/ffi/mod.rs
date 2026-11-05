//! Windows FFI (plan 19b, decision W1). The only `unsafe` in saiife outside
//! `saiife-darwin`, and every call is on the list in plan 19a's Global
//! Constraints. Each `unsafe` block is one call with a `SAFETY:` comment; each
//! handle and buffer sits in an RAII guard. Errors carry the Win32 code.
#![cfg(windows)]
#![allow(unsafe_code)]

pub mod account;
pub mod acl;
pub mod pipe;
pub mod proc;
pub mod process;
pub mod sd;
pub mod service;
pub mod token;

#[cfg(test)]
mod windows_tests;

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;

/// `s` as a NUL-terminated UTF-16 string. An interior NUL would silently cut the
/// text the call sees, so it is an error.
pub(crate) fn wide(s: impl AsRef<OsStr>) -> io::Result<Vec<u16>> {
    let mut out: Vec<u16> = s.as_ref().encode_wide().collect();
    if out.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a NUL inside a string for a Windows call",
        ));
    }
    out.push(0);
    Ok(out)
}

/// The UTF-16 units, as text. Text that is not valid UTF-16 is an error: a name
/// must never be replaced by a near match.
pub(crate) fn text_of(units: &[u16]) -> io::Result<String> {
    String::from_utf16(units).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// The NUL-terminated string at `p`, as text.
///
/// # Safety
/// `p` is non-null and points to a NUL-terminated UTF-16 string, readable for the
/// duration of the call.
pub(crate) unsafe fn text_at(p: *const u16) -> io::Result<String> {
    let mut len = 0;
    // SAFETY: the caller promises a NUL terminator, and this stops at the first
    // one, so every unit read is inside the string.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: the loop just read these `len` units; u16 needs no more alignment
    // than the caller's string has.
    text_of(unsafe { std::slice::from_raw_parts(p, len) })
}
