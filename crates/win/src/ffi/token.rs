//! Who a token is.
//!
//! FFI calls: `GetCurrentProcess`, `OpenProcessToken`, `GetCurrentThread`,
//! `OpenThreadToken`, `GetTokenInformation` (`TokenUser`, `TokenGroups`),
//! `CloseHandle`.

use super::account::sid_to_string;
pub use crate::sid::TokenFacts;
use std::io;
use std::mem::size_of;
use std::ptr;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, HANDLE, TRUE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenGroups, TokenUser, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

/// A token handle, closed on drop.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenThreadToken or OpenProcessToken, and this
        // guard is its only owner.
        unsafe { CloseHandle(self.0) };
    }
}

/// The calling thread's token when it is impersonating, or else the process's. The
/// access check runs as the process, so an impersonated client without rights on its
/// own token still gets an answer.
fn open_current() -> io::Result<Token> {
    let mut handle: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentThread takes nothing and returns a pseudo handle that needs
    // no closing. `handle` is a valid out pointer.
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &mut handle) };
    if ok != 0 {
        return Ok(Token(handle));
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
        return Err(e);
    }
    // SAFETY: GetCurrentProcess takes nothing and returns a pseudo handle that needs
    // no closing. `handle` is a valid out pointer.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Token(handle))
}

/// One class of a token's information, in a buffer aligned for what it holds.
struct Info {
    buf: Vec<u64>,
    bytes: usize,
}

fn info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Info> {
    let mut needed = 0u32;
    // SAFETY: a null buffer with length 0 is the documented way to ask for the size;
    // `needed` is a valid out pointer. A bad handle is an error, not undefined.
    let ok = unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &mut needed) };
    if ok == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(e);
        }
    }
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    let len = (buf.len() * 8) as u32;
    // SAFETY: `buf` is `len` bytes long and aligned for the pointers the structures
    // hold; `needed` is a valid out pointer.
    let ok =
        unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut needed) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Info {
        buf,
        bytes: needed as usize,
    })
}

/// The facts of the current token: see [`open_current`].
pub fn current() -> io::Result<TokenFacts> {
    let token = open_current()?;
    facts_of(token.0)
}

/// The facts of a token opened with `TOKEN_QUERY`. The caller keeps the handle. A
/// handle that is no such token is an error.
pub fn facts_of(token: HANDLE) -> io::Result<TokenFacts> {
    let user = info(token, TokenUser)?;
    if user.bytes < size_of::<TOKEN_USER>() {
        return Err(short_answer());
    }
    // SAFETY: the buffer holds a TOKEN_USER (just checked), aligned by Vec<u64>. Its
    // SID points into the same buffer, alive across the read and the conversion.
    let sid = unsafe { sid_to_string((*user.buf.as_ptr().cast::<TOKEN_USER>()).User.Sid) }?;

    let groups = info(token, TokenGroups)?;
    let base = groups.buf.as_ptr().cast::<TOKEN_GROUPS>();
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    if groups.bytes < offset {
        return Err(short_answer());
    }
    // SAFETY: the buffer holds at least the count (just checked), aligned by Vec<u64>.
    let count = unsafe { (*base).GroupCount } as usize;
    let room = (groups.bytes - offset) / size_of::<SID_AND_ATTRIBUTES>();
    if count > room {
        return Err(short_answer());
    }
    // SAFETY: `count` entries follow the count (just checked against the buffer); the
    // pointer keeps the provenance of the whole buffer, which outlives this slice.
    let entries = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*base).Groups).cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let groups_with_attrs = entries
        .iter()
        // SAFETY: each entry's SID points into `groups.buf`, alive across this.
        .map(|g| Ok((unsafe { sid_to_string(g.Sid) }?, g.Attributes)))
        .collect::<io::Result<Vec<_>>>()?;
    Ok(TokenFacts::from_groups(sid, groups_with_attrs))
}

fn short_answer() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "GetTokenInformation returned too little",
    )
}
