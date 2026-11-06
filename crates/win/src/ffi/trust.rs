//! Whether Windows accepts a file's embedded Authenticode signature.
//!
//! FFI calls: `WinVerifyTrust`.
//!
//! In-process, so an elevated doctor runs no program to ask, and no program of the
//! caller's choosing can answer (see `doctor/windows.rs`). Revocation is not fetched: this
//! must not reach the network, and no window may open.

use super::wide;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// What `WinVerifyTrust` answers for the signature in `path`: 0 is trusted, anything else
/// an `HRESULT` saying why not. Reading it is the caller's.
pub fn authenticode_status(path: &Path) -> io::Result<i32> {
    let path = wide(path)?;
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..WINTRUST_DATA::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let no_window: HANDLE = ptr::null_mut();
    // SAFETY: `action` and `data` are valid for the call, `data` names `file`, and `file`
    // names `path`, a NUL-terminated string; all outlive this function's two calls.
    let status = unsafe {
        WinVerifyTrust(
            no_window.cast(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: as above. Closing frees what the verify step left in `hWVTStateData`, whatever
    // it answered; its result says nothing about the file.
    let _ = unsafe {
        WinVerifyTrust(
            no_window.cast(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    Ok(status)
}
