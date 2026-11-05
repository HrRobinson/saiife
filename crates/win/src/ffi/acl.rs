//! File and directory ACLs as SDDL.
//!
//! FFI calls: `GetSecurityInfo`, `SetSecurityInfo`, `CreateDirectoryW`.
//!
//! The named-path calls follow a reparse point, and between any check and such a call
//! a writer of the parent could swap one in, and an elevated `set_sddl` would re-ACL its
//! target. So both functions here open the path itself, without following the last
//! component, check that handle, and act on the same handle. The object checked is the
//! object changed.
//!
//! This covers the last component only. A junction higher up the path is still followed
//! on open, so callers check the ancestors top-down before every set (W14, `ancestor_ok`).

use super::account;
use super::sd::{self, LocalMem};
use super::wide;
use crate::sddl;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FALSE};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};

/// `path` itself, file or dir, opened with `access` and without following a final
/// reparse point. An error if it is one.
fn open_no_follow(path: &Path, access: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        // `metadata` below reads attributes.
        .access_mode(access | FILE_READ_ATTRIBUTES)
        // Backup semantics: without it a directory cannot be opened at all.
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a reparse point", path.display()),
        ));
    }
    Ok(file)
}

/// The descriptor text `sddl` as [`sddl::check_settable`] allows, parsed by Windows.
fn settable(sddl_text: &str) -> io::Result<sd::SecurityDescriptor> {
    sddl::check_settable(sddl_text).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    sd::from_sddl(sddl_text)
}

/// The owner, group and DACL of `path`, as SDDL. A reparse point is an error.
pub fn get_sddl(path: &Path) -> io::Result<String> {
    let file = open_no_follow(path, READ_CONTROL)?;
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut raw: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the handle is open with READ_CONTROL and `file` outlives the call. The
    // owner, group, DACL and SACL out pointers may be null, as `raw` receives the whole
    // descriptor. On success `raw` is ours to free.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            info,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut raw,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let guard = LocalMem(raw);
    // SAFETY: `guard` holds the descriptor Windows just returned, alive across the call.
    unsafe { sd::to_sddl(guard.0, info) }
}

/// Sets the owner, a protected DACL and any group of `path` from `sddl_text`, which
/// must name an owner and say `D:P`. The group counts because `winacl::actual_ok`
/// compares it: `G:SY` left unset would fail every later check of the path. A reparse
/// point is an error.
pub fn set_sddl(path: &Path, sddl_text: &str) -> io::Result<()> {
    let desc = settable(sddl_text)?;
    let parsed =
        sddl::parse(sddl_text).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let group = parsed
        .group
        .as_deref()
        .map(account::binary_sid)
        .transpose()?;
    let (group_ptr, group_flag) = match &group {
        Some(g) => (g.as_psid(), GROUP_SECURITY_INFORMATION),
        None => (ptr::null_mut(), 0),
    };
    let owner = desc.owner_sid()?;
    let dacl = desc.dacl()?;
    let file = open_no_follow(path, READ_CONTROL | WRITE_DAC | WRITE_OWNER)?;
    // SAFETY: the handle is open with WRITE_DAC and WRITE_OWNER, and `file` outlives the
    // call. `owner` and `dacl` point into `desc`, alive across the call, and neither is
    // null. `group_ptr` is alive in `group`, and null only when its flag is not passed.
    // The SACL may be null, as its flag is not passed.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | group_flag,
            owner,
            group_ptr,
            dacl,
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Creates the directory `path` holding `sddl_text` from its first moment, so it
/// never has an ACL inherited from its parent. An existing path is an error
/// (`ERROR_ALREADY_EXISTS`), so nobody else's dir is taken over.
pub fn create_dir_with_sddl(path: &Path, sddl_text: &str) -> io::Result<()> {
    let desc = settable(sddl_text)?;
    desc.dacl()?;
    let name = wide(path)?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: desc.as_ptr(),
        bInheritHandle: FALSE,
    };
    // SAFETY: `name` is NUL-terminated, and `attrs` and the descriptor it points to
    // are alive across the call.
    let ok = unsafe { CreateDirectoryW(name.as_ptr(), &attrs) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
