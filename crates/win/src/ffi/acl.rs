//! File and directory ACLs as SDDL.
//!
//! FFI calls: `GetNamedSecurityInfoW`, `SetNamedSecurityInfoW`, `CreateDirectoryW`.
//!
//! `GetNamedSecurityInfoW` and `SetNamedSecurityInfoW` follow a reparse point, so
//! they would read or re-ACL its target. Both refuse a path that is one. That check
//! and the call are two steps, so it stops a planted link, not one a writer of the
//! parent swaps in between; callers also check that the ancestors are safe (W14).

use super::sd::{self, LocalMem};
use super::wide;
use crate::sddl;
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FALSE};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT};

/// An error unless `path` exists and is no reparse point.
fn refuse_reparse_point(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a reparse point", path.display()),
        ));
    }
    Ok(())
}

/// The descriptor text `sddl` as [`sddl::check_settable`] allows, parsed by Windows.
fn settable(sddl_text: &str) -> io::Result<sd::SecurityDescriptor> {
    sddl::check_settable(sddl_text).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    sd::from_sddl(sddl_text)
}

/// The owner, group and DACL of `path`, as SDDL. A reparse point is an error.
pub fn get_sddl(path: &Path) -> io::Result<String> {
    refuse_reparse_point(path)?;
    let name = wide(path)?;
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut raw: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `name` is NUL-terminated and outlives the call. The owner, group, DACL
    // and SACL out pointers may be null, as `raw` receives the whole descriptor. On
    // success `raw` is ours to free.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
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
    sd::to_sddl(guard.0, info)
}

/// Sets the owner and a protected DACL of `path` from `sddl_text`, which must name an
/// owner and say `D:P`. A group in the text is not applied. A reparse point is an
/// error.
pub fn set_sddl(path: &Path, sddl_text: &str) -> io::Result<()> {
    let desc = settable(sddl_text)?;
    let owner = desc.owner_sid()?;
    let dacl = desc.dacl()?;
    refuse_reparse_point(path)?;
    let name = wide(path)?;
    // SAFETY: `name` is NUL-terminated and outlives the call. `owner` and `dacl` point
    // into `desc`, alive across the call, and neither is null. The group and SACL may
    // be null, as their flags are not passed.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            ptr::null_mut(),
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
