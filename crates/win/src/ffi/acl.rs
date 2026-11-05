//! File and directory ACLs as SDDL.
//!
//! FFI calls: `GetSecurityInfo`, `SetSecurityInfo`, `GetFileInformationByHandle`,
//! `GetFinalPathNameByHandleW`, `CreateDirectoryW`.
//!
//! The named-path calls follow a reparse point, and between any check and such a call
//! a writer of the parent could swap one in, and an elevated `set_sddl` would re-ACL its
//! target. So both functions here open the path itself, without following the last
//! component, check that handle, and act on the same handle. The object checked is the
//! object changed.
//!
//! `set_sddl` also refuses a file with more than one hard link, read from that handle: a
//! descriptor belongs to the file, so the set would reach the link's target. As Linux
//! does in `check_daemon_file`.
//!
//! A junction higher up the path is still followed on open. So `set_sddl` also asks the
//! handle where it really is and refuses if that is not the path it was given. Callers
//! check the ancestors top-down before every set as well (W14, `ancestor_ok`).

use super::account;
use super::sd::{self, LocalMem};
use super::text_of;
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
    CreateDirectoryW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, READ_CONTROL, VOLUME_NAME_DOS, WRITE_DAC, WRITE_OWNER,
};

const ERROR_SHARING_VIOLATION: i32 = 32;

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

/// An error if `file`, open as `path`, is a file with more than one hard link
/// ([`sddl::check_links`]). The handle stays open across the set that follows, so what
/// this reads is the object changed.
fn refuse_hard_links(file: &File, path: &Path) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open with FILE_READ_ATTRIBUTES and `file` outlives the call;
    // `info` is a valid place for the call to write.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    sddl::check_links(info.dwFileAttributes, info.nNumberOfLinks).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: {e}", path.display()),
        )
    })
}

/// An error unless `file`, opened as `path`, really is at `path`
/// ([`sddl::same_final_path`]). The open follows a junction above the last component;
/// this is what catches one swapped in after the caller checked the chain.
fn refuse_redirect(file: &File, path: &Path) -> io::Result<()> {
    let mut buf = vec![0u16; 1024];
    let len = loop {
        // SAFETY: the handle is open and `file` outlives the call; `buf` holds as many
        // units as the length passed.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            break n;
        }
        // Too small: `n` is the size it needs, terminator included.
        buf.resize(n, 0);
    };
    let actual = text_of(&buf[..len])?;
    let expected = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not valid text", path.display()),
        )
    })?;
    if !sddl::same_final_path(expected, &actual) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{expected} is really {actual}: a reparse point is on the way"),
        ));
    }
    Ok(())
}

/// Holds the directory `path` so it cannot be renamed or deleted while the handle lives:
/// it gives no `FILE_SHARE_DELETE`. A reparse point is an error.
///
/// It asks for `FILE_LIST_DIRECTORY` on purpose. Windows leaves a handle out of its
/// sharing checks when it asks only for attributes, and such a handle would deny nothing.
pub fn hold_dir(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
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

/// Takes the lock file `path`: open with no sharing at all, so one holder at a time, and
/// deleted when the handle closes, a crash included. `Ok(None)` when another holds it. The
/// caller has checked that only administrators can write the directory.
pub fn lock_file(path: &Path) -> io::Result<Option<File>> {
    let opened = OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
        .share_mode(0)
        .create(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_DELETE_ON_CLOSE)
        .open(path);
    let file = match opened {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => return Ok(None),
        Err(e) => return Err(e),
    };
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a reparse point", path.display()),
        ));
    }
    Ok(Some(file))
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
/// point, a file with more than one hard link, or a handle that is not really at `path`
/// is an error. So `path` must be the long, canonical spelling.
///
/// This propagates, as CI showed: `SetSecurityInfo` on a directory handle gave an
/// existing child that inherits exactly the new inheritable entries, as inherited
/// entries, in place of what it inherited before (its `A;ID;FA;;;BA` became
/// `A;ID;FA;;;LA` with the parent's). Not yet seen in CI, and expected: it does not reach
/// a child with `P` set, nor an explicit entry a child holds, so the caller still sets those
/// itself (`winacl::set_sddl_tree`). Pinned by `set_sddl_on_temp_dir_roundtrips`.
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
    refuse_hard_links(&file, path)?;
    refuse_redirect(&file, path)?;
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
