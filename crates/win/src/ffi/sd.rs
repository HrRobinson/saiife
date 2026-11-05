//! Security descriptors in memory.
//!
//! FFI calls: `ConvertStringSecurityDescriptorToSecurityDescriptorW`,
//! `ConvertSecurityDescriptorToStringSecurityDescriptorW`,
//! `GetSecurityDescriptorOwner`, `GetSecurityDescriptorDacl`, `LocalFree`.

use super::{text_at, wide};
use std::ffi::c_void;
use std::io;
use std::ptr;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, PSECURITY_DESCRIPTOR, PSID,
};

/// Memory Windows allocated for us with `LocalAlloc`, freed on drop.
pub(crate) struct LocalMem(pub(crate) *mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Windows call whose contract says to
            // free it with LocalFree, and this guard is its only owner. The call's
            // result is the pointer again on failure, with nothing to do about it.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// A self-relative security descriptor parsed from SDDL.
pub struct SecurityDescriptor {
    mem: LocalMem,
}

/// Parses `sddl` as Windows itself does.
pub fn from_sddl(sddl: &str) -> io::Result<SecurityDescriptor> {
    let text = wide(sddl)?;
    let mut raw: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `text` is NUL-terminated and outlives the call; `raw` is a valid out
    // pointer. The size out pointer may be null. On success `raw` is ours to free.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(SecurityDescriptor { mem: LocalMem(raw) })
}

impl SecurityDescriptor {
    /// The descriptor, valid while `self` lives.
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.mem.0
    }

    /// The owner's SID, valid while `self` lives. No owner is an error.
    pub fn owner_sid(&self) -> io::Result<PSID> {
        let mut owner: PSID = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: the descriptor is valid while `self` lives; both out pointers are
        // valid. The result points into the descriptor.
        let ok = unsafe { GetSecurityDescriptorOwner(self.as_ptr(), &mut owner, &mut defaulted) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if owner.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the security descriptor names no owner",
            ));
        }
        Ok(owner)
    }

    /// The DACL, valid while `self` lives. A missing or NULL DACL grants everyone
    /// everything, so both are errors, never a null pointer for a caller to apply.
    pub fn dacl(&self) -> io::Result<*mut ACL> {
        let mut present = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: the descriptor is valid while `self` lives; all three out pointers
        // are valid. The result points into the descriptor.
        let ok = unsafe {
            GetSecurityDescriptorDacl(self.as_ptr(), &mut present, &mut dacl, &mut defaulted)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the security descriptor has no DACL, or a NULL one",
            ));
        }
        Ok(dacl)
    }

    /// The parts `info` names, as SDDL.
    pub fn to_sddl(&self, info: u32) -> io::Result<String> {
        to_sddl(self.as_ptr(), info)
    }
}

/// The parts `info` names of the descriptor at `sd`, as SDDL. `sd` must be valid
/// for the call, which every caller in this module tree guarantees.
pub(crate) fn to_sddl(sd: PSECURITY_DESCRIPTOR, info: u32) -> io::Result<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: the callers pass a descriptor they hold alive; `text` is a valid out
    // pointer. The length out pointer may be null. On success `text` is ours to free.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            info,
            &mut text,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let guard = LocalMem(text.cast());
    // SAFETY: on success `text` is a NUL-terminated string, alive until `guard`
    // drops at the end of this function.
    unsafe { text_at(guard.0.cast::<u16>()) }
}
