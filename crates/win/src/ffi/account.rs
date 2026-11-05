//! SIDs, account names and local groups.
//!
//! FFI calls: `ConvertSidToStringSidW`, `ConvertStringSidToSidW`,
//! `LookupAccountNameW`, `LookupAccountSidW`, `NetUserGetLocalGroups`,
//! `NetLocalGroupGetMembers`, `NetApiBufferFree`.
//!
//! The SID is the identity: a name is only ever looked up to reach one.

use super::sd::LocalMem;
use super::{text_at, text_of, wide};
use std::ffi::c_void;
use std::io;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetApiBufferFree, NetLocalGroupGetMembers, NetUserGetLocalGroups,
    LG_INCLUDE_INDIRECT, LOCALGROUP_MEMBERS_INFO_3, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{LookupAccountNameW, LookupAccountSidW, PSID, SID_NAME_USE};

/// What a group member without a readable name appears as. It is never a user name,
/// so a "no other members" check refuses it.
pub const UNNAMED_MEMBER: &str = "<member without a name>";

/// The SID at `sid` as text. `sid` must be valid for the call, which every caller in
/// this module tree guarantees.
pub(crate) fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: the callers pass a SID they hold alive; `text` is a valid out pointer.
    // On success `text` is ours to free with LocalFree.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let guard = LocalMem(text.cast());
    // SAFETY: on success `text` is a NUL-terminated string, alive until `guard` drops
    // at the end of this function.
    unsafe { text_at(guard.0.cast::<u16>()) }
}

/// `DOMAIN\name`, or just `name` for the few accounts with no domain (`Everyone`).
fn qualified(domain: &str, name: &str) -> String {
    if domain.is_empty() {
        name.to_string()
    } else {
        format!(r"{domain}\{name}")
    }
}

/// The SID and the canonical `DOMAIN\name` of the account `name`, which may be
/// written `name` or `DOMAIN\name`.
pub fn lookup_name(name: &str) -> io::Result<(String, String)> {
    if name.is_empty() {
        // Windows answers an empty name with the machine's own SID.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an empty account name",
        ));
    }
    let account = wide(name)?;
    let mut sid_bytes = 0u32;
    let mut domain_len = 0u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: `account` is NUL-terminated. Null buffers with zero sizes are the
    // documented way to ask for the sizes; every out pointer is valid.
    let ok = unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &mut sid_bytes,
            ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(e);
        }
    }
    // A SID holds u32s, so its buffer is built of them.
    let mut sid_buf = vec![0u32; (sid_bytes as usize).div_ceil(4).max(1)];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    let mut domain_len = domain.len() as u32;
    // SAFETY: both buffers are as long as the sizes passed, and every pointer is valid
    // for the call.
    let ok = unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid_buf.as_mut_ptr().cast(),
            &mut sid_bytes,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = sid_to_string(sid_buf.as_mut_ptr().cast())?;
    let canonical = lookup_sid(&sid)?;
    Ok((sid, canonical))
}

/// The SID in binary, as `ConvertStringSidToSidW` made it.
pub(crate) struct BinarySid(LocalMem);

impl BinarySid {
    /// The SID, valid while `self` lives.
    pub(crate) fn as_psid(&self) -> PSID {
        (self.0).0
    }
}

pub(crate) fn binary_sid(sid: &str) -> io::Result<BinarySid> {
    let text = wide(sid)?;
    let mut raw: PSID = ptr::null_mut();
    // SAFETY: `text` is NUL-terminated and outlives the call; `raw` is a valid out
    // pointer. On success `raw` is ours to free with LocalFree.
    let ok = unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut raw) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(BinarySid(LocalMem(raw)))
}

/// The canonical `DOMAIN\name` of the SID in text.
pub fn lookup_sid(sid: &str) -> io::Result<String> {
    let binary = binary_sid(sid)?;
    let raw = binary.as_psid();
    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: `raw` is alive in `binary`. Null buffers with zero sizes are the
    // documented way to ask for the sizes; every out pointer is valid.
    let ok = unsafe {
        LookupAccountSidW(
            ptr::null(),
            raw,
            ptr::null_mut(),
            &mut name_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(e);
        }
    }
    let mut name = vec![0u16; name_len.max(1) as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    // SAFETY: both buffers are as long as the sizes passed, and every pointer is valid
    // for the call.
    let ok = unsafe {
        LookupAccountSidW(
            ptr::null(),
            raw,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // On success the lengths leave out the terminator.
    let name = text_of(&name[..name_len as usize])?;
    let domain = text_of(&domain[..domain_len as usize])?;
    Ok(qualified(&domain, &name))
}

/// A buffer a `Net*` call allocated, freed on drop.
struct NetBuf(*mut u8);

impl Drop for NetBuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Net* call whose contract says to free it
            // with NetApiBufferFree, and this guard is its only owner.
            unsafe { NetApiBufferFree(self.0.cast::<c_void>().cast_const()) };
        }
    }
}

/// An error unless a `Net*` call succeeded and returned everything it had. A partial
/// list could hide a member, so it is no answer.
fn check_net(status: u32, read: u32, total: u32) -> io::Result<()> {
    if status != NERR_Success {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if read != total {
        return Err(io::Error::from_raw_os_error(ERROR_MORE_DATA as i32));
    }
    Ok(())
}

/// The local groups `user` is in, nested ones included. Names only: group names are
/// localized, so compare the SIDs [`lookup_name`] gives for them.
pub fn local_groups_of(user: &str) -> io::Result<Vec<String>> {
    let account = wide(user)?;
    let mut buf: *mut u8 = ptr::null_mut();
    let (mut read, mut total) = (0u32, 0u32);
    // SAFETY: `account` is NUL-terminated; every out pointer is valid. A null server
    // is this machine. On return a non-null `buf` is ours to free.
    let status = unsafe {
        NetUserGetLocalGroups(
            ptr::null(),
            account.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
        )
    };
    let guard = NetBuf(buf);
    check_net(status, read, total)?;
    if read == 0 || guard.0.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: at level 0 the buffer is `read` LOCALGROUP_USERS_INFO_0 entries, aligned
    // by the allocator, alive while `guard` lives.
    let entries = unsafe {
        std::slice::from_raw_parts(
            guard.0.cast::<LOCALGROUP_USERS_INFO_0>().cast_const(),
            read as usize,
        )
    };
    entries
        .iter()
        // SAFETY: each name is a NUL-terminated string inside the same buffer.
        .map(|e| unsafe { text_at(e.lgrui0_name) })
        .collect()
}

/// The members of the local group `group`, as `DOMAIN\name`. A member Windows gives
/// no name for is [`UNNAMED_MEMBER`].
pub fn local_group_members(group: &str) -> io::Result<Vec<String>> {
    let name = wide(group)?;
    let mut buf: *mut u8 = ptr::null_mut();
    let (mut read, mut total) = (0u32, 0u32);
    // SAFETY: `name` is NUL-terminated; every out pointer is valid. A null server is
    // this machine, and a null resume handle asks for one call. On return a non-null
    // `buf` is ours to free.
    let status = unsafe {
        NetLocalGroupGetMembers(
            ptr::null(),
            name.as_ptr(),
            3,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            ptr::null_mut(),
        )
    };
    let guard = NetBuf(buf);
    check_net(status, read, total)?;
    if read == 0 || guard.0.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: at level 3 the buffer is `read` LOCALGROUP_MEMBERS_INFO_3 entries,
    // aligned by the allocator, alive while `guard` lives.
    let entries = unsafe {
        std::slice::from_raw_parts(
            guard.0.cast::<LOCALGROUP_MEMBERS_INFO_3>().cast_const(),
            read as usize,
        )
    };
    entries
        .iter()
        .map(|e| {
            if e.lgrmi3_domainandname.is_null() {
                return Ok(UNNAMED_MEMBER.to_string());
            }
            // SAFETY: a non-null name is a NUL-terminated string inside the same buffer.
            unsafe { text_at(e.lgrmi3_domainandname) }
        })
        .collect()
}
