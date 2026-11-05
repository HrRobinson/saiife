//! Windows Credential Manager, generic credentials only (the personal broker's vault key).
//!
//! FFI calls: `CredReadW`, `CredWriteW`, `CredDeleteW`, `CredFree`.
//!
//! A credential is per user and kept by the OS under the user's logon secret (DPAPI), so
//! another account cannot read it. `CRED_PERSIST_LOCAL_MACHINE`: it survives a reboot and
//! does not roam. The blob is a secret: it is copied into a [`Zeroizing`] buffer, the OS
//! copy is overwritten before `CredFree`, and no error here carries it.

use super::wide;
use crate::cred::{check_blob, check_comment, check_target};
use std::io;
use std::ptr;
use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
use windows_sys::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
    CRED_TYPE_GENERIC,
};
use zeroize::Zeroizing;

fn is_not_found(e: &io::Error) -> bool {
    e.raw_os_error()
        .is_some_and(|c| c as u32 == ERROR_NOT_FOUND)
}

/// The credential `target`, or `None` when there is none.
pub fn read(target: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    check_target(target)?;
    let name = wide(target)?;
    let mut found: *mut CREDENTIALW = ptr::null_mut();
    // SAFETY: `name` is NUL-terminated and outlives the call; `found` is a valid place
    // for the call to write one pointer.
    let ok = unsafe { CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut found) };
    if ok == 0 {
        let e = io::Error::last_os_error();
        return if is_not_found(&e) { Ok(None) } else { Err(e) };
    }
    if found.is_null() {
        return Err(io::Error::other("CredReadW returned no credential"));
    }
    // SAFETY: on success `found` points to a CREDENTIALW that stays valid until
    // `CredFree`; its blob is `CredentialBlobSize` bytes at `CredentialBlob`.
    let (blob, len) = unsafe {
        (
            (*found).CredentialBlob,
            (*found).CredentialBlobSize as usize,
        )
    };
    let out = if len == 0 {
        Ok(Zeroizing::new(Vec::new()))
    } else if blob.is_null() {
        Err(io::Error::other("a credential with a size and no data"))
    } else {
        // SAFETY: the blob is `len` readable bytes, valid until `CredFree`.
        let copy = Zeroizing::new(unsafe { std::slice::from_raw_parts(blob, len) }.to_vec());
        // SAFETY: the same `len` bytes are writable; the OS's copy of the secret is wiped
        // before it is freed.
        unsafe { ptr::write_bytes(blob, 0, len) };
        Ok(copy)
    };
    // SAFETY: `found` came from `CredReadW` and is freed once, here; it is not used again.
    unsafe { CredFree(found.cast()) };
    out.map(Some)
}

/// Create or replace the credential `target`. `comment` is shown to the user.
pub fn write(target: &str, comment: &str, blob: &[u8]) -> io::Result<()> {
    check_target(target)?;
    check_comment(comment)?;
    check_blob(blob)?;
    let mut name = wide(target)?;
    let mut note = wide(comment)?;
    let cred = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: name.as_mut_ptr(),
        Comment: note.as_mut_ptr(),
        CredentialBlobSize: blob.len() as u32,
        // `CredWriteW` only reads the blob; the field is `*mut` for the sake of reads.
        CredentialBlob: blob.as_ptr().cast_mut(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..Default::default()
    };
    // SAFETY: `cred` is complete: the strings are NUL-terminated and the blob is
    // `blob.len()` bytes, all alive across the call, which copies them and writes
    // nothing through the pointers.
    let ok = unsafe { CredWriteW(&cred, 0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Remove the credential `target`; `false` when there was none.
pub fn delete(target: &str) -> io::Result<bool> {
    check_target(target)?;
    let name = wide(target)?;
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let ok = unsafe { CredDeleteW(name.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if ok == 0 {
        let e = io::Error::last_os_error();
        return if is_not_found(&e) { Ok(false) } else { Err(e) };
    }
    Ok(true)
}

/// Run in CI's `test` job on `windows-latest`. They touch the runner's own Credential
/// Manager under a random `saiife-test:` target and delete it again.
#[cfg(test)]
mod tests {
    use super::*;

    /// No RNG crate here: the clock and the process id are random enough for a test name.
    fn target() -> String {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        format!(
            "saiife-test:{:016x}",
            t ^ (u64::from(std::process::id()) << 40)
        )
    }

    #[test]
    fn wincred_roundtrip() {
        let t = target();
        assert_eq!(read(&t).unwrap(), None);
        write(&t, "saiife test item", &[9u8; 32]).unwrap();
        assert_eq!(read(&t).unwrap().unwrap().as_slice(), &[9u8; 32]);
        // A second write replaces.
        write(&t, "saiife test item", &[5u8; 16]).unwrap();
        assert_eq!(read(&t).unwrap().unwrap().as_slice(), &[5u8; 16]);
        assert!(delete(&t).unwrap());
        assert!(!delete(&t).unwrap());
        assert_eq!(read(&t).unwrap(), None);
    }

    #[test]
    fn a_bad_target_or_blob_never_reaches_windows() {
        assert!(read("").is_err());
        assert!(write("saiife-test:x", "c", &vec![0u8; crate::cred::MAX_BLOB + 1]).is_err());
        assert!(delete("a\0b").is_err());
    }
}
