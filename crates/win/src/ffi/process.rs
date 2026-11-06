//! Process-wide settings of the daemon (plan 19b, W10, W28) and free disk space.
//!
//! FFI calls: `SetDefaultDllDirectories`, `SetStdHandle`, `GetDiskFreeSpaceExW`.

use super::wide;
use std::fs::File;
use std::io;
use std::os::windows::io::IntoRawHandle;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};
use windows_sys::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

/// DLLs load from System32 only, never from the current dir or `PATH` (W28).
pub fn harden_dll_search() -> io::Result<()> {
    // SAFETY: takes one flag and no pointers.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Standard error goes to `file` for the rest of the process (W10): a service has no
/// console. `eprintln!` asks for the handle on each write, so this reaches it.
pub fn redirect_stderr(file: File) -> io::Result<()> {
    // The handle stays open for good: it is now the process's standard error.
    let handle = file.into_raw_handle();
    // SAFETY: `handle` is a valid open file whose ownership was given up just above, so
    // nothing closes it while it is the standard handle.
    if unsafe { SetStdHandle(STD_ERROR_HANDLE, handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The bytes this caller may still use on the volume of `dir`, quotas counted.
pub fn disk_free_bytes(dir: &Path) -> io::Result<u64> {
    let path = wide(dir)?;
    let mut free = 0u64;
    // SAFETY: `path` is NUL-terminated and outlives the call; `free` is a valid out
    // pointer, and the two other outs may be null.
    let ok =
        unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut free, ptr::null_mut(), ptr::null_mut()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(free)
}

/// These run in CI on windows-latest, with no admin rights assumed.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_free_of_temp_is_positive() {
        assert!(disk_free_bytes(&std::env::temp_dir()).unwrap() > 0);
    }

    #[test]
    fn disk_free_of_a_missing_dir_is_an_error() {
        let d = std::env::temp_dir().join("saiife-no-such-dir-p19b");
        assert!(disk_free_bytes(&d).is_err());
    }
}
