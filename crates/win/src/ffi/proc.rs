//! The process table (plan 19b, W17): pid, parent and exe name of every process, for
//! every user, with no rights needed.
//!
//! FFI calls: `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`, and the
//! `CloseHandle` of `token.rs`'s list.

pub use crate::proc::ProcEntry;
use std::io;
use std::mem::size_of;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

/// Closes the snapshot on every path.
struct Snapshot(HANDLE);

impl Drop for Snapshot {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful CreateToolhelp32Snapshot, and only
        // this guard closes it.
        unsafe { CloseHandle(self.0) };
    }
}

fn entry_of(e: &PROCESSENTRY32W) -> ProcEntry {
    let len = e
        .szExeFile
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(e.szExeFile.len());
    ProcEntry {
        pid: e.th32ProcessID,
        ppid: e.th32ParentProcessID,
        // Attribution only: a name that is not valid UTF-16 simply matches no agent.
        exe: String::from_utf16_lossy(&e.szExeFile[..len]),
    }
}

/// Every process running now.
pub fn snapshot() -> io::Result<Vec<ProcEntry>> {
    // SAFETY: takes no pointers. The process id is ignored for this flag.
    let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snap = Snapshot(h);
    // SAFETY: PROCESSENTRY32W is plain data, for which all zeroes is valid.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut out = Vec::new();
    // SAFETY: the handle is alive in `snap`; `entry` is valid with its size set.
    let mut more = unsafe { Process32FirstW(snap.0, &mut entry) } != 0;
    while more {
        out.push(entry_of(&entry));
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap.0, &mut entry) } != 0;
    }
    let last = io::Error::last_os_error();
    if last.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
        return Err(last);
    }
    Ok(out)
}

/// These run in CI on windows-latest, with no admin rights assumed.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_snapshot_has_own_parent() {
        let all = snapshot().unwrap();
        let me = all
            .iter()
            .find(|e| e.pid == std::process::id())
            .expect("this process is in the snapshot");
        assert_ne!(me.ppid, 0);
        assert!(me.exe.to_lowercase().ends_with(".exe"), "{}", me.exe);
    }
}
