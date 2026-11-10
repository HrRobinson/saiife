//! The process table (plan 19b, W17): pid, parent and exe name of every process, for
//! every user, with no rights needed. [`snapshot_timed`] adds each process's creation
//! time and session where the caller may read them (plan 21: the co-signer's process
//! tree tie).
//!
//! FFI calls: `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`,
//! `OpenProcess` (`PROCESS_QUERY_LIMITED_INFORMATION`), `GetProcessTimes`,
//! `ProcessIdToSessionId`, and the `CloseHandle` of `token.rs`'s list.

pub use crate::proc::ProcEntry;
use std::io;
use std::mem::size_of;
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
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
        created: None,
        session: None,
    }
}

/// Closes a process handle on every path.
struct Process(HANDLE);

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful OpenProcess, and only this guard
        // closes it.
        unsafe { CloseHandle(self.0) };
    }
}

/// When `pid` was created (100 ns ticks since 1601); `None` when it cannot be opened
/// for `PROCESS_QUERY_LIMITED_INFORMATION` (another user's process, for a caller
/// without rights to it) or has exited.
pub fn created(pid: u32) -> Option<u64> {
    // SAFETY: takes no pointers; a failed open returns a null handle.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let p = Process(h);
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: the handle is alive in `p`; the four out pointers are valid FILETIMEs.
    let ok = unsafe { GetProcessTimes(p.0, &mut created, &mut exited, &mut kernel, &mut user) };
    (ok != 0).then(|| (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// The Remote Desktop session of `pid`; `None` when the caller may not read it.
pub fn session(pid: u32) -> Option<u32> {
    let mut id = 0u32;
    // SAFETY: `id` is a valid out pointer for the call.
    let ok = unsafe { ProcessIdToSessionId(pid, &mut id) };
    (ok != 0).then_some(id)
}

/// [`snapshot`], with each process's creation time and session where they can be
/// read. One open per process: for the co-signer's tie, not for a hot path.
pub fn snapshot_timed() -> io::Result<Vec<ProcEntry>> {
    let mut all = snapshot()?;
    for e in &mut all {
        e.created = created(e.pid);
        e.session = session(e.pid);
    }
    Ok(all)
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
        assert_eq!((me.created, me.session), (None, None), "names only");
    }

    #[test]
    fn timed_snapshot_has_own_start_and_session() {
        let all = snapshot_timed().unwrap();
        let me = all.iter().find(|e| e.pid == std::process::id()).unwrap();
        assert!(me.created.is_some_and(|t| t > 0), "{me:?}");
        assert_eq!(me.session, session(std::process::id()));
        assert!(me.session.is_some());
        // The parent was created before this process, so the tree ties.
        let parent = all.iter().find(|e| e.pid == me.ppid);
        if let Some(c) = parent.and_then(|p| p.created) {
            assert!(c <= me.created.unwrap());
        }
        assert_eq!(created(0), None, "the idle process cannot be opened");
    }
}
