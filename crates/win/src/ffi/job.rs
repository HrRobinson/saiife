//! A job object that kills what is in it when its last handle closes (plan 19b review,
//! finding 8). The managed hook puts its eval worker in one: however the hook ends, the
//! watchdog's `exit` or a crash included, Windows closes the handle and the worker goes
//! with it. It is the analogue of the worker dying with its parent's process group on
//! Linux.
//!
//! FFI calls: `CreateJobObjectW`, `SetInformationJobObject`
//! (`JobObjectExtendedLimitInformation`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`),
//! `AssignProcessToJobObject`. The handle is an `OwnedHandle`, closed on drop.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::process::Child;
use std::ptr;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// An unnamed job, not inheritable, whose processes are killed when it closes.
pub struct KillOnClose(OwnedHandle);

impl KillOnClose {
    pub fn new() -> io::Result<KillOnClose> {
        // SAFETY: null attributes (a handle no child inherits) and a null name (an
        // unnamed job nobody else can open) are both documented.
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a handle CreateJobObjectW just returned, and nothing else owns
        // it.
        let job = KillOnClose(unsafe { OwnedHandle::from_raw_handle(raw) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the handle is open, `limits` is the structure the class names, and the
        // length passed is its size; the call only reads it.
        let ok = unsafe {
            SetInformationJobObject(
                job.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    /// Puts `child` in the job. A process already in another job joins this one as a
    /// nested job (Windows 8 and later).
    pub fn assign(&self, child: &Child) -> io::Result<()> {
        // SAFETY: both handles are open: the job's is ours, and `child` owns its process
        // handle across the call.
        let ok = unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), child.as_raw_handle()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// These run in CI on windows-latest, with no admin rights assumed.
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// A child in the job dies when the job's handle closes, though nobody kills it.
    #[test]
    fn a_child_dies_with_the_job() {
        let ping = std::path::Path::new(&std::env::var_os("SystemRoot").unwrap())
            .join(r"System32\PING.EXE");
        // About a minute of loopback pings: long past this test's deadline.
        let mut child = Command::new(ping)
            .args(["-n", "60", "127.0.0.1"])
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let job = KillOnClose::new().unwrap();
        job.assign(&child).unwrap();
        assert!(child.try_wait().unwrap().is_none(), "still running");
        drop(job);
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() > end {
                let _ = child.kill();
                panic!("the child outlived its job");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
