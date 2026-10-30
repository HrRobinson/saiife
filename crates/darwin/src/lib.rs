//! The one crate of saiife allowed `unsafe` (plan 13, decision 1).
//!
//! It holds exactly one FFI call: `sysctl({CTL_KERN, KERN_PROC,
//! KERN_PROC_PID, pid})` on macOS, read into a `struct kinfo_proc`. That is
//! how the daemon learns a peer's parent, uid, name and start time without
//! `/proc`. `scripts/check-unsafe.sh` fails CI when `unsafe` appears in any
//! other crate.
//!
//! On every other target the crate is empty and forbids `unsafe`.
#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "macos")]
pub use macos::{proc_info, ProcInfo};

#[cfg(target_os = "macos")]
mod macos {
    use std::mem::{size_of, MaybeUninit};

    /// One process as `sysctl(KERN_PROC_PID)` reports it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProcInfo {
        /// The parent pid (`kp_eproc.e_ppid`).
        pub ppid: u32,
        /// The effective uid (`kp_eproc.e_ucred.cr_uid`).
        pub uid: u32,
        /// The process name (`kp_proc.p_comm`): at most 16 bytes, lossy UTF-8.
        pub comm: String,
        /// The start time (`kp_proc.p_starttime`) in microseconds since the
        /// epoch. Together with the pid it names one process: a reused pid
        /// has a later start time.
        pub start_us: u64,
    }

    /// Reads `pid` with `sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PID, pid})`.
    ///
    /// `None` for pid 0 (the kernel), for a pid above `i32::MAX`, when the
    /// call fails, and when it returns anything but one whole `kinfo_proc`
    /// (a pid that is gone returns size 0).
    pub fn proc_info(pid: u32) -> Option<ProcInfo> {
        if pid == 0 {
            return None;
        }
        let pid = libc::c_int::try_from(pid).ok()?;
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        // All fields are integers, integer arrays or raw pointers, so all
        // zero bytes is a valid `KinfoProc`.
        let mut kp = MaybeUninit::<KinfoProc>::zeroed();
        let mut len: libc::size_t = size_of::<KinfoProc>();
        // SAFETY: `mib` is a live array of 4 c_ints and the length passed is
        // its own. `kp` is a live, writable `KinfoProc` buffer and `len` holds
        // its exact size, so the kernel writes at most that many bytes into
        // it and stores the count it wrote back into `len`. No new value is
        // set (null pointer, length 0). None of the pointers outlive the call.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                kp.as_mut_ptr().cast::<libc::c_void>(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len != size_of::<KinfoProc>() {
            return None;
        }
        // SAFETY: `kp` was zero-initialised above, which is a valid
        // `KinfoProc` (integers, integer arrays and raw pointers only), and
        // the kernel overwrote it with a whole `kinfo_proc` (`len` checked).
        let kp = unsafe { kp.assume_init() };
        Some(from_kinfo(&kp))
    }

    fn from_kinfo(kp: &KinfoProc) -> ProcInfo {
        let comm_bytes: Vec<u8> = kp
            .kp_proc
            .p_comm
            .iter()
            .take_while(|&&c| c != 0)
            .take(libc::MAXCOMLEN)
            .map(|&c| c as u8)
            .collect();
        // In a `kinfo_proc` from sysctl, `p_un` is always `p_starttime`.
        let start = kp.kp_proc.p_starttime;
        let start_us = u64::try_from(start.tv_sec)
            .unwrap_or(0)
            .saturating_mul(1_000_000)
            .saturating_add(u64::try_from(start.tv_usec).unwrap_or(0));
        ProcInfo {
            ppid: u32::try_from(kp.kp_eproc.e_ppid).unwrap_or(0),
            uid: kp.kp_eproc.e_ucred.cr_uid,
            comm: String::from_utf8_lossy(&comm_bytes).into_owned(),
            start_us,
        }
    }

    // `libc` has no `kinfo_proc` for Apple targets, so the layout of
    // <sys/sysctl.h> and <sys/proc.h> (xnu, LP64) is written out here. Field
    // names follow the headers; pointers the kernel fills with zero or a
    // scrubbed value are never read. The size and offset checks below and
    // the runtime `len` check keep it honest: a wrong layout yields `None`
    // for every pid, which the macOS tests catch.

    const WMESGLEN: usize = 7;
    const COMAPTMAXLOGNAME: usize = 12;
    const NGROUPS: usize = 16;

    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)] // the kernel fills these; only a few are read
    struct ExternProc {
        /// The union `p_un`; sysctl fills its `__p_starttime` member.
        p_starttime: libc::timeval,
        p_vmspace: *mut libc::c_void,
        p_sigacts: *mut libc::c_void,
        p_flag: libc::c_int,
        p_stat: libc::c_char,
        p_pid: libc::pid_t,
        p_oppid: libc::pid_t,
        p_dupfd: libc::c_int,
        user_stack: *mut libc::c_char,
        exit_thread: *mut libc::c_void,
        p_debugger: libc::c_int,
        sigwait: libc::c_int,
        p_estcpu: libc::c_uint,
        p_cpticks: libc::c_int,
        p_pctcpu: u32,
        p_wchan: *mut libc::c_void,
        p_wmesg: *mut libc::c_char,
        p_swtime: libc::c_uint,
        p_slptime: libc::c_uint,
        p_realtimer: libc::itimerval,
        p_rtime: libc::timeval,
        p_uticks: u64,
        p_sticks: u64,
        p_iticks: u64,
        p_traceflag: libc::c_int,
        p_tracep: *mut libc::c_void,
        p_siglist: libc::c_int,
        p_textvp: *mut libc::c_void,
        p_holdcnt: libc::c_int,
        p_sigmask: libc::sigset_t,
        p_sigignore: libc::sigset_t,
        p_sigcatch: libc::sigset_t,
        p_priority: libc::c_uchar,
        p_usrpri: libc::c_uchar,
        p_nice: libc::c_char,
        p_comm: [libc::c_char; libc::MAXCOMLEN + 1],
        p_pgrp: *mut libc::c_void,
        p_addr: *mut libc::c_void,
        p_xstat: libc::c_ushort,
        p_acflag: libc::c_ushort,
        p_ru: *mut libc::c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)] // the kernel fills these; only a few are read
    struct Pcred {
        pc_lock: [libc::c_char; 72],
        pc_ucred: *mut libc::c_void,
        p_ruid: libc::uid_t,
        p_svuid: libc::uid_t,
        p_rgid: libc::gid_t,
        p_svgid: libc::gid_t,
        p_refcnt: libc::c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)] // the kernel fills these; only a few are read
    struct Ucred {
        cr_ref: i32,
        cr_uid: libc::uid_t,
        cr_ngroups: libc::c_short,
        cr_groups: [libc::gid_t; NGROUPS],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)] // the kernel fills these; only a few are read
    struct Vmspace {
        dummy: i32,
        dummy2: *mut libc::c_char,
        dummy3: [i32; 5],
        dummy4: [*mut libc::c_char; 3],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)] // the kernel fills these; only a few are read
    struct Eproc {
        e_paddr: *mut libc::c_void,
        e_sess: *mut libc::c_void,
        e_pcred: Pcred,
        e_ucred: Ucred,
        e_vm: Vmspace,
        e_ppid: libc::pid_t,
        e_pgid: libc::pid_t,
        e_jobc: libc::c_short,
        e_tdev: libc::dev_t,
        e_tpgid: libc::pid_t,
        e_tsess: *mut libc::c_void,
        e_wmesg: [libc::c_char; WMESGLEN + 1],
        e_xsize: i32,
        e_xrssize: libc::c_short,
        e_xccount: libc::c_short,
        e_xswrss: libc::c_short,
        e_flag: i32,
        e_login: [libc::c_char; COMAPTMAXLOGNAME],
        e_spare: [i32; 4],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct KinfoProc {
        kp_proc: ExternProc,
        kp_eproc: Eproc,
    }

    // The LP64 layout of xnu's headers (every macOS 15 target is LP64).
    const _: () = {
        use std::mem::offset_of;
        assert!(size_of::<ExternProc>() == 296);
        assert!(offset_of!(ExternProc, p_pid) == 40);
        assert!(offset_of!(ExternProc, p_comm) == 243);
        assert!(size_of::<Pcred>() == 104);
        assert!(size_of::<Ucred>() == 76);
        assert!(size_of::<Vmspace>() == 64);
        assert!(offset_of!(Eproc, e_ucred) == 120);
        assert!(offset_of!(Eproc, e_ppid) == 264);
        assert!(size_of::<Eproc>() == 352);
        assert!(size_of::<KinfoProc>() == 648);
    };

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn own_pid_has_parent_and_comm() {
            let me = proc_info(std::process::id()).expect("own pid");
            assert_eq!(me.ppid, std::os::unix::process::parent_id());
            assert!(!me.comm.is_empty());
            assert!(me.comm.len() <= 16);
            // The test binary's name starts with the crate name.
            assert!(me.comm.starts_with("saiife_darwin"), "comm {:?}", me.comm);
            // Owned by whoever runs the tests: the same uid as a file this
            // process just created.
            let dir = std::env::temp_dir();
            let f = dir.join(format!("saiife-darwin-uid-probe-{}", std::process::id()));
            std::fs::write(&f, b"").expect("write probe");
            let file_uid =
                std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&f).expect("stat probe"));
            let _ = std::fs::remove_file(&f);
            assert_eq!(me.uid, file_uid);
        }

        #[test]
        fn pid_1_is_launchd_owned_by_root() {
            let launchd = proc_info(1).expect("pid 1");
            assert_eq!(launchd.comm, "launchd");
            assert_eq!(launchd.uid, 0);
            assert_eq!(launchd.ppid, 0);
        }

        #[test]
        fn missing_pid_is_none() {
            assert_eq!(proc_info(i32::MAX as u32), None);
            assert_eq!(proc_info(0), None);
            assert_eq!(proc_info(u32::MAX), None);
        }

        #[test]
        fn start_time_stable_across_calls() {
            let a = proc_info(std::process::id()).expect("own pid");
            let b = proc_info(std::process::id()).expect("own pid");
            assert!(a.start_us > 0);
            assert_eq!(a.start_us, b.start_us);
            assert_eq!(a, b);
        }
    }
}
