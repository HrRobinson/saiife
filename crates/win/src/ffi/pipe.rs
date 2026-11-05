//! The named pipe's Windows calls (plan 19b, decision W11). The rules, and the order
//! of the impersonation calls, are in [`crate::pipe`], where Linux tests reach them.
//!
//! FFI calls: `ServerOptions::create_with_security_attributes_raw` (tokio, feature
//! `pipe-server`), `GetNamedPipeClientProcessId`, `ImpersonateNamedPipeClient`,
//! `RevertToSelf`, `GetSecurityInfo`. The token itself is read in `token.rs`.

use super::account::sid_to_string;
use super::sd::LocalMem;
use crate::pipe::{
    check_pipe_name, read_identity, IdentityOps, PeerToken, CLIENT_ACCESS, CLIENT_QOS,
};
pub use crate::pipe::{control_sddl, PipeClient};
use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    RevertToSelf, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};

const _: () = assert!(CLIENT_QOS == SECURITY_IDENTIFICATION);

/// A server instance of `name` with the descriptor `sddl`.
///
/// Refuses a descriptor with no owner or a missing or NULL DACL, and a pipe whose owner
/// is not the descriptor's: see [`crate::pipe::create_checked`]. A name someone else
/// holds is `ErrorKind::AlreadyExists`, with W11's log line as its text. Must run inside
/// a tokio runtime with I/O enabled.
#[cfg(feature = "pipe-server")]
pub fn create_server(
    name: &str,
    sddl: &str,
    first: bool,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let sd = super::sd::from_sddl(sddl)?;
    sd.dacl()?;
    let owner = sd.owner_sid()?;
    // SAFETY: `owner` points into `sd`, alive across the call.
    let owner = unsafe { sid_to_string(owner) }?;
    crate::pipe::create_checked(&server::Real { name, sd: &sd }, name, &owner, first)
}

#[cfg(feature = "pipe-server")]
mod server {
    use super::super::sd::SecurityDescriptor;
    use super::owner_sid;
    use crate::pipe::{Namespace, ServerPlan};
    use std::io;
    use std::mem::size_of;
    use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    pub(super) struct Real<'a> {
        pub(super) name: &'a str,
        pub(super) sd: &'a SecurityDescriptor,
    }

    impl Namespace for Real<'_> {
        type Instance = NamedPipeServer;

        fn create(&self, plan: &ServerPlan) -> io::Result<NamedPipeServer> {
            let mode = if plan.byte_mode {
                PipeMode::Byte
            } else {
                PipeMode::Message
            };
            let mut attrs = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.sd.as_ptr(),
                bInheritHandle: FALSE,
            };
            // SAFETY: `attrs` is a complete SECURITY_ATTRIBUTES, the size set, and it and
            // the descriptor it points to outlive the call. Windows copies what it needs.
            unsafe {
                ServerOptions::new()
                    .first_pipe_instance(plan.first_pipe_instance)
                    .reject_remote_clients(plan.reject_remote_clients)
                    .max_instances(plan.max_instances)
                    .pipe_mode(mode)
                    .create_with_security_attributes_raw(
                        self.name,
                        (&raw mut attrs).cast::<std::ffi::c_void>(),
                    )
            }
        }

        fn owner(&self, instance: &NamedPipeServer) -> io::Result<String> {
            owner_sid(instance)
        }
    }
}

/// Opens the pipe as a client: identification level only, and only the rights the
/// control pipe's DACL gives Users. The handle is synchronous. The caller checks
/// [`owner_sid`] on this handle before it writes anything.
pub fn open_client(name: &str) -> io::Result<File> {
    check_pipe_name(name)?;
    std::fs::OpenOptions::new()
        .access_mode(CLIENT_ACCESS)
        .security_qos_flags(CLIENT_QOS)
        .open(name)
}

/// The owner of the kernel object behind `handle`, as a SID. The handle needs
/// `READ_CONTROL`, which [`open_client`] asks for.
pub fn owner_sid(handle: &impl AsRawHandle) -> io::Result<String> {
    let mut owner: PSID = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the handle lives as long as the borrow, and a bad one is an error. Both out
    // pointers are valid and the rest may be null. On success `sd` is ours to free, and
    // `owner` points into it.
    let code = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let _sd = LocalMem(sd);
    if owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the pipe has no owner",
        ));
    }
    // SAFETY: non-null (just checked), and it points into the descriptor `_sd` holds
    // alive until this function returns.
    unsafe { sid_to_string(owner) }
}

/// Who is on the other end of a server instance. Synchronous: it impersonates the client,
/// reads its token and reverts in this one call, on this thread. A failing `RevertToSelf`
/// aborts the process, which must never go on running as the client.
pub fn client_facts(pipe: &impl AsRawHandle) -> io::Result<PipeClient> {
    read_identity(&RealIdentity {
        pipe: pipe.as_raw_handle(),
    })
}

struct RealIdentity {
    pipe: HANDLE,
}

impl IdentityOps for RealIdentity {
    fn client_pid(&self) -> io::Result<u32> {
        let mut pid = 0u32;
        // SAFETY: the caller's borrow keeps the handle alive, and a bad one is an error.
        // `pid` is a valid out pointer.
        if unsafe { GetNamedPipeClientProcessId(self.pipe, &mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }

    fn impersonate(&self) -> io::Result<()> {
        // SAFETY: the caller's borrow keeps the handle alive, and a bad one is an error.
        // On success this thread impersonates, and `read_identity` reverts it.
        if unsafe { ImpersonateNamedPipeClient(self.pipe) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_thread_token(&self) -> io::Result<PeerToken> {
        super::token::impersonated()
    }

    fn revert(&self) -> io::Result<()> {
        // SAFETY: takes nothing and acts on this thread only.
        if unsafe { RevertToSelf() } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn revert_failed(&self, _: &io::Error) {
        std::process::abort();
    }
}

/// These run in CI on windows-latest, with no admin rights assumed: no Windows machine
/// builds this crate locally. Each pipe here belongs to the test, with the runner's own
/// SID as its owner.
#[cfg(all(test, feature = "pipe-server"))]
mod tests {
    use super::super::token;
    use super::*;
    use crate::pipe::{ERROR_ACCESS_DENIED, MAX_INSTANCES};
    use crate::sid::valid_sid;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::net::windows::named_pipe::PipeMode;

    fn unique_name(test: &str) -> String {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\saiife-test-{}-{n}-{test}", std::process::id())
    }

    fn me() -> String {
        token::current().unwrap().sid
    }

    /// The runner may do everything, as the service may on the control pipe.
    fn full_sddl(sid: &str) -> String {
        format!("O:{sid}G:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)")
    }

    /// The runner holds only what Users hold on the control pipe.
    fn users_sddl(sid: &str) -> String {
        format!("O:{sid}G:{sid}D:P(A;;0x12019b;;;{sid})(A;;GA;;;SY)")
    }

    #[tokio::test]
    async fn client_facts_names_the_runner() {
        let before = token::current().unwrap();
        let name = unique_name("facts");
        let server = create_server(&name, &full_sddl(&before.sid), true).unwrap();
        let _client = open_client(&name).unwrap();
        server.connect().await.unwrap();

        let got = client_facts(&server).unwrap();
        assert_eq!(got.facts.sid, before.sid);
        assert!(valid_sid(&got.facts.sid));
        // The real integrity and restricted-SID reads: the runner's own token is what it
        // is, so an elevated runner (W23) stays elevated on the pipe.
        assert_eq!(got.facts.group_sids, before.group_sids);
        assert_eq!(got.facts.elevated_admin, before.elevated_admin);
        assert_eq!(got.pid, std::process::id());
    }

    #[tokio::test]
    async fn client_facts_leaves_the_thread_reverted() {
        let name = unique_name("reverted");
        let server = create_server(&name, &full_sddl(&me()), true).unwrap();
        let _client = open_client(&name).unwrap();
        server.connect().await.unwrap();
        client_facts(&server).unwrap();

        // OpenThreadToken is ERROR_NO_TOKEN again: no thread token remains.
        let e = RealIdentity {
            pipe: server.as_raw_handle(),
        }
        .read_thread_token()
        .err()
        .unwrap();
        assert_eq!(
            e.raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_NO_TOKEN as i32)
        );
    }

    /// No client has connected, so impersonation fails: an error, not the process token.
    #[tokio::test]
    async fn client_facts_with_no_client_is_an_error() {
        let name = unique_name("noclient");
        let server = create_server(&name, &full_sddl(&me()), true).unwrap();
        assert!(client_facts(&server).is_err());
    }

    #[tokio::test]
    async fn second_first_instance_fails() {
        let name = unique_name("first");
        let sddl = full_sddl(&me());
        let _server = create_server(&name, &sddl, true).unwrap();
        let e = create_server(&name, &sddl, true).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists, "{e}");
        assert_eq!(
            e.to_string(),
            format!("pipe {name} exists and is not ours; refusing to start")
        );
        // A later instance is allowed, by a caller the DACL lets add one.
        let _second = create_server(&name, &sddl, false).unwrap();
    }

    /// The right an agent's user lacks on the control pipe: it can connect, but it can
    /// never add an instance to answer the next client.
    #[tokio::test]
    async fn users_rights_cannot_add_an_instance() {
        let me = me();
        let name = unique_name("noadd");
        let _server = create_server(&name, &users_sddl(&me), true).unwrap();
        // A client with exactly these rights can open it.
        let _client = open_client(&name).unwrap();
        let e = create_server(&name, &users_sddl(&me), false).err().unwrap();
        assert_eq!(e.raw_os_error(), Some(ERROR_ACCESS_DENIED), "{e}");
    }

    #[tokio::test]
    async fn owner_sid_reads_both_ends() {
        let me = me();
        let name = unique_name("owner");
        let server = create_server(&name, &full_sddl(&me), true).unwrap();
        let client = open_client(&name).unwrap();
        assert_eq!(owner_sid(&server).unwrap(), me);
        assert_eq!(owner_sid(&client).unwrap(), me);
    }

    #[tokio::test]
    async fn create_server_takes_only_a_real_descriptor() {
        let me = me();
        let name = unique_name("sddl");
        for bad in [
            "not sddl".to_string(),
            format!("O:{me}G:{me}D:NO_ACCESS_CONTROL"),
            format!("D:P(A;;GA;;;{me})"),
        ] {
            assert!(create_server(&name, &bad, true).is_err(), "{bad}");
        }
        assert!(create_server(r"\\evil\pipe\x", &full_sddl(&me), true).is_err());
    }

    /// `reject_remote_clients` has no read-back in Windows: see `ServerPlan`'s test.
    #[tokio::test]
    async fn instance_options_reach_windows() {
        let name = unique_name("info");
        let server = create_server(&name, &full_sddl(&me()), true).unwrap();
        let info = server.info().unwrap();
        assert_eq!(info.mode, PipeMode::Byte);
        assert_eq!(info.max_instances as usize, MAX_INSTANCES);
    }
}
