//! [`RealHost`] on Windows (plan 19b): ACLs, accounts and tokens through
//! `saiife-win`, the registry through `winreg`, the service manager through
//! `windows-service`, and `net.exe` and `sc.exe` by absolute path, read by exit code
//! only since their text is localized.
//!
//! The Linux tools have no meaning here and are `Unsupported`. So are `chown`,
//! `create_system_user` and `delete_user`: W10's virtual account needs no user, and an
//! owner is set with the ACL.

use super::{
    argv_net_add_member, argv_net_create_group, argv_net_delete_group, argv_net_remove_member,
    argv_sc_paramchange, argv_sc_sdset, check_exit, exec, parse_win_build, windows_only, CmdOutput,
    Host, RealHost, ReloadAnswer, UserInfo, WinBuild, ADMIN_TIMEOUT, REG_NT_CURRENT_VERSION,
};
use crate::winservice::{ServiceOp, ServiceSpec, ServiceState, SidType, StartKind, WIN_SERVICE};
use saiife_win::ffi::{account, acl, token};
use saiife_win::sid::uid_of;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceSidType,
    ServiceStartType, ServiceState as ScmState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;

/// The caller's uid label (W12). A token that cannot be read is no administrator:
/// `u32::MAX` is what [`uid_of`] never returns.
pub(super) fn own_euid() -> u32 {
    token::current()
        .map(|t| uid_of(&t.sid, t.elevated_admin))
        .unwrap_or(u32::MAX)
}

/// The caller's uid label as a plain user, for the fake host's "the test user".
pub(super) fn own_uid() -> u32 {
    token::current()
        .map(|t| uid_of(&t.sid, false))
        .unwrap_or(u32::MAX)
}

fn net(argv: io::Result<Vec<String>>) -> io::Result<()> {
    let argv = argv?;
    let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    let out = exec(&argv[0], &args, None, ADMIN_TIMEOUT)?;
    check_exit(&argv, &out)
}

fn hklm(key: &str) -> Option<RegKey> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(key, KEY_READ)
        .ok()
}

fn scm_error(e: windows_service::Error) -> io::Error {
    match e {
        windows_service::Error::Winapi(e) => e,
        other => io::Error::other(other),
    }
}

fn manager(access: ServiceManagerAccess) -> io::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).map_err(scm_error)
}

fn open(access: ServiceAccess) -> io::Result<Service> {
    manager(ServiceManagerAccess::CONNECT)?
        .open_service(WIN_SERVICE, access)
        .map_err(scm_error)
}

fn is_missing(e: &io::Error) -> bool {
    e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST)
}

fn info_of(spec: &ServiceSpec) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(&spec.name),
        display_name: OsString::from(&spec.display),
        service_type: ServiceType::OWN_PROCESS,
        start_type: match spec.start {
            StartKind::Auto => ServiceStartType::AutoStart,
            StartKind::Manual => ServiceStartType::OnDemand,
            StartKind::Disabled => ServiceStartType::Disabled,
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(&spec.binary),
        launch_arguments: spec.args.iter().map(OsString::from).collect(),
        dependencies: Vec::new(),
        account_name: Some(OsString::from(&spec.account)),
        account_password: None,
    }
}

/// What [`ServiceInfo`] does not carry: failure actions, the SID type, the DACL.
fn configure(service: &Service, spec: &ServiceSpec) -> io::Result<()> {
    let action = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: spec.failure.restart_delay,
    };
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(spec.failure.reset_after),
            reboot_msg: None,
            command: None,
            actions: Some(vec![action; spec.failure.restarts as usize]),
        })
        .map_err(scm_error)?;
    service
        .set_failure_actions_on_non_crash_failures(spec.failure.on_non_crash)
        .map_err(scm_error)?;
    service
        .set_config_service_sid_info(match spec.sid_type {
            SidType::None => ServiceSidType::None,
            SidType::Unrestricted => ServiceSidType::Unrestricted,
            SidType::Restricted => ServiceSidType::Restricted,
        })
        .map_err(scm_error)?;
    sdset(&spec.sddl)
}

fn sdset(sddl: &str) -> io::Result<()> {
    net(argv_sc_sdset(WIN_SERVICE, sddl))
}

fn state_of(service: &Service) -> io::Result<ServiceState> {
    let status = service.query_status().map_err(scm_error)?;
    Ok(match status.current_state {
        ScmState::Stopped => ServiceState::Stopped,
        ScmState::Running => ServiceState::Running {
            pid: status.process_id.unwrap_or(0),
        },
        ScmState::StartPending => ServiceState::Other("start-pending".to_string()),
        ScmState::StopPending => ServiceState::Other("stop-pending".to_string()),
        ScmState::ContinuePending => ServiceState::Other("continue-pending".to_string()),
        ScmState::PausePending => ServiceState::Other("pause-pending".to_string()),
        ScmState::Paused => ServiceState::Other("paused".to_string()),
    })
}

fn query() -> io::Result<ServiceState> {
    match open(ServiceAccess::QUERY_STATUS) {
        Ok(service) => state_of(&service),
        Err(e) if is_missing(&e) => Ok(ServiceState::Missing),
        Err(e) => Err(e),
    }
}

fn create(spec: &ServiceSpec) -> io::Result<ServiceState> {
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let service = manager
        .create_service(&info_of(spec), ServiceAccess::all())
        .map_err(scm_error)?;
    if let Err(e) = configure(&service, spec) {
        // Only what this call created. A service left half set up, with the default
        // DACL and no restart policy, must not pass as installed.
        let _ = service.delete();
        return Err(e);
    }
    state_of(&service)
}

fn update(spec: &ServiceSpec) -> io::Result<ServiceState> {
    let service = open(ServiceAccess::all())?;
    service.change_config(&info_of(spec)).map_err(scm_error)?;
    configure(&service, spec)?;
    state_of(&service)
}

fn stop(wait: Duration) -> io::Result<ServiceState> {
    let service = open(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    match service.stop().map_err(scm_error) {
        Ok(_) => {}
        Err(e) if e.raw_os_error() == Some(ERROR_SERVICE_NOT_ACTIVE) => {}
        Err(e) => return Err(e),
    }
    let deadline = Instant::now() + wait;
    loop {
        let state = state_of(&service)?;
        if state == ServiceState::Stopped {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{WIN_SERVICE} did not stop within {} s ({state:?})",
                    wait.as_secs()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

impl Host for RealHost {
    fn euid(&self) -> u32 {
        own_euid()
    }

    fn user(&self, name: &str) -> Option<UserInfo> {
        let (sid, _) = account::lookup_name(name).ok()?;
        Some(UserInfo {
            uid: uid_of(&sid, false),
            gid: 0,
            home: PathBuf::new(),
            shell: String::new(),
        })
    }

    fn group_id(&self, name: &str) -> Option<u32> {
        let (sid, _) = account::lookup_name(name).ok()?;
        Some(uid_of(&sid, false))
    }

    fn group_members(&self, name: &str) -> Option<Vec<String>> {
        account::local_group_members(name).ok()
    }

    /// Windows groups have no primary-group members that a group's list would miss.
    fn users_with_primary_gid(&self, _gid: u32) -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn create_system_group(&self, name: &str) -> io::Result<()> {
        net(argv_net_create_group(name))
    }

    fn create_system_user(&self, _name: &str, _group: &str) -> io::Result<()> {
        Err(windows_only())
    }

    fn add_to_group(&self, user: &str, group: &str) -> io::Result<()> {
        net(argv_net_add_member(user, group))
    }

    fn delete_user(&self, _name: &str) -> io::Result<()> {
        Err(windows_only())
    }

    fn delete_group(&self, name: &str) -> io::Result<()> {
        net(argv_net_delete_group(name))
    }

    fn remove_from_group(&self, user: &str, group: &str) -> io::Result<()> {
        net(argv_net_remove_member(user, group))
    }

    fn chown(&self, _path: &Path, _uid: u32, _gid: u32) -> io::Result<()> {
        Err(windows_only())
    }

    fn systemctl(&self, _args: &[&str]) -> io::Result<CmdOutput> {
        Err(windows_only())
    }

    fn systemd_version(&self) -> io::Result<u32> {
        Err(windows_only())
    }

    fn encrypt_credential(&self, _name: &str, _secret: &[u8], _out: &Path) -> io::Result<()> {
        Err(windows_only())
    }

    /// The registry's `ContainerType` value, of whichever type it was written.
    fn container(&self) -> Option<String> {
        crate::supported::windows_container(self).then(|| "windows".to_string())
    }

    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> io::Result<CmdOutput> {
        exec(program, args, None, timeout)
    }

    fn launchctl(&self, _args: &[&str]) -> io::Result<CmdOutput> {
        Err(windows_only())
    }

    fn macos_version(&self) -> io::Result<(u32, u32)> {
        Err(windows_only())
    }

    fn sip_enabled(&self) -> bool {
        false
    }

    fn run_input(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        timeout: Duration,
    ) -> io::Result<CmdOutput> {
        exec(program, args, Some(input), timeout)
    }

    fn owner_uid(&self, _path: &Path, on_disk: u32) -> u32 {
        on_disk
    }

    fn policy_reload(
        &self,
        _socket_dir: &Path,
        _daemon_uid: u32,
        _wait: Duration,
    ) -> io::Result<ReloadAnswer> {
        Err(windows_only())
    }

    fn set_sddl(&self, path: &Path, sddl: &str) -> io::Result<()> {
        acl::set_sddl(path, sddl)
    }

    fn get_sddl(&self, path: &Path) -> io::Result<String> {
        acl::get_sddl(path)
    }

    fn create_dir_sddl(&self, path: &Path, sddl: &str) -> io::Result<()> {
        acl::create_dir_with_sddl(path, sddl)
    }

    fn lookup_sid(&self, name: &str) -> Option<String> {
        account::lookup_name(name).ok().map(|(sid, _)| sid)
    }

    fn reg_string(&self, key: &str, value: &str) -> Option<String> {
        hklm(key)?.get_value::<String, _>(value).ok()
    }

    fn reg_dword(&self, key: &str, value: &str) -> Option<u32> {
        hklm(key)?.get_value::<u32, _>(value).ok()
    }

    fn windows_build(&self) -> io::Result<WinBuild> {
        parse_win_build(
            self.reg_string(REG_NT_CURRENT_VERSION, "CurrentBuildNumber"),
            self.reg_string(REG_NT_CURRENT_VERSION, "InstallationType"),
        )
    }

    fn service(&self, op: ServiceOp) -> io::Result<ServiceState> {
        match op {
            ServiceOp::Query => query(),
            ServiceOp::Create(spec) => create(&spec),
            ServiceOp::Update(spec) => update(&spec),
            ServiceOp::Start => {
                let service = open(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
                service.start::<&str>(&[]).map_err(scm_error)?;
                state_of(&service)
            }
            ServiceOp::Stop { wait } => stop(wait),
            ServiceOp::Delete => {
                open(ServiceAccess::DELETE)?.delete().map_err(scm_error)?;
                Ok(ServiceState::Missing)
            }
            ServiceOp::SetSddl(sddl) => {
                sdset(&sddl)?;
                query()
            }
            // `windows-service` sends only user-defined codes, so this goes through
            // sc.exe, which W10 also uses for the DACL.
            ServiceOp::ParamChange => {
                net(argv_sc_paramchange(WIN_SERVICE))?;
                query()
            }
        }
    }
}

/// Run in CI's `test` job on `windows-latest`. No admin rights assumed.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::supported::default_folders;
    use crate::winacl::ancestor_ok;
    use saiife_win::sddl::parse;
    use std::io::Write;

    #[test]
    fn real_ancestors_pass_ancestor_ok() {
        for path in [r"C:\", r"C:\ProgramData", r"C:\Program Files"] {
            let text = RealHost.get_sddl(Path::new(path)).unwrap();
            let _ = writeln!(std::io::stderr(), "real SDDL of {path}: {text}");
            let sd = parse(&text).unwrap_or_else(|e| panic!("{path}: {text}: {e}"));
            ancestor_ok(&sd).unwrap_or_else(|e| panic!("{path}: {text}: {e}"));
        }
    }

    #[test]
    fn real_registry_has_the_default_folders_and_a_build() {
        assert!(default_folders(&RealHost));
        let build = RealHost.windows_build().unwrap();
        assert!(build.build >= 17763, "{build:?}");
        // GitHub's `windows-latest` is a server, and no container.
        assert!(!crate::supported::windows_container(&RealHost));
    }

    #[test]
    fn real_euid_and_lookups_agree() {
        let facts = token::current().unwrap();
        assert_eq!(RealHost.euid(), uid_of(&facts.sid, facts.elevated_admin));
        let name = account::lookup_sid(&facts.sid).unwrap();
        assert_eq!(RealHost.lookup_sid(&name).as_deref(), Some(&*facts.sid));
        assert_eq!(RealHost.user(&name).unwrap().uid, uid_of(&facts.sid, false));
    }

    #[test]
    fn real_query_of_a_missing_service_is_missing_or_refused() {
        // The runner has no saiifed; a job that lacks SCM rights gets an error.
        if let Ok(state) = RealHost.service(ServiceOp::Query) {
            assert_eq!(state, ServiceState::Missing);
        }
    }
}
