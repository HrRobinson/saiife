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
    Hold, Host, RealHost, ReloadAnswer, UserInfo, WinBuild, ADMIN_TIMEOUT, REG_NT_CURRENT_VERSION,
    SC_EXE,
};
use crate::layout::WIN_SERVICE;
use crate::winservice::{
    failure_policy_from, live_spec_from, sdshow_text, FailurePolicy, LiveService, ServiceOp,
    ServiceSpec, ServiceState, SidType, StartKind,
};
use saiife_ipc::client::Client;
use saiife_win::ffi::{account, acl, token};
use saiife_win::pipe::peer_facts;
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

/// What the service manager's failure actions say, as W10 writes them. Anything else, a
/// mix of actions say, reads as no restarts at all, which doctor reports.
fn failure_policy(service: &Service) -> io::Result<FailurePolicy> {
    let actions = service.get_failure_actions().map_err(scm_error)?;
    let list: Vec<(bool, Duration)> = actions
        .actions
        .unwrap_or_default()
        .iter()
        .map(|a| (a.action_type == ServiceActionType::Restart, a.delay))
        .collect();
    let reset = match actions.reset_period {
        ServiceFailureResetPeriod::After(d) => d,
        ServiceFailureResetPeriod::Never => Duration::ZERO,
    };
    let on_non_crash = service
        .get_failure_actions_on_non_crash_failures()
        .map_err(scm_error)?;
    Ok(failure_policy_from(&list, reset, on_non_crash))
}

/// `sc.exe sdshow saiifed`: W10 grants Authenticated Users `RC`, so a plain shell may
/// ask. An exit code is all that is read of a failure: its text is localized.
fn sdshow() -> io::Result<String> {
    let out = exec(SC_EXE, &["sdshow", WIN_SERVICE], None, ADMIN_TIMEOUT)?;
    sdshow_text(out.status, &out.stdout)
}

fn live_spec() -> io::Result<Option<ServiceSpec>> {
    let service = match open(ServiceAccess::QUERY_CONFIG) {
        Ok(s) => s,
        Err(e) if is_missing(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let config = service.query_config().map_err(scm_error)?;
    Ok(Some(live_spec_from(LiveService {
        display: config.display_name.to_string_lossy().into_owned(),
        command_line: config.executable_path.to_string_lossy().into_owned(),
        account: config
            .account_name
            .map(|a| a.to_string_lossy().into_owned())
            .unwrap_or_default(),
        start: match config.start_type {
            ServiceStartType::AutoStart => StartKind::Auto,
            ServiceStartType::OnDemand => StartKind::Manual,
            // Boot and system start are for drivers: neither is W10's, and the compare
            // needs only that this differs.
            _ => StartKind::Disabled,
        },
        sid_type: match service.get_config_service_sid_info().map_err(scm_error)? {
            ServiceSidType::None => SidType::None,
            ServiceSidType::Unrestricted => SidType::Unrestricted,
            ServiceSidType::Restricted => SidType::Restricted,
        },
        failure: failure_policy(&service)?,
        sddl: sdshow()?,
    })))
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

    /// From the registry's `ContainerType` value. A failed read is
    /// [`CONTAINER_UNKNOWN`](super::CONTAINER_UNKNOWN), as on Linux.
    fn container(&self) -> Option<String> {
        match crate::supported::windows_container(self) {
            Ok(true) => Some("windows".to_string()),
            Ok(false) => None,
            Err(_) => Some(super::CONTAINER_UNKNOWN.to_string()),
        }
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

    /// Over the pipe: Windows has no socket dir, and the owner check is on the service's
    /// SID, not a uid.
    fn policy_reload(
        &self,
        _socket_dir: &Path,
        _daemon_uid: u32,
        wait: Duration,
    ) -> io::Result<ReloadAnswer> {
        use saiife_ipc::client::ClientError;
        use saiife_ipc::msg::OP_POLICY_RELOAD;
        let deadline = Instant::now() + wait;
        let mut c = connect_pipe(deadline)?;
        match c.call(OP_POLICY_RELOAD, serde_json::Map::new(), deadline) {
            Ok(a) => Ok(ReloadAnswer::from_answer(&a)),
            Err(ClientError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no answer to policy.reload within {} s", wait.as_secs()),
            )),
            Err(e) => Err(io::Error::other(format!("policy.reload: {e}"))),
        }
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

    fn reg_value_present(&self, key: &str, value: &str) -> io::Result<bool> {
        let not_found = |e: io::Error| match e.kind() {
            io::ErrorKind::NotFound => Ok(false),
            _ => Err(e),
        };
        let opened = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(key, KEY_READ);
        match opened {
            Ok(k) => k.get_raw_value(value).map(|_| true).or_else(not_found),
            Err(e) => not_found(e),
        }
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

    /// W26. Read as a pipe peer's token is: `Administrators` counts only at high
    /// integrity or above with no restricted SIDs. SYSTEM (the MSI's custom action) holds
    /// it enabled at System integrity. A token that cannot be read is not elevated.
    fn elevated(&self) -> bool {
        token::current_peer().is_ok_and(|t| peer_facts(t).elevated_admin)
    }

    fn lookup_local_group(&self, name: &str) -> io::Result<Option<String>> {
        account::lookup_local_group(name)
    }

    fn hold_dir(&self, path: &Path) -> io::Result<Hold> {
        Ok(Box::new(acl::hold_dir(path)?))
    }

    fn lock_file(&self, path: &Path) -> io::Result<Option<Hold>> {
        Ok(acl::lock_file(path)?.map(|f| Box::new(f) as Hold))
    }

    fn claude_hklm_policy(&self) -> saiife_agents::claude::HklmPolicy {
        saiife_agents::claude::hklm_policy_live()
    }

    fn wait_for_pipe(&self, wait: Duration) -> io::Result<()> {
        connect_pipe(Instant::now() + wait).map(|_| ())
    }

    fn service_spec(&self) -> io::Result<Option<ServiceSpec>> {
        live_spec()
    }

    fn local_groups_of(&self, user: &str) -> io::Result<Vec<String>> {
        account::local_groups_of(user)
    }

    fn authenticode_status(&self, path: &Path) -> io::Result<i32> {
        saiife_win::ffi::trust::authenticode_status(path)
    }

    fn daemon_status(
        &self,
        wait: Duration,
    ) -> io::Result<serde_json::Map<String, serde_json::Value>> {
        use saiife_ipc::msg::OP_STATUS;
        let deadline = Instant::now() + wait;
        connect_pipe(deadline)?
            .call(OP_STATUS, serde_json::Map::new(), deadline)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

/// The daemon's pipe, retried until `deadline`. `connect_pipe` checks that the service
/// owns it, so a squatted pipe never answers.
fn connect_pipe(deadline: Instant) -> io::Result<Client> {
    use crate::layout::WIN_PIPE;
    use saiife_ipc::client::system_sid;
    loop {
        let per_try = (Instant::now() + Duration::from_secs(1)).min(deadline);
        let err = match Client::connect_pipe(WIN_PIPE, &system_sid(), per_try) {
            Ok(c) => return Ok(c),
            Err(e) => e,
        };
        let pause = Duration::from_millis(200);
        if Instant::now() + pause >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, err.to_string()));
        }
        std::thread::sleep(pause);
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
        assert!(!crate::supported::windows_container(&RealHost).unwrap());
    }

    #[test]
    fn real_probe_finds_any_value_and_only_not_found_is_absent() {
        let host = RealHost;
        assert!(host
            .reg_value_present(REG_NT_CURRENT_VERSION, "CurrentBuildNumber")
            .unwrap());
        assert!(!host
            .reg_value_present(REG_NT_CURRENT_VERSION, "NoSuchValueSaiifeTest")
            .unwrap());
        assert!(!host
            .reg_value_present(r"SOFTWARE\NoSuchKeySaiifeTest", "x")
            .unwrap());
        // `DigitalProductId` is REG_BINARY: neither reg_string nor reg_dword reads it.
        assert!(host
            .reg_value_present(REG_NT_CURRENT_VERSION, "DigitalProductId")
            .unwrap());
    }

    /// `saiife.exe` and the managed files are `OICI` rows on files. Windows strips
    /// `OI` and `CI` from a file, so they are checked with `actual_file_ok`.
    #[test]
    fn oici_row_on_a_file_passes_actual_ok() {
        let facts = token::current().unwrap();
        if !facts.elevated_admin {
            // Only an administrator can make `BA` the owner, so this cannot run. Not
            // being able to on the runner is itself a failure: W23 says it is elevated.
            assert!(
                std::env::var_os("RUNNER_TEMP").is_none(),
                "the CI runner is expected to be elevated"
            );
            return;
        }
        let base = std::env::var_os("RUNNER_TEMP")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        // Canonical: `set_sddl` compares the path with where the handle really is, and the
        // runner's %TEMP% can hold an 8.3 name.
        let dir = tempfile::tempdir_in(std::fs::canonicalize(base).unwrap()).unwrap();
        let file = dir.path().join("saiife.exe");
        std::fs::write(&file, b"x").unwrap();
        let row = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
        RealHost.set_sddl(&file, row).unwrap();
        let text = RealHost.get_sddl(&file).unwrap();
        let _ = writeln!(std::io::stderr(), "OICI row on a file reads: {text}");
        let sd = parse(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
        crate::winacl::actual_file_ok(row, &sd).unwrap_or_else(|e| panic!("{text}: {e}"));
    }

    #[test]
    fn real_euid_and_lookups_agree() {
        let facts = token::current().unwrap();
        assert_eq!(RealHost.euid(), uid_of(&facts.sid, facts.elevated_admin));
        let name = account::lookup_sid(&facts.sid).unwrap();
        assert_eq!(RealHost.lookup_sid(&name).as_deref(), Some(&*facts.sid));
        assert_eq!(RealHost.user(&name).unwrap().uid, uid_of(&facts.sid, false));
    }

    /// The runner has no saiifed, and anyone may connect and ask.
    #[test]
    fn real_query_of_a_missing_service_is_missing() {
        assert_eq!(
            RealHost.service(ServiceOp::Query).unwrap(),
            ServiceState::Missing
        );
        assert_eq!(RealHost.service_spec().unwrap(), None);
    }

    /// A program run here sees what is in the table, and nothing this process holds.
    #[test]
    fn a_child_inherits_no_environment_and_no_working_directory() {
        let cmd = r"C:\Windows\System32\cmd.exe";
        let out = RealHost
            .run(cmd, &["/c", "set"], Duration::from_secs(30))
            .unwrap();
        let _ = writeln!(std::io::stderr(), "the child's environment: {}", out.stdout);
        // Set on every machine, and not in the table.
        let upper = out.stdout.to_ascii_uppercase();
        for name in ["USERNAME=", "USERPROFILE=", "PSMODULEPATH="] {
            assert!(!upper.contains(name), "{name}: {}", out.stdout);
        }
        let out = RealHost
            .run(cmd, &["/c", "cd"], Duration::from_secs(30))
            .unwrap();
        assert!(
            out.stdout
                .trim()
                .eq_ignore_ascii_case(super::super::WINDOWS_CHILD_DIR),
            "{}",
            out.stdout
        );
    }

    /// The test binary is not Authenticode-signed, and notepad's own bytes differ.
    #[test]
    fn an_unsigned_file_is_not_valid() {
        use crate::binary::{authenticode_verdict, Authenticode};
        let exe = std::env::current_exe().unwrap();
        let status = RealHost.authenticode_status(&exe).unwrap();
        let _ = writeln!(
            std::io::stderr(),
            "WinVerifyTrust on the test exe: 0x{status:08X}"
        );
        assert_ne!(authenticode_verdict(status), Authenticode::Valid);
    }
}
