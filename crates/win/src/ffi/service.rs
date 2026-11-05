//! The service entry (plan 19b, W1, W10): the one `extern "system"` function that
//! `define_windows_service!` expands to. The macro's expansion holds `unsafe`, so it
//! lives here and nowhere else.
//!
//! Stop and shutdown become [`Control::Stop`]. `SERVICE_CONTROL_PARAMCHANGE` becomes
//! [`Control::Reload`], the analogue of SIGHUP. No tokio: the daemon bridges the channel.

use std::ffi::OsString;
use std::io;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    register, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: this process was not started by the
/// service manager, so [`run_as_service`] has nothing to attach to.
pub const NOT_A_SERVICE: i32 = 1063;

/// How long the service manager is told a stop may take: calls in flight and the last record.
const STOP_WAIT_HINT: Duration = Duration::from_secs(30);

/// What the service manager asks of the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Stop,
    Reload,
}

/// Reports the service's state. Without a handle (outside the service manager) it does
/// nothing.
#[derive(Clone, Copy)]
pub struct StatusPort(Option<ServiceStatusHandle>);

impl StatusPort {
    fn set(&self, state: ServiceState, accept: ServiceControlAccept, code: i32) {
        let Some(handle) = self.0 else {
            return;
        };
        let exit_code = match code {
            0 => ServiceExitCode::Win32(0),
            // Non-zero makes it a non-crash failure, so the restart actions run (W10).
            c => ServiceExitCode::ServiceSpecific(c as u32),
        };
        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::from_secs(0),
            process_id: None,
        };
        if let Err(e) = handle.set_service_status(status) {
            eprintln!("saiife: warning: cannot report the service state: {e}");
        }
    }

    /// The daemon is serving.
    pub fn set_running(&self) {
        self.set(
            ServiceState::Running,
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::PARAM_CHANGE,
            0,
        );
    }

    /// A stop was asked for, and the daemon is finishing its calls and its log.
    fn set_stop_pending(&self) {
        let Some(handle) = self.0 else {
            return;
        };
        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: STOP_WAIT_HINT,
            process_id: None,
        };
        if let Err(e) = handle.set_service_status(status) {
            eprintln!("saiife: warning: cannot report the service state: {e}");
        }
    }

    /// The daemon has stopped with exit code `code`.
    pub fn set_stopped(&self, code: i32) {
        self.set(ServiceState::Stopped, ServiceControlAccept::empty(), code);
    }
}

/// What the daemon gets from the service manager.
pub struct ServiceCtl {
    pub control: Receiver<Control>,
    pub status: StatusPort,
}

impl ServiceCtl {
    /// A control channel with no service manager behind it, for tests.
    pub fn detached() -> (Sender<Control>, ServiceCtl) {
        let (tx, control) = channel();
        (
            tx,
            ServiceCtl {
                control,
                status: StatusPort(None),
            },
        )
    }

    pub fn set_running(&self) {
        self.status.set_running();
    }

    pub fn set_stopped(&self, code: i32) {
        self.status.set_stopped(code);
    }
}

struct Entry {
    name: &'static str,
    main: fn(ServiceCtl) -> i32,
}

/// The service entry takes no argument, so what it runs waits here.
static ENTRY: OnceLock<Entry> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    let Some(entry) = ENTRY.get() else {
        return;
    };
    let (tx, control) = channel();
    // The handler runs on the dispatcher's thread, and needs Fn + Sync.
    let tx = Mutex::new(tx);
    // Registering gives the handle, and the handler is what's registered.
    let port = Arc::new(OnceLock::<StatusPort>::new());
    let stopping = Arc::clone(&port);
    let handler = move |c: ServiceControl| {
        let send = |what| {
            let _ = tx.lock().unwrap_or_else(|p| p.into_inner()).send(what);
            ServiceControlHandlerResult::NoError
        };
        match c {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // Before the daemon hears of it, so its Stopped can't be overwritten.
                if let Some(status) = stopping.get() {
                    status.set_stop_pending();
                }
                send(Control::Stop)
            }
            ServiceControl::ParamChange => send(Control::Reload),
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let handle = match register(entry.name, handler) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("saiife: cannot register the service handler: {e}");
            return;
        }
    };
    let status = StatusPort(Some(handle));
    let _ = port.set(status);
    status.set(ServiceState::StartPending, ServiceControlAccept::empty(), 0);
    let code = (entry.main)(ServiceCtl { control, status });
    status.set_stopped(code);
}

/// Hands this thread to the service manager, which runs `main` as service `name`.
/// Returns when the service has stopped. A process the manager did not start gets an
/// error with the code [`NOT_A_SERVICE`], and `main` does not run.
pub fn run_as_service(name: &'static str, main: fn(ServiceCtl) -> i32) -> io::Result<()> {
    ENTRY
        .set(Entry { name, main })
        .map_err(|_| io::Error::other("the service entry is already set"))?;
    service_dispatcher::start(name, ffi_service_main).map_err(|e| match e {
        windows_service::Error::Winapi(e) => e,
        e => io::Error::other(e.to_string()),
    })
}

/// These run in CI on windows-latest, outside the service manager.
#[cfg(test)]
mod tests {
    use super::*;

    fn never(_: ServiceCtl) -> i32 {
        panic!("main must not run outside the service manager");
    }

    #[test]
    fn outside_the_service_manager_is_not_a_service() {
        let e = run_as_service("saiife-test", never).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(NOT_A_SERVICE), "{e}");
    }

    #[test]
    fn detached_status_reports_nothing_and_control_flows() {
        let (tx, ctl) = ServiceCtl::detached();
        ctl.set_running();
        tx.send(Control::Reload).unwrap();
        tx.send(Control::Stop).unwrap();
        assert_eq!(ctl.control.recv().unwrap(), Control::Reload);
        assert_eq!(ctl.control.recv().unwrap(), Control::Stop);
        ctl.set_stopped(0);
    }
}
