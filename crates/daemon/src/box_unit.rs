//! Locked mode: start, stop and ask about the `saiife-box@<id>.service`
//! units over the system bus (plan 35, Task 6). The polkit rule the install
//! writes lets the daemon user do exactly `start`, `stop` and `set-property`
//! (the per-box `MemoryMax=`/`CPUQuota=` before each start) on those units.
//!
//! [`UnitBus`] is sync and is called from `spawn_blocking` threads (every box
//! manager call is), never from an async task: `Handle::block_on` panics in a
//! runtime thread's task context, so each call runs on a helper thread that
//! blocks on the runtime handle with a 5 s timeout, and the caller waits at
//! most 6 s of wall-clock time. Called from the one thread of a current-thread
//! runtime, nothing would drive the bus: the call then ends in an error after
//! the wall-clock bound instead of hanging. No unit test of the bus itself (it
//! needs a system bus); the box smoke fragment exercises it.

use std::future::Future;
use std::sync::mpsc;
use std::time::Duration;

use saiife_boxhost::launch::{UnitBus, VmmLimits};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::Connection;

const DEST: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER: &str = "org.freedesktop.systemd1.Manager";
const UNIT: &str = "org.freedesktop.systemd1.Unit";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";
/// Each bus call gives up after this long.
const CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// The caller's wall-clock bound, a little over the call's own.
const WALL_CLOCK: Duration = Duration::from_secs(6);

pub struct SystemdBus {
    conn: Connection,
    handle: tokio::runtime::Handle,
}

impl SystemdBus {
    /// Connects to the system bus. Call it from inside the daemon's runtime:
    /// its handle is kept for the sync calls.
    pub async fn connect() -> Result<SystemdBus, String> {
        let conn = Connection::system()
            .await
            .map_err(|e| format!("system bus: {e}"))?;
        Ok(SystemdBus {
            conn,
            handle: tokio::runtime::Handle::current(),
        })
    }

    /// [`SystemdBus::connect`] from a thread that is not a task (the box
    /// build runs on a `spawn_blocking` thread while the daemon's main
    /// thread drives the runtime), bounded as every call is. Without a
    /// runtime, or with nothing driving it, it fails instead of hanging.
    pub fn connect_blocking() -> Result<SystemdBus, String> {
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "system bus: no runtime to connect on".to_string())?;
        bounded(WALL_CLOCK, move || {
            handle.block_on(async {
                tokio::time::timeout(CALL_TIMEOUT, SystemdBus::connect())
                    .await
                    .unwrap_or_else(|_| Err("system bus: the connect timed out".to_string()))
            })
        })?
    }

    /// Runs `f` to completion on the runtime from a thread that is not a
    /// task, never for longer than [`WALL_CLOCK`].
    fn run<T, F, Fut>(&self, f: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: FnOnce(Connection) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, String>> + Send + 'static,
    {
        let conn = self.conn.clone();
        let handle = self.handle.clone();
        bounded(WALL_CLOCK, move || {
            handle.block_on(async move {
                tokio::time::timeout(CALL_TIMEOUT, f(conn))
                    .await
                    .unwrap_or_else(|_| Err("system bus call timed out".to_string()))
            })
        })?
    }
}

/// Runs `work` on its own thread and waits at most `wall` for it. The thread
/// is left behind when the time is up.
fn bounded<T: Send + 'static>(
    wall: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("saiife-box-bus".into())
        .spawn(move || {
            let _ = tx.send(work());
        })
        .map_err(|e| format!("system bus call: cannot start a thread: {e}"))?;
    rx.recv_timeout(wall)
        .map_err(|_| "system bus call did not finish in time".to_string())
}

/// `StartUnit` / `StopUnit` with `mode`.
async fn job(conn: Connection, method: &str, unit: String, mode: &str) -> Result<(), String> {
    conn.call_method(
        Some(DEST),
        MANAGER_PATH,
        Some(MANAGER),
        method,
        &(unit.as_str(), mode),
    )
    .await
    .map(|_| ())
    .map_err(|e| format!("{method} {unit}: {e}"))
}

/// `SetUnitProperties` with `runtime` true (a drop-in under /run, gone
/// at reboot): `MemoryMax=` and `CPUQuota=` (as `CPUQuotaPerSecUSec`).
async fn set_limits(conn: Connection, unit: String, l: VmmLimits) -> Result<(), String> {
    use zbus::zvariant::Value;
    let props: Vec<(&str, Value<'_>)> = vec![
        ("MemoryMax", Value::from(l.memory_max)),
        ("CPUQuotaPerSecUSec", Value::from(l.cpu_usec_per_sec)),
    ];
    conn.call_method(
        Some(DEST),
        MANAGER_PATH,
        Some(MANAGER),
        "SetUnitProperties",
        &(unit.as_str(), true, props),
    )
    .await
    .map(|_| ())
    .map_err(|e| format!("SetUnitProperties {unit}: {e}"))
}

async fn is_active(conn: Connection, unit: String) -> Result<bool, String> {
    let reply = match conn
        .call_method(
            Some(DEST),
            MANAGER_PATH,
            Some(MANAGER),
            "GetUnit",
            &(unit.as_str(),),
        )
        .await
    {
        Ok(r) => r,
        // Not loaded: it never ran, or it ended and systemd dropped it.
        Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == NO_SUCH_UNIT => {
            return Ok(false)
        }
        Err(e) => return Err(format!("GetUnit {unit}: {e}")),
    };
    let path: OwnedObjectPath = reply
        .body()
        .deserialize()
        .map_err(|e| format!("GetUnit {unit}: {e}"))?;
    let reply = conn
        .call_method(
            Some(DEST),
            path.as_str(),
            Some(PROPERTIES),
            "Get",
            &(UNIT, "ActiveState"),
        )
        .await
        .map_err(|e| format!("ActiveState {unit}: {e}"))?;
    let value: OwnedValue = reply
        .body()
        .deserialize()
        .map_err(|e| format!("ActiveState {unit}: {e}"))?;
    let state = String::try_from(value).map_err(|e| format!("ActiveState {unit}: {e}"))?;
    Ok(alive(&state))
}

/// Only `inactive` and `failed` mean the unit has no process. Any other
/// state, a state systemd adds later, or an empty or odd answer counts as
/// alive: a wrong "gone" starts a second VMM on the same disks (fail closed).
fn alive(state: &str) -> bool {
    !matches!(state, "inactive" | "failed")
}

impl UnitBus for SystemdBus {
    fn start(&self, unit: &str) -> Result<(), String> {
        let unit = unit.to_string();
        self.run(|c| job(c, "StartUnit", unit, "fail"))
    }

    fn set_limits(&self, unit: &str, limits: &VmmLimits) -> Result<(), String> {
        let (unit, l) = (unit.to_string(), *limits);
        self.run(move |c| set_limits(c, unit, l))
    }

    fn stop(&self, unit: &str) -> Result<(), String> {
        let unit = unit.to_string();
        self.run(|c| job(c, "StopUnit", unit, "replace"))
    }

    fn active(&self, unit: &str) -> Result<bool, String> {
        let unit = unit.to_string();
        self.run(|c| is_active(c, unit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_inactive_and_failed_are_gone() {
        for s in [
            "active",
            "reloading",
            "activating",
            "deactivating",
            "refreshing",
            "maintenance",
            "",
            "frobnicating",
        ] {
            assert!(alive(s), "{s:?}");
        }
        for s in ["inactive", "failed"] {
            assert!(!alive(s), "{s}");
        }
    }

    #[test]
    fn a_call_cannot_hang_without_limit() {
        assert_eq!(bounded(Duration::from_secs(5), || 7).unwrap(), 7);
        let t = std::time::Instant::now();
        let r = bounded(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_millis(600));
        });
        assert!(r.is_err());
        assert!(t.elapsed() < Duration::from_millis(500));
    }
}
