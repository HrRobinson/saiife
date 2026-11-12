//! Locked mode: start, stop and ask about the `saiife-box@<id>.service`
//! units over the system bus (plan 35, Task 6). The polkit rule the install
//! writes lets the daemon user do exactly `start` and `stop` on those units.
//!
//! [`UnitBus`] is sync and is called from tokio worker threads, where
//! `Handle::block_on` panics: each call runs on a short-lived thread of its
//! own that blocks on the runtime handle, with a 5 s timeout. No unit test
//! (it needs a system bus); the box smoke fragment exercises it.

use std::future::Future;
use std::time::Duration;

use saiife_boxhost::launch::UnitBus;
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

    /// Runs `f` on a short-lived thread that blocks on the runtime, so it is
    /// safe from a runtime thread, and joins it.
    fn run<T, F, Fut>(&self, f: F) -> Result<T, String>
    where
        T: Send,
        F: FnOnce(Connection) -> Fut + Send,
        Fut: Future<Output = Result<T, String>> + Send,
    {
        let conn = self.conn.clone();
        let handle = self.handle.clone();
        std::thread::scope(|s| {
            s.spawn(move || {
                handle.block_on(async move {
                    tokio::time::timeout(CALL_TIMEOUT, f(conn))
                        .await
                        .unwrap_or_else(|_| Err("system bus call timed out".to_string()))
                })
            })
            .join()
            .unwrap_or_else(|_| Err("system bus call panicked".to_string()))
        })
    }
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

/// A unit in any of these states may still have its process: "gone" is only
/// `inactive` and `failed` (fail closed).
fn alive(state: &str) -> bool {
    matches!(
        state,
        "active" | "activating" | "deactivating" | "reloading"
    )
}

impl UnitBus for SystemdBus {
    fn start(&self, unit: &str) -> Result<(), String> {
        let unit = unit.to_string();
        self.run(|c| job(c, "StartUnit", unit, "fail"))
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
    use super::alive;

    #[test]
    fn only_inactive_and_failed_are_gone() {
        for s in ["active", "activating", "deactivating", "reloading"] {
            assert!(alive(s), "{s}");
        }
        for s in ["inactive", "failed"] {
            assert!(!alive(s), "{s}");
        }
    }
}
