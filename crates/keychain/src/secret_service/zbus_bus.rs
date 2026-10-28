//! [`SsBus`] over a zbus connection.
//!
//! zbus is async; the backend is called from synchronous code (the daemon
//! calls the keychain only in `start`, before its own runtime exists). So
//! each [`ZbusBus`] owns a current-thread tokio runtime that drives its
//! connection, and every call is a `block_on` on it. A `block_on` inside
//! another runtime would panic, so every call first asserts that there is
//! no current runtime, with a message that says why.
//!
//! Dropping a [`ZbusBus`] is safe anywhere: inside a runtime its own
//! runtime is shut down in the background instead of being dropped there
//! (which would panic).

use super::bus::{
    Found, Prompted, SsBus, CONTENT_TYPE, PROP_ATTRIBUTES, PROP_LABEL, SS_COLLECTION, SS_DEST,
    SS_ITEM, SS_PATH, SS_PROMPT, SS_SERVICE,
};
use crate::KeychainError;
use futures_lite::StreamExt;
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::DBusError;
use zeroize::Zeroizing;

/// How long connecting and authenticating to the bus may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one method call may take (D-Bus's usual default is 25 s).
const CALL_TIMEOUT: Duration = Duration::from_secs(25);
/// How long the courtesy `Prompt.Dismiss` after a timed-out prompt may take.
const DISMISS_TIMEOUT: Duration = Duration::from_secs(2);

/// The Secret Service over a zbus connection, driven by its own
/// current-thread runtime.
#[derive(Debug)]
pub struct ZbusBus {
    conn: zbus::Connection,
    /// Always `Some` until `drop` takes it.
    rt: Option<tokio::runtime::Runtime>,
}

impl Drop for ZbusBus {
    fn drop(&mut self) {
        let Some(rt) = self.rt.take() else { return };
        if tokio::runtime::Handle::try_current().is_ok() {
            // Dropping a runtime inside another one panics; this is tokio's
            // non-blocking way to stop it from async context. It does not
            // wait for the connection's tasks, which only read the socket.
            rt.shutdown_background();
        } else {
            drop(rt);
        }
    }
}

/// Panic with a clear message when called inside a tokio runtime, where
/// the `block_on` would panic anyway (or deadlock the caller's runtime).
fn assert_no_runtime() {
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "saiife-keychain: the Secret Service backend blocks; call it outside any tokio runtime"
    );
}

/// Map a zbus failure. The text is the error's name and description, never
/// a message body, so it never holds secret bytes.
fn map_err(e: zbus::Error) -> KeychainError {
    let (name, text) = match &e {
        zbus::Error::MethodError(name, desc, _) => (
            name.as_str().to_string(),
            match desc {
                Some(d) => format!("{}: {d}", name.as_str()),
                None => name.as_str().to_string(),
            },
        ),
        zbus::Error::FDO(f) => (f.name().as_str().to_string(), f.to_string()),
        zbus::Error::InputOutput(_) | zbus::Error::Handshake(_) => {
            return KeychainError::Unavailable(format!("the session bus connection failed: {e}"))
        }
        _ => return KeychainError::Other(format!("Secret Service: {e}")),
    };
    match name.as_str() {
        "org.freedesktop.DBus.Error.ServiceUnknown"
        | "org.freedesktop.DBus.Error.NameHasNoOwner"
        | "org.freedesktop.DBus.Error.Disconnected"
        | "org.freedesktop.DBus.Error.Spawn.ChildExited"
        | "org.freedesktop.DBus.Error.Spawn.ExecFailed" => {
            KeychainError::Unavailable(format!("no Secret Service on the session bus ({text})"))
        }
        "org.freedesktop.Secret.Error.IsLocked" => KeychainError::Locked(text),
        _ => KeychainError::Other(format!("Secret Service: {text}")),
    }
}

/// `"/"` is the Secret Service's "no object" (no prompt, no alias).
fn some_path(p: OwnedObjectPath) -> Option<String> {
    (p.as_str() != "/").then(|| p.as_str().to_string())
}

fn path(p: &str) -> zbus::Result<ObjectPath<'_>> {
    Ok(ObjectPath::try_from(p)?)
}

async fn proxy<'a>(
    conn: &zbus::Connection,
    path: &'a str,
    iface: &'a str,
) -> zbus::Result<zbus::Proxy<'a>> {
    zbus::proxy::Builder::<zbus::Proxy<'a>>::new(conn)
        .destination(SS_DEST)?
        .path(path)?
        .interface(iface)?
        .cache_properties(CacheProperties::No)
        .build()
        .await
}

impl ZbusBus {
    /// The user's session bus, from `DBUS_SESSION_BUS_ADDRESS`. No address,
    /// or a connect failure, is `Unavailable("no session bus: …")`. zbus's
    /// own fallback (`$XDG_RUNTIME_DIR/bus`) is not used: no address means
    /// no session bus.
    pub fn session() -> Result<Self, KeychainError> {
        let addr = std::env::var_os("DBUS_SESSION_BUS_ADDRESS")
            .filter(|a| !a.is_empty())
            .ok_or_else(|| {
                KeychainError::Unavailable(
                    "no session bus: DBUS_SESSION_BUS_ADDRESS is not set".into(),
                )
            })?;
        let addr = addr.into_string().map_err(|_| {
            KeychainError::Unavailable(
                "no session bus: DBUS_SESSION_BUS_ADDRESS is not UTF-8".into(),
            )
        })?;
        Self::connect(move || async move {
            zbus::connection::Builder::address(addr.as_str())?
                .method_timeout(CALL_TIMEOUT)
                .build()
                .await
        })
        .map_err(|m| KeychainError::Unavailable(format!("no session bus: {m}")))
    }

    /// A bus over the connection `connect` builds (on this bus's runtime).
    /// For tests, which serve a Secret Service peer-to-peer.
    #[doc(hidden)]
    pub fn over<F, Fut>(connect: F) -> Result<Self, KeychainError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = zbus::Result<zbus::Connection>>,
    {
        Self::connect(connect)
            .map_err(|m| KeychainError::Unavailable(format!("cannot connect: {m}")))
    }

    fn connect<F, Fut>(connect: F) -> Result<Self, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = zbus::Result<zbus::Connection>>,
    {
        assert_no_runtime();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("cannot start the D-Bus runtime: {e}"))?;
        let conn = rt.block_on(async {
            match tokio::time::timeout(CONNECT_TIMEOUT, connect()).await {
                Ok(r) => r.map_err(|e| e.to_string()),
                Err(_) => Err(format!("no answer within {CONNECT_TIMEOUT:?}")),
            }
        })?;
        Ok(ZbusBus { conn, rt: Some(rt) })
    }

    fn block<T, Fut>(&self, f: Fut) -> Result<T, KeychainError>
    where
        Fut: Future<Output = zbus::Result<T>>,
    {
        assert_no_runtime();
        let rt = self.rt.as_ref().expect("the runtime lives until drop");
        rt.block_on(f).map_err(map_err)
    }
}

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

impl SsBus for ZbusBus {
    fn open_session(&self) -> Result<String, KeychainError> {
        self.block(async {
            let p = proxy(&self.conn, SS_PATH, SS_SERVICE).await?;
            let (_out, session): (OwnedValue, OwnedObjectPath) =
                p.call("OpenSession", &("plain", Value::from(""))).await?;
            Ok(session.as_str().to_string())
        })
    }

    fn read_alias(&self, name: &str) -> Result<Option<String>, KeychainError> {
        self.block(async {
            let p = proxy(&self.conn, SS_PATH, SS_SERVICE).await?;
            let c: OwnedObjectPath = p.call("ReadAlias", &(name,)).await?;
            Ok(some_path(c))
        })
    }

    fn search_items(&self, attributes: &[(&str, &str)]) -> Result<Found, KeychainError> {
        let attrs: HashMap<&str, &str> = attributes.iter().copied().collect();
        self.block(async {
            let p = proxy(&self.conn, SS_PATH, SS_SERVICE).await?;
            let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
                p.call("SearchItems", &(attrs,)).await?;
            let s = |v: Vec<OwnedObjectPath>| v.iter().map(|p| p.as_str().to_string()).collect();
            Ok(Found {
                unlocked: s(unlocked),
                locked: s(locked),
            })
        })
    }

    fn unlock(&self, objects: &[String]) -> Result<(Vec<String>, Option<String>), KeychainError> {
        self.block(async {
            let objs = objects
                .iter()
                .map(|o| path(o))
                .collect::<zbus::Result<Vec<_>>>()?;
            let p = proxy(&self.conn, SS_PATH, SS_SERVICE).await?;
            let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) =
                p.call("Unlock", &(objs,)).await?;
            Ok((
                unlocked.iter().map(|p| p.as_str().to_string()).collect(),
                some_path(prompt),
            ))
        })
    }

    fn locked_collections(&self) -> Result<Vec<String>, KeychainError> {
        self.block(async {
            let service = proxy(&self.conn, SS_PATH, SS_SERVICE).await?;
            let all: Vec<OwnedObjectPath> = service.get_property("Collections").await?;
            let mut locked = vec![];
            for c in all {
                let p = proxy(&self.conn, c.as_str(), SS_COLLECTION).await?;
                if p.get_property::<bool>("Locked").await? {
                    locked.push(c.as_str().to_string());
                }
            }
            Ok(locked)
        })
    }

    fn prompt(&self, prompt: &str, wait: Duration) -> Result<Prompted, KeychainError> {
        self.block(async {
            let p = proxy(&self.conn, prompt, SS_PROMPT).await?;
            // Subscribe before prompting, so a fast answer is not missed.
            let mut completed = p.receive_signal("Completed").await?;
            let answer = tokio::time::timeout(wait, async {
                p.call_method("Prompt", &("",)).await?;
                Ok::<_, zbus::Error>(completed.next().await)
            })
            .await;
            match answer {
                Ok(Ok(Some(msg))) => {
                    let (dismissed, _result): (bool, OwnedValue) = msg.body().deserialize()?;
                    Ok(if dismissed {
                        Prompted::Dismissed
                    } else {
                        Prompted::Done
                    })
                }
                Ok(Ok(None)) => Err(zbus::Error::Failure(
                    "the connection closed while a prompt was open".into(),
                )),
                Ok(Err(e)) => Err(e),
                Err(_) => {
                    // Take the stale dialog away; its answer no longer counts.
                    let _ =
                        tokio::time::timeout(DISMISS_TIMEOUT, p.call_method("Dismiss", &())).await;
                    Ok(Prompted::TimedOut)
                }
            }
        })
    }

    fn get_secret(&self, item: &str, session: &str) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
        self.block(async {
            let p = proxy(&self.conn, item, SS_ITEM).await?;
            let (_session, params, value, _type): Secret =
                p.call("GetSecret", &(path(session)?,)).await?;
            drop(Zeroizing::new(params));
            Ok(Zeroizing::new(value))
        })
    }

    fn create_item(
        &self,
        collection: &str,
        label: &str,
        attributes: &[(&str, &str)],
        session: &str,
        secret: &[u8],
    ) -> Result<Option<String>, KeychainError> {
        let attrs: HashMap<&str, &str> = attributes.iter().copied().collect();
        self.block(async {
            let p = proxy(&self.conn, collection, SS_COLLECTION).await?;
            let mut props: HashMap<&str, Value> = HashMap::new();
            props.insert(PROP_LABEL, Value::from(label));
            props.insert(PROP_ATTRIBUTES, Value::from(attrs));
            let empty: &[u8] = &[];
            let body = (props, (path(session)?, empty, secret, CONTENT_TYPE), true);
            let (_item, prompt): (OwnedObjectPath, OwnedObjectPath) =
                p.call("CreateItem", &body).await?;
            Ok(some_path(prompt))
        })
    }

    fn delete(&self, item: &str) -> Result<Option<String>, KeychainError> {
        self.block(async {
            let p = proxy(&self.conn, item, SS_ITEM).await?;
            let prompt: OwnedObjectPath = p.call("Delete", &()).await?;
            Ok(some_path(prompt))
        })
    }
}
