//! The Secret Service backend over a real zbus connection, against a
//! minimal in-test Secret Service served peer-to-peer over a socket pair.
//! No session bus is involved.
//!
//! The tests run on plain `#[test]` threads, so the backend owns its own
//! runtime; each server runs on its own thread with its own runtime.
#![cfg(target_os = "linux")]

use saiife_keychain::secret_service::{SecretService, ZbusBus};
use saiife_keychain::{Keychain, KeychainError, VAULT_KEY, VAULT_KEY_LABEL};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{connection, fdo, interface};

const LOGIN: &str = "/org/freedesktop/secrets/collection/login";
/// A second, non-default collection.
const OTHER: &str = "/org/freedesktop/secrets/collection/other";
const PROMPT: &str = "/org/freedesktop/secrets/prompt/p1";

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum PromptMode {
    #[default]
    Done,
    Dismissed,
    Never,
}

struct StoredItem {
    path: String,
    attrs: HashMap<String, String>,
    label: String,
    secret: Vec<u8>,
    content_type: String,
}

#[derive(Default)]
struct State {
    /// `OpenSession` answers ServiceUnknown, as a bus without the service.
    unknown: bool,
    locked: bool,
    /// A locked collection hides its items (KeePassXC, closed KWallet).
    hide_locked: bool,
    prompt: PromptMode,
    items: Vec<StoredItem>,
    next: u32,
    sessions: Vec<String>,
    algorithms: Vec<String>,
    replace_seen: Vec<bool>,
}

type Shared = Arc<Mutex<State>>;

fn op(p: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(p.to_string()).unwrap()
}

fn locked_err() -> fdo::Error {
    fdo::Error::Failed("org.freedesktop.Secret.Error.IsLocked".into())
}

struct Service(Shared);

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    fn open_session(
        &self,
        algorithm: &str,
        _input: OwnedValue,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        let mut s = self.0.lock().unwrap();
        if s.unknown {
            return Err(fdo::Error::ServiceUnknown(
                "The name org.freedesktop.secrets was not provided by any .service files".into(),
            ));
        }
        if algorithm != "plain" {
            return Err(fdo::Error::NotSupported(algorithm.into()));
        }
        s.algorithms.push(algorithm.into());
        let path = format!("/org/freedesktop/secrets/session/{}", s.sessions.len() + 1);
        s.sessions.push(path.clone());
        Ok((Value::from("").try_to_owned().unwrap(), op(&path)))
    }

    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let s = self.0.lock().unwrap();
        if s.unknown {
            return Err(fdo::Error::ServiceUnknown("no secrets service".into()));
        }
        let hits: Vec<OwnedObjectPath> = s
            .items
            .iter()
            .filter(|i| attributes.iter().all(|(k, v)| i.attrs.get(k) == Some(v)))
            .map(|i| op(&i.path))
            .collect();
        Ok(if s.locked && s.hide_locked {
            (vec![], vec![])
        } else if s.locked {
            (vec![], hits)
        } else {
            (hits, vec![])
        })
    }

    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        vec![op(LOGIN), op(OTHER)]
    }

    fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let s = self.0.lock().unwrap();
        Ok(if s.locked {
            (vec![], op(PROMPT))
        } else {
            (objects, op("/"))
        })
    }

    fn read_alias(&self, name: &str) -> fdo::Result<OwnedObjectPath> {
        let s = self.0.lock().unwrap();
        if s.unknown {
            return Err(fdo::Error::ServiceUnknown("no secrets service".into()));
        }
        Ok(op(if name == "default" { LOGIN } else { "/" }))
    }
}

struct Collection(Shared);

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.lock().unwrap().locked
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label: String = properties
            .get("org.freedesktop.Secret.Item.Label")
            .ok_or_else(|| fdo::Error::InvalidArgs("no label".into()))?
            .try_clone()
            .unwrap()
            .try_into()
            .map_err(|_| fdo::Error::InvalidArgs("label".into()))?;
        let attrs: HashMap<String, String> = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .ok_or_else(|| fdo::Error::InvalidArgs("no attributes".into()))?
            .try_clone()
            .unwrap()
            .try_into()
            .map_err(|_| fdo::Error::InvalidArgs("attributes".into()))?;
        let (path, removed) = {
            let mut s = self.0.lock().unwrap();
            if s.locked {
                return Err(locked_err());
            }
            if !s.sessions.iter().any(|p| p.as_str() == secret.0.as_str()) {
                return Err(fdo::Error::InvalidArgs("unknown session".into()));
            }
            s.replace_seen.push(replace);
            let mut removed = vec![];
            if replace {
                s.items.retain(|i| {
                    let same = i.attrs == attrs;
                    if same {
                        removed.push(i.path.clone());
                    }
                    !same
                });
            }
            s.next += 1;
            let path = format!("{LOGIN}/{}", s.next);
            s.items.push(StoredItem {
                path: path.clone(),
                attrs,
                label,
                secret: secret.2,
                content_type: secret.3,
            });
            (path, removed)
        };
        for r in removed {
            server.remove::<Item, _>(r.as_str()).await?;
        }
        server
            .at(
                path.as_str(),
                Item {
                    state: self.0.clone(),
                    path: path.clone(),
                },
            )
            .await?;
        Ok((op(&path), op("/")))
    }
}

struct Item {
    state: Shared,
    path: String,
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    fn get_secret(&self, session: OwnedObjectPath) -> fdo::Result<Secret> {
        let s = self.state.lock().unwrap();
        if s.locked {
            return Err(locked_err());
        }
        let i = s
            .items
            .iter()
            .find(|i| i.path == self.path)
            .ok_or_else(|| fdo::Error::UnknownObject(self.path.clone()))?;
        Ok((session, vec![], i.secret.clone(), i.content_type.clone()))
    }

    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<OwnedObjectPath> {
        {
            let mut s = self.state.lock().unwrap();
            if s.locked {
                return Err(locked_err());
            }
            s.items.retain(|i| i.path != self.path);
        }
        server.remove::<Item, _>(self.path.as_str()).await?;
        Ok(op("/"))
    }
}

struct Prompt(Shared);

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(
        &self,
        _window_id: &str,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let mode = self.0.lock().unwrap().prompt;
        match mode {
            PromptMode::Never => {}
            PromptMode::Done => {
                self.0.lock().unwrap().locked = false;
                Prompt::completed(&emitter, false, Value::from("")).await?;
            }
            PromptMode::Dismissed => {
                Prompt::completed(&emitter, true, Value::from("")).await?;
            }
        }
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

/// Serve a Secret Service with `state` on one end of a socket pair, on its
/// own thread and runtime, and connect the backend to the other end.
fn serve(state: Shared, prompt_wait: Duration) -> SecretService<ZbusBus> {
    let (server, client) = std::os::unix::net::UnixStream::pair().unwrap();
    server.set_nonblocking(true).unwrap();
    client.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let stream = tokio::net::UnixStream::from_std(server).unwrap();
            let _conn = connection::Builder::unix_stream(stream)
                .p2p()
                .server(zbus::Guid::generate())
                .unwrap()
                .serve_at("/org/freedesktop/secrets", Service(state.clone()))
                .unwrap()
                .serve_at(LOGIN, Collection(state.clone()))
                .unwrap()
                .serve_at(OTHER, Collection(state.clone()))
                .unwrap()
                .serve_at(PROMPT, Prompt(state.clone()))
                .unwrap()
                .build()
                .await
                .unwrap();
            // Items seeded before the start get their objects too.
            let seeded: Vec<String> = state
                .lock()
                .unwrap()
                .items
                .iter()
                .map(|i| i.path.clone())
                .collect();
            for path in seeded {
                _conn
                    .object_server()
                    .at(
                        path.as_str(),
                        Item {
                            state: state.clone(),
                            path: path.clone(),
                        },
                    )
                    .await
                    .unwrap();
            }
            std::future::pending::<()>().await;
        });
    });
    let bus = ZbusBus::over(move || async move {
        let stream = tokio::net::UnixStream::from_std(client)?;
        connection::Builder::unix_stream(stream).p2p().build().await
    })
    .unwrap();
    SecretService::with_prompt_wait(bus, prompt_wait)
}

fn shared() -> Shared {
    Arc::new(Mutex::new(State::default()))
}

#[test]
fn p2p_roundtrip_set_get_delete() {
    let state = shared();
    let k = serve(state.clone(), Duration::from_secs(10));
    assert_eq!(k.backend(), "secret-service");
    assert_eq!(k.get(&VAULT_KEY).unwrap(), None);
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"first").unwrap();
    assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"first");
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"second").unwrap();
    assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"second");
    {
        let s = state.lock().unwrap();
        assert_eq!(s.items.len(), 1);
        assert_eq!(s.replace_seen, vec![true, true]);
        assert!(s.algorithms.iter().all(|a| a == "plain"));
    }
    assert!(k.delete(&VAULT_KEY).unwrap());
    assert!(!k.delete(&VAULT_KEY).unwrap());
    assert_eq!(k.get(&VAULT_KEY).unwrap(), None);
}

#[test]
fn p2p_secret_bytes_exact() {
    let state = shared();
    let k = serve(state.clone(), Duration::from_secs(10));
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37);
    }
    key[5] = 0x00;
    key[31] = 0xff;
    assert_eq!(key[0], 0x00);
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, &key).unwrap();
    assert_eq!(state.lock().unwrap().items[0].secret, key);
    let got = k.get(&VAULT_KEY).unwrap().unwrap();
    assert_eq!(got.as_slice(), &key);
    assert_eq!(
        state.lock().unwrap().items[0].content_type,
        "application/octet-stream"
    );
}

#[test]
fn p2p_attributes_and_label() {
    let state = shared();
    let k = serve(state.clone(), Duration::from_secs(10));
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"k").unwrap();
    let s = state.lock().unwrap();
    let item = &s.items[0];
    let want: HashMap<String, String> = [
        ("xdg:schema".to_string(), "dev.saiife.VaultKey".to_string()),
        ("application".to_string(), "saiife".to_string()),
        ("saiife-item".to_string(), "vault-key".to_string()),
    ]
    .into();
    assert_eq!(item.attrs, want);
    assert_eq!(item.label, VAULT_KEY_LABEL);
}

#[test]
fn p2p_service_unknown_is_unavailable() {
    let state = shared();
    state.lock().unwrap().unknown = true;
    let k = serve(state, Duration::from_secs(10));
    let e = k.get(&VAULT_KEY).unwrap_err();
    assert!(matches!(e, KeychainError::Unavailable(_)), "{e:?}");
    assert!(e.to_string().starts_with("keychain unavailable: "), "{e}");
    let e = k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"k").unwrap_err();
    assert!(matches!(e, KeychainError::Unavailable(_)), "{e:?}");
}

#[test]
fn p2p_locked_item_prompts_then_reads() {
    let state = shared();
    let k = serve(state.clone(), Duration::from_secs(10));
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"kept").unwrap();
    state.lock().unwrap().locked = true;
    assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"kept");
    assert!(!state.lock().unwrap().locked);
}

#[test]
fn p2p_dismissed_prompt_is_locked() {
    let state = shared();
    let k = serve(state.clone(), Duration::from_secs(10));
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"k").unwrap();
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.prompt = PromptMode::Dismissed;
    }
    let e = k.get(&VAULT_KEY).unwrap_err();
    assert!(matches!(e, KeychainError::Locked(_)), "{e:?}");
}

#[test]
fn p2p_prompt_timeout_is_locked() {
    let state = shared();
    let k = serve(state.clone(), Duration::from_millis(200));
    k.set(&VAULT_KEY, VAULT_KEY_LABEL, b"k").unwrap();
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.prompt = PromptMode::Never;
    }
    let t = Instant::now();
    let e = k.get(&VAULT_KEY).unwrap_err();
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    assert_eq!(
        e,
        KeychainError::Locked("the Secret Service prompt got no answer within 200ms".into())
    );
}

/// `ZbusBus::session()` without `DBUS_SESSION_BUS_ADDRESS`, or with a dead
/// one. Runs in a child process (this test binary, filtered to this test)
/// so this process's environment stays as it is.
#[test]
fn session_without_bus_env_is_unavailable() {
    if std::env::var_os("SAIIFE_SS_CHILD").is_some() {
        child_session_checks();
        return;
    }
    let scratch = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "session_without_bus_env_is_unavailable",
            "--test-threads=1",
            "--nocapture",
        ])
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env("SAIIFE_SS_CHILD", scratch.path())
        // zbus would fall back to $XDG_RUNTIME_DIR/bus; point it nowhere.
        .env("XDG_RUNTIME_DIR", scratch.path())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "{text}");
    assert!(text.contains("child checks ran"), "{text}");
}

fn child_session_checks() {
    assert!(std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none());
    let e = ZbusBus::session().unwrap_err();
    let KeychainError::Unavailable(m) = &e else {
        panic!("{e:?}")
    };
    assert!(m.starts_with("no session bus: "), "{m}");
    let e = SecretService::session().unwrap_err();
    assert!(matches!(e, KeychainError::Unavailable(_)), "{e:?}");
    let e = saiife_keychain::platform().err().unwrap();
    assert!(matches!(e, KeychainError::Unavailable(_)), "{e:?}");

    // A dead path: the connect fails, and is Unavailable too.
    let dir = std::path::PathBuf::from(std::env::var_os("SAIIFE_SS_CHILD").unwrap());
    std::env::set_var(
        "DBUS_SESSION_BUS_ADDRESS",
        format!("unix:path={}", dir.join("no-bus").display()),
    );
    let t = Instant::now();
    let e = ZbusBus::session().unwrap_err();
    assert!(t.elapsed() < Duration::from_secs(10));
    let KeychainError::Unavailable(m) = &e else {
        panic!("{e:?}")
    };
    assert!(m.starts_with("no session bus: "), "{m}");
    println!("child checks ran");
}

#[test]
fn p2p_call_inside_a_runtime_panics_clearly() {
    let k = serve(shared(), Duration::from_secs(10));
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async { k.get(&VAULT_KEY) })
    }));
    let msg = r.unwrap_err();
    let msg = msg
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| msg.downcast_ref::<String>().cloned())
        .unwrap();
    assert!(msg.contains("outside any tokio runtime"), "{msg}");
    // Outside a runtime the same backend still works.
    assert_eq!(k.get(&VAULT_KEY).unwrap(), None);
}

/// The vault key's attributes, as another client would have stored them.
fn key_attrs() -> HashMap<String, String> {
    [
        ("xdg:schema", "dev.saiife.VaultKey"),
        ("application", "saiife"),
        ("saiife-item", "vault-key"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

fn seed(state: &Shared, collection: &str, n: u32, secret: &[u8]) {
    state.lock().unwrap().items.push(StoredItem {
        path: format!("{collection}/seed{n}"),
        attrs: key_attrs(),
        label: "seeded".into(),
        secret: secret.to_vec(),
        content_type: "application/octet-stream".into(),
    });
}

#[test]
fn p2p_item_in_non_default_collection_is_found() {
    let state = shared();
    seed(&state, OTHER, 1, b"elsewhere");
    let k = serve(state, Duration::from_secs(10));
    assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"elsewhere");
}

#[test]
fn p2p_match_in_two_collections_is_other() {
    let state = shared();
    seed(&state, LOGIN, 1, b"in-login-QXJ");
    seed(&state, OTHER, 2, b"in-other-ZWK");
    let k = serve(state, Duration::from_secs(10));
    let e = k.get(&VAULT_KEY).unwrap_err();
    let KeychainError::Other(m) = &e else {
        panic!("{e:?}")
    };
    assert!(m.starts_with("2 Secret Service items"), "{m}");
    assert!(!m.contains("QXJ") && !m.contains("ZWK"), "{m}");
}

#[test]
fn p2p_locked_collection_hides_item_until_unlocked() {
    let state = shared();
    seed(&state, LOGIN, 1, b"hidden");
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.hide_locked = true;
    }
    let k = serve(state.clone(), Duration::from_secs(10));
    assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"hidden");
    assert!(!state.lock().unwrap().locked);
}

#[test]
fn p2p_still_locked_is_locked_not_none() {
    let state = shared();
    {
        let mut s = state.lock().unwrap();
        s.locked = true;
        s.hide_locked = true;
        s.prompt = PromptMode::Dismissed;
    }
    let k = serve(state.clone(), Duration::from_secs(10));
    let e = k.get(&VAULT_KEY).unwrap_err();
    assert!(matches!(e, KeychainError::Locked(_)), "{e:?}");
}

#[test]
fn p2p_drop_inside_a_runtime_does_not_panic() {
    let k = serve(shared(), Duration::from_secs(10));
    assert_eq!(k.get(&VAULT_KEY).unwrap(), None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move { drop(k) });
}
