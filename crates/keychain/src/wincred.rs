//! The Windows backend: Credential Manager, one generic credential per item.
//!
//! The credential is the current user's own (kept by the OS under the logon secret), so
//! another account cannot read it, and the personal broker is not a boundary against the
//! same user. The calls are `saiife_win::ffi::cred`'s; this crate stays free of `unsafe`.
//! The calls sit behind [`CredApi`] so Linux tests run the mapping and the error text.
//!
//! A target is `<service>:<account>` (`saiife:vault-key`). The label goes in the
//! credential's comment. Error text names the OS error, never the secret.

use crate::{ItemId, Keychain, KeychainError};
use std::io;
use zeroize::Zeroizing;

/// The backend name in status lines and records.
pub const BACKEND: &str = "windows-credential-manager";

/// `ERROR_NO_SUCH_LOGON_SESSION`: no logon session to hold a credential, as in a
/// service on a machine that has no profile for it.
const NO_LOGON_SESSION: i32 = 1312;
/// `ERROR_INVALID_PARAMETER`: Credential Manager refused the call as formed (an item too big).
const INVALID_PARAMETER: i32 = 87;

/// The credential target for `id`: `<service>:<account>`.
pub fn target_of(id: &ItemId) -> String {
    format!("{}:{}", id.service, id.account)
}

/// The three Credential Manager calls.
pub trait CredApi: Send + Sync {
    fn read(&self, target: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>>;
    fn write(&self, target: &str, comment: &str, blob: &[u8]) -> io::Result<()>;
    fn delete(&self, target: &str) -> io::Result<bool>;
}

/// The real calls; off Windows they fail as unsupported, so nothing here compiles away.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ffi;

#[cfg(windows)]
impl CredApi for Ffi {
    fn read(&self, target: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        saiife_win::ffi::cred::read(target)
    }
    fn write(&self, target: &str, comment: &str, blob: &[u8]) -> io::Result<()> {
        saiife_win::ffi::cred::write(target, comment, blob)
    }
    fn delete(&self, target: &str) -> io::Result<bool> {
        saiife_win::ffi::cred::delete(target)
    }
}

#[cfg(not(windows))]
impl CredApi for Ffi {
    fn read(&self, _: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        Err(unsupported())
    }
    fn write(&self, _: &str, _: &str, _: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }
    fn delete(&self, _: &str) -> io::Result<bool> {
        Err(unsupported())
    }
}

#[cfg(not(windows))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Credential Manager needs Windows",
    )
}

/// A failed call as a [`KeychainError`]. Only the OS error's own text goes in.
fn mapped(e: &io::Error) -> KeychainError {
    match e.raw_os_error() {
        Some(NO_LOGON_SESSION) => KeychainError::Unavailable(format!("credential manager: {e}")),
        Some(INVALID_PARAMETER) => KeychainError::Other(format!("credential manager: {e}")),
        _ if e.kind() == io::ErrorKind::Unsupported => {
            KeychainError::Unavailable(format!("credential manager: {e}"))
        }
        _ => KeychainError::Other(format!("credential manager: {e}")),
    }
}

/// Credential Manager as a [`Keychain`].
#[derive(Debug, Default, Clone, Copy)]
pub struct WinCredential<A: CredApi = Ffi> {
    api: A,
}

impl WinCredential<Ffi> {
    pub fn new() -> Self {
        Self { api: Ffi }
    }
}

impl<A: CredApi> WinCredential<A> {
    pub fn with_api(api: A) -> Self {
        Self { api }
    }
}

impl<A: CredApi> Keychain for WinCredential<A> {
    fn get(&self, id: &ItemId) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        self.api.read(&target_of(id)).map_err(|e| mapped(&e))
    }

    fn set(&self, id: &ItemId, label: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.api
            .write(&target_of(id), label, secret)
            .map_err(|e| mapped(&e))
    }

    fn delete(&self, id: &ItemId) -> Result<bool, KeychainError> {
        self.api.delete(&target_of(id)).map_err(|e| mapped(&e))
    }

    fn backend(&self) -> &'static str {
        BACKEND
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VAULT_KEY, VAULT_KEY_LABEL};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// An in-memory Credential Manager that records what it was asked.
    #[derive(Default)]
    struct Mem {
        items: Mutex<HashMap<String, (String, Vec<u8>)>>,
        fail: Option<i32>,
    }

    impl CredApi for Mem {
        fn read(&self, t: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
            if let Some(c) = self.fail {
                return Err(io::Error::from_raw_os_error(c));
            }
            Ok(self
                .items
                .lock()
                .unwrap()
                .get(t)
                .map(|(_, b)| Zeroizing::new(b.clone())))
        }
        fn write(&self, t: &str, c: &str, b: &[u8]) -> io::Result<()> {
            if let Some(code) = self.fail {
                return Err(io::Error::from_raw_os_error(code));
            }
            self.items
                .lock()
                .unwrap()
                .insert(t.to_string(), (c.to_string(), b.to_vec()));
            Ok(())
        }
        fn delete(&self, t: &str) -> io::Result<bool> {
            Ok(self.items.lock().unwrap().remove(t).is_some())
        }
    }

    #[test]
    fn the_vault_key_target_is_saiife_vault_key() {
        assert_eq!(target_of(&VAULT_KEY), "saiife:vault-key");
    }

    #[test]
    fn roundtrip_through_the_trait() {
        let k = WinCredential::with_api(Mem::default());
        assert_eq!(k.backend(), "windows-credential-manager");
        assert!(k.get(&VAULT_KEY).unwrap().is_none());
        k.set(&VAULT_KEY, VAULT_KEY_LABEL, &[3u8; 32]).unwrap();
        assert_eq!(k.get(&VAULT_KEY).unwrap().unwrap().as_slice(), &[3u8; 32]);
        let (label, _) = k.api.items.lock().unwrap()["saiife:vault-key"].clone();
        assert_eq!(label, VAULT_KEY_LABEL);
        assert!(k.delete(&VAULT_KEY).unwrap());
        assert!(!k.delete(&VAULT_KEY).unwrap());
    }

    #[test]
    fn no_logon_session_is_unavailable_and_errors_hold_no_secret() {
        let k = WinCredential::with_api(Mem {
            fail: Some(NO_LOGON_SESSION),
            ..Default::default()
        });
        let secret = [0x5au8; 32];
        let e = k.set(&VAULT_KEY, VAULT_KEY_LABEL, &secret).unwrap_err();
        assert!(matches!(e, KeychainError::Unavailable(_)), "{e}");
        assert!(!e.to_string().contains("ZZZZ"), "{e}");
        let e = WinCredential::with_api(Mem {
            fail: Some(5),
            ..Default::default()
        })
        .get(&VAULT_KEY)
        .unwrap_err();
        assert!(matches!(e, KeychainError::Other(_)), "{e}");
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_real_calls_are_unavailable() {
        let e = WinCredential::new().get(&VAULT_KEY).unwrap_err();
        assert!(matches!(e, KeychainError::Unavailable(_)), "{e}");
    }

    /// Deletes the test's credential however the test ends.
    #[cfg(windows)]
    struct Remove(ItemId);

    #[cfg(windows)]
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = WinCredential::new().delete(&self.0);
        }
    }

    /// The real Credential Manager under a random throwaway item, so it runs in CI only
    /// (`build.rs`): on someone's machine this would write to their own store.
    #[cfg(windows)]
    #[test]
    #[cfg_attr(
        not(saiife_ci),
        ignore = "writes to Credential Manager; runs when CI is set"
    )]
    fn wincred_roundtrip() {
        use std::hash::{BuildHasher, Hasher};
        // The std hasher's seed is random per instance, and needs no RNG crate here.
        let random = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        let id = ItemId {
            service: "saiife-test",
            account: Box::leak(format!("{random:016x}").into_boxed_str()),
        };
        let k = WinCredential::new();
        let _remove = Remove(id);
        assert!(k.get(&id).unwrap().is_none());
        k.set(&id, "saiife test item", &[8u8; 32]).unwrap();
        assert_eq!(k.get(&id).unwrap().unwrap().as_slice(), &[8u8; 32]);
        assert!(k.delete(&id).unwrap());
        assert!(k.get(&id).unwrap().is_none());
    }
}
