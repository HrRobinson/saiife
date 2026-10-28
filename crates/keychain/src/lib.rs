//! The OS keychain behind saiife's personal broker (`saiife daemon --user`).
//!
//! The broker keeps one item here, the 32-byte vault key ([`VAULT_KEY`]);
//! the secrets themselves stay in `vault.bin`, sealed under that key.
//!
//! - [`platform`] is the real backend: Secret Service on Linux
//!   ([`secret_service::SecretService`]), the login Keychain on macOS
//!   ([`MacKeychain`]).
//! - [`FakeKeychain`] is an in-memory backend for unit tests.
//! - [`DirKeychain`] (debug builds only) keeps one 0600 file per item in a
//!   0700 dir. [`from_env`] selects it when `SAIIFE_TEST_KEYCHAIN=<dir>` is
//!   set, so integration tests never reach the desktop keyring. Release
//!   builds have no such seam.
//!
//! Error messages never contain secret bytes.

#![forbid(unsafe_code)]

use std::fmt;
use zeroize::Zeroizing;

#[cfg(all(debug_assertions, unix))]
mod dir;
mod fake;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
pub mod secret_service;

#[cfg(all(debug_assertions, unix))]
pub use dir::DirKeychain;
pub use fake::FakeKeychain;
#[cfg(target_os = "macos")]
pub use macos::MacKeychain;

/// One keychain item: a service and an account name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ItemId {
    pub service: &'static str,
    pub account: &'static str,
}

/// The personal broker's vault key.
pub const VAULT_KEY: ItemId = ItemId {
    service: "saiife",
    account: "vault-key",
};

/// The label the vault key item is stored with.
pub const VAULT_KEY_LABEL: &str = "saiife personal broker: vault key";

/// A keychain failure. The text says what went wrong, never what the
/// secret is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeychainError {
    /// No keychain to talk to (no session bus, no Secret Service, an
    /// unsupported platform).
    Unavailable(String),
    /// The keychain is locked and was not unlocked (a dismissed or
    /// timed-out prompt).
    Locked(String),
    /// Anything else.
    Other(String),
}

impl fmt::Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeychainError::Unavailable(m) => write!(f, "keychain unavailable: {m}"),
            KeychainError::Locked(m) => write!(f, "keychain locked: {m}"),
            KeychainError::Other(m) => write!(f, "keychain error: {m}"),
        }
    }
}

impl std::error::Error for KeychainError {}

/// A store of small secrets keyed by [`ItemId`].
pub trait Keychain: Send + Sync {
    /// The item's secret, or `None` when there is no such item.
    fn get(&self, id: &ItemId) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError>;
    /// Create or replace the item.
    fn set(&self, id: &ItemId, label: &str, secret: &[u8]) -> Result<(), KeychainError>;
    /// Remove the item; `false` when there was none.
    fn delete(&self, id: &ItemId) -> Result<bool, KeychainError>;
    /// A short backend name for status lines and records.
    fn backend(&self) -> &'static str;
}

/// The platform keychain.
pub fn platform() -> Result<Box<dyn Keychain>, KeychainError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(MacKeychain::new()))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(secret_service::SecretService::session()?))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(KeychainError::Unavailable(
            "no keychain backend on this platform".into(),
        ))
    }
}

/// The keychain the broker uses: in debug builds `SAIIFE_TEST_KEYCHAIN=<dir>`
/// selects a [`DirKeychain`]; otherwise [`platform`].
pub fn from_env() -> Result<Box<dyn Keychain>, KeychainError> {
    #[cfg(all(debug_assertions, unix))]
    if let Some(dir) = std::env::var_os("SAIIFE_TEST_KEYCHAIN").filter(|d| !d.is_empty()) {
        return Ok(Box::new(DirKeychain::new(dir)?));
    }
    platform()
}
