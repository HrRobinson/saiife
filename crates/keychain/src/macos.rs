//! The macOS login Keychain, as generic passwords.
//!
//! The saiife binary creates the item, so the item's default access list
//! names that binary (spec §6.6 "access list"). Another program of the same
//! user reading it gets a prompt the user may click through.
//!
//! This compiles and is checked on the macOS CI runner; it is not run there.
//! `saiife daemon --user` on macOS is refused until the plan 13 daemon port.

use crate::{ItemId, Keychain, KeychainError};
use security_framework::base::Error as SecError;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use zeroize::Zeroizing;

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_NO_SUCH_KEYCHAIN: i32 = -25294;
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
const ERR_SEC_NO_DEFAULT_KEYCHAIN: i32 = -25307;

/// The login Keychain through Security.framework.
#[derive(Debug, Default)]
pub struct MacKeychain;

impl MacKeychain {
    pub fn new() -> Self {
        MacKeychain
    }
}

/// Map an OSStatus to a [`KeychainError`]. The text is the status and
/// Apple's description of it, never the secret.
fn map(e: SecError) -> KeychainError {
    let code = e.code();
    let msg = format!(
        "{} (OSStatus {code})",
        e.message()
            .unwrap_or_else(|| "Security.framework error".into())
    );
    match code {
        ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_AUTH_FAILED | ERR_SEC_USER_CANCELED => {
            KeychainError::Locked(msg)
        }
        ERR_SEC_NO_SUCH_KEYCHAIN | ERR_SEC_NOT_AVAILABLE | ERR_SEC_NO_DEFAULT_KEYCHAIN => {
            KeychainError::Unavailable(msg)
        }
        _ => KeychainError::Other(msg),
    }
}

impl Keychain for MacKeychain {
    fn get(&self, id: &ItemId) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        match get_generic_password(id.service, id.account) {
            Ok(b) => Ok(Some(Zeroizing::new(b))),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(map(e)),
        }
    }

    /// The label is not stored on macOS: `set_generic_password` updates an
    /// existing item in place, and a label in the query would stop it from
    /// matching an item stored under another label.
    fn set(&self, id: &ItemId, _label: &str, secret: &[u8]) -> Result<(), KeychainError> {
        set_generic_password(id.service, id.account, secret).map_err(map)
    }

    fn delete(&self, id: &ItemId) -> Result<bool, KeychainError> {
        match delete_generic_password(id.service, id.account) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(e) => Err(map(e)),
        }
    }

    fn backend(&self) -> &'static str {
        "macos-keychain"
    }
}
