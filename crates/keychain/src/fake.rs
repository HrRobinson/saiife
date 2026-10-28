//! An in-memory keychain for tests.

use crate::{ItemId, Keychain, KeychainError};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

#[derive(Default)]
struct State {
    items: HashMap<ItemId, Zeroizing<Vec<u8>>>,
    fail_next: Option<KeychainError>,
    locked: bool,
    calls: Vec<&'static str>,
}

/// An in-memory [`Keychain`]. It records every call, can fail the next one,
/// and can act locked.
#[derive(Default)]
pub struct FakeKeychain {
    state: Mutex<State>,
}

impl fmt::Debug for FakeKeychain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.lock();
        f.debug_struct("FakeKeychain")
            .field("items", &s.items.len())
            .field("locked", &s.locked)
            .finish()
    }
}

impl FakeKeychain {
    pub fn new() -> Self {
        Self::default()
    }

    /// The next call (of any kind) fails with `e`, once.
    pub fn fail_next(&self, e: KeychainError) {
        self.lock().fail_next = Some(e);
    }

    /// While locked, every call fails with [`KeychainError::Locked`].
    pub fn set_locked(&self, locked: bool) {
        self.lock().locked = locked;
    }

    /// The calls made so far, in order: `"get"`, `"set"` or `"delete"`.
    pub fn calls(&self) -> Vec<&'static str> {
        self.lock().calls.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn enter(&self, call: &'static str) -> Result<MutexGuard<'_, State>, KeychainError> {
        let mut s = self.lock();
        s.calls.push(call);
        if let Some(e) = s.fail_next.take() {
            return Err(e);
        }
        if s.locked {
            return Err(KeychainError::Locked("the fake keychain is locked".into()));
        }
        Ok(s)
    }
}

impl Keychain for FakeKeychain {
    fn get(&self, id: &ItemId) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        let s = self.enter("get")?;
        Ok(s.items.get(id).cloned())
    }

    fn set(&self, id: &ItemId, _label: &str, secret: &[u8]) -> Result<(), KeychainError> {
        let mut s = self.enter("set")?;
        s.items.insert(*id, Zeroizing::new(secret.to_vec()));
        Ok(())
    }

    fn delete(&self, id: &ItemId) -> Result<bool, KeychainError> {
        let mut s = self.enter("delete")?;
        Ok(s.items.remove(id).is_some())
    }

    fn backend(&self) -> &'static str {
        "fake"
    }
}
