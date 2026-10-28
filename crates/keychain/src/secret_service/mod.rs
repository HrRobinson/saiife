//! The freedesktop Secret Service (GNOME Keyring, KWallet, KeePassXC) over
//! D-Bus, with a `plain` session.
//!
//! The bus is the user's own, so the DH session encryption would add
//! dependencies and no protection: any process that can read the bus can
//! ask the service for the secret itself.
//!
//! The order matters for security:
//! - `get` refuses more than one matching item rather than guess which one
//!   holds the key;
//! - `get` unlocks (prompting if needed) before it reads, and a dismissed
//!   or unanswered prompt is [`KeychainError::Locked`];
//! - `set` writes only to the `default` alias collection, replacing an item
//!   with the same attributes;
//! - no session bus, or no Secret Service on it, is
//!   [`KeychainError::Unavailable`], never a panic or a hang.

mod bus;
mod zbus_bus;

pub use bus::{Found, Prompted, SsBus};
pub use zbus_bus::ZbusBus;

use crate::{ItemId, Keychain, KeychainError};
use std::time::Duration;
use zeroize::Zeroizing;

/// How long an unlock (or other) prompt may stay unanswered.
pub const PROMPT_WAIT: Duration = Duration::from_secs(120);

/// The alias of the collection new items go to.
const DEFAULT_ALIAS: &str = "default";

/// A [`Keychain`] over the Secret Service API.
pub struct SecretService<B: SsBus> {
    bus: B,
    prompt_wait: Duration,
}

impl<B: SsBus> std::fmt::Debug for SecretService<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretService")
            .field("prompt_wait", &self.prompt_wait)
            .finish_non_exhaustive()
    }
}

impl SecretService<ZbusBus> {
    /// The Secret Service on the user's session bus.
    pub fn session() -> Result<Self, KeychainError> {
        Ok(Self::new(ZbusBus::session()?))
    }
}

impl<B: SsBus> SecretService<B> {
    /// The backend over `bus`, waiting [`PROMPT_WAIT`] for prompts.
    pub fn new(bus: B) -> Self {
        Self::with_prompt_wait(bus, PROMPT_WAIT)
    }

    /// The backend over `bus`, waiting `prompt_wait` for prompts.
    pub fn with_prompt_wait(bus: B, prompt_wait: Duration) -> Self {
        SecretService { bus, prompt_wait }
    }

    fn run_prompt(&self, prompt: &str) -> Result<(), KeychainError> {
        match self.bus.prompt(prompt, self.prompt_wait)? {
            Prompted::Done => Ok(()),
            Prompted::Dismissed => Err(KeychainError::Locked(
                "the Secret Service prompt was dismissed".into(),
            )),
            Prompted::TimedOut => Err(KeychainError::Locked(format!(
                "the Secret Service prompt got no answer within {:?}",
                self.prompt_wait
            ))),
        }
    }

    /// Unlock `objects`, prompting if the service asks for it.
    fn unlock(&self, objects: &[String]) -> Result<(), KeychainError> {
        let (_unlocked, prompt) = self.bus.unlock(objects)?;
        match prompt {
            Some(p) => self.run_prompt(&p),
            None => Ok(()),
        }
    }

    /// Every item with `id`'s attributes, unlocked or locked.
    fn find(&self, id: &ItemId) -> Result<Found, KeychainError> {
        self.bus.search_items(&attributes(id))
    }
}

/// The attributes an item is stored and found under:
/// `application=<service>`, `saiife-item=<account>`.
fn attributes(id: &ItemId) -> [(&'static str, &'static str); 2] {
    [("application", id.service), ("saiife-item", id.account)]
}

impl<B: SsBus> Keychain for SecretService<B> {
    fn get(&self, id: &ItemId) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        let found = self.find(id)?;
        let count = found.unlocked.len() + found.locked.len();
        let item = match count {
            0 => return Ok(None),
            1 => found
                .unlocked
                .first()
                .or(found.locked.first())
                .cloned()
                .unwrap_or_default(),
            n => {
                return Err(KeychainError::Other(format!(
                    "{n} Secret Service items have application={} saiife-item={}; \
                     refusing to guess which one to read",
                    id.service, id.account
                )))
            }
        };
        if !found.locked.is_empty() {
            self.unlock(&found.locked)?;
        }
        let session = self.bus.open_session()?;
        self.bus.get_secret(&item, &session).map(Some)
    }

    fn set(&self, id: &ItemId, label: &str, secret: &[u8]) -> Result<(), KeychainError> {
        let collection = self.bus.read_alias(DEFAULT_ALIAS)?.ok_or_else(|| {
            KeychainError::Unavailable("the Secret Service has no default collection".into())
        })?;
        self.unlock(std::slice::from_ref(&collection))?;
        let session = self.bus.open_session()?;
        let prompt = self
            .bus
            .create_item(&collection, label, &attributes(id), &session, secret)?;
        match prompt {
            Some(p) => self.run_prompt(&p),
            None => Ok(()),
        }
    }

    fn delete(&self, id: &ItemId) -> Result<bool, KeychainError> {
        let found = self.find(id)?;
        if found.unlocked.is_empty() && found.locked.is_empty() {
            return Ok(false);
        }
        if !found.locked.is_empty() {
            self.unlock(&found.locked)?;
        }
        for item in found.unlocked.iter().chain(&found.locked) {
            if let Some(p) = self.bus.delete(item)? {
                self.run_prompt(&p)?;
            }
        }
        Ok(true)
    }

    fn backend(&self) -> &'static str {
        "secret-service"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VAULT_KEY, VAULT_KEY_LABEL};
    use std::sync::{Mutex, MutexGuard};
    use std::time::Instant;

    const LOGIN: &str = "/org/freedesktop/secrets/collection/login";

    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    enum PromptMode {
        #[default]
        Done,
        Dismissed,
        Never,
    }

    struct Item {
        path: String,
        collection: String,
        attrs: Vec<(String, String)>,
        label: String,
        secret: Vec<u8>,
    }

    #[derive(Default)]
    struct State {
        alias: Option<String>,
        locked: bool,
        prompt: PromptMode,
        items: Vec<Item>,
        next: u32,
        calls: Vec<&'static str>,
        waited: Option<Duration>,
    }

    /// A Secret Service in memory: one lock flag for everything, prompts
    /// that complete, are dismissed or never answer.
    #[derive(Default)]
    struct FakeBus(Mutex<State>);

    impl FakeBus {
        fn s(&self) -> MutexGuard<'_, State> {
            self.0.lock().unwrap()
        }
        fn with_login() -> Self {
            let b = FakeBus::default();
            b.s().alias = Some(LOGIN.into());
            b
        }
        fn add(&self, attrs: [(&str, &str); 2], secret: &[u8]) {
            let mut s = self.s();
            s.next += 1;
            let path = format!("{LOGIN}/{}", s.next);
            s.items.push(Item {
                path,
                collection: LOGIN.into(),
                attrs: attrs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                label: "old".into(),
                secret: secret.to_vec(),
            });
        }
        fn calls(&self) -> Vec<&'static str> {
            self.s().calls.clone()
        }
    }

    fn matches(item: &Item, attrs: &[(&str, &str)]) -> bool {
        attrs
            .iter()
            .all(|(k, v)| item.attrs.iter().any(|(ik, iv)| ik == k && iv == v))
    }

    impl SsBus for FakeBus {
        fn open_session(&self) -> Result<String, KeychainError> {
            self.s().calls.push("open_session");
            Ok("/org/freedesktop/secrets/session/1".into())
        }
        fn read_alias(&self, _name: &str) -> Result<Option<String>, KeychainError> {
            let mut s = self.s();
            s.calls.push("read_alias");
            Ok(s.alias.clone())
        }
        fn search_items(&self, attrs: &[(&str, &str)]) -> Result<Found, KeychainError> {
            let mut s = self.s();
            s.calls.push("search_items");
            let paths: Vec<String> = s
                .items
                .iter()
                .filter(|i| matches(i, attrs))
                .map(|i| i.path.clone())
                .collect();
            Ok(if s.locked {
                Found {
                    unlocked: vec![],
                    locked: paths,
                }
            } else {
                Found {
                    unlocked: paths,
                    locked: vec![],
                }
            })
        }
        fn unlock(
            &self,
            objects: &[String],
        ) -> Result<(Vec<String>, Option<String>), KeychainError> {
            let mut s = self.s();
            s.calls.push("unlock");
            if s.locked {
                Ok((vec![], Some("/org/freedesktop/secrets/prompt/1".into())))
            } else {
                Ok((objects.to_vec(), None))
            }
        }
        fn prompt(&self, _prompt: &str, wait: Duration) -> Result<Prompted, KeychainError> {
            let mode = {
                let mut s = self.s();
                s.calls.push("prompt");
                s.waited = Some(wait);
                s.prompt
            };
            Ok(match mode {
                PromptMode::Done => {
                    self.s().locked = false;
                    Prompted::Done
                }
                PromptMode::Dismissed => Prompted::Dismissed,
                PromptMode::Never => {
                    std::thread::sleep(wait);
                    Prompted::TimedOut
                }
            })
        }
        fn get_secret(
            &self,
            item: &str,
            _session: &str,
        ) -> Result<Zeroizing<Vec<u8>>, KeychainError> {
            let mut s = self.s();
            s.calls.push("get_secret");
            if s.locked {
                return Err(KeychainError::Locked("IsLocked".into()));
            }
            let i = s.items.iter().find(|i| i.path == item).unwrap();
            Ok(Zeroizing::new(i.secret.clone()))
        }
        fn create_item(
            &self,
            collection: &str,
            label: &str,
            attrs: &[(&str, &str)],
            _session: &str,
            secret: &[u8],
        ) -> Result<Option<String>, KeychainError> {
            let mut s = self.s();
            s.calls.push("create_item");
            if s.locked {
                return Err(KeychainError::Locked("IsLocked".into()));
            }
            // replace = true: an item with the same attributes in this
            // collection is overwritten.
            s.items
                .retain(|i| !(i.collection == collection && matches(i, attrs)));
            s.next += 1;
            let path = format!("{collection}/{}", s.next);
            s.items.push(Item {
                path,
                collection: collection.into(),
                attrs: attrs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                label: label.into(),
                secret: secret.to_vec(),
            });
            Ok(None)
        }
        fn delete(&self, item: &str) -> Result<Option<String>, KeychainError> {
            let mut s = self.s();
            s.calls.push("delete");
            s.items.retain(|i| i.path != item);
            Ok(None)
        }
    }

    const KEY_ATTRS: [(&str, &str); 2] = [("application", "saiife"), ("saiife-item", "vault-key")];

    #[test]
    fn backend_name() {
        assert_eq!(
            SecretService::new(FakeBus::default()).backend(),
            "secret-service"
        );
    }

    #[test]
    fn get_none_when_no_item() {
        let ss = SecretService::new(FakeBus::with_login());
        assert_eq!(ss.get(&VAULT_KEY).unwrap(), None);
        assert_eq!(ss.bus.calls(), vec!["search_items"]);
    }

    #[test]
    fn get_unlocks_locked_item_then_reads() {
        let bus = FakeBus::with_login();
        bus.add(KEY_ATTRS, b"locked key");
        bus.s().locked = true;
        let ss = SecretService::new(bus);
        assert_eq!(
            ss.get(&VAULT_KEY).unwrap().unwrap().as_slice(),
            b"locked key"
        );
        assert_eq!(
            ss.bus.calls(),
            vec![
                "search_items",
                "unlock",
                "prompt",
                "open_session",
                "get_secret"
            ]
        );
        assert_eq!(ss.bus.s().waited, Some(PROMPT_WAIT));
    }

    #[test]
    fn dismissed_prompt_is_locked() {
        let bus = FakeBus::with_login();
        bus.add(KEY_ATTRS, b"k");
        bus.s().locked = true;
        bus.s().prompt = PromptMode::Dismissed;
        let ss = SecretService::new(bus);
        let e = ss.get(&VAULT_KEY).unwrap_err();
        assert_eq!(
            e,
            KeychainError::Locked("the Secret Service prompt was dismissed".into())
        );
        assert!(!ss.bus.calls().contains(&"get_secret"));
        // The same for a write into a locked collection.
        assert!(matches!(
            ss.set(&VAULT_KEY, VAULT_KEY_LABEL, b"x"),
            Err(KeychainError::Locked(_))
        ));
        assert!(!ss.bus.calls().contains(&"create_item"));
    }

    #[test]
    fn prompt_timeout_is_locked() {
        let bus = FakeBus::with_login();
        bus.add(KEY_ATTRS, b"k");
        bus.s().locked = true;
        bus.s().prompt = PromptMode::Never;
        let ss = SecretService::with_prompt_wait(bus, Duration::from_millis(50));
        let t = Instant::now();
        let e = ss.get(&VAULT_KEY).unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(5));
        assert_eq!(
            e,
            KeychainError::Locked("the Secret Service prompt got no answer within 50ms".into())
        );
        assert_eq!(ss.bus.s().waited, Some(Duration::from_millis(50)));
        assert!(!ss.bus.calls().contains(&"get_secret"));
    }

    #[test]
    fn two_items_is_error() {
        let bus = FakeBus::with_login();
        bus.add(KEY_ATTRS, b"first-QXJ");
        bus.add(KEY_ATTRS, b"second-ZWK");
        let ss = SecretService::new(bus);
        let e = ss.get(&VAULT_KEY).unwrap_err();
        let KeychainError::Other(m) = &e else {
            panic!("{e:?}")
        };
        assert!(m.starts_with("2 Secret Service items"), "{m}");
        assert!(!m.contains("QXJ") && !m.contains("ZWK"), "{m}");
        assert_eq!(ss.bus.calls(), vec!["search_items"]);
    }

    #[test]
    fn set_without_default_alias_is_unavailable() {
        let ss = SecretService::new(FakeBus::default());
        assert_eq!(
            ss.set(&VAULT_KEY, VAULT_KEY_LABEL, b"k"),
            Err(KeychainError::Unavailable(
                "the Secret Service has no default collection".into()
            ))
        );
        assert_eq!(ss.bus.calls(), vec!["read_alias"]);
    }

    #[test]
    fn set_replaces_existing() {
        let bus = FakeBus::with_login();
        bus.add(KEY_ATTRS, b"old key");
        let ss = SecretService::new(bus);
        ss.set(&VAULT_KEY, VAULT_KEY_LABEL, b"new key").unwrap();
        assert_eq!(ss.get(&VAULT_KEY).unwrap().unwrap().as_slice(), b"new key");
        let s = ss.bus.s();
        assert_eq!(s.items.len(), 1);
        assert_eq!(s.items[0].label, VAULT_KEY_LABEL);
        assert_eq!(s.items[0].collection, LOGIN);
    }

    #[test]
    fn delete_unlocks_and_removes() {
        let bus = FakeBus::with_login();
        bus.add(KEY_ATTRS, b"k");
        bus.s().locked = true;
        let ss = SecretService::new(bus);
        assert!(ss.delete(&VAULT_KEY).unwrap());
        assert!(ss.bus.s().items.is_empty());
        assert!(!ss.delete(&VAULT_KEY).unwrap());
        assert_eq!(
            ss.bus.calls(),
            vec!["search_items", "unlock", "prompt", "delete", "search_items"]
        );
    }
}
