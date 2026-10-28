//! The Secret Service calls the backend makes, as a trait: [`ZbusBus`] makes
//! them over D-Bus, and the unit tests use a fake.
//!
//! [`ZbusBus`]: super::ZbusBus

use crate::KeychainError;
use std::time::Duration;
use zeroize::Zeroizing;

/// The Secret Service's well-known bus name.
pub const SS_DEST: &str = "org.freedesktop.secrets";
/// The service object.
pub const SS_PATH: &str = "/org/freedesktop/secrets";
pub const SS_SERVICE: &str = "org.freedesktop.Secret.Service";
pub const SS_COLLECTION: &str = "org.freedesktop.Secret.Collection";
pub const SS_ITEM: &str = "org.freedesktop.Secret.Item";
pub const SS_PROMPT: &str = "org.freedesktop.Secret.Prompt";
/// The item properties `CreateItem` takes.
pub const PROP_LABEL: &str = "org.freedesktop.Secret.Item.Label";
pub const PROP_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";
/// The content type the vault key is stored with.
pub const CONTENT_TYPE: &str = "application/octet-stream";

/// What `SearchItems` found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    pub unlocked: Vec<String>,
    pub locked: Vec<String>,
}

/// How a prompt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompted {
    /// `Completed` with `dismissed = false`.
    Done,
    /// `Completed` with `dismissed = true`.
    Dismissed,
    /// No `Completed` within the wait.
    TimedOut,
}

/// One method per Secret Service call the backend uses. Object paths are
/// strings; a `"/"` path (no object, no prompt) is `None`.
pub trait SsBus: Send + Sync {
    /// `Service.OpenSession("plain", "")`: the session path.
    fn open_session(&self) -> Result<String, KeychainError>;
    /// `Service.ReadAlias(name)`: the collection, or `None` for no alias.
    fn read_alias(&self, name: &str) -> Result<Option<String>, KeychainError>;
    /// `Service.SearchItems(attributes)`.
    fn search_items(&self, attributes: &[(&str, &str)]) -> Result<Found, KeychainError>;
    /// `Service.Unlock(objects)`: the objects unlocked now, and a prompt to
    /// run for the rest.
    fn unlock(&self, objects: &[String]) -> Result<(Vec<String>, Option<String>), KeychainError>;
    /// `Prompt.Prompt("")`, then wait up to `wait` for `Completed`.
    fn prompt(&self, prompt: &str, wait: Duration) -> Result<Prompted, KeychainError>;
    /// `Item.GetSecret(session)`: the secret's value.
    fn get_secret(&self, item: &str, session: &str) -> Result<Zeroizing<Vec<u8>>, KeychainError>;
    /// `Collection.CreateItem(properties, secret, replace = true)`: a prompt
    /// to run, if any.
    fn create_item(
        &self,
        collection: &str,
        label: &str,
        attributes: &[(&str, &str)],
        session: &str,
        secret: &[u8],
    ) -> Result<Option<String>, KeychainError>;
    /// `Item.Delete()`: a prompt to run, if any.
    fn delete(&self, item: &str) -> Result<Option<String>, KeychainError>;
}
