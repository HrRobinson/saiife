//! `[blind]`: the Data Shield policy (plan 43). Left out of the serialised
//! form (and so the policy hash) while default. Error texts name keys and
//! datasets, never values.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub const LIST_CAP_RANGE: std::ops::RangeInclusive<u32> = 1..=10_000;
pub const SESSION_MINUTES_RANGE: std::ops::RangeInclusive<u32> = 5..=480;
pub const DEFAULT_K: u32 = 10;
pub const DEFAULT_LIST_CAP: u32 = 100;
pub const DEFAULT_SESSION_MINUTES: u32 = 30;
pub const DEFAULT_OUTBOX_DAYS: u32 = 365;
pub const DEFAULT_NER_MAX_BYTES: u64 = 1 << 30;
pub const DEFAULT_CLOUD_MODEL: &str = "claude-opus-5-5";
/// The five column classes.
pub const COLUMN_CLASSES: [&str; 5] = ["identifier", "quasi", "sensitive", "free_text", "public"];

fn exact() -> String {
    "exact".to_string()
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindCfg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_cap: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_minutes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbox_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ner: Option<NerCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<CloudModelCfg>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dataset: Vec<BlindDataset>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NerCfg {
    pub model_url: String,
    pub model_sha256: String,
    pub vocab_url: String,
    pub vocab_sha256: String,
    pub labels_url: String,
    pub labels_sha256: String,
    /// Default 1 GiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudModelCfg {
    /// A vault token secret allowing service "blind-model".
    pub secret: String,
    /// Default "claude-opus-5-5".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindDataset {
    pub name: String,
    pub source: BlindSource,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub approvers: Vec<String>,
    #[serde(default = "exact")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k: Option<u32>,
    #[serde(default)]
    pub preview_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_cap: Option<u32>,
    #[serde(default)]
    pub tables: BTreeMap<String, TableCfg>,
    /// Keys are `table.column`.
    #[serde(default)]
    pub columns: BTreeMap<String, ColumnCfg>,
    #[serde(default)]
    pub entity: Vec<EntityCfg>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum BlindSource {
    Csv {
        file_name: String,
    },
    Xlsx {
        file_name: String,
    },
    Sqlite {
        file_name: String,
    },
    Postgres {
        host: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        dbname: String,
        user: String,
        password_secret: String,
        tables: Vec<String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TableCfg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnCfg {
    pub class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntityCfg {
    pub table: String,
    pub key: String,
    pub names: Vec<String>,
    #[serde(default)]
    pub show: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub word: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub word_da: Option<String>,
}

impl BlindCfg {
    pub fn is_default(&self) -> bool {
        *self == BlindCfg::default()
    }

    /// The k for a dataset: its own, else the global, else 10.
    pub fn k_for(&self, d: &BlindDataset) -> u32 {
        d.k.or(self.k).unwrap_or(DEFAULT_K)
    }

    pub fn list_cap(&self) -> u32 {
        self.list_cap.unwrap_or(DEFAULT_LIST_CAP)
    }

    pub fn session(&self) -> Duration {
        Duration::from_secs(60 * u64::from(self.session_minutes.unwrap_or(DEFAULT_SESSION_MINUTES)))
    }

    pub fn outbox_days(&self) -> u32 {
        self.outbox_days.unwrap_or(DEFAULT_OUTBOX_DAYS)
    }

    /// `Err` names the key or dataset at fault, never a value.
    pub fn validate(&self) -> Result<(), String> {
        if self.k.is_some_and(|k| k < 2) {
            return Err("[blind] k must be at least 2".to_string());
        }
        if self.list_cap.is_some_and(|v| !LIST_CAP_RANGE.contains(&v)) {
            return Err("[blind] list_cap must be 1..=10000".to_string());
        }
        if self
            .session_minutes
            .is_some_and(|v| !SESSION_MINUTES_RANGE.contains(&v))
        {
            return Err("[blind] session_minutes must be 5..=480".to_string());
        }
        if self.outbox_days == Some(0) {
            return Err("[blind] outbox_days must be at least 1".to_string());
        }
        if let Some(n) = &self.ner {
            n.validate()?;
        }
        if let Some(c) = &self.cloud {
            if c.secret.is_empty() {
                return Err("[blind.cloud] secret is empty".to_string());
            }
            if c.model.as_deref() == Some("") {
                return Err("[blind.cloud] model is empty".to_string());
            }
        }
        let mut seen = BTreeSet::new();
        for d in &self.dataset {
            if !valid_dataset_name(&d.name) {
                return Err("[[blind.dataset]] name must match ^[a-z][a-z0-9-]{0,31}$".to_string());
            }
            if !seen.insert(d.name.as_str()) {
                return Err(format!("[[blind.dataset]] name {:?} is used twice", d.name));
            }
            d.validate()?;
        }
        Ok(())
    }
}

impl NerCfg {
    fn validate(&self) -> Result<(), String> {
        for (key, v) in [
            ("model_url", &self.model_url),
            ("vocab_url", &self.vocab_url),
            ("labels_url", &self.labels_url),
        ] {
            if !v.starts_with("https://") {
                return Err(format!("[blind.ner] {key} must start with https://"));
            }
        }
        for (key, v) in [
            ("model_sha256", &self.model_sha256),
            ("vocab_sha256", &self.vocab_sha256),
            ("labels_sha256", &self.labels_sha256),
        ] {
            if !is_hex64(v) {
                return Err(format!("[blind.ner] {key} must be 64 lowercase hex digits"));
            }
        }
        if self.max_bytes == Some(0) {
            return Err("[blind.ner] max_bytes must be at least 1".to_string());
        }
        Ok(())
    }
}

impl BlindDataset {
    fn validate(&self) -> Result<(), String> {
        let n = &self.name;
        if self.mode != "exact" {
            return Err(format!(
                "[[blind.dataset]] {n}: mode must be \"exact\" (judgment mode is a later stage)"
            ));
        }
        if self.k.is_some_and(|k| k < 2) {
            return Err(format!("[[blind.dataset]] {n}: k must be at least 2"));
        }
        if self.list_cap.is_some_and(|v| !LIST_CAP_RANGE.contains(&v)) {
            return Err(format!("[[blind.dataset]] {n}: list_cap must be 1..=10000"));
        }
        for (key, list) in [("users", &self.users), ("approvers", &self.approvers)] {
            for e in list {
                if !crate::system::valid_principal(e) {
                    return Err(format!(
                        "[[blind.dataset]] {n}: {key} has an entry that is not a user name or group:<name>"
                    ));
                }
            }
        }
        for (key, c) in &self.columns {
            match key.split_once('.') {
                Some((t, col)) if !t.is_empty() && !col.is_empty() => {}
                _ => {
                    return Err(format!(
                        "[[blind.dataset]] {n}: columns key {key:?} is not table.column"
                    ))
                }
            }
            if !COLUMN_CLASSES.contains(&c.class.as_str()) {
                return Err(format!(
                    "[[blind.dataset]] {n}: columns.{key} class must be one of {}",
                    COLUMN_CLASSES.join(", ")
                ));
            }
        }
        if let BlindSource::Postgres { host, .. } = &self.source {
            let local =
                host.starts_with('/') || matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");
            if !local {
                return Err(format!(
                    "[[blind.dataset]] {n}: remote Postgres needs TLS, which is a later stage"
                ));
            }
        }
        Ok(())
    }
}

fn valid_dataset_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
