//! Plan 45: approved methods and their strict reuse rule (R45-11, spec
//! §2.3.5). A method approved by a user with the approver role plus a touch
//! (recorded by plan 48) is reused only for the same dataset, language,
//! question template key and parameter type tags; every dataset refresh
//! re-validates each stored method, and one that no longer validates is
//! suspended. Nothing here is fuzzy.

use crate::error::ShieldError;
use crate::plan::PlanReply;
use crate::public::PublicValues;
use crate::schema::{DatasetName, Lang, Param, ParamType, Schema};
use crate::sql::{validate, validate_check, ErrorClass, MethodError};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

/// The file format version.
const FILE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodStatus {
    Active,
    /// `reason` is an error class and the cloud name, or `replaced by vN`.
    Suspended {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedMethod {
    pub id: String,
    pub version: u32,
    pub dataset: DatasetName,
    pub lang: Lang,
    pub template_key: String,
    pub param_tags: Vec<String>,
    pub reply: PlanReply,
    pub preview_sha256: String,
    pub approved_by: String,
    pub approved_at: String,
    /// Credential label and sign count, from plan 48.
    pub touch: String,
    pub status: MethodStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MethodStore {
    pub methods: Vec<ApprovedMethod>,
}

#[derive(Serialize, Deserialize)]
struct FileForm {
    v: u32,
    methods: Vec<ApprovedMethod>,
}

/// `m-<slug>-v<n>`; the slug is the first 4 words of the key, ASCII
/// lowercased, characters outside `[a-z0-9]` dropped, empty words skipped.
pub fn method_id(key: &str, version: u32) -> String {
    let words: Vec<String> = key
        .split_whitespace()
        .map(|w| {
            w.chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .map(|c| c.to_ascii_lowercase())
                .collect::<String>()
        })
        .filter(|w| !w.is_empty())
        .take(4)
        .collect();
    format!("m-{}-v{}", words.join("-"), version)
}

fn same_slot(m: &ApprovedMethod, ds: &DatasetName, lang: Lang, key: &str, tags: &[String]) -> bool {
    m.dataset == *ds && m.lang == lang && m.template_key == key && m.param_tags == tags
}

fn tag_param(i: usize, tag: &str, schema: &Schema) -> Result<Param, MethodError> {
    let bad = || MethodError {
        class: ErrorClass::Syntax,
        detail: None,
    };
    let ty = if let Some(t) = tag.strip_prefix("entity:") {
        let spec = schema.entity_for(t).ok_or_else(|| MethodError {
            class: ErrorClass::UnknownTable,
            detail: Some(t.chars().take(120).collect()),
        })?;
        ParamType::Entity {
            table: t.to_string(),
            word: spec.word.clone(),
        }
    } else if let Some(r) = tag.strip_prefix("text:") {
        let (t, c) = r.split_once('.').ok_or_else(bad)?;
        ParamType::Text {
            table: t.to_string(),
            column: c.to_string(),
        }
    } else {
        match tag {
            "amount" => ParamType::Amount,
            "integer" => ParamType::Integer,
            "percent" => ParamType::Percent,
            "date" => ParamType::Date,
            "date_range" => ParamType::DateRange,
            _ => return Err(bad()),
        }
    };
    Ok(Param {
        name: format!("p{}", i + 1),
        ty,
        bound: None,
        display: String::new(),
    })
}

fn revalidate_one(
    m: &ApprovedMethod,
    schema: &Schema,
    public: &[PublicValues],
) -> Result<(), MethodError> {
    let params: Vec<Param> = m
        .param_tags
        .iter()
        .enumerate()
        .map(|(i, t)| tag_param(i, t, schema))
        .collect::<Result<_, _>>()?;
    validate(&m.reply.method, schema, public, &params)?;
    for c in &m.reply.checks {
        validate_check(c, schema, public, &params)?;
    }
    Ok(())
}

fn io_err(what: &'static str) -> ShieldError {
    ShieldError::Io(what.to_string())
}

impl MethodStore {
    /// A missing file is an empty store; a corrupt or unknown-version file
    /// is a fixed-text error (serde's text can quote content).
    pub fn load(path: &Path) -> Result<MethodStore, ShieldError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(MethodStore::default()),
            Err(_) => return Err(io_err("could not read the methods file")),
        };
        let f: FileForm = serde_json::from_slice(&bytes)
            .map_err(|_| ShieldError::Corrupt("the methods file is not valid"))?;
        if f.v != FILE_VERSION {
            return Err(ShieldError::Corrupt(
                "the methods file has an unknown version",
            ));
        }
        Ok(MethodStore { methods: f.methods })
    }

    /// Temp file in the same directory, fsync, rename over the target, fsync
    /// the directory; mode 0600 on unix.
    pub fn save(&self, path: &Path) -> Result<(), ShieldError> {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        let name = path
            .file_name()
            .ok_or_else(|| io_err("the methods path has no file name"))?;
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(format!(".tmp{}", std::process::id()));
        let tmp = dir.join(tmp_name);
        let body = serde_json::to_vec_pretty(&FileForm {
            v: FILE_VERSION,
            methods: self.methods.clone(),
        })
        .map_err(|_| io_err("could not encode the methods file"))?;
        let write = || -> std::io::Result<()> {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(&body)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, path)?;
            #[cfg(unix)]
            {
                std::fs::File::open(dir)?.sync_all()?;
            }
            Ok(())
        };
        write().map_err(|_| {
            let _ = std::fs::remove_file(&tmp);
            io_err("could not write the methods file")
        })
    }

    /// R45-11: equal dataset, language, template key and ordered param tags;
    /// Active only.
    pub fn find(
        &self,
        ds: &DatasetName,
        lang: Lang,
        key: &str,
        tags: &[String],
    ) -> Option<&ApprovedMethod> {
        self.methods
            .iter()
            .find(|m| m.status == MethodStatus::Active && same_slot(m, ds, lang, key, tags))
    }

    /// A method for a key and tags that already has one gets the next
    /// version (id from [`method_id`]); the older Active one is kept as
    /// history, suspended `replaced by vN`.
    pub fn add(&mut self, mut m: ApprovedMethod) -> &ApprovedMethod {
        let max = self
            .methods
            .iter()
            .filter(|o| same_slot(o, &m.dataset, m.lang, &m.template_key, &m.param_tags))
            .map(|o| o.version)
            .max();
        if let Some(max) = max {
            let v = max.saturating_add(1);
            m.version = v;
            for o in self.methods.iter_mut() {
                if o.status == MethodStatus::Active
                    && same_slot(o, &m.dataset, m.lang, &m.template_key, &m.param_tags)
                {
                    o.status = MethodStatus::Suspended {
                        reason: format!("replaced by v{v}"),
                    };
                }
            }
        }
        m.id = method_id(&m.template_key, m.version);
        self.methods.push(m);
        &self.methods[self.methods.len() - 1]
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let n = self.methods.len();
        self.methods.retain(|m| m.id != id);
        self.methods.len() != n
    }

    /// Spec §2.1.1, on every refresh: re-validate each Active method (its
    /// method and every check, with params rebuilt from `param_tags`); a
    /// failure suspends it with `<class> <cloud name>`. Suspended methods
    /// are history and are not revalidated or reported.
    pub fn revalidate(
        &mut self,
        schema: &Schema,
        public: &[PublicValues],
    ) -> Vec<(String, Result<(), MethodError>)> {
        let mut out = Vec::new();
        for m in self.methods.iter_mut() {
            if m.status != MethodStatus::Active {
                continue;
            }
            let r = revalidate_one(m, schema, public);
            if let Err(e) = &r {
                let reason = match &e.detail {
                    Some(d) => format!("{} {}", e.class.as_str(), d),
                    None => e.class.as_str().to_string(),
                };
                m.status = MethodStatus::Suspended { reason };
            }
            out.push((m.id.clone(), r));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::SelfCheck;
    use crate::schema::{ColType, ColumnClass, ColumnInfo, EntitySpec, TableInfo};

    fn col(name: &str, ty: ColType, class: ColumnClass) -> ColumnInfo {
        ColumnInfo {
            name: name.into(),
            ty,
            class,
            alias: None,
        }
    }

    fn schema(with_status: bool) -> Schema {
        use ColType::*;
        use ColumnClass::*;
        let mut inv = vec![
            col("id", Integer, Identifier),
            col("customer_id", Integer, Identifier),
            col("amount", Real, Sensitive),
        ];
        if with_status {
            inv.push(col("status", Text, Public));
        }
        Schema {
            dataset: "crm".parse().unwrap(),
            tables: vec![
                TableInfo {
                    name: "customers".into(),
                    alias: None,
                    rows: 500,
                    columns: vec![col("id", Integer, Identifier), col("city", Text, Quasi)],
                },
                TableInfo {
                    name: "invoices".into(),
                    alias: None,
                    rows: 5000,
                    columns: inv,
                },
            ],
            entities: vec![EntitySpec {
                table: "customers".into(),
                key: "id".into(),
                names: vec![],
                show: vec![],
                word: "customer".into(),
                word_da: "kunde".into(),
            }],
        }
    }

    fn public() -> Vec<PublicValues> {
        vec![PublicValues {
            column: "invoices.status".into(),
            passing: vec!["open".into(), "paid".into()],
            total_distinct: 3,
        }]
    }

    const SQL: &str = "SELECT COUNT(*) AS n FROM invoices i JOIN customers c ON c.id = i.customer_id WHERE c.id = :p1 AND i.status = 'open'";

    fn method(key: &str, tags: &[&str], lang: Lang) -> ApprovedMethod {
        ApprovedMethod {
            id: String::new(),
            version: 1,
            dataset: "crm".parse().unwrap(),
            lang,
            template_key: key.into(),
            param_tags: tags.iter().map(|s| s.to_string()).collect(),
            reply: PlanReply {
                method: SQL.into(),
                template: "{int(n)}".into(),
                checks: vec![SelfCheck::RowsBetween { min: 0, max: 1 }],
                intent: "count".into(),
                needs_judgment: false,
            },
            preview_sha256: "ab".into(),
            approved_by: "boss".into(),
            approved_at: "2026-11-17T10:00:00Z".into(),
            touch: "key-1 #3".into(),
            status: MethodStatus::Active,
        }
    }

    fn tags(t: &[&str]) -> Vec<String> {
        t.iter().map(|s| s.to_string()).collect()
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("p45-t6-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn exact_match_only() {
        let mut s = MethodStore::default();
        s.add(method(
            "balance of a customer",
            &["entity:customers", "date"],
            Lang::En,
        ));
        let ds: DatasetName = "crm".parse().unwrap();
        let t = tags(&["entity:customers", "date"]);
        assert!(s.find(&ds, Lang::En, "balance of a customer", &t).is_some());
        let swapped = tags(&["date", "entity:customers"]);
        assert!(s
            .find(&ds, Lang::En, "balance of a customer", &swapped)
            .is_none());
        assert!(s.find(&ds, Lang::Da, "balance of a customer", &t).is_none());
        assert!(s
            .find(&ds, Lang::En, "balance of a customer now", &t)
            .is_none());
        assert!(s.find(&ds, Lang::En, "Balance of a customer", &t).is_none());
        let other: DatasetName = "hr".parse().unwrap();
        assert!(s
            .find(&other, Lang::En, "balance of a customer", &t)
            .is_none());
    }

    #[test]
    fn revalidate_suspends() {
        let mut s = MethodStore::default();
        s.add(method("count open", &["entity:customers"], Lang::En));
        let r = s.revalidate(&schema(true), &public());
        assert_eq!(r.len(), 1);
        assert!(r[0].1.is_ok(), "{:?}", r[0].1);
        assert_eq!(s.methods[0].status, MethodStatus::Active);
        let r = s.revalidate(&schema(false), &public());
        let e = r[0].1.as_ref().unwrap_err();
        assert_eq!(e.class, ErrorClass::UnknownColumn);
        match &s.methods[0].status {
            MethodStatus::Suspended { reason } => {
                assert!(reason.starts_with("unknown_column "), "{reason}");
                assert!(reason.contains("status"), "{reason}");
            }
            o => panic!("{o:?}"),
        }
        let ds: DatasetName = "crm".parse().unwrap();
        assert!(s
            .find(&ds, Lang::En, "count open", &tags(&["entity:customers"]))
            .is_none());
        // Suspended methods are not revalidated again.
        assert!(s.revalidate(&schema(true), &public()).is_empty());
    }

    #[test]
    fn revalidate_unknown_entity_table_and_bad_tag() {
        let mut s = MethodStore::default();
        s.add(method("a", &["entity:ghosts"], Lang::En));
        s.add(method("b", &["bogus"], Lang::En));
        let r = s.revalidate(&schema(true), &public());
        assert_eq!(r[0].1.as_ref().unwrap_err().class, ErrorClass::UnknownTable);
        assert_eq!(r[1].1.as_ref().unwrap_err().class, ErrorClass::Syntax);
        match &s.methods[0].status {
            MethodStatus::Suspended { reason } => assert_eq!(reason, "unknown_table ghosts"),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn versions() {
        assert_eq!(
            method_id("Balance of a customer today", 1),
            "m-balance-of-a-customer-v1"
        );
        let mut s = MethodStore::default();
        let t = ["entity:customers"];
        let id1 = s.add(method("balance of a", &t, Lang::En)).id.clone();
        assert_eq!(id1, "m-balance-of-a-v1");
        let m2 = s.add(method("balance of a", &t, Lang::En));
        assert_eq!(m2.id, "m-balance-of-a-v2");
        assert_eq!(m2.version, 2);
        assert_eq!(s.methods.len(), 2);
        assert_eq!(
            s.methods[0].status,
            MethodStatus::Suspended {
                reason: "replaced by v2".into()
            }
        );
        let ds: DatasetName = "crm".parse().unwrap();
        assert_eq!(
            s.find(&ds, Lang::En, "balance of a", &tags(&t)).unwrap().id,
            "m-balance-of-a-v2"
        );
        assert!(s.remove("m-balance-of-a-v1"));
        assert!(!s.remove("m-balance-of-a-v1"));
    }

    #[test]
    fn ids_never_panic_on_unicode() {
        assert_eq!(method_id("İ ß K\u{212A} 😀 x", 3), "m-k-x-v3");
        assert_eq!(method_id("  ", 1), "m--v1");
        assert_eq!(
            method_id("hvad skylder æ ø å kunde", 2),
            "m-hvad-skylder-kunde-v2"
        );
    }

    #[test]
    fn save_is_atomic_and_0600() {
        let d = scratch("save");
        let p = d.join("methods.json");
        assert_eq!(MethodStore::load(&p).unwrap(), MethodStore::default());
        let mut s = MethodStore::default();
        s.add(method("balance of a", &["entity:customers"], Lang::Da));
        s.save(&p).unwrap();
        assert_eq!(MethodStore::load(&p).unwrap(), s);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"v\": 1"));
        // Overwrite works and keeps the mode.
        s.save(&p).unwrap();
        // Corrupt and unknown-version files give fixed text.
        std::fs::write(&p, "{\"v\":1,\"methods\":[{\"secret-cell\":1}]}").unwrap();
        let e = MethodStore::load(&p).unwrap_err().to_string();
        assert!(!e.contains("secret-cell"), "{e}");
        std::fs::write(&p, "{\"v\":9,\"methods\":[]}").unwrap();
        assert!(MethodStore::load(&p).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
