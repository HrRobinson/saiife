//! Plan 45: approved methods and their strict reuse rule (R45-11, spec
//! §2.3.5). A method approved by a user with the approver role plus a touch
//! (recorded by plan 48) is reused only for the same dataset, language,
//! question template key and parameter type tags; every dataset refresh
//! re-validates each stored method, and one that no longer validates is
//! suspended. Nothing here is fuzzy.

use crate::dataset::replace_private_part;
use crate::error::ShieldError;
use crate::plan::PlanReply;
use crate::public::PublicValues;
use crate::schema::{DatasetName, Lang, Param, ParamType, Schema};
use crate::sql::{validate, validate_check, ErrorClass, MethodError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    /// The keyed MAC of the preview text the approver touched for (plan 48
    /// T3: HMAC-SHA256 under the dataset's index key, as the audit's
    /// `preview_mac`); never a bare hash, as the text holds the user's
    /// words.
    pub preview_mac: String,
    pub approved_by: String,
    pub approved_at: String,
    /// Credential label and sign count, from plan 48.
    pub touch: String,
    pub status: MethodStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MethodStore {
    pub methods: Vec<ApprovedMethod>,
    /// Plan 45 final review M1: the highest version ever issued per slug,
    /// kept after a `remove`, so an id is never issued twice (the audit
    /// names methods by id). Absent in older files (serde default).
    #[serde(default)]
    pub issued: BTreeMap<String, u32>,
}

#[derive(Serialize, Deserialize)]
struct FileForm {
    v: u32,
    methods: Vec<ApprovedMethod>,
    #[serde(default)]
    issued: BTreeMap<String, u32>,
}

/// `m-<slug>-v<n>`; the slug is the first 4 words of the key, ASCII
/// lowercased, characters outside `[a-z0-9]` dropped, empty words skipped.
pub fn method_id(key: &str, version: u32) -> String {
    format!("m-{}-v{}", slug(key), version)
}

fn slug(key: &str) -> String {
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
    words.join("-")
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
        Ok(MethodStore {
            methods: f.methods,
            issued: f.issued,
        })
    }

    /// Written through the shared private-file protocol (dataset.rs): the
    /// directory is ours and 0700, the part file is created new, 0600 and
    /// never through a symlink, fsynced, then renamed over the target (a
    /// planted symlink at the part or final path refuses), and the directory
    /// is fsynced.
    pub fn save(&self, path: &Path) -> Result<(), ShieldError> {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => return Err(io_err("the methods path needs a directory")),
        };
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| io_err("the methods path has no file name"))?;
        let body = serde_json::to_vec_pretty(&FileForm {
            v: FILE_VERSION,
            methods: self.methods.clone(),
            issued: self.issued.clone(),
        })
        .map_err(|_| io_err("could not encode the methods file"))?;
        replace_private_part(dir, name, |part| {
            std::fs::write(part, &body).map_err(|_| io_err("could not write the methods file"))
        })
        .map(|_| ())
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
        // Ids are unique by construction: n is one more than the highest
        // version ever issued for the slug: among every stored method with
        // the same slug (any slot, any status) and the high-water mark that
        // survives a `remove` (M1).
        let sl = slug(&m.template_key);
        let max = self
            .methods
            .iter()
            .filter(|o| slug(&o.template_key) == sl)
            .map(|o| o.version)
            .chain(self.issued.get(&sl).copied())
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
        let hw = self.issued.entry(sl).or_insert(0);
        *hw = (*hw).max(m.version);
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
    /// failure suspends it with `<class> <cloud name>`. Only methods of
    /// `schema.dataset` are touched (the store may hold several datasets). Suspended methods
    /// are history and are not revalidated or reported.
    pub fn revalidate(
        &mut self,
        schema: &Schema,
        public: &[PublicValues],
    ) -> Vec<(String, Result<(), MethodError>)> {
        let mut out = Vec::new();
        for m in self.methods.iter_mut() {
            if m.status != MethodStatus::Active || m.dataset != schema.dataset {
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
            joins: vec![],
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
                context: vec![],
            },
            preview_mac: "ab".into(),
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
    fn removed_ids_are_never_reissued() {
        let mut s = MethodStore::default();
        let t = ["entity:customers"];
        s.add(method("balance of a", &t, Lang::En));
        let v2 = s.add(method("balance of a", &t, Lang::En)).id.clone();
        assert_eq!(v2, "m-balance-of-a-v2");
        // Removing the highest version does not free its id.
        assert!(s.remove(&v2));
        let v3 = s.add(method("balance of a", &t, Lang::En)).id.clone();
        assert_eq!(v3, "m-balance-of-a-v3");
        // Removing every method keeps the mark too, also across a save and
        // a load.
        assert!(s.remove("m-balance-of-a-v1"));
        assert!(s.remove(&v3));
        assert!(s.methods.is_empty());
        let dir = scratch("issued");
        let path = dir.join("methods.json");
        s.save(&path).unwrap();
        let mut back = MethodStore::load(&path).unwrap();
        assert_eq!(back, s);
        let v4 = back.add(method("balance of a", &t, Lang::En)).id.clone();
        assert_eq!(v4, "m-balance-of-a-v4");
        // A file without the mark (written before M1) still loads.
        std::fs::write(&path, br#"{"v":1,"methods":[]}"#).unwrap();
        let old = MethodStore::load(&path).unwrap();
        assert!(old.issued.is_empty() && old.methods.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
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

    #[cfg(unix)]
    #[test]
    fn save_refuses_planted_symlinks() {
        use std::os::unix::fs::symlink;
        let d = scratch("symlink");
        let victim = d.join("victim.txt");
        std::fs::write(&victim, "keep me").unwrap();
        let dir = d.join("ds");
        std::fs::create_dir(&dir).unwrap();
        let p = dir.join("methods.json");
        let mut s = MethodStore::default();
        s.add(method("balance of a", &["entity:customers"], Lang::En));
        // A link at the temp paths (the helper's .part and the old pid name).
        symlink(&victim, dir.join("methods.json.part")).unwrap();
        symlink(
            &victim,
            dir.join(format!(".methods.json.tmp{}", std::process::id())),
        )
        .unwrap();
        assert!(s.save(&p).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
        std::fs::remove_file(dir.join("methods.json.part")).unwrap();
        // A link at the final path is refused, the target untouched.
        symlink(&victim, &p).unwrap();
        assert!(s.save(&p).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
        // A symlinked directory is refused.
        let link = d.join("dslink");
        symlink(&dir, &link).unwrap();
        assert!(s.save(&link.join("methods.json")).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn save_makes_the_dir_private_and_keeps_no_part() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("dirmode");
        let dir = d.join("ds");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = dir.join("methods.json");
        let mut s = MethodStore::default();
        s.add(method("balance of a", &["entity:customers"], Lang::En));
        s.save(&p).unwrap();
        s.save(&p).unwrap(); // a rewrite replaces the file
        let mode = |q: &std::path::Path| std::fs::metadata(q).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&p), 0o600);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert_eq!(MethodStore::load(&p).unwrap(), s);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn stale_part_does_not_block_save() {
        use std::os::unix::fs::symlink;
        let d = scratch("stale");
        let dir = d.join("ds");
        std::fs::create_dir(&dir).unwrap();
        let p = dir.join("methods.json");
        let mut s = MethodStore::default();
        s.add(method("balance of a", &["entity:customers"], Lang::En));
        std::fs::write(dir.join("methods.json.part"), "half").unwrap();
        s.save(&p).unwrap();
        assert_eq!(MethodStore::load(&p).unwrap(), s);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        // A symlink at the part path is still refused and left alone.
        let victim = d.join("victim.txt");
        std::fs::write(&victim, "keep me").unwrap();
        let part = dir.join("methods.json.part");
        symlink(&victim, &part).unwrap();
        assert!(s.save(&p).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
        assert!(std::fs::symlink_metadata(&part)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn save_refuses_a_bare_file_name() {
        let s = MethodStore::default();
        assert!(s.save(Path::new("methods.json")).is_err());
    }

    #[test]
    fn ids_are_unique_across_slots() {
        let mut s = MethodStore::default();
        let t = ["entity:customers"];
        let a = s.add(method("balance of a", &t, Lang::En)).id.clone();
        let b = s.add(method("balance of a", &t, Lang::Da)).id.clone();
        let c = s
            .add(method("balance of a", &["date"], Lang::En))
            .id
            .clone();
        let d = s
            .add(method("balance of a customer x", &t, Lang::En))
            .id
            .clone();
        let e = s
            .add(method("balance of a customer y", &t, Lang::En))
            .id
            .clone();
        let ids = [&a, &b, &c, &d, &e];
        for (i, x) in ids.iter().enumerate() {
            for y in &ids[i + 1..] {
                assert_ne!(x, y);
            }
        }
        assert_eq!(a, "m-balance-of-a-v1");
        // Same slot again: a higher version, old one suspended.
        let a2 = s.add(method("balance of a", &t, Lang::En));
        assert_eq!(a2.id, format!("m-balance-of-a-v{}", a2.version));
        assert!(a2.version > 1);
        assert!(s.remove(&b));
        assert_eq!(s.methods.len(), 5);
        assert!(!s.remove(&b));
    }

    #[test]
    fn revalidate_touches_only_its_dataset() {
        let mut s = MethodStore::default();
        s.add(method("count open", &["entity:customers"], Lang::En));
        let mut other = method("count open", &["entity:customers"], Lang::En);
        other.dataset = "hr".parse().unwrap();
        s.add(other);
        let r = s.revalidate(&schema(false), &public());
        assert_eq!(r.len(), 1);
        assert!(matches!(
            s.methods[0].status,
            MethodStatus::Suspended { .. }
        ));
        assert_eq!(s.methods[1].status, MethodStatus::Active);
    }
}
