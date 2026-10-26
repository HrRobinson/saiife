//! The effective policy and its hash (spec §8.1, last paragraph).

use crate::project::Merged;
use crate::system::SystemConfig;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackInfo {
    pub id: String,
    pub version: u32,
    pub default_on: bool,
}

/// The pack locked mode always turns on.
pub const LOCK_PACK: &str = "core.lock";

/// Default-on packs, plus `core.lock` when `locked = true` (and the catalog
/// has it), plus `[guard] packs`, plus project packs, sorted by id.
/// Unknown ids produce a warning each and are skipped.
pub fn active_packs(
    cfg: &SystemConfig,
    catalog: &[PackInfo],
    project: Option<&Merged>,
) -> (Vec<PackInfo>, Vec<String>) {
    let mut ids: BTreeSet<&str> = catalog
        .iter()
        .filter(|p| p.default_on)
        .map(|p| p.id.as_str())
        .collect();
    // Locked mode protects saiife's own install (spec §6.17).
    if cfg.locked && catalog.iter().any(|p| p.id == LOCK_PACK) {
        ids.insert(LOCK_PACK);
    }
    let mut warnings = Vec::new();
    let requested = cfg
        .guard
        .packs
        .iter()
        .chain(project.into_iter().flat_map(|m| m.packs.iter()));
    for id in requested {
        if catalog.iter().any(|p| &p.id == id) {
            ids.insert(id.as_str());
        } else {
            let w = format!("unknown pack {id} skipped");
            if !warnings.contains(&w) {
                warnings.push(w);
            }
        }
    }
    let packs = ids
        .into_iter()
        .filter_map(|id| catalog.iter().find(|p| p.id == id).cloned())
        .collect();
    (packs, warnings)
}

/// `{"saiife_policy":1,"system":…,"packs":[{"id","version"}],"project":…|null}`.
/// Durations in `system` are whole seconds; `project` leaves out the notes.
pub fn effective_policy(cfg: &SystemConfig, packs: &[PackInfo], project: Option<&Merged>) -> Value {
    // Plain data with string keys: serialization cannot fail.
    let system = serde_json::to_value(cfg).unwrap_or(Value::Null);
    let project = project
        .map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    let packs: Vec<Value> = packs
        .iter()
        .map(|p| json!({"id": p.id, "version": p.version}))
        .collect();
    json!({
        "saiife_policy": 1,
        "system": system,
        "packs": packs,
        "project": project,
    })
}

/// Compact JSON with object keys sorted recursively by byte order. Sorting is
/// explicit: `serde_json` is built with `preserve_order` in this workspace.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (k, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_canonical(val, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::String(s) => write_string(s, out),
        // null, bools and numbers have one compact form.
        other => out.push_str(&other.to_string()),
    }
}

fn write_string(s: &str, out: &mut String) {
    // serde_json's string escaping; a &str always serializes.
    out.push_str(&serde_json::to_string(s).unwrap_or_default());
}

/// `"sha256:" + hex(sha256(canonical_json(v)))`.
pub fn policy_hash(v: &Value) -> String {
    let digest = Sha256::digest(canonical_json(v).as_bytes());
    let mut out = String::from("sha256:");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::{merge_project, parse_project, Mode};

    fn catalog() -> Vec<PackInfo> {
        let p = |id: &str, version, default_on| PackInfo {
            id: id.into(),
            version,
            default_on,
        };
        vec![
            p("core.git", 1, true),
            p("core.filesystem", 1, true),
            p("db.postgres", 2, false),
            p("db.mysql", 1, false),
        ]
    }

    const CFG_A: &str = "version = 2\nlocked = true\n\
        [guard]\npacks = [\"db.postgres\"]\n\
        [audit]\ncheckpoint_interval = \"15m\"\n[audit.forward.siem]\ntype = \"syslog\"\naddress = \"x\"\n\
        [[scope]]\nname = \"s\"\nusers = [\"u\"]\nenv = \"prod\"\n\
        [services.shopify]\nconnector = \"shopify\"\nallow = [\"a\"]\n";
    const CFG_B: &str = "[services.shopify]\nallow = [\"a\"]\nconnector = \"shopify\"\n\
        [[scope]]\nenv = \"prod\"\nusers = [\"u\"]\nname = \"s\"\n\
        [audit.forward.siem]\naddress = \"x\"\ntype = \"syslog\"\n\
        [guard]\npacks = [\"db.postgres\"]\n\
        [audit]\ncheckpoint_interval = \"15m\"\n";

    fn cfg(text: &str) -> SystemConfig {
        toml::from_str(text).unwrap()
    }

    fn hash_of(c: &SystemConfig, cat: &[PackInfo], m: Option<&Merged>) -> String {
        let (packs, _) = active_packs(c, cat, m);
        policy_hash(&effective_policy(c, &packs, m))
    }

    #[test]
    fn canonical_json_is_exact() {
        let v: Value = serde_json::from_str(r#"{"b":{"d":1,"c":[{"z":0,"y":1}]},"a":""}"#).unwrap();
        assert_eq!(
            canonical_json(&v),
            r#"{"a":"","b":{"c":[{"y":1,"z":0}],"d":1}}"#
        );
    }

    #[test]
    fn canonical_json_escapes_and_sorts_by_bytes() {
        let v: Value =
            serde_json::from_str(r#"{"é":1,"Z":"a\"b\n","a":[true,null,-1.5]}"#).unwrap();
        assert_eq!(
            canonical_json(&v),
            "{\"Z\":\"a\\\"b\\n\",\"a\":[true,null,-1.5],\"é\":1}"
        );
    }

    #[test]
    fn policy_hash_format() {
        let h = policy_hash(&Value::Null);
        // sha256("null")
        assert_eq!(
            h,
            "sha256:74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"
        );
    }

    #[test]
    fn effective_policy_shape() {
        let c = cfg("version = 2\n");
        let (packs, w) = active_packs(&c, &catalog(), None);
        assert!(w.is_empty());
        let v = effective_policy(&c, &packs, None);
        assert_eq!(v["saiife_policy"], 1);
        assert_eq!(v["project"], Value::Null);
        assert_eq!(v["system"]["audit"]["checkpoint_interval"], 900);
        assert_eq!(v["system"]["approval"]["timeout"], 1800);
        assert_eq!(v["system"]["guard"]["fail"], "closed");
        assert_eq!(
            v["packs"],
            serde_json::json!([{"id":"core.filesystem","version":1},{"id":"core.git","version":1}])
        );
    }

    #[test]
    fn active_packs_union_sorted() {
        let c = cfg("version = 2\n[guard]\npacks = [\"db.postgres\", \"core.git\"]\n");
        let p = parse_project(b"version = 2\npacks = [\"db.mysql\"]\n").unwrap();
        let m = merge_project(&c.guard.packs, &p, Mode::Locked);
        let (packs, w) = active_packs(&c, &catalog(), Some(&m));
        let ids: Vec<_> = packs.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["core.filesystem", "core.git", "db.mysql", "db.postgres"]
        );
        assert!(w.is_empty());
    }

    #[test]
    fn hash_ignores_toml_order() {
        let a = cfg(CFG_A);
        let b = cfg(&format!("locked = true\nversion = 2\n{CFG_B}"));
        assert_eq!(a, b);
        assert_eq!(hash_of(&a, &catalog(), None), hash_of(&b, &catalog(), None));
    }

    #[test]
    fn hash_changes_with_pack_version() {
        let c = cfg(CFG_A);
        let mut cat = catalog();
        let before = hash_of(&c, &cat, None);
        cat.iter_mut()
            .find(|p| p.id == "db.postgres")
            .unwrap()
            .version = 3;
        assert_ne!(before, hash_of(&c, &cat, None));
    }

    #[test]
    fn hash_changes_with_project_deny() {
        let c = cfg(CFG_A);
        let p1 = parse_project(b"version = 2\n[services.shopify]\ndeny = [\"a\"]\n").unwrap();
        let p2 =
            parse_project(b"version = 2\n[services.shopify]\ndeny = [\"a\", \"b\"]\n").unwrap();
        let m1 = merge_project(&c.guard.packs, &p1, Mode::Locked);
        let m2 = merge_project(&c.guard.packs, &p2, Mode::Locked);
        assert_ne!(
            hash_of(&c, &catalog(), Some(&m1)),
            hash_of(&c, &catalog(), Some(&m2))
        );
        assert_ne!(
            hash_of(&c, &catalog(), None),
            hash_of(&c, &catalog(), Some(&m1))
        );
    }

    #[test]
    fn policy_hash_changes_with_service() {
        let a = cfg(CFG_A);
        let b = cfg(&CFG_A.replace("allow = [\"a\"]", "allow = [\"b\"]"));
        assert_ne!(a, b);
        assert_ne!(hash_of(&a, &catalog(), None), hash_of(&b, &catalog(), None));
        // Secrets and limits are part of the hash too.
        let c = cfg(&format!(
            "{CFG_A}[secrets.k]\nrun_allow = [\"/usr/bin/curl\"]\n"
        ));
        assert_ne!(hash_of(&a, &catalog(), None), hash_of(&c, &catalog(), None));
        let d = cfg(&format!(
            "{CFG_A}[services.shopify.limits]\nrequests_per_minute = 1\n"
        ));
        assert_ne!(hash_of(&a, &catalog(), None), hash_of(&d, &catalog(), None));
    }

    #[test]
    fn notes_do_not_change_hash() {
        let c = cfg(CFG_A);
        let p = parse_project(b"version = 2\n[services.shopify]\ndeny = [\"a\"]\n").unwrap();
        let m1 = merge_project(&c.guard.packs, &p, Mode::Locked);
        let mut m2 = m1.clone();
        m2.notes.push("something".into());
        assert_eq!(
            hash_of(&c, &catalog(), Some(&m1)),
            hash_of(&c, &catalog(), Some(&m2))
        );
    }

    #[test]
    fn unknown_pack_is_warning() {
        let c = cfg("version = 2\n[guard]\npacks = [\"db.oracle\"]\n");
        let (packs, w) = active_packs(&c, &catalog(), None);
        assert_eq!(packs.len(), 2);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("db.oracle"), "{w:?}");
    }

    #[test]
    fn locked_adds_core_lock() {
        let mut cat = catalog();
        cat.push(PackInfo {
            id: "core.lock".into(),
            version: 1,
            default_on: false,
        });
        let ids = |text: &str, cat: &[PackInfo]| -> Vec<String> {
            let (packs, w) = active_packs(&cfg(text), cat, None);
            assert!(w.is_empty(), "{w:?}");
            packs.into_iter().map(|p| p.id).collect()
        };
        assert!(ids("version = 2\nlocked = true\n", &cat).contains(&"core.lock".to_string()));
        assert!(!ids("version = 2\nlocked = false\n", &cat).contains(&"core.lock".to_string()));
        assert!(!ids("version = 2\n", &cat).contains(&"core.lock".to_string()));
        // A catalog without it: nothing is added, and no warning.
        assert!(!ids("version = 2\nlocked = true\n", &catalog()).contains(&"core.lock".to_string()));
    }
}
