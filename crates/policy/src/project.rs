//! Project config `.saiife/config.toml` (spec §8.2) and its add-only merge.

use crate::load::PolicyError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct ServiceOverlay {
    pub allow: Vec<String>,
    pub ask: Vec<String>,
    pub deny: Vec<String>,
}

/// A parsed project config. Unknown keys are ignored, as in v1: the project
/// config holds no authority in locked mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ProjectOverlay {
    /// 1 when absent, as in developer mode.
    #[serde(default = "version_1")]
    pub version: i64,
    #[serde(default)]
    pub packs: Vec<String>,
    #[serde(default)]
    pub env: Option<String>,
    /// Kept only so the locked merge can say it was ignored.
    #[serde(default)]
    pub locked: Option<bool>,
    #[serde(default)]
    pub services: BTreeMap<String, ServiceOverlay>,
}

fn version_1() -> i64 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Developer,
    Locked,
}

/// The project's contribution after the merge. `notes` say what was dropped
/// and are not part of the effective policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Merged {
    pub packs: Vec<String>,
    pub services: BTreeMap<String, ServiceOverlay>,
    #[serde(skip)]
    pub notes: Vec<String>,
}

/// Parses a project config; versions 1 and 2 are accepted.
pub fn parse_project(bytes: &[u8]) -> Result<ProjectOverlay, PolicyError> {
    let path = PathBuf::from(PROJECT_CONFIG);
    let text = std::str::from_utf8(bytes).map_err(|_| PolicyError::Parse {
        path: path.clone(),
        detail: "not valid UTF-8".to_string(),
    })?;
    let p: ProjectOverlay = toml::from_str(text).map_err(|e| PolicyError::Parse {
        path: path.clone(),
        detail: e.to_string(),
    })?;
    if !matches!(p.version, 1 | 2) {
        return Err(PolicyError::Invalid {
            path,
            detail: format!("version must be 1 or 2, found {}", p.version),
        });
    }
    Ok(p)
}

/// The path errors from [`parse_project`] name (relative to the project).
const PROJECT_CONFIG: &str = ".saiife/config.toml";

/// Appends the items of `add` not yet in `into`, keeping order.
fn extend_unique(into: &mut Vec<String>, add: &[String]) {
    for x in add {
        if !into.contains(x) {
            into.push(x.clone());
        }
    }
}

fn dedup(v: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    extend_unique(&mut out, v);
    out
}

/// System packs plus project packs (a project never removes one). In
/// `Locked` mode the project's `allow` lists, `env` and `locked` are dropped,
/// each with a note. Every list is deduplicated, first occurrence kept.
pub fn merge_project(system_packs: &[String], p: &ProjectOverlay, mode: Mode) -> Merged {
    let locked = mode == Mode::Locked;
    let mut notes = Vec::new();
    let mut packs = dedup(system_packs);
    extend_unique(&mut packs, &p.packs);

    let mut services = BTreeMap::new();
    for (name, s) in &p.services {
        let allow = if locked {
            if !s.allow.is_empty() {
                notes.push(format!("allow for {name} ignored in locked mode"));
            }
            Vec::new()
        } else {
            dedup(&s.allow)
        };
        services.insert(
            name.clone(),
            ServiceOverlay {
                allow,
                ask: dedup(&s.ask),
                deny: dedup(&s.deny),
            },
        );
    }
    if locked {
        if p.env.is_some() {
            notes.push("env ignored in locked mode".to_string());
        }
        if p.locked.is_some() {
            notes.push("locked ignored in locked mode: only /etc decides".to_string());
        }
    }
    Merged {
        packs,
        services,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    const PROJECT: &str = "version = 2\npacks = []\nenv = \"dev\"\n\
        [services.shopify]\nallow = [\"x:read\"]\ndeny = [\"products:write\"]\nask = [\"y:write\"]\n";

    #[test]
    fn locked_merge_is_add_only() {
        let p = parse_project(PROJECT.as_bytes()).unwrap();
        let m = merge_project(&s(&["core.git", "db.postgres"]), &p, Mode::Locked);
        assert_eq!(m.packs, s(&["core.git", "db.postgres"]));
        let sh = &m.services["shopify"];
        assert!(sh.allow.is_empty());
        assert_eq!(sh.deny, s(&["products:write"]));
        assert_eq!(sh.ask, s(&["y:write"]));
        assert_eq!(m.notes.len(), 2, "{:?}", m.notes);
        assert!(
            m.notes
                .iter()
                .any(|n| n == "allow for shopify ignored in locked mode"),
            "{:?}",
            m.notes
        );
        assert!(m.notes.iter().any(|n| n.contains("env")), "{:?}", m.notes);
    }

    #[test]
    fn locked_merge_adds_packs_and_dedups() {
        let p = parse_project(
            b"version = 2\npacks = [\"db.postgres\", \"x\", \"x\"]\nlocked = false\n\
              [services.a]\ndeny = [\"d\", \"d\", \"e\"]\n",
        )
        .unwrap();
        let m = merge_project(
            &s(&["core.git", "db.postgres", "core.git"]),
            &p,
            Mode::Locked,
        );
        assert_eq!(m.packs, s(&["core.git", "db.postgres", "x"]));
        assert_eq!(m.services["a"].deny, s(&["d", "e"]));
        assert_eq!(m.notes.len(), 1, "{:?}", m.notes);
        assert!(m.notes[0].contains("locked"));
    }

    #[test]
    fn developer_merge_keeps_allow() {
        let p = parse_project(PROJECT.as_bytes()).unwrap();
        let m = merge_project(&s(&["core.git"]), &p, Mode::Developer);
        assert_eq!(m.services["shopify"].allow, s(&["x:read"]));
        assert!(m.notes.is_empty(), "{:?}", m.notes);
    }

    #[test]
    fn v1_file_parses() {
        let p = parse_project(b"version = 1\npacks = [\"db.postgres\"]\nlocked = false\n").unwrap();
        assert_eq!(p.version, 1);
        assert_eq!(p.packs, s(&["db.postgres"]));
        assert_eq!(p.locked, Some(false));
    }

    /// No `version` means 1, as in developer mode (I3): the packs count in
    /// the locked merge.
    #[test]
    fn missing_version_defaults_to_1() {
        let p = parse_project(b"packs = [\"db.postgres\"]\n").unwrap();
        assert_eq!(p.version, 1);
        let m = merge_project(&s(&["core.git"]), &p, Mode::Locked);
        assert_eq!(m.packs, s(&["core.git", "db.postgres"]));
    }

    #[test]
    fn unknown_keys_ignored_bad_version_rejected() {
        let p = parse_project(
            b"version = 2\nwhatever = 1\n[guard]\nx = 1\n[services.s]\nsecret = \"k\"\n",
        )
        .unwrap();
        assert_eq!(p.services["s"], ServiceOverlay::default());
        assert!(matches!(
            parse_project(b"version = 3\n"),
            Err(PolicyError::Invalid { .. })
        ));
        assert!(matches!(
            parse_project(b"version = [\n"),
            Err(PolicyError::Parse { .. })
        ));
        assert!(matches!(
            parse_project(b"\xff\xfe"),
            Err(PolicyError::Parse { .. })
        ));
    }
}
