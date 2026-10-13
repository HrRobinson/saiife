//! The project config `.saiife/config.toml` (spec §5.1).
//!
//! ```toml
//! version = 1
//! packs = ["core.filesystem", "core.git", "db.postgres"]
//! locked = false   # reserved for the v2 admin lock; v1 reads and ignores it
//! ```
//!
//! Default-on packs are always active; `packs` adds opt-in ones. Edited with
//! `toml_edit`, so a user's comments and edits survive `saiife init`.

use std::path::{Path, PathBuf};

use toml_edit::{Array, DocumentMut, Item};

use crate::{fsutil, AgentError, Change};

pub const CONFIG_REL: &str = ".saiife/config.toml";

/// What saiife reads from the project config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectConfig {
    /// `version`; 1 when absent.
    pub version: i64,
    /// `packs`, in file order. Ids are not checked here.
    pub packs: Vec<String>,
    /// `locked`: reserved (spec §9.1). Read so the field is known; v1
    /// ignores its value.
    pub locked: bool,
}

/// The nearest directory at or above `start` that contains
/// `.saiife/config.toml`.
pub fn find_project_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|d| d.join(CONFIG_REL).is_file())
        .map(Path::to_path_buf)
}

/// Read `<project>/.saiife/config.toml`.
pub fn load(project: &Path) -> Result<ProjectConfig, AgentError> {
    let path = project.join(CONFIG_REL);
    let text = std::fs::read_to_string(&path).map_err(fsutil::io_err(&path))?;
    let doc = parse(&path, &text)?;
    let packs = match doc.get("packs") {
        None => Vec::new(),
        Some(item) => item
            .as_array()
            .ok_or_else(|| layout(&path, "`packs` is not a list"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
    };
    Ok(ProjectConfig {
        version: doc.get("version").and_then(Item::as_integer).unwrap_or(1),
        packs,
        locked: doc.get("locked").and_then(Item::as_bool).unwrap_or(false),
    })
}

/// Make sure the config exists and lists `packs`. A missing file is created
/// listing exactly `packs`; an existing file only gets the ids it lacks
/// appended, keeping everything else as the user wrote it.
pub fn ensure(project: &Path, packs: &[String]) -> Result<Change, AgentError> {
    let path = project.join(CONFIG_REL);
    let Some(text) = fsutil::read_optional(&path)? else {
        return fsutil::write(project, CONFIG_REL, &new_file(packs));
    };
    let mut doc = parse(&path, &text)?;
    let list = doc
        .entry("packs")
        .or_insert_with(|| Item::Value(Array::new().into()))
        .as_array_mut()
        .ok_or_else(|| layout(&path, "`packs` is not a list"))?;
    let mut added = false;
    for id in packs {
        if !list.iter().any(|v| v.as_str() == Some(id)) {
            list.push(id.as_str());
            added = true;
        }
    }
    if !added {
        return Ok(Change::Unchanged);
    }
    fsutil::write(project, CONFIG_REL, &doc.to_string())
}

fn new_file(packs: &[String]) -> String {
    let list: Vec<String> = packs.iter().map(|p| format!("{p:?}")).collect();
    format!(
        "# saiife project config. Default-on packs are always active;\n\
         # list opt-in packs here to turn them on (`saiife packs` lists them).\n\
         version = 1\n\
         packs = [{}]\n\
         # Reserved for the admin lock (v2); saiife v1 reads and ignores it.\n\
         locked = false\n",
        list.join(", ")
    )
}

fn parse(path: &Path, text: &str) -> Result<DocumentMut, AgentError> {
    text.parse::<DocumentMut>().map_err(|e| AgentError::Parse {
        path: path.to_path_buf(),
        format: "TOML",
        detail: e.to_string().trim().replace('\n', " "),
    })
}

fn layout(path: &Path, detail: &str) -> AgentError {
    AgentError::Layout {
        path: path.to_path_buf(),
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn new_file_lists_packs_and_reserves_locked() {
        let p = tempfile::tempdir().unwrap();
        let c = ensure(p.path(), &ids(&["core.filesystem", "core.git"])).unwrap();
        assert_eq!(
            c,
            Change::Created {
                created_dirs: vec![".saiife".into()]
            }
        );
        let text = fs::read_to_string(p.path().join(CONFIG_REL)).unwrap();
        assert!(text.contains("packs = [\"core.filesystem\", \"core.git\"]\n"));
        assert!(text.contains("locked = false\n"));
        assert_eq!(
            load(p.path()).unwrap(),
            ProjectConfig {
                version: 1,
                packs: ids(&["core.filesystem", "core.git"]),
                locked: false
            }
        );
    }

    /// Review Focus 5: re-running init after hand edits keeps them.
    #[test]
    fn existing_file_keeps_user_edits_and_only_gains_missing_ids() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        let mine = "# team config\nversion = 1\npacks = [\"core.git\", \"db.mysql\"] # mysql for CI\nlocked = false\n";
        fs::write(p.path().join(CONFIG_REL), mine).unwrap();
        assert_eq!(
            ensure(p.path(), &ids(&["db.mysql"])).unwrap(),
            Change::Unchanged
        );
        assert_eq!(fs::read_to_string(p.path().join(CONFIG_REL)).unwrap(), mine);
        assert_eq!(
            ensure(p.path(), &ids(&["db.postgres"])).unwrap(),
            Change::Updated
        );
        let text = fs::read_to_string(p.path().join(CONFIG_REL)).unwrap();
        assert!(text.starts_with("# team config\n"), "{text}");
        assert!(text.contains("# mysql for CI"), "{text}");
        assert_eq!(
            load(p.path()).unwrap().packs,
            ids(&["core.git", "db.mysql", "db.postgres"])
        );
    }

    #[test]
    fn locked_is_read_but_reserved() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        fs::write(p.path().join(CONFIG_REL), "locked = true\n").unwrap();
        let c = load(p.path()).unwrap();
        assert!(c.locked);
        assert_eq!(c.version, 1);
        assert!(c.packs.is_empty());
    }

    #[test]
    fn bad_files_are_errors_not_rewrites() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        for bad in ["packs = \"db.mysql\"\n", "packs = [\n"] {
            fs::write(p.path().join(CONFIG_REL), bad).unwrap();
            assert!(load(p.path()).is_err(), "{bad:?}");
            assert!(ensure(p.path(), &ids(&["db.postgres"])).is_err(), "{bad:?}");
            assert_eq!(fs::read_to_string(p.path().join(CONFIG_REL)).unwrap(), bad);
        }
    }

    #[test]
    fn root_is_found_from_a_subdirectory() {
        let p = tempfile::tempdir().unwrap();
        ensure(p.path(), &ids(&["core.git"])).unwrap();
        let deep = p.path().join("src/nested/dir");
        assert_eq!(find_project_root(&deep), Some(p.path().to_path_buf()));
        assert_eq!(find_project_root(p.path()), Some(p.path().to_path_buf()));
        let other = tempfile::tempdir().unwrap();
        assert_eq!(find_project_root(other.path()), None);
    }
}
