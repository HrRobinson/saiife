//! Which packs a project turns on (spec §5.1, §9.1 precedence): default-on
//! packs always, plus the opt-in packs listed in the nearest
//! `.saiife/config.toml`, plus any `--pack` given on the command line.

use std::path::{Path, PathBuf};

use saiife_agents::config::{self, CONFIG_REL};
use saiife_agents::integrity::{self, Integrity};
use saiifeguard::Pack;

/// The saiife project `status`, `init` and `init --off` work on: the
/// nearest directory at or above `cwd` that holds `.saiife/config.toml` as a
/// file or has an integrity record on this machine; `cwd` if none does.
/// A project whose config was removed is still found by its record, so
/// `init` restores that project instead of re-baselining a parent's config
/// or starting a new project below it. A stray `.saiife/` with neither does
/// not count. (The hook's own lookup is config-only:
/// `config::find_project_root`.)
pub fn project_root(cwd: &Path) -> PathBuf {
    cwd.ancestors()
        .find(|d| {
            d.join(CONFIG_REL).is_file()
                || integrity::record_path(d)
                    .ok()
                    .flatten()
                    .is_some_and(|p| matches!(Integrity::load(&p), Ok(Some(_))))
        })
        .unwrap_or(cwd)
        .to_path_buf()
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProjectPacks {
    /// Directory holding `.saiife/config.toml`, if one was found.
    pub root: Option<PathBuf>,
    /// Known pack ids from the config, in file order.
    pub enabled: Vec<String>,
    /// Plain-language problems (unknown ids, unreadable config). Never fatal.
    pub warnings: Vec<String>,
}

/// Find the project config at or above `start` and read its packs. Unknown
/// pack ids are warned about and ignored.
pub fn project_packs(start: &Path, known: &[Pack]) -> ProjectPacks {
    project_packs_known(start, |id| known.iter().any(|p| p.id == id))
}

/// `project_packs` with `known` telling which pack ids exist.
pub fn project_packs_known(start: &Path, known: impl Fn(&str) -> bool) -> ProjectPacks {
    let Some(root) = config::find_project_root(start) else {
        return ProjectPacks::default();
    };
    let mut out = ProjectPacks {
        root: Some(root.clone()),
        ..Default::default()
    };
    match config::load(&root) {
        Ok(cfg) => {
            for id in cfg.packs {
                if known(&id) {
                    out.enabled.push(id);
                } else {
                    out.warnings.push(format!(
                        "unknown pack {id:?} in {}; ignored",
                        root.join(CONFIG_REL).display()
                    ));
                }
            }
        }
        Err(e) => out
            .warnings
            .push(format!("{e}; using the default packs only")),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiifeguard::builtins::builtin_packs;

    #[test]
    fn reads_known_packs_and_warns_about_unknown_ones() {
        let (known, _) = builtin_packs();
        let p = tempfile::tempdir().unwrap();
        std::fs::create_dir(p.path().join(".saiife")).unwrap();
        std::fs::write(
            p.path().join(CONFIG_REL),
            "packs = [\"core.git\", \"db.postgres\", \"db.oracle\"]\n",
        )
        .unwrap();
        let got = project_packs(&p.path().join("src"), &known);
        assert_eq!(got.root.as_deref(), Some(p.path()));
        assert_eq!(got.enabled, ["core.git", "db.postgres"]);
        assert_eq!(got.warnings.len(), 1);
        assert!(got.warnings[0].contains("\"db.oracle\""));
    }

    #[test]
    fn no_config_means_defaults_only() {
        let (known, _) = builtin_packs();
        let p = tempfile::tempdir().unwrap();
        assert_eq!(project_packs(p.path(), &known), ProjectPacks::default());
    }

    #[test]
    fn broken_config_is_a_warning() {
        let (known, _) = builtin_packs();
        let p = tempfile::tempdir().unwrap();
        std::fs::create_dir(p.path().join(".saiife")).unwrap();
        std::fs::write(p.path().join(CONFIG_REL), "packs = [\n").unwrap();
        let got = project_packs(p.path(), &known);
        assert!(got.enabled.is_empty());
        assert!(got.warnings[0].contains("default packs only"));
    }
}
