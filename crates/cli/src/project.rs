//! Which packs a project turns on (spec §5.1, §9.1 precedence): default-on
//! packs always, plus the opt-in packs listed in the nearest
//! `.saiife/config.toml`, plus any `--pack` given on the command line.

use std::path::{Path, PathBuf};

use saiife_agents::config::{self, CONFIG_REL};
use saiifeguard::Pack;

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
                if known.iter().any(|p| p.id == id) {
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
