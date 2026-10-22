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

use crate::fingerprint::sha256_hex;
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
    load_hashed(project).config
}

/// The project config and the hash of the exact bytes it was read from.
#[derive(Debug)]
pub struct LoadedConfig {
    /// Lowercase hex SHA-256 of the file's bytes; `None` when the file could
    /// not be read (missing, refused or an I/O error). Set even when the
    /// bytes do not parse.
    pub sha256: Option<String>,
    pub config: Result<ProjectConfig, AgentError>,
}

/// `load`, plus the hash of what was read: one bounded read serves both.
pub fn load_hashed(project: &Path) -> LoadedConfig {
    let path = project.join(CONFIG_REL);
    let text = match read_bounded(project) {
        Ok(t) => t,
        Err(e) => {
            return LoadedConfig {
                sha256: None,
                config: Err(e),
            }
        }
    };
    LoadedConfig {
        sha256: Some(sha256_hex(text.as_bytes())),
        config: parse_config(&path, &text),
    }
}

fn parse_config(path: &Path, text: &str) -> Result<ProjectConfig, AgentError> {
    let doc = parse(path, text)?;
    let packs = match doc.get("packs") {
        None => Vec::new(),
        Some(item) => item
            .as_array()
            .ok_or_else(|| layout(path, "`packs` is not a list"))?
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

/// A project config is a few lines; anything bigger is refused unread so a
/// hostile tree cannot make every hook call slow or exhaust memory.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// The config's text, read at most `MAX_CONFIG_BYTES` (+1 to detect more).
/// A symlinked config is followed only while it stays inside the project:
/// the path and the project root are canonicalized and a target outside is
/// refused before it is opened (a cloned repo must not make the hook open
/// or quote `~/.ssh/id_rsa`, or open a device). The canonical path, which
/// holds no symlink, is then opened with `O_NOFOLLOW`, without blocking (a
/// FIFO swapped in meanwhile cannot hang the open) and without a controlling
/// terminal; anything the handle does not show as a regular file, or as
/// larger than the cap, is refused before a byte is read.
fn read_bounded(project: &Path) -> Result<String, AgentError> {
    use std::io::Read;
    let orig = project.join(CONFIG_REL);
    let path = &confine(project, &orig)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW);
    }
    let file = opts.open(path).map_err(fsutil::io_err(path))?;
    let meta = file.metadata().map_err(fsutil::io_err(path))?;
    if !meta.is_file() {
        return Err(layout(path, "not a regular file"));
    }
    let too_big = || {
        layout(
            path,
            &format!("larger than {} KiB", MAX_CONFIG_BYTES / 1024),
        )
    };
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(too_big());
    }
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(fsutil::io_err(path))?;
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(too_big());
    }
    Ok(text)
}

/// The canonical form of `orig` (`<project>/.saiife/config.toml`), if it lies
/// inside the canonical project root.
fn confine(project: &Path, orig: &Path) -> Result<PathBuf, AgentError> {
    let root = std::fs::canonicalize(project).map_err(fsutil::io_err(project))?;
    let canon = std::fs::canonicalize(orig).map_err(fsutil::io_err(orig))?;
    if !canon.starts_with(&root) {
        return Err(layout(orig, "points outside the project"));
    }
    Ok(canon)
}

/// Make sure the config exists and lists `packs`. A missing file is created
/// listing exactly `packs`; an existing file only gets the ids it lacks
/// appended, keeping everything else as the user wrote it.
pub fn ensure(project: &Path, packs: &[String]) -> Result<Change, AgentError> {
    let path = project.join(CONFIG_REL);
    // Same confinement as the hook's read; also covers a symlinked
    // `.saiife` directory and a dangling link, before anything is written.
    fsutil::ensure_inside(project, CONFIG_REL)?;
    if std::fs::symlink_metadata(&path).is_err() {
        return fsutil::write(project, CONFIG_REL, &new_file(packs));
    }
    let text = read_bounded(project)?;
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
    fn oversized_config_is_refused() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        let big = format!("# {}\npacks = []\n", "x".repeat(70 * 1024));
        fs::write(p.path().join(CONFIG_REL), &big).unwrap();
        assert!(load(p.path()).is_err());
        assert_eq!(fs::read_to_string(p.path().join(CONFIG_REL)).unwrap(), big);
    }

    #[test]
    fn load_hashed_hashes_the_bytes_read() {
        let p = tempfile::tempdir().unwrap();
        assert_eq!(load_hashed(p.path()).sha256, None, "no config");
        fs::create_dir(p.path().join(".saiife")).unwrap();
        for body in ["packs = [\"core.git\"]\n", "packs = [\n"] {
            fs::write(p.path().join(CONFIG_REL), body).unwrap();
            assert_eq!(
                load_hashed(p.path()).sha256,
                Some(sha256_hex(body.as_bytes())),
                "{body:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_project_is_followed() {
        let p = tempfile::tempdir().unwrap();
        let body = "packs = [\"db.mysql\"]\n";
        fs::create_dir(p.path().join(".saiife")).unwrap();
        fs::create_dir(p.path().join("other")).unwrap();
        fs::write(p.path().join("other/config.toml"), body).unwrap();
        std::os::unix::fs::symlink("../other/config.toml", p.path().join(CONFIG_REL)).unwrap();
        let got = load_hashed(p.path());
        assert_eq!(got.config.unwrap().packs, ids(&["db.mysql"]));
        assert_eq!(got.sha256, Some(sha256_hex(body.as_bytes())));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_outside_project_is_refused_without_leaking() {
        let p = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = "SECRET-CANARY-not-toml = = =\n";
        fs::write(outside.path().join("id_rsa"), secret).unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("id_rsa"), p.path().join(CONFIG_REL))
            .unwrap();
        let got = load_hashed(p.path());
        let err = got.config.unwrap_err().to_string();
        assert!(err.contains("points outside the project"), "{err}");
        assert!(!err.contains("SECRET-CANARY"), "{err}");
        assert_eq!(got.sha256, None);
        let err = ensure(p.path(), &ids(&["db.mysql"]))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("SECRET-CANARY"), "{err}");
        assert_eq!(
            fs::read_to_string(outside.path().join("id_rsa")).unwrap(),
            secret
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_follows_inside_symlink_and_refuses_oversized() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        fs::create_dir(p.path().join("other")).unwrap();
        fs::write(p.path().join("other/c.toml"), "packs = []\n").unwrap();
        std::os::unix::fs::symlink("../other/c.toml", p.path().join(CONFIG_REL)).unwrap();
        assert_eq!(
            ensure(p.path(), &ids(&["db.mysql"])).unwrap(),
            Change::Updated
        );
        assert!(fs::read_to_string(p.path().join("other/c.toml"))
            .unwrap()
            .contains("db.mysql"));
        let big = format!("# {}\n", "x".repeat(70 * 1024));
        fs::write(p.path().join("other/c.toml"), &big).unwrap();
        assert!(ensure(p.path(), &ids(&["db.git"])).is_err());
        assert_eq!(
            fs::read_to_string(p.path().join("other/c.toml")).unwrap(),
            big
        );
    }

    /// A symlink is followed only to a regular file within the cap: one to
    /// a FIFO is refused without blocking, one to an oversized file unread.
    #[cfg(unix)]
    #[test]
    fn symlink_to_fifo_or_oversized_file_is_refused() {
        let p = tempfile::tempdir().unwrap();
        let outside = p.path().join("other");
        fs::create_dir(&outside).unwrap();
        let fifo = outside.join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let big = outside.join("big.toml");
        fs::File::create(&big)
            .unwrap()
            .set_len(MAX_CONFIG_BYTES + 1)
            .unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        for target in [&fifo, &big] {
            let _ = fs::remove_file(p.path().join(CONFIG_REL));
            std::os::unix::fs::symlink(target, p.path().join(CONFIG_REL)).unwrap();
            let got = load_hashed(p.path());
            assert!(got.config.is_err(), "{}", target.display());
            assert_eq!(got.sha256, None, "{}", target.display());
        }
    }

    /// A FIFO at the config path neither blocks the open nor gets read.
    #[cfg(unix)]
    #[test]
    fn fifo_config_does_not_block() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        let fifo = p.path().join(CONFIG_REL);
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let got = load_hashed(p.path());
        assert!(got.config.is_err());
        assert_eq!(got.sha256, None);
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
