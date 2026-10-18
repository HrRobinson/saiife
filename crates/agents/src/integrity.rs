//! The integrity record (spec §7.5): what `saiife init` wrote into a
//! project, kept OUTSIDE the project at
//! `<data dir>/saiife/projects/<sha256 of canonical project path>.json`, so
//! `saiife status` can tell when it was removed or changed.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fingerprint::sha256_hex;
use crate::fsutil::io_err;
use crate::AgentError;

/// Overrides `<data dir>/saiife` (tests, admins); mirrors the audit crate's
/// `SAIIFE_AUDIT_DIR`.
pub const DATA_DIR_ENV: &str = "SAIIFE_DATA_DIR";

pub const INTEGRITY_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrity {
    pub v: u32,
    /// Canonical project path.
    pub project: String,
    /// Canonical path of the `saiife` binary that ran `init`.
    pub saiife_path: String,
    /// Its version (`CARGO_PKG_VERSION`).
    pub saiife_version: String,
    /// SHA-256 of the `saiife` binary file that ran `init`. Empty in records
    /// from older versions.
    #[serde(default)]
    pub saiife_sha256: String,
    /// Set when `init` could not compute `saiife_sha256` (the reason), so
    /// `status` can tell "could not hash" from an older record without the
    /// field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saiife_sha256_error: Option<String>,
    /// SHA-256 of `.saiife/config.toml` as `init` left it.
    pub config_sha256: String,
    /// SHA-256 of `.saiife/config.toml` as saiife itself last wrote it
    /// (created, or packs appended). `init --off` deletes the file only
    /// while it still matches. Empty in records from older versions.
    #[serde(default)]
    pub config_written_sha256: String,
    /// Agent name (`claude`, `codex`, `gemini`) -> the hook entry written.
    pub hooks: BTreeMap<String, HookRecord>,
    /// Files and directories `init` created, relative to the project, in
    /// creation order (a directory before what is inside it).
    #[serde(default)]
    pub created: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookRecord {
    /// Config file, relative to the project.
    pub file: String,
    /// Fingerprint of the hook entry (`Agent::expected_entry`). Empty when
    /// `error` is set.
    pub sha256: String,
    /// Set when `init` tried to set this agent up and failed (the reason).
    /// `status` reports such an agent as a failed check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `$SAIIFE_DATA_DIR`, else `<data dir>/saiife`.
pub fn data_dir() -> Option<PathBuf> {
    data_dir_from(std::env::var_os(DATA_DIR_ENV))
}

/// A relative `SAIIFE_DATA_DIR` is ignored: it would resolve against the
/// caller's working directory, usually the project.
fn data_dir_from(var: Option<std::ffi::OsString>) -> Option<PathBuf> {
    match var {
        Some(d) if Path::new(&d).is_absolute() => Some(PathBuf::from(d)),
        _ => dirs::data_dir().map(|d| d.join("saiife")),
    }
}

/// The project path that identifies a project: canonical, so a project
/// reached through a symlink or with `..` is still the same project.
pub fn canonical_project(project: &Path) -> Result<PathBuf, AgentError> {
    fs::canonicalize(project).map_err(io_err(project))
}

/// Where the integrity record of `project` lives. `None` if there is no data
/// directory.
pub fn record_path(project: &Path) -> Result<Option<PathBuf>, AgentError> {
    let canonical = canonical_project(project)?;
    let key = sha256_hex(canonical.as_os_str().as_encoded_bytes());
    Ok(data_dir().map(|d| d.join("projects").join(format!("{key}.json"))))
}

impl Integrity {
    /// `None` if there is no record (never initialized here, or removed).
    pub fn load(path: &Path) -> Result<Option<Integrity>, AgentError> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(path)(e)),
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| AgentError::Parse {
                path: path.to_path_buf(),
                format: "JSON",
                detail: e.to_string(),
            })
    }

    /// Write atomically; the directory is created owner-only (0700) and the
    /// file is owner-only (0600) on unix.
    pub fn save(&self, path: &Path) -> Result<(), AgentError> {
        let dir = path.parent().expect("record path has a parent");
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir).map_err(io_err(dir))?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(io_err(dir))?;
        let mut body = serde_json::to_string_pretty(self).expect("integrity serializes");
        body.push('\n');
        tmp.write_all(body.as_bytes()).map_err(io_err(path))?;
        tmp.as_file().sync_all().map_err(io_err(path))?;
        tmp.persist(path).map_err(|e| io_err(path)(e.error))?;
        crate::fsutil::sync_dir(dir);
        Ok(())
    }

    /// Delete the record; a missing one is fine.
    pub fn delete(path: &Path) -> Result<(), AgentError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(path)(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(project: &str) -> Integrity {
        let mut hooks = BTreeMap::new();
        hooks.insert(
            "claude".to_string(),
            HookRecord {
                file: ".claude/settings.json".into(),
                sha256: "ab".repeat(32),
                error: None,
            },
        );
        Integrity {
            v: INTEGRITY_VERSION,
            project: project.into(),
            saiife_path: "/usr/local/bin/saiife".into(),
            saiife_version: "0.1.0".into(),
            saiife_sha256: "12".repeat(32),
            saiife_sha256_error: None,
            config_sha256: "cd".repeat(32),
            config_written_sha256: "ef".repeat(32),
            hooks,
            created: vec![".saiife".into(), ".saiife/config.toml".into()],
        }
    }

    #[test]
    fn save_load_delete_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("projects/x.json");
        assert_eq!(Integrity::load(&path).unwrap(), None);
        let rec = sample("/p");
        rec.save(&path).unwrap();
        assert_eq!(Integrity::load(&path).unwrap(), Some(rec));
        Integrity::delete(&path).unwrap();
        Integrity::delete(&path).unwrap();
        assert_eq!(Integrity::load(&path).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn record_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("projects/x.json");
        sample("/p").save(&path).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn corrupt_record_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("x.json");
        fs::write(&path, "{").unwrap();
        assert!(Integrity::load(&path).is_err());
    }

    #[test]
    fn a_relative_data_dir_is_ignored() {
        let default = data_dir_from(None);
        assert!(default.as_ref().unwrap().ends_with("saiife"));
        assert_eq!(data_dir_from(Some("rel-data".into())), default);
        assert_eq!(
            data_dir_from(Some("/abs/data".into())),
            Some(PathBuf::from("/abs/data"))
        );
    }

    /// Review Focus 3: the same project through a symlink or `..` has one
    /// record. (Only this test in this binary touches DATA_DIR_ENV.)
    #[cfg(unix)]
    #[test]
    fn symlinked_project_path_maps_to_the_same_record() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        fs::create_dir_all(real.join("sub")).unwrap();
        std::os::unix::fs::symlink(&real, d.path().join("link")).unwrap();
        std::env::set_var(DATA_DIR_ENV, d.path().join("data"));
        let a = record_path(&real).unwrap().unwrap();
        let b = record_path(&d.path().join("link")).unwrap().unwrap();
        let c = record_path(&real.join("sub/..")).unwrap().unwrap();
        std::env::remove_var(DATA_DIR_ENV);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert!(a.starts_with(d.path().join("data/projects")));
        assert_eq!(a.file_name().unwrap().len(), 64 + ".json".len());
    }
}
