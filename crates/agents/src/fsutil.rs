//! File helpers for writing into a user's project: never leave a half-written
//! settings file behind, keep the file's permissions, and write through a
//! symlinked settings file instead of replacing the link.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::{AgentError, Change};

pub(crate) fn io_err(path: &Path) -> impl FnOnce(io::Error) -> AgentError + '_ {
    move |source| AgentError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The file's text, or `None` if it does not exist.
pub fn read_optional(path: &Path) -> Result<Option<String>, AgentError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path)(e)),
    }
}

/// Follow the symlink chain starting at `start` (at most 40 hops) and return
/// the first target that does not exist. `None` if `start` is not a symlink,
/// or the chain is a loop or too long.
fn dangling_end(start: &Path) -> Option<PathBuf> {
    fs::read_link(start).ok()?;
    let mut cur = start.to_path_buf();
    for _ in 0..40 {
        let Ok(target) = fs::read_link(&cur) else {
            return None;
        };
        let next = cur.parent().map_or(target.clone(), |d| d.join(&target));
        if fs::symlink_metadata(&next).is_err() {
            return Some(next);
        }
        cur = next;
    }
    None
}

/// Refuse `<project>/<rel>` when it resolves outside the project: a
/// symlinked agent config (or config directory) pointing elsewhere, e.g. a
/// user-wide file, must not be rewritten by a per-project `init`. A missing
/// file is checked through its nearest existing ancestor.
pub fn ensure_inside(project: &Path, rel: &str) -> Result<(), AgentError> {
    let path = project.join(rel);
    let canon_project = fs::canonicalize(project).map_err(io_err(project))?;
    let existing = path
        .ancestors()
        .find(|p| fs::symlink_metadata(p).is_ok())
        .unwrap_or(project);
    let resolved = match fs::canonicalize(existing) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // A dangling symlink: say what it points at, not a raw I/O error.
            if let Some(missing) = dangling_end(existing) {
                return Err(AgentError::Layout {
                    path: existing.to_path_buf(),
                    detail: format!(
                        "it is a symlink to {}, which does not exist",
                        missing.display()
                    ),
                });
            }
            return Err(io_err(existing)(e));
        }
        Err(e) => return Err(io_err(existing)(e)),
    };
    if resolved.starts_with(&canon_project) {
        return Ok(());
    }
    Err(AgentError::OutsideProject { path, resolved })
}

/// Write `contents` to `<project>/<rel>` atomically (temp file in the same
/// directory, then rename). An existing file keeps its permissions; a
/// symlink is followed and its target replaced. Missing directories are
/// created and reported in `Change::Created`.
pub fn write(project: &Path, rel: &str, contents: &str) -> Result<Change, AgentError> {
    let path = project.join(rel);
    let existed = fs::symlink_metadata(&path).is_ok();
    let target = if existed {
        fs::canonicalize(&path).map_err(io_err(&path))?
    } else {
        path.clone()
    };
    let parent = target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let created_dirs = if existed {
        Vec::new()
    } else {
        create_dirs(project, &parent)?
    };
    let mut tmp = tempfile::NamedTempFile::new_in(&parent).map_err(io_err(&parent))?;
    tmp.write_all(contents.as_bytes())
        .map_err(io_err(&target))?;
    let perms = match fs::metadata(&target) {
        Ok(m) => m.permissions(),
        Err(_) => default_permissions(),
    };
    fs::set_permissions(tmp.path(), perms).map_err(io_err(&target))?;
    tmp.as_file().sync_all().map_err(io_err(&target))?;
    tmp.persist(&target).map_err(|e| io_err(&target)(e.error))?;
    sync_dir(&parent);
    Ok(if existed {
        Change::Updated
    } else {
        Change::Created { created_dirs }
    })
}

/// Make a rename into `dir` durable: fsync the directory itself. Best
/// effort: some platforms and filesystems refuse to open or sync a
/// directory, and the data is already written either way.
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Delete `<project>/<rel>`; a missing file is fine.
pub fn remove(project: &Path, rel: &str) -> Result<(), AgentError> {
    let path = project.join(rel);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(&path)(e)),
    }
}

/// A machine-wide managed config (locked mode, spec §8.3): its text, or
/// `None` if it does not exist. The open does not follow a symlink, and only
/// a regular file is read, so a planted link cannot redirect saiife.
pub fn read_managed(path: &Path) -> Result<Option<String>, AgentError> {
    use std::io::Read;
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(not_regular(path));
            }
            return Err(io_err(path)(e));
        }
    };
    let meta = f.metadata().map_err(io_err(path))?;
    if !meta.is_file() {
        return Err(not_regular(path));
    }
    let mut text = String::new();
    f.read_to_string(&mut text).map_err(io_err(path))?;
    Ok(Some(text))
}

fn not_regular(path: &Path) -> AgentError {
    AgentError::Layout {
        path: path.to_path_buf(),
        detail: "not a regular file (symlinks are not followed)".to_string(),
    }
}

/// Writes a managed config: a temp file next to it at mode 0644 (set on the
/// open handle), synced, then renamed over the old one. A symlink at `path`
/// is refused, never followed. The directory must exist.
pub fn write_managed(path: &Path, contents: &str) -> Result<Change, AgentError> {
    let existed = match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => true,
        Ok(_) => return Err(not_regular(path)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(io_err(path)(e)),
    };
    let parent = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(io_err(parent))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(io_err(path))?;
    }
    tmp.write_all(contents.as_bytes()).map_err(io_err(path))?;
    tmp.as_file().sync_all().map_err(io_err(path))?;
    tmp.persist(path).map_err(|e| io_err(path)(e.error))?;
    sync_dir(parent);
    Ok(if existed {
        Change::Updated
    } else {
        Change::Created {
            created_dirs: Vec::new(),
        }
    })
}

/// Create `dir` and its missing ancestors; return the ones created, relative
/// to `project`, outermost first.
fn create_dirs(project: &Path, dir: &Path) -> Result<Vec<String>, AgentError> {
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(d) = cur {
        if d.exists() {
            break;
        }
        missing.push(d.to_path_buf());
        cur = d.parent();
    }
    fs::create_dir_all(dir).map_err(io_err(dir))?;
    missing.reverse();
    Ok(missing
        .iter()
        .filter_map(|d| d.strip_prefix(project).ok())
        .map(|d| d.to_string_lossy().into_owned())
        .collect())
}

fn default_permissions() -> fs::Permissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o644)
    }
    #[cfg(not(unix))]
    {
        fs::metadata(".").unwrap().permissions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_file_and_reports_new_dirs() {
        let p = tempfile::tempdir().unwrap();
        let c = write(p.path(), ".claude/settings.json", "{}\n").unwrap();
        assert_eq!(
            c,
            Change::Created {
                created_dirs: vec![".claude".into()]
            }
        );
        assert_eq!(
            fs::read_to_string(p.path().join(".claude/settings.json")).unwrap(),
            "{}\n"
        );
        let c = write(p.path(), ".claude/settings.json", "{\"a\":1}\n").unwrap();
        assert_eq!(c, Change::Updated);
    }

    #[cfg(unix)]
    #[test]
    fn keeps_permissions_and_follows_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let p = tempfile::tempdir().unwrap();
        let real = p.path().join("real.json");
        fs::write(&real, "{}").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        fs::create_dir(p.path().join(".gemini")).unwrap();
        std::os::unix::fs::symlink(&real, p.path().join(".gemini/settings.json")).unwrap();
        write(p.path(), ".gemini/settings.json", "{\"x\":1}").unwrap();
        assert!(fs::symlink_metadata(p.path().join(".gemini/settings.json"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&real).unwrap(), "{\"x\":1}");
        assert_eq!(
            fs::metadata(&real).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// M1: a config (or its directory) resolving outside the project is
    /// refused; one resolving inside it is fine.
    #[cfg(unix)]
    #[test]
    fn ensure_inside_refuses_paths_resolving_outside_the_project() {
        let p = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(p.path().join("real.json"), "{}").unwrap();
        fs::create_dir(p.path().join(".gemini")).unwrap();
        std::os::unix::fs::symlink(
            p.path().join("real.json"),
            p.path().join(".gemini/settings.json"),
        )
        .unwrap();
        ensure_inside(p.path(), ".gemini/settings.json").unwrap();
        ensure_inside(p.path(), ".claude/settings.json").unwrap();
        std::os::unix::fs::symlink(outside.path(), p.path().join(".codex")).unwrap();
        let e = ensure_inside(p.path(), ".codex/config.toml").unwrap_err();
        assert!(e.to_string().contains("outside the project"), "{e}");
    }

    /// F1: syncing a directory is best effort and never fails a write.
    #[test]
    fn sync_dir_is_best_effort() {
        let p = tempfile::tempdir().unwrap();
        sync_dir(p.path());
        sync_dir(&p.path().join("missing"));
    }

    #[test]
    fn read_optional_and_remove_tolerate_missing_files() {
        let p = tempfile::tempdir().unwrap();
        assert_eq!(read_optional(&p.path().join("nope")).unwrap(), None);
        remove(p.path(), "nope").unwrap();
    }
}
