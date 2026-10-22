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
    let bytes = match read_config_bytes(project) {
        Ok(Some(b)) => b,
        Ok(None) => {
            return LoadedConfig {
                sha256: None,
                config: Err(not_found(&path)),
            }
        }
        Err(e) => {
            return LoadedConfig {
                sha256: None,
                config: Err(e),
            }
        }
    };
    let config = match std::str::from_utf8(&bytes) {
        Ok(text) => parse_config(&path, text),
        Err(_) => Err(AgentError::Parse {
            path,
            format: "TOML",
            detail: "not UTF-8".into(),
        }),
    };
    LoadedConfig {
        sha256: Some(sha256_hex(&bytes)),
        config,
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

/// The bytes of `<project>/.saiife/config.toml`, or `None` when it does not
/// exist. The one reader for the project config (hook, `init`, `status`).
///
/// - A symlink (the file or `.saiife`) is followed only while it stays
///   inside the project; a target outside is refused with
///   `AgentError::OutsideProject` and never read, so a cloned repo cannot
///   make saiife open or quote `~/.ssh/id_rsa`, or open a device.
/// - The open never blocks (a FIFO cannot hang it) and takes no
///   controlling terminal; anything the handle does not show as a regular
///   file, or as larger than `MAX_CONFIG_BYTES`, is refused unread, and the
///   read itself stops one byte past the cap.
///
/// On Linux the kernel does the confinement (`openat2` with
/// `RESOLVE_BENEATH` against the opened project root), so there is no
/// window between check and open. Where `openat2` is missing or filtered,
/// and on macOS, `read_fallback` checks where the opened handle really
/// points instead.
pub fn read_config_bytes(project: &Path) -> Result<Option<Vec<u8>>, AgentError> {
    #[cfg(target_os = "linux")]
    if let Some(done) = read_beneath(project) {
        return done;
    }
    read_fallback(project, || {})
}

/// `None` when `openat2` is unavailable (`ENOSYS`: old kernel; `EPERM`:
/// seccomp), so the caller falls back.
#[cfg(target_os = "linux")]
fn read_beneath(project: &Path) -> Option<Result<Option<Vec<u8>>, AgentError>> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use rustix::io::Errno;
    let path = project.join(CONFIG_REL);
    let root = match rustix::fs::open(
        project,
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(e) => return Some(Err(fsutil::io_err(project)(e.into()))),
    };
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let open = |rel: &Path, resolve: ResolveFlags| {
        // EAGAIN: the kernel saw a concurrent rename that could have let
        // the lookup escape; retrying a few times is safe.
        let mut again = 0;
        loop {
            match rustix::fs::openat2(&root, rel, flags, Mode::empty(), resolve) {
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) if again < 3 => again += 1,
                r => return r,
            }
        }
    };
    let fd = match open(
        Path::new(CONFIG_REL),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => fd,
        Err(Errno::NOSYS | Errno::PERM) => return None,
        Err(Errno::NOENT) => return Some(Ok(None)),
        // The lookup left the root, or met an absolute symlink, which
        // RESOLVE_BENEATH refuses even when it points back inside. Work out
        // the target from the path alone (nothing is opened); if it lies
        // inside, open that symlink-free path, still beneath the root.
        Err(Errno::XDEV) => match confine(project, &path) {
            Ok(Some((canon_root, canon))) => {
                let Ok(rel) = canon.strip_prefix(&canon_root) else {
                    return Some(Err(outside(&path, Some(canon))));
                };
                match open(
                    rel,
                    ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
                ) {
                    Ok(fd) => fd,
                    Err(Errno::NOENT) => return Some(Ok(None)),
                    Err(Errno::XDEV) => return Some(Err(outside(&path, Some(canon)))),
                    Err(e) => return Some(Err(fsutil::io_err(&path)(e.into()))),
                }
            }
            Ok(None) => return Some(Ok(None)),
            Err(e) => return Some(Err(e)),
        },
        Err(e) => return Some(Err(fsutil::io_err(&path)(e.into()))),
    };
    Some(read_open(&path, std::fs::File::from(fd)).map(Some))
}

/// The portable read: `confine()` first, then open the canonical path
/// (`O_NOFOLLOW`, non-blocking, no controlling terminal), then check where
/// the opened handle really is. A directory on the way swapped for a
/// symlink between the check and the open shows up there and is refused
/// before a byte is read. `before_open` runs between the two (a test seam;
/// production passes `|| {}`).
fn read_fallback(
    project: &Path,
    before_open: impl FnOnce(),
) -> Result<Option<Vec<u8>>, AgentError> {
    let orig = project.join(CONFIG_REL);
    let Some((root, canon)) = confine(project, &orig)? else {
        return Ok(None);
    };
    before_open();
    let file = match open_nofollow(&canon) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fsutil::io_err(&canon)(e)),
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let real = fd_path(&file).map_err(fsutil::io_err(&canon))?;
        if !real.starts_with(&root) {
            return Err(outside(&orig, Some(real)));
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = root;
    read_open(&canon, file).map(Some)
}

#[cfg(unix)]
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    let flags =
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    Ok(rustix::fs::open(path, flags, Mode::empty())?.into())
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Where an open handle really points.
#[cfg(target_os = "linux")]
fn fd_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(target_os = "macos")]
fn fd_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let c = rustix::fs::getpath(file)?;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(c.into_bytes())))
}

/// Read an opened config handle within the limits.
fn read_open(path: &Path, file: std::fs::File) -> Result<Vec<u8>, AgentError> {
    use std::io::Read;
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
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(fsutil::io_err(path))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(too_big());
    }
    Ok(bytes)
}

/// The canonical project root and the canonical form of `orig`
/// (`<project>/.saiife/config.toml`) if it lies inside it; `None` when the
/// config does not exist. Nothing is opened.
fn confine(project: &Path, orig: &Path) -> Result<Option<(PathBuf, PathBuf)>, AgentError> {
    let root = std::fs::canonicalize(project).map_err(fsutil::io_err(project))?;
    let canon = match std::fs::canonicalize(orig) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fsutil::io_err(orig)(e)),
    };
    if !canon.starts_with(&root) {
        return Err(outside(orig, Some(canon)));
    }
    Ok(Some((root, canon)))
}

/// The config resolves outside the project. `resolved`, when not known,
/// is worked out from the path alone (no file is opened).
fn outside(path: &Path, resolved: Option<PathBuf>) -> AgentError {
    let resolved = resolved
        .or_else(|| std::fs::canonicalize(path).ok())
        .unwrap_or_else(|| path.to_path_buf());
    AgentError::OutsideProject {
        path: path.to_path_buf(),
        resolved,
    }
}

fn not_found(path: &Path) -> AgentError {
    AgentError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory"),
    }
}

/// `read_config_bytes` for a config that must exist, as text.
fn read_text(project: &Path) -> Result<String, AgentError> {
    let path = project.join(CONFIG_REL);
    let bytes = read_config_bytes(project)?.ok_or_else(|| not_found(&path))?;
    String::from_utf8(bytes).map_err(|_| AgentError::Parse {
        path,
        format: "TOML",
        detail: "not UTF-8".into(),
    })
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
    let text = read_text(project)?;
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
        assert!(err.contains("outside the project"), "{err}");
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

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        let made = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(made.success());
    }

    #[test]
    fn missing_config_is_none() {
        let p = tempfile::tempdir().unwrap();
        assert!(read_config_bytes(p.path()).unwrap().is_none());
        fs::create_dir(p.path().join(".saiife")).unwrap();
        assert!(read_config_bytes(p.path()).unwrap().is_none());
        fs::write(p.path().join(CONFIG_REL), "packs = []\n").unwrap();
        assert_eq!(
            read_config_bytes(p.path()).unwrap(),
            Some(b"packs = []\n".to_vec())
        );
    }

    /// The outside target is a FIFO: a blocking open of it would hang, so
    /// a passing test also shows it was never opened for reading.
    #[cfg(unix)]
    #[test]
    fn config_symlink_outside_is_refused() {
        let p = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let fifo = outside.path().join("fifo");
        mkfifo(&fifo);
        fs::create_dir(p.path().join(".saiife")).unwrap();
        std::os::unix::fs::symlink(&fifo, p.path().join(CONFIG_REL)).unwrap();
        let err = read_config_bytes(p.path()).unwrap_err();
        assert!(matches!(err, AgentError::OutsideProject { .. }), "{err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn saiife_dir_symlink_outside_is_refused() {
        let p = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("config.toml"), "SECRET-CANARY = = =\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), p.path().join(".saiife")).unwrap();
        let err = read_config_bytes(p.path()).unwrap_err();
        assert!(matches!(err, AgentError::OutsideProject { .. }), "{err:?}");
        assert!(!err.to_string().contains("SECRET-CANARY"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn read_config_bytes_follows_inside_symlink() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        fs::create_dir(p.path().join("other")).unwrap();
        fs::write(p.path().join("other/config.toml"), "packs = []\n").unwrap();
        std::os::unix::fs::symlink("../other/config.toml", p.path().join(CONFIG_REL)).unwrap();
        assert_eq!(
            read_config_bytes(p.path()).unwrap(),
            Some(b"packs = []\n".to_vec())
        );
    }

    /// `RESOLVE_BENEATH` refuses every absolute symlink; one that stays
    /// inside the project must still be followed.
    #[cfg(unix)]
    #[test]
    fn absolute_symlink_inside_project_is_followed() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        fs::create_dir(p.path().join("other")).unwrap();
        fs::write(p.path().join("other/config.toml"), "packs = []\n").unwrap();
        std::os::unix::fs::symlink(
            p.path().join("other/config.toml"),
            p.path().join(CONFIG_REL),
        )
        .unwrap();
        assert_eq!(
            read_config_bytes(p.path()).unwrap(),
            Some(b"packs = []\n".to_vec())
        );
        fs::remove_file(p.path().join(CONFIG_REL)).unwrap();
        fs::remove_dir(p.path().join(".saiife")).unwrap();
        std::os::unix::fs::symlink(p.path().join("other"), p.path().join(".saiife")).unwrap();
        assert_eq!(
            read_config_bytes(p.path()).unwrap(),
            Some(b"packs = []\n".to_vec())
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_config_does_not_hang() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        mkfifo(&p.path().join(CONFIG_REL));
        let started = std::time::Instant::now();
        assert!(read_config_bytes(p.path()).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn read_config_bytes_refuses_oversized() {
        let p = tempfile::tempdir().unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        fs::File::create(p.path().join(CONFIG_REL))
            .unwrap()
            .set_len(MAX_CONFIG_BYTES + 1)
            .unwrap();
        let err = read_config_bytes(p.path()).unwrap_err().to_string();
        assert!(err.contains("larger than 64 KiB"), "{err}");
    }

    /// The race the post-open check closes: `.saiife` is swapped for a
    /// symlink to an outside directory after `confine()` passed.
    #[cfg(unix)]
    #[test]
    fn fallback_refuses_dir_swapped_after_confine() {
        let p = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("config.toml"), "SECRET-CANARY = = =\n").unwrap();
        fs::create_dir(p.path().join(".saiife")).unwrap();
        fs::write(p.path().join(CONFIG_REL), "packs = []\n").unwrap();
        let root = p.path().to_path_buf();
        let out = outside.path().to_path_buf();
        let got = read_fallback(p.path(), move || {
            fs::rename(root.join(".saiife"), root.join(".saiife-away")).unwrap();
            std::os::unix::fs::symlink(&out, root.join(".saiife")).unwrap();
        });
        let err = got.unwrap_err();
        assert!(matches!(err, AgentError::OutsideProject { .. }), "{err:?}");
        assert!(!err.to_string().contains("SECRET-CANARY"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn fallback_reads_normal_config() {
        let p = tempfile::tempdir().unwrap();
        assert!(read_fallback(p.path(), || {}).unwrap().is_none());
        fs::create_dir(p.path().join(".saiife")).unwrap();
        fs::create_dir(p.path().join("other")).unwrap();
        fs::write(p.path().join("other/c.toml"), "packs = []\n").unwrap();
        std::os::unix::fs::symlink("../other/c.toml", p.path().join(CONFIG_REL)).unwrap();
        assert_eq!(
            read_fallback(p.path(), || {}).unwrap(),
            Some(b"packs = []\n".to_vec())
        );
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
