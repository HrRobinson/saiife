//! Plan 43: dataset (filled in by Task 7 of plan 43).
//!
//! The private-file helpers (Task 3 fix round, S1) live here so the snapshot,
//! the lexicon, the index, the Bloom filter, the allow list and the manifest
//! all write their files the same way: inside a directory that is ours and
//! 0700, as new 0600 files that never follow a symlink, then sealed 0400.

use crate::error::ShieldError;
use rusqlite::{Connection, OpenFlags};
use std::fs::File;
use std::path::{Path, PathBuf};

fn io(why: &str) -> ShieldError {
    ShieldError::Io(why.to_string())
}

/// Makes `dir` (and any missing parents) 0700 at creation; an existing `dir`
/// must be a real directory (not a symlink) owned by us, and is tightened to
/// 0700 if group or other bits are set.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<(), ShieldError> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    match std::fs::symlink_metadata(dir) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(io("the dataset directory is a symlink"))
        }
        Ok(md) if !md.is_dir() => return Err(io("the dataset directory is not a directory")),
        Ok(_) => {}
        Err(_) => b
            .create(dir)
            .map_err(|_| io("could not make the dataset directory"))?,
    }
    // Check again after creating: what is there now must be ours.
    let md =
        std::fs::symlink_metadata(dir).map_err(|_| io("could not read the dataset directory"))?;
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(io("the dataset directory is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if md.uid() != rustix::process::geteuid().as_raw() {
            return Err(io("the dataset directory belongs to another user"));
        }
        if md.mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| io("could not make the dataset directory private"))?;
        }
    }
    Ok(())
}

/// Creates a new file: `create_new`, 0600, never following a symlink. The
/// caller has made its directory private with [`ensure_private_dir`].
pub(crate) fn create_private_file(path: &Path) -> Result<File, ShieldError> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let f = o
        .open(path)
        .map_err(|_| io("could not create a private file"))?;
    let md = f
        .metadata()
        .map_err(|_| io("could not create a private file"))?;
    if !md.is_file() {
        return Err(io("could not create a private file"));
    }
    Ok(f)
}

/// Flushes `f` to disk and makes it read-only (0400 on unix).
pub(crate) fn seal_file(f: &File) -> Result<(), ShieldError> {
    f.sync_all().map_err(|_| io("could not seal a file"))?;
    #[cfg(unix)]
    let perm = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o400)
    };
    #[cfg(not(unix))]
    let perm = {
        let mut p = f
            .metadata()
            .map_err(|_| io("could not seal a file"))?
            .permissions();
        p.set_readonly(true);
        p
    };
    f.set_permissions(perm)
        .map_err(|_| io("could not seal a file"))
}

/// Fsyncs a directory after a rename into it (unix; a no-op elsewhere).
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Removes the part file unless the write finished.
struct PartGuard<'a>(&'a Path, bool);
impl Drop for PartGuard<'_> {
    fn drop(&mut self) {
        if !self.1 {
            let _ = std::fs::remove_file(self.0);
        }
    }
}

/// The S1 write protocol, shared by every dataset file: makes `dir` private
/// ([`ensure_private_dir`]); refuses if `dir/final_name` exists; creates
/// `dir/<final_name>.part` with [`create_private_file`] (so anything already
/// at the part path, a planted symlink included, refuses and is left alone);
/// runs `write` on the part path; then seals the part 0400, renames it to
/// `final_name` in the same directory and syncs the directory. The part file
/// is removed on every error after it was created. Returns the final path
/// and what `write` returned.
pub(crate) fn with_private_part<T>(
    dir: &Path,
    final_name: &str,
    write: impl FnOnce(&Path) -> Result<T, ShieldError>,
) -> Result<(PathBuf, T), ShieldError> {
    ensure_private_dir(dir)?;
    let path = dir.join(final_name);
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(io("a dataset file already exists"));
    }
    let part = dir.join(format!("{final_name}.part"));
    let file = create_private_file(&part)?;
    let mut guard = PartGuard(&part, false);
    let v = write(&part)?;
    seal_file(&file)?;
    drop(file);
    std::fs::rename(&part, &path).map_err(|_| io("could not write a dataset file"))?;
    guard.1 = true;
    sync_dir(dir);
    Ok((path, v))
}

/// Opens a part file made by [`with_private_part`] as a SQLite database for
/// writing: READ_WRITE without CREATE (the file exists: create_new, 0600,
/// O_NOFOLLOW, in a checked 0700 dir), and without SQLITE_OPEN_NOFOLLOW,
/// which applies to every path component and refuses symlinked ancestors
/// (macOS /var, /home -> /var/home). Before any write: `journal_mode=OFF`
/// (checked), `temp_store=MEMORY` (no temp files with plaintext), and
/// `synchronous=OFF` (the file is fsynced when sealed). Errors are `why`.
pub(crate) fn open_part_db(part: &Path, why: &'static str) -> Result<Connection, ShieldError> {
    let err = |_| ShieldError::Sqlite(why.into());
    let conn = Connection::open_with_flags(
        part,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(err)?;
    let mode = conn
        .pragma_update_and_check(None, "journal_mode", "OFF", |r| r.get::<_, String>(0))
        .map_err(err)?;
    if !mode.eq_ignore_ascii_case("off") {
        return Err(ShieldError::Sqlite(
            "the journal could not be turned off".into(),
        ));
    }
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(err)?;
    conn.pragma_update(None, "synchronous", "OFF")
        .map_err(err)?;
    Ok(conn)
}

/// Sets `temp_store=MEMORY` on a reading connection: sorts, GROUP BY and
/// DISTINCT never spill values to temp files with umask permissions.
pub(crate) fn memory_temp_store(conn: &Connection) -> Result<(), ()> {
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|_| ())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn private_dir_and_file() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("x").join("y");
        ensure_private_dir(&d).unwrap();
        assert_eq!(mode(&d), 0o700);
        assert_eq!(mode(&t.path().join("x")), 0o700);
        let f = create_private_file(&d.join("f")).unwrap();
        assert_eq!(mode(&d.join("f")), 0o600);
        assert!(create_private_file(&d.join("f")).is_err());
        seal_file(&f).unwrap();
        assert_eq!(mode(&d.join("f")), 0o400);
        std::os::unix::fs::symlink(d.join("f"), d.join("l")).unwrap();
        assert!(ensure_private_dir(&d.join("l")).is_err());
        assert!(create_private_file(&d.join("l")).is_err());
    }

    #[test]
    fn private_part_protocol() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("ds");
        // Success: written through the part, sealed 0400, renamed, no part.
        let (p, v) = with_private_part(&d, "x.bin", |part| {
            assert_eq!(part, d.join("x.bin.part"));
            assert_eq!(mode(part), 0o600);
            std::fs::write(part, b"abc").unwrap();
            Ok(7)
        })
        .unwrap();
        assert_eq!((p.clone(), v), (d.join("x.bin"), 7));
        assert_eq!(std::fs::read(&p).unwrap(), b"abc");
        assert_eq!(mode(&p), 0o400);
        assert_eq!(mode(&d), 0o700);
        assert!(std::fs::symlink_metadata(d.join("x.bin.part")).is_err());
        // The final file exists: refused before the writer runs.
        let r = with_private_part(&d, "x.bin", |_| -> Result<(), ShieldError> {
            panic!("must not run")
        });
        assert!(r.is_err());
        // The writer fails: the part is removed, nothing is renamed.
        let r = with_private_part(&d, "y.bin", |part| -> Result<(), ShieldError> {
            std::fs::write(part, b"half").unwrap();
            Err(ShieldError::Io("boom".into()))
        });
        assert!(r.is_err());
        assert!(std::fs::symlink_metadata(d.join("y.bin.part")).is_err());
        assert!(std::fs::symlink_metadata(d.join("y.bin")).is_err());
        // A symlink planted at the part path: refused, left alone, not followed.
        let target = t.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, d.join("z.bin.part")).unwrap();
        let r = with_private_part(&d, "z.bin", |_| -> Result<(), ShieldError> {
            panic!("must not run")
        });
        assert!(r.is_err());
        assert!(!target.exists());
        assert!(std::fs::symlink_metadata(d.join("z.bin.part")).is_ok());
        assert!(std::fs::symlink_metadata(d.join("z.bin")).is_err());
    }

    #[test]
    fn part_db_pragmas() {
        let t = tempfile::tempdir().unwrap();
        let (p, ()) = with_private_part(t.path(), "db.sqlite", |part| {
            let c = open_part_db(part, "could not write")?;
            let j: String = c
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap();
            assert_eq!(j, "off");
            let ts: i64 = c.query_row("PRAGMA temp_store", [], |r| r.get(0)).unwrap();
            assert_eq!(ts, 2);
            c.execute_batch("CREATE TABLE t(x)").unwrap();
            c.close().map_err(|_| ShieldError::Sqlite("close".into()))
        })
        .unwrap();
        let names: Vec<String> = std::fs::read_dir(t.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["db.sqlite".to_string()]);
        assert_eq!(mode(&p), 0o400);
    }
}
