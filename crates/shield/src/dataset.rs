//! Plan 43 T7: the dataset directory and its atomic build.
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
    private_part(dir, final_name, false, write)
}

/// [`with_private_part`] for a file that is rewritten in place (the approved
/// method store): an existing `dir/final_name` must be a regular file (never
/// a symlink) and is replaced by the rename; the new file stays 0600 (it is
/// fsynced, not sealed 0400). Everything else is as in `with_private_part`.
pub(crate) fn replace_private_part<T>(
    dir: &Path,
    final_name: &str,
    write: impl FnOnce(&Path) -> Result<T, ShieldError>,
) -> Result<(PathBuf, T), ShieldError> {
    private_part(dir, final_name, true, write)
}

/// Replace mode only: a leftover part from a crash (a regular file of ours,
/// not a symlink) is removed so it cannot block every later save; anything
/// else at the part path is left alone and refuses at creation.
fn remove_stale_part(part: &Path) -> Result<(), ShieldError> {
    let md = match std::fs::symlink_metadata(part) {
        Ok(md) => md,
        Err(_) => return Ok(()),
    };
    #[cfg(unix)]
    let ours = {
        use std::os::unix::fs::MetadataExt;
        md.uid() == rustix::process::geteuid().as_raw()
    };
    #[cfg(not(unix))]
    let ours = true;
    if md.is_file() && ours {
        std::fs::remove_file(part).map_err(|_| io("could not remove a stale part file"))?;
    }
    Ok(())
}

fn private_part<T>(
    dir: &Path,
    final_name: &str,
    replace: bool,
    write: impl FnOnce(&Path) -> Result<T, ShieldError>,
) -> Result<(PathBuf, T), ShieldError> {
    ensure_private_dir(dir)?;
    let path = dir.join(final_name);
    match std::fs::symlink_metadata(&path) {
        Ok(md) if replace && md.is_file() => {}
        Ok(_) => return Err(io("a dataset file already exists")),
        Err(_) => {}
    }
    let part = dir.join(format!("{final_name}.part"));
    if replace {
        remove_stale_part(&part)?;
    }
    let file = create_private_file(&part)?;
    let mut guard = PartGuard(&part, false);
    let v = write(&part)?;
    if replace {
        file.sync_all()
            .map_err(|_| io("could not write a dataset file"))?;
    } else {
        seal_file(&file)?;
    }
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
    no_dqs(&conn).map_err(|()| ShieldError::Sqlite(why.into()))?;
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

/// I7: turns off SQLite's double-quoted-string fallback (DQS) for DML and
/// DDL, so an unknown `"column"` is an error, never a string literal.
pub(crate) fn no_dqs(conn: &Connection) -> Result<(), ()> {
    use rusqlite::config::DbConfig;
    for c in [
        DbConfig::SQLITE_DBCONFIG_DQS_DML,
        DbConfig::SQLITE_DBCONFIG_DQS_DDL,
    ] {
        if conn.set_db_config(c, false).map_err(|_| ())? {
            return Err(());
        }
    }
    Ok(())
}

/// Sets `temp_store=MEMORY` on a reading connection: sorts, GROUP BY and
/// DISTINCT never spill values to temp files with umask permissions.
pub(crate) fn memory_temp_store(conn: &Connection) -> Result<(), ()> {
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|_| ())
}

// ---------------------------------------------------------- Task 7 ----
//
// The atomic dataset build (spec §2.1.1). A build writes every file into
// `<root>/stage/` and then swaps: `live` -> `old` (rename), `stage` -> `live`
// (rename), fsync the dataset dir, remove `old`. A reader therefore finds
// the old complete set or the new complete set, never a mix. A crash between
// the two renames leaves `old` and `stage` (and no `live`):
// [`DatasetDir::recover`] puts `old` back. A leftover `stage/` from a killed
// build is removed when the next build starts.

use crate::classify::{self, checks, Guess};
use crate::index::{
    build_index, write_allow, BuildStats, IndexKey, ALLOW_FILE, BLOOM_FILE, INDEX_FILE,
};
use crate::lexicon::{build_lexicon, LEXICON_FILE};
use crate::public::{
    people_count, public_gate, public_values, table_people_count, PublicValues, NO_IDENTIFIER,
};
use crate::schema::{
    is_reserved_name, rows_band, ColType, ColumnClass, ColumnInfo, DatasetName, KeyJoin, Schema,
    TableInfo,
};
use crate::snapshot::{build_snapshot, open_ro, SnapshotInfo, SNAPSHOT_FILE};
use crate::source::{quote_ident, RowSource};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufWriter, Read, Write};

/// The manifest's file name in `live/`.
pub const MANIFEST_FILE: &str = "manifest.json";
/// The manifest format version written. Version 2 adds `schema.joins`;
/// [`load_manifest`] also reads version 1 (see [`MIN_MANIFEST_VERSION`]).
pub const MANIFEST_VERSION: u32 = 2;
/// The oldest manifest version [`load_manifest`] reads. A version 1
/// manifest has no `schema.joins`: they are derived on load with
/// [`Schema::conventional_joins`], which needs only the schema.
pub const MIN_MANIFEST_VERSION: u32 = 1;
/// The default frequency floor.
pub const DEFAULT_K: u32 = 10;
/// The smallest frequency floor a build accepts.
pub const MIN_K: u32 = 2;

/// Stage-only sidecar: the snapshot hash and the source names, from
/// `stage_snapshot` to `finish`. Removed before the swap.
const STAGE_INFO_FILE: &str = "stage.json";
/// The next stage info, renamed over [`STAGE_INFO_FILE`].
const STAGE_INFO_NEXT: &str = "stage.json.next";
const MAX_JSON_BYTES: u64 = 64 << 20;
const PUBLIC_REFUSED: &str = "a public column holds names, IDs or amounts";
const RESERVED: &str = "names starting with _p_ are reserved; rename it";
const BAD_JOIN: &str = "a join must link an entity key to an INTEGER column of another table";
const MISMATCH: &str = "a dataset file does not match its manifest";

/// The files the manifest hashes besides the snapshot.
const HASHED: [&str; 4] = [LEXICON_FILE, INDEX_FILE, BLOOM_FILE, ALLOW_FILE];

/// A dataset's directory: `<state>/blind/datasets/<name>`, holding `stage/`
/// during a build and `live/` once one finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetDir {
    pub root: PathBuf,
}

impl DatasetDir {
    pub fn stage(&self) -> PathBuf {
        self.root.join("stage")
    }

    pub fn live(&self) -> PathBuf {
        self.root.join("live")
    }

    fn old(&self) -> PathBuf {
        self.root.join("old")
    }

    /// The live snapshot.
    pub fn snapshot(&self) -> PathBuf {
        self.live().join(SNAPSHOT_FILE)
    }

    /// The live lexicon.
    pub fn lexicon(&self) -> PathBuf {
        self.live().join(LEXICON_FILE)
    }

    /// The live manifest.
    pub fn manifest(&self) -> PathBuf {
        self.live().join(MANIFEST_FILE)
    }

    /// Removes `stage/` and everything in it. A `stage` that is a symlink
    /// is unlinked; its target is never touched.
    pub fn clean_stage(&self) -> io::Result<()> {
        remove_entry(&self.stage())
    }

    /// Repairs what a crash in the swap left. `old` without `live` (a crash
    /// between the two renames): `old` goes back to `live` and the staged
    /// build is removed. `old` beside `live` (a crash after the swap):
    /// `old` is removed. Anything else is left as it is.
    pub fn recover(&self) -> Result<(), ShieldError> {
        if self.restore_old()? {
            self.clean_stage()
                .map_err(|_| io("could not remove the staged build"))?;
            sync_dir(&self.root);
        }
        Ok(())
    }

    /// `old` without `live`: renames `old` back (true). `old` beside
    /// `live`: removes `old`. Never touches the stage.
    fn restore_old(&self) -> Result<bool, ShieldError> {
        let old = self.old();
        if !exists(&old) {
            return Ok(false);
        }
        let restored = if exists(&self.live()) {
            remove_entry(&old).map_err(|_| io("could not remove the previous dataset"))?;
            false
        } else {
            std::fs::rename(&old, self.live())
                .map_err(|_| io("could not restore the previous dataset"))?;
            true
        };
        sync_dir(&self.root);
        Ok(restored)
    }
}

/// A built dataset's description: names, the k-floor public values, row
/// counts and file hashes. It holds no cell value outside the public lists.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub v: u32,
    pub dataset: DatasetName,
    /// RFC 3339, UTC.
    pub built_at: String,
    /// `sha256:` + 64 hex of `snapshot.sqlite`.
    pub snapshot_sha256: String,
    /// The policy's classes, with each table's row count from the snapshot.
    pub schema: Schema,
    /// The k-floor values of every `public` column; `column` is
    /// `table.column` here. `allow.json` was written from this same list.
    pub public: Vec<PublicValues>,
    /// `table.column` -> the value format (synthetic rows, plan 44).
    pub formats: BTreeMap<String, Format>,
    pub index: BuildStats,
    /// Snapshot name (`table` or `table.column`) -> the name in the source,
    /// for display (R43-2).
    pub source_names: BTreeMap<String, String>,
    /// `sha256:` hashes of `lexicon.sqlite`, `index.bin`, `index.bloom` and
    /// `allow.json`, checked by [`load_manifest`].
    pub files: BTreeMap<String, String>,
    /// Table -> its rows band ([`rows_band`]).
    pub rows_bands: BTreeMap<String, String>,
}

/// A column's value format, from `classify::checks` on its sample (at
/// least 80 % of the sampled values pass).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Plain,
    Email,
    Phone,
    Iban,
    Cpr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    Snapshot,
    Lexicon,
    Index,
    Validate,
    Swap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildProgress {
    pub phase: Phase,
    pub done: u64,
    pub total: Option<u64>,
}

/// One column's suggestion for the init wizard.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub table: String,
    pub column: String,
    pub ty: ColType,
    pub guess: Guess,
    pub uncertain: bool,
    /// Why this column can never be `public`; then there is no preview.
    pub public_refusal: Option<&'static str>,
    /// The values a `public` mark would list (k-floor), when not refused.
    pub public_preview: Option<PublicValues>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StageInfo {
    /// The snapshot as staged (no indexes); the classifier's sample seed.
    snapshot_sha256: String,
    source_names: BTreeMap<String, String>,
    /// The snapshot after a `finish` added its indexes, so a retry on the
    /// same stage knows the file it left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    indexed_sha256: Option<String>,
}

fn exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

/// Removes `p` without following a symlink: a link or a file is unlinked, a
/// real directory is removed with its contents. Missing is fine.
fn remove_entry(p: &Path) -> io::Result<()> {
    let md = match std::fs::symlink_metadata(p) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(md) => md,
    };
    if md.file_type().is_symlink() {
        // A directory symlink on Windows is removed with remove_dir.
        return std::fs::remove_file(p).or_else(|_| std::fs::remove_dir(p));
    }
    if md.is_dir() {
        #[cfg(not(unix))]
        clear_readonly(p);
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    }
}

/// Windows refuses to delete read-only files: clear the flag on the
/// (flat) dataset directory's files first.
#[cfg(not(unix))]
#[allow(clippy::permissions_set_readonly_false)]
fn clear_readonly(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Ok(md) = std::fs::symlink_metadata(e.path()) {
                if md.is_file() && md.permissions().readonly() {
                    let mut p = md.permissions();
                    p.set_readonly(false);
                    let _ = std::fs::set_permissions(e.path(), p);
                }
            }
        }
    }
}

/// Opens an existing file without following a symlink.
fn open_nofollow(path: &Path, write: bool, why: &'static str) -> Result<File, ShieldError> {
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(true)
    {
        return Err(io(why));
    }
    let mut o = std::fs::OpenOptions::new();
    o.read(!write).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let f = o.open(path).map_err(|_| io(why))?;
    if !f.metadata().map_err(|_| io(why))?.is_file() {
        return Err(io(why));
    }
    Ok(f)
}

/// Opens a sealed dataset file: a regular file of ours whose mode is
/// exactly `mode` (unix). A wrong mode or owner is `Corrupt`.
fn open_sealed(path: &Path, mode: u32) -> Result<File, ShieldError> {
    let f = open_nofollow(path, false, "could not read a dataset file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let md = f
            .metadata()
            .map_err(|_| io("could not read a dataset file"))?;
        if md.mode() & 0o7777 != mode || md.uid() != rustix::process::geteuid().as_raw() {
            return Err(ShieldError::Corrupt("a dataset file has the wrong mode"));
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(f)
}

/// `sha256:` + 64 lowercase hex of `f`'s bytes.
fn sha256_of(mut f: File) -> Result<String, ShieldError> {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|_| io("could not read a dataset file"))?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for b in ctx.finish().as_ref() {
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
}

/// Writes `value` as JSON to `dir/name` through the private-part protocol.
fn write_json_part<T: serde::Serialize>(
    dir: &Path,
    name: &str,
    value: &T,
    why: &'static str,
) -> Result<PathBuf, ShieldError> {
    let (path, ()) = with_private_part(dir, name, |part| {
        let f = open_nofollow(part, true, why)?;
        let mut w = BufWriter::new(f);
        serde_json::to_writer_pretty(&mut w, value).map_err(|_| io(why))?;
        w.flush().map_err(|_| io(why))
    })?;
    Ok(path)
}

/// Reads JSON from an open file, at most 64 MiB. Any fault is `bad`.
fn read_json<T: serde::de::DeserializeOwned>(f: File, bad: &'static str) -> Result<T, ShieldError> {
    let mut s = String::new();
    f.take(MAX_JSON_BYTES + 1)
        .read_to_string(&mut s)
        .map_err(|_| ShieldError::Corrupt(bad))?;
    if s.len() as u64 > MAX_JSON_BYTES {
        return Err(ShieldError::Limit("a dataset JSON file is over 64 MiB"));
    }
    serde_json::from_str(&s).map_err(|_| ShieldError::Corrupt(bad))
}

fn check_k(k: u32) -> Result<(), ShieldError> {
    if k < MIN_K {
        return Err(ShieldError::Limit(
            "the frequency floor k must be at least 2",
        ));
    }
    Ok(())
}

fn snap_err(_: rusqlite::Error) -> ShieldError {
    ShieldError::Sqlite("could not read the snapshot".into())
}

/// The snapshot's tables in order, each with its columns (without the
/// `_rowid` key) and their types.
type Layout = Vec<(String, Vec<(String, ColType)>)>;

fn snapshot_layout(conn: &Connection) -> Result<Layout, ShieldError> {
    let mut st = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY rowid",
        )
        .map_err(snap_err)?;
    let tables = st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(snap_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(snap_err)?;
    let mut cs = conn
        .prepare("SELECT name, type FROM pragma_table_info(?1) ORDER BY cid")
        .map_err(snap_err)?;
    let mut out = Vec::with_capacity(tables.len());
    for t in tables {
        let cols = cs
            .query_map([&t], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(snap_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(snap_err)?;
        let mut typed = Vec::with_capacity(cols.len());
        for (c, decl) in cols {
            if c == "_rowid" {
                continue;
            }
            let ty = match decl.as_str() {
                "INTEGER" => ColType::Integer,
                "REAL" => ColType::Real,
                "TEXT" => ColType::Text,
                "DATE" => ColType::Date,
                "BOOL" => ColType::Bool,
                _ => {
                    return Err(ShieldError::Corrupt(
                        "the snapshot has an unknown column type",
                    ))
                }
            };
            typed.push((c, ty));
        }
        out.push((t, typed));
    }
    Ok(out)
}

/// The schema names exactly the snapshot's tables and columns, with the
/// snapshot's types: a column left out of the policy would go unclassified
/// and unindexed.
fn check_schema(schema: &Schema, layout: &Layout) -> Result<(), ShieldError> {
    let bad = ShieldError::Corrupt("the schema does not match the snapshot");
    let names: BTreeSet<&str> = schema.tables.iter().map(|t| t.name.as_str()).collect();
    if names.len() != schema.tables.len() || names.len() != layout.len() {
        return Err(bad);
    }
    for (t, cols) in layout {
        let Some(ti) = schema.table(t) else {
            return Err(bad);
        };
        let have: BTreeMap<&str, ColType> =
            ti.columns.iter().map(|c| (c.name.as_str(), c.ty)).collect();
        let want: BTreeMap<&str, ColType> = cols.iter().map(|(c, ty)| (c.as_str(), *ty)).collect();
        if have.len() != ti.columns.len() || have != want {
            return Err(bad);
        }
    }
    check_reserved(schema)?;
    check_entities(schema, layout)?;
    check_joins(schema)
}

/// Plan 45 S1: no snapshot name and no alias (a cloud name) starts with
/// the planner's `_p_` prefix. Import already refuses such source names;
/// this covers the policy's aliases and a snapshot from elsewhere.
fn check_reserved(schema: &Schema) -> Result<(), ShieldError> {
    for t in &schema.tables {
        if is_reserved_name(&t.name) || t.alias.as_deref().is_some_and(is_reserved_name) {
            return Err(policy_err(&t.name, None, RESERVED));
        }
        for c in &t.columns {
            if is_reserved_name(&c.name) || c.alias.as_deref().is_some_and(is_reserved_name) {
                return Err(policy_err(&t.name, Some(&c.name), RESERVED));
            }
        }
    }
    Ok(())
}

/// A join the policy declares links an EntitySpec's key to an INTEGER
/// column of another schema table (the schema already matches the
/// snapshot).
fn check_joins(schema: &Schema) -> Result<(), ShieldError> {
    for j in &schema.joins {
        let entity = schema
            .entities
            .iter()
            .any(|e| e.table == j.entity && e.key == j.key);
        let fk_int = schema
            .column(&j.table, &j.column)
            .is_some_and(|c| c.ty == ColType::Integer);
        if !entity || !fk_int || j.table == j.entity {
            return Err(policy_err(&j.table, Some(&j.column), BAD_JOIN));
        }
    }
    Ok(())
}

/// The key-side columns of `schema` (with its joins built), sorted: every
/// EntitySpec key and the entity side of every [`Schema::joins`] entry.
/// The FK side of a join may repeat (many invoices to one customer) and is
/// not here.
fn key_side_columns(schema: &Schema) -> BTreeSet<(&str, &str)> {
    let mut out: BTreeSet<(&str, &str)> = schema
        .entities
        .iter()
        .map(|e| (e.table.as_str(), e.key.as_str()))
        .collect();
    for j in &schema.joins {
        out.insert((j.entity.as_str(), j.key.as_str()));
    }
    out
}

/// **Invariant (plan 48 C5, owner ruling D51-4):** in a built snapshot every
/// key-side column ([`key_side_columns`]) is UNIQUE and NON-NULL: no NULL,
/// no empty or whitespace-only text, no value on two rows. A join from an
/// FK to it therefore matches at most one row, so it never multiplies the
/// rows of the other side; the validator's join rules
/// ([`Schema::key_join`], `sql.rs`) and the calculator rely on this.
///
/// Checked in SQL on the staged snapshot, before any index exists, with
/// two queries per column: the empty rows (one scan) and the rows whose key
/// another row shares (`GROUP BY` the key, `HAVING COUNT(*) > 1`: one scan
/// and one sort in memory, `O(n log n)`; about 4 s at 3M keys in random
/// order, where `COUNT(DISTINCT)` and its temp B-tree took 5.4 s). The refusal
/// names the table, the column and the count of affected rows, never a
/// value ([`crate::error::repeated_key_reason`]).
fn check_unique_keys(conn: &Connection, schema: &Schema) -> Result<(), ShieldError> {
    for (t, c) in key_side_columns(schema) {
        let (tq, cq) = (quote_ident(t), quote_ident(c));
        // NULL (the loader's empty and whitespace-only cell), or empty text
        // in a snapshot from elsewhere.
        let empty = format!("({cq} IS NULL OR (typeof({cq}) = 'text' AND TRIM({cq}) = ''))");
        let count = |sql: String| -> Result<i64, ShieldError> {
            conn.query_row(&sql, [], |r| r.get(0)).map_err(snap_err)
        };
        let empties = count(format!("SELECT COUNT(*) FROM {tq} WHERE {empty}"))?;
        // Every row whose key another row shares.
        let shared = count(format!(
            "SELECT COALESCE(SUM(n), 0) FROM (SELECT COUNT(*) AS n FROM {tq} \
             WHERE NOT {empty} GROUP BY {cq} HAVING COUNT(*) > 1)"
        ))?;
        if empties + shared > 0 {
            return Err(ShieldError::RepeatedKey {
                table: t.to_string(),
                column: c.to_string(),
                rows: (empties + shared) as u64,
            });
        }
    }
    Ok(())
}

/// The declared joins and the conventional ones, sorted, no duplicates.
fn all_joins(schema: &Schema) -> Vec<KeyJoin> {
    let mut joins = schema.joins.clone();
    joins.extend(schema.conventional_joins());
    joins.sort();
    joins.dedup();
    joins
}

/// A fixed policy error naming a table and maybe a column (never a value).
fn policy_err(table: &str, column: Option<&str>, why: &'static str) -> ShieldError {
    ShieldError::Source {
        file: "policy".into(),
        table: Some(table.to_string()),
        column: column.map(str::to_string),
        row: None,
        why,
    }
}

/// I7: every EntitySpec names a snapshot table, an INTEGER key column, at
/// least one name column, and only snapshot columns to show. (Queries quote
/// these names; an unknown one must fail here, not read as nothing.)
fn check_entities(schema: &Schema, layout: &Layout) -> Result<(), ShieldError> {
    const MISSING: &str = "an entity column is not in the snapshot";
    for e in &schema.entities {
        let Some((_, cols)) = layout.iter().find(|(t, _)| *t == e.table) else {
            return Err(policy_err(
                &e.table,
                None,
                "an entity table is not in the snapshot",
            ));
        };
        let ty = |c: &str| cols.iter().find(|(n, _)| n == c).map(|x| x.1);
        match ty(&e.key) {
            None => return Err(policy_err(&e.table, Some(&e.key), MISSING)),
            Some(ColType::Integer) => {}
            Some(_) => {
                return Err(policy_err(
                    &e.table,
                    Some(&e.key),
                    "an entity key is not an INTEGER column",
                ))
            }
        }
        if e.names.is_empty() {
            return Err(policy_err(&e.table, None, "an entity has no name columns"));
        }
        for c in e.names.iter().chain(&e.show) {
            if ty(c).is_none() {
                return Err(policy_err(&e.table, Some(c), MISSING));
            }
        }
    }
    Ok(())
}

/// The format most of `sample` passes, for a text or integer column (M2:
/// phones and CPRs are often inferred as INTEGER).
fn format_of(ty: ColType, sample: &[String]) -> Format {
    if !matches!(ty, ColType::Text | ColType::Integer) || sample.is_empty() {
        return Format::Plain;
    }
    type Check = fn(&str) -> bool;
    let tests: [(Format, Check); 4] = [
        (Format::Cpr, checks::cpr),
        (Format::Iban, checks::iban),
        (Format::Email, checks::email),
        (Format::Phone, checks::phone),
    ];
    for (f, test) in tests {
        let pass = sample.iter().filter(|v| test(v)).count();
        if pass * 5 >= sample.len() * 4 {
            return f;
        }
    }
    Format::Plain
}

/// D3: the classifier's sample seed for one column, from the snapshot's
/// hash and the names, so `propose` and `finish` read the same sample and
/// reach the same public verdict for a borderline column.
fn sample_seed(snapshot_sha256: &str, table: &str, column: &str) -> u64 {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for part in ["saiife-shield-sample", snapshot_sha256, table, column] {
        ctx.update(part.as_bytes());
        ctx.update(&[0]);
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&ctx.finish().as_ref()[..8]);
    u64::from_le_bytes(b)
}

/// Now as RFC 3339 UTC, second precision.
fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Stage 1 of a build: removes a stale `stage/`, then writes
/// `stage/snapshot.sqlite` from `src`. Returns what the wizard shows next to
/// [`propose`]'s suggestions. `live/` is not touched.
pub fn stage_snapshot(
    dir: &DatasetDir,
    src: &mut dyn RowSource,
    progress: &mut dyn FnMut(BuildProgress),
) -> Result<SnapshotInfo, ShieldError> {
    ensure_private_dir(&dir.root)?;
    dir.recover()?;
    dir.clean_stage()
        .map_err(|_| io("could not remove a stale staged build"))?;
    sync_dir(&dir.root);
    let stage = dir.stage();
    ensure_private_dir(&stage)?;
    // Rows done over all tables so far.
    let (mut base, mut cur_table, mut cur_done) = (0u64, String::new(), 0u64);
    let info = build_snapshot(src, &stage, &mut |p| {
        if p.table != cur_table {
            base += cur_done;
            cur_table = p.table.clone();
        }
        cur_done = p.rows_done;
        progress(BuildProgress {
            phase: Phase::Snapshot,
            done: base + cur_done,
            total: None,
        });
    })?;
    let mut source_names = BTreeMap::new();
    for (t, src_t, _, cols) in &info.tables {
        source_names.insert(t.clone(), src_t.clone());
        for (c, src_c, _) in cols {
            source_names.insert(format!("{t}.{c}"), src_c.clone());
        }
    }
    let si = StageInfo {
        snapshot_sha256: info.sha256.clone(),
        source_names,
        indexed_sha256: None,
    };
    write_json_part(
        &stage,
        STAGE_INFO_FILE,
        &si,
        "could not write the staged build",
    )?;
    Ok(info)
}

/// One suggestion per snapshot column. For each column the public refusal
/// is decided first (Review Focus 4); only a column that is not refused has
/// its k-floor values read for a preview. A refusal found while reading
/// them (too many values, a value that looks like an ID) is a refusal too.
pub fn propose(snapshot: &Path, k: u32) -> Result<Vec<Proposal>, ShieldError> {
    check_k(k)?;
    let sha = sha256_of(open_nofollow(
        snapshot,
        false,
        "could not read the snapshot",
    )?)?;
    // R-22: the source names (`CustomerID`) from the stage sidecar, when
    // the snapshot was staged by `stage_snapshot`. Its staged hash is the
    // sample seed, as in `finish` (a failed `finish` may have added the
    // indexes since).
    let info_path = snapshot.with_file_name(STAGE_INFO_FILE);
    let (sha, source_names) = if exists(&info_path) {
        let si: StageInfo = read_json(
            open_sealed(&info_path, 0o400)?,
            "the staged build is incomplete",
        )?;
        (si.snapshot_sha256, si.source_names)
    } else {
        (sha, BTreeMap::new())
    };
    let conn = open_ro(snapshot)?;
    let mut out = Vec::new();
    for (table, cols) in snapshot_layout(&conn)? {
        let mut seen = Vec::with_capacity(cols.len());
        for (column, ty) in cols {
            let st = classify::stats(&conn, &table, &column, ty)?;
            let source = source_names
                .get(&format!("{table}.{column}"))
                .map(String::as_str);
            let sample = classify::sample_seeded(
                &conn,
                &table,
                &column,
                sample_seed(&sha, &table, &column),
            )?;
            // R-22: an ID-shaped source name is guessed by its split form
            // (`employee_id`), never as a public category.
            let split = source
                .filter(|s| classify::source_id_shaped(s))
                .map(classify::camel_split);
            let guess = classify::guess(split.as_deref().unwrap_or(&column), ty, &st, &sample);
            seen.push((column, ty, st, sample, source, guess));
        }
        // I4: the preview counts people as `finish` will, by the guessed
        // classes (no EntitySpec or join is known yet). A table that cannot
        // be counted lists no values.
        let guessed = TableInfo {
            name: table.clone(),
            alias: None,
            rows: 0,
            columns: seen
                .iter()
                .map(|(c, ty, _, _, _, g)| ColumnInfo {
                    name: c.clone(),
                    ty: *ty,
                    class: g.class,
                    alias: None,
                })
                .collect(),
        };
        let count = match people_count(&guessed, None, &[]) {
            Ok(c) => Some(c),
            Err(ShieldError::Source {
                why: NO_IDENTIFIER, ..
            }) => None,
            Err(e) => return Err(e),
        };
        for (column, ty, st, sample, source, guess) in seen {
            let mut refusal = public_gate(&[], &table, &column, source, ty, &st, &sample);
            let mut preview = None;
            // M5: no k-floor listing of free text (the gate refuses it, S4).
            if refusal.is_none() && guess.class != ColumnClass::FreeText {
                match &count {
                    Some(count) => match public_values(&conn, &table, &column, k, count) {
                        Ok(pv) => preview = Some(pv),
                        Err(ShieldError::Source { why, .. }) => refusal = Some(why),
                        Err(e) => return Err(e),
                    },
                    None => refusal = Some(NO_IDENTIFIER),
                }
            }
            out.push(Proposal {
                table: table.clone(),
                column,
                ty,
                guess,
                uncertain: classify::uncertain(&guess),
                public_refusal: refusal,
                public_preview: preview,
            });
        }
    }
    Ok(out)
}

/// Removes what an earlier failed `finish` left in `stage/`, so a retry on
/// the same stage starts clean. The snapshot and the stage info stay.
fn clear_derived(stage: &Path) -> Result<(), ShieldError> {
    let rd = std::fs::read_dir(stage).map_err(|_| io("could not read the staged build"))?;
    for e in rd {
        let e = e.map_err(|_| io("could not read the staged build"))?;
        let name = e.file_name().to_string_lossy().into_owned();
        let derived =
            HASHED.contains(&name.as_str()) || name == MANIFEST_FILE || name == STAGE_INFO_NEXT;
        let part = name.ends_with(".part") && name != format!("{SNAPSHOT_FILE}.part");
        if derived
            || part
            || name.starts_with("index.run.")
            || name.ends_with("-journal")
            || name.ends_with("-wal")
            || name.ends_with("-shm")
        {
            remove_entry(&e.path()).map_err(|_| io("could not clear the staged build"))?;
        }
    }
    sync_dir(stage);
    Ok(())
}

/// The (table, column) pairs `finish` indexes in the snapshot, sorted: every
/// entity key and the FK column of every [`Schema::joins`] entry (pass the
/// built schema, whose joins include the conventional ones). Plan 45's
/// calculator can rely on these being indexed.
pub fn snapshot_index_columns(schema: &Schema) -> Vec<(String, String)> {
    let mut out: BTreeSet<(String, String)> = schema
        .entities
        .iter()
        .map(|e| (e.table.clone(), e.key.clone()))
        .collect();
    for j in &schema.joins {
        out.insert((j.entity.clone(), j.key.clone()));
        out.insert((j.table.clone(), j.column.clone()));
    }
    out.into_iter().collect()
}

/// The name of the index on `table.column`. Snapshot names hold no `.`,
/// so no two pairs share a name; `IF NOT EXISTS` keeps a retry idempotent.
fn index_name(table: &str, column: &str) -> String {
    format!("saiife_ix:{table}.{column}")
}

/// Makes a sealed file of ours writable again (0600 on unix).
#[cfg(unix)]
fn unseal(path: &Path, why: &'static str) -> Result<(), ShieldError> {
    use std::os::unix::fs::PermissionsExt;
    open_nofollow(path, false, why)?
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| io(why))
}

/// Makes a sealed file of ours writable again (clears read-only).
#[cfg(not(unix))]
#[allow(clippy::permissions_set_readonly_false)]
fn unseal(path: &Path, why: &'static str) -> Result<(), ShieldError> {
    let md = std::fs::symlink_metadata(path).map_err(|_| io(why))?;
    if md.file_type().is_symlink() || !md.is_file() {
        return Err(io(why));
    }
    let mut p = md.permissions();
    p.set_readonly(false);
    std::fs::set_permissions(path, p).map_err(|_| io(why))
}

/// Adds the [`snapshot_index_columns`] indexes to the sealed staged
/// snapshot in place: unseal, create, fsync and seal 0400 again. A crash
/// here leaves a file whose hash matches neither the staged nor an indexed
/// one, so the next `finish` refuses it and the user stages again.
fn index_snapshot(snap: &Path, schema: &Schema) -> Result<(), ShieldError> {
    const WHY: &str = "could not index the snapshot";
    unseal(snap, WHY)?;
    let built = create_indexes(snap, schema, WHY);
    // Sealed again on every path: a failure leaves a 0400 file whose hash
    // the next `finish` refuses as a changed snapshot (stage again).
    let sealed = open_nofollow(snap, true, WHY).and_then(|f| seal_file(&f));
    built.and(sealed)
}

/// Drops the `saiife_ix:` indexes an earlier attempt made that this schema
/// does not want, then creates the wanted ones.
fn create_indexes(snap: &Path, schema: &Schema, why: &'static str) -> Result<(), ShieldError> {
    let err = |_| ShieldError::Sqlite(why.into());
    let conn = open_part_db(snap, why)?;
    let want: Vec<(String, String)> = snapshot_index_columns(schema);
    let names: BTreeSet<String> = want.iter().map(|(t, c)| index_name(t, c)).collect();
    let have: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'saiife\\_ix:%' ESCAPE '\\'")
        .and_then(|mut st| {
            st.query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(err)?;
    for n in have.iter().filter(|n| !names.contains(*n)) {
        conn.execute_batch(&format!("DROP INDEX {}", quote_ident(n)))
            .map_err(err)?;
    }
    for (t, c) in &want {
        conn.execute_batch(&format!(
            "CREATE INDEX IF NOT EXISTS {} ON {} ({})",
            quote_ident(&index_name(t, c)),
            quote_ident(t),
            quote_ident(c)
        ))
        .map_err(err)?;
    }
    conn.close().map_err(|_| ShieldError::Sqlite(why.into()))
}

/// Stage 2: see the brief; `finish` and the crash seam share it.
fn finish_inner(
    dir: &DatasetDir,
    schema: &Schema,
    k: u32,
    key: &IndexKey,
    validate: &mut dyn FnMut(&Manifest) -> Result<(), String>,
    progress: &mut dyn FnMut(BuildProgress),
    crash_after_first_rename: bool,
) -> Result<Manifest, ShieldError> {
    check_k(k)?;
    if dir.root.file_name().and_then(|n| n.to_str()) != Some(schema.dataset.as_str()) {
        return Err(ShieldError::Corrupt("the schema names another dataset"));
    }
    ensure_private_dir(&dir.root)?;
    let stage = dir.stage();
    match std::fs::symlink_metadata(&stage) {
        Ok(md) if md.is_dir() && !md.file_type().is_symlink() => {}
        _ => return Err(io("there is no staged build")),
    }
    ensure_private_dir(&stage)?;
    clear_derived(&stage)?;

    let si: StageInfo = read_json(
        open_sealed(&stage.join(STAGE_INFO_FILE), 0o400)?,
        "the staged build is incomplete",
    )?;
    let snap_path = stage.join(SNAPSHOT_FILE);
    let found = sha256_of(open_sealed(&snap_path, 0o400)?)?;
    if found != si.snapshot_sha256 && si.indexed_sha256.as_ref() != Some(&found) {
        return Err(ShieldError::Corrupt("the staged snapshot changed"));
    }
    // The sample seed is the staged hash, as in `propose`.
    let staged_sha256 = si.snapshot_sha256.clone();

    let conn = open_ro(&snap_path)?;
    let layout = snapshot_layout(&conn)?;
    check_schema(schema, &layout)?;
    let policy = schema.clone();
    let mut schema = schema.clone();
    schema.joins = all_joins(&schema);
    // C5 (D51-4): after the load, before the indexes and the manifest.
    check_unique_keys(&conn, &schema)?;
    // I4: every table can be counted, or the build is refused here.
    let counts = schema
        .tables
        .iter()
        .map(|t| table_people_count(&schema, &t.name))
        .collect::<Result<Vec<_>, _>>()?;
    let mut public = Vec::new();
    let mut formats = BTreeMap::new();
    let mut rows_bands = BTreeMap::new();
    for (t, count) in schema.tables.iter_mut().zip(&counts) {
        let n: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", quote_ident(&t.name)),
                [],
                |r| r.get(0),
            )
            .map_err(snap_err)?;
        t.rows = n.max(0) as u64;
        rows_bands.insert(t.name.clone(), rows_band(t.rows));
        for c in &t.columns {
            let seed = sample_seed(&staged_sha256, &t.name, &c.name);
            let sample = classify::sample_seeded(&conn, &t.name, &c.name, seed)?;
            if c.class == ColumnClass::Public {
                // Defence in depth for a hand-edited policy: the wizard's
                // refusal is checked again before any value is listed.
                let st = classify::stats(&conn, &t.name, &c.name, c.ty)?;
                let source = si
                    .source_names
                    .get(&format!("{}.{}", t.name, c.name))
                    .map(String::as_str);
                if public_gate(
                    &policy.entities,
                    &t.name,
                    &c.name,
                    source,
                    c.ty,
                    &st,
                    &sample,
                )
                .is_some()
                {
                    return Err(ShieldError::Corrupt(PUBLIC_REFUSED));
                }
                public.push(public_values(&conn, &t.name, &c.name, k, count)?);
            }
            formats.insert(format!("{}.{}", t.name, c.name), format_of(c.ty, &sample));
        }
    }
    drop(conn);

    // Bench item 2: the key and join indexes, after the bulk load. The
    // manifest hashes the indexed file; the stage info records it so a
    // retry of a failed `finish` accepts it.
    index_snapshot(&snap_path, &schema)?;
    let snapshot_sha256 = sha256_of(open_sealed(&snap_path, 0o400)?)?;
    if snapshot_sha256 != found {
        let next = StageInfo {
            snapshot_sha256: staged_sha256.clone(),
            source_names: si.source_names.clone(),
            indexed_sha256: Some(snapshot_sha256.clone()),
        };
        // Replaced by a rename (atomic on unix): a crash leaves the old or
        // the new stage info, never none.
        const WHY: &str = "could not write the staged build";
        let _ = remove_entry(&stage.join(STAGE_INFO_NEXT));
        let tmp = write_json_part(&stage, STAGE_INFO_NEXT, &next, WHY)?;
        #[cfg(not(unix))]
        unseal(&stage.join(STAGE_INFO_FILE), WHY)?;
        std::fs::rename(&tmp, stage.join(STAGE_INFO_FILE)).map_err(|_| io(WHY))?;
        sync_dir(&stage);
    }

    progress(BuildProgress {
        phase: Phase::Lexicon,
        done: 0,
        total: Some(1),
    });
    build_lexicon(&snap_path, &schema, &stage)?;
    progress(BuildProgress {
        phase: Phase::Lexicon,
        done: 1,
        total: Some(1),
    });

    // The allow list comes from this same public list. `build_index` reads
    // it from the stage and derives its k-floor words with the same `k`, so
    // `allow.json` and the index agree by construction.
    write_allow(&schema, &public, &stage)?;
    progress(BuildProgress {
        phase: Phase::Index,
        done: 0,
        total: None,
    });
    let index = build_index(&snap_path, &schema, k, key, &stage, &mut |n| {
        progress(BuildProgress {
            phase: Phase::Index,
            done: n,
            total: None,
        })
    })?;

    let mut files = BTreeMap::new();
    for f in HASHED {
        files.insert(
            f.to_string(),
            sha256_of(open_sealed(&stage.join(f), 0o400)?)?,
        );
    }
    let manifest = Manifest {
        v: MANIFEST_VERSION,
        dataset: schema.dataset.clone(),
        built_at: now_utc(),
        snapshot_sha256,
        schema,
        public,
        formats,
        index,
        source_names: si.source_names,
        files,
        rows_bands,
    };

    progress(BuildProgress {
        phase: Phase::Validate,
        done: 0,
        total: None,
    });
    // The closure's text may carry anything: it is dropped (M3).
    validate(&manifest).map_err(|_| ShieldError::Corrupt("the build did not pass validation"))?;

    let mpath = write_json_part(
        &stage,
        MANIFEST_FILE,
        &manifest,
        "could not write the manifest",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        open_nofollow(&mpath, false, "could not write the manifest")?
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| io("could not write the manifest"))?;
    }
    #[cfg(not(unix))]
    let _ = mpath;
    remove_entry(&stage.join(STAGE_INFO_FILE))
        .map_err(|_| io("could not clear the staged build"))?;
    sync_dir(&stage);

    progress(BuildProgress {
        phase: Phase::Swap,
        done: 0,
        total: Some(1),
    });
    swap(dir, crash_after_first_rename)?;
    progress(BuildProgress {
        phase: Phase::Swap,
        done: 1,
        total: Some(1),
    });
    Ok(manifest)
}

/// `live` -> `old`, `stage` -> `live`, fsync, remove `old`.
fn swap(dir: &DatasetDir, crash_after_first_rename: bool) -> Result<(), ShieldError> {
    let (live, old, stage) = (dir.live(), dir.old(), dir.stage());
    // A leftover `old` from an earlier crash.
    dir.restore_old()?;
    let had_live = exists(&live);
    if had_live {
        std::fs::rename(&live, &old).map_err(|_| io("could not replace the dataset"))?;
    }
    if crash_after_first_rename {
        return Ok(());
    }
    if std::fs::rename(&stage, &live).is_err() {
        if had_live {
            let _ = std::fs::rename(&old, &live);
        }
        sync_dir(&dir.root);
        return Err(io("could not replace the dataset"));
    }
    sync_dir(&dir.root);
    if had_live {
        // The new set is live; a failure here leaves `old` for `recover`.
        let _ = remove_entry(&old);
        sync_dir(&dir.root);
    }
    Ok(())
}

/// Stage 2 of a build: with the policy's classes (as a Schema), builds the
/// lexicon, the public values, the allow list and the index in `stage/`,
/// runs `validate` (plan 47 passes the approved-method re-validation),
/// writes the manifest, then swaps `stage` -> `live`. Every column the
/// schema marks `public` is checked again with `public_refusal`. On an
/// error `live/` is unchanged; the stage stays for a retry and is removed
/// by the next [`stage_snapshot`].
pub fn finish(
    dir: &DatasetDir,
    schema: &Schema,
    k: u32,
    key: &IndexKey,
    validate: &mut dyn FnMut(&Manifest) -> Result<(), String>,
    progress: &mut dyn FnMut(BuildProgress),
) -> Result<Manifest, ShieldError> {
    finish_inner(dir, schema, k, key, validate, progress, false)
}

/// Test seam: [`finish`] that stops right after `live` -> `old`, as a crash
/// there would.
#[doc(hidden)]
pub fn finish_crash_after_first_rename(
    dir: &DatasetDir,
    schema: &Schema,
    k: u32,
    key: &IndexKey,
    validate: &mut dyn FnMut(&Manifest) -> Result<(), String>,
    progress: &mut dyn FnMut(BuildProgress),
) -> Result<(), ShieldError> {
    finish_inner(dir, schema, k, key, validate, progress, true).map(|_| ())
}

/// A private directory of ours (unix: no group or other bits).
fn check_private_dir(p: &Path) -> Result<(), ShieldError> {
    let md = std::fs::symlink_metadata(p).map_err(|_| io("no dataset has been built"))?;
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(ShieldError::Corrupt("a dataset directory is not valid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.mode() & 0o077 != 0 || md.uid() != rustix::process::geteuid().as_raw() {
            return Err(ShieldError::Corrupt("a dataset directory is not private"));
        }
    }
    Ok(())
}

/// Reads `live/manifest.json` after [`DatasetDir::recover`], and checks it:
/// version, dataset name, the directory and file modes, and the SHA-256 of
/// the snapshot, lexicon, index, Bloom filter and allow list. Any mismatch
/// is `Corrupt`: a flipped bit in the Bloom filter must not become a silent
/// false negative.
pub fn load_manifest(dir: &DatasetDir) -> Result<Manifest, ShieldError> {
    let name: DatasetName = dir
        .root
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(ShieldError::BadName)?
        .parse()?;
    dir.recover()?;
    check_private_dir(&dir.root)?;
    check_private_dir(&dir.live())?;
    let mut m: Manifest = read_json(
        open_sealed(&dir.manifest(), 0o600)?,
        "the manifest is not valid",
    )?;
    if !(MIN_MANIFEST_VERSION..=MANIFEST_VERSION).contains(&m.v) {
        return Err(ShieldError::Corrupt(
            "the manifest version is not supported",
        ));
    }
    if m.v == 1 {
        m.schema.joins = m.schema.conventional_joins();
    }
    // Plan 45 S1 for every version: a dataset built before the check
    // existed may hold a `_p_` name or alias.
    check_reserved(&m.schema)
        .map_err(|_| ShieldError::Corrupt("a dataset name starts with the reserved _p_"))?;
    if m.dataset != name || m.schema.dataset != name {
        return Err(ShieldError::Corrupt("the manifest names another dataset"));
    }
    if sha256_of(open_sealed(&dir.snapshot(), 0o400)?)? != m.snapshot_sha256 {
        return Err(ShieldError::Corrupt(MISMATCH));
    }
    if m.files.len() != HASHED.len() {
        return Err(ShieldError::Corrupt(MISMATCH));
    }
    for f in HASHED {
        let want = m.files.get(f).ok_or(ShieldError::Corrupt(MISMATCH))?;
        if &sha256_of(open_sealed(&dir.live().join(f), 0o400)?)? != want {
            return Err(ShieldError::Corrupt(MISMATCH));
        }
    }
    Ok(m)
}

#[cfg(test)]
mod format_tests {
    use super::*;

    /// M2: phones and CPRs inferred as INTEGER get their format too.
    #[test]
    fn integer_columns_get_a_format() {
        let phones: Vec<String> = (0..10).map(|i| format!("{}", 20_000_000 + i)).collect();
        assert_eq!(format_of(ColType::Integer, &phones), Format::Phone);
        let cprs: Vec<String> = (0..10).map(|i| format!("{}", 1_201_801_230 + i)).collect();
        assert_eq!(format_of(ColType::Integer, &cprs), Format::Cpr);
        assert_eq!(format_of(ColType::Real, &phones), Format::Plain);
    }
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
