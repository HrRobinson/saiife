//! Plan 43: snapshot (filled in by a later task of plan 43).

// Provisional copy of plan 43 Task 3's `open_ro`; plan 43's file wins at merge.
use crate::error::ShieldError;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Open a snapshot read-only and immutable.
pub fn open_ro(path: &Path) -> Result<Connection, ShieldError> {
    let mut enc = String::new();
    for ch in path.to_string_lossy().chars() {
        match ch {
            '%' => enc.push_str("%25"),
            '?' => enc.push_str("%3f"),
            '#' => enc.push_str("%23"),
            c => enc.push(c),
        }
    }
    let uri = format!("file:{enc}?mode=ro&immutable=1");
    Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ShieldError::Sqlite("could not open the snapshot read-only".to_string()))
}
