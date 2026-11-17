//! Plan 43: the import sources (CSV, xlsx, SQLite and in-memory rows), read
//! as tables of cells for the snapshot. Errors name the file, table, column
//! and row number only, never a cell value (and never the text of a library
//! error, which can carry one).

use crate::error::ShieldError;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};

/// R43-4 limits. Over a limit is an error, never a truncation.
pub const MAX_TABLES: usize = 64;
pub const MAX_COLUMNS: usize = 512;
pub const MAX_ROWS: u64 = 50_000_000;
pub const MAX_CELL_BYTES: usize = 64 * 1024;
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// How much of a CSV is read up front to sniff the encoding, the delimiter
/// and the header.
const SNIFF: usize = 64 * 1024;
/// Rows fetched per page from a SQLite source.
const PAGE: i64 = 10_000;

/// One cell as the source gives it. CSV gives only `Null` and `Text`; the
/// snapshot infers the column type. `Debug` shows the kind only (I8).
#[derive(Clone, PartialEq)]
pub enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    /// ISO `YYYY-MM-DD`.
    Date(String),
    Bool(bool),
}

impl std::fmt::Debug for Cell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Cell::Null => "Null",
            Cell::Int(_) => "Int(..)",
            Cell::Real(_) => "Real(..)",
            Cell::Text(_) => "Text(..)",
            Cell::Date(_) => "Date(..)",
            Cell::Bool(_) => "Bool(..)",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTable {
    pub name: String,
    pub columns: Vec<String>,
}

pub type RowIter<'a> = Box<dyn Iterator<Item = Result<Vec<Cell>, ShieldError>> + 'a>;

pub trait RowSource {
    fn tables(&self) -> Vec<SourceTable>;
    /// The rows of one table (no header row). The snapshot calls this twice
    /// per table: once to infer the types, once to insert.
    fn rows(&mut self, table: &str) -> Result<RowIter<'_>, ShieldError>;
    /// The file name errors show.
    fn file_name(&self) -> &str {
        "data"
    }
    /// The row number errors show for the first data row: 2 when the file
    /// has a header row (CSV, xlsx), else 1.
    fn first_data_row(&self) -> u64 {
        1
    }
    /// Where a source that can be read only once keeps a copy for the second
    /// pass (the CSV spool).
    fn set_spool_dir(&mut self, _dir: &Path) {}
    /// Removes any such copy.
    fn release(&mut self) {}
    /// R-22: may a column of decimal commas (`12,50`) be read as REAL?
    /// Only a `;` or tab CSV says yes: in a comma CSV, `"1,234"` is an
    /// English thousands group, and xlsx and SQLite give typed numbers.
    fn decimal_comma(&self) -> bool {
        false
    }
}

pub(crate) fn src_err(
    file: &str,
    table: Option<&str>,
    column: Option<&str>,
    row: Option<u64>,
    why: &'static str,
) -> ShieldError {
    ShieldError::Source {
        file: file.to_string(),
        table: table.map(str::to_string),
        column: column.map(str::to_string),
        row,
        why,
    }
}

fn no_table(file: &str, table: &str) -> ShieldError {
    src_err(file, Some(table), None, None, "no such table in the source")
}

fn base_name(file_name: &str) -> String {
    Path::new(file_name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name)
        .to_string()
}

/// I5: the fixed reason for a file whose first row is data.
const HEADERLESS: &str = "the first row looks like data, not column names";
/// D1: the fixed reason for an xlsx error cell (`#DIV/0!`, `#REF!`...).
const SHEET_ERROR: &str = "a cell holds a spreadsheet error";

/// I5: a header cell that is a number, a date or an identifier (email,
/// IBAN, phone, CPR, card number) is a data row, not column names.
fn looks_like_data(cell: &str) -> bool {
    use crate::snapshot::{parse_date, parse_int, parse_real};
    let t = cell.trim();
    parse_int(t).is_some()
        || parse_real(t).is_some()
        || parse_date(t).is_some()
        || crate::classify::looks_like_identifier(t)
}

fn header_name(raw: &str, i: usize) -> String {
    let t = raw.trim();
    if t.is_empty() {
        format!("column_{}", i + 1)
    } else {
        t.to_string()
    }
}

// ---------------------------------------------------------------- CSV ----

/// A reader error that means the file is over [`MAX_FILE_BYTES`].
#[derive(Debug)]
struct OverLimit;
impl std::fmt::Display for OverLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("over the file size limit")
    }
}
impl std::error::Error for OverLimit {}

/// A byte stream for the CSV reader: counts bytes against the file limit and,
/// on the first pass, copies them to the spool.
struct Feed<'a> {
    inner: Box<dyn Read + Send + 'a>,
    spool: Option<BufWriter<File>>,
    seen: u64,
}

impl Read for Feed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.seen += n as u64;
        if self.seen > MAX_FILE_BYTES {
            return Err(io::Error::other(OverLimit));
        }
        if let Some(w) = self.spool.as_mut() {
            w.write_all(&buf[..n])?;
        }
        Ok(n)
    }
}

impl Feed<'_> {
    fn finish(&mut self) -> io::Result<()> {
        if let Some(mut w) = self.spool.take() {
            w.flush()?;
            w.get_ref().sync_all()?;
        }
        Ok(())
    }
}

/// A CSV file: one table named after the file stem. UTF-8 (with or without
/// a BOM) only; the delimiter is sniffed among `,` `;` and tab.
pub struct CsvSource {
    file: String,
    table: SourceTable,
    delim: u8,
    head: Vec<u8>,
    rest: Option<Box<dyn Read + Send>>,
    spool_dir: Option<PathBuf>,
    spool: Option<PathBuf>,
    spooled: bool,
}

fn sniff_delim(head: &[u8]) -> u8 {
    let (mut counts, mut quoted) = ([0usize; 3], false);
    for &b in head {
        match b {
            b'"' => quoted = !quoted,
            b'\n' if !quoted => break,
            b',' if !quoted => counts[0] += 1,
            b';' if !quoted => counts[1] += 1,
            b'\t' if !quoted => counts[2] += 1,
            _ => {}
        }
    }
    let cands = b",;\t";
    let mut best = 0;
    for i in 1..3 {
        if counts[i] > counts[best] {
            best = i;
        }
    }
    cands[best]
}

impl CsvSource {
    pub fn open(mut r: Box<dyn Read + Send>, file_name: &str) -> Result<CsvSource, ShieldError> {
        let file = base_name(file_name);
        let read_err = |_| src_err(&file, None, None, None, "the file could not be read");
        let mut head = Vec::with_capacity(SNIFF);
        r.by_ref()
            .take(SNIFF as u64)
            .read_to_end(&mut head)
            .map_err(read_err)?;
        let full = head.len() == SNIFF;
        if head.starts_with(&[0xFF, 0xFE]) || head.starts_with(&[0xFE, 0xFF]) {
            return Err(src_err(
                &file,
                None,
                None,
                None,
                "the file is UTF-16; save it as UTF-8",
            ));
        }
        if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
            head.drain(..3);
        }
        if let Err(e) = std::str::from_utf8(&head) {
            // A character cut at the end of a full sniff buffer is fine.
            if !(full && e.error_len().is_none()) {
                return Err(src_err(
                    &file,
                    None,
                    None,
                    None,
                    "the file is not UTF-8; save it as UTF-8",
                ));
            }
        }
        let delim = sniff_delim(&head);
        let mut hr = csv::ReaderBuilder::new()
            .delimiter(delim)
            .has_headers(false)
            .from_reader(Cursor::new(&head[..]));
        let mut rec = csv::ByteRecord::new();
        let got = hr.read_byte_record(&mut rec).unwrap_or(false);
        let end = hr.position().byte();
        if !got || rec.is_empty() {
            return Err(src_err(
                &file,
                None,
                None,
                Some(1),
                "the file has no header row",
            ));
        }
        if full && end >= head.len() as u64 {
            return Err(src_err(
                &file,
                None,
                None,
                Some(1),
                "the header row is longer than 64 KiB",
            ));
        }
        let stem = Path::new(&file)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("data")
            .to_string();
        let mut columns = Vec::with_capacity(rec.len());
        for (i, f) in rec.iter().enumerate() {
            let s = std::str::from_utf8(f).map_err(|_| {
                src_err(
                    &file,
                    None,
                    None,
                    Some(1),
                    "the file is not UTF-8; save it as UTF-8",
                )
            })?;
            if looks_like_data(s) {
                return Err(src_err(&file, Some(&stem), None, Some(1), HEADERLESS));
            }
            columns.push(header_name(s, i));
        }
        Ok(CsvSource {
            file,
            table: SourceTable {
                name: stem,
                columns,
            },
            delim,
            head,
            rest: Some(r),
            spool_dir: None,
            spool: None,
            spooled: false,
        })
    }

    fn new_spool(&mut self) -> Result<Option<BufWriter<File>>, ShieldError> {
        let Some(dir) = self.spool_dir.clone() else {
            return Ok(None);
        };
        let mut rnd = [0u8; 8];
        getrandom::fill(&mut rnd).map_err(|_| ShieldError::Io("no randomness".into()))?;
        let tag: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!(".saiife-import-{tag}.tmp"));
        let f = crate::dataset::create_private_file(&path)?;
        self.spool = Some(path);
        Ok(Some(BufWriter::with_capacity(1 << 20, f)))
    }
}

impl Drop for CsvSource {
    fn drop(&mut self) {
        self.release();
    }
}

struct CsvRows<'a> {
    rdr: csv::Reader<Feed<'a>>,
    rec: csv::ByteRecord,
    file: &'a str,
    table: &'a str,
    row: u64,
    done: Option<&'a mut bool>,
    finished: bool,
}

impl CsvRows<'_> {
    fn err(&self, why: &'static str) -> ShieldError {
        src_err(self.file, Some(self.table), None, Some(self.row), why)
    }

    fn step(&mut self) -> Option<Result<Vec<Cell>, ShieldError>> {
        self.row += 1;
        match self.rdr.read_byte_record(&mut self.rec) {
            Ok(true) => {}
            Ok(false) => {
                if self.rdr.get_mut().finish().is_err() {
                    return Some(Err(ShieldError::Io(
                        "could not write the import copy".into(),
                    )));
                }
                if let Some(d) = self.done.take() {
                    *d = true;
                }
                return None;
            }
            Err(e) => {
                let why = match e.kind() {
                    csv::ErrorKind::UnequalLengths { .. } => {
                        "this row has a different number of fields than the header"
                    }
                    csv::ErrorKind::Io(ioe)
                        if ioe.get_ref().is_some_and(|x| x.is::<OverLimit>()) =>
                    {
                        return Some(Err(ShieldError::Limit("a file is larger than 16 GiB")));
                    }
                    csv::ErrorKind::Io(_) => "the file could not be read",
                    _ => "this row could not be read as CSV",
                };
                return Some(Err(self.err(why)));
            }
        }
        let mut out = Vec::with_capacity(self.rec.len());
        for f in self.rec.iter() {
            if f.iter().all(u8::is_ascii_whitespace) {
                out.push(Cell::Null);
                continue;
            }
            match std::str::from_utf8(f) {
                Ok(s) => out.push(Cell::Text(s.to_string())),
                Err(_) => return Some(Err(self.err("the file is not UTF-8; save it as UTF-8"))),
            }
        }
        Some(Ok(out))
    }
}

impl Iterator for CsvRows<'_> {
    type Item = Result<Vec<Cell>, ShieldError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let r = self.step();
        if !matches!(r, Some(Ok(_))) {
            self.finished = true;
        }
        r
    }
}

impl RowSource for CsvSource {
    fn tables(&self) -> Vec<SourceTable> {
        vec![self.table.clone()]
    }

    fn rows(&mut self, table: &str) -> Result<RowIter<'_>, ShieldError> {
        if table != self.table.name {
            return Err(no_table(&self.file, table));
        }
        let (inner, spool, done): (Box<dyn Read + Send>, _, _) =
            if let Some(rest) = self.rest.take() {
                let head = std::mem::take(&mut self.head);
                let spool = self.new_spool()?;
                (Box::new(Cursor::new(head).chain(rest)), spool, true)
            } else if self.spooled {
                let p = self
                    .spool
                    .as_ref()
                    .ok_or(ShieldError::Corrupt("import copy lost"))?;
                let f = File::open(p)
                    .map_err(|_| ShieldError::Io("could not read the import copy".into()))?;
                (Box::new(BufReader::with_capacity(1 << 20, f)), None, false)
            } else {
                return Err(src_err(
                    &self.file,
                    Some(table),
                    None,
                    None,
                    "the CSV can be read only once here",
                ));
            };
        let feed = Feed {
            inner,
            spool,
            seen: 0,
        };
        let rdr = csv::ReaderBuilder::new()
            .delimiter(self.delim)
            .has_headers(true)
            .flexible(false)
            .buffer_capacity(1 << 20)
            .from_reader(feed);
        Ok(Box::new(CsvRows {
            rdr,
            rec: csv::ByteRecord::new(),
            file: &self.file,
            table: &self.table.name,
            row: 1,
            done: if done { Some(&mut self.spooled) } else { None },
            finished: false,
        }))
    }

    fn file_name(&self) -> &str {
        &self.file
    }

    fn first_data_row(&self) -> u64 {
        2
    }

    fn decimal_comma(&self) -> bool {
        self.delim != b','
    }

    fn set_spool_dir(&mut self, dir: &Path) {
        self.spool_dir = Some(dir.to_path_buf());
    }

    fn release(&mut self) {
        if let Some(p) = self.spool.take() {
            let _ = std::fs::remove_file(p);
        }
        self.spooled = false;
    }
}

// --------------------------------------------------------------- xlsx ----

/// An xlsx workbook: one table per sheet; row 1 is the header. Empty sheets
/// are skipped.
pub struct XlsxSource {
    file: String,
    sheets: Vec<(SourceTable, calamine::Range<calamine::Data>)>,
}

/// One xlsx cell; an error cell is None (the caller refuses it, D1).
fn xlsx_cell(d: &calamine::Data) -> Option<Cell> {
    use calamine::Data;
    Some(match d {
        Data::Error(_) => return None,
        Data::Empty => Cell::Null,
        Data::Int(i) => Cell::Int(*i),
        Data::Float(f) => {
            if f.fract() == 0.0 && f.abs() < 9.0e15 {
                Cell::Int(*f as i64)
            } else {
                Cell::Real(*f)
            }
        }
        Data::String(s) => {
            if s.trim().is_empty() {
                Cell::Null
            } else {
                Cell::Text(s.clone())
            }
        }
        Data::Bool(b) => Cell::Bool(*b),
        Data::DateTime(dt) if dt.is_duration() => Cell::Real(dt.as_f64()),
        Data::DateTime(dt) => {
            let (y, m, d, h, mi, s, ms) = dt.to_ymd_hms_milli();
            let date = format!("{y:04}-{m:02}-{d:02}");
            if (h, mi, s, ms) == (0, 0, 0, 0) {
                Cell::Date(date)
            } else {
                Cell::Text(format!("{date} {h:02}:{mi:02}:{s:02}"))
            }
        }
        Data::DateTimeIso(s) | Data::DurationIso(s) => Cell::Text(s.clone()),
    })
}

impl XlsxSource {
    pub fn open(r: File, file_name: &str) -> Result<XlsxSource, ShieldError> {
        use calamine::Reader;
        let file = base_name(file_name);
        let len = r
            .metadata()
            .map_err(|_| src_err(&file, None, None, None, "the file could not be read"))?
            .len();
        if len > MAX_FILE_BYTES {
            return Err(ShieldError::Limit("a file is larger than 16 GiB"));
        }
        let mut wb = calamine::Xlsx::new(BufReader::new(r)).map_err(|_| {
            src_err(
                &file,
                None,
                None,
                None,
                "the file is not a readable xlsx workbook",
            )
        })?;
        let names = wb.sheet_names();
        if names.len() > MAX_TABLES {
            return Err(ShieldError::Limit("more than 64 tables"));
        }
        let mut sheets = Vec::with_capacity(names.len());
        for name in names {
            let range = wb.worksheet_range(&name).map_err(|_| {
                src_err(
                    &file,
                    Some(&name),
                    None,
                    None,
                    "the sheet could not be read",
                )
            })?;
            let Some(head) = range.rows().next() else {
                continue;
            };
            let mut columns = Vec::with_capacity(head.len());
            for (i, d) in head.iter().enumerate() {
                use calamine::Data;
                let raw = match d {
                    Data::String(s) if !looks_like_data(s) => s.clone(),
                    Data::Empty => String::new(),
                    Data::Error(_) => {
                        return Err(src_err(&file, Some(&name), None, Some(1), SHEET_ERROR))
                    }
                    // A number, a date or an identifier in row 1 is data.
                    _ => return Err(src_err(&file, Some(&name), None, Some(1), HEADERLESS)),
                };
                columns.push(header_name(&raw, i));
            }
            sheets.push((SourceTable { name, columns }, range));
        }
        Ok(XlsxSource { file, sheets })
    }
}

impl RowSource for XlsxSource {
    fn tables(&self) -> Vec<SourceTable> {
        self.sheets.iter().map(|s| s.0.clone()).collect()
    }

    fn rows(&mut self, table: &str) -> Result<RowIter<'_>, ShieldError> {
        let (info, range) = self
            .sheets
            .iter()
            .find(|s| s.0.name == table)
            .ok_or_else(|| no_table(&self.file, table))?;
        let file = &self.file;
        Ok(Box::new(range.rows().enumerate().skip(1).map(
            move |(ri, r)| {
                r.iter()
                    .enumerate()
                    .map(|(ci, d)| {
                        xlsx_cell(d).ok_or_else(|| {
                            src_err(
                                file,
                                Some(&info.name),
                                info.columns.get(ci).map(String::as_str),
                                Some(ri as u64 + 1),
                                SHEET_ERROR,
                            )
                        })
                    })
                    .collect()
            },
        )))
    }

    fn file_name(&self) -> &str {
        &self.file
    }

    fn first_data_row(&self) -> u64 {
        2
    }
}

// ------------------------------------------------------------- SQLite ----

/// `file:<path>?<query>` with the path percent-encoded for SQLite's URI
/// parser.
pub(crate) fn sqlite_uri(path: &Path, query: &str) -> String {
    let s = path.to_string_lossy();
    #[cfg(windows)]
    let s = {
        let t = s.replace('\\', "/");
        if t.starts_with('/') {
            t
        } else {
            format!("/{t}")
        }
    };
    let mut u = String::from("file:");
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"/._-~:".contains(&b) {
            u.push(b as char);
        } else {
            u.push_str(&format!("%{b:02X}"));
        }
    }
    u.push('?');
    u.push_str(query);
    u
}

pub(crate) fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

struct SqlTable {
    info: SourceTable,
    /// The quoted table name and column list.
    from: String,
    cols: String,
    /// A rowid name usable for keyset paging, or None (WITHOUT ROWID).
    key: Option<&'static str>,
    /// For WITHOUT ROWID tables: the quoted primary key columns, in order.
    order: String,
}

/// A SQLite database file, opened `mode=ro&immutable=1`. User tables only
/// (no `sqlite_*`, no virtual tables); views are skipped; declared BLOB
/// columns are left out.
pub struct SqliteSource {
    file: String,
    conn: rusqlite::Connection,
    tables: Vec<SqlTable>,
}

impl SqliteSource {
    pub fn open(path: &Path) -> Result<SqliteSource, ShieldError> {
        use rusqlite::OpenFlags;
        let file = base_name(&path.to_string_lossy());
        let bad = |why| src_err(&file, None, None, None, why);
        let len = std::fs::metadata(path)
            .map_err(|_| bad("the file could not be read"))?
            .len();
        if len > MAX_FILE_BYTES {
            return Err(ShieldError::Limit("a file is larger than 16 GiB"));
        }
        // R-10: `immutable=1` would silently ignore rows still in the WAL.
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        if std::fs::metadata(&wal).is_ok_and(|m| m.len() > 0) {
            return Err(bad(
                "the database has unsaved changes (a -wal file); checkpoint it first",
            ));
        }
        // D2: `immutable=1` would ignore a hot rollback journal too.
        let mut journal = path.as_os_str().to_os_string();
        journal.push("-journal");
        if std::fs::metadata(&journal).is_ok_and(|m| m.len() > 0) {
            return Err(bad(
                "the database has an unfinished transaction (a -journal file); open and close it in SQLite first",
            ));
        }
        let conn = rusqlite::Connection::open_with_flags(
            sqlite_uri(path, "mode=ro&immutable=1"),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| bad("the file is not a readable SQLite database"))?;
        crate::dataset::no_dqs(&conn)
            .map_err(|()| bad("the file is not a readable SQLite database"))?;
        // The paged SELECTs sort: never into a temp file.
        crate::dataset::memory_temp_store(&conn)
            .map_err(|_| bad("the file is not a readable SQLite database"))?;
        let names: Vec<String> = (|| {
            let mut st = conn.prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
                 AND coalesce(sql, '') NOT LIKE 'CREATE VIRTUAL%' ORDER BY name",
            )?;
            let v = st
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, rusqlite::Error>(v)
        })()
        .map_err(|_| bad("the file is not a readable SQLite database"))?;
        if names.len() > MAX_TABLES {
            return Err(ShieldError::Limit("more than 64 tables"));
        }
        let mut tables = Vec::with_capacity(names.len());
        for name in names {
            let tbad = || {
                src_err(
                    &file,
                    Some(&name),
                    None,
                    None,
                    "the table could not be read",
                )
            };
            let from = quote_ident(&name);
            let mut columns = Vec::new();
            let mut all = Vec::new();
            let mut pk: Vec<(i64, String)> = Vec::new();
            {
                let mut st = conn
                    .prepare(&format!("PRAGMA table_info({from})"))
                    .map_err(|_| tbad())?;
                let mut rows = st.query([]).map_err(|_| tbad())?;
                while let Some(r) = rows.next().map_err(|_| tbad())? {
                    let c: String = r.get(1).map_err(|_| tbad())?;
                    let ty: String = r
                        .get::<_, Option<String>>(2)
                        .map_err(|_| tbad())?
                        .unwrap_or_default();
                    let pk_pos: i64 = r.get(5).map_err(|_| tbad())?;
                    if pk_pos > 0 {
                        pk.push((pk_pos, quote_ident(&c)));
                    }
                    all.push(c.to_ascii_lowercase());
                    if !ty.to_ascii_uppercase().contains("BLOB") {
                        columns.push(c);
                    }
                }
            }
            let cols = columns
                .iter()
                .map(|c| quote_ident(c))
                .collect::<Vec<_>>()
                .join(", ");
            let key = ["rowid", "_rowid_", "oid"]
                .into_iter()
                .filter(|k| !all.iter().any(|c| c == k))
                .find(|k| {
                    conn.prepare(&format!("SELECT {k} FROM {from} LIMIT 0"))
                        .is_ok()
                });
            pk.sort();
            let order = if !pk.is_empty() {
                pk.into_iter().map(|p| p.1).collect::<Vec<_>>().join(", ")
            } else if cols.is_empty() {
                "NULL".to_string()
            } else {
                cols.clone()
            };
            tables.push(SqlTable {
                info: SourceTable { name, columns },
                from,
                cols,
                key,
                order,
            });
        }
        Ok(SqliteSource { file, conn, tables })
    }
}

struct SqlRows<'a> {
    conn: &'a rusqlite::Connection,
    file: &'a str,
    t: &'a SqlTable,
    sql: String,
    last: i64,
    offset: i64,
    buf: std::collections::VecDeque<Vec<Cell>>,
    row: u64,
    done: bool,
}

impl SqlRows<'_> {
    fn fetch(&mut self) -> Result<(), ShieldError> {
        let fail = || {
            src_err(
                self.file,
                Some(&self.t.info.name),
                None,
                None,
                "the table could not be read",
            )
        };
        let mut st = self.conn.prepare_cached(&self.sql).map_err(|_| fail())?;
        let arg = if self.t.key.is_some() {
            self.last
        } else {
            self.offset
        };
        let mut rows = st.query([arg]).map_err(|_| fail())?;
        let skip = usize::from(self.t.key.is_some());
        let ncol = self.t.info.columns.len();
        let mut n = 0i64;
        let mut last = None;
        while let Some(r) = rows.next().map_err(|_| fail())? {
            n += 1;
            if self.t.key.is_some() {
                last = Some(r.get::<_, i64>(0).map_err(|_| fail())?);
            }
            let at = self.row + self.buf.len() as u64 + 1;
            let mut cells = Vec::with_capacity(ncol);
            for i in 0..ncol {
                use rusqlite::types::ValueRef;
                let col = || Some(self.t.info.columns[i].as_str());
                let v = r.get_ref(i + skip).map_err(|_| fail())?;
                cells.push(match v {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(x) => Cell::Int(x),
                    ValueRef::Real(x) => Cell::Real(x),
                    ValueRef::Text(b) => match std::str::from_utf8(b) {
                        Ok(s) if s.trim().is_empty() => Cell::Null,
                        Ok(s) => Cell::Text(s.to_string()),
                        Err(_) => {
                            return Err(src_err(
                                self.file,
                                Some(&self.t.info.name),
                                col(),
                                Some(at),
                                "a cell is not UTF-8 text",
                            ))
                        }
                    },
                    ValueRef::Blob(_) => {
                        return Err(src_err(
                            self.file,
                            Some(&self.t.info.name),
                            col(),
                            Some(at),
                            "a cell holds binary data",
                        ))
                    }
                });
            }
            self.buf.push_back(cells);
        }
        self.offset += n;
        // `last` is the next page's first key (`>=`), so the lowest rowid
        // (i64::MIN) is not skipped; past i64::MAX there is nothing left.
        match last.map(|k| k.checked_add(1)) {
            Some(Some(next)) => self.last = next,
            Some(None) => self.done = true,
            None => {}
        }
        if n < PAGE {
            self.done = true;
        }
        Ok(())
    }
}

impl Iterator for SqlRows<'_> {
    type Item = Result<Vec<Cell>, ShieldError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() && !self.done {
            if let Err(e) = self.fetch() {
                self.done = true;
                self.buf.clear();
                return Some(Err(e));
            }
        }
        let r = self.buf.pop_front()?;
        self.row += 1;
        Some(Ok(r))
    }
}

impl RowSource for SqliteSource {
    fn tables(&self) -> Vec<SourceTable> {
        self.tables.iter().map(|t| t.info.clone()).collect()
    }

    fn rows(&mut self, table: &str) -> Result<RowIter<'_>, ShieldError> {
        let t = self
            .tables
            .iter()
            .find(|t| t.info.name == table)
            .ok_or_else(|| no_table(&self.file, table))?;
        let list = if t.cols.is_empty() { "NULL" } else { &t.cols };
        let sql = match t.key {
            Some(k) => format!(
                "SELECT {k}, {list} FROM {} WHERE {k} >= ?1 ORDER BY {k} LIMIT {PAGE}",
                t.from
            ),
            None => format!(
                "SELECT {list} FROM {} ORDER BY {} LIMIT {PAGE} OFFSET ?1",
                t.from, t.order
            ),
        };
        Ok(Box::new(SqlRows {
            conn: &self.conn,
            file: &self.file,
            t,
            sql,
            last: i64::MIN,
            offset: 0,
            buf: std::collections::VecDeque::new(),
            row: 0,
            done: false,
        }))
    }

    fn file_name(&self) -> &str {
        &self.file
    }
}

// ----------------------------------------------------------- in memory ----

/// Rows held in memory: tests and the Postgres bridge (plan 47). `Debug`
/// shows the tables and row counts, never a cell (I8).
#[derive(Clone, Default)]
pub struct VecSource {
    pub tables: Vec<(SourceTable, Vec<Vec<Cell>>)>,
}

impl std::fmt::Debug for VecSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut l = f.debug_list();
        for (t, rows) in &self.tables {
            l.entry(&(t, rows.len()));
        }
        l.finish()
    }
}

impl RowSource for VecSource {
    fn tables(&self) -> Vec<SourceTable> {
        self.tables.iter().map(|t| t.0.clone()).collect()
    }

    fn rows(&mut self, table: &str) -> Result<RowIter<'_>, ShieldError> {
        let (_, rows) = self
            .tables
            .iter()
            .find(|t| t.0.name == table)
            .ok_or_else(|| no_table("data", table))?;
        Ok(Box::new(rows.iter().map(|r| Ok(r.clone()))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_source_temp_store_is_memory() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.db");
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch("CREATE TABLE a(x); INSERT INTO a VALUES (1);")
            .unwrap();
        drop(c);
        let s = SqliteSource::open(&p).unwrap();
        let ts: i64 = s
            .conn
            .query_row("PRAGMA temp_store", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ts, 2, "sorts must never spill values to temp files");
        // I7: no double-quoted-string fallback.
        assert!(s
            .conn
            .query_row("SELECT \"nosuchcol\" FROM a", [], |r| r.get::<_, i64>(0))
            .is_err());
    }

    /// I8: cells and in-memory rows print no value.
    #[test]
    fn cell_debug_has_no_values() {
        let cells = vec![
            Cell::Text("Anna Berg".into()),
            Cell::Int(4411),
            Cell::Real(44.11),
            Cell::Date("1980-04-11".into()),
            Cell::Bool(true),
            Cell::Null,
        ];
        let d = format!("{cells:?}");
        for v in ["Anna", "4411", "44.11", "1980"] {
            assert!(!d.contains(v), "{d}");
        }
        let src = VecSource {
            tables: vec![(
                SourceTable {
                    name: "people".into(),
                    columns: vec!["name".into()],
                },
                vec![vec![Cell::Text("Anna Berg".into())]],
            )],
        };
        let d = format!("{src:?}");
        assert!(!d.contains("Anna"), "{d}");
        assert!(d.contains("people"), "{d}");
    }

    #[test]
    fn delimiter_sniffing() {
        assert_eq!(sniff_delim(b"a,b,c\n1;2;3;4;5\n"), b',');
        assert_eq!(sniff_delim(b"a;b;\"c,d,e\"\n"), b';');
        assert_eq!(sniff_delim(b"a\tb\n"), b'\t');
        assert_eq!(sniff_delim(b"single\n"), b',');
    }

    #[test]
    fn uri_escapes_the_path() {
        let u = sqlite_uri(Path::new("/x/a b?#%.db"), "mode=ro");
        assert!(u.starts_with("file:"), "{u}");
        assert!(u.ends_with("a%20b%3F%23%25.db?mode=ro"), "{u}");
    }
}
