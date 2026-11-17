//! Plan 43: the read-only snapshot (R43-2, R43-3, R43-4). One SQLite file,
//! `snapshot.sqlite`, written once with `journal_mode=OFF`, then made
//! `0400` and hashed. Column types are inferred in a first pass over the
//! source; a second pass inserts the rows in batches of 10 000.

use crate::dataset::{
    ensure_private_dir, memory_temp_store, no_dqs, open_part_db, with_private_part,
};
use crate::error::ShieldError;
use crate::schema::ColType;
use crate::source::{
    quote_ident, sqlite_uri, src_err, Cell, RowSource, MAX_CELL_BYTES, MAX_COLUMNS, MAX_ROWS,
    MAX_TABLES,
};
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags};
use std::io::Read;
use std::path::{Path, PathBuf};

/// The snapshot's file name inside the dataset directory.
pub const SNAPSHOT_FILE: &str = "snapshot.sqlite";
const BATCH: u64 = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotInfo {
    pub path: PathBuf,
    /// `sha256:` + 64 lowercase hex of the file bytes.
    pub sha256: String,
    /// (snapshot name, source name, rows, [(snapshot column, source column, type)]).
    pub tables: Vec<SnapshotTable>,
}

/// (snapshot name, source name, rows, [(snapshot column, source column, type)]).
pub type SnapshotTable = (String, String, u64, Vec<(String, String, ColType)>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub table: String,
    pub rows_done: u64,
}

// ------------------------------------------------------------- names ----

/// R43-7 fold first (`æ→ae ø→oe å→aa ß→ss`, marks dropped, lower-case, every
/// run of non-alphanumerics, `_` included, becomes one separator), then R43-2:
/// lower-case, every character outside `[a-z0-9_]` becomes `_`,
/// leading and trailing `_` are dropped. An empty result is `fallback`; a
/// leading digit gets `fallback_` in front.
pub(crate) fn clean_name(raw: &str, fallback: &str) -> String {
    // R43-7 first: `Løn` is `loen`, `Beløb` is `beloeb`, `Kunde Nr.` is `kunde_nr`.
    let folded = crate::norm::normalize(raw).replace(' ', "_");
    let mut s: String = folded
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    s = s.trim_matches('_').to_string();
    if s.is_empty() {
        return fallback.to_string();
    }
    if s.as_bytes()[0].is_ascii_digit() {
        s = format!("{fallback}_{s}");
    }
    s
}

/// Cleaned names, made unique with `_2`, `_3`, ...
fn unique_names<'a>(raw: impl Iterator<Item = &'a str>, table: bool) -> Vec<String> {
    let fallback = if table { "t" } else { "c" };
    let mut out: Vec<String> = Vec::new();
    for r in raw {
        let mut base = clean_name(r, fallback);
        if table && base.starts_with("sqlite") {
            base = format!("t_{base}");
        }
        let mut name = base.clone();
        let mut k = 2;
        while out.contains(&name) {
            name = format!("{base}_{k}");
            k += 1;
        }
        out.push(name);
    }
    out
}

// ------------------------------------------------------------- types ----

pub(crate) fn parse_int(s: &str) -> Option<i64> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    let b = digits.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
        return None;
    }
    if s.starts_with('-') && digits == "0" {
        return None;
    }
    s.parse().ok()
}

/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`, finite.
pub(crate) fn parse_real(s: &str) -> Option<f64> {
    let b = s.strip_prefix('-').unwrap_or(s).as_bytes();
    let int_len = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if int_len == 0 || (int_len > 1 && b[0] == b'0') {
        return None;
    }
    let mut i = int_len;
    if b.get(i) == Some(&b'.') {
        let n = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        i += 1 + n;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let n = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        i += n;
    }
    if i != b.len() {
        return None;
    }
    // Digits only, beyond i64 (account numbers): TEXT, never a rounded REAL.
    if i == int_len && parse_int(s).is_none() {
        return None;
    }
    s.parse::<f64>().ok().filter(|f| f.is_finite())
}

/// I6: a Danish decimal comma, `-?\d+,\d+` or `-?\d{1,3}(\.\d{3})+,\d+`
/// (`.` groups thousands), as the exact `f64` (`1.234,50` is 1234.5).
pub(crate) fn parse_decimal_comma(s: &str) -> Option<f64> {
    let (neg, body) = match s.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, s),
    };
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    let (int, frac) = body.split_once(',')?;
    if !digits(frac) {
        return None;
    }
    let mut groups = int.split('.');
    let first = groups.next()?;
    let rest: Vec<&str> = groups.collect();
    let int_ok = if rest.is_empty() {
        digits(first)
    } else {
        digits(first) && first.len() <= 3 && rest.iter().all(|g| g.len() == 3 && digits(g))
    };
    if !int_ok {
        return None;
    }
    let plain = format!(
        "{}{}.{frac}",
        if neg { "-" } else { "" },
        int.replace('.', "")
    );
    plain.parse::<f64>().ok().filter(|f| f.is_finite())
}

/// R-22: `-?\d{1,3},\d{3}` is an English thousands group as much as a
/// Danish decimal (`1,234`): a column of only these is never REAL.
fn ambiguous_comma(s: &str) -> bool {
    let b = s.strip_prefix('-').unwrap_or(s);
    let Some((i, f)) = b.split_once(',') else {
        return false;
    };
    (1..=3).contains(&i.len())
        && f.len() == 3
        && i.bytes().chain(f.bytes()).all(|c| c.is_ascii_digit())
}

fn days_in(y: u32, m: u32) -> u32 {
    match m {
        2 if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `YYYY-MM-DD`, `DD-MM-YYYY`, `DD.MM.YYYY`, `DD/MM/YYYY` to ISO.
pub(crate) fn parse_date(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() != 10 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let p = &b[r];
        if p.iter().all(u8::is_ascii_digit) {
            p.iter()
                .try_fold(0u32, |a, d| Some(a * 10 + u32::from(d - b'0')))
        } else {
            None
        }
    };
    let (y, m, d) = if b[4] == b'-' && b[7] == b'-' {
        (num(0..4)?, num(5..7)?, num(8..10)?)
    } else if b[2] == b[5] && matches!(b[2], b'-' | b'.' | b'/') {
        (num(6..10)?, num(3..5)?, num(0..2)?)
    } else {
        return None;
    };
    if y == 0 || !(1..=12).contains(&m) || d == 0 || d > days_in(y, m) {
        return None;
    }
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

pub(crate) fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "ja" => Some(true),
        "false" | "no" | "nej" => Some(false),
        _ => None,
    }
}

/// Which types every non-empty cell of a column so far fits.
#[derive(Clone)]
struct Infer {
    int: bool,
    real: bool,
    /// I6: every non-empty cell is a Danish decimal comma (and the source
    /// allows them, R-22).
    dcomma: bool,
    /// R-22: some cell is not of the ambiguous `1,234` shape.
    dcomma_clear: bool,
    date: bool,
    boolean: bool,
    seen: bool,
}

impl Infer {
    fn new(decimal_comma: bool) -> Infer {
        Infer {
            int: true,
            real: true,
            dcomma: decimal_comma,
            dcomma_clear: false,
            date: true,
            boolean: true,
            seen: false,
        }
    }

    fn see(&mut self, c: &Cell) {
        let (i, r, dc, d, b) = match c {
            Cell::Null => return,
            Cell::Int(_) => (true, true, false, false, false),
            Cell::Real(_) => (false, true, false, false, false),
            Cell::Date(_) => (false, false, false, true, false),
            Cell::Bool(_) => (false, false, false, false, true),
            Cell::Text(s) => {
                let t = s.trim();
                if t.is_empty() {
                    return;
                }
                if !ambiguous_comma(t) {
                    self.dcomma_clear = true;
                }
                (
                    self.int && parse_int(t).is_some(),
                    self.real && parse_real(t).is_some(),
                    self.dcomma && parse_decimal_comma(t).is_some(),
                    self.date && parse_date(t).is_some(),
                    self.boolean && parse_bool(t).is_some(),
                )
            }
        };
        self.seen = true;
        self.int &= i;
        self.real &= r;
        self.dcomma &= dc;
        self.date &= d;
        self.boolean &= b;
    }

    fn ty(&self) -> ColType {
        if !self.seen {
            ColType::Text
        } else if self.int {
            ColType::Integer
        } else if self.real || self.decimal_comma() {
            ColType::Real
        } else if self.date {
            ColType::Date
        } else if self.boolean {
            ColType::Bool
        } else {
            ColType::Text
        }
    }
}

impl Infer {
    /// The column is REAL through decimal commas (never mixed with dot
    /// decimals, which give TEXT).
    fn decimal_comma(&self) -> bool {
        self.seen && !self.int && !self.real && self.dcomma && self.dcomma_clear
    }
}

fn decl(t: ColType) -> &'static str {
    match t {
        ColType::Integer => "INTEGER",
        ColType::Real => "REAL",
        ColType::Text => "TEXT",
        ColType::Date => "DATE",
        ColType::Bool => "BOOL",
    }
}

/// The stored value of a cell in a column of type `ty` (`dcomma`: a REAL
/// column of decimal commas); None if the cell does not fit (the source
/// changed between the passes).
fn convert(c: Cell, ty: ColType, dcomma: bool) -> Option<Value> {
    if let Cell::Text(s) = &c {
        if s.trim().is_empty() {
            return Some(Value::Null);
        }
    }
    Some(match (ty, c) {
        (_, Cell::Null) => Value::Null,
        (ColType::Text, Cell::Text(s) | Cell::Date(s)) => Value::Text(s),
        (ColType::Text, Cell::Int(i)) => Value::Text(i.to_string()),
        (ColType::Text, Cell::Real(f)) => Value::Text(f.to_string()),
        (ColType::Text, Cell::Bool(b)) => Value::Text(b.to_string()),
        (ColType::Integer, Cell::Int(i)) => Value::Integer(i),
        (ColType::Integer, Cell::Text(s)) => Value::Integer(parse_int(s.trim())?),
        (ColType::Real, Cell::Int(i)) => Value::Real(i as f64),
        (ColType::Real, Cell::Real(f)) => Value::Real(f),
        (ColType::Real, Cell::Text(s)) if dcomma => Value::Real(parse_decimal_comma(s.trim())?),
        (ColType::Real, Cell::Text(s)) => Value::Real(parse_real(s.trim())?),
        (ColType::Date, Cell::Date(s)) => Value::Text(s),
        (ColType::Date, Cell::Text(s)) => Value::Text(parse_date(s.trim())?),
        (ColType::Bool, Cell::Bool(b)) => Value::Integer(i64::from(b)),
        (ColType::Bool, Cell::Text(s)) => Value::Integer(i64::from(parse_bool(s.trim())?)),
        _ => return None,
    })
}

// ----------------------------------------------------------- building ----

const CHANGED: ShieldError = ShieldError::Corrupt("the source changed during the import");

fn sql_err(_: rusqlite::Error) -> ShieldError {
    ShieldError::Sqlite("could not write the snapshot".into())
}

/// Builds `out/snapshot.sqlite` from `src`. `out` is the stage directory:
/// made 0700 if missing, else it must be ours and not a symlink (and is
/// tightened to 0700). A CSV keeps its second-pass copy inside `out` and
/// removes it at the end; every file is created 0600 and never through a
/// symlink.
pub fn build_snapshot(
    src: &mut dyn RowSource,
    out: &Path,
    progress: &mut dyn FnMut(Progress),
) -> Result<SnapshotInfo, ShieldError> {
    ensure_private_dir(out)?;
    src.set_spool_dir(out);
    let r = build_in(src, out, progress);
    src.release();
    r
}

fn build_in(
    src: &mut dyn RowSource,
    out: &Path,
    progress: &mut dyn FnMut(Progress),
) -> Result<SnapshotInfo, ShieldError> {
    // A leftover part file (or anything planted at its name) refuses: the
    // caller clears a stale stage.
    let (path, tables) =
        with_private_part(out, SNAPSHOT_FILE, |part| write_tables(src, part, progress))?;
    let sha256 = match hash_file(&path) {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
    };
    Ok(SnapshotInfo {
        path,
        sha256,
        tables,
    })
}

fn write_tables(
    src: &mut dyn RowSource,
    part: &Path,
    progress: &mut dyn FnMut(Progress),
) -> Result<Vec<SnapshotTable>, ShieldError> {
    let file = src.file_name().to_string();
    let first_row = src.first_data_row();
    let tables = src.tables();
    if tables.is_empty() {
        return Err(src_err(&file, None, None, None, "the source has no tables"));
    }
    if tables.len() > MAX_TABLES {
        return Err(ShieldError::Limit("more than 64 tables"));
    }
    if tables.iter().any(|t| t.columns.len() > MAX_COLUMNS) {
        return Err(ShieldError::Limit("more than 512 columns in a table"));
    }
    let tnames = unique_names(tables.iter().map(|t| t.name.as_str()), true);

    let conn = open_part_db(part, "could not write the snapshot")?;

    let mut out = Vec::with_capacity(tables.len());
    for (t, tname) in tables.iter().zip(tnames) {
        let ncol = t.columns.len();
        let cnames = unique_names(t.columns.iter().map(String::as_str), false);
        let at = |i: u64| Some(first_row + i);
        let err = |col: Option<usize>, i: u64, why| {
            src_err(
                &file,
                Some(&t.name),
                col.map(|c| t.columns[c].as_str()),
                at(i),
                why,
            )
        };

        // Pass 1: limits, widths and types.
        let mut inf = vec![Infer::new(src.decimal_comma()); ncol];
        let mut n = 0u64;
        for row in src.rows(&t.name)? {
            let row = row?;
            if n == MAX_ROWS {
                return Err(ShieldError::Limit("more than 50 000 000 rows in a table"));
            }
            if row.len() != ncol {
                return Err(err(None, n, "this row has a different number of cells"));
            }
            for (i, c) in row.iter().enumerate() {
                if let Cell::Text(s) | Cell::Date(s) = c {
                    if s.len() > MAX_CELL_BYTES {
                        return Err(err(
                            Some(i),
                            n,
                            "over a limit: a cell is longer than 64 KiB",
                        ));
                    }
                }
                inf[i].see(c);
            }
            n += 1;
        }
        let types: Vec<ColType> = inf.iter().map(Infer::ty).collect();
        let dcomma: Vec<bool> = inf.iter().map(Infer::decimal_comma).collect();

        // The table.
        let qt = quote_ident(&tname);
        let mut create = format!("CREATE TABLE {qt} (\"_rowid\" INTEGER PRIMARY KEY");
        for (c, ty) in cnames.iter().zip(&types) {
            create.push_str(&format!(", {} {}", quote_ident(c), decl(*ty)));
        }
        create.push(')');
        conn.execute_batch(&create).map_err(sql_err)?;
        let insert = if ncol == 0 {
            format!("INSERT INTO {qt} DEFAULT VALUES")
        } else {
            let cols: Vec<String> = cnames.iter().map(|c| quote_ident(c)).collect();
            let marks: Vec<String> = (1..=ncol).map(|i| format!("?{i}")).collect();
            format!(
                "INSERT INTO {qt} ({}) VALUES ({})",
                cols.join(", "),
                marks.join(", ")
            )
        };

        // Pass 2: insert.
        conn.execute_batch("BEGIN").map_err(sql_err)?;
        let mut m = 0u64;
        {
            let mut st = conn.prepare(&insert).map_err(sql_err)?;
            for row in src.rows(&t.name)? {
                let row = row?;
                if m == n || row.len() != ncol {
                    return Err(CHANGED);
                }
                for (i, (c, ty)) in row.into_iter().zip(&types).enumerate() {
                    let v = convert(c, *ty, dcomma[i]).ok_or(CHANGED)?;
                    st.raw_bind_parameter(i + 1, &v).map_err(sql_err)?;
                }
                st.raw_execute().map_err(sql_err)?;
                m += 1;
                if m.is_multiple_of(BATCH) {
                    conn.execute_batch("COMMIT; BEGIN").map_err(sql_err)?;
                    progress(Progress {
                        table: tname.clone(),
                        rows_done: m,
                    });
                }
            }
        }
        conn.execute_batch("COMMIT").map_err(sql_err)?;
        if m != n {
            return Err(CHANGED);
        }
        progress(Progress {
            table: tname.clone(),
            rows_done: m,
        });
        let cols = cnames
            .into_iter()
            .zip(t.columns.iter().cloned())
            .zip(types)
            .map(|((a, b), ty)| (a, b, ty))
            .collect();
        out.push((tname, t.name.clone(), n, cols));
    }
    conn.close().map_err(|(_, e)| sql_err(e))?;
    Ok(out)
}

fn hash_file(path: &Path) -> Result<String, ShieldError> {
    let bad = |_| ShieldError::Io("could not read the snapshot".into());
    let mut f = std::fs::File::open(path).map_err(bad)?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).map_err(bad)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let d = ctx.finish();
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for b in d.as_ref() {
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
}

/// Opens a snapshot read-only: `file:<path>?mode=ro&immutable=1`.
/// `temp_store=MEMORY`: no sort or GROUP BY of a reader spills values to a
/// temp file.
pub fn open_ro(path: &Path) -> Result<Connection, ShieldError> {
    let bad = || ShieldError::Sqlite("could not open the snapshot".into());
    let conn = Connection::open_with_flags(
        sqlite_uri(path, "mode=ro&immutable=1"),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| bad())?;
    no_dqs(&conn).map_err(|()| bad())?;
    memory_temp_store(&conn).map_err(|_| bad())?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_cleaning() {
        assert_eq!(clean_name("Kunde Nr.", "c"), "kunde_nr");
        assert_eq!(clean_name("Løn", "c"), "loen");
        assert_eq!(clean_name("CPR-nr", "c"), "cpr_nr");
        assert_eq!(clean_name("Beløb", "c"), "beloeb");
        assert_eq!(clean_name("2024 Sales", "c"), "c_2024_sales");
        assert_eq!(clean_name("***", "c"), "c");
        assert_eq!(clean_name("_rowid", "c"), "rowid");
        let u = unique_names(["a b", "A-B", "a_b", "sqlite_x"].into_iter(), true);
        assert_eq!(u, vec!["a_b", "a_b_2", "a_b_3", "t_sqlite_x"]);
    }

    #[test]
    fn parsers() {
        assert_eq!(parse_int("42"), Some(42));
        assert_eq!(parse_int("-7"), Some(-7));
        for bad in ["007", "-0", "", "1.0", "+1", "1 2", "99999999999999999999"] {
            assert_eq!(parse_int(bad), None, "{bad}");
        }
        assert_eq!(parse_real("12.25"), Some(12.25));
        assert_eq!(parse_real("1e3"), Some(1000.0));
        assert_eq!(parse_real("0.5"), Some(0.5));
        for bad in ["NaN", "inf", ".5", "5.", "01.5", "1,5", "1e"] {
            assert_eq!(parse_real(bad), None, "{bad}");
        }
        assert_eq!(parse_date("2024-02-29").as_deref(), Some("2024-02-29"));
        assert_eq!(parse_date("31-01-2024").as_deref(), Some("2024-01-31"));
        assert_eq!(parse_date("31.01.2024").as_deref(), Some("2024-01-31"));
        assert_eq!(parse_date("31/01/2024").as_deref(), Some("2024-01-31"));
        for bad in [
            "2023-02-29",
            "31-04-2024",
            "2024/01/31",
            "31-01.2024",
            "1.1.2024",
        ] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
        assert_eq!(parse_bool("TRUE"), Some(true));
        assert_eq!(parse_bool("Nej"), Some(false));
        assert_eq!(parse_bool("1"), None);
    }

    #[test]
    fn inference_order() {
        let ty = |cells: &[Cell]| {
            let mut i = Infer::new(true);
            cells.iter().for_each(|c| i.see(c));
            i.ty()
        };
        assert_eq!(ty(&[Cell::Text("1".into()), Cell::Null]), ColType::Integer);
        assert_eq!(ty(&[Cell::Int(1), Cell::Real(1.5)]), ColType::Real);
        assert_eq!(
            ty(&[Cell::Text("1".into()), Cell::Text("x".into())]),
            ColType::Text
        );
        assert_eq!(ty(&[Cell::Null]), ColType::Text);
        assert_eq!(
            ty(&[
                Cell::Date("2024-01-01".into()),
                Cell::Text("02.01.2024".into())
            ]),
            ColType::Date
        );
        assert_eq!(
            ty(&[Cell::Bool(true), Cell::Text("nej".into())]),
            ColType::Bool
        );
        assert_eq!(ty(&[Cell::Text("0800".into())]), ColType::Text);
        assert_eq!(ty(&[Cell::Text("12,50".into())]), ColType::Real);
        assert_eq!(
            ty(&[Cell::Text("12,50".into()), Cell::Text("13".into())]),
            ColType::Text
        );
        assert_eq!(
            ty(&[Cell::Text("12,50".into()), Cell::Real(1.5)]),
            ColType::Text
        );
        assert_eq!(ty(&[Cell::Text("1,234".into())]), ColType::Text);
        assert_eq!(
            ty(&[Cell::Text("1,234".into()), Cell::Text("1,5".into())]),
            ColType::Real
        );
        let mut i = Infer::new(false);
        i.see(&Cell::Text("12,50".into()));
        assert_eq!(i.ty(), ColType::Text);
        assert_eq!(parse_decimal_comma("1.234,50"), Some(1234.5));
        assert_eq!(parse_decimal_comma("-12,5"), Some(-12.5));
        for bad in ["1,", ",5", "1.23,5", "1234.567,8", "12.50", "1,2,3", "a,5"] {
            assert_eq!(parse_decimal_comma(bad), None, "{bad}");
        }
    }
}
