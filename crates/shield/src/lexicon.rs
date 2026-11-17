//! Plan 43: the lexicon (R43-6), entity resolution (spec §2.1.6) and "did you
//! mean" (R43-8, spec §2.1.7).
//!
//! `lexicon.sqlite` is a second local SQLite file beside `snapshot.sqlite`.
//! It holds plaintext normalized names and literal values, so it is written
//! the way the snapshot is (a new 0600 part file that never follows a
//! symlink, `journal_mode=OFF`, sealed 0400, renamed in place) and is only
//! ever opened `mode=ro&immutable=1`. It never leaves the daemon.
//!
//! Tables:
//! - `entity(norm, sorted, key, tbl, display, rid)`: one row per entity row;
//!   `rid` is the snapshot `_rowid`, so the `show` columns are read from the
//!   snapshot by primary key, only for the candidates returned.
//! - `prefix(p, norm)`: the first two characters of each token of each
//!   distinct `norm` (the did-you-mean search space).
//! - `literal(norm, tbl, col, value, count)`: every distinct value of the
//!   `identifier` and `quasi` columns that are not entity name columns, and
//!   of the `public` columns.
//! - `spec(tbl, show)`: each entity table's `show` columns (JSON).

use crate::dataset::{memory_temp_store, open_part_db, with_private_part};
use crate::error::ShieldError;
use crate::norm::{token_spans, tokens};
use crate::schema::{ColType, ColumnClass, EntitySpec, Schema};
use crate::snapshot::{open_ro, SNAPSHOT_FILE};
use crate::source::{quote_ident, sqlite_uri};
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// The lexicon's file name inside the dataset directory.
pub const LEXICON_FILE: &str = "lexicon.sqlite";
/// The most candidates [`Lexicon::resolve`] returns.
pub const MAX_CANDIDATES: usize = 20;
/// R43-8: the most names one did-you-mean lookup compares.
pub const SUGGEST_CAP: usize = 50_000;
/// More distinct token prefixes than this in a phrase: no suggestion.
const MAX_PREFIXES: usize = 32;
const BATCH: u64 = 50_000;

// ------------------------------------------------------------- types ----

/// One entity row a phrase resolved to. `display` and `show` hold real
/// values: local only, and left out of `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Candidate {
    pub key: i64,
    pub table: String,
    /// The name as stored: the `names` columns joined by a space.
    pub display: String,
    /// The entity's `show` columns: (column, value as text; "" for NULL).
    pub show: Vec<(String, String)>,
}

impl fmt::Debug for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cols: Vec<&str> = self.show.iter().map(|s| s.0.as_str()).collect();
        f.debug_struct("Candidate")
            .field("key", &self.key)
            .field("table", &self.table)
            .field("display", &"<hidden>")
            .field("show", &cols)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolve {
    None,
    One(Candidate),
    /// At most [`MAX_CANDIDATES`]; more sets the `too_many` flag.
    Many(Vec<Candidate>),
}

/// A literal value found in a question: (table, column), the value as
/// stored, and how many rows hold it.
#[derive(Clone, PartialEq, Eq)]
pub struct LiteralHit {
    pub column: (String, String),
    pub value: String,
    pub count: u64,
}

impl fmt::Debug for LiteralHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiteralHit")
            .field("column", &self.column)
            .field("value", &"<hidden>")
            .field("count", &self.count)
            .finish()
    }
}

/// A span of a question: `start..end` are byte offsets into the question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanHit {
    Entity {
        start: usize,
        end: usize,
        table: String,
    },
    Literal {
        start: usize,
        end: usize,
        hit: LiteralHit,
    },
}

// ---------------------------------------------------------- building ----

fn wr(_: rusqlite::Error) -> ShieldError {
    ShieldError::Sqlite("could not write the lexicon".into())
}

fn rd(_: rusqlite::Error) -> ShieldError {
    ShieldError::Sqlite("could not read the snapshot".into())
}

fn lx(_: rusqlite::Error) -> ShieldError {
    ShieldError::Sqlite("could not read the lexicon".into())
}

/// A cell as text: numbers in plain notation, a `bool` column as
/// `true`/`false`; NULL and blobs give None.
fn cell_text(v: ValueRef<'_>, ty: Option<ColType>) -> Option<String> {
    match v {
        ValueRef::Null | ValueRef::Blob(_) => None,
        ValueRef::Integer(i) if ty == Some(ColType::Bool) => Some((i != 0).to_string()),
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Text(b) => Some(String::from_utf8_lossy(b).into_owned()),
    }
}

/// Builds the lexicon from a finished snapshot. `out` is the lexicon's file
/// path (`.../lexicon.sqlite`), or a directory to put `lexicon.sqlite` in.
/// Its directory is made private like the snapshot's; an existing lexicon or
/// anything at the part path refuses. `Lexicon::open` finds the snapshot
/// beside the lexicon, so build it into the snapshot's directory.
pub fn build_lexicon(snapshot: &Path, schema: &Schema, out: &Path) -> Result<(), ShieldError> {
    let path: PathBuf = match std::fs::symlink_metadata(out) {
        Ok(md) if md.is_dir() => out.join(LEXICON_FILE),
        _ => out.to_path_buf(),
    };
    let name = path
        .file_name()
        .ok_or_else(|| ShieldError::Io("the lexicon path has no file name".into()))?
        .to_string_lossy()
        .into_owned();
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let snap = open_ro(snapshot)?;
    // A leftover part file (or anything planted at its name) refuses.
    with_private_part(&dir, &name, |part| write_lexicon(&snap, schema, part))?;
    Ok(())
}

fn write_lexicon(snap: &Connection, schema: &Schema, part: &Path) -> Result<(), ShieldError> {
    let conn = open_part_db(part, "could not write the lexicon")?;
    conn.execute_batch(
        "CREATE TABLE spec(tbl TEXT NOT NULL, show TEXT NOT NULL);
         CREATE TABLE entity(norm TEXT NOT NULL, sorted TEXT NOT NULL, key INTEGER NOT NULL,
                             tbl TEXT NOT NULL, display TEXT NOT NULL, rid INTEGER NOT NULL);
         CREATE TABLE prefix(p TEXT NOT NULL, norm TEXT NOT NULL);
         CREATE TABLE literal(norm TEXT NOT NULL, tbl TEXT NOT NULL, col TEXT NOT NULL,
                              value TEXT NOT NULL, count INTEGER NOT NULL);",
    )
    .map_err(wr)?;

    for e in &schema.entities {
        write_entities(&conn, snap, schema, e)?;
    }
    write_literals(&conn, snap, schema)?;

    // Indexes after the bulk inserts.
    conn.execute_batch(
        "CREATE INDEX entity_norm ON entity(norm);
         CREATE INDEX entity_sorted ON entity(sorted, tbl);",
    )
    .map_err(wr)?;
    write_prefixes(&conn)?;
    conn.execute_batch(
        "CREATE INDEX prefix_p ON prefix(p, norm);
         CREATE INDEX literal_norm ON literal(norm);",
    )
    .map_err(wr)?;
    conn.close().map_err(|(_, e)| wr(e))
}

fn write_entities(
    conn: &Connection,
    snap: &Connection,
    schema: &Schema,
    e: &EntitySpec,
) -> Result<(), ShieldError> {
    let show: Vec<(String, Option<ColType>)> = e
        .show
        .iter()
        .map(|c| (c.clone(), schema.column(&e.table, c).map(|x| x.ty)))
        .collect();
    let show_json = serde_json::to_string(&show)
        .map_err(|_| ShieldError::Io("could not write the lexicon".into()))?;
    conn.execute(
        "INSERT INTO spec(tbl, show) VALUES (?1, ?2)",
        params![e.table, show_json],
    )
    .map_err(wr)?;

    let cols: Vec<String> = std::iter::once(&e.key)
        .chain(&e.names)
        .map(|c| quote_ident(c))
        .collect();
    let sql = format!(
        "SELECT \"_rowid\", {} FROM {}",
        cols.join(", "),
        quote_ident(&e.table)
    );
    let mut sel = snap.prepare(&sql).map_err(rd)?;
    let mut rows = sel.query([]).map_err(rd)?;
    conn.execute_batch("BEGIN").map_err(wr)?;
    let mut ins = conn
        .prepare(
            "INSERT INTO entity(norm, sorted, key, tbl, display, rid)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .map_err(wr)?;
    let mut n = 0u64;
    let mut parts: Vec<String> = Vec::with_capacity(e.names.len());
    while let Some(r) = rows.next().map_err(rd)? {
        let rid: i64 = r.get(0).map_err(rd)?;
        let key = match r.get_ref(1).map_err(rd)? {
            ValueRef::Integer(k) => k,
            // A row without a key cannot be bound: it is not resolvable.
            ValueRef::Null => continue,
            _ => {
                return Err(ShieldError::Source {
                    file: SNAPSHOT_FILE.into(),
                    table: Some(e.table.clone()),
                    column: Some(e.key.clone()),
                    row: None,
                    why: "the entity key is not an integer",
                })
            }
        };
        parts.clear();
        for i in 0..e.names.len() {
            if let Some(s) = cell_text(r.get_ref(2 + i).map_err(rd)?, None) {
                let s = s.trim();
                if !s.is_empty() {
                    parts.push(s.to_string());
                }
            }
        }
        let display = parts.join(" ");
        let mut t = tokens(&display);
        if t.is_empty() {
            continue;
        }
        let norm = t.join(" ");
        t.sort_unstable();
        let sorted = t.join(" ");
        ins.execute(params![norm, sorted, key, e.table, display, rid])
            .map_err(wr)?;
        n += 1;
        if n.is_multiple_of(BATCH) {
            conn.execute_batch("COMMIT; BEGIN").map_err(wr)?;
        }
    }
    drop(ins);
    conn.execute_batch("COMMIT").map_err(wr)
}

fn write_literals(
    conn: &Connection,
    snap: &Connection,
    schema: &Schema,
) -> Result<(), ShieldError> {
    let mut ins = conn
        .prepare("INSERT INTO literal(norm, tbl, col, value, count) VALUES (?1, ?2, ?3, ?4, ?5)")
        .map_err(wr)?;
    conn.execute_batch("BEGIN").map_err(wr)?;
    let mut n = 0u64;
    for t in &schema.tables {
        let is_name = |c: &str| {
            schema
                .entities
                .iter()
                .any(|e| e.table == t.name && e.names.iter().any(|x| x == c))
        };
        for c in &t.columns {
            let lit = match c.class {
                ColumnClass::Identifier | ColumnClass::Quasi => !is_name(&c.name),
                ColumnClass::Public => true,
                ColumnClass::Sensitive | ColumnClass::FreeText => false,
            };
            if !lit {
                continue;
            }
            let q = quote_ident(&c.name);
            let sql = format!(
                "SELECT {q}, COUNT(*) FROM {} WHERE {q} IS NOT NULL GROUP BY {q}",
                quote_ident(&t.name)
            );
            let mut sel = snap.prepare(&sql).map_err(rd)?;
            let mut rows = sel.query([]).map_err(rd)?;
            while let Some(r) = rows.next().map_err(rd)? {
                let Some(value) = cell_text(r.get_ref(0).map_err(rd)?, Some(c.ty)) else {
                    continue;
                };
                let count: i64 = r.get(1).map_err(rd)?;
                let norm = tokens(&value).join(" ");
                if norm.is_empty() {
                    continue;
                }
                ins.execute(params![norm, t.name, c.name, value, count])
                    .map_err(wr)?;
                n += 1;
                if n.is_multiple_of(BATCH) {
                    conn.execute_batch("COMMIT; BEGIN").map_err(wr)?;
                }
            }
        }
    }
    conn.execute_batch("COMMIT").map_err(wr)
}

fn prefix_of(token: &str) -> String {
    token.chars().take(2).collect()
}

fn write_prefixes(conn: &Connection) -> Result<(), ShieldError> {
    conn.execute_batch("BEGIN").map_err(wr)?;
    {
        let mut sel = conn
            .prepare("SELECT DISTINCT norm FROM entity ORDER BY norm")
            .map_err(wr)?;
        let mut ins = conn
            .prepare("INSERT INTO prefix(p, norm) VALUES (?1, ?2)")
            .map_err(wr)?;
        let mut rows = sel.query([]).map_err(wr)?;
        let mut seen: Vec<String> = Vec::new();
        while let Some(r) = rows.next().map_err(wr)? {
            let norm: String = r.get(0).map_err(wr)?;
            seen.clear();
            for tok in norm.split(' ') {
                let p = prefix_of(tok);
                if !seen.contains(&p) {
                    ins.execute(params![p, norm]).map_err(wr)?;
                    seen.push(p);
                }
            }
        }
    }
    conn.execute_batch("COMMIT").map_err(wr)
}

// ------------------------------------------------------------ lookups ----

/// The read-only lexicon, with the snapshot beside it for the `show`
/// columns.
pub struct Lexicon {
    conn: Connection,
    snap: Connection,
    /// Entity table → its `show` columns and their types.
    show: HashMap<String, Vec<(String, Option<ColType>)>>,
}

impl fmt::Debug for Lexicon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lexicon { .. }")
    }
}

impl Lexicon {
    /// Opens `path` (a `lexicon.sqlite`) read-only, `mode=ro&immutable=1`,
    /// and the `snapshot.sqlite` in the same directory the same way.
    pub fn open(path: &Path) -> Result<Lexicon, ShieldError> {
        let conn = Connection::open_with_flags(
            sqlite_uri(path, "mode=ro&immutable=1"),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| ShieldError::Sqlite("could not open the lexicon".into()))?;
        memory_temp_store(&conn)
            .map_err(|_| ShieldError::Sqlite("could not open the lexicon".into()))?;
        let mut show = HashMap::new();
        {
            let mut st = conn.prepare("SELECT tbl, show FROM spec").map_err(lx)?;
            let mut rows = st.query([]).map_err(lx)?;
            while let Some(r) = rows.next().map_err(lx)? {
                let tbl: String = r.get(0).map_err(lx)?;
                let js: String = r.get(1).map_err(lx)?;
                let cols: Vec<(String, Option<ColType>)> = serde_json::from_str(&js)
                    .map_err(|_| ShieldError::Corrupt("the lexicon is damaged"))?;
                show.insert(tbl, cols);
            }
        }
        let snap = open_ro(&path.with_file_name(SNAPSHOT_FILE))?;
        Ok(Lexicon { conn, snap, show })
    }

    /// A candidate with its `show` columns read from the snapshot.
    fn candidate(
        &self,
        key: i64,
        table: String,
        display: String,
        rid: i64,
    ) -> Result<Candidate, ShieldError> {
        let cols = self.show.get(&table).map(Vec::as_slice).unwrap_or(&[]);
        let mut show = Vec::with_capacity(cols.len());
        if !cols.is_empty() {
            let list: Vec<String> = cols.iter().map(|c| quote_ident(&c.0)).collect();
            let sql = format!(
                "SELECT {} FROM {} WHERE \"_rowid\" = ?1",
                list.join(", "),
                quote_ident(&table)
            );
            let mut st = self.snap.prepare_cached(&sql).map_err(rd)?;
            let mut rows = st.query([rid]).map_err(rd)?;
            let r = rows.next().map_err(rd)?.ok_or(ShieldError::Corrupt(
                "the lexicon does not match the snapshot",
            ))?;
            for (i, (c, ty)) in cols.iter().enumerate() {
                let v = cell_text(r.get_ref(i).map_err(rd)?, *ty).unwrap_or_default();
                show.push((c.clone(), v));
            }
        }
        Ok(Candidate {
            key,
            table,
            display,
            show,
        })
    }

    /// Resolves `phrase` to rows of `entity_table` by its normalized,
    /// name-order-free key. Returns up to [`MAX_CANDIDATES`] candidates in
    /// key order; the flag is true when there were more.
    pub fn resolve(
        &self,
        entity_table: &str,
        phrase: &str,
    ) -> Result<(Resolve, bool), ShieldError> {
        let mut t = tokens(phrase);
        if t.is_empty() {
            return Ok((Resolve::None, false));
        }
        t.sort_unstable();
        let sorted = t.join(" ");
        let mut st = self
            .conn
            .prepare_cached(
                "SELECT key, display, rid FROM entity WHERE sorted = ?1 AND tbl = ?2
                 ORDER BY key, rid LIMIT ?3",
            )
            .map_err(lx)?;
        let mut rows = st
            .query(params![sorted, entity_table, MAX_CANDIDATES as i64 + 1])
            .map_err(lx)?;
        let mut found: Vec<(i64, String, i64)> = Vec::new();
        while let Some(r) = rows.next().map_err(lx)? {
            found.push((
                r.get(0).map_err(lx)?,
                r.get(1).map_err(lx)?,
                r.get(2).map_err(lx)?,
            ));
        }
        let too_many = found.len() > MAX_CANDIDATES;
        found.truncate(MAX_CANDIDATES);
        let mut c = Vec::with_capacity(found.len());
        for (key, display, rid) in found {
            c.push(self.candidate(key, entity_table.to_string(), display, rid)?);
        }
        Ok((
            match c.len() {
                0 => Resolve::None,
                1 => Resolve::One(c.remove(0)),
                _ => Resolve::Many(c),
            },
            too_many,
        ))
    }

    /// The entity table whose name has this sorted key (the first by name
    /// when several tables have it).
    fn entity_table(&self, sorted: &str) -> Result<Option<String>, ShieldError> {
        self.conn
            .prepare_cached("SELECT tbl FROM entity WHERE sorted = ?1 ORDER BY tbl LIMIT 1")
            .map_err(lx)?
            .query_row([sorted], |r| r.get(0))
            .optional()
            .map_err(lx)
    }

    /// The literal with this normalized value (the most common one when
    /// several columns hold it).
    fn literal(&self, norm: &str) -> Result<Option<LiteralHit>, ShieldError> {
        self.conn
            .prepare_cached(
                "SELECT tbl, col, value, count FROM literal WHERE norm = ?1
                 ORDER BY count DESC, tbl, col, value LIMIT 1",
            )
            .map_err(lx)?
            .query_row([norm], |r| {
                Ok(LiteralHit {
                    column: (r.get(0)?, r.get(1)?),
                    value: r.get(2)?,
                    count: r.get::<_, i64>(3)?.max(0) as u64,
                })
            })
            .optional()
            .map_err(lx)
    }

    /// The entity names and literal values in `question`.
    ///
    /// Exact semantics: the question is cut into normalized tokens
    /// (R43-7). The scan is greedy, left to right. At each start token it
    /// tries the longest run first, `min(max_tokens, tokens left)` tokens,
    /// then one fewer, down to 1. A run is an entity when its tokens, sorted,
    /// equal an entity name's sorted key (in any entity table; the first
    /// table by name), else a literal when its normalized text equals a
    /// literal's (the most common one; ties by table, column, value). An
    /// entity beats a literal of the same length. On a hit the span is
    /// emitted and the scan continues after its last token; with no hit it
    /// moves on one token. So spans never overlap and come in question
    /// order, and an earlier start wins over a longer match that starts
    /// later. `start..end` are byte offsets into `question`, from the
    /// first byte of the first token to the last byte of the last token,
    /// so the separators between tokens (`, `) are inside the span.
    /// `max_tokens == 0` finds nothing.
    pub fn find_spans(
        &self,
        question: &str,
        max_tokens: usize,
    ) -> Result<Vec<SpanHit>, ShieldError> {
        let toks = token_spans(question);
        let mut out = Vec::new();
        let mut i = 0;
        while i < toks.len() {
            let mut hit = None;
            for len in (1..=max_tokens.min(toks.len() - i)).rev() {
                let words: Vec<&str> = toks[i..i + len].iter().map(|t| t.0.as_str()).collect();
                let (start, end) = (toks[i].1, toks[i + len - 1].2);
                let mut sw = words.clone();
                sw.sort_unstable();
                if let Some(table) = self.entity_table(&sw.join(" "))? {
                    hit = Some((len, SpanHit::Entity { start, end, table }));
                    break;
                }
                if let Some(h) = self.literal(&words.join(" "))? {
                    hit = Some((len, SpanHit::Literal { start, end, hit: h }));
                    break;
                }
            }
            match hit {
                Some((len, span)) => {
                    out.push(span);
                    i += len;
                }
                None => i += 1,
            }
        }
        Ok(out)
    }

    /// R43-8: the one closest entity name to `phrase`, by Damerau-Levenshtein
    /// on normalized full names (in the given order or both sorted, whichever
    /// is closer). Qualifies at a distance ≤ 2 and ≤ 25 % of the query's
    /// length (rounded down, at least 1); given only when exactly one
    /// distinct name has the smallest distance. The names compared share a
    /// token's first two characters with the query; over [`SUGGEST_CAP`] of
    /// them gives no suggestion. The candidate is the name's first row: a
    /// "yes" resolves its `display` again with [`Lexicon::resolve`].
    pub fn did_you_mean(&self, phrase: &str) -> Result<Option<Candidate>, ShieldError> {
        let qt = tokens(phrase);
        if qt.is_empty() {
            return Ok(None);
        }
        let q = qt.join(" ");
        let qs = sorted_join(&q);
        let mut prefixes: Vec<String> = Vec::new();
        for t in &qt {
            let p = prefix_of(t);
            if !prefixes.contains(&p) {
                prefixes.push(p);
            }
        }
        if prefixes.len() > MAX_PREFIXES {
            return Ok(None);
        }
        let marks = vec!["?"; prefixes.len()].join(", ");
        let sql = format!(
            "SELECT DISTINCT norm FROM prefix WHERE p IN ({marks}) LIMIT {}",
            SUGGEST_CAP + 1
        );
        let mut norms: Vec<String> = Vec::new();
        {
            let mut st = self.conn.prepare_cached(&sql).map_err(lx)?;
            let mut rows = st
                .query(rusqlite::params_from_iter(prefixes.iter()))
                .map_err(lx)?;
            while let Some(r) = rows.next().map_err(lx)? {
                norms.push(r.get(0).map_err(lx)?);
            }
        }
        if norms.len() > SUGGEST_CAP {
            return Ok(None);
        }

        let qlen = q.chars().count();
        let limit = (qlen / 4).clamp(1, 2);
        // (distance, sorted key, norm) of the best; `tie` when another
        // distinct name (another sorted key) is as close.
        let mut best: Option<(usize, String, &str)> = None;
        let mut tie = false;
        for n in &norms {
            if n.chars().count().abs_diff(qlen) > limit {
                continue;
            }
            let ns = sorted_join(n);
            let d = strsim::damerau_levenshtein(&q, n).min(strsim::damerau_levenshtein(&qs, &ns));
            if d > limit {
                continue;
            }
            match &best {
                Some((bd, bs, _)) if d == *bd => {
                    if *bs != ns {
                        tie = true;
                    }
                }
                Some((bd, _, _)) if d > *bd => {}
                _ => {
                    best = Some((d, ns, n.as_str()));
                    tie = false;
                }
            }
        }
        let Some((_, _, norm)) = best else {
            return Ok(None);
        };
        if tie {
            return Ok(None);
        }
        let row: Option<(i64, String, String, i64)> = self
            .conn
            .prepare_cached(
                "SELECT key, tbl, display, rid FROM entity WHERE norm = ?1
                 ORDER BY tbl, key, rid LIMIT 1",
            )
            .map_err(lx)?
            .query_row([norm], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .optional()
            .map_err(lx)?;
        match row {
            Some((key, tbl, display, rid)) => Ok(Some(self.candidate(key, tbl, display, rid)?)),
            None => Err(ShieldError::Corrupt("the lexicon is damaged")),
        }
    }
}

/// The tokens of an already normalized string, sorted and joined.
fn sorted_join(norm: &str) -> String {
    let mut t: Vec<&str> = norm.split(' ').collect();
    t.sort_unstable();
    t.join(" ")
}
