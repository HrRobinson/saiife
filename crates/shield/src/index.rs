//! Plan 43 T6: the keyed-hash known-value index, its Bloom filter (R43-9)
//! and the allow list (R43-10).
//!
//! `index.bin`: a 32-byte header (`SAIIFEKI`, u32 version 1, u64 entry
//! count, 12 zero bytes; little-endian), then sorted, distinct 16-byte
//! entries `HMAC-SHA-256(key, domain ‖ 0x00 ‖ normalized)[..16]`. `domain`
//! is `n` for identifier and quasi values (and entity full names), `p` for
//! free-text phrases.
//!
//! `index.bloom`: a 24-byte header (`SAIIFEKB`, u32 version 1, u64 bit
//! count, u32 hash count; little-endian), then the bit array (bit `i` is bit
//! `i % 8` of byte `i / 8`). 20 bits per entry (at least 64, rounded up to a
//! multiple of 64), 14 hashes by double hashing: `h1` is entry bytes 0..8,
//! `h2` bytes 8..16 (low bit set), hash `i` is `(h1 + i·h2) mod bits`.
//!
//! Which values enter (R43-10): an identifier or quasi value only if it
//! occurs in at most `k` records of its column (`GROUP BY … HAVING n <= k`,
//! on the raw value: a value split over spellings may enter although it is
//! common in total, which only blocks more). `n` is `COUNT(DISTINCT key)` in
//! an entity table (R-14: one person in many rows is one record), else
//! `COUNT(*)`. An entity's full name (its name columns together) enters
//! under the same floor, and so does each free-text phrase
//! (split at `. ! ? ; \n`) of 3 to 40 tokens, whole. Single words of free
//! text never enter. Allow words (schema words, aliases, the k-floor public
//! values, and `allow.json` if the dataset dir has one) never enter.
//!
//! A value enters in every form of [`value_forms`], and a lookup tries the
//! same forms, so the two sides always agree: the normalized text, its
//! tokens sorted (`berg anna` = `anna berg`), a number's canonical text
//! (an integer as `i64` text, `4411`; any other number as Rust's shortest
//! round-trip `f64` text, so `12.50`, `12,5` and the REAL 12.5 are all
//! `12.5`, and `3.0` is `3`), and a date's ISO form (`03.05.1980` is
//! `1980-05-03`), each normalized, and for a value of digits and
//! separators (space, `-`, `.`, `/`) only, its digits alone (`12 34 56 78`
//! is `12345678`). A phrase lookup tries the whole input and every piece of
//! [`split_phrases`] (R-15).
//!
//! The build streams the entries into sorted runs of at most 64 MB (new
//! 0600 files in the output dir, removed on success and on every error),
//! merges them with a heap (dropping duplicates), and writes `index.bin`
//! and then `index.bloom` through the private-part protocol (0600 part,
//! sealed 0400, renamed, dir synced). A lookup reads the Bloom filter from
//! memory, then binary-searches `index.bin` with positioned reads (no mmap:
//! it needs `unsafe`).
//!
//! No error or `Debug` text carries a value, an entry or key bytes.

use crate::dataset::{create_private_file, ensure_private_dir, sync_dir, with_private_part};
use crate::error::ShieldError;
use crate::norm::{normalize, tokens};
use crate::public::{public_values, PublicValues};
use crate::schema::{ColType, ColumnClass, Schema};
use crate::snapshot::{open_ro, parse_date, parse_int, parse_real};
use crate::source::quote_ident;
use ring::hmac;
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap};
use std::fmt;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const INDEX_FILE: &str = "index.bin";
pub const BLOOM_FILE: &str = "index.bloom";
pub const ALLOW_FILE: &str = "allow.json";
/// The default sort-run size (R43-9).
pub const DEFAULT_RUN_BYTES: usize = 64 << 20;

const INDEX_MAGIC: &[u8; 8] = b"SAIIFEKI";
const BLOOM_MAGIC: &[u8; 8] = b"SAIIFEKB";
const VERSION: u32 = 1;
const ALLOW_VERSION: u32 = 1;
const HEADER: u64 = 32;
const BLOOM_HEADER: u64 = 24;
const ENTRY: usize = 16;
const BITS_PER_ENTRY: u64 = 20;
const HASHES: u32 = 14;
const MIN_BITS: u64 = 64;
const MAX_FANIN: usize = 64;
const IO_BUF: usize = 1 << 20;
const MAX_ALLOW_BYTES: u64 = 64 << 20;
const DOMAIN_VALUE: u8 = b'n';
const DOMAIN_PHRASE: u8 = b'p';
const MIN_PHRASE: usize = 3;
const MAX_PHRASE: usize = 40;

type Entry = [u8; ENTRY];

/// The index key. Built by the daemon from the sealed key set (plan 47).
pub struct IndexKey(pub Zeroizing<[u8; 32]>);

impl fmt::Debug for IndexKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IndexKey(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BuildStats {
    /// Distinct entries in `index.bin`.
    pub entries: u64,
    /// Distinct identifier/quasi values (and full names) left out because
    /// they occur in more than `k` rows.
    pub left_out_common: u64,
    /// Free-text phrases offered to the index (before duplicates are merged).
    pub phrases: u64,
}

fn io(why: &str) -> ShieldError {
    ShieldError::Io(why.to_string())
}

fn rd(_: rusqlite::Error) -> ShieldError {
    ShieldError::Sqlite("could not read the snapshot".into())
}

fn hmac_key(k: &IndexKey) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, &k.0[..])
}

fn entry_of(key: &hmac::Key, domain: u8, norm: &str) -> Entry {
    let mut c = hmac::Context::with_key(key);
    c.update(&[domain, 0]);
    c.update(norm.as_bytes());
    let tag = c.sign();
    let mut e = [0u8; ENTRY];
    e.copy_from_slice(&tag.as_ref()[..ENTRY]);
    e
}

// ------------------------------------------------------------- forms ----

/// A number's canonical text: an `i64` as itself, any other number as the
/// shortest round-trip `f64` text; a single decimal comma is a point.
fn canonical_number(t: &str) -> Option<String> {
    if let Some(i) = parse_int(t) {
        return Some(i.to_string());
    }
    if let Some(f) = parse_real(t) {
        return Some(f.to_string());
    }
    if t.matches(',').count() == 1 && !t.contains('.') {
        if let Some(f) = parse_real(&t.replace(',', ".")) {
            return Some(f.to_string());
        }
    }
    None
}

/// Every normalized form a value enters and is looked up under (see the
/// module docs). Empty for a value with no letters or digits.
fn value_forms(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |v: String| {
        if !v.is_empty() && !out.contains(&v) {
            out.push(v);
        }
    };
    let toks = tokens(s);
    if toks.len() > 1 {
        let mut sorted = toks.clone();
        sorted.sort_unstable();
        push(toks.join(" "));
        push(sorted.join(" "));
    } else {
        push(toks.join(" "));
    }
    let t = s.trim();
    if let Some(n) = canonical_number(t) {
        push(normalize(&n));
    }
    if let Some(d) = parse_date(t) {
        push(normalize(&d));
    }
    if let Some(d) = digits_only(t) {
        push(d);
    }
    out
}

/// A value of digits and separators (space, `-`, `.`, `/`) only, with at
/// least one separator: its digits alone (`12 34 56 78` is `12345678`,
/// `010180-1234` is `0101801234`).
fn digits_only(t: &str) -> Option<String> {
    let ok = t.chars().any(|c| c.is_ascii_digit())
        && t.chars().any(|c| matches!(c, ' ' | '-' | '.' | '/'))
        && t.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ' ' | '-' | '.' | '/'));
    ok.then(|| t.chars().filter(char::is_ascii_digit).collect())
}

/// The phrases of a free-text cell: split at `. ! ? ; \n`, each of 3 to 40
/// tokens, normalized.
fn phrases(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(['.', '!', '?', ';', '\n']).filter_map(|p| {
        let t = tokens(p);
        (MIN_PHRASE..=MAX_PHRASE)
            .contains(&t.len())
            .then(|| t.join(" "))
    })
}

/// R-15: the phrases of `s` as the build makes them (normalized pieces of 3
/// to 40 tokens, split at `. ! ? ; \n`).
pub fn split_phrases(s: &str) -> Vec<String> {
    phrases(s).collect()
}

/// A cell as text: integers and reals in plain notation, a `bool` column as
/// `true`/`false`; NULL and blobs give None.
fn cell_text(v: ValueRef<'_>, ty: ColType) -> Option<String> {
    match v {
        ValueRef::Null | ValueRef::Blob(_) => None,
        ValueRef::Integer(i) if ty == ColType::Bool => Some((i != 0).to_string()),
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Text(b) => Some(String::from_utf8_lossy(b).into_owned()),
    }
}

// --------------------------------------------------------------- files ----

#[cfg(unix)]
fn nofollow(o: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    o.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
}

#[cfg(not(unix))]
fn nofollow(_: &mut std::fs::OpenOptions) {}

/// Opens an existing regular file for reading, never through a symlink.
fn open_read(path: &Path, why: &str) -> Result<File, ShieldError> {
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(io(why));
    }
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    nofollow(&mut o);
    let f = o.open(path).map_err(|_| io(why))?;
    let md = f.metadata().map_err(|_| io(why))?;
    if !md.is_file() {
        return Err(io(why));
    }
    Ok(f)
}

/// Opens a part file made by `with_private_part` for writing.
fn open_part(part: &Path, why: &str) -> Result<File, ShieldError> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true);
    nofollow(&mut o);
    o.open(part).map_err(|_| io(why))
}

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, off)
}

#[cfg(windows)]
fn read_at(f: &File, buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0;
    while done < buf.len() {
        let n = f.seek_read(&mut buf[done..], off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        done += n;
        off += n as u64;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_at(_: &File, _: &mut [u8], _: u64) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// Reads one entry; None at a clean end, Corrupt on a partial one.
fn read_entry(r: &mut impl Read) -> Result<Option<Entry>, ShieldError> {
    let mut e = [0u8; ENTRY];
    let mut got = 0;
    while got < ENTRY {
        match r.read(&mut e[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(x) if x.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(io("could not read an index run")),
        }
    }
    match got {
        0 => Ok(None),
        ENTRY => Ok(Some(e)),
        _ => Err(ShieldError::Corrupt("an index run is truncated")),
    }
}

// --------------------------------------------------------------- bloom ----

/// The Bloom filter's bit count for `n` entries.
fn bloom_bits(n: u64) -> Option<u64> {
    let bits = n.checked_mul(BITS_PER_ENTRY)?.max(MIN_BITS);
    bits.checked_add(63).map(|b| b / 64 * 64)
}

fn bloom_positions(e: &Entry, bits: u64, hashes: u32) -> impl Iterator<Item = u64> {
    let mut a = [0u8; 8];
    a.copy_from_slice(&e[..8]);
    let h1 = u64::from_le_bytes(a);
    a.copy_from_slice(&e[8..]);
    let h2 = u64::from_le_bytes(a) | 1;
    (0..u64::from(hashes)).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) % bits)
}

fn bloom_test(bloom: &[u8], bits: u64, hashes: u32, e: &Entry) -> bool {
    bloom_positions(e, bits, hashes).all(|p| bloom[(p / 8) as usize] & (1 << (p % 8)) != 0)
}

/// Builds the Bloom part from the finished `index.bin`.
fn write_bloom(index: &Path, part: &Path) -> Result<(), ShieldError> {
    let mut r = BufReader::with_capacity(IO_BUF, open_read(index, "could not read the index")?);
    let mut h = [0u8; HEADER as usize];
    r.read_exact(&mut h)
        .map_err(|_| io("could not read the index"))?;
    let count = header_count(&h)?;
    let bits = bloom_bits(count).ok_or(ShieldError::Limit("the index is too large"))?;
    let mut bloom = vec![0u8; (bits / 8) as usize];
    let mut seen = 0u64;
    while let Some(e) = read_entry(&mut r)? {
        for p in bloom_positions(&e, bits, HASHES) {
            bloom[(p / 8) as usize] |= 1 << (p % 8);
        }
        seen += 1;
    }
    if seen != count {
        return Err(ShieldError::Corrupt("the index entry count is wrong"));
    }
    let mut w = BufWriter::with_capacity(IO_BUF, open_part(part, "could not write the index")?);
    let bad = |_| io("could not write the index");
    w.write_all(BLOOM_MAGIC).map_err(bad)?;
    w.write_all(&VERSION.to_le_bytes()).map_err(bad)?;
    w.write_all(&bits.to_le_bytes()).map_err(bad)?;
    w.write_all(&HASHES.to_le_bytes()).map_err(bad)?;
    w.write_all(&bloom).map_err(bad)?;
    w.flush().map_err(bad)
}

fn index_header(count: u64) -> [u8; HEADER as usize] {
    let mut h = [0u8; HEADER as usize];
    h[..8].copy_from_slice(INDEX_MAGIC);
    h[8..12].copy_from_slice(&VERSION.to_le_bytes());
    h[12..20].copy_from_slice(&count.to_le_bytes());
    h
}

/// The entry count of a valid `index.bin` header.
fn header_count(h: &[u8; HEADER as usize]) -> Result<u64, ShieldError> {
    let bad = ShieldError::Corrupt("the index header is not valid");
    if &h[..8] != INDEX_MAGIC
        || h[8..12] != VERSION.to_le_bytes()
        || h[20..].iter().any(|b| *b != 0)
    {
        return Err(bad);
    }
    let mut c = [0u8; 8];
    c.copy_from_slice(&h[12..20]);
    Ok(u64::from_le_bytes(c))
}

// ---------------------------------------------------------------- runs ----

/// The sort-run files of one build: removed when dropped (success, error or
/// panic).
struct Runs<'a> {
    dir: &'a Path,
    tag: String,
    next: u64,
    paths: Vec<PathBuf>,
}

impl Runs<'_> {
    /// A new private run file, registered for removal before it is written.
    fn create(&mut self) -> Result<BufWriter<File>, ShieldError> {
        let p = self
            .dir
            .join(format!("index.run.{}.{}", self.tag, self.next));
        self.next += 1;
        let f = create_private_file(&p)?;
        self.paths.push(p);
        Ok(BufWriter::with_capacity(IO_BUF, f))
    }
}

impl Drop for Runs<'_> {
    fn drop(&mut self) {
        for p in &self.paths {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn run_tag() -> Result<String, ShieldError> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).map_err(|_| io("could not name an index run"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Merges sorted runs into `w`, dropping duplicates; returns the count.
fn merge(paths: &[PathBuf], w: &mut impl Write) -> Result<u64, ShieldError> {
    let mut readers = Vec::with_capacity(paths.len());
    for p in paths {
        readers.push(BufReader::with_capacity(
            IO_BUF / 4,
            open_read(p, "could not read an index run")?,
        ));
    }
    let mut heap = BinaryHeap::with_capacity(readers.len());
    for (i, r) in readers.iter_mut().enumerate() {
        if let Some(e) = read_entry(r)? {
            heap.push(Reverse((e, i)));
        }
    }
    let mut last: Option<Entry> = None;
    let mut n = 0u64;
    while let Some(Reverse((e, i))) = heap.pop() {
        if last != Some(e) {
            w.write_all(&e)
                .map_err(|_| io("could not write the index"))?;
            last = Some(e);
            n += 1;
        }
        if let Some(next) = read_entry(&mut readers[i])? {
            heap.push(Reverse((next, i)));
        }
    }
    Ok(n)
}

struct Sorter<'a> {
    key: hmac::Key,
    allow: BTreeSet<String>,
    buf: Vec<Entry>,
    cap: usize,
    runs: Runs<'a>,
    offered: u64,
    progress: &'a mut dyn FnMut(u64),
}

impl Sorter<'_> {
    fn push(&mut self, domain: u8, norm: &str) -> Result<(), ShieldError> {
        if norm.is_empty() || self.allow.contains(norm) {
            return Ok(());
        }
        self.buf.push(entry_of(&self.key, domain, norm));
        self.offered += 1;
        if self.buf.len() >= self.cap {
            self.flush_run()?;
        }
        Ok(())
    }

    fn flush_run(&mut self) -> Result<(), ShieldError> {
        self.buf.sort_unstable();
        self.buf.dedup();
        let mut w = self.runs.create()?;
        let bad = |_| io("could not write an index run");
        for e in &self.buf {
            w.write_all(e).map_err(bad)?;
        }
        w.flush().map_err(bad)?;
        drop(w);
        self.buf.clear();
        (self.progress)(self.offered);
        Ok(())
    }

    /// Writes the sorted, distinct entries to the `index.bin` part.
    fn finish_into(&mut self, part: &Path) -> Result<u64, ShieldError> {
        let bad = |_| io("could not write the index");
        let mut w = BufWriter::with_capacity(IO_BUF, open_part(part, "could not write the index")?);
        w.write_all(&index_header(0)).map_err(bad)?;
        let count = if self.runs.paths.is_empty() {
            self.buf.sort_unstable();
            self.buf.dedup();
            for e in &self.buf {
                w.write_all(e).map_err(bad)?;
            }
            self.buf.len() as u64
        } else {
            if !self.buf.is_empty() {
                self.flush_run()?;
            }
            self.buf = Vec::new();
            while self.runs.paths.len() > MAX_FANIN {
                let group: Vec<PathBuf> = self.runs.paths[..MAX_FANIN].to_vec();
                let mut rw = self.runs.create()?;
                merge(&group, &mut rw)?;
                rw.flush().map_err(|_| io("could not write an index run"))?;
                drop(rw);
                for p in &group {
                    let _ = std::fs::remove_file(p);
                }
                self.runs.paths.drain(..MAX_FANIN);
            }
            merge(&self.runs.paths, &mut w)?
        };
        let mut f = w
            .into_inner()
            .map_err(|_| io("could not write the index"))?;
        f.seek(SeekFrom::Start(0)).map_err(bad)?;
        f.write_all(&index_header(count)).map_err(bad)?;
        Ok(count)
    }
}

// --------------------------------------------------------------- build ----

/// The schema words: the dataset name, table and column names and aliases,
/// and the entity words, normalized.
fn schema_words(schema: &Schema) -> BTreeSet<String> {
    let mut raw: Vec<&str> = vec![schema.dataset.as_str()];
    for t in &schema.tables {
        raw.push(&t.name);
        raw.extend(t.alias.as_deref());
        for c in &t.columns {
            raw.push(&c.name);
            raw.extend(c.alias.as_deref());
        }
    }
    for e in &schema.entities {
        raw.push(&e.word);
        raw.push(&e.word_da);
    }
    raw.into_iter()
        .map(normalize)
        .filter(|w| !w.is_empty())
        .collect()
}

/// R43-9/R43-10: builds `out_dir/index.bin` and `out_dir/index.bloom` from
/// a finished snapshot (see the module docs). `k` is the dataset policy's
/// frequency floor. `progress` gets the number of entries offered so far.
pub fn build_index(
    snapshot: &Path,
    schema: &Schema,
    k: u32,
    key: &IndexKey,
    out_dir: &Path,
    progress: &mut dyn FnMut(u64),
) -> Result<BuildStats, ShieldError> {
    build_index_with_run_bytes(
        snapshot,
        schema,
        k,
        key,
        out_dir,
        progress,
        DEFAULT_RUN_BYTES,
    )
}

/// [`build_index`] with the sort-run size as a seam (tests force tiny runs).
/// The files are the same for every run size.
#[doc(hidden)]
pub fn build_index_with_run_bytes(
    snapshot: &Path,
    schema: &Schema,
    k: u32,
    key: &IndexKey,
    out_dir: &Path,
    progress: &mut dyn FnMut(u64),
    run_bytes: usize,
) -> Result<BuildStats, ShieldError> {
    ensure_private_dir(out_dir)?;
    for f in [INDEX_FILE, BLOOM_FILE] {
        if std::fs::symlink_metadata(out_dir.join(f)).is_ok() {
            return Err(io("a dataset file already exists"));
        }
    }
    let snap = open_ro(snapshot)?;

    let mut allow = schema_words(schema);
    for t in &schema.tables {
        for c in t.columns.iter().filter(|c| c.class == ColumnClass::Public) {
            let pv =
                public_values(&snap, &t.name, &c.name, k).map_err(|_| ShieldError::Source {
                    file: "snapshot".into(),
                    table: Some(t.name.clone()),
                    column: Some(c.name.clone()),
                    row: None,
                    why: "the public column's values could not be read",
                })?;
            allow.extend(pv.passing.iter().map(|v| normalize(v)));
        }
    }
    let allow_path = out_dir.join(ALLOW_FILE);
    if std::fs::symlink_metadata(&allow_path).is_ok() {
        allow.extend(read_allow(&allow_path)?.words);
    }
    allow.remove("");

    let mut stats = BuildStats::default();
    let mut sorter = Sorter {
        key: hmac_key(key),
        allow,
        buf: Vec::new(),
        cap: (run_bytes / ENTRY).max(1),
        runs: Runs {
            dir: out_dir,
            tag: run_tag()?,
            next: 0,
            paths: Vec::new(),
        },
        offered: 0,
        progress,
    };

    let k = i64::from(k);
    for t in &schema.tables {
        let qt = quote_ident(&t.name);
        let have = snapshot_columns(&snap, &t.name)?;
        let need = |c: &str| -> Result<(), ShieldError> {
            if have.iter().any(|h| h == c) {
                Ok(())
            } else {
                Err(ShieldError::Source {
                    file: "snapshot".into(),
                    table: Some(t.name.clone()),
                    column: Some(c.to_string()),
                    row: None,
                    why: "the column is not in the snapshot",
                })
            }
        };
        // R-14: in an entity table the floor counts people (distinct keys),
        // not rows: one customer in many rows of a denormalized table is
        // one record.
        let people = match schema.entity_for(&t.name) {
            Some(e) => {
                need(&e.key)?;
                format!("COUNT(DISTINCT {})", quote_ident(&e.key))
            }
            None => "COUNT(*)".to_string(),
        };
        for c in &t.columns {
            if matches!(
                c.class,
                ColumnClass::Identifier | ColumnClass::Quasi | ColumnClass::FreeText
            ) {
                need(&c.name)?;
            }
            let qc = quote_ident(&c.name);
            match c.class {
                ColumnClass::Identifier | ColumnClass::Quasi => {
                    let sql = format!(
                        "SELECT {qc} FROM {qt} WHERE {qc} IS NOT NULL \
                         GROUP BY {qc} HAVING {people} <= ?1"
                    );
                    let mut st = snap.prepare(&sql).map_err(rd)?;
                    let mut rows = st.query([k]).map_err(rd)?;
                    while let Some(r) = rows.next().map_err(rd)? {
                        if let Some(v) = cell_text(r.get_ref(0).map_err(rd)?, c.ty) {
                            for f in value_forms(&v) {
                                sorter.push(DOMAIN_VALUE, &f)?;
                            }
                        }
                    }
                    stats.left_out_common += count_common(
                        &snap,
                        &format!("SELECT 1 FROM {qt} WHERE {qc} IS NOT NULL GROUP BY {qc}"),
                        &people,
                        k,
                    )?;
                }
                ColumnClass::FreeText => {
                    let sql = format!("SELECT {qc} FROM {qt} WHERE {qc} IS NOT NULL");
                    let mut st = snap.prepare(&sql).map_err(rd)?;
                    let mut rows = st.query([]).map_err(rd)?;
                    while let Some(r) = rows.next().map_err(rd)? {
                        if let Some(v) = cell_text(r.get_ref(0).map_err(rd)?, c.ty) {
                            for p in phrases(&v) {
                                stats.phrases += 1;
                                sorter.push(DOMAIN_PHRASE, &p)?;
                            }
                        }
                    }
                }
                ColumnClass::Sensitive | ColumnClass::Public => {}
            }
        }
        // Full names: an entity's name columns together, under the floor.
        for e in schema
            .entities
            .iter()
            .filter(|e| e.table == t.name && e.names.len() > 1)
        {
            for n in &e.names {
                need(n)?;
            }
            let cols: Vec<String> = e.names.iter().map(|n| quote_ident(n)).collect();
            let list = cols.join(", ");
            let any = cols
                .iter()
                .map(|c| format!("{c} IS NOT NULL"))
                .collect::<Vec<_>>()
                .join(" OR ");
            let sql = format!(
                "SELECT {list} FROM {qt} WHERE {any} GROUP BY {list} HAVING {people} <= ?1"
            );
            let mut st = snap.prepare(&sql).map_err(rd)?;
            let mut rows = st.query([k]).map_err(rd)?;
            while let Some(r) = rows.next().map_err(rd)? {
                let mut parts = Vec::with_capacity(cols.len());
                for (i, n) in e.names.iter().enumerate() {
                    let ty = schema.column(&t.name, n).map_or(ColType::Text, |c| c.ty);
                    if let Some(v) = cell_text(r.get_ref(i).map_err(rd)?, ty) {
                        parts.push(v);
                    }
                }
                for f in value_forms(&parts.join(" ")) {
                    sorter.push(DOMAIN_VALUE, &f)?;
                }
            }
            stats.left_out_common += count_common(
                &snap,
                &format!("SELECT 1 FROM {qt} WHERE {any} GROUP BY {list}"),
                &people,
                k,
            )?;
        }
    }
    drop(snap);

    let (index_path, count) =
        with_private_part(out_dir, INDEX_FILE, |part| sorter.finish_into(part))?;
    // The offered count: it never goes back (the deduplicated count can be
    // smaller); `BuildStats::entries` has the final count.
    (sorter.progress)(sorter.offered);
    // The runs are gone before the Bloom filter is built.
    drop(sorter);
    if let Err(e) = with_private_part(out_dir, BLOOM_FILE, |part| write_bloom(&index_path, part)) {
        // An index without its filter cannot be opened: remove it so a
        // rebuild can run.
        let _ = std::fs::remove_file(&index_path);
        sync_dir(out_dir);
        return Err(e);
    }
    stats.entries = count;
    Ok(stats)
}

/// The column names of a snapshot table. SQLite reads an unknown
/// double-quoted name as a string literal, so every column is checked
/// first: a schema that does not match the snapshot must fail, not index
/// nothing.
fn snapshot_columns(snap: &Connection, table: &str) -> Result<Vec<String>, ShieldError> {
    let mut st = snap
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .map_err(rd)?;
    let rows = st
        .query_map([table], |r| r.get::<_, String>(0))
        .map_err(rd)?;
    let cols = rows.collect::<Result<Vec<_>, _>>().map_err(rd)?;
    if cols.is_empty() {
        return Err(ShieldError::Source {
            file: "snapshot".into(),
            table: Some(table.to_string()),
            column: None,
            row: None,
            why: "the table is not in the snapshot",
        });
    }
    Ok(cols)
}

/// How many groups of `grouped` (a `SELECT 1 … GROUP BY …`) have more than
/// `k` records (`count` is `COUNT(*)` or `COUNT(DISTINCT key)`).
fn count_common(snap: &Connection, grouped: &str, count: &str, k: i64) -> Result<u64, ShieldError> {
    let sql = format!("SELECT COUNT(*) FROM ({grouped} HAVING {count} > ?1)");
    let n: i64 = snap.query_row(&sql, [k], |r| r.get(0)).map_err(rd)?;
    Ok(n.max(0) as u64)
}

// -------------------------------------------------------------- lookup ----

/// An open index: the `index.bin` handle and the Bloom bits in memory.
pub struct KnownIndex {
    file: File,
    entries: u64,
    bloom: Vec<u8>,
    bits: u64,
    key: hmac::Key,
}

impl fmt::Debug for KnownIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnownIndex")
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

impl KnownIndex {
    /// Opens `dir/index.bin` and `dir/index.bloom` (never through a
    /// symlink) and checks that their headers and sizes agree.
    pub fn open(dir: &Path, key: IndexKey) -> Result<KnownIndex, ShieldError> {
        let file = open_read(&dir.join(INDEX_FILE), "could not open the index")?;
        let mut h = [0u8; HEADER as usize];
        read_at(&file, &mut h, 0).map_err(|_| ShieldError::Corrupt("the index is truncated"))?;
        let entries = header_count(&h)?;
        let len = file
            .metadata()
            .map_err(|_| io("could not open the index"))?
            .len();
        let want = entries
            .checked_mul(ENTRY as u64)
            .and_then(|b| b.checked_add(HEADER));
        if want != Some(len) {
            return Err(ShieldError::Corrupt("the index size is wrong"));
        }

        let bad = ShieldError::Corrupt("the Bloom filter is not valid");
        let bits = bloom_bits(entries).ok_or(ShieldError::Limit("the index is too large"))?;
        let mut bf = open_read(&dir.join(BLOOM_FILE), "could not open the index")?;
        let blen = bf
            .metadata()
            .map_err(|_| io("could not open the index"))?
            .len();
        if blen != BLOOM_HEADER + bits / 8 {
            return Err(bad);
        }
        let mut bh = [0u8; BLOOM_HEADER as usize];
        bf.read_exact(&mut bh)
            .map_err(|_| io("could not open the index"))?;
        if &bh[..8] != BLOOM_MAGIC
            || bh[8..12] != VERSION.to_le_bytes()
            || bh[12..20] != bits.to_le_bytes()
            || bh[20..24] != HASHES.to_le_bytes()
        {
            return Err(bad);
        }
        let mut bloom = vec![0u8; (bits / 8) as usize];
        bf.read_exact(&mut bloom)
            .map_err(|_| io("could not open the index"))?;
        Ok(KnownIndex {
            file,
            entries,
            bloom,
            bits,
            key: hmac_key(&key),
        })
    }

    /// Is `s` (in any of its forms) a known identifier or quasi value, or a
    /// known full name? Domain `n`.
    pub fn contains_value(&self, s: &str) -> Result<bool, ShieldError> {
        for f in value_forms(s) {
            if self.has(DOMAIN_VALUE, &f)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// R-15: does `s` hold a known free-text phrase? Tries the whole
    /// normalized input, then every piece of [`split_phrases`] (the build's
    /// own splitter), so a sentence copied from a note hits whatever the
    /// caller's splitter did. Domain `p`.
    pub fn contains_phrase(&self, s: &str) -> Result<bool, ShieldError> {
        let n = normalize(s);
        if !n.is_empty() && self.has(DOMAIN_PHRASE, &n)? {
            return Ok(true);
        }
        for p in phrases(s) {
            if p != n && self.has(DOMAIN_PHRASE, &p)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The Bloom filter's answer alone for [`Self::contains_value`] (tests
    /// measure its false-positive rate).
    #[doc(hidden)]
    pub fn bloom_may_contain_value(&self, s: &str) -> bool {
        value_forms(s).iter().any(|f| {
            let e = entry_of(&self.key, DOMAIN_VALUE, f);
            bloom_test(&self.bloom, self.bits, HASHES, &e)
        })
    }

    fn has(&self, domain: u8, norm: &str) -> Result<bool, ShieldError> {
        let e = entry_of(&self.key, domain, norm);
        if !bloom_test(&self.bloom, self.bits, HASHES, &e) {
            return Ok(false);
        }
        let (mut lo, mut hi) = (0u64, self.entries);
        let mut buf = [0u8; ENTRY];
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            read_at(&self.file, &mut buf, HEADER + mid * ENTRY as u64)
                .map_err(|_| io("could not read the index"))?;
            match buf.cmp(&e) {
                std::cmp::Ordering::Equal => return Ok(true),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        Ok(false)
    }
}

// --------------------------------------------------------------- allow ----

/// The words that pass the firewall and never enter the index: normalized
/// schema words, aliases and the k-floor public values.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct AllowList {
    pub words: BTreeSet<String>,
}

impl fmt::Debug for AllowList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllowList")
            .field("words", &self.words.len())
            .finish()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowFile {
    version: u32,
    words: Vec<String>,
}

/// Writes `allow.json` (`{"version":1,"words":[...]}`, sorted) through the
/// private-part protocol. `out` is the file path, or a directory to put
/// `allow.json` in. An existing file, or anything at the part path, refuses.
pub fn write_allow(
    schema: &Schema,
    public: &[PublicValues],
    out: &Path,
) -> Result<AllowList, ShieldError> {
    let path: PathBuf = match std::fs::symlink_metadata(out) {
        Ok(md) if md.is_dir() => out.join(ALLOW_FILE),
        _ => out.to_path_buf(),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io("the allow list path has no file name"))?
        .to_string_lossy()
        .into_owned();
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut words = schema_words(schema);
    for pv in public {
        words.extend(pv.passing.iter().map(|v| normalize(v)));
    }
    words.remove("");
    let file = AllowFile {
        version: ALLOW_VERSION,
        words: words.iter().cloned().collect(),
    };
    with_private_part(&dir, &name, |part| {
        let mut w = BufWriter::new(open_part(part, "could not write the allow list")?);
        serde_json::to_writer(&mut w, &file).map_err(|_| io("could not write the allow list"))?;
        w.flush().map_err(|_| io("could not write the allow list"))
    })?;
    Ok(AllowList { words })
}

/// Reads `allow.json` (never through a symlink). Every word must be
/// non-empty and already normalized.
pub fn read_allow(path: &Path) -> Result<AllowList, ShieldError> {
    let f = open_read(path, "could not read the allow list")?;
    let len = f
        .metadata()
        .map_err(|_| io("could not read the allow list"))?
        .len();
    if len > MAX_ALLOW_BYTES {
        return Err(ShieldError::Limit("the allow list is over 64 MiB"));
    }
    let mut s = String::new();
    f.take(MAX_ALLOW_BYTES)
        .read_to_string(&mut s)
        .map_err(|_| io("could not read the allow list"))?;
    let bad = ShieldError::Corrupt("the allow list is not valid");
    let file: AllowFile = serde_json::from_str(&s).map_err(|_| bad)?;
    if file.version != ALLOW_VERSION {
        return Err(ShieldError::Corrupt("the allow list is not valid"));
    }
    let mut words = BTreeSet::new();
    for w in file.words {
        if w.is_empty() || normalize(&w) != w {
            return Err(ShieldError::Corrupt("the allow list is not valid"));
        }
        words.insert(w);
    }
    Ok(AllowList { words })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_agree() {
        assert_eq!(value_forms(" 4411 "), vec!["4411"]);
        assert_eq!(value_forms("12.50"), vec!["12 50", "12 5", "1250"]);
        assert_eq!(value_forms("Berg, Anna"), vec!["berg anna", "anna berg"]);
        assert_eq!(
            value_forms("03.05.1980"),
            vec!["03 05 1980", "1980 05 03", "03051980"]
        );
        assert!(value_forms(" ,; ").is_empty());
        assert_eq!(value_forms("12 34"), vec!["12 34", "1234"]);
        assert_eq!(digits_only("12a 34"), None);
        assert_eq!(digits_only("1234"), None);
        let p: Vec<String> = phrases("one two. three four five!\nsix seven eight nine").collect();
        assert_eq!(p, vec!["three four five", "six seven eight nine"]);
    }

    #[test]
    fn bloom_sizes() {
        assert_eq!(bloom_bits(0), Some(64));
        assert_eq!(bloom_bits(3), Some(64));
        assert_eq!(bloom_bits(4), Some(128));
        assert_eq!(bloom_bits(30_000_000), Some(600_000_000));
        assert_eq!(bloom_bits(u64::MAX), None);
    }
}
