//! Plan 43 T4: the column classifier. It suggests a class per column from the
//! name, the type, cheap statistics and a local sample. Nothing here applies a
//! class: `uncertain` tells the caller which suggestions the user must confirm.

use crate::error::ShieldError;
use crate::schema::{ColType, ColumnClass};
use crate::source::quote_ident as quote;
use rusqlite::Connection;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Guess {
    pub class: ColumnClass,
    pub confidence: f32,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnStats {
    pub rows: u64,
    pub non_null: u64,
    pub distinct: u64,
    pub max_len: usize,
    pub numeric: bool,
}

const IDENT_WORDS: &[&str] = &[
    "name",
    "navn",
    "first_name",
    "fornavn",
    "last_name",
    "efternavn",
    "email",
    "mail",
    "phone",
    "telefon",
    "tlf",
    "cpr",
    "ssn",
    "national_id",
    "customer_no",
    "kundenr",
    "account",
    "konto",
    "iban",
];
// Every entry is in the folded form `clean_name` gives a column name
// (`født` is `foedt`): a test asserts it, so no entry can be unreachable.
const QUASI_WORDS: &[&str] = &[
    "postcode", "postnr", "zip", "city", "by", "birth", "fodsel", "foedsel", "foedt", "fodt",
    "gender", "koen", "kon", "title", "stilling", "age", "alder",
];
const AMOUNT_WORDS: &[&str] = &[
    "amount", "beloeb", "belob", "balance", "saldo", "salary", "loen", "lon", "price", "pris",
    "limit", "total", "sum",
];
const FREETEXT_WORDS: &[&str] = &[
    "note",
    "notes",
    "comment",
    "comments",
    "description",
    "memo",
    "remark",
    "bemaerkning",
    "kommentar",
    "beskrivelse",
];

/// True when `word` is the whole name or a whole `_`-delimited part of it.
fn name_has(name: &str, word: &str) -> bool {
    // "by" is a Danish word for city but also a common English suffix
    // ("created_by"): only the bare name counts.
    if word == "by" {
        return name.eq_ignore_ascii_case("by");
    }
    let lower = name.to_lowercase();
    let mut padded = String::with_capacity(lower.len() + 2);
    padded.push('_');
    padded.push_str(&lower);
    padded.push('_');
    let mut w = String::with_capacity(word.len() + 2);
    w.push('_');
    w.push_str(word);
    w.push('_');
    padded.contains(&w)
}

fn name_in(name: &str, words: &[&str]) -> bool {
    words.iter().any(|w| name_has(name, w))
}

/// C1 / R-16 (spec §2.1.2: IDs are never public): the name says the column
/// holds IDs or names. `id`, a name ending in `_id`, `_no`, `_nr`, `nr` or
/// `nummer` (`customer_id`, `order_no`, `kundenr`, `kundenummer`), or one
/// holding an identifier word. Every ID column is caught, not only those of
/// people: a product or status ID cannot be public either (fails closed).
pub fn id_shaped(name: &str) -> bool {
    let n = name.to_lowercase();
    n == "id"
        || ["_id", "_no", "_nr", "nr", "nummer"]
            .iter()
            .any(|s| n.ends_with(s))
        || name_in(&n, IDENT_WORDS)
}

pub mod checks {
    use super::{name_in, AMOUNT_WORDS};

    pub fn email(s: &str) -> bool {
        let s = s.trim();
        let Some((local, domain)) = s.split_once('@') else {
            return false;
        };
        !local.is_empty()
            && !local.contains(char::is_whitespace)
            && !domain.contains('@')
            && !domain.contains(char::is_whitespace)
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
    }

    /// ISO 13616 mod-97: 15 to 34 characters, country letters, check digits.
    pub fn iban(s: &str) -> bool {
        let mut buf = [0u8; 34];
        let mut n = 0;
        for b in s.bytes() {
            if b == b' ' {
                continue;
            }
            if n == 34 || !b.is_ascii_alphanumeric() {
                return false;
            }
            buf[n] = b.to_ascii_uppercase();
            n += 1;
        }
        if n < 15 || !buf[0].is_ascii_uppercase() || !buf[1].is_ascii_uppercase() {
            return false;
        }
        if !buf[2].is_ascii_digit() || !buf[3].is_ascii_digit() {
            return false;
        }
        let mut rem: u32 = 0;
        for &b in buf[4..n].iter().chain(buf[..4].iter()) {
            if b.is_ascii_digit() {
                rem = (rem * 10 + u32::from(b - b'0')) % 97;
            } else {
                rem = (rem * 100 + u32::from(b - b'A') + 10) % 97;
            }
        }
        rem == 1
    }

    /// 8 digits (DK, digits and spaces only), or `+CC` and 7 to 15 digits.
    pub fn phone(s: &str) -> bool {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix('+') {
            let mut digits = 0;
            for b in rest.bytes() {
                match b {
                    b'0'..=b'9' => digits += 1,
                    b' ' | b'-' | b'(' | b')' => {}
                    _ => return false,
                }
            }
            return (7..=15).contains(&digits)
                && rest.as_bytes().first().is_some_and(|b| *b != b'0');
        }
        let mut digits = 0;
        for b in s.bytes() {
            match b {
                b'0'..=b'9' => digits += 1,
                b' ' => {}
                _ => return false,
            }
        }
        digits == 8
    }

    /// `DDMMYY-SSSS` or `DDMMYYSSSS` with a real calendar date. Modulus 11 is
    /// not required: CPRs issued after 2007 need not pass it.
    pub fn cpr(s: &str) -> bool {
        let b = s.trim().as_bytes();
        let d: [u8; 10] = match b.len() {
            10 if b.iter().all(u8::is_ascii_digit) => {
                let mut d = [0; 10];
                d.copy_from_slice(b);
                d
            }
            11 if b[6] == b'-' && b[..6].iter().chain(&b[7..]).all(u8::is_ascii_digit) => {
                let mut d = [0; 10];
                d[..6].copy_from_slice(&b[..6]);
                d[6..].copy_from_slice(&b[7..]);
                d
            }
            _ => return false,
        };
        let v = |i: usize| u32::from(d[i] - b'0');
        let day = v(0) * 10 + v(1);
        let month = v(2) * 10 + v(3);
        let yy = v(4) * 10 + v(5);
        if !(1..=12).contains(&month) || day == 0 {
            return false;
        }
        let max = match month {
            4 | 6 | 9 | 11 => 30,
            // The century is not known from the digits alone: allow Feb 29
            // when any century could make `yy` a leap year.
            2 => {
                if yy % 4 == 0 {
                    29
                } else {
                    28
                }
            }
            _ => 31,
        };
        day <= max
    }

    /// Luhn over 13 to 19 digits (spaces and hyphens allowed).
    pub fn luhn(s: &str) -> bool {
        let mut sum = 0u32;
        let mut n = 0u32;
        for b in s.trim().bytes().rev() {
            match b {
                b'0'..=b'9' => {
                    let mut d = u32::from(b - b'0');
                    if n % 2 == 1 {
                        d *= 2;
                        if d > 9 {
                            d -= 9;
                        }
                    }
                    sum += d;
                    n += 1;
                }
                b' ' | b'-' => {}
                _ => return false,
            }
        }
        (13..=19).contains(&n) && sum.is_multiple_of(10)
    }

    /// The column name holds an amount word (`amount`, `credit_limit`, `saldo`...).
    pub fn amount_name(col: &str) -> bool {
        name_in(col, AMOUNT_WORDS)
    }
}

/// The one fixed sqlite error of the classifier and the k-floor (M3: no text
/// from rusqlite, it can carry values).
pub(crate) fn sqlite_err() -> ShieldError {
    ShieldError::Sqlite("sqlite: classifier query failed".into())
}

/// Row, non-null and distinct counts and the longest value, in one pass.
pub fn stats(
    conn: &Connection,
    table: &str,
    column: &str,
    ty: ColType,
) -> Result<ColumnStats, ShieldError> {
    let (t, c) = (quote(table), quote(column));
    let sql = format!(
        "SELECT COUNT(*), COUNT({c}), COUNT(DISTINCT {c}), \
         COALESCE(MAX(LENGTH(CAST({c} AS TEXT))), 0) FROM {t}"
    );
    conn.query_row(&sql, [], |r| {
        Ok(ColumnStats {
            rows: r.get::<_, i64>(0)?.max(0) as u64,
            non_null: r.get::<_, i64>(1)?.max(0) as u64,
            distinct: r.get::<_, i64>(2)?.max(0) as u64,
            max_len: r.get::<_, i64>(3)?.max(0) as usize,
            numeric: matches!(ty, ColType::Integer | ColType::Real),
        })
    })
    .map_err(|_| sqlite_err())
}

/// Distinct non-null values as text, read locally for `guess`, drawn across
/// the whole table. Method: random probes of the snapshot's `"_rowid"`
/// primary key over `[min, max]`, at most 1000 lookups and 200 distinct
/// values, so O(sample) and no sort of the table. A table whose `_rowid`
/// range is at most 1000 is read in full (up to 1000 distinct values), so
/// no row is missed. Shares computed over the result (`identifier_share`)
/// are over these distinct non-null values, not over rows.
pub fn sample(conn: &Connection, table: &str, column: &str) -> Result<Vec<String>, ShieldError> {
    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).map_err(|_| ShieldError::Io("no randomness".into()))?;
    sample_seeded(conn, table, column, u64::from_le_bytes(seed))
}

/// `sample` with a fixed seed, so a test can repeat a draw.
#[doc(hidden)]
pub fn sample_seeded(
    conn: &Connection,
    table: &str,
    column: &str,
    seed: u64,
) -> Result<Vec<String>, ShieldError> {
    const WANT: usize = 200;
    const PROBES: u64 = 1000;
    let (t, c) = (quote(table), quote(column));
    let (lo, hi): (Option<i64>, Option<i64>) = conn
        .query_row(
            &format!("SELECT MIN(\"_rowid\"), MAX(\"_rowid\") FROM {t}"),
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| sqlite_err())?;
    let (Some(lo), Some(hi)) = (lo, hi) else {
        return Ok(Vec::new());
    };
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut take = |v: Option<String>, out: &mut Vec<String>| {
        if let Some(v) = v {
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    };
    let span = (i128::from(hi) - i128::from(lo) + 1) as u128;
    if span <= u128::from(PROBES) {
        let mut st = conn
            .prepare(&format!("SELECT CAST({c} AS TEXT) FROM {t}"))
            .map_err(|_| sqlite_err())?;
        let mut rows = st.query([]).map_err(|_| sqlite_err())?;
        while let Some(r) = rows.next().map_err(|_| sqlite_err())? {
            take(r.get(0).map_err(|_| sqlite_err())?, &mut out);
        }
    } else {
        let mut st = conn
            .prepare(&format!(
                "SELECT CAST({c} AS TEXT) FROM {t} WHERE \"_rowid\" = ?1"
            ))
            .map_err(|_| sqlite_err())?;
        // SplitMix64.
        let mut x = seed;
        for _ in 0..PROBES {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let id = (i128::from(lo) + (u128::from(z) % span) as i128) as i64;
            let v: Option<Option<String>> = match st.query_row([id], |r| r.get(0)) {
                Ok(v) => Some(v),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(_) => return Err(sqlite_err()),
            };
            take(v.flatten(), &mut out);
            if out.len() >= WANT {
                break;
            }
        }
    }
    Ok(out)
}

/// True when any identifier check matches the value.
pub(crate) fn looks_like_identifier(v: &str) -> bool {
    checks::email(v) || checks::iban(v) || checks::phone(v) || checks::cpr(v) || checks::luhn(v)
}

/// The share (0.0 to 1.0) of the sample that any identifier check matches.
pub fn identifier_share(sample: &[String]) -> f32 {
    if sample.is_empty() {
        return 0.0;
    }
    let n = sample.iter().filter(|v| looks_like_identifier(v)).count();
    n as f32 / sample.len() as f32
}

fn g(class: ColumnClass, confidence: f32, reason: &'static str) -> Guess {
    Guess {
        class,
        confidence,
        reason,
    }
}

/// The first rule that holds wins (see the plan's rule list).
pub fn guess(name: &str, ty: ColType, st: &ColumnStats, sample: &[String]) -> Guess {
    use ColumnClass::*;
    let numeric = matches!(ty, ColType::Integer | ColType::Real);
    if name_in(name, IDENT_WORDS) {
        return g(Identifier, 0.95, "the name says it holds names or IDs");
    }
    let ids = identifier_share(sample);
    if ids >= 0.8 {
        return g(Identifier, 0.95, "the values look like names or IDs");
    }
    if ids >= 0.2 {
        return g(Sensitive, 0.5, "some values look like identifiers");
    }
    if name_in(name, QUASI_WORDS) {
        return g(Quasi, 0.9, "the name says it can single out a person");
    }
    if ty == ColType::Date && name_has(name, "birth") {
        return g(Quasi, 0.9, "a birth date can single out a person");
    }
    if numeric && checks::amount_name(name) {
        return g(Sensitive, 0.95, "the name says it holds amounts");
    }
    // Not in the brief's list: notes-like columns hold prose even when short
    // and repetitive, and must not be offered as a public category.
    if ty == ColType::Text && name_in(name, FREETEXT_WORDS) {
        return g(FreeText, 0.9, "the name says it holds free text");
    }
    if ty == ColType::Text {
        let mean = if sample.is_empty() {
            0
        } else {
            sample.iter().map(|v| v.chars().count()).sum::<usize>() / sample.len()
        };
        if mean > 40 || st.max_len > 200 {
            return g(FreeText, 0.9, "the values are long text");
        }
    }
    if matches!(ty, ColType::Text | ColType::Integer)
        && !id_shaped(name)
        && st.non_null > 0
        && st.distinct <= 50
        && (st.distinct as f64) / (st.non_null as f64) <= 0.01
    {
        return g(Public, 0.6, "few distinct values: a category list");
    }
    if ty == ColType::Integer
        && (name.eq_ignore_ascii_case("id") || name.to_lowercase().ends_with("_id"))
        && st.non_null > 0
        && st.distinct == st.non_null
    {
        return g(Identifier, 0.85, "a unique ID column");
    }
    g(Sensitive, 0.5, UNKNOWN)
}

/// The reason of the fallback guess: nothing told us what the column is.
pub const UNKNOWN: &str = "unknown columns are treated as sensitive";

/// R43-5: the user must confirm this suggestion.
pub fn uncertain(g: &Guess) -> bool {
    g.confidence < 0.8 || g.class == ColumnClass::Public
}

#[cfg(test)]
mod tests {
    use super::checks::*;
    use super::*;

    #[test]
    fn name_matching_is_by_part() {
        assert!(name_has("first_name", "name"));
        assert!(name_has("customer_no", "customer_no"));
        assert!(!name_has("created_by", "by"));
        assert!(name_has("by", "by"));
        assert!(!name_has("postcodes", "postcode"));
        assert!(amount_name("credit_limit"));
        assert!(!amount_name("status"));
    }

    #[test]
    fn word_lists_are_in_cleaned_form() {
        for w in IDENT_WORDS
            .iter()
            .chain(QUASI_WORDS)
            .chain(AMOUNT_WORDS)
            .chain(FREETEXT_WORDS)
        {
            assert_eq!(&crate::snapshot::clean_name(w, "c"), w, "{w}");
        }
    }

    #[test]
    fn id_shaped_names() {
        for n in [
            "id",
            "ID",
            "customer_id",
            "order_no",
            "konto_nr",
            "kundenr",
            "kundenummer",
            "email",
        ] {
            assert!(id_shaped(n), "{n}");
        }
        for n in ["status", "segment", "paid", "valid", "idea", "notes"] {
            assert!(!id_shaped(n), "{n}");
        }
    }

    #[test]
    fn phone_formats() {
        assert!(phone("+45 00 12 34 56"));
        assert!(phone("12345678"));
        assert!(!phone("2024-01-31"));
        assert!(!phone("1234567"));
    }
}
