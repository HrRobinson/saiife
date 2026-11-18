//! Plan 44 T5: the deterministic leak firewall (spec §2.2.5).
//!
//! Outgoing, every scan runs and every hit is collected, in this order:
//!
//! 1. **Part types.** `v`/`kind` fixed; schema names, entity words and
//!    public values are words of the dataset's allow list (schema words and
//!    k-floor values); row counts are bands; free text is capped (R44-7);
//!    parameter names, tags and stand-ins (R44-4) have their fixed forms;
//!    `retry.error_class` is a plan 45 planner class ([`PLANNER_ERROR_CLASSES`],
//!    ruling P-20) and `retry.previous_method_sha256` is `sha256:` and 64
//!    lowercase hex; every name of a schema join is a table or column of
//!    the envelope's own schema (plan 48 C1); every synthetic value has the exact shape the generator
//!    (`synth.rs`, R44-6) makes for its column. A part that fails is
//!    `bad_part` (`oversize` for a size).
//! 2. **Known values.** Every token and every 2-4-token window of every
//!    free-text string (the question, the context questions, synthetic text
//!    values) goes through
//!    [`KnownIndex::contains_value`], except windows whose every token is
//!    covered by an allow-list word; every whole sentence (split as
//!    [`crate::index::split_phrases`] splits) and the whole text go through
//!    [`KnownIndex::contains_phrase`].
//! 3. **Numbers** (R44-8, ruling P-4) over the question, the context
//!    questions and synthetic text (minus the generator's own numbers):
//!    every run of numeric characters, every number [`find_numbers`] finds
//!    (both languages; the other language's words that are common words of
//!    this one, Danish `to` and `fire` in English, are left out), every
//!    unreadable numeric ([`find_unreadable_numerics`]) and every number
//!    word. Exempt: `:pN` when `pN` is a parameter of that same part (P-21;
//!    any other `:p<digits>` is a hit), and digits inside an allow-list
//!    word that also has a letter (`address2`).
//! 4. **Patterns** over every string: email (except the two exact stand-in
//!    forms of ruling P-19), phone, IBAN (mod 97), CPR (`DDMMYY-?SSSS` with
//!    a real day and month); in free text also a date before today minus 15
//!    years (`pattern:birth_date`).
//! 5. **Names.** The detector over free text; a `Person` span that is not a
//!    released name (`blind:name`) or a stand-in of this envelope is `name`.
//!
//! The firewall is a strict schema allowlist (rulings P-22, P-25, P-26):
//! the caller keeps an [`Expected`] from the moment it builds the envelope,
//! and every part that is not free text must match it. `v` is 1;
//! `list_cap` and `lang` are the expected ones; the schema part hashes
//! ([`crate::envelope::schema_sha256`]) to the hash of
//! [`crate::envelope::cloud_schema`]'s output, so every name, band, class,
//! entity word and public value list is pinned byte for byte; every
//! stand-in is one the session issued; a retry carries exactly the hash of
//! the method the caller received ([`crate::envelope::method_sha256`]) and
//! never the method text (plan 48 C1, ruling R-C11). The form checks
//! (row bands as [`rows_band`] renders them, allow-list words, R44-4
//! symbols, parameter names `p1..pK` in order, each used as `:pN` in its
//! own text) stay as defence in depth. Synthetic rows (R44-6) hold exactly
//! the envelope's tables and columns, at most 5 rows a table, every value
//! of the generator's shape for its column, and hash
//! ([`crate::envelope::synthetic_sha256`]) to the expected hash. Only then
//! (P-24) are the generator's own spans exempt: the number inside a
//! synthetic text (`Synthetic_4711`, `synthetic12@example.invalid`), a
//! whole synthetic date and a whole k-floor public value. The number,
//! known-value and pattern scans skip those spans (a synthetic date has a
//! phone number's digit count; a k-floor value is pattern-scanned as a
//! typed part where the schema lists it, under `schema...values`); the
//! name scan runs on all of the text, and every scan runs on the rest of
//! it (`Synthetic_` and the column name).
//!
//! [`Firewall::check_bytes`] takes the exact bytes to send: they must
//! deserialize into [`Envelope`] (unknown fields refused at every level)
//! and be byte-equal to that envelope's [`Envelope::canonical`], else the
//! verdict is `bad_part` on `body`. Strings are never re-parsed as JSON:
//! they are scanned as they are. Then the scans of `check_outgoing` run, so
//! `check_bytes(e.canonical())` gives the same hits as `check_outgoing`.
//! Plan 47 wraps these bytes verbatim in its own typed request frame (P-23).
//!
//! Incoming text (method, template, intent line) gets the known-value scan
//! (number-only windows aside: the validator refuses literals) and the
//! email, IBAN and CPR patterns. Any hit means the provider had a value it
//! should never have had: every incoming hit is `known_value`.
//!
//! Fail closed: an index or detector error is an `Err`; a detector span off
//! a character boundary is an `Err`. S-1: every offset is a byte offset into
//! the string being scanned, computed on that same string; every slice goes
//! through `str::get`. A [`Hit`] names the part and the span, never the
//! text. Error texts are fixed strings.

use crate::envelope::{
    schema_sha256, synthetic_sha256, CloudColumn, CloudParam, CloudSchema, Envelope, ENVELOPE_KIND,
    ENVELOPE_VERSION,
};
use crate::error::ShieldError;
use crate::index::{AllowList, KnownIndex};
use crate::lang::{find_dates, find_numbers, find_unreadable_numerics, number_words};
use crate::ner::{NameDetector, SpanLabel};
use crate::norm::{normalize, token_spans};
use crate::schema::{rows_band, ColType, ColumnClass, Decimal, Lang};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;

// -------------------------------------------------------------- values ----

pub const KNOWN_VALUE: &str = "known_value";
pub const KNOWN_PHRASE: &str = "known_phrase";
pub const NUMBER: &str = "number";
pub const EMAIL: &str = "pattern:email";
pub const PHONE: &str = "pattern:phone";
pub const IBAN: &str = "pattern:iban";
pub const CPR: &str = "pattern:cpr";
pub const BIRTH_DATE: &str = "pattern:birth_date";
pub const NAME: &str = "name";
pub const OVERSIZE: &str = "oversize";
pub const BAD_PART: &str = "bad_part";

/// R44-7: the stripped question and each context question.
pub const MAX_FREE_TEXT_CHARS: usize = 1_000;
/// R44-7: context turns.
pub const MAX_CONTEXT_TURNS: usize = 10;
/// R44-7 / P-20: `retry.error_class`.
pub const MAX_ERROR_CLASS_CHARS: usize = 120;
/// R44-6: synthetic rows per table.
pub const MAX_SYNTHETIC_ROWS: usize = 5;
/// The whole HTTP body `check_bytes` accepts.
pub const MAX_BODY_BYTES: usize = 4 << 20;
/// The known-value window (spec §2.2.5: 2-4 tokens).
const WINDOW: usize = 4;
/// The longest allow-list word (in tokens) looked for in a text.
const MAX_ALLOW_TOKENS: usize = 16;
/// R43-9 / `index::split_phrases`: where free text splits into sentences.
const PHRASE_SPLIT: [char; 5] = ['.', '!', '?', ';', '\n'];
/// Years before today that make a date in free text a birth date.
const BIRTH_YEARS: i64 = 15;

/// The parameter type tags (plan 44 fixed values).
pub const PARAM_TYPES: [&str; 7] = [
    "entity",
    "amount",
    "integer",
    "percent",
    "date",
    "date_range",
    "text",
];

/// Plan 45 R45-8: the error classes that can go back to the planner (the
/// ones found before the preview). Keep in step with plan 45's
/// `ErrorClass`; the run-time classes never go back (ruling P-20).
pub const PLANNER_ERROR_CLASSES: [&str; 16] = [
    "syntax",
    "not_select",
    "multiple_statements",
    "unknown_table",
    "unknown_column",
    "function_not_allowed",
    "construct_not_allowed",
    "literal_not_allowed",
    "param_misuse",
    "param_type",
    "null_masking",
    "too_many_joins",
    "too_deep",
    "too_many_columns",
    "identifier_output",
    "template_slot",
];
/// R45-8: the classes sent with the cloud name that failed.
const NAMED_ERROR_CLASSES: [&str; 3] = ["unknown_table", "unknown_column", "template_slot"];

/// One finding: the kind, the part (`question`, `synthetic.customers[2].city`,
/// ...) and the byte span in that part. Never the matched text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub kind: &'static str,
    pub part: String,
    pub span: Option<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Block(Vec<Hit>),
}

fn verdict(hits: Vec<Hit>) -> Verdict {
    if hits.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Block(hits)
    }
}

pub struct Firewall<'a> {
    pub index: &'a KnownIndex,
    pub allow: &'a AllowList,
    pub detector: &'a dyn NameDetector,
    /// The names a `blind:name` touch released (ruling P-28): this ask's
    /// releases together with [`crate::session::Session::released_names`]
    /// (the live turns' releases), because the context turns resend those
    /// turns' questions. Bounded by the session (at most 10 turns, 30
    /// minutes).
    pub released_names: &'a [String],
    /// What the caller put in the envelope (P-22, P-25, P-26).
    pub expected: Expected<'a>,
}

/// The caller-held expectations of one envelope (ruling P-26): the caller
/// keeps them from the moment it builds the envelope, and the firewall
/// requires the envelope to match them byte for byte.
///
/// Never derive any field from the envelope being checked (for example
/// `schema_sha256(&e.schema)` or the symbols of `e.params`): the pin is then
/// circular and checks nothing. Build each from the inputs the caller gave
/// `build_envelope`, and `symbols` from
/// [`crate::session::Session::issued_symbols`] after the build.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The `list_cap` passed to `build_envelope`.
    pub list_cap: u32,
    /// The draft's language.
    pub lang: Lang,
    /// [`schema_sha256`] of [`crate::envelope::cloud_schema`]'s output.
    pub schema_sha256: &'a str,
    /// [`synthetic_sha256`] of the `synthetic_rows` output passed to
    /// `build_envelope`.
    pub synthetic_sha256: &'a str,
    /// Every stand-in the session issued (P-25):
    /// [`crate::session::Session::issued_symbols`], called after
    /// `build_envelope`.
    pub symbols: &'a [String],
    /// [`crate::envelope::method_sha256`] of the previous method received from the planner,
    /// for a retry; `None` for a first request.
    pub previous_method_sha256: Option<&'a str>,
}

impl fmt::Debug for Firewall<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Firewall")
            .field("index", &self.index)
            .field("allow", &self.allow)
            .field("released_names", &self.released_names.len())
            .field("list_cap", &self.expected.list_cap)
            .field("lang", &self.expected.lang)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------- parts ----

/// Normalized tokens with their byte spans in the original text.
type Tokens = Vec<(String, usize, usize)>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Every scan (question, context questions, synthetic text).
    Free,
    /// Incoming text: known values and patterns.
    Method,
    /// Typed parts: patterns only (part 1 checked their form).
    Typed,
}

struct Text {
    part: String,
    text: String,
    class: Class,
    /// `:pN` names that are parameters of this part.
    params: Vec<String>,
    /// Spans of generator-made numbers and k-floor values (exempt).
    exempt: Vec<(usize, usize)>,
    /// Over its size cap: blocked already, not scanned further.
    oversize: bool,
}

impl Text {
    fn new(part: String, text: &str, class: Class) -> Text {
        Text {
            part,
            text: text.to_string(),
            class,
            params: Vec::new(),
            exempt: Vec::new(),
            oversize: false,
        }
    }
}

fn hit(hits: &mut Vec<Hit>, kind: &'static str, part: &str, span: Option<(usize, usize)>) {
    let h = Hit {
        kind,
        part: part.to_string(),
        span,
    };
    if !hits.contains(&h) {
        hits.push(h);
    }
}

fn inside(ex: &[(usize, usize)], s: usize, e: usize) -> bool {
    ex.iter().any(|&(a, b)| a <= s && e <= b)
}

fn allowed(allow: Option<&AllowList>, s: &str) -> bool {
    match allow {
        None => true,
        Some(a) => {
            let n = normalize(s);
            !n.is_empty() && a.words.contains(&n)
        }
    }
}

/// `<Word>_<4 or 6 base32>` (R44-4); with `word`, the Word must be that
/// entity word as `standin` capitalizes it.
fn symbol_ok(sym: &str, word: Option<&str>) -> bool {
    let Some((w, code)) = sym.split_once('_') else {
        return false;
    };
    let mut wc = w.chars();
    let word_ok = wc.next().is_some_and(|c| c.is_ascii_uppercase())
        && wc.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let code_ok = (code.len() == 4 || code.len() == 6)
        && code
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b));
    word_ok && code_ok && word.is_none_or(|x| capitalize(x) == w)
}

/// As `standin::capitalize`: ASCII alphanumerics, first upper, rest lower.
fn capitalize(word: &str) -> String {
    let mut w: String = word.chars().filter(char::is_ascii_alphanumeric).collect();
    if w.is_empty() {
        w.push_str("entity");
    }
    w.chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// The tag of a parameter: a fixed type, or `entity:<cloud table>` /
/// `text:<cloud table>.<cloud column>` of this schema. Returns the entity
/// word the stand-in must carry: `Some(Some(w))` for a named entity table,
/// `Some(None)` for a bare `entity`, `None` for a valid non-entity tag; the
/// outer `Err` is a bad tag.
fn tag_check(schema: &CloudSchema, ty: &str) -> Result<Option<Option<String>>, ()> {
    if ty == "entity" {
        return Ok(Some(None));
    }
    if PARAM_TYPES.contains(&ty) {
        return Ok(None);
    }
    if let Some(t) = ty.strip_prefix("entity:") {
        return schema
            .tables
            .iter()
            .find(|x| x.name == t)
            .and_then(|x| x.entity.clone())
            .map(|w| Some(Some(w)))
            .ok_or(());
    }
    if let Some(tc) = ty.strip_prefix("text:") {
        let ok = schema.tables.iter().any(|t| {
            t.columns
                .iter()
                .any(|c| tc.strip_prefix(t.name.as_str()) == Some(&format!(".{}", c.name)))
        });
        return if ok { Ok(None) } else { Err(()) };
    }
    Err(())
}

/// Ruling P-20.
fn error_class_ok(schema: &CloudSchema, s: &str) -> bool {
    if s.chars().count() > MAX_ERROR_CLASS_CHARS {
        return false;
    }
    let (class, rest) = match s.split_once(' ') {
        Some((c, r)) => (c, Some(r)),
        None => (s, None),
    };
    if !PLANNER_ERROR_CLASSES.contains(&class) {
        return false;
    }
    let Some(name) = rest else {
        return true;
    };
    NAMED_ERROR_CLASSES.contains(&class)
        && schema.tables.iter().any(|t| {
            t.name == name
                || t.columns.iter().any(|c| {
                    c.name == name
                        || name.strip_prefix(t.name.as_str()) == Some(&format!(".{}", c.name))
                })
        })
}

/// `sha256:` and 64 lowercase hex, as [`crate::envelope::sha256_hex`]
/// writes it.
fn sha256_form_ok(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Exactly a [`rows_band`] output: the number it names, rendered again,
/// gives the same bytes (P-22).
fn band_ok(s: &str) -> bool {
    if s == "<100" {
        return true;
    }
    let Some(rest) = s.strip_prefix("about ") else {
        return false;
    };
    let (n, unit) = rest.split_once(' ').unwrap_or((rest, ""));
    let mult: u64 = match unit {
        "" => 1,
        "thousand" => 1_000,
        "million" => 1_000_000,
        "billion" => 1_000_000_000,
        _ => return false,
    };
    if n.is_empty() || n.len() > 4 || n.starts_with('0') || !n.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    n.parse::<u64>()
        .ok()
        .and_then(|v| v.checked_mul(mult))
        .is_some_and(|v| rows_band(v) == s)
}

/// A generator number: 1..=99 999, no leading zero.
fn gen_number(s: &str) -> bool {
    !s.is_empty() && s.len() <= 5 && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit())
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `YYYY-MM-DD`, a real date.
fn iso_date_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let p = b.get(r)?;
        p.iter().try_fold(0i64, |a, &c| {
            c.is_ascii_digit().then(|| a * 10 + i64::from(c - b'0'))
        })
    };
    match (num(0..4), num(5..7), num(8..10)) {
        (Some(y), Some(m), Some(d)) => (1..=12).contains(&m) && d >= 1 && d <= days_in_month(y, m),
        _ => false,
    }
}

/// R44-6: the exact shape `synth.rs` gives a value of `col`. `Ok` holds the
/// exempt spans (the generated number, a generated date, a k-floor value);
/// `Err` is a value the generator cannot have made.
fn synthetic_shape(
    col: &CloudColumn,
    v: &Value,
    allow: Option<&AllowList>,
) -> Result<Vec<(usize, usize)>, ()> {
    let list = col.values.as_deref().unwrap_or(&[]);
    if v.is_null() {
        // The generator writes NULL only for a public column with no k-floor
        // value.
        return if col.class == ColumnClass::Public && list.is_empty() {
            Ok(Vec::new())
        } else {
            Err(())
        };
    }
    match col.class {
        ColumnClass::Public => {
            let s = v.as_str().ok_or(())?;
            let in_list = list.iter().any(|x| x == s);
            return if in_list && allowed(allow, s) {
                Ok(vec![(0, s.len())])
            } else {
                Err(())
            };
        }
        ColumnClass::FreeText => {
            return if v.as_str() == Some("(free text)") {
                Ok(Vec::new())
            } else {
                Err(())
            };
        }
        _ => {}
    }
    match col.ty {
        ColType::Integer => match v.as_u64() {
            Some(n) if (1..=99_999).contains(&n) => Ok(Vec::new()),
            _ => Err(()),
        },
        ColType::Real => {
            let Value::Number(n) = v else {
                return Err(());
            };
            let d = Decimal::parse_plain(&n.to_string()).ok_or(())?;
            let lo = Decimal { units: 0, scale: 0 };
            let hi = Decimal {
                units: 9_999_999,
                scale: 2,
            };
            if d.scale <= 2 && d >= lo && d <= hi {
                Ok(Vec::new())
            } else {
                Err(())
            }
        }
        ColType::Bool => v.as_bool().map(|_| Vec::new()).ok_or(()),
        ColType::Date => {
            let s = v.as_str().ok_or(())?;
            if iso_date_ok(s) && ("2000-01-01"..="2030-12-31").contains(&s) {
                Ok(vec![(0, s.len())])
            } else {
                Err(())
            }
        }
        ColType::Text => {
            let s = v.as_str().ok_or(())?;
            const MAIL_AT: &str = "@example.invalid";
            if let Some(n) = s
                .strip_prefix("synthetic")
                .and_then(|r| r.strip_suffix(MAIL_AT))
            {
                return if gen_number(n) {
                    Ok(vec![(9, 9 + n.len())])
                } else {
                    Err(())
                };
            }
            let rest = s.strip_prefix("Synthetic_").ok_or(())?;
            let n = if col.class == ColumnClass::Identifier {
                rest
            } else {
                rest.strip_prefix(col.name.as_str())
                    .and_then(|r| r.strip_prefix('_'))
                    .ok_or(())?
            };
            if gen_number(n) {
                Ok(vec![(s.len() - n.len(), s.len())])
            } else {
                Err(())
            }
        }
    }
}

/// A name for a part path: the name when it is byte-equal to a name of a
/// schema part the caller's hash pinned, else `#<index>` (a part name never
/// carries an unchecked text).
fn path_name(pinned: bool, name: &str, known: bool, i: usize) -> String {
    if pinned && known {
        name.to_string()
    } else {
        format!("#{i}")
    }
}

/// What the caller expects of an envelope, with the allow list.
struct Expect<'x> {
    allow: &'x AllowList,
    expected: Expected<'x>,
}

/// Part 1 and the strings of an envelope. `expect` None (the summary): the
/// checks against the caller's expectations are skipped, and the caller
/// drops every hit of part 1.
fn envelope_parts(e: &Envelope, expect: Option<&Expect<'_>>, hits: &mut Vec<Hit>) -> Vec<Text> {
    let mut texts: Vec<Text> = Vec::new();
    let allow = expect.map(|x| x.allow);
    let p = |s: &str| s.to_string();

    if e.v != ENVELOPE_VERSION {
        hit(hits, BAD_PART, &p("v"), None);
    }
    if expect.is_some_and(|x| x.expected.list_cap != e.list_cap) {
        hit(hits, BAD_PART, &p("list_cap"), None);
    }
    if expect.is_some_and(|x| x.expected.lang != e.lang) {
        hit(hits, BAD_PART, &p("lang"), None);
    }
    // P-26: the schema part is byte-pinned by the caller's hash. The form
    // checks below stay as defence in depth.
    let schema_ok = expect.is_some_and(|x| schema_sha256(&e.schema) == x.expected.schema_sha256);
    if expect.is_some() && !schema_ok {
        hit(hits, BAD_PART, &p("schema"), None);
    }
    if e.kind != ENVELOPE_KIND {
        hit(hits, BAD_PART, &p("kind"), None);
    }
    texts.push(Text::new(p("kind"), &e.kind, Class::Typed));

    // The schema: names and words from the allow list, bands, k-floor values.
    for (ti, t) in e.schema.tables.iter().enumerate() {
        let tp = p(&format!("schema.tables[{ti}]"));
        if !allowed(allow, &t.name)
            || e.schema.tables.iter().filter(|x| x.name == t.name).count() > 1
        {
            hit(hits, BAD_PART, &format!("{tp}.name"), None);
        }
        texts.push(Text::new(format!("{tp}.name"), &t.name, Class::Typed));
        if !band_ok(&t.rows) {
            hit(hits, BAD_PART, &format!("{tp}.rows"), None);
        }
        texts.push(Text::new(format!("{tp}.rows"), &t.rows, Class::Typed));
        if let Some(w) = &t.entity {
            if !allowed(allow, w) {
                hit(hits, BAD_PART, &format!("{tp}.entity"), None);
            }
            texts.push(Text::new(format!("{tp}.entity"), w, Class::Typed));
        }
        for (ci, c) in t.columns.iter().enumerate() {
            let cp = format!("{tp}.columns[{ci}]");
            if !allowed(allow, &c.name) || t.columns.iter().filter(|x| x.name == c.name).count() > 1
            {
                hit(hits, BAD_PART, &format!("{cp}.name"), None);
            }
            texts.push(Text::new(format!("{cp}.name"), &c.name, Class::Typed));
            if let Some(vals) = &c.values {
                if c.class != ColumnClass::Public {
                    hit(hits, BAD_PART, &format!("{cp}.values"), None);
                }
                for (vi, v) in vals.iter().enumerate() {
                    let vp = format!("{cp}.values[{vi}]");
                    if !allowed(allow, v) {
                        hit(hits, BAD_PART, &vp, None);
                    }
                    texts.push(Text::new(vp, v, Class::Typed));
                }
            }
        }
    }

    // The joins (plan 48 C1): every name is one of the envelope's own
    // tables and columns (an entity table and its column; another table
    // and its INTEGER column), from the allow list, no duplicates.
    for (ji, j) in e.schema.joins.iter().enumerate() {
        let jp = format!("schema.joins[{ji}]");
        let table = |n: &str| e.schema.tables.iter().find(|t| t.name == n);
        let column =
            |t: &str, c: &str| table(t).and_then(|t| t.columns.iter().find(|x| x.name == c));
        let ok = table(&j.entity).is_some_and(|t| t.entity.is_some())
            && column(&j.entity, &j.key).is_some()
            && j.table != j.entity
            && column(&j.table, &j.column).is_some_and(|c| c.ty == ColType::Integer)
            && [&j.entity, &j.key, &j.table, &j.column]
                .iter()
                .all(|n| allowed(allow, n))
            && !e.schema.joins[..ji].contains(j);
        if !ok {
            hit(hits, BAD_PART, &jp, None);
        }
        for (k, n) in [
            ("entity", &j.entity),
            ("key", &j.key),
            ("table", &j.table),
            ("column", &j.column),
        ] {
            texts.push(Text::new(format!("{jp}.{k}"), n, Class::Typed));
        }
    }

    // Synthetic rows: exactly the schema's tables and columns, the caller's
    // hash, each value of the generator's exact shape.
    let hash_ok =
        expect.is_none_or(|x| synthetic_sha256(&e.synthetic) == x.expected.synthetic_sha256);
    let want: BTreeSet<&str> = e.schema.tables.iter().map(|t| t.name.as_str()).collect();
    let have: BTreeSet<&str> = e.synthetic.keys().map(String::as_str).collect();
    if !hash_ok || want != have {
        hit(hits, BAD_PART, &p("synthetic"), None);
    }
    for (ti, (tname, rows)) in e.synthetic.iter().enumerate() {
        let table = e.schema.tables.iter().find(|t| &t.name == tname);
        let tp = p(&format!(
            "synthetic.{}",
            path_name(schema_ok, tname, table.is_some(), ti)
        ));
        if table.is_none() || rows.len() > MAX_SYNTHETIC_ROWS {
            hit(hits, BAD_PART, &tp, None);
        }
        texts.push(Text::new(format!("{tp}#name"), tname, Class::Typed));
        let cols: BTreeSet<&str> = table
            .map(|t| t.columns.iter().map(|c| c.name.as_str()).collect())
            .unwrap_or_default();
        for (ri, row) in rows.iter().enumerate() {
            let keys: BTreeSet<&str> = row.keys().map(String::as_str).collect();
            if keys != cols {
                hit(hits, BAD_PART, &format!("{tp}[{ri}]"), None);
            }
            for (ci, (cname, v)) in row.iter().enumerate() {
                let col = table.and_then(|t| t.columns.iter().find(|c| &c.name == cname));
                let vp = format!(
                    "{tp}[{ri}].{}",
                    path_name(schema_ok, cname, col.is_some(), ci)
                );
                if col.is_none() {
                    hit(hits, BAD_PART, &vp, None);
                    texts.push(Text::new(format!("{vp}#name"), cname, Class::Typed));
                }
                let shape = col.map_or(Err(()), |c| synthetic_shape(c, v, allow));
                if shape.is_err() {
                    hit(hits, BAD_PART, &vp, None);
                }
                if let Value::String(s) = v {
                    let mut t = Text::new(vp, s, Class::Free);
                    // P-24: exempt only when the shape and the hash hold.
                    if hash_ok {
                        t.exempt = shape.unwrap_or_default();
                    }
                    if s.chars().count() > MAX_FREE_TEXT_CHARS {
                        hit(hits, OVERSIZE, &t.part, None);
                        t.oversize = true;
                    }
                    texts.push(t);
                }
            }
        }
    }

    // The question and its parameters.
    let mut q = Text::new(p("question"), &e.question, Class::Free);
    q.params = e.params.iter().map(|x| x.name.clone()).collect();
    if e.question.chars().count() > MAX_FREE_TEXT_CHARS {
        hit(hits, OVERSIZE, &q.part, None);
        q.oversize = true;
    }
    check_params(e, &e.params, &p("params"), &q.text, hits, &mut texts);
    texts.push(q);

    // The context.
    if e.context.len() > MAX_CONTEXT_TURNS {
        hit(hits, OVERSIZE, &p("context"), None);
    }
    for (i, turn) in e.context.iter().enumerate() {
        let tp = p(&format!("context[{i}]"));
        let mut t = Text::new(format!("{tp}.question"), &turn.question, Class::Free);
        t.params = turn.params.iter().map(|x| x.name.clone()).collect();
        if turn.question.chars().count() > MAX_FREE_TEXT_CHARS {
            hit(hits, OVERSIZE, &t.part, None);
            t.oversize = true;
        }
        check_params(
            e,
            &turn.params,
            &format!("{tp}.params"),
            &t.text,
            hits,
            &mut texts,
        );
        texts.push(t);
    }

    // P-25: every stand-in is one the session issued, byte for byte.
    if let Some(x) = expect {
        let all = e
            .params
            .iter()
            .enumerate()
            .map(|(i, cp)| (format!("params[{i}].symbol"), cp))
            .chain(e.context.iter().enumerate().flat_map(|(t, turn)| {
                turn.params
                    .iter()
                    .enumerate()
                    .map(move |(i, cp)| (format!("context[{t}].params[{i}].symbol"), cp))
            }));
        for (part, cp) in all {
            if let Some(sym) = &cp.symbol {
                if !x.expected.symbols.iter().any(|s| s == sym) {
                    hit(hits, BAD_PART, &part, None);
                }
            }
        }
        // P-26, R-C11: a retry carries exactly the hash of the method the
        // caller received.
        match (&e.retry, x.expected.previous_method_sha256) {
            (None, None) => {}
            (Some(r), Some(h)) if r.previous_method_sha256 == h => {}
            (Some(_), Some(_)) => hit(hits, BAD_PART, &p("retry.previous_method_sha256"), None),
            _ => hit(hits, BAD_PART, &p("retry"), None),
        }
    }

    // The retry.
    if let Some(r) = &e.retry {
        if !error_class_ok(&e.schema, &r.error_class) {
            hit(hits, BAD_PART, &p("retry.error_class"), None);
        }
        texts.push(Text::new(
            p("retry.error_class"),
            &r.error_class,
            Class::Typed,
        ));
        // The hash only (R-C11): its form is fixed, and the caller's pin
        // above ties it to the method the daemon received.
        if !sha256_form_ok(&r.previous_method_sha256) {
            hit(hits, BAD_PART, &p("retry.previous_method_sha256"), None);
        }
        texts.push(Text::new(
            p("retry.previous_method_sha256"),
            &r.previous_method_sha256,
            Class::Typed,
        ));
    }
    texts
}

/// Names exactly `p1..pK` in order, each referenced as `:pN` in `text`
/// (P-22); tags from the fixed list; an entity has a well-formed stand-in,
/// nothing else has one.
fn check_params(
    e: &Envelope,
    params: &[CloudParam],
    base: &str,
    text: &str,
    hits: &mut Vec<Hit>,
    texts: &mut Vec<Text>,
) {
    let refs: Vec<&str> = param_refs(text).into_iter().map(|r| r.2).collect();
    for (i, cp) in params.iter().enumerate() {
        let pp = format!("{base}[{i}]");
        let name_ok = cp.name == format!("p{}", i + 1) && refs.contains(&cp.name.as_str());
        if !name_ok {
            hit(hits, BAD_PART, &format!("{pp}.name"), None);
        }
        texts.push(Text::new(format!("{pp}.name"), &cp.name, Class::Typed));
        texts.push(Text::new(format!("{pp}.ty"), &cp.ty, Class::Typed));
        match (tag_check(&e.schema, &cp.ty), &cp.symbol) {
            (Err(()), _) => hit(hits, BAD_PART, &format!("{pp}.ty"), None),
            (Ok(None), Some(_)) | (Ok(Some(_)), None) => {
                hit(hits, BAD_PART, &format!("{pp}.symbol"), None)
            }
            (Ok(Some(word)), Some(sym)) => {
                let ok = match word {
                    Some(w) => symbol_ok(sym, Some(&w)),
                    None => e
                        .schema
                        .tables
                        .iter()
                        .filter_map(|t| t.entity.as_deref())
                        .any(|w| symbol_ok(sym, Some(w))),
                };
                if !ok {
                    hit(hits, BAD_PART, &format!("{pp}.symbol"), None);
                }
            }
            (Ok(None), None) => {}
        }
        if let Some(sym) = &cp.symbol {
            texts.push(Text::new(format!("{pp}.symbol"), sym, Class::Typed));
        }
    }
}

/// Every symbol of the envelope (they may appear as detector spans).
fn symbols_of(e: &Envelope) -> Vec<String> {
    e.params
        .iter()
        .chain(e.context.iter().flat_map(|t| t.params.iter()))
        .filter_map(|p| p.symbol.clone())
        .collect()
}

// ------------------------------------------------------------- patterns ----

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn prev_char(s: &str, i: usize) -> Option<char> {
    s.get(..i).and_then(|p| p.chars().next_back())
}

fn next_char(s: &str, i: usize) -> Option<char> {
    s.get(i..).and_then(|p| p.chars().next())
}

/// Ruling P-19: the only emails that are not a hit.
fn exempt_email(m: &str) -> bool {
    let Some(local) = m.strip_suffix("@example.invalid") else {
        return false;
    };
    if let Some(d) = local.strip_prefix("synthetic") {
        return !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit());
    }
    local.strip_prefix("user_").is_some_and(|c| {
        (c.len() == 4 || c.len() == 6)
            && c.bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
    })
}

fn email_spans(s: &str) -> Vec<(usize, usize)> {
    let local = |c: char| c.is_alphanumeric() || "._%+-'".contains(c);
    let domain = |c: char| c.is_alphanumeric() || c == '.' || c == '-';
    let mut out = Vec::new();
    for (at, _) in s.match_indices('@') {
        let mut start = at;
        while let Some(c) = prev_char(s, start) {
            if !local(c) {
                break;
            }
            start -= c.len_utf8();
        }
        let mut end = at + 1;
        while let Some(c) = next_char(s, end) {
            if !domain(c) {
                break;
            }
            end += c.len_utf8();
        }
        while end > at + 1 && s.get(..end).is_some_and(|p| p.ends_with(['.', '-'])) {
            end -= 1;
        }
        let Some(dom) = s.get(at + 1..end) else {
            continue;
        };
        let has_dot = dom
            .rsplit_once('.')
            .is_some_and(|(a, tld)| !a.is_empty() && tld.chars().count() >= 2);
        if start < at && has_dot {
            if let Some(m) = s.get(start..end) {
                if !exempt_email(m) {
                    out.push((start, end));
                }
            }
        }
    }
    out
}

/// 8 to 15 digits, optionally after `+`, with single separators
/// (` -./()`), not inside a word.
fn phone_spans(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(c) = next_char(s, i) {
        let starts = (c == '+' || c.is_numeric()) && !prev_char(s, i).is_some_and(is_word);
        if !starts {
            i += c.len_utf8();
            continue;
        }
        let mut j = i + c.len_utf8();
        let mut digits = usize::from(c.is_numeric());
        let mut last_digit_end = if c.is_numeric() { j } else { i };
        let mut sep = c == '+';
        while let Some(d) = next_char(s, j) {
            if d.is_numeric() {
                digits += 1;
                j += d.len_utf8();
                last_digit_end = j;
                sep = false;
            } else if " -./()".contains(d) && !sep {
                sep = true;
                j += d.len_utf8();
            } else {
                break;
            }
        }
        let end = last_digit_end;
        if (8..=15).contains(&digits) && !next_char(s, end).is_some_and(is_word) {
            out.push((i, end));
            i = end;
        } else {
            i += c.len_utf8();
        }
    }
    out
}

/// Two letters, two digits, then letters and digits (single spaces allowed
/// between them), 15 to 34 in all, with the mod-97 check.
fn iban_spans(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(c) = next_char(s, i) {
        if !c.is_ascii_alphabetic() || prev_char(s, i).is_some_and(is_word) {
            i += c.len_utf8();
            continue;
        }
        // (char, byte end) of each alphanumeric, spaces skipped.
        let mut chars: Vec<(u8, usize)> = Vec::with_capacity(34);
        let mut j = i;
        let mut space = false;
        while chars.len() < 34 {
            match next_char(s, j) {
                Some(d) if d.is_ascii_alphanumeric() => {
                    j += 1;
                    chars.push((d.to_ascii_uppercase() as u8, j));
                    space = false;
                }
                Some(' ') if !space && !chars.is_empty() => {
                    j += 1;
                    space = true;
                }
                _ => break,
            }
        }
        let head = chars.len() >= 4
            && chars[1].0.is_ascii_alphabetic()
            && chars[2].0.is_ascii_digit()
            && chars[3].0.is_ascii_digit();
        let mut found = None;
        if head {
            for len in (15..=chars.len()).rev() {
                let end = chars[len - 1].1;
                if next_char(s, end).is_some_and(|d| d.is_ascii_alphanumeric()) {
                    continue;
                }
                if mod97(&chars[..len]) == 1 {
                    found = Some(end);
                    break;
                }
            }
        }
        match found {
            Some(end) => {
                out.push((i, end));
                i = end;
            }
            None => i += c.len_utf8(),
        }
    }
    out
}

fn mod97(chars: &[(u8, usize)]) -> u32 {
    let mut r: u32 = 0;
    let rotated = chars[4..].iter().chain(chars[..4].iter());
    for &(c, _) in rotated {
        if c.is_ascii_digit() {
            r = (r * 10 + u32::from(c - b'0')) % 97;
        } else {
            let v = u32::from(c - b'A') + 10;
            r = (r * 100 + v) % 97;
        }
    }
    r
}

/// `\b\d{6}-?\d{4}\b` whose first six digits are a real `DDMMYY`.
fn cpr_spans(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let at_start =
            b[i].is_ascii_digit() && s.is_char_boundary(i) && !prev_char(s, i).is_some_and(is_word);
        if !at_start {
            i += 1;
            continue;
        }
        let digits = |from: usize, n: usize| {
            b.get(from..from + n)
                .is_some_and(|x| x.iter().all(u8::is_ascii_digit))
        };
        let mut found = None;
        if digits(i, 6) {
            for (gap, total) in [(1usize, 11usize), (0, 10)] {
                if gap == 1 && b.get(i + 6) != Some(&b'-') {
                    continue;
                }
                if digits(i + 6 + gap, 4) && !next_char(s, i + total).is_some_and(is_word) {
                    found = Some(i + total);
                    break;
                }
            }
        }
        let date_ok = |b: &[u8]| {
            let n = |k: usize| u32::from(b[i + k] - b'0');
            let (d, m) = (n(0) * 10 + n(1), n(2) * 10 + n(3));
            let max = match m {
                2 => 29,
                4 | 6 | 9 | 11 => 30,
                1..=12 => 31,
                _ => 0,
            };
            d >= 1 && d <= max
        };
        match found {
            Some(end) if date_ok(b) => {
                out.push((i, end));
                i = end;
            }
            _ => i += 1,
        }
    }
    out
}

/// Today minus 15 years as `YYYY-MM-DD` (29 February becomes the 28th).
/// A clock before 1970 is an error: the scan never runs with a wrong date.
fn birth_cutoff() -> Result<String, ShieldError> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ShieldError::Corrupt("the system clock is before 1970"))?
        .as_secs();
    Ok(cutoff_from_days((secs / 86_400) as i64))
}

fn cutoff_from_days(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    let y = y - BIRTH_YEARS;
    let d = d.min(days_in_month(y, m));
    format!("{y:04}-{m:02}-{d:02}")
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Which pattern scans a string gets.
#[derive(Clone, Copy)]
struct Patterns {
    phone: bool,
    birth: bool,
}

fn pattern_hits(t: &Text, which: Patterns, cutoff: &str, hits: &mut Vec<Hit>) {
    let s = t.text.as_str();
    let mut found: Vec<(&'static str, (usize, usize))> = Vec::new();
    found.extend(email_spans(s).into_iter().map(|x| (EMAIL, x)));
    if which.phone {
        found.extend(phone_spans(s).into_iter().map(|x| (PHONE, x)));
    }
    found.extend(iban_spans(s).into_iter().map(|x| (IBAN, x)));
    found.extend(cpr_spans(s).into_iter().map(|x| (CPR, x)));
    if which.birth {
        for lang in [Lang::En, Lang::Da] {
            for (a, b, iso) in find_dates(s, lang) {
                if iso.as_str() < cutoff {
                    found.push((BIRTH_DATE, (a, b)));
                }
            }
        }
    }
    for (kind, (a, b)) in found {
        if !inside(&t.exempt, a, b) {
            hit(hits, kind, &t.part, Some((a, b)));
        }
    }
}

// -------------------------------------------------------------- numbers ----

/// Danish number words that are common English words: not a hit in an
/// English text through the Danish list (they still are in Danish text).
fn ambiguous_in_other(lang: Lang, word: &str) -> bool {
    lang == Lang::Da && matches!(word.to_lowercase().as_str(), "to" | "fire")
}

/// `:p<digits>` references: (start, end, name without the colon).
pub(crate) fn param_refs(s: &str) -> Vec<(usize, usize, &str)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b.get(i) == Some(&b':') && b.get(i + 1) == Some(&b'p') {
            let mut j = i + 2;
            while b.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
            }
            if j > i + 2 {
                if let Some(name) = s.get(i + 1..j) {
                    out.push((i, j, name));
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// R44-8 / P-4 / P-21.
fn number_hits(
    t: &Text,
    toks: &[(String, usize, usize)],
    marks: &[bool],
    primary: &[Lang],
    hits: &mut Vec<Hit>,
) {
    let s = t.text.as_str();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    // Every run of numeric characters (ASCII digits, ², ５, ١٢٣, ½, ...).
    let mut run: Option<usize> = None;
    for (i, c) in s.char_indices() {
        if c.is_numeric() {
            run.get_or_insert(i);
        } else if let Some(a) = run.take() {
            spans.push((a, i));
        }
    }
    if let Some(a) = run {
        spans.push((a, s.len()));
    }
    for lang in [Lang::En, Lang::Da] {
        let own = primary.contains(&lang);
        for (a, b, _) in find_numbers(s, lang) {
            if own || !s.get(a..b).is_some_and(|w| ambiguous_in_other(lang, w)) {
                spans.push((a, b));
            }
        }
    }
    spans.extend(find_unreadable_numerics(s));
    for (_, a, b) in toks {
        let Some(w) = s.get(*a..*b) else {
            continue;
        };
        let lw = w.to_lowercase();
        for lang in [Lang::En, Lang::Da] {
            let own = primary.contains(&lang);
            if number_words(lang).is_number_word(&lw) && (own || !ambiguous_in_other(lang, w)) {
                spans.push((*a, *b));
            }
        }
    }

    let mut ex = t.exempt.clone();
    for (a, b, name) in param_refs(s) {
        if t.params.iter().any(|p| p == name) {
            ex.push((a, b));
        } else {
            spans.push((a, b));
        }
    }
    for (k, (tok, a, b)) in toks.iter().enumerate() {
        if marks.get(k) == Some(&true) && tok.chars().any(char::is_alphabetic) {
            ex.push((*a, *b));
        }
    }
    spans.retain(|&(a, b)| !inside(&ex, a, b));
    spans.sort_unstable();
    spans.dedup();
    for sp in spans {
        hit(hits, NUMBER, &t.part, Some(sp));
    }
}

// ------------------------------------------------------------- firewall ----

impl Firewall<'_> {
    /// Marks the tokens covered by an allow-list word (one or more tokens).
    fn allowed_marks(&self, toks: &[(String, usize, usize)], max_words: usize) -> Vec<bool> {
        let mut marks = vec![false; toks.len()];
        for i in 0..toks.len() {
            let mut w = String::new();
            for j in i..toks.len().min(i + max_words) {
                if j > i {
                    w.push(' ');
                }
                w.push_str(&toks[j].0);
                if self.allow.words.contains(&w) {
                    marks[i..=j].iter_mut().for_each(|m| *m = true);
                }
            }
        }
        marks
    }

    fn max_allow_tokens(&self) -> usize {
        self.allow
            .words
            .iter()
            .map(|w| w.split(' ').count())
            .max()
            .unwrap_or(1)
            .clamp(1, MAX_ALLOW_TOKENS)
    }

    /// Scan 2: token windows and whole sentences.
    fn known_hits(
        &self,
        t: &Text,
        toks: &[(String, usize, usize)],
        marks: &[bool],
        skip_numeric: bool,
        hits: &mut Vec<Hit>,
    ) -> Result<(), ShieldError> {
        let s = t.text.as_str();
        let n = toks.len();
        let free: Vec<bool> = toks
            .iter()
            .enumerate()
            .map(|(k, (_, a, b))| !(marks[k] || inside(&t.exempt, *a, *b)))
            .collect();
        let numeric: Vec<bool> = toks
            .iter()
            .map(|(x, _, _)| x.chars().all(|c| c.is_numeric()))
            .collect();
        for i in 0..n {
            for w in 1..=WINDOW {
                let j = i + w - 1;
                if j >= n {
                    break;
                }
                if !(i..=j).any(|k| free[k]) {
                    continue;
                }
                if skip_numeric && (i..=j).all(|k| numeric[k]) {
                    continue;
                }
                let (a, b) = (toks[i].1, toks[j].2);
                let slice = s
                    .get(a..b)
                    .ok_or(ShieldError::Corrupt("a token span is not valid"))?;
                if self.index.contains_value(slice)? {
                    hit(hits, KNOWN_VALUE, &t.part, Some((a, b)));
                }
            }
        }
        // Whole sentences, split where the index build splits free text.
        let mut pieces: Vec<(usize, usize)> = Vec::new();
        let mut start = 0;
        for (i, c) in s.char_indices() {
            if PHRASE_SPLIT.contains(&c) {
                pieces.push((start, i));
                start = i + c.len_utf8();
            }
        }
        pieces.push((start, s.len()));
        let mut any = false;
        for (a, b) in pieces {
            let piece = s
                .get(a..b)
                .ok_or(ShieldError::Corrupt("a sentence span is not valid"))?;
            if piece.trim().is_empty() || inside(&t.exempt, a, b) {
                continue;
            }
            if self.index.contains_phrase(piece)? {
                any = true;
                hit(hits, KNOWN_PHRASE, &t.part, Some((a, b)));
            }
        }
        if !any && !s.trim().is_empty() && self.index.contains_phrase(s)? {
            hit(hits, KNOWN_PHRASE, &t.part, None);
        }
        Ok(())
    }

    /// Scan 5.
    fn name_hits(
        &self,
        t: &Text,
        symbols: &[String],
        hits: &mut Vec<Hit>,
    ) -> Result<(), ShieldError> {
        let s = t.text.as_str();
        let spans = self
            .detector
            .detect(s)
            .map_err(|_| ShieldError::Io("the name detector failed".into()))?;
        let released: Vec<String> = self
            .released_names
            .iter()
            .map(|r| normalize(r))
            .filter(|r| !r.is_empty())
            .collect();
        for sp in spans {
            if sp.start > sp.end {
                return Err(ShieldError::Corrupt(
                    "the name detector gave a span outside the text",
                ));
            }
            let name = s.get(sp.start..sp.end).ok_or(ShieldError::Corrupt(
                "the name detector gave a span outside the text",
            ))?;
            if sp.label != SpanLabel::Person {
                continue;
            }
            let n = normalize(name);
            let ok = symbols.iter().any(|x| x == name.trim())
                || (!n.is_empty() && released.contains(&n));
            if !ok {
                hit(hits, NAME, &t.part, Some((sp.start, sp.end)));
            }
        }
        Ok(())
    }

    /// Scans 2-5 over collected strings, scan by scan.
    fn scan_texts(
        &self,
        texts: &[Text],
        primary: &[Lang],
        symbols: &[String],
        hits: &mut Vec<Hit>,
    ) -> Result<(), ShieldError> {
        let max_words = self.max_allow_tokens();
        let cutoff = birth_cutoff()?;
        let prepared: Vec<(&Text, Tokens, Vec<bool>)> = texts
            .iter()
            .filter(|t| !t.oversize)
            .map(|t| {
                let toks = if t.class == Class::Typed {
                    Vec::new()
                } else {
                    token_spans(&t.text)
                };
                let marks = self.allowed_marks(&toks, max_words);
                (t, toks, marks)
            })
            .collect();
        for (t, toks, marks) in &prepared {
            if t.class != Class::Typed {
                self.known_hits(t, toks, marks, false, hits)?;
            }
        }
        for (t, toks, marks) in &prepared {
            if t.class == Class::Free {
                number_hits(t, toks, marks, primary, hits);
            }
        }
        for (t, _, _) in &prepared {
            let which = Patterns {
                phone: true,
                birth: t.class == Class::Free,
            };
            pattern_hits(t, which, &cutoff, hits);
        }
        for (t, _, _) in &prepared {
            if t.class != Class::Typed {
                self.name_hits(t, symbols, hits)?;
            }
        }
        Ok(())
    }

    fn envelope_hits(
        &self,
        e: &Envelope,
        primary: &[Lang],
        hits: &mut Vec<Hit>,
    ) -> Result<(), ShieldError> {
        let expect = Expect {
            allow: self.allow,
            expected: self.expected,
        };
        let texts = envelope_parts(e, Some(&expect), hits);
        self.scan_texts(&texts, primary, &symbols_of(e), hits)
    }

    /// Every outgoing envelope, before it is encoded and sent. `lang` and
    /// the envelope's language must both be the caller's expected one.
    pub fn check_outgoing(&self, e: &Envelope, lang: Lang) -> Result<Verdict, ShieldError> {
        let mut hits = Vec::new();
        if lang != self.expected.lang {
            hit(&mut hits, BAD_PART, "lang", None);
        }
        self.envelope_hits(e, &[self.expected.lang], &mut hits)?;
        Ok(verdict(hits))
    }

    /// The exact bytes to send (P-22): a typed [`Envelope`], unknown
    /// fields refused at every level, byte-equal to its canonical form; then
    /// every scan of [`Self::check_outgoing`] in the envelope's language.
    /// Bytes that are not such an envelope are `bad_part` on `body`.
    pub fn check_bytes(&self, body: &[u8]) -> Result<Verdict, ShieldError> {
        let mut hits = Vec::new();
        if body.len() > MAX_BODY_BYTES {
            hit(&mut hits, OVERSIZE, "body", None);
            return Ok(verdict(hits));
        }
        let Ok(e) = serde_json::from_slice::<Envelope>(body) else {
            hit(&mut hits, BAD_PART, "body", None);
            return Ok(verdict(hits));
        };
        if e.canonical() != body {
            hit(&mut hits, BAD_PART, "body", None);
        }
        self.envelope_hits(&e, &[self.expected.lang], &mut hits)?;
        Ok(verdict(hits))
    }

    /// The planner's reply: method text, the template's fixed text and the
    /// intent line, each with a part name. Any hit is a leak (`known_value`).
    pub fn check_incoming(&self, reply_texts: &[(&str, &str)]) -> Result<Verdict, ShieldError> {
        let mut hits = Vec::new();
        let max_words = self.max_allow_tokens();
        for (part, text) in reply_texts {
            let t = Text::new((*part).to_string(), text, Class::Method);
            let toks = token_spans(text);
            let marks = self.allowed_marks(&toks, max_words);
            let mut found = Vec::new();
            self.known_hits(&t, &toks, &marks, true, &mut found)?;
            pattern_hits(
                &t,
                Patterns {
                    phone: false,
                    birth: false,
                },
                "",
                &mut found,
            );
            for h in found {
                hit(&mut hits, KNOWN_VALUE, &h.part, h.span);
            }
        }
        Ok(verdict(hits))
    }
}

/// Does free text `s` hold a value or phrase of `index`? The scan 2 of the
/// firewall without allow-list marks or exemptions: every token window of up
/// to `WINDOW` tokens (all-digit windows included: account, phone, CPR and
/// zip values are in the index), every sentence and the whole text. For the
/// daemon's log scrub (plan 47 R47-10). A lookup error is an error: the
/// caller must not treat the text as clean. Amounts (Sensitive columns) are
/// not in the index, so the no-amounts guarantee of a log rests on the
/// question being parameterized, not on this scan.
pub fn text_has_known(index: &KnownIndex, s: &str) -> Result<bool, ShieldError> {
    let toks = token_spans(s);
    let n = toks.len();
    for i in 0..n {
        for w in 1..=WINDOW {
            let j = i + w - 1;
            if j >= n {
                break;
            }
            let slice = s
                .get(toks[i].1..toks[j].2)
                .ok_or(ShieldError::Corrupt("a token span is not valid"))?;
            if index.contains_value(slice)? {
                return Ok(true);
            }
        }
    }
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if PHRASE_SPLIT.contains(&c) {
            if !s[start..i].trim().is_empty() && index.contains_phrase(&s[start..i])? {
                return Ok(true);
            }
            start = i + c.len_utf8();
        }
    }
    if !s[start..].trim().is_empty() && index.contains_phrase(&s[start..])? {
        return Ok(true);
    }
    Ok(!s.trim().is_empty() && index.contains_phrase(s)?)
}

/// The index-free scans (patterns) over an envelope, as the summary counts
/// them: part 1's checks are not counted.
pub(crate) fn standalone_hits(e: &Envelope) -> Vec<Hit> {
    let mut ignored = Vec::new();
    let texts = envelope_parts(e, None, &mut ignored);
    let mut hits = Vec::new();
    // No clock: the birth-date scan cannot run (an empty cutoff matches no
    // date), so count one `pattern:birth_date` hit on `clock` instead: the
    // summary never reads cleaner than a real scan would.
    let cutoff = match birth_cutoff() {
        Ok(c) => c,
        Err(_) => {
            hit(&mut hits, BIRTH_DATE, "clock", None);
            String::new()
        }
    };
    for t in texts.iter().filter(|t| !t.oversize) {
        let which = Patterns {
            phone: true,
            birth: t.class == Class::Free,
        };
        pattern_hits(t, which, &cutoff, &mut hits);
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(s: &str, f: fn(&str) -> Vec<(usize, usize)>) -> Vec<&str> {
        f(s).into_iter().map(|(a, b)| &s[a..b]).collect()
    }

    #[test]
    fn emails_and_exemptions() {
        assert_eq!(
            spans("mail anna.berg.7@example.invalid now", email_spans),
            vec!["anna.berg.7@example.invalid"]
        );
        assert_eq!(spans("søren@ærø.dk.", email_spans), vec!["søren@ærø.dk"]);
        assert!(email_spans("synthetic42@example.invalid").is_empty());
        assert!(email_spans("user_K7QF@example.invalid").is_empty());
        assert!(email_spans("user_K7QF2A@example.invalid").is_empty());
        // P-19: nothing else at example.invalid.
        assert_eq!(email_spans("user_k7qf@example.invalid").len(), 1);
        assert_eq!(email_spans("user_K7QF1@example.invalid").len(), 1);
        assert_eq!(email_spans("syntheticx@example.invalid").len(), 1);
        assert_eq!(email_spans("x.synthetic42@example.invalid").len(), 1);
        assert!(email_spans("a @ b").is_empty());
        assert!(email_spans("@").is_empty());
    }

    #[test]
    fn phones_ibans_cprs() {
        assert_eq!(
            spans("ring +45 00 12 34 56.", phone_spans),
            vec!["+45 00 12 34 56"]
        );
        assert_eq!(spans("tlf 12345678", phone_spans), vec!["12345678"]);
        assert!(phone_spans("1234567").is_empty());
        assert!(phone_spans("abc12345678").is_empty());
        // A well-known example IBAN (not an account of anyone).
        assert_eq!(
            spans("to GB82 WEST 1234 5698 7654 32 please", iban_spans),
            vec!["GB82 WEST 1234 5698 7654 32"]
        );
        assert_eq!(spans("DE89370400440532013000", iban_spans).len(), 1);
        assert!(iban_spans("GB82 WEST 1234 5698 7654 33").is_empty());
        assert_eq!(spans("cpr 010190-1234", cpr_spans), vec!["010190-1234"]);
        assert_eq!(spans("0101901234", cpr_spans), vec!["0101901234"]);
        assert!(cpr_spans("320190-1234").is_empty(), "day 32");
        assert!(cpr_spans("011390-1234").is_empty(), "month 13");
        assert!(cpr_spans("x010190-1234").is_empty());
        assert!(cpr_spans("010190-12345").is_empty());
    }

    #[test]
    fn param_refs_and_names() {
        let r: Vec<&str> = param_refs(":p1 and :p12, :p, :px :p3")
            .iter()
            .map(|x| x.2)
            .collect();
        assert_eq!(r, vec!["p1", "p12", "p3"]);
    }

    #[test]
    fn symbols_and_bands_and_classes() {
        assert!(symbol_ok("Customer_K7QF", Some("customer")));
        assert!(symbol_ok("Customer_K7QF2A", None));
        assert!(!symbol_ok("Customer_K7QF", Some("record")));
        assert!(!symbol_ok("Customer_K7Q1", None));
        assert!(!symbol_ok("customer_K7QF", None));
        assert!(!symbol_ok("Customer_K7QFA", None));
        assert!(!symbol_ok("Søren_K7QF", None));
        for b in ["<100", "about 3 million", "about 400", "about 20 thousand"] {
            assert!(band_ok(b), "{b}");
        }
        for b in [
            "about 03",
            "about 3 people",
            "3 million",
            "about ",
            "about 1234 million",
            "about 3500",
            "about 30 thousand ",
            "about 0",
            "<1000",
        ] {
            assert!(!band_ok(b), "{b}");
        }
        let schema = CloudSchema {
            tables: vec![crate::envelope::CloudTable {
                name: "customers".into(),
                rows: "<100".into(),
                columns: vec![CloudColumn {
                    name: "email".into(),
                    ty: ColType::Text,
                    class: ColumnClass::Identifier,
                    values: None,
                }],
                entity: Some("customer".into()),
            }],
            joins: vec![],
        };
        assert!(sha256_form_ok(&crate::envelope::method_sha256("SELECT 1")));
        assert!(!sha256_form_ok("sha256:ABC"));
        assert!(!sha256_form_ok("SELECT 1"));
        assert!(error_class_ok(&schema, "syntax"));
        assert!(error_class_ok(&schema, "unknown_column email"));
        assert!(error_class_ok(&schema, "unknown_column customers.email"));
        assert!(error_class_ok(&schema, "unknown_table customers"));
        assert!(!error_class_ok(&schema, "syntax email"));
        assert!(!error_class_ok(&schema, "unknown_column phone"));
        assert!(!error_class_ok(&schema, "runtime_error"));
        assert!(!error_class_ok(&schema, "unknown_column  email"));
        assert_eq!(
            tag_check(&schema, "entity:customers"),
            Ok(Some(Some("customer".into())))
        );
        assert_eq!(tag_check(&schema, "text:customers.email"), Ok(None));
        assert_eq!(tag_check(&schema, "amount"), Ok(None));
        assert_eq!(tag_check(&schema, "text:customers.phone"), Err(()));
        assert_eq!(tag_check(&schema, "entity:orders"), Err(()));
        assert_eq!(tag_check(&schema, "money"), Err(()));
    }

    #[test]
    fn synthetic_shapes() {
        let col = |name: &str, ty, class| CloudColumn {
            name: name.into(),
            ty,
            class,
            values: None,
        };
        use ColumnClass::*;
        let s = |x: &str| Value::String(x.into());
        let id = col("navn", ColType::Text, Identifier);
        assert_eq!(
            synthetic_shape(&id, &s("Synthetic_4711"), None),
            Ok(vec![(10, 14)])
        );
        assert_eq!(
            synthetic_shape(&id, &s("synthetic12@example.invalid"), None),
            Ok(vec![(9, 11)])
        );
        assert!(synthetic_shape(&id, &s("Synthetic_0"), None).is_err());
        assert!(synthetic_shape(&id, &s("Synthetic_100000"), None).is_err());
        assert!(synthetic_shape(&id, &s("Søren Ærø"), None).is_err());
        let q = col("by", ColType::Text, Quasi);
        assert_eq!(
            synthetic_shape(&q, &s("Synthetic_by_7"), None),
            Ok(vec![(13, 14)])
        );
        assert!(synthetic_shape(&q, &s("Synthetic_7"), None).is_err());
        let n = col("n", ColType::Integer, Quasi);
        assert!(synthetic_shape(&n, &Value::from(99_999u64), None).is_ok());
        assert!(synthetic_shape(&n, &Value::from(100_000u64), None).is_err());
        assert!(synthetic_shape(&n, &s("5"), None).is_err());
        let r = col("r", ColType::Real, Sensitive);
        let num = |x: &str| serde_json::from_str::<Value>(x).unwrap();
        assert!(synthetic_shape(&r, &num("99999.99"), None).is_ok());
        assert!(synthetic_shape(&r, &num("0.5"), None).is_ok());
        assert!(synthetic_shape(&r, &num("100000.0"), None).is_err());
        assert!(synthetic_shape(&r, &num("1.234"), None).is_err());
        assert!(synthetic_shape(&r, &num("-1"), None).is_err());
        let d = col("d", ColType::Date, Quasi);
        assert_eq!(
            synthetic_shape(&d, &s("2013-02-28"), None),
            Ok(vec![(0, 10)])
        );
        assert!(synthetic_shape(&d, &s("1985-02-28"), None).is_err());
        assert!(synthetic_shape(&d, &s("2013-02-30"), None).is_err());
        let f = col("note", ColType::Text, FreeText);
        assert!(synthetic_shape(&f, &s("(free text)"), None).is_ok());
        assert!(synthetic_shape(&f, &s("called Søren"), None).is_err());
        // NULL only where the generator writes it: a public column with no
        // k-floor value.
        assert!(synthetic_shape(&f, &Value::Null, None).is_err());
        assert!(synthetic_shape(&n, &Value::Null, None).is_err());
        let mut p = col("seg", ColType::Text, Public);
        assert!(synthetic_shape(&p, &Value::Null, None).is_ok());
        assert!(synthetic_shape(&p, &s("vip"), None).is_err());
        p.values = Some(vec!["vip".into()]);
        assert!(synthetic_shape(&p, &Value::Null, None).is_err());
        assert_eq!(synthetic_shape(&p, &s("vip"), None), Ok(vec![(0, 3)]));
        assert!(synthetic_shape(&p, &s("retail"), None).is_err());
    }

    #[test]
    fn birth_cutoff_is_fifteen_years_back() {
        let c = birth_cutoff().unwrap();
        assert!(iso_date_ok(&c));
        assert_eq!(cutoff_from_days(0), "1955-01-01");
        assert_eq!(cutoff_from_days(19_782), "2009-02-28", "29 February 2024");
        assert!(c.as_str() > "2010-01-01" && c.as_str() < "2100-01-01");
    }
}
