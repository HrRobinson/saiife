//! Plan 44 T5: the deterministic leak firewall (spec §2.2.5).
//!
//! Outgoing, every scan runs and every hit is collected, in this order:
//!
//! 1. **Part types.** `v`/`kind` fixed; schema names, entity words and
//!    public values are words of the dataset's allow list (schema words and
//!    k-floor values); row counts are bands; free text is capped (R44-7);
//!    parameter names, tags and stand-ins (R44-4) have their fixed forms;
//!    `retry.error_class` is a plan 45 planner class ([`PLANNER_ERROR_CLASSES`],
//!    ruling P-20); every synthetic value has the exact shape the generator
//!    (`synth.rs`, R44-6) makes for its column. A part that fails is
//!    `bad_part` (`oversize` for a size).
//! 2. **Known values.** Every token and every 2-4-token window of every
//!    free-text string (the question, the context questions, synthetic text
//!    values, the retry's previous method) goes through
//!    [`KnownIndex::contains_value`], except windows whose every token is
//!    covered by an allow-list word; every whole sentence (split as
//!    [`crate::index::split_phrases`] splits) and the whole text go through
//!    [`KnownIndex::contains_phrase`].
//! 3. **Numbers** (R44-8, ruling P-4) over the question and the context
//!    questions (and synthetic text, minus the generator's own numbers):
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
//! Synthetic numbers (JSON numbers, and the generated number inside a
//! synthetic text such as `Synthetic_4711`, or a synthetic date) are exempt
//! from the number, date and known-value scans (R44-6): part 1 checked that
//! they have exactly the generator's shape and range, so they are drawn, not
//! read. Anything else in a synthetic text goes through every scan.
//!
//! [`Firewall::check_bytes`] parses the whole HTTP body (strictly: a
//! duplicate key is `bad_part`) and scans every string and key. An object
//! of kind `saiife-blind-plan` (top level, or a string holding JSON) must be
//! an envelope whose canonical bytes are exactly the bytes it came from; it
//! gets the full envelope scans, so `check_bytes(e.canonical())` gives the
//! same hits as `check_outgoing`. Other strings get scans 2-5 as free text
//! in both languages; strings equal to a caller's fixed constant (the system
//! prompt, the model id) are skipped ([`Firewall::check_bytes_with`]).
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
    CloudColumn, CloudParam, CloudSchema, Envelope, ENVELOPE_KIND, ENVELOPE_VERSION,
};
use crate::error::ShieldError;
use crate::index::{AllowList, KnownIndex};
use crate::lang::{find_dates, find_numbers, find_unreadable_numerics, number_words};
use crate::ner::{NameDetector, SpanLabel};
use crate::norm::{normalize, token_spans};
use crate::schema::{ColType, ColumnClass, Decimal, Lang};
use serde_json::{Map, Value};
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
/// The retry's previous method (plan 45 caps the method itself; this is a
/// backstop so a huge text is refused before it is scanned).
pub const MAX_METHOD_CHARS: usize = 20_000;
/// R44-6: synthetic rows per table.
pub const MAX_SYNTHETIC_ROWS: usize = 5;
/// The whole HTTP body `check_bytes` accepts.
pub const MAX_BODY_BYTES: usize = 4 << 20;
/// Strings holding JSON inside strings, at most this deep.
const MAX_NESTING: usize = 4;
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
pub const PLANNER_ERROR_CLASSES: [&str; 15] = [
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
    /// The names a `blind:name` touch of this ask released.
    pub released_names: &'a [String],
}

impl fmt::Debug for Firewall<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Firewall")
            .field("index", &self.index)
            .field("allow", &self.allow)
            .field("released_names", &self.released_names.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------- parts ----

/// Normalized tokens with their byte spans in the original text.
type Tokens = Vec<(String, usize, usize)>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Every scan (question, context questions, synthetic text, other
    /// strings of a body).
    Free,
    /// The retry's previous method: known values, patterns, names.
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

/// `p` followed by a number from 1, no leading zero.
fn param_name_ok(n: &str) -> bool {
    n.strip_prefix('p').is_some_and(|d| {
        !d.is_empty()
            && d.len() <= 6
            && !d.starts_with('0')
            && d.bytes().all(|b| b.is_ascii_digit())
    })
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

/// `about <n>[ thousand| million| billion]` or `<100` (`rows_band`).
fn band_ok(s: &str) -> bool {
    if s == "<100" {
        return true;
    }
    let Some(rest) = s.strip_prefix("about ") else {
        return false;
    };
    let (n, unit) = rest.split_once(' ').unwrap_or((rest, ""));
    matches!(unit, "" | "thousand" | "million" | "billion")
        && !n.is_empty()
        && n.len() <= 4
        && !n.starts_with('0')
        && n.bytes().all(|b| b.is_ascii_digit())
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
    if v.is_null() {
        return Ok(Vec::new());
    }
    match col.class {
        ColumnClass::Public => {
            let s = v.as_str().ok_or(())?;
            let in_list = col.values.as_ref().is_none_or(|l| l.iter().any(|x| x == s));
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

/// A name for a part path: the name when it is a word of the allow list,
/// else `#<index>` (a part name never carries an unchecked text).
fn path_name(allow: Option<&AllowList>, name: &str, i: usize) -> String {
    if allow.is_some() && allowed(allow, name) {
        name.to_string()
    } else {
        format!("#{i}")
    }
}

/// Part 1 and the strings of an envelope. `allow` None (the summary): the
/// allow-list checks are skipped and every hit of part 1 is dropped by the
/// caller.
fn envelope_parts(
    e: &Envelope,
    allow: Option<&AllowList>,
    prefix: &str,
    hits: &mut Vec<Hit>,
) -> Vec<Text> {
    let mut texts: Vec<Text> = Vec::new();
    let p = |s: &str| format!("{prefix}{s}");

    if e.v != ENVELOPE_VERSION {
        hit(hits, BAD_PART, &p("v"), None);
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

    // Synthetic rows: each value has the generator's exact shape.
    for (ti, (tname, rows)) in e.synthetic.iter().enumerate() {
        let table = e.schema.tables.iter().find(|t| &t.name == tname);
        let tp = p(&format!("synthetic.{}", path_name(allow, tname, ti)));
        if table.is_none() || rows.len() > MAX_SYNTHETIC_ROWS {
            hit(hits, BAD_PART, &tp, None);
        }
        texts.push(Text::new(format!("{tp}#name"), tname, Class::Typed));
        for (ri, row) in rows.iter().enumerate() {
            for (ci, (cname, v)) in row.iter().enumerate() {
                let col = table.and_then(|t| t.columns.iter().find(|c| &c.name == cname));
                let vp = format!("{tp}[{ri}].{}", path_name(allow, cname, ci));
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
                    t.exempt = shape.unwrap_or_default();
                    t.oversize = s.chars().count() > MAX_FREE_TEXT_CHARS;
                    texts.push(t);
                } else if !matches!(v, Value::Null | Value::Bool(_) | Value::Number(_)) {
                    // Arrays and objects are never synthetic values: scan
                    // every string inside them as free text too.
                    let mut inner = Vec::new();
                    strings_of(v, &vp, &mut inner);
                    for (part, s) in inner {
                        texts.push(Text::new(part, &s, Class::Free));
                    }
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
    texts.push(q);
    check_params(e, &e.params, &p("params"), true, hits, &mut texts);

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
        texts.push(t);
        check_params(
            e,
            &turn.params,
            &format!("{tp}.params"),
            false,
            hits,
            &mut texts,
        );
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
        let mut m = Text::new(
            p("retry.previous_method"),
            &r.previous_method,
            Class::Method,
        );
        if r.previous_method.chars().count() > MAX_METHOD_CHARS {
            hit(hits, OVERSIZE, &m.part, None);
            m.oversize = true;
        }
        texts.push(m);
    }
    texts
}

/// Names `p1..pK` in order for the question (`sequential`), else distinct
/// `p<n>`; tags from the fixed list; an entity has a well-formed stand-in,
/// nothing else has one.
fn check_params(
    e: &Envelope,
    params: &[CloudParam],
    base: &str,
    sequential: bool,
    hits: &mut Vec<Hit>,
    texts: &mut Vec<Text>,
) {
    for (i, cp) in params.iter().enumerate() {
        let pp = format!("{base}[{i}]");
        let name_ok = if sequential {
            cp.name == format!("p{}", i + 1)
        } else {
            param_name_ok(&cp.name) && params.iter().filter(|x| x.name == cp.name).count() == 1
        };
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

/// Every string in a JSON value, with a positional path.
fn strings_of(v: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match v {
        Value::String(s) => out.push((path.to_string(), s.clone())),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                strings_of(x, &format!("{path}[{i}]"), out);
            }
        }
        Value::Object(m) => {
            for (i, (k, x)) in m.iter().enumerate() {
                out.push((format!("{path}.#{i}#key"), k.clone()));
                strings_of(x, &format!("{path}.#{i}"), out);
            }
        }
        _ => {}
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
fn birth_cutoff() -> String {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| (d.as_secs() / 86_400) as i64);
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
fn param_refs(s: &str) -> Vec<(usize, usize, &str)> {
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

// ---------------------------------------------------------------- strict ----

/// A JSON value parsed with duplicate keys refused.
struct Strict(Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> serde::de::Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("not a JSON number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut v = Vec::new();
        while let Some(Strict(x)) = a.next_element()? {
            v.push(x);
        }
        Ok(Value::Array(v))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut m = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            let Strict(x) = a.next_value()?;
            if m.insert(k, x).is_some() {
                return Err(serde::de::Error::custom("duplicate key"));
            }
        }
        Ok(Value::Object(m))
    }
}

fn parse_strict(b: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Strict>(b).ok().map(|s| s.0)
}

fn is_envelope_kind(v: &Value) -> bool {
    v.get("kind").and_then(Value::as_str) == Some(ENVELOPE_KIND)
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
        let cutoff = birth_cutoff();
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
        prefix: &str,
        hits: &mut Vec<Hit>,
    ) -> Result<(), ShieldError> {
        let texts = envelope_parts(e, Some(self.allow), prefix, hits);
        self.scan_texts(&texts, primary, &symbols_of(e), hits)
    }

    /// Every outgoing envelope, before it is encoded and sent.
    pub fn check_outgoing(&self, e: &Envelope, lang: Lang) -> Result<Verdict, ShieldError> {
        let mut primary = vec![lang];
        if e.lang != lang {
            primary.push(e.lang);
        }
        let mut hits = Vec::new();
        self.envelope_hits(e, &primary, "", &mut hits)?;
        Ok(verdict(hits))
    }

    /// The whole HTTP body plan 47 sends: [`Self::check_bytes_with`] with no
    /// fixed constants.
    pub fn check_bytes(&self, body: &[u8]) -> Result<Verdict, ShieldError> {
        self.check_bytes_with(body, &[])
    }

    /// The whole HTTP body. A string equal to one of `fixed` (the system
    /// prompt, the model id: constants of the caller's code, never data) is
    /// not scanned.
    pub fn check_bytes_with(&self, body: &[u8], fixed: &[&str]) -> Result<Verdict, ShieldError> {
        let mut hits = Vec::new();
        if body.len() > MAX_BODY_BYTES {
            hit(&mut hits, OVERSIZE, "body", None);
            return Ok(verdict(hits));
        }
        let Some(v) = parse_strict(body) else {
            hit(&mut hits, BAD_PART, "body", None);
            return Ok(verdict(hits));
        };
        let mut generic = Vec::new();
        self.walk(&v, Some(body), "", 0, fixed, &mut generic, &mut hits)?;
        let both = [Lang::En, Lang::Da];
        self.scan_texts(&generic, &both, &[], &mut hits)?;
        Ok(verdict(hits))
    }

    /// The part path of a key: the key when it is plain lowercase ASCII and
    /// not a known value, else `#<index>`.
    fn key_path(&self, path: &str, k: &str, i: usize) -> Result<String, ShieldError> {
        let plain = !k.is_empty()
            && k.len() <= 32
            && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            && !self.index.contains_value(k)?;
        let seg = if plain {
            k.to_string()
        } else {
            format!("#{i}")
        };
        Ok(if path.is_empty() || path.ends_with('/') {
            format!("{path}{seg}")
        } else {
            format!("{path}.{seg}")
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(
        &self,
        v: &Value,
        raw: Option<&[u8]>,
        path: &str,
        depth: usize,
        fixed: &[&str],
        generic: &mut Vec<Text>,
        hits: &mut Vec<Hit>,
    ) -> Result<(), ShieldError> {
        let here = if path.is_empty() { "body" } else { path };
        // The string a nested value came from (`messages[0].content`).
        let from = here.strip_suffix('/').unwrap_or(here);
        if is_envelope_kind(v) {
            match serde_json::from_value::<Envelope>(v.clone()) {
                Ok(e) => {
                    if raw.is_some_and(|r| r != e.canonical().as_slice()) {
                        hit(hits, BAD_PART, from, None);
                    }
                    let prefix = if path.is_empty() || path.ends_with('/') {
                        path.to_string()
                    } else {
                        format!("{path}/")
                    };
                    return self.envelope_hits(&e, &[e.lang], &prefix, hits);
                }
                Err(_) => hit(hits, BAD_PART, from, None),
            }
        }
        match v {
            Value::String(s) => {
                if fixed.contains(&s.as_str()) {
                    return Ok(());
                }
                let t = s.trim_start();
                if t.starts_with('{') || t.starts_with('[') {
                    if let Some(inner) = parse_strict(s.as_bytes()) {
                        if inner.is_object() || inner.is_array() {
                            if depth >= MAX_NESTING {
                                hit(hits, BAD_PART, here, None);
                                return Ok(());
                            }
                            return self.walk(
                                &inner,
                                Some(s.as_bytes()),
                                &format!("{here}/"),
                                depth + 1,
                                fixed,
                                generic,
                                hits,
                            );
                        }
                    }
                }
                generic.push(Text::new(here.to_string(), s, Class::Free));
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    self.walk(
                        x,
                        None,
                        &format!("{here}[{i}]"),
                        depth,
                        fixed,
                        generic,
                        hits,
                    )?;
                }
            }
            Value::Object(m) => {
                let base = if path.is_empty() { "" } else { path };
                for (i, (k, x)) in m.iter().enumerate() {
                    let kp = self.key_path(base, k, i)?;
                    if !fixed.contains(&k.as_str()) {
                        generic.push(Text::new(format!("{kp}#key"), k, Class::Free));
                    }
                    self.walk(x, None, &kp, depth, fixed, generic, hits)?;
                }
            }
            _ => {}
        }
        Ok(())
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

/// The index-free scans (patterns) over an envelope, as the summary counts
/// them: part 1's checks are not counted.
pub(crate) fn standalone_hits(e: &Envelope) -> Vec<Hit> {
    let mut ignored = Vec::new();
    let texts = envelope_parts(e, None, "", &mut ignored);
    let cutoff = birth_cutoff();
    let mut hits = Vec::new();
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
        assert!(param_name_ok("p1") && param_name_ok("p10"));
        assert!(!param_name_ok("p0") && !param_name_ok("p01") && !param_name_ok("q1"));
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
        for b in ["about 03", "about 3 people", "3 million", "about "] {
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
        };
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
        assert!(synthetic_shape(&f, &Value::Null, None).is_ok());
    }

    #[test]
    fn birth_cutoff_is_fifteen_years_back() {
        let c = birth_cutoff();
        assert!(iso_date_ok(&c));
        assert!(c.as_str() > "2010-01-01" && c.as_str() < "2100-01-01");
    }
}
