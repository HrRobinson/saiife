//! Plan 45: answer templates (R45-9). The cloud planner writes fixed text with
//! slots; saiife fills the slots locally from the calculator's `ResultSet` and
//! records every exact number and date it printed, so the strict checker can
//! verify that each number in the answer came from the calculator.
//!
//! Formatting is deterministic and locale-aware (en `18,420.00`, da
//! `18.420,00`). A NULL cell or a non-number given to a number formatter
//! refuses (`check_failed`): nothing is ever printed as 0 or empty.

use crate::calc::{CellValue, ResultSet};
use crate::grammar::{grammar_ok, Seg};
use crate::lexicon::Candidate;
use crate::question::Draft;
use crate::schema::{Bound, ColumnClass, Decimal, Lang, Param, ParamType, Schema};
use crate::sql::{ErrorClass, MethodError, Validated};

const DETAIL_MAX: usize = 120;

type Formatter<'a> = &'a dyn Fn(&CellValue, Lang) -> Option<(String, Decimal)>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CellRef {
    row: usize,
    col: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Slot {
    Money(CellRef, Option<String>),
    Number(CellRef),
    Int(CellRef),
    Percent(CellRef),
    RatioPercent(CellRef),
    Round(CellRef, u8),
    Date(CellRef),
    Cmp(CellRef, CellRef),
    Param(String),
    Rows,
    TotalRows,
    List(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Text(String),
    Slot(Slot),
}

/// A parsed template: fixed text and slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    parts: Vec<Part>,
}

/// One printed span of `Filled.text` (byte offsets on char boundaries) and the
/// exact values and dates it shows. `from_param`: the span is a parameter
/// display; the checker treats the whole span as a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Printed {
    pub start: usize,
    pub end: usize,
    pub values: Vec<Decimal>,
    pub dates: Vec<String>,
    pub from_param: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filled {
    pub text: String,
    pub printed: Vec<Printed>,
}

fn slot_err(name: &str) -> MethodError {
    MethodError {
        class: ErrorClass::TemplateSlot,
        detail: Some(name.trim().chars().take(DETAIL_MAX).collect()),
    }
}

fn check_failed() -> MethodError {
    MethodError {
        class: ErrorClass::CheckFailed,
        detail: None,
    }
}

// ---- parsing ----

fn parse_cell(arg: &str, columns: &[String], list_cap: u32) -> Result<CellRef, MethodError> {
    let arg = arg.trim();
    if columns.iter().any(|c| c == arg) {
        return Ok(CellRef {
            row: 0,
            col: arg.to_string(),
        });
    }
    if let Some(rest) = arg.strip_prefix('r') {
        if let Some((n, col)) = rest.split_once('.') {
            if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(row) = n.parse::<u32>() {
                    if row < list_cap && columns.iter().any(|c| c == col) {
                        return Ok(CellRef {
                            row: row as usize,
                            col: col.to_string(),
                        });
                    }
                }
            }
        }
    }
    Err(slot_err(arg))
}

fn parse_slot(
    inner: &str,
    columns: &[String],
    params: &[Param],
    list_cap: u32,
) -> Result<Slot, MethodError> {
    let inner = inner.trim();
    let Some(open) = inner.find('(') else {
        return Err(slot_err(inner));
    };
    let Some(body) = inner.strip_suffix(')') else {
        return Err(slot_err(inner));
    };
    let name = inner.get(..open).unwrap_or("").trim();
    let args_src = body.get(open + 1..).unwrap_or("");
    let args: Vec<&str> = if args_src.trim().is_empty() {
        Vec::new()
    } else {
        args_src.split(',').map(str::trim).collect()
    };
    let cell = |i: usize| parse_cell(args[i], columns, list_cap);
    let arity = |n: usize| {
        if args.len() == n {
            Ok(())
        } else {
            Err(slot_err(name))
        }
    };
    match name {
        "money" => {
            if args.is_empty() || args.len() > 2 {
                return Err(slot_err(name));
            }
            let c = cell(0)?;
            let code = match args.get(1) {
                None => None,
                Some(code) => {
                    if code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase()) {
                        Some((*code).to_string())
                    } else {
                        return Err(slot_err(code));
                    }
                }
            };
            Ok(Slot::Money(c, code))
        }
        "number" | "int" | "percent" | "ratio_percent" | "date" => {
            arity(1)?;
            let c = cell(0)?;
            Ok(match name {
                "number" => Slot::Number(c),
                "int" => Slot::Int(c),
                "percent" => Slot::Percent(c),
                "ratio_percent" => Slot::RatioPercent(c),
                _ => Slot::Date(c),
            })
        }
        "round" => {
            arity(2)?;
            let c = cell(0)?;
            let n = args[1].as_bytes();
            if n.len() == 1 && (b'0'..=b'6').contains(&n[0]) {
                Ok(Slot::Round(c, n[0] - b'0'))
            } else {
                Err(slot_err(args[1]))
            }
        }
        "cmp" => {
            arity(2)?;
            Ok(Slot::Cmp(cell(0)?, cell(1)?))
        }
        "param" => {
            arity(1)?;
            if params.iter().any(|p| p.name == args[0]) {
                Ok(Slot::Param(args[0].to_string()))
            } else {
                Err(slot_err(args[0]))
            }
        }
        "rows" => {
            arity(0)?;
            Ok(Slot::Rows)
        }
        "total_rows" => {
            arity(0)?;
            Ok(Slot::TotalRows)
        }
        "list" => {
            if args.is_empty() {
                return Err(slot_err(name));
            }
            for a in &args {
                if !columns.iter().any(|c| c == a) {
                    return Err(slot_err(a));
                }
            }
            Ok(Slot::List(args.iter().map(|a| (*a).to_string()).collect()))
        }
        _ => Err(slot_err(name)),
    }
}

/// Parse a template. Unknown function, column or parameter, a row beyond
/// `list_cap`, a bad `round` digit, an unbalanced brace, or fixed text outside
/// the allow-listed grammar (see `grammar.rs`) is `template_slot` carrying the
/// planner's own slot text or a short fixed reason.
pub fn parse_template(
    s: &str,
    columns: &[String],
    params: &[Param],
    list_cap: u32,
) -> Result<Template, MethodError> {
    let mut parts = Vec::new();
    let mut text = String::new();
    let mut it = s.char_indices().peekable();
    while let Some((i, ch)) = it.next() {
        match ch {
            '{' => {
                if matches!(it.peek(), Some(&(_, '{'))) {
                    it.next();
                    text.push('{');
                    continue;
                }
                let start = i + 1;
                let mut end = None;
                for (j, c) in it.by_ref() {
                    if c == '}' {
                        end = Some(j);
                        break;
                    }
                    if c == '{' {
                        break;
                    }
                }
                let Some(end) = end else {
                    return Err(slot_err(s.get(start..).unwrap_or("")));
                };
                let inner = s.get(start..end).unwrap_or("");
                let slot = parse_slot(inner, columns, params, list_cap)?;
                if !text.is_empty() {
                    parts.push(Part::Text(std::mem::take(&mut text)));
                }
                parts.push(Part::Slot(slot));
            }
            '}' => {
                if matches!(it.peek(), Some(&(_, '}'))) {
                    it.next();
                    text.push('}');
                } else {
                    return Err(slot_err("}"));
                }
            }
            c => text.push(c),
        }
    }
    if !text.is_empty() {
        parts.push(Part::Text(text));
    }
    // The fixed text is an allow-listed grammar (R45-10, ruling T5-c).
    let segs: Vec<Seg> = parts
        .iter()
        .map(|p| match p {
            Part::Text(t) => Seg::Text(t),
            Part::Slot(Slot::Cmp(..) | Slot::Param(_)) => Seg::Param,
            Part::Slot(_) => Seg::Num,
        })
        .collect();
    grammar_ok(&segs).map_err(slot_err)?;
    Ok(Template { parts })
}

impl Template {
    /// The parameters a `{param(pN)}` slot shows, in template order, without
    /// repeats.
    pub fn param_slots(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for p in &self.parts {
            if let Part::Slot(Slot::Param(n)) = p {
                if !out.contains(&n.as_str()) {
                    out.push(n);
                }
            }
        }
        out
    }
}

/// Plan 45 final review I3 (ruling F-c, narrowed by F-f, then F-g): a bound
/// question parameter the method ignores answers another question ("open
/// invoices in Q3 2026" summed over all time; "Anna Berg's total" over every
/// customer; "total of invoices over 5000" over every invoice).
///
/// Every bound parameter, filter (entity key, `DateRange`, `Date`, `Text`)
/// or scalar threshold (`Amount`, `Integer`, `Percent`), must be used by the
/// method ([`Validated::params_used`]), whether the template shows it or not:
/// echoing "over 5,000" or "in Q3 2026" next to a number the method computed
/// without it is the anti-goal. Ruling F-g allowed an unused threshold only
/// as an operand of a `cmp` slot; `cmp` compares two result cells and takes
/// no parameter operand, so that exemption has no legitimate use and none is
/// made. The `template` argument is kept for the checker's call shape.
///
/// Ruling F-p (supersedes F-o): no parameter is covered by a `LIMIT`.
/// Plan 44's binding has no row-count role, and an `Integer` equal to the
/// limit may be a filter ("more than 10 items" answered by `LIMIT 10`).
/// The stage-1.5 top-N task carries the rule (R45-6).
///
/// Otherwise `param_misuse` (no detail: R45-8 sends a detail only for the
/// name classes). Unbound draft parameters are not judged. Found before the
/// preview, so the planner can retry; the checker's [`crate::checker::check`]
/// runs it again over the method and template it is given.
pub fn check_params_covered(
    method: &Validated,
    _template: &Template,
    params: &[Param],
) -> Result<(), MethodError> {
    let unused = params
        .iter()
        .any(|p| p.bound.is_some() && !method.params_used.contains(&p.name));
    if unused {
        return Err(MethodError {
            class: ErrorClass::ParamMisuse,
            detail: None,
        });
    }
    Ok(())
}

// ---- entity parameters in the answer (ruling F-n) ----

/// The words the user typed for parameter `param` in `d.original`, when the
/// draft fixes them: `d.text` is `d.original` with each parameter's span
/// replaced by `:pN` (plan 44 copies the text between them verbatim), and
/// the span is taken only when the earliest and the latest fit of those
/// pieces into the original agree on it. Otherwise `None`.
///
/// A parameter bound from the session's context (plan 48 T2,
/// [`crate::envelope::bind_context`]) follows the question's own and is not
/// in `d.text`: the user did not type it here, so it is `None`.
pub fn spoken(d: &Draft, param: &str) -> Option<String> {
    let refs = crate::firewall::param_refs(&d.text);
    let in_text = d
        .params
        .iter()
        .take_while(|p| refs.iter().any(|r| r.2 == p.name))
        .count();
    let n = d.params.iter().position(|p| p.name == param)? + 1;
    if n > in_text {
        return None;
    }
    let segs = split_params(&d.text, in_text)?;
    let k = segs.len() - 1;
    let o = d.original.as_str();
    if !o.starts_with(segs[0]) {
        return None;
    }
    // Earliest fit: piece i starts at least one byte after piece i-1 ends.
    let mut early = vec![(0usize, segs[0].len())];
    for seg in &segs[1..k] {
        let from = early.last()?.1 + 1;
        let at = o.get(from..)?.find(seg)? + from;
        early.push((at, at + seg.len()));
    }
    let last_at = o.len().checked_sub(segs[k].len())?;
    if o.get(last_at..)? != segs[k] || last_at < early.last()?.1 + 1 {
        return None;
    }
    early.push((last_at, o.len()));
    // Latest fit, from the end.
    let mut late = vec![(last_at, o.len())];
    for seg in segs[1..k].iter().rev() {
        let until = late.last()?.0.checked_sub(1)?;
        let at = o.get(..until)?.rfind(seg)?;
        late.push((at, at + seg.len()));
    }
    late.push((0, segs[0].len()));
    late.reverse();
    let span = |fit: &[(usize, usize)]| (fit[n - 1].1, fit[n].0);
    let (a, b) = span(&early);
    if span(&late) != (a, b) || a >= b {
        return None;
    }
    let s = o.get(a..b)?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// `d.text` split at `:p1`..`:pK` in order (exactly those), or `None`.
fn split_params(text: &str, k: usize) -> Option<Vec<&str>> {
    let mut segs = Vec::with_capacity(k + 1);
    let mut rest = text;
    for n in 1..=k {
        let tok = format!(":p{n}");
        let mut from = 0;
        let at = loop {
            let i = rest.get(from..)?.find(&tok)? + from;
            let next = rest.get(i + tok.len()..).and_then(|r| r.chars().next());
            if !next.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                break i;
            }
            from = i + tok.len();
        };
        segs.push(rest.get(..at)?);
        rest = rest.get(at + tok.len()..)?;
    }
    segs.push(rest);
    Some(segs)
}

/// The entity type's plain word: en `the customer`, da `pågældende kunde`.
fn plain_word(d: &Draft, schema: &Schema, table: &str, word: &str) -> String {
    match d.lang {
        Lang::En => format!("the {word}"),
        Lang::Da => {
            let w = schema
                .entity_for(table)
                .map_or(word, |e| e.word_da.as_str());
            format!("pågældende {w}")
        }
    }
}

/// How an entity parameter is named in an answer or a refusal (ruling F-n):
/// the user's own words ([`spoken`]), else the entity type's plain word;
/// never the snapshot's name, `show` value or key. `None` for a parameter
/// that is not an entity of the draft.
fn entity_words(d: &Draft, schema: &Schema, param: &str) -> Option<String> {
    let p = d.params.iter().find(|p| p.name == param)?;
    let ParamType::Entity { table, word } = &p.ty else {
        return None;
    };
    Some(spoken(d, param).unwrap_or_else(|| plain_word(d, schema, table, word)))
}

/// The parameters to fill an exact-mode answer with (ruling F-n): each
/// entity parameter's `display` becomes [`spoken`] text or the plain word;
/// every other parameter is unchanged. The checker's
/// [`crate::checker::check`] refuses an answer whose entity slot shows
/// anything else.
pub fn answer_params(d: &Draft, schema: &Schema) -> Vec<Param> {
    d.params
        .iter()
        .map(|p| {
            let mut p = p.clone();
            if let Some(w) = entity_words(d, schema, &p.name) {
                p.display = w;
            }
            p
        })
        .collect()
}

// ---- entities in local resolution UI and the preview (R45-13, R-C2) ----

/// The `show` values of `c` a user may see in local resolution UI and in
/// the method preview (plan 48 ruling R-C2, owner rule R45-13): not empty,
/// of a column of the entity's table that is not Identifier-class and is
/// not the entity's key, whatever its class (plan 48 final review m4). A
/// column the schema does not have, or a table with no entity, is not
/// shown (fail closed). Never the key.
pub fn shown_values<'a>(c: &'a Candidate, schema: &Schema) -> Vec<&'a str> {
    let key = schema.entity_for(&c.table).map(|e| e.key.as_str());
    c.show
        .iter()
        .filter(|(col, v)| {
            !v.is_empty()
                && key.is_some_and(|k| k != col.as_str())
                && schema
                    .column(&c.table, col)
                    .is_some_and(|ci| ci.class != ColumnClass::Identifier)
        })
        .map(|(_, v)| v.as_str())
        .collect()
}

/// A pick-list or "did you mean" label (R-C2): the display name, needed
/// to choose, then [`shown_values`], comma-separated (`Anna Berg,
/// Aarhus`). Local only: never logged, never sent.
pub fn entity_label(c: &Candidate, schema: &Schema) -> String {
    std::iter::once(c.display.as_str())
        .chain(shown_values(c, schema))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The parameters the method preview names (R-C2): [`answer_params`] (each
/// entity by the user's own words, else the plain word of its type), and
/// for an entity bound to one key the [`shown_values`] of the record it
/// resolved to. That record is the one `chosen` names for the parameter
/// with that key (a pick, a "did you mean" yes), else the one `lookup`
/// (the lexicon's resolve of the user's words in the entity table) gives
/// with that key; none found: the words alone. Never the key, never a
/// snapshot name the user did not type.
pub fn preview_params(
    d: &Draft,
    schema: &Schema,
    chosen: &[(String, Candidate)],
    lookup: &dyn Fn(&str, &str) -> Vec<Candidate>,
) -> Vec<Param> {
    let mut ps = answer_params(d, schema);
    for p in ps.iter_mut() {
        let (ParamType::Entity { table, .. }, Some(Bound::Keys(k))) = (&p.ty, &p.bound) else {
            continue;
        };
        let [key] = k.as_slice() else {
            continue;
        };
        let c = chosen
            .iter()
            .rev()
            .find(|(n, c)| *n == p.name && c.key == *key && c.table == *table)
            .map(|(_, c)| c.clone())
            .or_else(|| {
                let w = spoken(d, &p.name)?;
                lookup(table, &w)
                    .into_iter()
                    .find(|c| c.key == *key && c.table == *table)
            });
        if let Some(c) = c {
            for v in shown_values(&c, schema) {
                p.display.push_str(", ");
                p.display.push_str(v);
            }
        }
    }
    ps
}

/// The `empty_for_key` refusal reason (R45-6, ruling F-n): en `the method
/// found no rows for <words>`, da `metoden fandt ingen rækker for <words>`,
/// the words as in [`answer_params`].
pub fn empty_for_key_reason(d: &Draft, schema: &Schema, param: &str) -> String {
    let w = entity_words(d, schema, param).unwrap_or_else(|| match d.lang {
        Lang::En => "the entity".into(),
        Lang::Da => "den valgte".into(),
    });
    match d.lang {
        Lang::En => format!("the method found no rows for {w}"),
        Lang::Da => format!("metoden fandt ingen rækker for {w}"),
    }
}

/// The `empty_result` refusal reason (plan 48 T2): the method ran and found
/// nothing (zero rows, or every aggregate NULL). Worded like
/// [`empty_for_key_reason`]; the one text for it everywhere.
pub fn empty_result_reason(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "the method found no matching rows",
        Lang::Da => "metoden fandt ingen rækker, der passer",
    }
}

/// Ruling F-n, the checker's side: an entity parameter's display may be
/// shown only when it is the user's own words (a part of the question) or
/// the plain word of its type.
pub fn entity_display_ok(p: &Param, question: &str, lang: Lang) -> bool {
    let ParamType::Entity { word, .. } = &p.ty else {
        return true;
    };
    let d = p.display.as_str();
    if d.is_empty() {
        return false;
    }
    if question.contains(d) {
        return true;
    }
    match lang {
        Lang::En => d == format!("the {word}"),
        Lang::Da => d.strip_prefix("pågældende ").is_some_and(|w| {
            !w.is_empty() && w.chars().all(|c| c.is_lowercase() && c.is_alphabetic())
        }),
    }
}

// ---- number formatting ----

/// The exact `Decimal` of a number cell. A `Real` goes through Rust's shortest
/// round-trip `Display` (never an exponent form); NaN, infinity and values
/// beyond the `Decimal` range give `None`.
fn to_decimal(x: &CellValue) -> Option<Decimal> {
    match x {
        CellValue::Int(i) => Some(Decimal {
            units: i128::from(*i),
            scale: 0,
        }),
        CellValue::Real(f) => {
            if !f.is_finite() {
                return None;
            }
            let s = format!("{f}");
            if s.contains(['e', 'E']) {
                return None;
            }
            Decimal::parse_plain(&s)
        }
        _ => None,
    }
}

/// Round half-even to exactly `places` decimals.
fn at_places(d: Decimal, places: u8) -> Option<Decimal> {
    let r = d.round_half_even(places);
    if r.scale == places {
        return Some(r);
    }
    let mut units = r.units;
    for _ in r.scale..places {
        units = units.checked_mul(10)?;
    }
    Some(Decimal {
        units,
        scale: places,
    })
}

fn group(digits: &str, sep: char) -> String {
    let n = digits.len();
    let mut out = String::with_capacity(n + n / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (n - i).is_multiple_of(3) {
            out.push(sep);
        }
        out.push(c);
    }
    out
}

fn render(d: &Decimal, lang: Lang) -> String {
    let (thousands, point) = match lang {
        Lang::En => (',', '.'),
        Lang::Da => ('.', ','),
    };
    let plain = d.to_plain();
    let (neg, rest) = match plain.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, plain.as_str()),
    };
    let (int, frac) = match rest.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (rest, None),
    };
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    out.push_str(&group(int, thousands));
    if let Some(f) = frac {
        out.push(point);
        out.push_str(f);
    }
    out
}

fn shown(x: &CellValue, places: u8, lang: Lang) -> Option<(String, Decimal)> {
    let d = at_places(to_decimal(x)?, places)?;
    Some((render(&d, lang), d))
}

/// Money: 2 decimals (the currency code is added by the slot).
pub fn format_money(x: &CellValue, lang: Lang) -> Option<(String, Decimal)> {
    shown(x, 2, lang)
}

/// `Int` prints as an integer, `Real` with 2 decimals.
pub fn format_number(x: &CellValue, lang: Lang) -> Option<(String, Decimal)> {
    match x {
        CellValue::Int(_) => shown(x, 0, lang),
        _ => shown(x, 2, lang),
    }
}

/// 0 decimals, half-even.
pub fn format_int(x: &CellValue, lang: Lang) -> Option<(String, Decimal)> {
    shown(x, 0, lang)
}

fn with_percent(text: String, lang: Lang) -> String {
    match lang {
        Lang::En => format!("{text}%"),
        Lang::Da => format!("{text} %"),
    }
}

/// `x` is already in percent: 1 decimal and `%`.
pub fn format_percent(x: &CellValue, lang: Lang) -> Option<(String, Decimal)> {
    let (t, d) = shown(x, 1, lang)?;
    Some((with_percent(t, lang), d))
}

/// `x` is a ratio: × 100 on the decimal, then as a percent.
pub fn format_ratio_percent(x: &CellValue, lang: Lang) -> Option<(String, Decimal)> {
    let d = to_decimal(x)?;
    let scaled = Decimal {
        units: d.units.checked_mul(100)?,
        scale: d.scale,
    };
    let d = at_places(scaled, 1)?;
    Some((with_percent(render(&d, lang), lang), d))
}

/// `places` decimals (0-6).
pub fn format_round(x: &CellValue, places: u8, lang: Lang) -> Option<(String, Decimal)> {
    if places > 6 {
        return None;
    }
    shown(x, places, lang)
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) {
                29
            } else {
                28
            }
        }
    }
}

/// An ISO `YYYY-MM-DD` text cell: the formatted date and the ISO string.
pub fn format_date(x: &CellValue, lang: Lang) -> Option<(String, String)> {
    let CellValue::Text(s) = x else { return None };
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = b.get(r)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        part.iter()
            .try_fold(0u32, |a, d| Some(a * 10 + u32::from(d - b'0')))
    };
    let (y, m, d) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    if y == 0 || !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    const EN: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    const DA: [&str; 12] = [
        "januar",
        "februar",
        "marts",
        "april",
        "maj",
        "juni",
        "juli",
        "august",
        "september",
        "oktober",
        "november",
        "december",
    ];
    let text = match lang {
        Lang::En => format!("{d} {} {y}", EN[(m - 1) as usize]),
        Lang::Da => format!("{d}. {} {y}", DA[(m - 1) as usize]),
    };
    Some((text, s.clone()))
}

// ---- filling ----

fn cell<'a>(r: &'a ResultSet, c: &CellRef) -> Result<&'a CellValue, MethodError> {
    let col = r
        .columns
        .iter()
        .position(|n| *n == c.col)
        .ok_or_else(check_failed)?;
    let v = r
        .rows
        .get(c.row)
        .and_then(|row| row.get(col))
        .ok_or_else(check_failed)?;
    if matches!(v, CellValue::Null) {
        return Err(check_failed());
    }
    Ok(v)
}

fn dec(v: &CellValue, places: u8) -> Result<Decimal, MethodError> {
    to_decimal(v)
        .and_then(|d| at_places(d, places))
        .ok_or_else(check_failed)
}

fn count(n: u64, lang: Lang) -> (String, Decimal) {
    let d = Decimal {
        units: i128::from(n),
        scale: 0,
    };
    (render(&d, lang), d)
}

struct Out {
    text: String,
    values: Vec<Decimal>,
    dates: Vec<String>,
    from_param: bool,
}

impl Out {
    fn num(t: String, d: Decimal) -> Out {
        Out {
            text: t,
            values: vec![d],
            dates: Vec::new(),
            from_param: false,
        }
    }
}

fn fill_slot(s: &Slot, r: &ResultSet, params: &[Param], lang: Lang) -> Result<Out, MethodError> {
    let fmt = |c: &CellRef, f: Formatter| -> Result<Out, MethodError> {
        let (t, d) = f(cell(r, c)?, lang).ok_or_else(check_failed)?;
        Ok(Out::num(t, d))
    };
    match s {
        Slot::Money(c, code) => {
            let mut o = fmt(c, &format_money)?;
            if let Some(code) = code {
                o.text.push(' ');
                o.text.push_str(code);
            }
            Ok(o)
        }
        Slot::Number(c) => fmt(c, &format_number),
        Slot::Int(c) => fmt(c, &format_int),
        Slot::Percent(c) => fmt(c, &format_percent),
        Slot::RatioPercent(c) => fmt(c, &format_ratio_percent),
        Slot::Round(c, n) => fmt(c, &|x, l| format_round(x, *n, l)),
        Slot::Date(c) => {
            let (t, iso) = format_date(cell(r, c)?, lang).ok_or_else(check_failed)?;
            Ok(Out {
                text: t,
                values: Vec::new(),
                dates: vec![iso],
                from_param: false,
            })
        }
        Slot::Cmp(a, b) => {
            let a = dec(cell(r, a)?, 2)?;
            let b = dec(cell(r, b)?, 2)?;
            let w = match (a.cmp(&b), lang) {
                (std::cmp::Ordering::Greater, Lang::En) => "above",
                (std::cmp::Ordering::Less, Lang::En) => "below",
                (std::cmp::Ordering::Equal, Lang::En) => "equal to",
                (std::cmp::Ordering::Greater, Lang::Da) => "over",
                (std::cmp::Ordering::Less, Lang::Da) => "under",
                (std::cmp::Ordering::Equal, Lang::Da) => "lig med",
            };
            Ok(Out {
                text: w.to_string(),
                values: Vec::new(),
                dates: Vec::new(),
                from_param: false,
            })
        }
        Slot::Param(name) => {
            let p = params
                .iter()
                .find(|p| p.name == *name)
                .ok_or_else(check_failed)?;
            if p.display.is_empty() {
                return Err(check_failed());
            }
            Ok(Out {
                text: p.display.clone(),
                values: Vec::new(),
                dates: Vec::new(),
                from_param: true,
            })
        }
        Slot::Rows => {
            let (t, d) = count(r.rows.len() as u64, lang);
            Ok(Out::num(t, d))
        }
        Slot::TotalRows => {
            let n = if r.truncated {
                r.total_rows.ok_or_else(check_failed)?
            } else {
                r.rows.len() as u64
            };
            let (t, d) = count(n, lang);
            Ok(Out::num(t, d))
        }
        Slot::List(cols) => {
            let mut o = Out {
                text: String::new(),
                values: Vec::new(),
                dates: Vec::new(),
                from_param: false,
            };
            for row in 0..r.rows.len() {
                if row > 0 {
                    o.text.push('\n');
                }
                o.text.push_str("- ");
                for (k, col) in cols.iter().enumerate() {
                    if k > 0 {
                        o.text.push_str(" · ");
                    }
                    let c = CellRef {
                        row,
                        col: col.clone(),
                    };
                    match cell(r, &c)? {
                        // A date cell (ISO `YYYY-MM-DD`, how the snapshot
                        // stores a `DATE`) prints as a date in the
                        // answer's language and is a date source, as a
                        // `{date(..)}` slot is (plan 48 T2).
                        v @ CellValue::Text(_) if format_date(v, lang).is_some() => {
                            let (t, iso) = format_date(v, lang).ok_or_else(check_failed)?;
                            o.text.push_str(&t);
                            o.dates.push(iso);
                        }
                        // Other text is verbatim and is not a number source.
                        CellValue::Text(t) => o.text.push_str(t),
                        v => {
                            let (t, d) = format_number(v, lang).ok_or_else(check_failed)?;
                            o.text.push_str(&t);
                            o.values.push(d);
                        }
                    }
                }
            }
            Ok(o)
        }
    }
}

/// Fill the slots from the result, recording each printed span.
pub fn fill(
    t: &Template,
    r: &ResultSet,
    params: &[Param],
    lang: Lang,
) -> Result<Filled, MethodError> {
    let mut text = String::new();
    let mut printed = Vec::new();
    for p in &t.parts {
        match p {
            Part::Text(s) => text.push_str(s),
            Part::Slot(s) => {
                let o = fill_slot(s, r, params, lang)?;
                let start = text.len();
                text.push_str(&o.text);
                printed.push(Printed {
                    start,
                    end: text.len(),
                    values: o.values,
                    dates: o.dates,
                    from_param: o.from_param,
                });
            }
        }
    }
    Ok(Filled { text, printed })
}
