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
use crate::schema::{Decimal, Lang, Param};
use crate::sql::{ErrorClass, MethodError};

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
            Part::Slot(Slot::Cmp(..) | Slot::Param(_)) => Seg::Other,
            Part::Slot(_) => Seg::Num,
        })
        .collect();
    grammar_ok(&segs).map_err(slot_err)?;
    Ok(Template { parts })
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
                        // Text is verbatim and is not a number source.
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
