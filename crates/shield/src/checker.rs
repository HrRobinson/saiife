//! Plan 45: the strict number checker (R45-10), the last gate before an
//! answer about real data is shown.
//!
//! Every number and date in the filled answer must be one the calculator
//! printed (a slot recorded it), one written in the user's question, or part
//! of a resolved parameter's display. Anything else refuses the whole answer.
//! The refusal reason quotes a number only when it sits in the template's
//! fixed text; a number inside a printed (data) or parameter span is never
//! quoted. Invalid spans refuse; nothing here slices blindly.
//!
//! Fail closed: a numeral the parser cannot read (`²`, `½`, Arabic-Indic
//! digits) refuses, a sign glued to a number belongs to it (`-18,420.00` is
//! not `18,420.00`), a date span is classified on its own and refuses on any
//! parser error, and a quantity word the number lexicon lacks (`twice`,
//! `halvt`, `hundreds`) refuses unless the question has it. ASCII Roman
//! numerals and slash dates are read as digits or words and refuse with the
//! generic reason.

use crate::lang::{find_dates, find_literals, find_numbers, find_unreadable_numerics, Literal};
use crate::schema::{Decimal, Lang};
use crate::template::{Filled, Printed};

/// How many numbers and dates each source accounted for. A found number or
/// date counts once, under the first source that accepts it (calculator,
/// parameters, question).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckReport {
    pub numbers: usize,
    pub from_calc: usize,
    pub from_question: usize,
    pub from_params: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRefusal {
    pub reason: String,
}

const DATA_REASON: &str = "a number in the answer is not from the calculator";
const DATE_REASON: &str = "a date in the answer is not from the calculator or your question";
const SPAN_REASON: &str = "the answer could not be verified";

fn refuse(reason: String) -> CheckRefusal {
    CheckRefusal { reason }
}

#[derive(Clone, Copy)]
enum Source {
    Calc,
    Params,
    Question,
}

/// Where a byte range sits relative to the printed spans.
enum Place<'a> {
    /// Entirely inside these spans (at least one).
    Inside(Vec<&'a Printed>),
    /// Overlaps a span without being inside any.
    Straddles,
    /// Outside every span: the template's fixed text.
    Fixed,
}

fn place(printed: &[Printed], s: usize, e: usize) -> Place<'_> {
    let inside: Vec<&Printed> = printed
        .iter()
        .filter(|p| p.start <= s && e <= p.end)
        .collect();
    if !inside.is_empty() {
        return Place::Inside(inside);
    }
    if printed.iter().any(|p| s < p.end && p.start < e) {
        Place::Straddles
    } else {
        Place::Fixed
    }
}

/// One date span read on its own: `(iso, is_range)`. Anything but exactly
/// one literal covering the whole span is `None`.
fn classify_date(text: &str, s: usize, e: usize, lang: Lang) -> Option<bool> {
    let slice = text.get(s..e)?;
    let lits = find_literals(slice, lang).ok()?;
    match lits.as_slice() {
        [l] if l.start == 0 && l.end == slice.len() => match l.lit {
            Literal::Date(_) => Some(false),
            Literal::DateRange { .. } => Some(true),
            _ => None,
        },
        _ => None,
    }
}

/// Dates of the text with the range flag; `None` when any span cannot be
/// classified.
fn dates_of(text: &str, lang: Lang) -> Option<Vec<(usize, usize, String, bool)>> {
    find_dates(text, lang)
        .into_iter()
        .map(|(s, e, iso)| classify_date(text, s, e, lang).map(|r| (s, e, iso, r)))
        .collect()
}

fn negate(d: Decimal) -> Decimal {
    Decimal {
        units: d.units.checked_neg().unwrap_or(i128::MAX),
        scale: d.scale,
    }
}

/// Numbers with a directly glued sign folded in: `-`, `U+2212` or `+` before
/// a number, when the char before the sign is not alphanumeric, belongs to
/// the number (the span starts at the sign).
fn signed_numbers(text: &str, lang: Lang) -> Vec<(usize, usize, Decimal)> {
    find_numbers(text, lang)
        .into_iter()
        .map(|(s, e, v)| {
            let Some(c) = text.get(..s).and_then(|t| t.chars().next_back()) else {
                return (s, e, v);
            };
            if !matches!(c, '-' | '\u{2212}' | '+') {
                return (s, e, v);
            }
            let ss = s - c.len_utf8();
            let before = text.get(..ss).and_then(|t| t.chars().next_back());
            if before.is_some_and(char::is_alphanumeric) {
                return (s, e, v);
            }
            (ss, e, if c == '+' { v } else { negate(v) })
        })
        .collect()
}

const DATA_WORD_REASON: &str = "a quantity word in the answer is not from the question";
const UNREADABLE_REASON: &str = "a number in the answer cannot be read";

/// Quantity words the number lexicon does not know (R44-3 gaps), checked
/// here until plan 44 extends it.
const QUANTITY_WORDS: &[&str] = &[
    "twice",
    "thrice",
    "double",
    "triple",
    "half",
    "couple",
    "pair",
    "hundreds",
    "thousands",
    "millions",
    "billions",
    "trillion",
    "trillions",
    "dozens",
    "hundredth",
    "thousandth",
    "millionth",
    "halvanden",
    "halv",
    "halvt",
    "halve",
    "dobbelt",
    "dobbelte",
    "tredobbelt",
    "par",
    "hundreder",
    "tusinder",
    "millioner",
    "trettende",
    "fjortende",
    "femtende",
    "sekstende",
    "syttende",
    "attende",
    "nittende",
    "tyvende",
    "tredivte",
];

fn is_quantity_word(w: &str) -> bool {
    QUANTITY_WORDS.contains(&w)
        || (w.len() > 6 && (w.ends_with("teenth") || w.ends_with("tieth")))
        || (w.ends_with("tyvende") && w.len() > 7)
}

/// Alphabetic words with byte spans and a char-wise lowercase form.
fn words(text: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut cur = String::new();
    for (i, c) in text.char_indices() {
        if c.is_alphabetic() {
            start.get_or_insert(i);
            cur.extend(c.to_lowercase());
        } else if let Some(s) = start.take() {
            out.push((s, i, std::mem::take(&mut cur)));
        }
    }
    if let Some(s) = start {
        out.push((s, text.len(), cur));
    }
    out
}

pub fn check(f: &Filled, question: &str, lang: Lang) -> Result<CheckReport, CheckRefusal> {
    let text = f.text.as_str();
    for p in &f.printed {
        if p.start > p.end || text.get(p.start..p.end).is_none() {
            return Err(refuse(SPAN_REASON.into()));
        }
    }
    // An unreadable numeral anywhere outside a parameter display refuses.
    // Non-ASCII numerals (`²`, `５`, `½`) are never sources: even those the
    // lexicon folds refuse in the answer.
    let mut runs = find_unreadable_numerics(text);
    runs.extend(
        text.char_indices()
            .filter(|(_, c)| c.is_numeric() && !c.is_ascii_digit())
            .map(|(i, c)| (i, i + c.len_utf8())),
    );
    for (s, e) in runs {
        if !matches!(place(&f.printed, s, e), Place::Inside(v) if v.iter().any(|p| p.from_param)) {
            return Err(refuse(UNREADABLE_REASON.into()));
        }
    }
    let q_numbers: Vec<Decimal> = signed_numbers(question, lang)
        .into_iter()
        .map(|(_, _, d)| d)
        .collect();
    // A question date that cannot be classified is simply not a source.
    let q_dates: Vec<(String, bool)> = find_dates(question, lang)
        .into_iter()
        .filter_map(|(s, e, iso)| classify_date(question, s, e, lang).map(|r| (iso, r)))
        .collect();
    let printed_values: Vec<&Decimal> = f
        .printed
        .iter()
        .filter(|p| !p.from_param)
        .flat_map(|p| p.values.iter())
        .collect();
    let printed_dates: Vec<&String> = f.printed.iter().flat_map(|p| p.dates.iter()).collect();

    let mut report = CheckReport {
        numbers: 0,
        from_calc: 0,
        from_question: 0,
        from_params: 0,
    };
    let count = |src: Source, r: &mut CheckReport| {
        r.numbers += 1;
        match src {
            Source::Calc => r.from_calc += 1,
            Source::Params => r.from_params += 1,
            Source::Question => r.from_question += 1,
        }
    };

    // Dates first: a number inside an accepted date is covered by it.
    let mut covered: Vec<(usize, usize)> = Vec::new();
    let Some(answer_dates) = dates_of(text, lang) else {
        return Err(refuse(DATE_REASON.into()));
    };
    for (s, e, iso, is_range) in answer_dates {
        let src = match place(&f.printed, s, e) {
            Place::Straddles => None,
            Place::Inside(spans) => {
                if spans
                    .iter()
                    .any(|p| !p.from_param && !is_range && p.dates.contains(&iso))
                {
                    Some(Source::Calc)
                } else if spans.iter().any(|p| p.from_param) {
                    Some(Source::Params)
                } else {
                    None
                }
            }
            Place::Fixed => {
                if !is_range && printed_dates.iter().any(|d| **d == iso) {
                    Some(Source::Calc)
                } else if q_dates.iter().any(|(d, r)| *d == iso && *r == is_range) {
                    Some(Source::Question)
                } else {
                    None
                }
            }
        };
        match src {
            Some(src) => {
                count(src, &mut report);
                covered.push((s, e));
            }
            None => return Err(refuse(DATE_REASON.into())),
        }
    }

    for (s, e, value) in signed_numbers(text, lang) {
        if covered.iter().any(|&(cs, ce)| cs <= s && e <= ce) {
            continue;
        }
        let src = match place(&f.printed, s, e) {
            Place::Straddles => None,
            Place::Inside(spans) => {
                if spans
                    .iter()
                    .any(|p| !p.from_param && p.values.contains(&value))
                {
                    Some(Source::Calc)
                } else if spans.iter().any(|p| p.from_param) {
                    Some(Source::Params)
                } else {
                    None
                }
            }
            Place::Fixed => {
                if printed_values.iter().any(|v| **v == value) {
                    Some(Source::Calc)
                } else if q_numbers.contains(&value) {
                    Some(Source::Question)
                } else {
                    return Err(refuse(match text.get(s..e) {
                        Some(n) => {
                            format!("the number {n} is not from the calculator or your question")
                        }
                        None => DATA_REASON.into(),
                    }));
                }
            }
        };
        match src {
            Some(src) => count(src, &mut report),
            None => return Err(refuse(DATA_REASON.into())),
        }
    }

    // Quantity words outside parameter displays need the same word in the
    // question.
    let q_words: Vec<String> = words(question).into_iter().map(|(_, _, w)| w).collect();
    for (s, e, w) in words(text) {
        if !is_quantity_word(&w) || q_words.contains(&w) {
            continue;
        }
        match place(&f.printed, s, e) {
            Place::Inside(v) if v.iter().any(|p| p.from_param) => {}
            Place::Fixed => {
                return Err(refuse(match text.get(s..e) {
                    Some(n) => format!("the word {n} is not from the question"),
                    None => DATA_WORD_REASON.into(),
                }));
            }
            _ => return Err(refuse(DATA_WORD_REASON.into())),
        }
    }
    Ok(report)
}
