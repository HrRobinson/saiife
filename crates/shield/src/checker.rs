//! Plan 45: the strict number checker (R45-10), the last gate before an
//! answer about real data is shown.
//!
//! Every number and date in the filled answer must be one the calculator
//! printed (a slot recorded it), one written in the user's question, or part
//! of a resolved parameter's display. Anything else refuses the whole answer.
//! The refusal reason quotes a number only when it sits in the template's
//! fixed text; a number inside a printed (data) or parameter span is never
//! quoted. Invalid spans refuse; nothing here slices blindly.

use crate::lang::{find_dates, find_literals, find_numbers, Literal};
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

/// Dates of the text with the range flag (`Q3 2026`, `juli 2026`).
fn dates_of(text: &str, lang: Lang) -> Vec<(usize, usize, String, bool)> {
    let ranges: Vec<usize> = find_literals(text, lang)
        .map(|v| {
            v.into_iter()
                .filter(|l| matches!(l.lit, Literal::DateRange { .. }))
                .map(|l| l.start)
                .collect()
        })
        .unwrap_or_default();
    find_dates(text, lang)
        .into_iter()
        .map(|(s, e, iso)| (s, e, iso, ranges.contains(&s)))
        .collect()
}

pub fn check(f: &Filled, question: &str, lang: Lang) -> Result<CheckReport, CheckRefusal> {
    let text = f.text.as_str();
    for p in &f.printed {
        if p.start > p.end || text.get(p.start..p.end).is_none() {
            return Err(refuse(SPAN_REASON.into()));
        }
    }
    let q_numbers: Vec<Decimal> = find_numbers(question, lang)
        .into_iter()
        .map(|(_, _, d)| d)
        .collect();
    let q_dates: Vec<(String, bool)> = dates_of(question, lang)
        .into_iter()
        .map(|(_, _, iso, r)| (iso, r))
        .collect();
    let printed_values: Vec<&Decimal> = f.printed.iter().flat_map(|p| p.values.iter()).collect();
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
    for (s, e, iso, is_range) in dates_of(text, lang) {
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

    for (s, e, value) in find_numbers(text, lang) {
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
                    let fixed = matches!(place(&f.printed, s, e), Place::Fixed);
                    let shown = text.get(s..e).filter(|_| fixed);
                    return Err(refuse(match shown {
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
    Ok(report)
}
