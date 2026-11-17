//! Plan 44 T3: the question parameterizer and the local resolution steps
//! (spec §2.1.6, §2.1.7, R44-2, R44-9).
//!
//! A question becomes a [`Draft`]: its text with every literal and entity
//! replaced by `:p1`, `:p2`, ... and the typed parameters bound locally.
//! Whatever needs the user (a pick between namesakes, "did you mean", keeping
//! an unknown name as text) is a [`Pending`] step answered with [`answer`].
//!
//! Spans are claimed in this order (ruling P-12): the literals
//! ([`find_literals`]) first; then the lexicon spans, searched in each part of
//! the question between literals; then the name detector's spans, searched
//! over the whole question. A detector span inside a claimed span is
//! dropped; the parts of one that no claimed span covers are each handled as
//! a span of the detector's label.
//!
//! S-1: every offset is a byte offset into the original question, from code
//! that worked on that same string (the literal parser, the lexicon's token
//! spans, the detector), and every slice goes through `str::get`. A span that
//! does not fit is an error, never a panic. Folded copies are never sliced.
//!
//! Fail closed: a literal that does not parse, a detector error or a bad
//! detector span refuses the question; a lexicon error is an `Err`. Nothing
//! falls back to sending more text. Error texts are fixed strings.
//!
//! `Draft`, `Pending`, `Step`, `Refusal` and `Answer` print in `Debug` the
//! kinds, names of parameters and counts only: never the question, a name a
//! user wrote, or a candidate (ruling P-14).

use crate::error::ShieldError;
use crate::lang::{detect_lang, find_literals, find_literals_detected, Literal, LiteralSpan};
use crate::lexicon::{Candidate, Lexicon, Resolve, SpanHit};
use crate::ner::{DetectError, NameDetector, NameSpan, SpanLabel};
use crate::norm::token_spans;
use crate::schema::{Bound, Lang, Param, ParamType, Schema};
use std::fmt;

/// The longest run of tokens the lexicon span finder tries at each start.
/// The lexicon does not record its longest entity name, so this is a fixed
/// cap: six tokens covers a full name with two middle names and a two-word
/// family name, and multi-word literal values (cities, segments) of that
/// length, while keeping the scan at 6 lookups per token.
pub const MAX_SPAN_TOKENS: usize = 6;

// ------------------------------------------------------------- types ----

/// A question with its parameters: plain public data (ruling P-16), so a
/// draft can be built by hand. `original` and `text` hold what the user
/// wrote: local only, and left out of `Debug`.
///
/// The invariants [`answer`] checks (an inconsistent draft is an `Err`):
/// `text` holds `:p1`..`:pK` once each, in order, for the K `params` (named
/// `p1`..`pK`), and nothing else shaped like a parameter; a `Pick` or
/// `DidYouMean` names an unbound param, each unbound param has exactly one
/// such step; a `KeepName` span is the name's bytes in `original`.
/// [`parameterize`] also copies the text between the parameters from
/// `original` verbatim and sets each `display` to the text as written, but
/// [`answer`] does not verify either: a hand-built draft must keep them.
#[derive(Clone)]
pub struct Draft {
    pub lang: Lang,
    pub original: String,
    /// The question with `:pN` for each parameter.
    pub text: String,
    pub params: Vec<Param>,
    /// In question order; `pending[0]` is the one [`answer`] answers.
    pub pending: Vec<Pending>,
}

#[derive(Clone)]
pub enum Pending {
    /// More than one match: the user picks from a local list (spec §2.1.6).
    /// `too_many`: there were more than the [`crate::lexicon::MAX_CANDIDATES`]
    /// listed.
    Pick {
        param: String,
        word: String,
        candidates: Vec<Candidate>,
        too_many: bool,
    },
    /// An unknown name close to one known name (R43-8).
    /// `word` is the entity word in the question's language, as in `Pick`
    /// (needed when a "yes" leads to a list or a refusal).
    DidYouMean {
        param: String,
        word: String,
        written: String,
        suggestion: Candidate,
    },
    /// An unknown name kept as plain text needs a `blind:name` touch (R44-9).
    KeepName { span: (usize, usize), name: String },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// 1-based index into the list; 0 is "none of these".
    Pick(usize),
    DidYouMean(bool),
    /// True only after the touch was verified (plan 48).
    KeepName(bool),
}

pub enum Step {
    Ready(Draft),
    /// `draft.pending[0]` is the question for the user.
    Ask(Draft),
    Refuse(Refusal),
}

#[derive(Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `no <word> named that`; `written` is the user's text (local only).
    NoMatch { word: String, written: String },
    /// A literal that does not parse as its type (byte range), with a fixed
    /// reason (e.g. [`crate::lang::AMBIGUOUS_NUMBER`]); never the text.
    BadLiteral {
        span: (usize, usize),
        why: &'static str,
    },
    /// The user declined to keep an unknown name as text, or the touch failed.
    NameRefused { name: String },
    /// "None of these" on a list that was cut at the candidate cap.
    TooMany { word: String },
    /// The name detector failed or gave a span that does not fit (fixed text).
    Detector(String),
}

// ---------------------------------------------------- internal state ----

#[derive(Clone)]
struct Item {
    start: usize,
    end: usize,
    state: State,
}

#[derive(Clone)]
enum State {
    Bound {
        ty: ParamType,
        bound: Bound,
        display: String,
    },
    Pick {
        ent: Ent,
        candidates: Vec<Candidate>,
        too_many: bool,
    },
    DidYouMean {
        ent: Ent,
        suggestion: Candidate,
    },
    /// Waiting for KeepName.
    KeepAsk,
}

/// An entity table's parameter type and its word in the question's language.
#[derive(Clone)]
struct Ent {
    ty: ParamType,
    word: String,
}

fn ent(schema: &Schema, table: &str, lang: Lang) -> Result<Ent, ShieldError> {
    let e = schema.entity_for(table).ok_or(ShieldError::Corrupt(
        "the lexicon does not match the schema",
    ))?;
    Ok(Ent {
        ty: ParamType::Entity {
            table: e.table.clone(),
            word: e.word.clone(),
        },
        word: match lang {
            Lang::En => e.word.clone(),
            Lang::Da => e.word_da.clone(),
        },
    })
}

/// `Anna Berg, Aarhus (customer #4411)`: the name, the first `show` column
/// when it has a value, the entity word and the key.
fn entity_display(c: &Candidate, word: &str) -> String {
    let mut s = c.display.clone();
    if let Some((_, v)) = c.show.first() {
        if !v.is_empty() {
            s.push_str(", ");
            s.push_str(v);
        }
    }
    format!("{s} ({word} #{})", c.key)
}

fn bad_span() -> ShieldError {
    ShieldError::Corrupt("a span does not fit the question")
}

fn slice(s: &str, a: usize, b: usize) -> Result<&str, ShieldError> {
    if a >= b {
        return Err(bad_span());
    }
    s.get(a..b).ok_or_else(bad_span)
}

// ------------------------------------------------------ parameterize ----

/// A span found before resolution.
enum Raw {
    Lit(Literal),
    Entity(String),
    Text(String, String, String),
    Person,
}

fn literal_state(lit: Literal, written: &str) -> State {
    let (ty, bound) = match lit {
        Literal::Amount { value, .. } => (ParamType::Amount, Bound::Amount(value)),
        Literal::Integer(n) => (ParamType::Integer, Bound::Integer(n)),
        Literal::Percent(p) => (ParamType::Percent, Bound::Percent(p)),
        Literal::Date(d) => (ParamType::Date, Bound::Date(d)),
        Literal::DateRange { from, to_exclusive } => {
            (ParamType::DateRange, Bound::DateRange(from, to_exclusive))
        }
    };
    State::Bound {
        ty,
        bound,
        display: written.to_string(),
    }
}

fn detect_text(e: &DetectError) -> &'static str {
    match e {
        DetectError::Unavailable(_) => "the name detector is not available",
        DetectError::Failed => "the name detector failed",
    }
}

/// The first and last token of `s[a..b]`, as offsets into `s`; None when
/// the part holds no letter or digit.
fn trim(s: &str, a: usize, b: usize) -> Result<Option<(usize, usize)>, ShieldError> {
    let t = token_spans(slice(s, a, b)?);
    Ok(match (t.first(), t.last()) {
        (Some(f), Some(l)) => Some((a + f.1, a + l.2)),
        _ => None,
    })
}

/// `a..b` minus the claimed spans (sorted, not overlapping).
fn uncovered(a: usize, b: usize, claimed: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = a;
    for &(cs, ce) in claimed {
        if ce <= at || cs >= b {
            continue;
        }
        if cs > at {
            out.push((at, cs));
        }
        at = at.max(ce);
    }
    if at < b {
        out.push((at, b));
    }
    out
}

/// Turns a question into a draft: the literals and entities become
/// parameters, and each name that does not resolve becomes a pending step.
pub fn parameterize(
    question: &str,
    lang: Option<Lang>,
    schema: &Schema,
    lex: &Lexicon,
    det: &dyn NameDetector,
) -> Result<Step, ShieldError> {
    // Ruling P-27: an explicit language reads `10,000` by its decimal mark;
    // a detected one refuses it as ambiguous.
    let (lang, detected) = match lang {
        Some(l) => (l, false),
        None => (detect_lang(question), true),
    };

    // 0. A typed `:p9` would read as a parameter name (and R44-8 skips
    // those in the number scan): refuse it like a bad literal.
    if let Some((a, b)) = param_token(question, 0) {
        return Ok(Step::Refuse(Refusal::BadLiteral {
            span: (a, b),
            why: "a parameter name typed in the question",
        }));
    }

    // 1. Literals.
    let found = if detected {
        find_literals_detected(question, lang)
    } else {
        find_literals(question, lang)
    };
    let lits: Vec<LiteralSpan> = match found {
        Ok(v) => v,
        Err(e) => {
            return Ok(Step::Refuse(Refusal::BadLiteral {
                span: (e.start, e.end),
                why: e.why,
            }))
        }
    };
    let mut raw: Vec<(usize, usize, Raw)> = Vec::new();
    let mut segments: Vec<(usize, usize)> = Vec::new();
    let mut at = 0;
    for l in lits {
        if l.start < at {
            return Err(bad_span());
        }
        slice(question, l.start, l.end)?;
        segments.push((at, l.start));
        at = l.end;
        raw.push((l.start, l.end, Raw::Lit(l.lit)));
    }
    segments.push((at, question.len()));

    // 2. Lexicon spans in the parts between literals.
    for (a, b) in segments {
        if a >= b {
            continue;
        }
        let seg = slice(question, a, b)?;
        for h in lex.find_spans(seg, MAX_SPAN_TOKENS)? {
            let (s, e, r) = match h {
                SpanHit::Entity { start, end, table } => (start, end, Raw::Entity(table)),
                SpanHit::Literal { start, end, hit } => {
                    let (t, c) = hit.column;
                    (start, end, Raw::Text(t, c, hit.value))
                }
            };
            let (s, e) = (
                s.checked_add(a).ok_or_else(bad_span)?,
                e.checked_add(a).ok_or_else(bad_span)?,
            );
            if e > b {
                return Err(bad_span());
            }
            slice(question, s, e)?;
            raw.push((s, e, r));
        }
    }
    raw.sort_by_key(|r| r.0);
    let mut claimed: Vec<(usize, usize)> = raw.iter().map(|r| (r.0, r.1)).collect();
    claimed.sort_unstable();
    if claimed.windows(2).any(|w| w[1].0 < w[0].1) {
        return Err(bad_span());
    }

    // 3. Detector spans over the whole question. Offsets are untrusted.
    let mut spans: Vec<NameSpan> = match det.detect(question) {
        Ok(v) => v,
        Err(e) => return Ok(Step::Refuse(Refusal::Detector(detect_text(&e).into()))),
    };
    if spans
        .iter()
        .any(|s| s.start >= s.end || question.get(s.start..s.end).is_none())
    {
        return Ok(Step::Refuse(Refusal::Detector(
            "the name detector gave a span outside the question".into(),
        )));
    }
    spans.sort_by_key(|s| (s.start, s.end));
    if spans.windows(2).any(|w| w[1].start < w[0].end) {
        return Ok(Step::Refuse(Refusal::Detector(
            "the name detector gave overlapping spans".into(),
        )));
    }
    for sp in spans {
        for (a, b) in uncovered(sp.start, sp.end, &claimed) {
            let Some((a, b)) = trim(question, a, b)? else {
                continue;
            };
            let piece = slice(question, a, b)?;
            // The whole part is a known name or value: as if the lexicon
            // had found it.
            let toks = token_spans(piece);
            let whole = match lex.find_spans(piece, MAX_SPAN_TOKENS)?.as_slice() {
                [h] => {
                    let (hs, he) = match h {
                        SpanHit::Entity { start, end, .. }
                        | SpanHit::Literal { start, end, .. } => (*start, *end),
                    };
                    let full = toks.first().map(|t| t.1) == Some(hs)
                        && toks.last().map(|t| t.2) == Some(he);
                    full.then(|| h.clone())
                }
                _ => None,
            };
            match whole {
                Some(SpanHit::Entity { table, .. }) => raw.push((a, b, Raw::Entity(table))),
                Some(SpanHit::Literal { hit, .. }) => {
                    let (t, c) = hit.column;
                    raw.push((a, b, Raw::Text(t, c, hit.value)));
                }
                // R44-9: an unknown Person must resolve or be kept by touch;
                // an unknown place, organization or other name stays text.
                None if sp.label == SpanLabel::Person => raw.push((a, b, Raw::Person)),
                None => {}
            }
        }
    }
    raw.sort_by_key(|r| r.0);

    // 4. Resolve in question order.
    let mut items = Vec::with_capacity(raw.len());
    for (start, end, r) in raw {
        let written = slice(question, start, end)?;
        let state = match r {
            Raw::Lit(l) => literal_state(l, written),
            Raw::Text(table, column, value) => State::Bound {
                ty: ParamType::Text { table, column },
                bound: Bound::Text(value),
                display: written.to_string(),
            },
            Raw::Entity(table) => {
                let e = ent(schema, &table, lang)?;
                let word = e.word.clone();
                match resolve_state(lex, e, &table, written)? {
                    Some(s) => s,
                    None => match suggest(lex, schema, lang, written)? {
                        Some(s) => s,
                        None => {
                            return Ok(Step::Refuse(Refusal::NoMatch {
                                word,
                                written: written.to_string(),
                            }));
                        }
                    },
                }
            }
            Raw::Person => suggest(lex, schema, lang, written)?.unwrap_or(State::KeepAsk),
        };
        items.push(Item { start, end, state });
    }
    let d = build(lang, question.to_string(), items)?;
    // The built draft must meet the invariants `answer` checks (a `:pN`
    // run into a digit, say): otherwise fail closed.
    check(&d)?;
    Ok(step(d))
}

/// Resolves `phrase` in `table`: one match is bound, several are a pick,
/// none is `None`.
fn resolve_state(
    lex: &Lexicon,
    e: Ent,
    table: &str,
    phrase: &str,
) -> Result<Option<State>, ShieldError> {
    Ok(match lex.resolve(table, phrase)? {
        (Resolve::One(c), _) => Some(State::Bound {
            display: entity_display(&c, &e.word),
            ty: e.ty,
            bound: Bound::Keys(vec![c.key]),
        }),
        (Resolve::Many(candidates), too_many) => Some(State::Pick {
            ent: e,
            candidates,
            too_many,
        }),
        (Resolve::None, _) => None,
    })
}

/// "Did you mean": a pending step with the closest known name, if any.
fn suggest(
    lex: &Lexicon,
    schema: &Schema,
    lang: Lang,
    written: &str,
) -> Result<Option<State>, ShieldError> {
    Ok(match lex.did_you_mean(written)? {
        Some(suggestion) => Some(State::DidYouMean {
            ent: ent(schema, &suggestion.table, lang)?,
            suggestion,
        }),
        None => None,
    })
}

/// The draft from the items: `:pN` in question order.
fn build(lang: Lang, original: String, items: Vec<Item>) -> Result<Draft, ShieldError> {
    let mut text = String::with_capacity(original.len());
    let mut params = Vec::new();
    let mut pending = Vec::new();
    let mut at = 0;
    for it in items {
        if it.start < at {
            return Err(bad_span());
        }
        text.push_str(original.get(at..it.start).ok_or_else(bad_span)?);
        let written = slice(&original, it.start, it.end)?;
        at = it.end;
        let name = format!("p{}", params.len() + 1);
        let (ty, bound, display) = match it.state {
            State::KeepAsk => {
                text.push_str(written);
                pending.push(Pending::KeepName {
                    span: (it.start, it.end),
                    name: written.to_string(),
                });
                continue;
            }
            State::Bound { ty, bound, display } => (ty, Some(bound), display),
            State::Pick {
                ent,
                candidates,
                too_many,
            } => {
                pending.push(Pending::Pick {
                    param: name.clone(),
                    word: ent.word,
                    candidates,
                    too_many,
                });
                (ent.ty, None, written.to_string())
            }
            State::DidYouMean { ent, suggestion } => {
                pending.push(Pending::DidYouMean {
                    param: name.clone(),
                    word: ent.word,
                    written: written.to_string(),
                    suggestion,
                });
                (ent.ty, None, written.to_string())
            }
        };
        text.push(':');
        text.push_str(&name);
        params.push(Param {
            name,
            ty,
            bound,
            display,
        });
    }
    text.push_str(original.get(at..).ok_or_else(bad_span)?);
    Ok(Draft {
        lang,
        original,
        text,
        params,
        pending,
    })
}

fn step(d: Draft) -> Step {
    if d.pending.is_empty() {
        Step::Ready(d)
    } else {
        Step::Ask(d)
    }
}

// ------------------------------------------------- the public draft ----

fn misfit() -> ShieldError {
    ShieldError::Corrupt("the answer does not fit the question")
}

fn bad_draft() -> ShieldError {
    ShieldError::Corrupt("the draft is not consistent")
}

/// The first parameter-shaped token in `s` (`:p` or `:P`, then an ASCII
/// digit) as (start, end of its digit run). Byte scan: `:`, `p` and digits
/// are ASCII, so they never sit inside a multi-byte character.
fn param_token(s: &str, from: usize) -> Option<(usize, usize)> {
    let b = s.as_bytes();
    let mut i = from;
    while i + 2 < b.len() {
        if b[i] == b':' && (b[i + 1] == b'p' || b[i + 1] == b'P') && b[i + 2].is_ascii_digit() {
            let mut j = i + 2;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            return Some((i, j));
        }
        i += 1;
    }
    None
}

/// The K+1 verbatim segments of `text` around `:p1`..`:pK`, which must each
/// appear exactly once, in order, written exactly so (no `:P1`, no `:p01`).
fn split_text(text: &str, k: usize) -> Result<Vec<&str>, ShieldError> {
    let mut segs = Vec::with_capacity(k + 1);
    let mut last = 0;
    let mut n = 0usize;
    while let Some((i, j)) = param_token(text, last) {
        n += 1;
        let tok = text.get(i..j).ok_or_else(bad_draft)?;
        if n > k || tok != format!(":p{n}") {
            return Err(bad_draft());
        }
        segs.push(text.get(last..i).ok_or_else(bad_draft)?);
        last = j;
    }
    if n != k {
        return Err(bad_draft());
    }
    segs.push(text.get(last..).ok_or_else(bad_draft)?);
    Ok(segs)
}

fn param_index(d: &Draft, name: &str) -> Result<usize, ShieldError> {
    d.params
        .iter()
        .position(|p| p.name == name)
        .ok_or_else(bad_draft)
}

/// The invariants of [`Draft`]; any break is an `Err`.
fn check(d: &Draft) -> Result<(), ShieldError> {
    split_text(&d.text, d.params.len())?;
    for (i, p) in d.params.iter().enumerate() {
        if p.name != format!("p{}", i + 1) {
            return Err(bad_draft());
        }
    }
    let mut asked: Vec<usize> = Vec::new();
    for p in &d.pending {
        match p {
            Pending::Pick { param, .. } | Pending::DidYouMean { param, .. } => {
                let i = param_index(d, param)?;
                if d.params[i].bound.is_some() || asked.contains(&i) {
                    return Err(bad_draft());
                }
                asked.push(i);
            }
            Pending::KeepName { span, name } => {
                if span.0 >= span.1 || d.original.get(span.0..span.1) != Some(name.as_str()) {
                    return Err(bad_draft());
                }
            }
        }
    }
    // Every unbound param waits for an answer.
    if d.params.iter().filter(|p| p.bound.is_none()).count() != asked.len() {
        return Err(bad_draft());
    }
    Ok(())
}

/// The char boundaries `q` of `s` (including `s.len()`) where `seg` starts.
fn starts(s: &str, seg: &str) -> Vec<usize> {
    s.char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(s.len()))
        .filter(|&q| s.get(q..).is_some_and(|t| t.starts_with(seg)))
        .collect()
}

/// Where param `n` (1-based) sits in `original`, given that its text there
/// is `w`: `original` = s0 W1 s1 .. WK sK with each other W non-empty. The
/// one placement that fits, or `Err` when none or several do (fail closed).
/// Every offset is found by matching on `original` itself (S-1).
fn locate(original: &str, segs: &[&str], n: usize, w: &str) -> Result<(usize, usize), ShieldError> {
    let k = segs.len().checked_sub(1).ok_or_else(bad_draft)?;
    if n == 0 || n > k || w.is_empty() || !original.starts_with(segs[0]) {
        return Err(bad_draft());
    }
    // Where W_n can start: after s0 W1 s1 .. W(n-1) s(n-1).
    let mut f: Vec<usize> = vec![segs[0].len()];
    for seg in &segs[1..n] {
        let lo = *f.iter().min().ok_or_else(bad_draft)?;
        f = starts(original, seg)
            .into_iter()
            .filter(|&q| q > lo)
            .map(|q| q + seg.len())
            .collect();
    }
    // Where s_n can start: before W(n+1) s(n+1) .. WK sK, which ends the text.
    let last = original
        .len()
        .checked_sub(segs[k].len())
        .filter(|&p| original.get(p..) == Some(segs[k]))
        .ok_or_else(bad_draft)?;
    let mut r: Vec<usize> = vec![last];
    for seg in segs[n..k].iter().rev() {
        let hi = *r.iter().max().ok_or_else(bad_draft)?;
        r = starts(original, seg)
            .into_iter()
            .filter(|&p| p + seg.len() < hi)
            .collect();
    }
    let mut found = None;
    for p in f {
        let q = p.checked_add(w.len()).ok_or_else(bad_draft)?;
        if original.get(p..q) == Some(w) && r.contains(&q) {
            if found.is_some() {
                return Err(bad_draft());
            }
            found = Some((p, q));
        }
    }
    found.ok_or_else(bad_draft)
}

/// DidYouMean "no": the written name goes back in place of `:pN`, the param
/// is dropped, the later ones are renumbered, and the name waits for the
/// keep-as-text touch (at the front of `pending`).
fn unbind(d: &mut Draft, i: usize, written: String) -> Result<(), ShieldError> {
    let k = d.params.len();
    let n = i + 1;
    let (text, span) = {
        let segs = split_text(&d.text, k)?;
        let span = locate(&d.original, &segs, n, &written)?;
        let mut t = String::with_capacity(d.text.len() + written.len());
        for (j, seg) in segs.iter().enumerate() {
            t.push_str(seg);
            let m = j + 1;
            if m > k {
                break;
            }
            if m == n {
                t.push_str(&written);
            } else {
                let num = if m > n { m - 1 } else { m };
                t.push_str(&format!(":p{num}"));
            }
        }
        (t, span)
    };
    d.text = text;
    d.params.remove(i);
    for (j, p) in d.params.iter_mut().enumerate().skip(i) {
        p.name = format!("p{}", j + 1);
    }
    let rename = |param: &mut String| -> Result<(), ShieldError> {
        let m: usize = param
            .strip_prefix('p')
            .and_then(|x| x.parse().ok())
            .ok_or_else(bad_draft)?;
        if m > n {
            *param = format!("p{}", m - 1);
        }
        Ok(())
    };
    for p in d.pending.iter_mut() {
        match p {
            Pending::Pick { param, .. } | Pending::DidYouMean { param, .. } => rename(param)?,
            Pending::KeepName { .. } => {}
        }
    }
    d.pending.insert(
        0,
        Pending::KeepName {
            span,
            name: written,
        },
    );
    Ok(())
}

/// Answers `draft.pending[0]`, working from the draft's public fields only.
/// An answer of the wrong kind, a pick past the list, or a draft that breaks
/// the invariants of [`Draft`] is an `Err`.
pub fn answer(draft: Draft, a: Answer, lex: &Lexicon) -> Result<Step, ShieldError> {
    let mut d = draft;
    check(&d)?;
    if d.pending.is_empty() {
        return Err(misfit());
    }
    let p0 = d.pending.remove(0);
    match (p0, a) {
        (
            Pending::Pick {
                param,
                word,
                too_many,
                ..
            },
            Answer::Pick(0),
        ) => {
            let i = param_index(&d, &param)?;
            let written = d.params[i].display.clone();
            return Ok(Step::Refuse(if too_many {
                Refusal::TooMany { word }
            } else {
                Refusal::NoMatch { word, written }
            }));
        }
        (
            Pending::Pick {
                param,
                word,
                candidates,
                ..
            },
            Answer::Pick(n),
        ) => {
            let i = param_index(&d, &param)?;
            let c = candidates.get(n - 1).ok_or_else(misfit)?;
            let p = &mut d.params[i];
            p.bound = Some(Bound::Keys(vec![c.key]));
            p.display = entity_display(c, &word);
        }
        (
            Pending::DidYouMean {
                param,
                word,
                written,
                suggestion,
            },
            Answer::DidYouMean(true),
        ) => {
            let i = param_index(&d, &param)?;
            if !matches!(&d.params[i].ty, ParamType::Entity { table, .. } if *table == suggestion.table)
            {
                return Err(bad_draft());
            }
            match lex.resolve(&suggestion.table, &suggestion.display)? {
                (Resolve::One(c), _) => {
                    let p = &mut d.params[i];
                    p.bound = Some(Bound::Keys(vec![c.key]));
                    p.display = entity_display(&c, &word);
                }
                (Resolve::Many(candidates), too_many) => d.pending.insert(
                    0,
                    Pending::Pick {
                        param,
                        word,
                        candidates,
                        too_many,
                    },
                ),
                (Resolve::None, _) => return Ok(Step::Refuse(Refusal::NoMatch { word, written })),
            }
        }
        (Pending::DidYouMean { param, written, .. }, Answer::DidYouMean(false)) => {
            let i = param_index(&d, &param)?;
            unbind(&mut d, i, written)?;
        }
        (Pending::KeepName { .. }, Answer::KeepName(true)) => {}
        (Pending::KeepName { name, .. }, Answer::KeepName(false)) => {
            return Ok(Step::Refuse(Refusal::NameRefused { name }))
        }
        _ => return Err(misfit()),
    }
    check(&d)?;
    Ok(step(d))
}

/// The approved-method match key (plan 45 Task 6): the parameterized text
/// lower-cased, whitespace collapsed, a trailing `?` or `.` dropped; and the
/// parameters' type tags in order.
pub fn template_key(d: &Draft) -> (String, Vec<String>) {
    let lower = d.text.to_lowercase();
    let joined = lower.split_whitespace().collect::<Vec<_>>().join(" ");
    let key = joined
        .trim_end_matches(|c: char| c == '?' || c == '.' || c.is_whitespace())
        .to_string();
    (key, d.params.iter().map(|p| p.ty.tag()).collect())
}

// ------------------------------------------------------------- Debug ----

impl fmt::Debug for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Draft")
            .field("lang", &self.lang)
            .field("original", &"<hidden>")
            .field("text", &"<hidden>")
            .field("params", &self.params)
            .field("pending", &self.pending)
            .finish()
    }
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pending::Pick {
                param,
                word,
                candidates,
                too_many,
            } => f
                .debug_struct("Pick")
                .field("param", param)
                .field("word", word)
                .field("candidates", &candidates.len())
                .field("too_many", too_many)
                .finish(),
            Pending::DidYouMean { param, .. } => f
                .debug_struct("DidYouMean")
                .field("param", param)
                .field("written", &"<hidden>")
                .field("suggestion", &"<hidden>")
                .finish(),
            Pending::KeepName { span, .. } => f
                .debug_struct("KeepName")
                .field("span", span)
                .field("name", &"<hidden>")
                .finish(),
        }
    }
}

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Answer::Pick(n) => write!(f, "Pick({n})"),
            Answer::DidYouMean(b) => write!(f, "DidYouMean({b})"),
            Answer::KeepName(b) => write!(f, "KeepName({b})"),
        }
    }
}

impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::Ready(d) => f.debug_tuple("Ready").field(d).finish(),
            Step::Ask(d) => f.debug_tuple("Ask").field(d).finish(),
            Step::Refuse(r) => f.debug_tuple("Refuse").field(r).finish(),
        }
    }
}

impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NoMatch { word, .. } => f
                .debug_struct("NoMatch")
                .field("word", word)
                .field("written", &"<hidden>")
                .finish(),
            Refusal::BadLiteral { span, why } => f
                .debug_struct("BadLiteral")
                .field("span", span)
                .field("why", why)
                .finish(),
            Refusal::NameRefused { .. } => f
                .debug_struct("NameRefused")
                .field("name", &"<hidden>")
                .finish(),
            Refusal::TooMany { word } => f.debug_struct("TooMany").field("word", word).finish(),
            Refusal::Detector(why) => f.debug_tuple("Detector").field(why).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncovered_parts() {
        let c = [(2, 4), (6, 8)];
        assert_eq!(uncovered(0, 10, &c), vec![(0, 2), (4, 6), (8, 10)]);
        assert_eq!(uncovered(2, 4, &c), vec![]);
        assert_eq!(uncovered(3, 7, &c), vec![(4, 6)]);
        assert_eq!(uncovered(9, 12, &c), vec![(9, 12)]);
    }

    #[test]
    fn trim_keeps_marks_and_offsets() {
        let s = "  , Ze\u{301}lie İ ?";
        let (a, b) = trim(s, 0, s.len()).unwrap().unwrap();
        assert_eq!(&s[a..b], "Ze\u{301}lie İ");
        assert_eq!(trim(s, 0, 3).unwrap(), None);
        assert!(trim(s, 0, 99).is_err());
        assert!(trim("ø", 0, 1).is_err());
    }
}
