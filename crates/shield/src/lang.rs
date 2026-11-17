//! Plan 44: English and Danish language detection, number words and literal
//! parsing (R44-1, R44-2, R44-3). No floating point anywhere: every number is
//! a [`Decimal`]. Errors carry byte ranges and fixed text, never the literal.

use crate::schema::{Decimal, Lang};
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------- language

const DA_WORDS: &[&str] = &[
    "hvad", "hvor", "hvem", "hvilke", "hvilken", "skylder", "kunde", "kunder", "har", "er", "og",
    "ikke", "af", "til", "fra", "med", "over", "under", "end",
];
const EN_WORDS: &[&str] = &[
    "what",
    "where",
    "who",
    "which",
    "does",
    "do",
    "owes",
    "owe",
    "customer",
    "customers",
    "has",
    "is",
    "and",
    "not",
    "of",
    "to",
    "from",
    "with",
    "over",
    "under",
    "than",
];

/// R44-1: Danish when the text holds `æ`, `ø` or `å`, or has at least two
/// Danish function words and more of them than English ones; else English.
pub fn detect_lang(text: &str) -> Lang {
    if text
        .chars()
        .any(|c| matches!(c, 'æ' | 'ø' | 'å' | 'Æ' | 'Ø' | 'Å'))
    {
        return Lang::Da;
    }
    let (mut da, mut en) = (0usize, 0usize);
    for w in text
        .split(|c: char| !c.is_alphabetic())
        .filter(|w| !w.is_empty())
    {
        let l = w.to_lowercase();
        if DA_WORDS.contains(&l.as_str()) {
            da += 1;
        }
        if EN_WORDS.contains(&l.as_str()) {
            en += 1;
        }
    }
    if da >= 2 && da > en {
        Lang::Da
    } else {
        Lang::En
    }
}

// ------------------------------------------------------------------- types

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    Amount {
        value: Decimal,
        currency: Option<String>,
    },
    Integer(i64),
    Percent(Decimal),
    /// ISO `YYYY-MM-DD`.
    Date(String),
    DateRange {
        from: String,
        to_exclusive: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralSpan {
    pub start: usize,
    pub end: usize,
    pub lit: Literal,
}

/// A literal that does not parse as its type. Names the byte range and a
/// fixed reason; never the text itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a number or date in the question cannot be read (bytes {start}..{end}: {why})")]
pub struct LiteralError {
    pub start: usize,
    pub end: usize,
    pub why: &'static str,
}

fn lit_err(start: usize, end: usize, why: &'static str) -> LiteralError {
    LiteralError { start, end, why }
}

// ------------------------------------------------------------ small helpers

fn dec_int(n: i128) -> Decimal {
    Decimal { units: n, scale: 0 }
}

/// `d * 10^p`, exact; `None` on overflow.
fn mul_pow10(d: Decimal, p: u8) -> Option<Decimal> {
    if d.scale >= p {
        return Some(Decimal {
            units: d.units,
            scale: d.scale - p,
        });
    }
    let k = u32::from(p - d.scale);
    let units = d.units.checked_mul(10i128.checked_pow(k)?)?;
    Some(Decimal { units, scale: 0 })
}

fn prev_char(text: &str, i: usize) -> Option<char> {
    text.get(..i)?.chars().next_back()
}

fn word_start(text: &str, i: usize) -> bool {
    prev_char(text, i).is_none_or(|c| !c.is_alphanumeric())
}

fn digits_at(b: &[u8], i: usize) -> usize {
    b.get(i..)
        .map_or(0, |s| s.iter().take_while(|c| c.is_ascii_digit()).count())
}

/// Width in bytes of a whitespace char usable between number parts, or 0.
fn ws_width(text: &str, i: usize) -> usize {
    match text.get(i..).and_then(|t| t.chars().next()) {
        Some(c @ (' ' | '\t' | '\u{a0}' | '\u{202f}')) => c.len_utf8(),
        _ => 0,
    }
}

fn skip_ws(text: &str, mut i: usize) -> usize {
    loop {
        let w = ws_width(text, i);
        if w == 0 {
            return i;
        }
        i += w;
    }
}

/// The maximal alphabetic run at `i`.
fn word_at(text: &str, i: usize) -> Option<(usize, usize)> {
    let rest = text.get(i..)?;
    let n: usize = rest
        .chars()
        .take_while(|c| c.is_alphabetic())
        .map(char::len_utf8)
        .sum();
    (n > 0).then_some((i, i + n))
}

fn parse_u32(s: &str) -> Option<u32> {
    s.parse().ok()
}

// -------------------------------------------------------------- number words

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Zero,
    Unit(i128),
    Teen(i128),
    Tens(i128),
    /// Danish `enogtyve` and the like: a finished 21..=99.
    Comp(i128),
    Hundred,
    Scale(i128),
    Dozen,
    And,
    Ord(i128),
    Article,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    Start,
    Art,
    Unit,
    Teen,
    Tens,
    Comp,
    Hundred,
    Scale,
    And,
}

/// The number words of one language (R44-3).
pub struct NumberWords {
    lang: Lang,
}

static EN: NumberWords = NumberWords { lang: Lang::En };
static DA: NumberWords = NumberWords { lang: Lang::Da };

pub fn number_words(lang: Lang) -> &'static NumberWords {
    match lang {
        Lang::En => &EN,
        Lang::Da => &DA,
    }
}

impl NumberWords {
    fn lex(&self, w: &str) -> Option<Tok> {
        match self.lang {
            Lang::En => lex_en(w),
            Lang::Da => lex_da(w),
        }
    }

    /// Parse a number written in words starting at byte `at` (which must be
    /// the start of a word). Returns the end byte and the value.
    pub fn parse_at(&self, text: &str, at: usize) -> Option<(usize, Decimal)> {
        if at >= text.len() || !text.is_char_boundary(at) || !word_start(text, at) {
            return None;
        }
        let mut chunk: i128 = 0;
        let mut total: i128 = 0;
        let mut last = St::Start;
        let mut last_scale = i128::MAX;
        let mut result: Option<(usize, i128)> = None;
        let mut pos = at;
        while let Some((ws, we)) = word_at(text, pos) {
            let w = text[ws..we].to_lowercase();
            let Some(tok) = self.lex(&w) else { break };
            // `commit` is true when this token completes a valid number.
            let mut commit = true;
            let mut done = false;
            match tok {
                Tok::Article => {
                    if last != St::Start {
                        break;
                    }
                    let next = sep_then_word(text, we)
                        .and_then(|(s, e)| self.lex(&text[s..e].to_lowercase()));
                    if !matches!(next, Some(Tok::Hundred | Tok::Scale(_) | Tok::Dozen)) {
                        break;
                    }
                    chunk = 1;
                    last = St::Art;
                    commit = false;
                }
                Tok::Zero => {
                    if last != St::Start {
                        break;
                    }
                    done = true;
                }
                Tok::Unit(u) => {
                    if !matches!(
                        last,
                        St::Start | St::Hundred | St::Scale | St::And | St::Tens
                    ) {
                        break;
                    }
                    chunk += u;
                    last = St::Unit;
                }
                Tok::Teen(t) => {
                    if !matches!(last, St::Start | St::Hundred | St::Scale | St::And) {
                        break;
                    }
                    chunk += t;
                    last = St::Teen;
                }
                Tok::Tens(t) => {
                    if !matches!(last, St::Start | St::Hundred | St::Scale | St::And) {
                        break;
                    }
                    chunk += t;
                    last = St::Tens;
                }
                Tok::Comp(t) => {
                    if !matches!(last, St::Start | St::Hundred | St::Scale | St::And) {
                        break;
                    }
                    chunk += t;
                    last = St::Comp;
                }
                Tok::Hundred => {
                    if !matches!(
                        last,
                        St::Start | St::Art | St::Unit | St::Teen | St::Tens | St::Comp
                    ) || chunk >= 100
                    {
                        break;
                    }
                    if last == St::Start {
                        chunk = 1;
                    }
                    chunk *= 100;
                    last = St::Hundred;
                }
                Tok::Scale(s) => {
                    if !matches!(
                        last,
                        St::Start
                            | St::Art
                            | St::Unit
                            | St::Teen
                            | St::Tens
                            | St::Comp
                            | St::Hundred
                    ) || s >= last_scale
                    {
                        break;
                    }
                    if last == St::Start {
                        chunk = 1;
                    }
                    let Some(add) = chunk.checked_mul(s).and_then(|v| total.checked_add(v)) else {
                        break;
                    };
                    total = add;
                    chunk = 0;
                    last_scale = s;
                    last = St::Scale;
                }
                Tok::Dozen => {
                    if !matches!(
                        last,
                        St::Start | St::Art | St::Unit | St::Teen | St::Tens | St::Comp
                    ) || total != 0
                    {
                        break;
                    }
                    if last == St::Start {
                        chunk = 1;
                    }
                    chunk *= 12;
                    done = true;
                }
                Tok::And => {
                    if !matches!(last, St::Hundred | St::Scale) {
                        break;
                    }
                    last = St::And;
                    commit = false;
                }
                Tok::Ord(v) => {
                    let ok = match last {
                        St::Start => true,
                        St::Tens => v < 10,
                        St::Hundred | St::Scale | St::And => v < 100,
                        _ => false,
                    };
                    if !ok {
                        break;
                    }
                    chunk += v;
                    done = true;
                }
            }
            if commit {
                // A digit glued to the word ("one2") is not a number word.
                if text
                    .get(we..)
                    .unwrap_or("")
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
                {
                    break;
                }
                let Some(v) = total.checked_add(chunk) else {
                    break;
                };
                result = Some((we, v));
            }
            if done {
                break;
            }
            match sep_then_word(text, we) {
                Some((s, _)) => pos = s,
                None => break,
            }
        }
        result.map(|(end, v)| (end, dec_int(v)))
    }

    /// True when the whole token is a number word or number-word phrase.
    pub fn is_number_word(&self, token: &str) -> bool {
        !token.is_empty()
            && self
                .parse_at(token, 0)
                .is_some_and(|(e, _)| e == token.len())
    }
}

/// After the word ending at `we`: one space or hyphen, then a word.
fn sep_then_word(text: &str, we: usize) -> Option<(usize, usize)> {
    match text.as_bytes().get(we) {
        Some(b' ' | b'-') => word_at(text, we + 1),
        _ => None,
    }
}

fn lex_en(w: &str) -> Option<Tok> {
    let t = match w {
        "a" | "an" => Tok::Article,
        "zero" => Tok::Zero,
        "one" => Tok::Unit(1),
        "two" => Tok::Unit(2),
        "three" => Tok::Unit(3),
        "four" => Tok::Unit(4),
        "five" => Tok::Unit(5),
        "six" => Tok::Unit(6),
        "seven" => Tok::Unit(7),
        "eight" => Tok::Unit(8),
        "nine" => Tok::Unit(9),
        "ten" => Tok::Teen(10),
        "eleven" => Tok::Teen(11),
        "twelve" => Tok::Teen(12),
        "thirteen" => Tok::Teen(13),
        "fourteen" => Tok::Teen(14),
        "fifteen" => Tok::Teen(15),
        "sixteen" => Tok::Teen(16),
        "seventeen" => Tok::Teen(17),
        "eighteen" => Tok::Teen(18),
        "nineteen" => Tok::Teen(19),
        "twenty" => Tok::Tens(20),
        "thirty" => Tok::Tens(30),
        "forty" => Tok::Tens(40),
        "fifty" => Tok::Tens(50),
        "sixty" => Tok::Tens(60),
        "seventy" => Tok::Tens(70),
        "eighty" => Tok::Tens(80),
        "ninety" => Tok::Tens(90),
        "hundred" => Tok::Hundred,
        "thousand" => Tok::Scale(1_000),
        "million" => Tok::Scale(1_000_000),
        "billion" => Tok::Scale(1_000_000_000),
        "dozen" => Tok::Dozen,
        "and" => Tok::And,
        "first" => Tok::Ord(1),
        "second" => Tok::Ord(2),
        "third" => Tok::Ord(3),
        "fourth" => Tok::Ord(4),
        "fifth" => Tok::Ord(5),
        "sixth" => Tok::Ord(6),
        "seventh" => Tok::Ord(7),
        "eighth" => Tok::Ord(8),
        "ninth" => Tok::Ord(9),
        "tenth" => Tok::Ord(10),
        "eleventh" => Tok::Ord(11),
        "twelfth" => Tok::Ord(12),
        "twentieth" => Tok::Ord(20),
        "hundredth" => Tok::Ord(100),
        _ => return None,
    };
    Some(t)
}

fn da_unit(w: &str) -> Option<i128> {
    Some(match w {
        "en" | "én" => 1,
        "to" => 2,
        "tre" => 3,
        "fire" => 4,
        "fem" => 5,
        "seks" => 6,
        "syv" => 7,
        "otte" => 8,
        "ni" => 9,
        _ => return None,
    })
}

fn da_tens(w: &str) -> Option<i128> {
    Some(match w {
        "tyve" => 20,
        "tredive" => 30,
        "fyrre" => 40,
        "halvtreds" => 50,
        "tres" => 60,
        "halvfjerds" => 70,
        "firs" => 80,
        "halvfems" => 90,
        _ => return None,
    })
}

fn lex_da(w: &str) -> Option<Tok> {
    let t = match w {
        // `en`/`et` are articles: only a multiplier prefix (`en million`).
        "en" | "et" => Tok::Article,
        "én" | "ét" => Tok::Unit(1),
        "nul" => Tok::Zero,
        "to" => Tok::Unit(2),
        "tre" => Tok::Unit(3),
        "fire" => Tok::Unit(4),
        "fem" => Tok::Unit(5),
        "seks" => Tok::Unit(6),
        "syv" => Tok::Unit(7),
        "otte" => Tok::Unit(8),
        "ni" => Tok::Unit(9),
        "ti" => Tok::Teen(10),
        "elleve" => Tok::Teen(11),
        "tolv" => Tok::Teen(12),
        "tretten" => Tok::Teen(13),
        "fjorten" => Tok::Teen(14),
        "femten" => Tok::Teen(15),
        "seksten" => Tok::Teen(16),
        "sytten" => Tok::Teen(17),
        "atten" => Tok::Teen(18),
        "nitten" => Tok::Teen(19),
        "hundrede" => Tok::Hundred,
        "tusind" | "tusinde" => Tok::Scale(1_000),
        "million" | "millioner" => Tok::Scale(1_000_000),
        "milliard" | "milliarder" => Tok::Scale(1_000_000_000),
        "og" => Tok::And,
        "første" => Tok::Ord(1),
        "anden" | "andet" => Tok::Ord(2),
        "tredje" => Tok::Ord(3),
        "fjerde" => Tok::Ord(4),
        "femte" => Tok::Ord(5),
        "sjette" => Tok::Ord(6),
        "syvende" => Tok::Ord(7),
        "ottende" => Tok::Ord(8),
        "niende" => Tok::Ord(9),
        "tiende" => Tok::Ord(10),
        "ellevte" => Tok::Ord(11),
        "tolvte" => Tok::Ord(12),
        _ => {
            if let Some(t) = da_tens(w) {
                return Some(Tok::Tens(t));
            }
            // `enogtyve` = unit + "og" + tens.
            for u in [
                "en", "to", "tre", "fire", "fem", "seks", "syv", "otte", "ni",
            ] {
                if let Some(rest) = w.strip_prefix(u).and_then(|r| r.strip_prefix("og")) {
                    if let (Some(un), Some(te)) = (da_unit(u), da_tens(rest)) {
                        return Some(Tok::Comp(un + te));
                    }
                }
            }
            return None;
        }
    };
    Some(t)
}

// ------------------------------------------------------------ digit numbers

/// One numeric token in digits starting at `i`: `1,234.5`, `1.234,5`,
/// `18 420,00`, `1 234`. `Ok((end, value, grouped))`; `Err((start, end))` for
/// a run whose separators make no valid reading.
fn scan_digits(text: &str, i: usize, lang: Lang) -> Result<(usize, Decimal, bool), (usize, usize)> {
    let b = text.as_bytes();
    // Collect the run: groups of digits joined by separators.
    let mut int_groups: Vec<&str> = Vec::new(); // digit groups joined by space
    let mut seps: Vec<(u8, &str)> = Vec::new(); // '.' or ',' and the digits after
    let mut pos = i;
    let n0 = digits_at(b, pos);
    let mut cur = &text[pos..pos + n0];
    pos += n0;
    let mut spaced = false;
    loop {
        // space group: only before any `.`/`,`, previous group <= 3 digits,
        // next group exactly three digits
        if seps.is_empty() && cur.len() <= 3 {
            let w = ws_width(text, pos);
            if w > 0 {
                let n = digits_at(b, pos + w);
                if n == 3 {
                    int_groups.push(cur);
                    cur = &text[pos + w..pos + w + 3];
                    pos += w + 3;
                    spaced = true;
                    continue;
                }
            }
        }
        if matches!(b.get(pos), Some(b'.' | b',')) {
            let n = digits_at(b, pos + 1);
            if n > 0 {
                if seps.is_empty() {
                    int_groups.push(cur);
                } else if let Some(l) = seps.last_mut() {
                    l.1 = cur;
                }
                let s = b[pos];
                cur = &text[pos + 1..pos + 1 + n];
                pos += 1 + n;
                seps.push((s, cur));
                continue;
            }
        }
        break;
    }
    if seps.is_empty() {
        int_groups.push(cur);
    }
    let end = pos;
    let bad = Err((i, end));
    let grouping_ok = |groups: &[&str]| -> bool {
        !groups.is_empty() && groups[0].len() <= 3 && groups[1..].iter().all(|g| g.len() == 3)
    };
    // Resolve to (integer digits, fraction digits, grouped).
    let (int_digits, frac, grouped): (String, &str, bool) = if spaced {
        // space-grouped integer part, optionally one decimal separator
        let ip: String = int_groups.concat();
        match seps.as_slice() {
            [] => (ip, "", true),
            [(_, f)] => (ip, f, true),
            _ => return bad,
        }
    } else {
        match seps.as_slice() {
            [] => (int_groups.concat(), "", false),
            [(s, f)] => {
                let first = int_groups[0];
                let lang_dec = if lang == Lang::En { b'.' } else { b',' };
                let group_ok = first.len() <= 3 && f.len() == 3;
                if *s == lang_dec || !group_ok {
                    (first.to_string(), f, false)
                } else {
                    (format!("{first}{f}"), "", true)
                }
            }
            many => {
                let all_same = many.iter().all(|(s, _)| *s == many[0].0);
                if all_same {
                    // repeated: group separator
                    let mut g = vec![int_groups[0]];
                    g.extend(many.iter().map(|(_, d)| *d));
                    if !grouping_ok(&g) {
                        return bad;
                    }
                    (g.concat(), "", true)
                } else {
                    // mixed: the last is the decimal point, once
                    let (ds, df) = many[many.len() - 1];
                    let gs = many[0].0;
                    if ds == gs || many[..many.len() - 1].iter().any(|(s, _)| *s != gs) {
                        return bad;
                    }
                    let mut g = vec![int_groups[0]];
                    g.extend(many[..many.len() - 1].iter().map(|(_, d)| *d));
                    if !grouping_ok(&g) {
                        return bad;
                    }
                    (g.concat(), df, true)
                }
            }
        }
    };
    let plain = if frac.is_empty() {
        int_digits
    } else {
        format!("{int_digits}.{frac}")
    };
    match Decimal::parse_plain(&plain) {
        Some(d) => Ok((end, d, grouped)),
        None => bad,
    }
}

fn saturating_digit_value(s: &str) -> Decimal {
    Decimal::parse_plain(s).unwrap_or(dec_int(i128::MAX))
}

/// Suffix attached to a number: `k`/`m` multiplier, ordinal `st/nd/rd/th`.
fn attached_suffix(text: &str, end: usize) -> Option<(usize, Suffix)> {
    // Decide on the original bytes: no case-converted copy, no foreign offsets.
    let rest = text.get(end..)?;
    let after_ok = |n: usize| {
        rest.get(n..)
            .is_some_and(|r| r.chars().next().is_none_or(|c| !c.is_alphanumeric()))
    };
    match rest.as_bytes().first() {
        Some(b'k' | b'K') if after_ok(1) => return Some((end + 1, Suffix::Pow(3))),
        Some(b'm' | b'M') if after_ok(1) => return Some((end + 1, Suffix::Pow(6))),
        _ => {}
    }
    for s in ["st", "nd", "rd", "th"] {
        if rest.get(..2).is_some_and(|h| h.eq_ignore_ascii_case(s)) && after_ok(2) {
            return Some((end + 2, Suffix::Ordinal));
        }
    }
    None
}

#[derive(Clone, Copy)]
enum Suffix {
    Pow(u8),
    Ordinal,
}

// ---------------------------------------------------------------- currency

fn code_for(word: &str) -> Option<&'static str> {
    Some(match word {
        "dkk" => "DKK",
        "nok" => "NOK",
        "sek" => "SEK",
        "eur" | "euro" | "euros" => "EUR",
        "usd" | "dollar" | "dollars" => "USD",
        "gbp" => "GBP",
        "kr" | "kroner" => "kr",
        _ => return None,
    })
}

/// A currency before a number: `kr. 500`, `$500`, `USD 500`. Returns the
/// index of the number's first digit and the currency.
fn currency_prefix(text: &str, i: usize) -> Option<(usize, &'static str)> {
    let c = text.get(i..).and_then(|t| t.chars().next())?;
    let (after, cur) = match c {
        '$' => (i + 1, "USD"),
        '€' => (i + c.len_utf8(), "EUR"),
        '£' => (i + c.len_utf8(), "GBP"),
        _ => {
            let (ws, we) = word_at(text, i)?;
            if !word_start(text, i) {
                return None;
            }
            let w = text[ws..we].to_lowercase();
            if !matches!(
                w.as_str(),
                "kr" | "dkk" | "nok" | "sek" | "eur" | "usd" | "gbp"
            ) {
                return None;
            }
            let mut e = we;
            if w == "kr" && text.as_bytes().get(e) == Some(&b'.') {
                e += 1;
            }
            (e, code_for(&w)?)
        }
    };
    let p = skip_ws(text, after);
    (p < text.len() && text.as_bytes()[p].is_ascii_digit()).then_some((p, cur))
}

/// A currency after a number: `500 NOK`, `500 kr.`, `500,-`.
fn currency_suffix(text: &str, end: usize) -> Option<(usize, &'static str)> {
    if text
        .get(end..)
        .is_some_and(|r| r.starts_with(",-") || r.starts_with(".-"))
    {
        return Some((end + 2, "kr"));
    }
    let p = skip_ws(text, end);
    let (ws, we) = word_at(text, p)?;
    let w = text[ws..we].to_lowercase();
    let cur = code_for(&w)?;
    let mut e = we;
    if w == "kr" && text.as_bytes().get(e) == Some(&b'.') {
        e += 1;
    }
    Some((e, cur))
}

fn percent_suffix(text: &str, end: usize) -> Option<usize> {
    let p = skip_ws(text, end);
    if text.as_bytes().get(p) == Some(&b'%') {
        return Some(p + 1);
    }
    if p > end {
        let (ws, we) = word_at(text, p)?;
        if matches!(
            text[ws..we].to_lowercase().as_str(),
            "procent" | "percent" | "pct"
        ) {
            return Some(we);
        }
    }
    None
}

// ------------------------------------------------------------------- dates

const MONTHS: &[(&str, u32)] = &[
    ("january", 1),
    ("januar", 1),
    ("february", 2),
    ("februar", 2),
    ("march", 3),
    ("marts", 3),
    ("april", 4),
    ("may", 5),
    ("maj", 5),
    ("june", 6),
    ("juni", 6),
    ("july", 7),
    ("juli", 7),
    ("august", 8),
    ("september", 9),
    ("october", 10),
    ("oktober", 10),
    ("november", 11),
    ("december", 12),
];
const MONTH_ABBR: &[(&str, u32)] = &[
    ("jan", 1),
    ("feb", 2),
    ("mar", 3),
    ("apr", 4),
    ("jun", 6),
    ("jul", 7),
    ("aug", 8),
    ("sep", 9),
    ("sept", 9),
    ("oct", 10),
    ("okt", 10),
    ("nov", 11),
    ("dec", 12),
];

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

fn valid_ymd(y: u32, m: u32, d: u32) -> bool {
    (1000..=9998).contains(&y) && (1..=12).contains(&m) && d >= 1 && d <= days_in_month(y, m)
}

fn iso(y: u32, m: u32, d: u32) -> String {
    format!("{y:04}-{m:02}-{d:02}")
}

/// First day of the month after (y, m), plus `months` extra months.
fn month_range(y: u32, m: u32, months: u32) -> Literal {
    let idx = m - 1 + months;
    Literal::DateRange {
        from: iso(y, m, 1),
        to_exclusive: iso(y + idx / 12, idx % 12 + 1, 1),
    }
}

fn month_at(text: &str, i: usize) -> Option<(usize, u32)> {
    let (ws, we) = word_at(text, i)?;
    let w = text[ws..we].to_lowercase();
    if let Some((_, m)) = MONTHS.iter().find(|(n, _)| *n == w) {
        return Some((we, *m));
    }
    let (_, m) = MONTH_ABBR.iter().find(|(n, _)| *n == w)?;
    let end = if text.as_bytes().get(we) == Some(&b'.') {
        we + 1
    } else {
        we
    };
    Some((end, *m))
}

/// A four-digit year at `i` (not part of a longer digit run).
fn year_at(text: &str, i: usize) -> Option<(usize, u32)> {
    let b = text.as_bytes();
    if digits_at(b, i) != 4 || (i > 0 && b[i - 1].is_ascii_digit()) {
        return None;
    }
    Some((i + 4, parse_u32(&text[i..i + 4])?))
}

/// A day or ordinal at `i`: digits (1-2) with optional `.`/`st`/`nd`/`rd`/`th`,
/// or a number word. Returns end and value.
fn ordinal_token(text: &str, i: usize, lang: Lang) -> Option<(usize, u32)> {
    let b = text.as_bytes();
    if i < text.len() && b[i].is_ascii_digit() {
        let n = digits_at(b, i);
        if n > 2 {
            return None;
        }
        let v = parse_u32(&text[i..i + n])?;
        let mut e = i + n;
        if b.get(e) == Some(&b'.') {
            e += 1;
        } else if let Some((e2, Suffix::Ordinal)) = attached_suffix(text, e) {
            e = e2;
        }
        return Some((e, v));
    }
    let (e, d) = number_words(lang).parse_at(text, i)?;
    let v = u32::try_from(d.units).ok()?;
    Some((e, v))
}

/// Try every date shape at `i`. `Ok(None)`: no date here. `Err`: the shape
/// is a date but its values are impossible.
fn date_at(text: &str, i: usize, lang: Lang) -> Result<Option<(usize, Literal)>, LiteralError> {
    let b = text.as_bytes();
    let c = b[i];
    if c.is_ascii_digit() {
        if i > 0
            && (b[i - 1].is_ascii_digit() || prev_char(text, i).is_some_and(char::is_alphabetic))
        {
            return Ok(None);
        }
        let n = digits_at(b, i);
        // ISO
        if n == 4
            && b.get(i + 4) == Some(&b'-')
            && digits_at(b, i + 5) == 2
            && b.get(i + 7) == Some(&b'-')
            && digits_at(b, i + 8) == 2
            && digits_at(b, i + 8) == 2
        {
            let end = i + 10;
            let (y, m, d) = (
                parse_u32(&text[i..i + 4]),
                parse_u32(&text[i + 5..i + 7]),
                parse_u32(&text[i + 8..i + 10]),
            );
            return match (y, m, d) {
                (Some(y), Some(m), Some(d)) if valid_ymd(y, m, d) => {
                    Ok(Some((end, Literal::Date(iso(y, m, d)))))
                }
                _ => Err(lit_err(i, end, "not a calendar date")),
            };
        }
        // D.M.YYYY
        if (1..=2).contains(&n) && b.get(i + n) == Some(&b'.') {
            let m0 = i + n + 1;
            let nm = digits_at(b, m0);
            if (1..=2).contains(&nm) && b.get(m0 + nm) == Some(&b'.') {
                if let Some((end, y)) = year_at(text, m0 + nm + 1) {
                    let d = parse_u32(&text[i..i + n]);
                    let m = parse_u32(&text[m0..m0 + nm]);
                    return match (d, m) {
                        (Some(d), Some(m)) if valid_ymd(y, m, d) => {
                            Ok(Some((end, Literal::Date(iso(y, m, d)))))
                        }
                        _ => Err(lit_err(i, end, "not a calendar date")),
                    };
                }
            }
        }
    } else if !word_start(text, i) {
        return Ok(None);
    }

    // Q3 2026
    if (c == b'Q' || c == b'q') && b.get(i + 1).is_some_and(|d| (b'1'..=b'4').contains(d)) {
        if !b.get(i + 2).is_some_and(u8::is_ascii_digit) {
            let q = u32::from(b[i + 1] - b'0');
            let mut p = i + 2;
            if matches!(b.get(p), Some(b'/' | b'-')) {
                p += 1;
            }
            p = skip_ws(text, p);
            if let Some((end, y)) = year_at(text, p) {
                if p > i + 2 {
                    return Ok(Some((end, quarter(y, q, i, end)?)));
                }
            }
        }
        return Ok(None);
    }

    // Month first: `July 2026`, `July 1, 2026`.
    if c.is_ascii_alphabetic() {
        if let Some((me, m)) = month_at(text, i) {
            let p = skip_ws(text, me);
            if p > me {
                if let Some((end, y)) = year_at(text, p) {
                    if valid_ymd(y, m, 1) {
                        return Ok(Some((end, month_range(y, m, 1))));
                    }
                    return Err(lit_err(i, end, "not a calendar date"));
                }
                let n = digits_at(b, p);
                if (1..=2).contains(&n) {
                    if let Some((de, d)) = ordinal_token(text, p, lang) {
                        let mut q = de;
                        if b.get(q) == Some(&b',') {
                            q += 1;
                        }
                        let q2 = skip_ws(text, q);
                        if q2 > de || q > de {
                            if let Some((end, y)) = year_at(text, q2) {
                                return if valid_ymd(y, m, d) {
                                    Ok(Some((end, Literal::Date(iso(y, m, d)))))
                                } else {
                                    Err(lit_err(i, end, "not a calendar date"))
                                };
                            }
                        }
                    }
                }
            }
            return Ok(None);
        }
    }

    // Day first (`1 July 2026`, `1. juli 2026`, `first of July 2026`) or
    // quarter by ordinal (`3. kvartal 2026`, `third quarter 2026`).
    let Some((de, d)) = ordinal_token(text, i, lang) else {
        return Ok(None);
    };
    let mut p = skip_ws(text, de);
    if p == de && b.get(de - 1) != Some(&b'.') {
        return Ok(None);
    }
    if let Some((ws, we)) = word_at(text, p) {
        let w = text[ws..we].to_lowercase();
        if w == "of" {
            p = skip_ws(text, we);
        } else if w == "quarter" || w == "kvartal" {
            let p2 = skip_ws(text, we);
            if p2 > we {
                if let Some((end, y)) = year_at(text, p2) {
                    return Ok(Some((end, quarter(y, d, i, end)?)));
                }
            }
            return Ok(None);
        }
    }
    if let Some((me, m)) = month_at(text, p) {
        let p2 = skip_ws(text, me);
        let q = if text.as_bytes().get(me) == Some(&b',') {
            skip_ws(text, me + 1)
        } else {
            p2
        };
        if let Some((end, y)) = year_at(text, q) {
            if q > me {
                return if valid_ymd(y, m, d) {
                    Ok(Some((end, Literal::Date(iso(y, m, d)))))
                } else {
                    Err(lit_err(i, end, "not a calendar date"))
                };
            }
        }
    }
    Ok(None)
}

fn quarter(y: u32, q: u32, start: usize, end: usize) -> Result<Literal, LiteralError> {
    if !(1..=4).contains(&q) || !(1000..=9998).contains(&y) {
        return Err(lit_err(start, end, "not a quarter"));
    }
    Ok(month_range(y, (q - 1) * 3 + 1, 3))
}

fn range_from(lit: &Literal) -> Option<String> {
    match lit {
        Literal::Date(d) => Some(d.clone()),
        Literal::DateRange { from, .. } => Some(from.clone()),
        _ => None,
    }
}

/// Dates in the text. A date range (`Q3 2026`, `July 2026`) reports its first
/// day. Impossible dates are skipped here (`find_literals` refuses them).
pub fn find_dates(text: &str, lang: Lang) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        if !text.is_char_boundary(i) {
            i += 1;
            continue;
        }
        if let Ok(Some((end, lit))) = date_at(text, i, lang) {
            if let Some(d) = range_from(&lit) {
                out.push((i, end, d));
                i = end;
                continue;
            }
        }
        i += text
            .get(i..)
            .and_then(|t| t.chars().next())
            .map_or(1, char::len_utf8);
    }
    out
}

// ---------------------------------------------------------------- literals

fn int_literal(d: Decimal) -> Option<i64> {
    if d.scale != 0 {
        return None;
    }
    i64::try_from(d.units).ok()
}

/// A number that starts with a digit (after an optional currency prefix).
fn digit_literal(
    text: &str,
    i: usize,
    lang: Lang,
    prefix_cur: Option<&'static str>,
    span_start: usize,
) -> Result<(usize, Literal), LiteralError> {
    let (end, mut value, grouped) =
        scan_digits(text, i, lang).map_err(|(s, e)| lit_err(s, e, "bad digit grouping"))?;
    let digits_len = end - i;
    let mut end = end;
    let mut currency: Option<&'static str> = prefix_cur;
    let mut scaled = false;
    let mut ordinal = false;
    match attached_suffix(text, end) {
        Some((e, Suffix::Pow(p))) => {
            value =
                mul_pow10(value, p).ok_or_else(|| lit_err(span_start, e, "number too large"))?;
            end = e;
            scaled = true;
        }
        Some((e, Suffix::Ordinal)) => {
            end = e;
            ordinal = true;
        }
        None => {}
    }
    if !ordinal {
        if prefix_cur.is_none() && !scaled {
            if let Some(e) = percent_suffix(text, end) {
                return Ok((e, Literal::Percent(value)));
            }
        }
        if prefix_cur.is_none() {
            if let Some((e, cur)) = currency_suffix(text, end) {
                end = e;
                currency = Some(cur);
            }
        }
    }
    let plain_int = !grouped && !scaled && currency.is_none() && value.scale == 0;
    if plain_int {
        // a bare four-digit year is a year range
        if !ordinal
            && digits_len == 4
            && (1900..=2100).contains(&value.units)
            && !text
                .get(..span_start)
                .unwrap_or("")
                .chars()
                .next_back()
                .is_some_and(|c| c == '-' || c == '.')
        {
            if let Ok(y) = u32::try_from(value.units) {
                return Ok((end, month_range(y, 1, 12)));
            }
        }
        let n =
            int_literal(value).ok_or_else(|| lit_err(span_start, end, "integer out of range"))?;
        return Ok((end, Literal::Integer(n)));
    }
    Ok((
        end,
        Literal::Amount {
            value,
            currency: currency.map(str::to_string),
        },
    ))
}

/// Number words as a literal, with an optional currency after
/// (`fem hundrede kroner`).
fn word_literal(text: &str, i: usize, lang: Lang) -> Option<(usize, Literal)> {
    let (end, value) = number_words(lang).parse_at(text, i)?;
    if let Some(e) = percent_suffix(text, end) {
        return Some((e, Literal::Percent(value)));
    }
    if let Some((e, cur)) = currency_suffix(text, end) {
        return Some((
            e,
            Literal::Amount {
                value,
                currency: Some(cur.to_string()),
            },
        ));
    }
    let big = value.units >= 1000;
    if big || int_literal(value).is_none() {
        return Some((
            end,
            Literal::Amount {
                value,
                currency: None,
            },
        ));
    }
    Some((end, Literal::Integer(int_literal(value)?)))
}

/// R44-2: every literal in the question, in order of appearance, each with
/// its byte span. A literal that does not parse refuses the question.
pub fn find_literals(text: &str, lang: Lang) -> Result<Vec<LiteralSpan>, LiteralError> {
    // Fail closed: a digit this parser cannot read is never passed through.
    if let Some(&(st, en)) = non_ascii_numeric_runs(text).first() {
        return Err(lit_err(st, en, "non-ASCII digit"));
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let Some(c) = text.get(i..).and_then(|t| t.chars().next()) else {
            break;
        };
        let w = c.len_utf8();
        let starts_word = c.is_alphabetic() && word_start(text, i);
        if c.is_alphabetic() && !starts_word {
            i += w;
            continue;
        }
        if c.is_ascii_digit() || starts_word {
            if let Some((end, lit)) = date_at(text, i, lang)? {
                out.push(LiteralSpan { start: i, end, lit });
                i = end;
                continue;
            }
        }
        if let Some((p, cur)) = (c == '$' || c == '€' || c == '£' || starts_word)
            .then(|| currency_prefix(text, i))
            .flatten()
        {
            let (end, lit) = digit_literal(text, p, lang, Some(cur), i)?;
            out.push(LiteralSpan { start: i, end, lit });
            i = end;
            continue;
        }
        if c.is_ascii_digit() {
            let (end, lit) = digit_literal(text, i, lang, None, i)?;
            out.push(LiteralSpan { start: i, end, lit });
            i = end;
            continue;
        }
        if starts_word {
            if let Some((end, lit)) = word_literal(text, i, lang) {
                out.push(LiteralSpan { start: i, end, lit });
                i = end;
                continue;
            }
            // skip the whole word
            i = word_at(text, i).map_or(i + w, |(_, e)| e);
            continue;
        }
        i += w;
    }
    Ok(out)
}

// ----------------------------------------------------------------- numbers

/// Every number in the text: digits (with grouping), words, percents (the
/// span includes `%`), `15k`-style shorthand and English ordinals (`3rd`).
/// A digit run that has no valid reading is reported group by group, so a
/// scan never misses a digit.
pub fn find_numbers(text: &str, lang: Lang) -> Vec<(usize, usize, Decimal)> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < text.len() {
        let Some(c) = text.get(i..).and_then(|t| t.chars().next()) else {
            break;
        };
        let w = c.len_utf8();
        if c.is_ascii_digit() {
            match scan_digits(text, i, lang) {
                Ok((mut end, mut value, _)) => {
                    match attached_suffix(text, end) {
                        Some((e, Suffix::Pow(p))) => match mul_pow10(value, p) {
                            Some(v) => {
                                value = v;
                                end = e;
                            }
                            None => end = e,
                        },
                        Some((e, Suffix::Ordinal)) => end = e,
                        None => {
                            if b.get(end) == Some(&b'%') {
                                end += 1;
                            } else if let Some(e) = percent_suffix(text, end) {
                                end = e;
                            }
                        }
                    }
                    out.push((i, end, value));
                    i = end;
                }
                Err((s, e)) => {
                    let mut p = s;
                    while p < e {
                        let n = digits_at(b, p);
                        if n == 0 {
                            p += 1;
                            continue;
                        }
                        out.push((p, p + n, saturating_digit_value(&text[p..p + n])));
                        p += n;
                    }
                    i = e;
                }
            }
            continue;
        }
        if c.is_numeric() {
            // non-ASCII numeric run (ASCII digits were handled above)
            let e = non_ascii_run_end(text, i);
            if let Some(v) = folded_value(&text[i..e]) {
                out.push((i, e, v));
            }
            i = e;
            continue;
        }
        if c.is_alphabetic() {
            let (_, we) = word_at(text, i).unwrap_or((i, i + w));
            if word_start(text, i) {
                if let Some((end, v)) = number_words(lang).parse_at(text, i) {
                    out.push((i, end, v));
                    i = end;
                    continue;
                }
            }
            i = we;
            continue;
        }
        i += w;
    }
    out
}

/// End of the run of non-ASCII numeric chars starting at `i`.
fn non_ascii_run_end(text: &str, i: usize) -> usize {
    let n: usize = text
        .get(i..)
        .unwrap_or("")
        .chars()
        .take_while(|c| c.is_numeric() && !c.is_ascii_digit())
        .map(char::len_utf8)
        .sum();
    i + n
}

/// Every run of non-ASCII numeric characters (`²`, `５`, `١٢٣`, `½`).
fn non_ascii_numeric_runs(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(c) = text.get(i..).and_then(|t| t.chars().next()) {
        if c.is_numeric() && !c.is_ascii_digit() {
            let e = non_ascii_run_end(text, i);
            out.push((i, e));
            i = e;
        } else {
            i += c.len_utf8();
        }
    }
    out
}

/// The value of a run when its NFKC fold is a plain ASCII number.
fn folded_value(run: &str) -> Option<Decimal> {
    let f: String = run.nfkc().collect();
    if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(saturating_digit_value(&f))
}

/// Non-ASCII numeric runs that do not fold to a plain number (Arabic-Indic
/// digits, vulgar fractions): the caller must treat each as unreadable.
pub fn find_unreadable_numerics(text: &str) -> Vec<(usize, usize)> {
    non_ascii_numeric_runs(text)
        .into_iter()
        .filter(|&(s, e)| folded_value(&text[s..e]).is_none())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::parse_plain(s).unwrap()
    }

    #[test]
    fn detects_danish() {
        assert_eq!(detect_lang("Hvad skylder Anna Berg?"), Lang::Da);
        assert_eq!(detect_lang("What does Anna owe?"), Lang::En);
        assert_eq!(detect_lang("Søren"), Lang::Da);
        assert_eq!(detect_lang("Anna Berg"), Lang::En);
    }

    #[test]
    fn grouping_rules() {
        let sn = |t: &str, l| {
            find_numbers(t, l)
                .into_iter()
                .map(|x| x.2)
                .collect::<Vec<_>>()
        };
        assert_eq!(sn("10.000,50", Lang::En), vec![d("10000.50")]);
        assert_eq!(sn("10,000.50", Lang::Da), vec![d("10000.50")]);
        assert_eq!(sn("1.234", Lang::Da), vec![d("1234")]);
        assert_eq!(sn("1,234", Lang::En), vec![d("1234")]);
        assert_eq!(sn("1.5", Lang::Da), vec![d("1.5")]);
        assert_eq!(sn("10,5", Lang::En), vec![d("10.5")]);
        assert_eq!(sn("1.234.567", Lang::En), vec![d("1234567")]);
        assert_eq!(sn("18 420,00", Lang::Da), vec![d("18420.00")]);
        assert_eq!(sn("3 2026", Lang::En), vec![d("3"), d("2026")]);
        assert_eq!(sn("1 2345", Lang::En), vec![d("1"), d("2345")]);
    }

    #[test]
    fn unreadable_run_still_reports_digits() {
        let v = find_numbers("10,0,0", Lang::En);
        assert_eq!(v.len(), 3);
        let big = "9".repeat(60);
        assert_eq!(find_numbers(&big, Lang::En).len(), 1);
    }

    #[test]
    fn word_boundaries() {
        let nw = number_words(Lang::Da);
        assert!(nw.parse_at("tone", 1).is_none());
        assert!(!number_words(Lang::En).is_number_word("and"));
        assert!(number_words(Lang::En).is_number_word("twenty-one"));
        assert!(!number_words(Lang::En).is_number_word("an"));
        assert!(number_words(Lang::En).parse_at("é", 1).is_none());
        assert!(number_words(Lang::En).parse_at("one2", 0).is_none());
    }

    #[test]
    fn error_has_no_text() {
        let e = find_literals("secret 10,0,0", Lang::En).unwrap_err();
        assert!(!e.to_string().contains("10,0,0"));
        assert_eq!((e.start, e.end), (7, 13));
    }
}
