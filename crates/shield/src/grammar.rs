//! Plan 45 (R45-10, ruling T5-c): the fixed text of an answer template is a
//! small allow-listed grammar, not free prose. One function, [`grammar_ok`],
//! judges a sequence of segments and is used twice: by `parse_template`
//! (so the planner can retry, `template_slot`) and by the checker over the
//! filled text (defence in depth, refuse).
//!
//! The rules (fixed text only; printed slot output is never judged here):
//! * R1 charset: ASCII letters, `æøåÆØÅéÉ`, space, `\n`, digits (their source
//!   is the checker's job), and `. , : ; ! ? ' " ( ) / - &`. A `-` is only
//!   allowed between two ASCII letters (`e-mail`), never as a sign or dash.
//! * R2 delimiting: a numeric slot, a date slot or a digit token in fixed
//!   text is preceded by the start, a space or `\n`, and followed by the end,
//!   a space, `\n`, or one of `. , ; : ! ?` that is itself followed by the
//!   end, a space or `\n`. Two such numbers are separated by an ASCII-letter
//!   word or a `\n` (a new line is a hard boundary).
//! * R3 neighbour words: the word before and after a number (skipping spaces
//!   and punctuation, never a `\n`) is not a scale, sign or unit word
//!   (`mio`, `thousand`, `times`, `percent`, ...), nor a word containing a
//!   scale stem (`hundredthousand`, `tenmillion`).
//! * R6 Roman numerals: no piece (whitespace tokens split on punctuation,
//!   any case) of two or more letters from `ivxlcdm`, nor `q` followed by
//!   such letters, except a short list of real words (`ROMAN_WORDS`). A
//!   piece that is exactly `q` makes the next piece (across punctuation or
//!   whitespace) a Roman numeral even as a single letter (`Q-I`, `Q I`).
//! * Parameter displays and comparison words are judged like numbers for R2
//!   and R3 (`{p1} million`, `about {p1}k`), though not for number separation.

/// One piece of an answer: fixed text, a numeric or date slot (or a digit
/// token), or any other printed output (a parameter display, a comparison).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Seg<'a> {
    Text(&'a str),
    Num,
    /// A parameter display or a comparison word: judged like a number for
    /// delimiting (R2) and neighbour words (R3), but not for number separation.
    Param,
}

const PUNCT: &str = ".,:;!?'\"()/-&";
const NEIGHBOURS: &[&str] = &[
    "minus",
    "negative",
    "negativ",
    "plus",
    "times",
    "gange",
    "x",
    "e",
    "k",
    "m",
    "mn",
    "mm",
    "bn",
    "mio",
    "mia",
    "mrd",
    "grand",
    "lakh",
    "hundred",
    "hundreds",
    "thousand",
    "thousands",
    "million",
    "millions",
    "billion",
    "billions",
    "trillion",
    "trillions",
    "hundrede",
    "tusind",
    "tusinde",
    "tusinder",
    "millioner",
    "milliard",
    "milliarder",
    "billioner",
    "percent",
    "procent",
    "per",
    "pct",
    "mil",
    "mill",
];

fn allowed_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            'æ' | 'ø' | 'å' | 'Æ' | 'Ø' | 'Å' | 'é' | 'É' | ' ' | '\n'
        )
        || PUNCT.contains(c)
}

fn charset_ok(t: &str) -> bool {
    let chars: Vec<char> = t.chars().collect();
    chars.iter().enumerate().all(|(i, &c)| {
        if !allowed_char(c) {
            return false;
        }
        c != '-'
            || (i > 0
                && chars[i - 1].is_ascii_alphabetic()
                && chars.get(i + 1).is_some_and(char::is_ascii_alphabetic))
    })
}

/// Real words (lower case) made only of `IVXLCDM`; every other all-Roman
/// token of two or more letters is a Roman numeral (`xii`, `mcm`, `MMXXVI`).
/// A single letter is never refused (`i` is Danish "in" and English "I").
const ROMAN_WORDS: &[&str] = &[
    "mix", "dim", "lid", "civil", "vivid", "mild", "vild", "id", "did", "mid", "ill",
];

fn is_roman(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| "ivxlcdm".contains(c))
}

/// One punctuation-free piece, any case.
fn roman_piece(piece: &str) -> bool {
    let p = piece.to_ascii_lowercase();
    if ROMAN_WORDS.contains(&p.as_str()) {
        return false;
    }
    (p.chars().count() >= 2 && is_roman(&p)) || p.strip_prefix('q').is_some_and(is_roman)
}

/// Every piece of the text split on whitespace and all punctuation is judged
/// (`Q-III`, `II/III`, `MMXXVI's`). A piece that is exactly `q` makes the
/// next piece a Roman numeral even as a single letter (`Q-I`, `Q.I`, `Q I`).
fn has_roman(t: &str) -> bool {
    let mut after_q = false;
    for piece in t
        .split(|c: char| c.is_whitespace() || PUNCT.contains(c))
        .filter(|p| !p.is_empty())
    {
        let p = piece.to_ascii_lowercase();
        if roman_piece(&p) || (after_q && is_roman(&p)) {
            return true;
        }
        after_q = p == "q";
    }
    false
}

/// Split a text into text pieces and digit tokens (`10,000`, `4.5`).
fn split_digits<'a>(t: &'a str, out: &mut Vec<Seg<'a>>) {
    let b = t.as_bytes();
    let mut last = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let mut j = i + 1;
            while j < b.len()
                && (b[j].is_ascii_digit()
                    || (matches!(b[j], b'.' | b',')
                        && b.get(j + 1).is_some_and(u8::is_ascii_digit)))
            {
                j += 1;
            }
            if i > last {
                out.push(Seg::Text(&t[last..i]));
            }
            out.push(Seg::Num);
            last = j;
            i = j;
        } else {
            i += 1;
        }
    }
    if last < t.len() {
        out.push(Seg::Text(&t[last..]));
    }
}

/// Scale stems (plan 45 final review M6): a word next to a number that
/// contains one is a scale word whatever is glued to it (`hundredthousand`,
/// `tenmillion`, `halvmilliard`). `illion` covers million, billion, trillion.
const SCALE_STEMS: &[&str] = &[
    "hundred", "thousand", "illion", "milliard", "tusind", "mio", "mia",
];

fn neighbour_bad(w: &str) -> bool {
    let w = w.to_ascii_lowercase();
    NEIGHBOURS.contains(&w.as_str()) || SCALE_STEMS.iter().any(|s| w.contains(s))
}

fn word_before(t: &str) -> &str {
    let t = t.trim_end_matches(|c: char| c == ' ' || PUNCT.contains(c));
    let n = t
        .chars()
        .rev()
        .take_while(char::is_ascii_alphabetic)
        .count();
    &t[t.len() - n..]
}

fn word_after(t: &str) -> &str {
    let t = t.trim_start_matches(|c: char| c == ' ' || PUNCT.contains(c));
    let n = t.chars().take_while(char::is_ascii_alphabetic).count();
    &t[..n]
}

/// Judge the segments. `Err` carries a short static reason (no data).
pub(crate) fn grammar_ok(segs: &[Seg]) -> Result<(), &'static str> {
    let mut items: Vec<Seg> = Vec::new();
    for s in segs {
        match s {
            Seg::Text(t) => {
                if !charset_ok(t) {
                    return Err("fixed text has a character outside the allowed set");
                }
                if has_roman(t) {
                    return Err("fixed text has a Roman numeral");
                }
                split_digits(t, &mut items);
            }
            other => items.push(*other),
        }
    }
    items.retain(|s| !matches!(s, Seg::Text("")));
    let mut last_num: Option<usize> = None;
    for (i, s) in items.iter().enumerate() {
        let is_num = match s {
            Seg::Num => true,
            Seg::Param => false,
            Seg::Text(_) => continue,
        };
        let prev = match i.checked_sub(1).map(|p| items[p]) {
            None => None,
            Some(Seg::Text(t)) if t.ends_with([' ', '\n']) => Some(t),
            Some(_) => return Err("a number is not set off by a space"),
        };
        let next = match items.get(i + 1) {
            None => None,
            Some(Seg::Text(t)) => {
                let mut cs = t.chars();
                match cs.next() {
                    Some(' ' | '\n') => {}
                    Some('.' | ',' | ';' | ':' | '!' | '?') => {
                        let rest = cs.as_str();
                        let ok = if rest.is_empty() {
                            i + 2 == items.len()
                        } else {
                            rest.starts_with([' ', '\n'])
                        };
                        if !ok {
                            return Err("a number is not set off by a space");
                        }
                    }
                    _ => return Err("a number is not set off by a space"),
                }
                Some(*t)
            }
            Some(_) => return Err("a number is not set off by a space"),
        };
        if prev.is_some_and(|t| neighbour_bad(word_before(t)))
            || next.is_some_and(|t| neighbour_bad(word_after(t)))
        {
            return Err("a number sits next to a scale, sign or unit word");
        }
        if !is_num {
            continue;
        }
        if let Some(l) = last_num {
            let between = &items[l + 1..i];
            let separated = between.iter().any(|s| match s {
                Seg::Text(t) => t.contains('\n') || t.chars().any(|c| c.is_ascii_alphabetic()),
                _ => false,
            });
            if !separated {
                return Err("two numbers need a word between them");
            }
        }
        last_num = Some(i);
    }
    Ok(())
}
