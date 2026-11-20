//! Plan 43: normalization of names and values (R43-7).
//!
//! `æ→ae`, `ø→oe`, `å→aa`, `ß→ss` first (either case), then NFKD with the
//! combining marks dropped, then lower case; every run of non-alphanumerics
//! becomes one space and the ends are trimmed. A person name's tokens are
//! also kept sorted ([`sorted_key`]) so `berg anna` = `anna berg`. Initials
//! are not expanded in stage 1.
//!
//! The work is done per cluster (a base character and the combining marks
//! after it), so every token knows the bytes of the input it came from
//! ([`token_spans`]); [`normalize`] is built from the same tokens, so the two
//! can never disagree.

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

/// The Danish and German letters that fold to two letters, not to a base
/// letter (NFKD would turn `å` into `a`, and leaves `æ`, `ø`, `ß` alone).
fn two_letter(c: char) -> Option<&'static str> {
    Some(match c {
        'æ' | 'Æ' => "ae",
        'ø' | 'Ø' => "oe",
        'å' | 'Å' => "aa",
        'ß' | 'ẞ' => "ss",
        _ => return None,
    })
}

/// Folds one cluster into `out`: the folded characters, alphanumeric or not.
fn fold_cluster(cluster: &str, out: &mut String) {
    // NFC first so a decomposed `A` + ring is the `Å` the map knows.
    for c in cluster.nfc() {
        if let Some(s) = two_letter(c) {
            out.push_str(s);
            continue;
        }
        for d in std::iter::once(c).nfkd() {
            if is_combining_mark(d) {
                continue;
            }
            for l in d.to_lowercase() {
                // Lower-casing can add a mark (`İ` → `i` + dot) or give a
                // letter the map folds (`ǽ` → `æ` after NFKD).
                if is_combining_mark(l) {
                    continue;
                }
                match two_letter(l) {
                    Some(s) => out.push_str(s),
                    None => out.push(l),
                }
            }
        }
    }
}

/// The byte ranges of `s` that are clusters: a character and the combining
/// marks that follow it.
fn clusters(s: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut it = s.char_indices().peekable();
    std::iter::from_fn(move || {
        let (start, _) = it.next()?;
        while let Some(&(_, c)) = it.peek() {
            if !is_combining_mark(c) {
                break;
            }
            it.next();
        }
        let end = it.peek().map_or(s.len(), |&(i, _)| i);
        Some((start, end))
    })
}

/// The normalized tokens of `s`, each with the byte range of `s` it came
/// from (`start..end`, on character boundaries).
pub(crate) fn token_spans(s: &str) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut start, mut end) = (0, 0);
    let mut buf = String::new();
    for (a, b) in clusters(s) {
        buf.clear();
        fold_cluster(&s[a..b], &mut buf);
        for ch in buf.chars() {
            if ch.is_alphanumeric() {
                if cur.is_empty() {
                    start = a;
                }
                cur.push(ch);
                end = b;
            } else if !cur.is_empty() {
                out.push((std::mem::take(&mut cur), start, end));
            }
        }
    }
    if !cur.is_empty() {
        out.push((cur, start, end));
    }
    out
}

/// R43-7: the normalized form of a name or value.
pub fn normalize(s: &str) -> String {
    tokens(s).join(" ")
}

/// The tokens of [`normalize`]`(s)`.
pub fn tokens(s: &str) -> Vec<String> {
    token_spans(s).into_iter().map(|t| t.0).collect()
}

/// The tokens sorted and joined by one space: the name-order-free key.
pub fn sorted_key(s: &str) -> String {
    let mut t = tokens(s);
    t.sort_unstable();
    t.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_point_into_the_input() {
        let s = "  Ærø, Søren-x ";
        let t = token_spans(s);
        let got: Vec<(&str, &str)> = t.iter().map(|(n, a, b)| (n.as_str(), &s[*a..*b])).collect();
        assert_eq!(got, vec![("aeroe", "Ærø"), ("soeren", "Søren"), ("x", "x")]);
        // A combining mark stays inside its token.
        let s = "Ze\u{301}lie";
        assert_eq!(token_spans(s), vec![("zelie".to_string(), 0, s.len())]);
        assert_eq!(normalize("İstanbul"), "istanbul");
        assert_eq!(normalize("ﬁsk"), "fisk");
    }
}
