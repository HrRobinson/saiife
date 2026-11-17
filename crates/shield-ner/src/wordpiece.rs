//! BERT basic tokenization plus greedy longest-match WordPiece.
//!
//! Offsets always refer to the ORIGINAL text: word boundaries come from
//! `char_indices` over the original, and the case-folded / accent-stripped
//! form of a word is a throw-away string used only for vocabulary lookup.

use crate::NerError;
use std::collections::HashMap;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

/// Largest accepted vocab file.
pub const VOCAB_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Most vocab entries.
pub const VOCAB_MAX_ENTRIES: usize = 1_000_000;
/// A word longer than this many chars is `[UNK]` (BERT's rule).
pub const MAX_WORD_CHARS: usize = 100;

#[derive(Debug, Clone)]
pub struct WordPiece {
    vocab: HashMap<String, u32>,
    lower: bool,
    strip_accents: bool,
    unk: i64,
    cls: i64,
    sep: i64,
    pad: i64,
}

/// `ids` holds content pieces only (no `[CLS]`/`[SEP]`; the runtime adds
/// them per window). `word_of_piece[i]` is `Some(w)` when piece `i` is the
/// FIRST piece of word `w` and `None` for continuation pieces. `words` are
/// byte ranges into the original text (always on char boundaries).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Encoding {
    pub ids: Vec<i64>,
    pub word_of_piece: Vec<Option<usize>>,
    pub words: Vec<(usize, usize)>,
}

fn is_punct(c: char) -> bool {
    c.is_ascii_punctuation()
        || (!c.is_alphanumeric() && !c.is_whitespace() && !is_combining_mark(c))
}

impl WordPiece {
    pub fn from_vocab(
        bytes: &[u8],
        lower: bool,
        strip_accents: bool,
    ) -> Result<WordPiece, NerError> {
        if bytes.len() > VOCAB_MAX_BYTES {
            return Err(NerError::Vocab);
        }
        let s = std::str::from_utf8(bytes).map_err(|_| NerError::Vocab)?;
        let mut vocab = HashMap::new();
        for (i, line) in s.split('\n').enumerate() {
            if i >= VOCAB_MAX_ENTRIES {
                return Err(NerError::Vocab);
            }
            let tok = line.strip_suffix('\r').unwrap_or(line);
            if !tok.is_empty() {
                vocab.entry(tok.to_string()).or_insert(i as u32);
            }
        }
        let id = |t: &str| vocab.get(t).map(|v| i64::from(*v)).ok_or(NerError::Vocab);
        let (unk, cls, sep, pad) = (id("[UNK]")?, id("[CLS]")?, id("[SEP]")?, id("[PAD]")?);
        Ok(WordPiece {
            vocab,
            lower,
            strip_accents,
            unk,
            cls,
            sep,
            pad,
        })
    }

    pub fn cls_id(&self) -> i64 {
        self.cls
    }
    pub fn sep_id(&self) -> i64 {
        self.sep
    }
    pub fn pad_id(&self) -> i64 {
        self.pad
    }

    /// Basic tokenization: byte ranges of words in the original text.
    fn split_words(text: &str) -> Vec<(usize, usize)> {
        let mut words: Vec<(usize, usize)> = Vec::new();
        let mut open = false; // the last word may still grow
        for (i, c) in text.char_indices() {
            let end = i + c.len_utf8();
            if c.is_whitespace() || c.is_control() {
                open = false;
            } else if is_combining_mark(c) {
                // a mark stays with the char before it when adjacent
                match words.last_mut() {
                    Some(w) if w.1 == i => w.1 = end,
                    _ => words.push((i, end)),
                }
                // after a mark, an alphanumeric word may continue
                open = open && words.last().is_some_and(|w| w.1 == end);
            } else if is_punct(c) {
                words.push((i, end));
                open = false;
            } else if open {
                if let Some(w) = words.last_mut() {
                    w.1 = end;
                }
            } else {
                words.push((i, end));
                open = true;
            }
        }
        words
    }

    /// The lookup form of a word (a throw-away copy; never sliced).
    fn normalize(&self, word: &str) -> Vec<char> {
        let folded: String = if self.lower {
            word.to_lowercase()
        } else {
            word.to_string()
        };
        if self.strip_accents {
            folded
                .nfd()
                .filter(|c| !is_combining_mark(*c))
                .collect::<String>()
                .chars()
                .collect()
        } else {
            folded.nfc().collect::<String>().chars().collect()
        }
    }

    fn pieces(&self, chars: &[char]) -> Option<Vec<i64>> {
        let mut out = Vec::new();
        let mut start = 0;
        while start < chars.len() {
            let mut end = chars.len();
            let mut found = None;
            while end > start {
                let mut s = String::new();
                if start > 0 {
                    s.push_str("##");
                }
                s.extend(&chars[start..end]);
                if let Some(id) = self.vocab.get(&s) {
                    found = Some(i64::from(*id));
                    break;
                }
                end -= 1;
            }
            out.push(found?);
            start = end;
        }
        Some(out)
    }

    pub fn encode(&self, text: &str) -> Encoding {
        let mut enc = Encoding::default();
        for (s, e) in Self::split_words(text) {
            let Some(word) = text.get(s..e) else { continue };
            let ids = if word.chars().take(MAX_WORD_CHARS + 1).count() > MAX_WORD_CHARS {
                None
            } else {
                let chars = self.normalize(word);
                if chars.is_empty() {
                    continue; // only accents, stripped away
                }
                if chars.len() > MAX_WORD_CHARS {
                    None
                } else {
                    self.pieces(&chars)
                }
            };
            let ids = ids.unwrap_or_else(|| vec![self.unk]);
            let w = enc.words.len();
            enc.words.push((s, e));
            for (k, id) in ids.into_iter().enumerate() {
                enc.ids.push(id);
                enc.word_of_piece.push(if k == 0 { Some(w) } else { None });
            }
        }
        enc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VOCAB: &str = "[PAD]\n[UNK]\n[CLS]\n[SEP]\nhvad\nskylder\ns\n##ø\n##ren\nå\n##se\n?\n";

    fn wp(lower: bool, strip: bool) -> WordPiece {
        WordPiece::from_vocab(VOCAB.as_bytes(), lower, strip).unwrap()
    }

    #[test]
    fn wordpiece_vocab() {
        let w = wp(true, false);
        let text = "Hvad skylder Søren?";
        let e = w.encode(text);
        assert_eq!(e.ids, vec![4, 5, 6, 7, 8, 11]);
        assert_eq!(e.words, vec![(0, 4), (5, 12), (13, 19), (19, 20)]);
        assert_eq!(
            e.word_of_piece,
            vec![Some(0), Some(1), Some(2), None, None, Some(3)]
        );
        assert_eq!(&text[13..19], "Søren");
        assert_eq!((w.cls_id(), w.sep_id(), w.pad_id()), (2, 3, 0));
        // unknown word and over-long word are [UNK]
        let e = w.encode("zzz");
        assert_eq!(e.ids, vec![1]);
        let long = "a".repeat(101);
        assert_eq!(w.encode(&long).ids, vec![1]);
        assert!(WordPiece::from_vocab(b"[PAD]\n[UNK]\n", true, false).is_err());
        assert!(WordPiece::from_vocab(b"\xff", true, false).is_err());
    }

    #[test]
    fn offsets_survive_normalization() {
        for (lower, strip) in [(true, true), (true, false), (false, true), (false, false)] {
            let w = wp(lower, strip);
            let cases: [(&str, &[&str]); 3] = [
                (
                    "Hvad skylder Åse Østergård?",
                    &["Hvad", "skylder", "Åse", "Østergård", "?"],
                ),
                ("A\u{030a}se", &["A\u{030a}se"]),
                ("x A\u{030a}se!", &["x", "A\u{030a}se", "!"]),
            ];
            for (text, expect) in cases {
                let e = w.encode(text);
                let got: Vec<&str> = e.words.iter().map(|(s, en)| &text[*s..*en]).collect();
                assert_eq!(got, expect, "lower={lower} strip={strip}");
            }
        }
        // stripped accents: decomposed and composed A-ring both reach "å"?
        // (strip removes the ring, so only plain "a" would match: UNK here)
        let e = wp(true, false).encode("A\u{030a}se");
        assert_eq!(e.words, vec![(0, 5)]);
        assert_eq!(e.ids, vec![9, 10]); // NFC folds to å + ##se
        let e = wp(true, false).encode("Åse");
        assert_eq!(e.ids, vec![9, 10]);
    }

    #[test]
    fn never_panics_arbitrary_utf8() {
        let mut samples: Vec<String> = vec![
            "İstanbul İİİ".into(),
            "K\u{212a}elvin \u{212a}".into(),
            "Straße ẞ ß".into(),
            "A\u{030a}\u{030a}\u{0301}\u{0323}se".into(),
            "\u{030a}lead mark".into(),
            "\u{030a}".into(),
            "👨‍👩‍👧‍👦 family 🏳️‍🌈 flag \u{fe0f}".into(),
            "a\0b\u{200b}c\u{feff}d".into(),
            "".into(),
            " \t\n ".into(),
            "??!!..".into(),
        ];
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..300 {
            let mut s = String::new();
            for _ in 0..(x % 40) {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let cp = ((x >> 33) % 0x2FFFF) as u32;
                let cp = if (x >> 20).is_multiple_of(3) {
                    cp % 0x0600
                } else {
                    cp
                };
                if let Some(c) = char::from_u32(cp) {
                    s.push(c);
                }
            }
            samples.push(s);
        }
        let labels: Vec<String> = ["O", "B-PER", "I-PER", "B-LOC"].map(String::from).to_vec();
        let mut k = 0usize;
        for (lower, strip) in [(true, true), (true, false), (false, true), (false, false)] {
            let w = wp(lower, strip);
            for t in &samples {
                let e = w.encode(t);
                assert_eq!(e.ids.len(), e.word_of_piece.len());
                for (s, en) in &e.words {
                    assert!(t.get(*s..*en).is_some(), "bad range");
                }
                for (a, b) in crate::windows(&e, 8) {
                    assert!(a <= b && b <= e.ids.len());
                }
                // probs of every shape, including too short and too long
                let n = e.ids.len();
                for len in [0, n / 2, n, n + 3] {
                    let probs: Vec<(usize, f32)> = (0..len)
                        .map(|i| {
                            k = k.wrapping_add(7);
                            ((i + k) % 6, 0.9)
                        })
                        .collect();
                    for ws in crate::decode_bio(&e, &labels, &probs) {
                        assert!(ws.to_span(t).is_some(), "span must map back");
                    }
                }
            }
        }
    }
}
