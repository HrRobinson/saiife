//! Text safety shared by everything that renders untrusted text (terminal
//! frames, rule targets). Tokio-free.
//!
//! The table below is generated, do not edit by hand. Source: Unicode 16.0.0
//! (general categories from UnicodeData via Python's `unicodedata`,
//! Default_Ignorable_Code_Point from DerivedCoreProperties-16.0.0.txt).
//! Regenerate with:
//!   python3 -I scripts/gen-unsafe-chars.py DerivedCoreProperties.txt

const UNSAFE: &[(u32, u32)] = &[
    (0x0, 0x8),
    (0xA, 0x1F),
    (0x7F, 0x9F),
    (0xAD, 0xAD),
    (0x34F, 0x34F),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xD800, 0xF8FF),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
    (0xF0000, 0xFFFFD),
    (0x100000, 0x10FFFD),
];

/// True for every character that must never reach a terminal or a rule:
/// general categories Cc, Cf, Co, Cs, Zl, Zp and Default_Ignorable_Code_Point
/// (bidi controls, zero-width and invisible characters, variation selectors,
/// tag characters, private use), except TAB. Callers decide about `'\n'`.
pub fn is_unsafe_char(c: char) -> bool {
    let u = c as u32;
    UNSAFE
        .binary_search_by(|&(lo, hi)| {
            if u < lo {
                std::cmp::Ordering::Greater
            } else if u > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_samples() {
        for c in [
            '\u{AD}',
            '\u{34F}',
            '\u{180E}',
            '\u{FFF9}',
            '\u{1D173}',
            '\u{E0001}',
            '\u{E000}',
            '\u{2028}',
            '\u{2029}',
            '\u{7}',
            '\u{9B}',
            '\u{7F}',
            '\u{200B}',
            '\u{202E}',
            '\u{FEFF}',
            '\u{61C}',
            '\u{FE0F}',
            '\n',
            '\r',
        ] {
            assert!(is_unsafe_char(c), "{:X}", c as u32);
        }
    }

    #[test]
    fn safe_samples() {
        for c in ['a', 'é', '中', '😀', ' ', '\t', '~', '\u{301}', '\u{A0}'] {
            assert!(!is_unsafe_char(c), "{:X}", c as u32);
        }
    }

    #[test]
    fn table_is_sorted_and_disjoint() {
        for w in UNSAFE.windows(2) {
            assert!(w[0].0 <= w[0].1 && w[0].1 < w[1].0);
        }
    }

    #[test]
    fn lossy_decode_has_no_surrogate() {
        let s = String::from_utf8_lossy(b"\xed\xa0\x80");
        assert!(s.chars().all(|c| c == '\u{FFFD}'));
        assert!(s.chars().all(|c| !is_unsafe_char(c)));
        assert!(!is_unsafe_char('\u{FFFD}'));
        // Surrogates are not chars; their category is in the table's range
        // all the same (D800..DFFF) so a future table edit cannot lose it.
        assert!(UNSAFE.iter().any(|&(lo, hi)| lo <= 0xD800 && 0xDFFF <= hi));
    }
}
