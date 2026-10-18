//! Text rules shared by the terminal table and the HTML report.

/// Unicode general category Cf (format, Unicode 15) plus U+034F (combining
/// grapheme joiner) and the line/paragraph separators U+2028/U+2029.
/// Sorted, non-overlapping inclusive ranges, for binary search.
const INVISIBLE: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

fn is_invisible(c: char) -> bool {
    let c = c as u32;
    INVISIBLE
        .binary_search_by(|&(lo, hi)| {
            if c < lo {
                std::cmp::Ordering::Greater
            } else if c > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Make log text safe to print: the log is written from agent-controlled
/// input, so these must not reach the terminal or report raw: C0 controls,
/// DEL and C1 controls (incl. CSI U+009B) and every Unicode format (Cf)
/// character (bidi overrides/isolates, directional marks, zero-width chars,
/// soft hyphen, BOM, tag characters, ...), plus U+034F and the line/paragraph
/// separators U+2028/U+2029. Newlines become `⏎`; controls become `\xNN`; the
/// rest become a visible `\u{NNNN}` (at least 4 hex digits).
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push('⏎'),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if is_invisible(c) => out.push_str(&format!("\\u{{{:04X}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn invisible_table_is_sorted() {
        for w in super::INVISIBLE.windows(2) {
            assert!(w[0].1 < w[1].0);
        }
    }

    #[test]
    fn directional_marks_are_escaped() {
        assert_eq!(
            sanitize("a\u{200E}b\u{200F}c\u{061C}d"),
            "a\\u{200E}b\\u{200F}c\\u{061C}d"
        );
        assert_eq!(
            sanitize("\u{202A}\u{202E}\u{2066}\u{2069}\u{9b}"),
            "\\u{202A}\\u{202E}\\u{2066}\\u{2069}\\x9b"
        );
        assert_eq!(
            sanitize("\u{200B}\u{200C}\u{200D}\u{2028}\u{2029}\u{FEFF}"),
            "\\u{200B}\\u{200C}\\u{200D}\\u{2028}\\u{2029}\\u{FEFF}"
        );
        assert_eq!(
            sanitize("\u{AD}\u{2060}\u{E0041}\u{1D173}\u{34F}"),
            "\\u{00AD}\\u{2060}\\u{E0041}\\u{1D173}\\u{034F}"
        );
        assert_eq!(sanitize("plain é 日本"), "plain é 日本");
        assert_eq!(sanitize("x\ny\u{1b}"), "x⏎y\\x1b");
    }
}
