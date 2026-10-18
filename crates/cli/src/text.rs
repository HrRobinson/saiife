//! Text rules shared by the terminal table and the HTML report.

/// Make log text safe to print: the log is written from agent-controlled
/// input, so these must not reach the terminal or report raw: C0 controls,
/// DEL and C1 controls (incl. CSI U+009B), bidi overrides/isolates
/// (U+202A-202E, U+2066-2069), directional marks (U+200E, U+200F, U+061C),
/// zero-width chars (U+200B-200D, U+FEFF) and line/paragraph separators
/// (U+2028, U+2029). Newlines become `⏎`; controls become `\xNN`; the rest
/// become a visible `\u{NNNN}`.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push('⏎'),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200D}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{FEFF}' => out.push_str(&format!("\\u{{{:04X}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sanitize;

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
        assert_eq!(sanitize("x\ny\u{1b}"), "x⏎y\\x1b");
    }
}
