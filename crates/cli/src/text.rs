//! Text rules shared by the terminal table and the HTML report.

/// Make log text safe to print: the log is written from agent-controlled
/// input, so terminal escapes (C0, DEL, C1 incl. CSI U+009B) and bidi
/// overrides must not reach the terminal. Newlines become `⏎`; every other
/// such char becomes a visible `\xNN` / `\u{NNNN}` escape.
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
            | '\u{061C}' => out.push_str(&format!("\\u{{{:04X}}}", c as u32)),
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
        assert_eq!(sanitize("x\ny\u{1b}"), "x⏎y\\x1b");
    }
}
