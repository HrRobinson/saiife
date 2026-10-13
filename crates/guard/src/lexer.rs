//! A real shell-ish tokenizer.
//!
//! This replaces the previous ad-hoc, regex/character-scan approach (a naive
//! `split_whitespace` "normalizer" plus a separate quote-aware character scan
//! for chaining-operator splitting). Two adversarial review rounds proved that
//! approach bypassable by quoting shapes it did not understand: an escaped
//! quote that does not close a string (`echo "a\""`), and adjacent-string
//! concatenation (`"/e"tc` is one argument, `/etc`). The fix is to tokenize
//! the whole command line **once**, correctly, and have everything downstream
//! (segmentation, argv construction, matching) operate on the resulting
//! tokens instead of raw text.
//!
//! ## What the lexer understands
//!
//! - **Single quotes** `'...'`: everything inside is literal; there is no
//!   escape mechanism inside single quotes (a backslash is just a backslash).
//! - **Double quotes** `"..."`: literal except for the backslash escapes
//!   POSIX defines inside double quotes — `\"`, `\\`, `\$`, `` \` ``. Any other
//!   backslash is left as a literal backslash (the following character is
//!   read normally on the next iteration). Critically, `\"` does **not**
//!   close the string — only a bare, unescaped `"` does.
//! - **Backslash escapes outside quotes**: `\<char>` is a literal `<char>`,
//!   so `\;` and `\&` are word data, never operators.
//! - **Adjacent-string concatenation**: nothing special is required to
//!   implement this — it falls out of the design. A "word" is a run of
//!   pieces (bare chars, single-quoted regions, double-quoted regions,
//!   escapes, substitutions) with no intervening whitespace; each piece
//!   appends its resolved text to the same word buffer, so `"/e"tc` naturally
//!   becomes the one token `/etc`.
//! - **Command substitution** `$(...)` and backticks `` `...` ``, including
//!   when they occur inside a double-quoted region (real shells still expand
//!   `$(...)` inside double quotes): lexed as a single **opaque** token —
//!   the raw source text is kept (never evaluated), the token's
//!   `has_substitution` flag is set, and — this is the point — any `;`,
//!   `&&`, `||`, `|` inside the substitution's parens/backticks is consumed
//!   as part of the opaque region and never seen as a top-level operator.
//! - **Operator splitting**: unquoted, unescaped `&&`, `||`, `;`, `|`, a
//!   lone `&` (background), and newlines end the current segment. A
//!   separator character that is quoted, escaped, or inside a substitution
//!   is word data, not a boundary.
//! - **Grouping/compound-command boundaries**: unquoted, unescaped `(`, `)`,
//!   `{`, `}` also end the current segment, exactly like `;` does — a
//!   subshell's or brace-group's contents become their own segment(s) rather
//!   than swallowing the whole construct into one un-`^`-anchorable word
//!   (`( rm -rf / )`, `{ rm -rf /; }` would otherwise put `rm` at argv[1],
//!   never argv[0], and every deny rule is anchored to argv[0]). `${...}`
//!   parameter-expansion syntax is the one carve-out: a `{` immediately
//!   after `$` is not a grouping boundary — real bash doesn't treat it as
//!   one either — so `${HOME}` stays one literal token, matching the
//!   existing `\$\{HOME\}` pack patterns. A leading shell keyword that only
//!   introduces the real command (`then`, `do`, `else`, `elif`) is stripped
//!   from a segment's front so the guarded command lands at argv[0]
//!   (`if true; then rm -rf /; fi` and `for i in 1; do rm -rf /; done` both
//!   judge `rm -rf /`, not `then`/`do`). This is heuristic keyword-stripping,
//!   not compound-statement parsing — see the design doc's "known
//!   limitations" for what a real shell grammar would additionally give.
//! - **`$'...'` ANSI-C quoting**: real bash decodes backslash escapes inside
//!   `$'...'` (`\n \t \r \\ \' \xHH \0NNN`, plus a handful more) rather than
//!   treating the body as literal the way `'...'` does. The lexer decodes
//!   the common escapes so `$'/'` and `$'\x2f'` both resolve to the argument
//!   `/` instead of surviving as unresolved junk. Escapes this lexer does
//!   not know (`\uXXXX`, `\UXXXXXXXX`, `\cX`, `\eE`, …) are kept literally
//!   (backslash + character) rather than guessed at — see "known
//!   limitations".
//!
//! ## What it deliberately does not do
//!
//! No shell grammar beyond the above: no variable expansion (`$VAR`,
//! `${VAR}` are left as literal, unevaluated text), no glob expansion, no
//! here-docs, no evaluating what a substitution would actually output, and
//! grouping/keyword handling is a boundary heuristic, not a parser for `if`/
//! `for`/`while`/`case` compound-command grammar. See the design doc's
//! "known limitations" for the honest scope.

/// One resolved argv token (a word): the fully concatenated, quote/escape
/// resolved text, plus whether it contains an opaque command-substitution
/// region (`$(...)` or `` `...` ``) that the guard could not look inside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub text: String,
    pub has_substitution: bool,
}

/// A single top-level command segment: the argv-order sequence of words
/// between chaining operators (`&&`, `||`, `;`, `|`, `&`, newline).
pub type Segment = Vec<Word>;

/// Split a raw command line into top-level segments of resolved words.
///
/// This is the crate's one entry point for turning raw shell text into
/// structured argv. Segmentation and quote/escape/concatenation resolution
/// happen together in a single pass, so a separator hidden inside a quoted
/// or escaped region can never be mistaken for a real boundary, and a real
/// boundary hidden by unresolved quoting (`a&&rm -rf /`, no whitespace)
/// can never be missed.
pub fn split_segments(cmd: &str) -> Vec<Segment> {
    let mut segments: Vec<Segment> = Vec::new();
    let mut current: Segment = Vec::new();

    for tok in lex(cmd) {
        match tok {
            LexTok::Word(w) => current.push(w),
            LexTok::Operator(_) => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
            }
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments.into_iter().map(strip_leading_keywords).collect()
}

/// Shell keywords that only ever *introduce* a real command inside a
/// compound construct (`if X; then CMD; fi`, `for i in 1; do CMD; done`) —
/// stripping a leading run of them off a segment reveals the actual
/// command at argv[0]. Deliberately narrow: `if`/`for`/`while`/`until`
/// themselves are left alone, since they head their own condition/list
/// segment (harmless as an argv[0] no pack cares about), not the guarded
/// command.
const LEADING_KEYWORDS: &[&str] = &["then", "do", "else", "elif"];

/// Drop a leading run of `LEADING_KEYWORDS` words from a segment. One pass,
/// one `drain` — bounded by the segment's own length, so this can't turn an
/// adversarially long segment into quadratic work.
fn strip_leading_keywords(mut seg: Segment) -> Segment {
    let mut i = 0;
    while i < seg.len() && LEADING_KEYWORDS.contains(&seg[i].text.as_str()) {
        i += 1;
    }
    if i > 0 {
        seg.drain(0..i);
    }
    seg
}

/// A chaining operator (or grouping boundary) that ends a segment. All
/// variants are treated identically by `split_segments` — the operator
/// itself is discarded and the current segment is flushed — so `(`/`)`/`{`/
/// `}` behave exactly like `;` for segmentation purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    AndAnd,
    OrOr,
    Pipe,
    Semi,
    Amp,
    Newline,
    LParen,
    RParen,
    LBrace,
    RBrace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LexTok {
    Word(Word),
    Operator(Operator),
}

/// Tokenize a raw command line into words and operators, in order. Exposed
/// (crate-visible) mainly so unit tests can assert on tokenization directly
/// rather than only through `split_segments`'s grouping.
#[allow(unused_assignments)] // the final flush_word!() sets state that is never read again
fn lex(input: &str) -> Vec<LexTok> {
    let mut toks: Vec<LexTok> = Vec::new();
    let mut chars = input.chars().peekable();

    let mut word_text = String::new();
    let mut word_has_sub = false;
    let mut in_word = false;

    // Flush the in-progress word (if any) as a completed token.
    macro_rules! flush_word {
        () => {
            if in_word {
                toks.push(LexTok::Word(Word {
                    text: std::mem::take(&mut word_text),
                    has_substitution: word_has_sub,
                }));
                in_word = false;
                word_has_sub = false;
            }
        };
    }

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\r' => flush_word!(),
            '\n' => {
                flush_word!();
                toks.push(LexTok::Operator(Operator::Newline));
            }
            '&' => {
                if chars.peek() == Some(&'&') {
                    chars.next();
                    flush_word!();
                    toks.push(LexTok::Operator(Operator::AndAnd));
                } else {
                    flush_word!();
                    toks.push(LexTok::Operator(Operator::Amp));
                }
            }
            '|' => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                    flush_word!();
                    toks.push(LexTok::Operator(Operator::OrOr));
                } else {
                    flush_word!();
                    toks.push(LexTok::Operator(Operator::Pipe));
                }
            }
            ';' => {
                flush_word!();
                toks.push(LexTok::Operator(Operator::Semi));
            }
            '(' => {
                flush_word!();
                toks.push(LexTok::Operator(Operator::LParen));
            }
            ')' => {
                flush_word!();
                toks.push(LexTok::Operator(Operator::RParen));
            }
            '{' => {
                flush_word!();
                toks.push(LexTok::Operator(Operator::LBrace));
            }
            '}' => {
                flush_word!();
                toks.push(LexTok::Operator(Operator::RBrace));
            }
            '\'' => {
                in_word = true;
                scan_single_quoted(&mut chars, &mut word_text);
            }
            '"' => {
                in_word = true;
                scan_double_quoted(&mut chars, &mut word_text, &mut word_has_sub);
            }
            '\\' => {
                in_word = true;
                // Outside quotes, `\<char>` is a literal `<char>` — this is
                // what keeps `\;` and `\&` from being read as operators. A
                // trailing backslash with nothing after it is kept literal.
                match chars.next() {
                    Some(n) => word_text.push(n),
                    None => word_text.push('\\'),
                }
            }
            '$' if chars.peek() == Some(&'(') => {
                chars.next(); // consume '('
                in_word = true;
                word_has_sub = true;
                word_text.push_str("$(");
                word_text.push_str(&scan_paren_balanced(&mut chars));
                word_text.push(')');
            }
            '$' if chars.peek() == Some(&'\'') => {
                chars.next(); // consume the opening '\''
                in_word = true;
                scan_ansi_c_quoted(&mut chars, &mut word_text);
            }
            '$' if chars.peek() == Some(&'{') => {
                // `${...}` parameter expansion: not evaluated (no variable
                // expansion, per the design doc's scope), but its `{`/`}`
                // are NOT a grouping boundary the way a bare `{`/`}` is —
                // real bash doesn't treat them as one either, and pack rules
                // like `\$\{HOME\}` depend on `${HOME}` surviving as one
                // contiguous literal token.
                chars.next(); // consume '{'
                in_word = true;
                word_text.push_str("${");
                word_text.push_str(&scan_brace_balanced(&mut chars));
                word_text.push('}');
            }
            '`' => {
                in_word = true;
                word_has_sub = true;
                word_text.push('`');
                word_text.push_str(&scan_backtick(&mut chars));
                word_text.push('`');
            }
            other => {
                in_word = true;
                word_text.push(other);
            }
        }
    }
    flush_word!();
    toks
}

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

/// Single-quoted region: everything up to the next `'` is literal, no
/// escapes at all. An unterminated quote (no closing `'` before EOF) is the
/// conservative fallback: whatever was scanned becomes the word's content
/// and there is nothing left to mis-split, since we have consumed the rest
/// of the input.
fn scan_single_quoted(chars: &mut Chars, out: &mut String) {
    for c in chars.by_ref() {
        if c == '\'' {
            return;
        }
        out.push(c);
    }
}

/// Double-quoted region. Literal except for the four POSIX backslash
/// escapes (`\"`, `\\`, `\$`, `` \` ``) and `$(...)` / `` `...` ``
/// substitution, which is still recognized (and expanded by real shells)
/// inside double quotes. A `\"` does **not** close the string — only a bare
/// `"` does. An unterminated quote is the same conservative fallback as
/// above.
fn scan_double_quoted(chars: &mut Chars, out: &mut String, has_sub: &mut bool) {
    while let Some(c) = chars.next() {
        match c {
            '"' => return,
            '\\' => match chars.peek() {
                Some('"') => {
                    out.push('"');
                    chars.next();
                }
                Some('\\') => {
                    out.push('\\');
                    chars.next();
                }
                Some('$') => {
                    out.push('$');
                    chars.next();
                }
                Some('`') => {
                    out.push('`');
                    chars.next();
                }
                // Not one of the four escapable characters: the backslash
                // is literal and the following character (if any) is read
                // normally on the next loop iteration.
                _ => out.push('\\'),
            },
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                *has_sub = true;
                out.push_str("$(");
                out.push_str(&scan_paren_balanced(chars));
                out.push(')');
            }
            '`' => {
                *has_sub = true;
                out.push('`');
                out.push_str(&scan_backtick(chars));
                out.push('`');
            }
            other => out.push(other),
        }
    }
}

/// Scan a `$(...)` body. The opening `$(` has already been consumed; this
/// consumes up to and including the matching `)` and returns the inner text
/// (delimiters excluded). Never evaluated — just scanned for correct
/// boundaries. Tracks paren depth, and skips over nested quotes so a `)`
/// inside a quoted string within the substitution does not prematurely end
/// it (`$(echo ")")` stays one substitution).
fn scan_paren_balanced(chars: &mut Chars) -> String {
    let mut depth = 1u32;
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            '(' => {
                depth += 1;
                out.push(c);
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return out;
                }
                out.push(c);
            }
            '\\' => {
                out.push(c);
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            '\'' => {
                out.push(c);
                for n in chars.by_ref() {
                    out.push(n);
                    if n == '\'' {
                        break;
                    }
                }
            }
            '"' => {
                out.push(c);
                loop {
                    match chars.next() {
                        Some('\\') => {
                            out.push('\\');
                            if let Some(n) = chars.next() {
                                out.push(n);
                            }
                        }
                        Some('"') => {
                            out.push('"');
                            break;
                        }
                        Some(n) => out.push(n),
                        None => break,
                    }
                }
            }
            other => out.push(other),
        }
    }
    // Unterminated: return everything scanned (fail-safe fallback).
    out
}

/// Scan a `` `...` `` body. The opening backtick has already been consumed;
/// this consumes up to and including the matching closing backtick and
/// returns the inner text. `\` escapes the next character (so `` \` ``
/// does not close it).
fn scan_backtick(chars: &mut Chars) -> String {
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            '`' => return out,
            '\\' => {
                out.push(c);
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// If `text` (an already-resolved `Word`'s text, or a slice of one) is
/// *entirely* one command-substitution region — `$(...)` or `` `...` ``,
/// with nothing concatenated before or after it — return the substitution's
/// raw, unevaluated inner text. Returns `None` for anything else, including
/// a substitution that is only part of a larger concatenated word
/// (`prefix$(cmd)suffix`) or a word with no substitution at all.
///
/// Reuses the same balanced-scanning the lexer used to build `text` in the
/// first place (`scan_paren_balanced`/`scan_backtick`), so a nested
/// substitution (`$(echo $(date))`) or one containing a quoted `)` is
/// delimited identically here and during the original tokenization —
/// there's no second, drifting notion of "balanced".
///
/// Used by `crate::subst` to detect a command substitution occupying
/// *command position* (`$(rm -rf /)`, or the value of a `NAME=$(...)`
/// assignment word) — a shape the original tokenizer only ever *flags*
/// (`has_substitution`) but does not otherwise interpret.
pub(crate) fn pure_substitution_body(text: &str) -> Option<String> {
    let mut chars = text.chars().peekable();
    match chars.next()? {
        '$' if chars.peek() == Some(&'(') => {
            chars.next(); // consume '('
            let inner = scan_paren_balanced(&mut chars);
            if chars.next().is_none() {
                Some(inner)
            } else {
                None // trailing text after the substitution: not "pure"
            }
        }
        '`' => {
            let inner = scan_backtick(&mut chars);
            if chars.next().is_none() {
                Some(inner)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract the raw, unevaluated inner text of *every* command-substitution
/// region — `$(...)` or `` `...` `` — found anywhere in `text`, left to
/// right. Unlike `pure_substitution_body`, `text` does not need to be
/// entirely one substitution: this finds every occurrence regardless of
/// what surrounds it — a prefix/suffix concatenated onto the same word
/// (`pre$(cmd)post`), several substitutions in one word (`$(a)$(b)`), or a
/// substitution nested inside grouping syntax (`$( ( cmd ) )`, itself just
/// more raw text to this scan). A real shell evaluates every one of these
/// eagerly wherever it sits — command position or argument, quoted or
/// bare, guarded command or not — so the caller recurses into each
/// returned string through the whole pipeline rather than only asking
/// "does the whole word reduce to one substitution" the way
/// `pure_substitution_body` does.
///
/// Reuses the lexer's own balanced scanners (`scan_paren_balanced`,
/// `scan_backtick`), so nesting and quoted delimiters inside a
/// substitution are delimited identically here and during the original
/// tokenization — there is no second, drifting notion of "balanced".
pub(crate) fn find_all_substitutions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '$' if chars.peek() == Some(&'(') => {
                chars.next(); // consume '('
                out.push(scan_paren_balanced(&mut chars));
            }
            '`' => {
                out.push(scan_backtick(&mut chars));
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod find_all_substitutions_tests {
    use super::find_all_substitutions;

    #[test]
    fn finds_a_single_bare_dollar_paren() {
        assert_eq!(
            find_all_substitutions("$(rm -rf /)"),
            vec!["rm -rf /".to_string()]
        );
    }

    #[test]
    fn finds_a_single_bare_backtick() {
        assert_eq!(
            find_all_substitutions("`rm -rf /`"),
            vec!["rm -rf /".to_string()]
        );
    }

    #[test]
    fn finds_a_substitution_concatenated_with_a_prefix_and_suffix() {
        assert_eq!(
            find_all_substitutions("pre$(rm -rf /)post"),
            vec!["rm -rf /".to_string()]
        );
        assert_eq!(
            find_all_substitutions("$(rm -rf /)suffix"),
            vec!["rm -rf /".to_string()]
        );
    }

    #[test]
    fn finds_multiple_substitutions_in_one_word() {
        assert_eq!(
            find_all_substitutions("$(rm -rf /)-$(git reset --hard)"),
            vec!["rm -rf /".to_string(), "git reset --hard".to_string()]
        );
    }

    #[test]
    fn finds_a_substitution_wrapping_a_grouped_subshell() {
        assert_eq!(
            find_all_substitutions("$( ( rm -rf / ) )"),
            vec![" ( rm -rf / ) ".to_string()]
        );
    }

    #[test]
    fn plain_text_yields_nothing() {
        assert!(find_all_substitutions("plain-text").is_empty());
        assert!(find_all_substitutions("").is_empty());
    }

    #[test]
    fn dollar_brace_param_expansion_is_not_a_substitution() {
        // `${HOME}` is parameter-expansion syntax, not a `$(...)`
        // substitution — must not be misdetected as one.
        assert!(find_all_substitutions("${HOME}").is_empty());
    }
}

#[cfg(test)]
mod pure_substitution_body_tests {
    use super::pure_substitution_body;

    #[test]
    fn bare_dollar_paren_is_pure() {
        assert_eq!(
            pure_substitution_body("$(rm -rf /)"),
            Some("rm -rf /".to_string())
        );
    }

    #[test]
    fn bare_backtick_is_pure() {
        assert_eq!(
            pure_substitution_body("`rm -rf /`"),
            Some("rm -rf /".to_string())
        );
    }

    #[test]
    fn nested_dollar_paren_is_pure_and_keeps_inner_raw() {
        assert_eq!(
            pure_substitution_body("$(echo $(date))"),
            Some("echo $(date)".to_string())
        );
    }

    #[test]
    fn trailing_text_after_substitution_is_not_pure() {
        assert_eq!(pure_substitution_body("$(rm -rf /)suffix"), None);
    }

    #[test]
    fn leading_text_before_substitution_is_not_pure() {
        assert_eq!(pure_substitution_body("prefix$(rm -rf /)"), None);
    }

    #[test]
    fn plain_word_is_not_pure() {
        assert_eq!(pure_substitution_body("rm"), None);
        assert_eq!(pure_substitution_body(""), None);
    }

    #[test]
    fn quoted_close_paren_inside_substitution_does_not_end_it_early() {
        assert_eq!(
            pure_substitution_body(r#"$(echo ")")"#),
            Some(r#"echo ")""#.to_string())
        );
    }
}

/// `$'...'` ANSI-C-quoted string body. The opening `$'` has already been
/// consumed. Decodes the common bash escapes (`\n \t \r \a \b \f \v \\ \'`,
/// `\xHH` up to two hex digits, `\0NNN` up to three octal digits) and copies
/// every other character — including a literal `/` — straight through. An
/// escape this scanner doesn't know is kept literally as `\<char>` rather
/// than guessed at (documented as a known limitation: `\uXXXX`, `\UXXXXXXXX`,
/// `\cX`, `\eE` are not decoded). Terminated by the first unescaped `'`; an
/// unterminated string is the same conservative fallback as the other quote
/// scanners — everything scanned becomes the word's content.
fn scan_ansi_c_quoted(chars: &mut Chars, out: &mut String) {
    while let Some(c) = chars.next() {
        match c {
            '\'' => return,
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('a') => out.push('\u{7}'),
                Some('b') => out.push('\u{8}'),
                Some('f') => out.push('\u{c}'),
                Some('v') => out.push('\u{b}'),
                Some('\\') => out.push('\\'),
                Some('\'') => out.push('\''),
                Some('x') => push_escaped_digits(chars, out, 16, 2),
                Some('0') => push_escaped_digits(chars, out, 8, 3),
                Some(other) => {
                    // Unrecognized escape: keep it literal rather than guess.
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            other => out.push(other),
        }
    }
}

/// Consume up to `max_digits` digits of the given `radix` from `chars` and
/// push the decoded character to `out`. Used for `\xHH` (radix 16) and
/// `\0NNN` (radix 8) inside `$'...'`. If zero digits are found, the escape
/// is kept literal (`\x` / `\0` with nothing valid after it).
fn push_escaped_digits(chars: &mut Chars, out: &mut String, radix: u32, max_digits: u32) {
    let mut val: u32 = 0;
    let mut n = 0;
    while n < max_digits {
        match chars.peek().and_then(|d| d.to_digit(radix)) {
            Some(d) => {
                val = val * radix + d;
                chars.next();
                n += 1;
            }
            None => break,
        }
    }
    if n > 0 {
        if let Some(ch) = char::from_u32(val) {
            out.push(ch);
        }
    } else {
        out.push('\\');
        out.push(if radix == 16 { 'x' } else { '0' });
    }
}

/// Scan a `${...}` body. The opening `${` has already been consumed; this
/// consumes up to and including the matching `}` and returns the inner text
/// (delimiters excluded). Never evaluated — parameter expansion is out of
/// scope (see the design doc) — this exists solely so `${HOME}` survives as
/// one contiguous literal token instead of having its `{`/`}` mistaken for a
/// grouping boundary. Mirrors `scan_paren_balanced`'s quote/escape/nesting
/// handling so a `}` inside a nested quote or a nested `${...}` doesn't
/// prematurely end it.
fn scan_brace_balanced(chars: &mut Chars) -> String {
    let mut depth = 1u32;
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            '{' => {
                depth += 1;
                out.push(c);
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return out;
                }
                out.push(c);
            }
            '\\' => {
                out.push(c);
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            '\'' => {
                out.push(c);
                for n in chars.by_ref() {
                    out.push(n);
                    if n == '\'' {
                        break;
                    }
                }
            }
            '"' => {
                out.push(c);
                loop {
                    match chars.next() {
                        Some('\\') => {
                            out.push('\\');
                            if let Some(n) = chars.next() {
                                out.push(n);
                            }
                        }
                        Some('"') => {
                            out.push('"');
                            break;
                        }
                        Some(n) => out.push(n),
                        None => break,
                    }
                }
            }
            other => out.push(other),
        }
    }
    // Unterminated: return everything scanned (fail-safe fallback).
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(cmd: &str) -> Vec<String> {
        split_segments(cmd)
            .into_iter()
            .flatten()
            .map(|w| w.text)
            .collect()
    }

    fn segs(cmd: &str) -> Vec<Vec<String>> {
        split_segments(cmd)
            .into_iter()
            .map(|seg| seg.into_iter().map(|w| w.text).collect())
            .collect()
    }

    // ---- quoting ------------------------------------------------------

    #[test]
    fn single_quotes_are_fully_literal() {
        assert_eq!(words("echo 'a && b; c'"), vec!["echo", "a && b; c"]);
    }

    #[test]
    fn double_quotes_resolve_backslash_escapes() {
        assert_eq!(words(r#"echo "a\"b""#), vec!["echo", "a\"b"]);
        assert_eq!(words(r#"echo "a\\b""#), vec!["echo", "a\\b"]);
        assert_eq!(words(r#"echo "a\$b""#), vec!["echo", "a$b"]);
        assert_eq!(words(r#"echo "a\`b""#), vec!["echo", "a`b"]);
    }

    #[test]
    fn escaped_double_quote_does_not_close_the_string() {
        // Round-2 Critical #1: `\"` is data, not a terminator. The real
        // closing quote is the *next* bare `"`.
        assert_eq!(words(r#"echo "a\"""#), vec!["echo", "a\""]);
        assert_eq!(
            segs(r#"echo "a\"" ; rm -rf /"#),
            vec![
                vec!["echo".to_string(), "a\"".to_string()],
                vec!["rm".to_string(), "-rf".to_string(), "/".to_string()],
            ]
        );
    }

    #[test]
    fn unrecognized_backslash_escape_in_double_quotes_is_literal() {
        // \n is not one of the four POSIX double-quote escapes, so the
        // backslash and the character both survive.
        assert_eq!(words(r#"echo "a\nb""#), vec!["echo", "a\\nb"]);
    }

    #[test]
    fn backslash_outside_quotes_escapes_operators_as_data() {
        assert_eq!(segs(r"a \; rm -rf /"), vec![vec!["a", ";", "rm", "-rf", "/"]]);
        assert_eq!(segs(r"a \& rm -rf /"), vec![vec!["a", "&", "rm", "-rf", "/"]]);
    }

    // ---- adjacent-string concatenation ---------------------------------

    #[test]
    fn adjacent_strings_concatenate_into_one_argument() {
        assert_eq!(words(r#"rm -rf "/e"tc"#), vec!["rm", "-rf", "/etc"]);
        assert_eq!(words(r#"rm -rf /et"c""#), vec!["rm", "-rf", "/etc"]);
        assert_eq!(words(r#"rm -rf ""/"#), vec!["rm", "-rf", "/"]);
        assert_eq!(words(r#"rm -rf /""#), vec!["rm", "-rf", "/"]);
        assert_eq!(words(r#"rm -rf "/"//"#), vec!["rm", "-rf", "///"]);
    }

    // ---- operator splitting --------------------------------------------

    #[test]
    fn splits_on_and_and_and_or_or_and_semi_and_pipe() {
        assert_eq!(
            segs("echo hi && rm -rf /"),
            vec![vec!["echo", "hi"], vec!["rm", "-rf", "/"]]
        );
        assert_eq!(
            segs("a && b || rm -rf /"),
            vec![vec!["a"], vec!["b"], vec!["rm", "-rf", "/"]]
        );
        assert_eq!(segs("true; rm -rf ~"), vec![vec!["true"], vec!["rm", "-rf", "~"]]);
        assert_eq!(segs("foo | rm -rf /"), vec![vec!["foo"], vec!["rm", "-rf", "/"]]);
    }

    #[test]
    fn splits_with_no_surrounding_whitespace() {
        assert_eq!(segs("a&&rm -rf /"), vec![vec!["a"], vec!["rm", "-rf", "/"]]);
        assert_eq!(segs("a ;rm -rf /"), vec![vec!["a"], vec!["rm", "-rf", "/"]]);
    }

    #[test]
    fn splits_on_newline() {
        assert_eq!(
            segs("a\nrm -rf /"),
            vec![vec!["a"], vec!["rm", "-rf", "/"]]
        );
    }

    #[test]
    fn does_not_split_a_separator_inside_quotes() {
        assert_eq!(segs(r#"echo "a && b""#), vec![vec!["echo", "a && b"]]);
        assert_eq!(segs(r#"echo "a; b""#), vec![vec!["echo", "a; b"]]);
        assert_eq!(segs("echo 'a; b'"), vec![vec!["echo", "a; b"]]);
    }

    #[test]
    fn drops_empty_segments_from_consecutive_separators() {
        assert_eq!(segs("echo hi ;; echo bye"), vec![vec!["echo", "hi"], vec!["echo", "bye"]]);
    }

    #[test]
    fn unterminated_quote_keeps_remainder_as_one_word() {
        assert_eq!(
            segs("echo 'unterminated && rm -rf /"),
            vec![vec!["echo", "unterminated && rm -rf /"]]
        );
    }

    // ---- command substitution ------------------------------------------

    #[test]
    fn dollar_paren_is_opaque_and_flagged() {
        let segments = split_segments("rm -rf $(some-cmd)");
        assert_eq!(segments.len(), 1);
        let seg = &segments[0];
        assert_eq!(seg[2].text, "$(some-cmd)");
        assert!(seg[2].has_substitution);
        assert!(!seg[0].has_substitution);
    }

    #[test]
    fn separators_inside_dollar_paren_do_not_split_the_segment() {
        let segments = segs("echo $(a; b && c) more");
        assert_eq!(segments.len(), 1, "got {segments:?}");
    }

    #[test]
    fn dollar_paren_inside_double_quotes_is_still_opaque() {
        let segments = split_segments(r#"echo "$(date)""#);
        assert_eq!(segments.len(), 1);
        let seg = &segments[0];
        assert_eq!(seg[1].text, "$(date)");
        assert!(seg[1].has_substitution);
    }

    #[test]
    fn backtick_substitution_is_opaque_and_flagged() {
        let segments = split_segments("echo `date`");
        let seg = &segments[0];
        assert_eq!(seg[1].text, "`date`");
        assert!(seg[1].has_substitution);
    }

    #[test]
    fn nested_parens_in_substitution_stay_balanced() {
        let segments = segs("echo $(echo $(date))");
        assert_eq!(segments.len(), 1);
    }

    // ---- grouping / compound-command boundaries ------------------------

    #[test]
    fn parens_are_segment_boundaries_with_and_without_whitespace() {
        assert_eq!(segs("( rm -rf / )"), vec![vec!["rm", "-rf", "/"]]);
        assert_eq!(segs("(rm -rf /)"), vec![vec!["rm", "-rf", "/"]]);
    }

    #[test]
    fn braces_are_segment_boundaries() {
        assert_eq!(segs("{ rm -rf /; }"), vec![vec!["rm", "-rf", "/"]]);
        assert_eq!(segs("{ ls; }"), vec![vec!["ls"]]);
    }

    #[test]
    fn leading_then_do_else_elif_are_stripped_revealing_the_real_command() {
        assert_eq!(
            segs("if true; then rm -rf /; fi"),
            vec![vec!["if", "true"], vec!["rm", "-rf", "/"], vec!["fi"]]
        );
        assert_eq!(
            segs("for i in 1; do rm -rf /; done"),
            vec![
                vec!["for", "i", "in", "1"],
                vec!["rm", "-rf", "/"],
                vec!["done"]
            ]
        );
        assert_eq!(
            segs("while true; do rm -rf /; done"),
            vec![vec!["while", "true"], vec!["rm", "-rf", "/"], vec!["done"]]
        );
    }

    #[test]
    fn grouping_chars_inside_quotes_or_escaped_are_data_not_boundaries() {
        assert_eq!(segs(r#"echo "(a)""#), vec![vec!["echo", "(a)"]]);
        assert_eq!(segs(r#"echo "{x}""#), vec![vec!["echo", "{x}"]]);
        assert_eq!(segs("echo '(a)'"), vec![vec!["echo", "(a)"]]);
        assert_eq!(segs(r"echo \(a\)"), vec![vec!["echo", "(a)"]]);
    }

    #[test]
    fn dollar_paren_is_unaffected_by_new_grouping_boundaries() {
        // `$(` is already consumed whole by the command-substitution scanner
        // before the bare `(` boundary arm ever sees it.
        let segments = split_segments("rm -rf $(some-cmd)");
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0][2].text, "$(some-cmd)");
    }

    #[test]
    fn dollar_brace_param_expansion_is_not_a_grouping_boundary() {
        // `${HOME}` must survive as one literal token — pack rules like
        // `\$\{HOME\}` depend on it, and real bash doesn't treat this `{`/`}`
        // as a command grouping brace either.
        assert_eq!(words("rm -rf ${HOME}"), vec!["rm", "-rf", "${HOME}"]);
    }

    #[test]
    fn ordinary_command_ls_inside_grouping_still_allows_shape() {
        // Not a bypass check — just confirms grouping doesn't mis-segment a
        // benign command (regression guard for the ALLOW side of the corpus).
        assert_eq!(segs("( ls )"), vec![vec!["ls"]]);
        assert_eq!(
            segs("for i in 1; do echo hi; done"),
            vec![vec!["for", "i", "in", "1"], vec!["echo", "hi"], vec!["done"]]
        );
    }

    // ---- $'...' ANSI-C quoting ------------------------------------------

    #[test]
    fn dollar_single_quote_literal_slash() {
        assert_eq!(words("rm -rf $'/'"), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn dollar_single_quote_decodes_hex_escape() {
        assert_eq!(words(r"rm -rf $'\x2f'"), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn dollar_single_quote_decodes_common_escapes() {
        assert_eq!(words(r"echo $'a\tb\nc'"), vec!["echo", "a\tb\nc"]);
        assert_eq!(words(r"echo $'a\\b'"), vec!["echo", "a\\b"]);
        assert_eq!(words(r"echo $'a\'b'"), vec!["echo", "a'b"]);
    }

    #[test]
    fn dollar_single_quote_decodes_octal_escape() {
        // \057 octal == 0x2f == '/'
        assert_eq!(words(r"rm -rf $'\057'"), vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn dollar_single_quote_unrecognized_escape_kept_literal() {
        assert_eq!(words(r"echo $'a\ub'"), vec!["echo", "a\\ub"]);
    }

    #[test]
    fn dollar_single_quote_concatenates_adjacent_like_other_quotes() {
        assert_eq!(words(r"rm -rf $'/e'tc"), vec!["rm", "-rf", "/etc"]);
    }
}
