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
//!   Where the region ends is found by lexing the body with this same
//!   state machine (a nested frame), so a quote, comment or here-document
//!   inside it (`"$(cat <<'EOF'` / `it's` / `EOF` / `)"`) is read exactly
//!   as at the top level.
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
//! - **Redirections** are their own tokens (`echo x>f` is `echo x > f`);
//!   **assignment words** (`NAME=`, `NAME+=`, `NAME[…]=`) are flagged;
//!   unquoted **brace expansions** (`{a,b}`) are expanded (bounded);
//!   **here-document bodies** are skipped as data unless a shell on the
//!   same line reads them (`bash <<EOF`), then they are lexed as commands.
//!
//! ## What it deliberately does not do
//!
//! No shell grammar beyond the above: no variable expansion (`$VAR`,
//! `${VAR}` are left as literal, unevaluated text), no glob expansion (the
//! engine expands operand globs itself), no evaluating what a substitution
//! would actually output, and
//! grouping/keyword handling is a boundary heuristic, not a parser for `if`/
//! `for`/`while`/`case` compound-command grammar. See the design doc's
//! "known limitations" for the honest scope.

/// One resolved argv token (a word): the fully concatenated, quote/escape
/// resolved text, plus whether it contains an opaque command-substitution
/// region (`$(...)` or `` `...` ``) that the guard could not look inside.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Word {
    pub text: String,
    pub has_substitution: bool,
    /// An unquoted redirection operator (`>`, `2>>`, `&>`, `<`, `<<<`,
    /// `2>&`, …), split off even when written without spaces
    /// (`echo x>f`); its target is the next word. A quoted `">"` is a
    /// plain word.
    pub redirect: bool,
    /// Contains an unquoted glob character (`*`, `?`, `[`), so the shell
    /// would expand it against the filesystem.
    pub glob: bool,
    /// A shell assignment word as bash sees it: an unquoted `NAME=`,
    /// `NAME+=`, `NAME[…]=` or `NAME[…]+=` prefix. In front of a command
    /// it sets a variable; it is not the command.
    pub assignment: bool,
    /// Its brace expansion was too large to expand (kept as written); the
    /// engine records the command as not fully judged.
    pub brace_overflow: bool,
    /// Some part of it was quoted or escaped.
    pub quoted: bool,
    /// The whole word is one double-quoted substitution, `"$(…)"` or
    /// ``"`…`"``: its value is one word, never split on blanks or globbed.
    /// (`$(…)""` is not: there the substitution itself is unquoted.)
    pub dq_substitution: bool,
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
    split_segments_noted(cmd).0
}

/// `split_segments`, plus why part of the line could not be lexed exactly
/// (`(( … ))` too long to tell arithmetic from subshells, substitutions
/// or here-documents nested too deeply). The caller records it as a
/// fail-open unless something else denies.
pub fn split_segments_noted(cmd: &str) -> (Vec<Segment>, Option<&'static str>) {
    split_noted(cmd, Ctx::new())
}

/// `split_segments_noted` for the body of a `$(…)` (the text between its
/// parentheses): here-documents end as bash ends them inside one.
pub fn split_substitution_noted(cmd: &str) -> (Vec<Segment>, Option<&'static str>) {
    split_noted(
        cmd,
        Ctx {
            sub_body: true,
            ..Ctx::new()
        },
    )
}

fn split_noted(cmd: &str, mut ctx: Ctx) -> (Vec<Segment>, Option<&'static str>) {
    let mut segments: Vec<Segment> = Vec::new();
    let mut current: Segment = Vec::new();
    let toks = lex_in(&mut Chars::new(cmd), &mut ctx, 0, false, false).toks;

    for tok in toks {
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
    (
        segments.into_iter().map(strip_leading_keywords).collect(),
        ctx.note,
    )
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

/// State shared by every lexer frame of one command line: the nested
/// frames of `$(…)` bodies and here-documents read as commands, and the
/// `((` look-aheads.
struct Ctx {
    /// Bytes the `((`/`$((` look-aheads may still read, all together.
    arith_budget: usize,
    /// Why part of the line could not be lexed exactly (the first reason).
    note: Option<&'static str>,
    /// The whole line is the body of a `$(…)`.
    sub_body: bool,
}

impl Ctx {
    fn new() -> Ctx {
        Ctx {
            arith_budget: ARITH_LOOKAHEAD_TOTAL,
            note: None,
            sub_body: false,
        }
    }

    fn note(&mut self, reason: &'static str) {
        self.note.get_or_insert(reason);
    }
}

/// What one lexer frame produced.
struct Frame {
    toks: Vec<LexTok>,
    /// Here-documents whose bodies start after the line the frame ended
    /// on (`"$(cat <<EOF)"` followed by the body): the enclosing frame
    /// reads them at its next newline. Their consumer is already decided.
    pending: Vec<PendingDoc>,
    /// A `$(…)` frame ended at its closing `)` (consumed), not at the end.
    closed: bool,
}

/// Frames nested inside each other (`$(…)` bodies, here-documents read as
/// commands) at most; deeper ones are scanned without here-document
/// awareness and the line is recorded as not fully judged.
const MAX_FRAME_DEPTH: usize = 32;
const TOO_DEEP: &str = "command substitution nested too deeply to judge";
const ARITH_TOO_LONG: &str = "arithmetic too long to judge";

/// Tokenize command text into words and operators, in order, reading
/// from `chars`. The whole line is one frame; the body of every `$(…)`
/// is lexed by a nested frame of this same state machine (`sub`), which
/// ends at the `)` that closes it, so quotes, here-documents and comments
/// inside a substitution are understood exactly as at the top level
/// (`"$(cat <<'EOF'` / `it's` / `EOF` / `)"`). `flat_arith`: the frame
/// starts inside a `$((` whose look-ahead was cut off (see `no_docs_above`).
#[allow(unused_assignments)] // the final flush_word!() sets state that is never read again
fn lex_in(chars: &mut Chars, ctx: &mut Ctx, depth: usize, sub: bool, flat_arith: bool) -> Frame {
    let mut toks: Vec<LexTok> = Vec::new();
    // Open `(` operators of this frame; in a `$(…)` frame, a `)` with
    // none open closes the substitution.
    let mut parens = 0usize;
    let mut closed = false;
    // End (in `word_text`) of a double-quoted region that was exactly one
    // substitution and the word's first piece: `"$(…)"`.
    let mut dq_sub_end: Option<usize> = None;

    let mut word_text = String::new();
    let mut word_has_sub = false;
    let mut in_word = false;
    // The word so far has a quoted or escaped piece (so `"2">f` is the
    // word `2`, not descriptor 2), or an unquoted glob character.
    let mut word_quoted = false;
    let mut word_glob = false;
    // The first unquoted `=` decides whether the word is an assignment.
    let mut word_eq_seen = false;
    let mut word_assignment = false;
    // Inside the `[…]` subscript of a would-be `NAME[…]=` assignment:
    // quotes, substitutions and `=` there do not decide anything.
    let mut subscript_depth = 0usize;
    let mut word_subscripted = false;
    // Byte offsets in `word_text` of the word's unquoted brace-expansion
    // `{`, `,` and `}`: only these separate alternatives (`{".env",x}`,
    // `{a\,b,c}`, `"{a,b}"` behave as in bash).
    let mut brace_marks: Vec<usize> = Vec::new();
    // Unquoted `{` of this word not yet closed.
    let mut brace_depth = 0usize;
    // Here-documents: the next word is a delimiter (`Some(strip_tabs)` after
    // `<<`/`<<-`), and the delimiters whose bodies start after this line.
    let mut expect_delim: Option<bool> = None;
    let mut pending_docs: Vec<PendingDoc> = Vec::new();
    // Between `[[` and `]]`, `<` and `>` compare strings.
    let mut in_test = false;
    // Inside a `((` whose look-ahead was cut off (lexed as the subshells
    // it may be), while `parens` is above this level: it may be
    // arithmetic, where `<<` is a shift, so `<<` opens no here-document.
    let mut no_docs_above: Option<usize> = flat_arith.then_some(0);
    // `case WORD in`: open `case` commands, whether the next word is the
    // `in`, and whether a pattern is being read (after `in`, `;;`, `;&`,
    // `;;&`), whose `)` ends the pattern and never closes a `$(…)`.
    let mut case_depth = 0usize;
    let mut case_await_in = false;
    let mut case_pattern = false;

    // Flush the in-progress word (if any) as a completed token.
    macro_rules! flush_word {
        () => {
            if in_word {
                let dq_substitution = dq_sub_end == Some(word_text.len());
                let word = Word {
                    text: std::mem::take(&mut word_text),
                    has_substitution: word_has_sub,
                    redirect: false,
                    glob: word_glob,
                    assignment: word_assignment,
                    brace_overflow: false,
                    quoted: word_quoted,
                    dq_substitution,
                };
                // Brace expansion happens before anything else looks at
                // the words: `{rm,-rf,/}` runs `rm -rf /`. Past the limits
                // the word stays as written, flagged for the engine.
                if let Some(strip_tabs) = expect_delim.take() {
                    pending_docs.push(PendingDoc {
                        delim: word.text.clone(),
                        strip_tabs,
                        // `<<'EOF'`, `<<"EOF"`, `<<\EOF`: no expansion.
                        quoted: word_quoted,
                        op: toks.len().saturating_sub(1),
                        commands: None,
                    });
                }
                if !word_quoted {
                    match word.text.as_str() {
                        "case" if starts_a_command(&current_segment(&toks)) => {
                            case_depth += 1;
                            case_await_in = true;
                        }
                        "in" if case_await_in => {
                            case_await_in = false;
                            case_pattern = true;
                        }
                        "esac"
                            if case_depth > 0
                                && (case_pattern || starts_a_command(&current_segment(&toks))) =>
                        {
                            case_depth -= 1;
                            case_pattern = false;
                        }
                        _ => {}
                    }
                }
                if !word_quoted && word.text == "[[" {
                    // A reserved word only where a command starts: first,
                    // or after reserved words that start one (`if`, `!`,
                    // `time`, …). `echo [[`, `env [[`, `sudo [[` and (as
                    // in bash) `FOO=1 [[` are a command and its arguments.
                    in_test = starts_a_command(&current_segment(&toks));
                } else if !word_quoted && word.text == "]]" {
                    in_test = false;
                }
                if brace_marks.is_empty() {
                    toks.push(LexTok::Word(word));
                } else {
                    match crate::canon::expand_marked(&word.text, &brace_marks) {
                        Some(words) => toks.extend(words.into_iter().map(|text| {
                            LexTok::Word(Word {
                                text,
                                ..word.clone()
                            })
                        })),
                        None => toks.push(LexTok::Word(Word {
                            brace_overflow: true,
                            ..word
                        })),
                    }
                }
                brace_marks.clear();
                brace_depth = 0;
                dq_sub_end = None;
                in_word = false;
                word_has_sub = false;
                word_quoted = false;
                word_glob = false;
                word_eq_seen = false;
                word_assignment = false;
                subscript_depth = 0;
                word_subscripted = false;
            }
        };
    }

    while let Some(c) = chars.next() {
        // A list or pipeline operator ends a `[[ … ]]` test.
        if in_test && matches!(toks.last(), Some(LexTok::Operator(_))) {
            in_test = false;
        }
        match c {
            ' ' | '\t' | '\r' => flush_word!(),
            '\n' => {
                flush_word!();
                toks.push(LexTok::Operator(Operator::Newline));
                for doc in std::mem::take(&mut pending_docs) {
                    // The body is commands when a shell in its pipeline
                    // reads it (or that cannot be known); otherwise data,
                    // whose `$(…)`/backticks still run unless the delimiter
                    // was quoted.
                    let body = read_heredoc(
                        chars,
                        &doc.delim,
                        doc.strip_tabs,
                        sub || ctx.sub_body,
                        ctx.sub_body,
                    );
                    let commands = doc
                        .commands
                        .unwrap_or_else(|| body_is_commands(&toks, doc.op));
                    if commands && depth + 1 >= MAX_FRAME_DEPTH {
                        ctx.note(TOO_DEEP);
                    } else if commands {
                        let inner = lex_in(&mut Chars::new(&body), ctx, depth + 1, false, false);
                        toks.extend(inner.toks);
                        toks.push(LexTok::Operator(Operator::Newline));
                    } else if !doc.quoted {
                        for inner in find_subs(&body, ctx, depth) {
                            toks.push(LexTok::Word(Word {
                                text: format!("$({inner})"),
                                has_substitution: true,
                                ..Word::default()
                            }));
                            toks.push(LexTok::Operator(Operator::Newline));
                        }
                    }
                }
            }
            '&' if chars.peek() == Some('>') => {
                // `&>f` / `&>>f`: stdout and stderr to a file.
                flush_word!();
                chars.next();
                let mut op = String::from("&>");
                if chars.peek() == Some('>') {
                    chars.next();
                    op.push('>');
                }
                toks.push(redirect_tok(op));
            }
            // `[[ a < b ]]` compares strings.
            '<' | '>' if in_test => {
                in_word = true;
                word_text.push(c);
            }
            '<' | '>' if chars.peek() == Some('(') => {
                // Process substitution `<(cmd)` / `>(cmd)`: not a file; its
                // `(` opens its own segment (never arithmetic: `<((x))`).
                flush_word!();
                chars.next();
                parens += 1;
                toks.push(LexTok::Operator(Operator::LParen));
            }
            '<' | '>' => {
                // A word of bare digits right before the operator is its
                // descriptor (`2>f`); anything else ends the word (`x>f`).
                let fd = in_word
                    && !word_quoted
                    && !word_has_sub
                    && word_text.bytes().all(|b| b.is_ascii_digit());
                let mut op = if fd {
                    in_word = false;
                    word_glob = false;
                    std::mem::take(&mut word_text)
                } else {
                    flush_word!();
                    String::new()
                };
                op.push(c);
                scan_redirection(chars, c, &mut op);
                let docs_allowed = no_docs_above.is_none_or(|b| parens <= b);
                match op.trim_start_matches(|c: char| c.is_ascii_digit()) {
                    "<<" if docs_allowed => expect_delim = Some(false),
                    "<<-" if docs_allowed => expect_delim = Some(true),
                    _ => {}
                }
                toks.push(redirect_tok(op));
            }
            '&' => {
                if chars.peek() == Some('&') {
                    chars.next();
                    flush_word!();
                    toks.push(LexTok::Operator(Operator::AndAnd));
                } else {
                    flush_word!();
                    toks.push(LexTok::Operator(Operator::Amp));
                }
            }
            '|' => {
                if chars.peek() == Some('|') {
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
                // `;;`, `;&`, `;;&` end a case arm: a pattern follows.
                if case_depth > 0 && matches!(chars.peek(), Some(';' | '&')) {
                    case_pattern = true;
                }
                toks.push(LexTok::Operator(Operator::Semi));
            }
            // `(( … ))`: arithmetic, where `<<` is a shift. One opaque word;
            // substitutions inside it are still found and judged.
            // Only with a real closing `))`; otherwise, as in bash, two
            // nested subshells: `((cat .env); true)`.
            '(' if !in_word && chars.peek() == Some('(') => {
                chars.next();
                // Look ahead (bounded) for the real `))`; the subshell
                // case is then lexed inline, sharing here-doc and test
                // state with the rest of the line.
                match arith_lookahead(chars, ctx, depth) {
                    Arith::Closes(len, docs) => {
                        // Here-documents opened in its substitutions are
                        // read after this line, as in bash.
                        pending_docs.extend(docs);
                        let body = &chars.rest()[..len - 2];
                        chars.skip_bytes(len);
                        in_word = true;
                        word_has_sub |= body.contains("$(") || body.contains('`');
                        word_text.push_str("((");
                        word_text.push_str(body);
                        word_text.push_str("))");
                        flush_word!();
                    }
                    other => {
                        // Too long to tell: judged as the subshells it may
                        // be, and recorded.
                        if other == Arith::TooLong {
                            ctx.note(ARITH_TOO_LONG);
                            no_docs_above.get_or_insert(parens);
                        }
                        parens += 2;
                        toks.push(LexTok::Operator(Operator::LParen));
                        toks.push(LexTok::Operator(Operator::LParen));
                    }
                }
            }
            '(' => {
                flush_word!();
                // A pattern's optional leading `(` (`(a) cmd;;`) is not
                // matched by the `)` that ends the pattern.
                if !case_pattern {
                    parens += 1;
                }
                toks.push(LexTok::Operator(Operator::LParen));
            }
            ')' => {
                flush_word!();
                if case_pattern {
                    case_pattern = false;
                    toks.push(LexTok::Operator(Operator::RParen));
                    continue;
                }
                if sub && parens == 0 {
                    closed = true;
                    break;
                }
                parens = parens.saturating_sub(1);
                if no_docs_above.is_some_and(|b| parens <= b) && !flat_arith {
                    no_docs_above = None;
                }
                toks.push(LexTok::Operator(Operator::RParen));
            }
            // `{` alone (followed by a blank or the end) opens a group,
            // like bash's reserved word; otherwise it is part of a word,
            // possibly a brace expansion.
            '{' if !in_word
                && chars
                    .peek()
                    .is_none_or(|n| matches!(n, ' ' | '\t' | '\r' | '\n')) =>
            {
                toks.push(LexTok::Operator(Operator::LBrace));
            }
            '{' => {
                in_word = true;
                brace_depth += 1;
                brace_marks.push(word_text.len());
                word_text.push('{');
            }
            ',' if brace_depth > 0 => {
                brace_marks.push(word_text.len());
                word_text.push(',');
            }
            '}' if brace_depth > 0 => {
                brace_depth -= 1;
                brace_marks.push(word_text.len());
                word_text.push('}');
            }
            // `}` starting a word closes a group; inside a word it is data.
            '}' if !in_word => {
                toks.push(LexTok::Operator(Operator::RBrace));
            }
            '\'' => {
                in_word = true;
                word_quoted = true;
                scan_single_quoted(chars, &mut word_text);
            }
            '"' => {
                let first = !in_word;
                in_word = true;
                word_quoted = true;
                let only_sub = scan_double_quoted(
                    chars,
                    &mut word_text,
                    &mut word_has_sub,
                    ctx,
                    depth,
                    &mut pending_docs,
                );
                if first && only_sub {
                    dq_sub_end = Some(word_text.len());
                }
            }
            '\\' => {
                in_word = true;
                word_quoted = true;
                // Outside quotes, `\<char>` is a literal `<char>` — this is
                // what keeps `\;` and `\&` from being read as operators. A
                // trailing backslash with nothing after it is kept literal.
                match chars.next() {
                    Some(n) => word_text.push(n),
                    None => word_text.push('\\'),
                }
            }
            // `$[ … ]`: old-style arithmetic, opaque like `$(( … ))`.
            '$' if chars.peek() == Some('[') => {
                chars.next();
                in_word = true;
                word_text.push_str("$[");
                let mut depth = 1usize;
                for n in chars.by_ref() {
                    word_text.push(n);
                    match n {
                        '[' => depth += 1,
                        ']' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                word_has_sub |= word_text.contains("$(") || word_text.contains('`');
            }
            // `#` starting a word comments out the rest of the line.
            '#' if !in_word => {
                while chars.peek().is_some_and(|n| n != '\n') {
                    chars.next();
                }
            }
            '$' if chars.peek() == Some('(') => {
                chars.next(); // consume '('
                in_word = true;
                word_has_sub = true;
                word_text.push_str("$(");
                word_text.push_str(scan_substitution(chars, ctx, depth, &mut pending_docs));
                word_text.push(')');
            }
            '$' if chars.peek() == Some('\'') => {
                chars.next(); // consume the opening '\''
                in_word = true;
                word_quoted = true;
                scan_ansi_c_quoted(chars, &mut word_text);
            }
            '$' if chars.peek() == Some('{') => {
                // `${...}` parameter expansion: not evaluated (no variable
                // expansion, per the design doc's scope), but its `{`/`}`
                // are NOT a grouping boundary the way a bare `{`/`}` is —
                // real bash doesn't treat them as one either, and pack rules
                // like `\$\{HOME\}` depend on `${HOME}` surviving as one
                // contiguous literal token.
                chars.next(); // consume '{'
                in_word = true;
                word_text.push_str("${");
                word_text.push_str(&scan_brace_balanced(chars));
                word_text.push('}');
            }
            '`' => {
                in_word = true;
                word_has_sub = true;
                word_text.push('`');
                word_text.push_str(&scan_backtick(chars));
                word_text.push('`');
            }
            '[' if subscript_depth > 0 => {
                subscript_depth += 1;
                word_text.push('[');
            }
            ']' if subscript_depth > 0 => {
                subscript_depth -= 1;
                word_text.push(']');
                if subscript_depth == 0 {
                    // The name before `[` was unquoted (checked on entry).
                    word_quoted = false;
                    word_subscripted = true;
                }
            }
            '[' if in_word
                && !word_eq_seen
                && !word_quoted
                && !word_has_sub
                && !word_subscripted
                && is_assignment_name(&word_text) =>
            {
                subscript_depth = 1;
                word_glob = true;
                word_text.push('[');
            }
            '=' if !word_eq_seen && subscript_depth == 0 => {
                word_eq_seen = true;
                word_assignment = in_word
                    && !word_quoted
                    && (!word_has_sub || word_subscripted)
                    && is_assignment_name(&word_text);
                in_word = true;
                word_text.push('=');
            }
            other => {
                in_word = true;
                word_glob |= matches!(other, '*' | '?' | '[');
                word_text.push(other);
            }
        }
    }
    flush_word!();
    // Here-documents still waiting for their body leave with the frame,
    // their consumer decided from this frame's tokens.
    if !pending_docs.is_empty() {
        toks.push(LexTok::Operator(Operator::Newline));
        for doc in &mut pending_docs {
            if doc.commands.is_none() {
                doc.commands = Some(body_is_commands(&toks, doc.op));
            }
        }
        toks.pop();
    }
    Frame {
        toks,
        pending: pending_docs,
        closed,
    }
}

/// A here-document whose body starts after the current line.
#[derive(Debug, PartialEq, Eq)]
struct PendingDoc {
    delim: String,
    strip_tabs: bool,
    quoted: bool,
    /// Index in the tokens of its `<<` operator.
    op: usize,
    /// Whether the body is commands, when already decided (a here-document
    /// opened inside a `$(…)` frame that has ended).
    commands: Option<bool>,
}

/// Where a `((` (or `$((`) look-ahead ended.
#[derive(Debug, PartialEq, Eq)]
enum Arith {
    /// Arithmetic: the body and the closing `))` are this many bytes; the
    /// here-documents its substitutions opened (their bodies follow the
    /// line).
    Closes(usize, Vec<PendingDoc>),
    /// Not arithmetic: nested subshells.
    Subshell,
    /// Not decided within the look-ahead's bounds.
    TooLong,
}

/// Bytes one `((` look-ahead reads at most.
const ARITH_LOOKAHEAD_BYTES: usize = 4096;
/// Bytes all look-aheads of one command line read at most.
const ARITH_LOOKAHEAD_TOTAL: usize = 64 * ARITH_LOOKAHEAD_BYTES;

/// After `((`: does the body end with a real `))` (arithmetic), or with a
/// `)` followed by something else (two subshells, `((cat x); y)`)? Reads
/// a bounded window of the input; quotes, substitutions and the
/// here-documents in them are skipped as the lexer would.
fn arith_lookahead(chars: &Chars, ctx: &mut Ctx, depth: usize) -> Arith {
    let rest = chars.rest();
    let mut cut = ctx.arith_budget.min(ARITH_LOOKAHEAD_BYTES).min(rest.len());
    while !rest.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut look = Chars::new(&rest[..cut]);
    let mut docs = Vec::new();
    let closes = arith_body(&mut look, ctx, depth, &mut docs);
    ctx.arith_budget = ctx.arith_budget.saturating_sub(look.pos.max(1));
    match closes {
        // Only a complete look-ahead hands on here-documents: a cut-off
        // one never decides that `<<` opens one.
        Some(true) => Arith::Closes(look.pos, docs),
        Some(false) => Arith::Subshell,
        // Unterminated (bash rejects the line), or cut off.
        None if cut == rest.len() => Arith::Subshell,
        None => Arith::TooLong,
    }
}

/// Scan an arithmetic body after `((`: `Some(true)` after its `))`,
/// `Some(false)` at a `)` closing it that is not followed by another,
/// `None` at the end of the input. Here-documents opened in substitutions
/// of the body and still waiting for their bodies go to `docs`.
fn arith_body(
    look: &mut Chars,
    ctx: &mut Ctx,
    depth: usize,
    docs: &mut Vec<PendingDoc>,
) -> Option<bool> {
    let mut open = 0usize;
    while let Some(c) = look.next() {
        match c {
            '(' => open += 1,
            ')' if open > 0 => open -= 1,
            ')' => {
                return match look.peek()? {
                    ')' => {
                        look.next();
                        Some(true)
                    }
                    _ => Some(false),
                }
            }
            '\\' => {
                look.next();
            }
            '\'' => scan_single_quoted(look, &mut String::new()),
            '"' => {
                scan_double_quoted(look, &mut String::new(), &mut false, ctx, depth + 1, docs);
            }
            '$' if look.peek() == Some('(') => {
                look.next();
                scan_substitution(look, ctx, depth + 1, docs);
            }
            '`' => {
                scan_backtick(look);
            }
            _ => {}
        }
    }
    None
}

/// Does a `[[` after these words (the current command so far) start a
/// test? Only in a reserved word's position: first, or after reserved
/// words that are themselves in one (`if`, `while`, `!`, `time [-p]`, …).
fn starts_a_command(words: &[Word]) -> bool {
    let mut after_time = false;
    words.iter().all(|w| {
        let reserved = !w.quoted
            && (matches!(
                w.text.as_str(),
                "!" | "time" | "if" | "elif" | "while" | "until" | "then" | "do" | "else"
            ) || (after_time && w.text == "-p"));
        after_time = w.text == "time";
        reserved
    })
}

/// Commands that run what they read on stdin as commands (or pass it to
/// something that does).
const STDIN_RUNNERS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "mksh", "busybox", "eval", "su", "ssh",
    "xargs", "source", ".",
];

/// Is the body of the here-document whose `<<` is `toks[op]` run as
/// commands? Yes when the line ends in an unfinished `|`, `&&` or `||`
/// (its consumer comes later), or when a command of its pipeline, with
/// wrappers, assignments, redirections and `exec` peeled, is a shell (see
/// `STDIN_RUNNERS`) or cannot be known (none left: `sudo -s`; a variable
/// or substitution: `$SHELL`).
fn body_is_commands(toks: &[LexTok], op: usize) -> bool {
    // A list operator ends the pipeline; `|` does not.
    let ends_pipeline = |t: &LexTok| matches!(t, LexTok::Operator(o) if *o != Operator::Pipe);
    // `toks` ends with the newline of the heredoc's line.
    let end = toks.len().saturating_sub(1);
    if matches!(
        toks[..end].last(),
        Some(LexTok::Operator(
            Operator::Pipe | Operator::AndAnd | Operator::OrOr
        ))
    ) {
        return true;
    }
    let start = toks[..op]
        .iter()
        .rposition(ends_pipeline)
        .map_or(0, |i| i + 1);
    let stop = toks[op..end]
        .iter()
        .position(ends_pipeline)
        .map_or(end, |i| op + i);
    toks[start..stop]
        .split(|t| matches!(t, LexTok::Operator(_)))
        .any(|seg| {
            let words: Vec<Word> = seg
                .iter()
                .filter_map(|t| match t {
                    LexTok::Word(w) => Some(w.clone()),
                    LexTok::Operator(_) => None,
                })
                .collect();
            runs_stdin(&words)
        })
}

/// The words of the segment being lexed (after the last operator).
fn current_segment(toks: &[LexTok]) -> Vec<Word> {
    let start = toks
        .iter()
        .rposition(|t| matches!(t, LexTok::Operator(_)))
        .map_or(0, |i| i + 1);
    toks[start..]
        .iter()
        .filter_map(|t| match t {
            LexTok::Word(w) => Some(w.clone()),
            LexTok::Operator(_) => None,
        })
        .collect()
}

/// Does this command (one pipeline segment) run its stdin as commands, or
/// is it unknown?
fn runs_stdin(words: &[Word]) -> bool {
    // After a compound command's end (`done <<EOF`, `fi <<EOF`): the body
    // feeds the whole compound command; judge it as commands.
    if words
        .first()
        .is_some_and(|w| matches!(w.text.as_str(), "done" | "fi" | "esac"))
    {
        return true;
    }
    let mut rest = crate::wrappers::effective_command(words);
    // `exec [-cl] [-a NAME] cmd`.
    while rest.first().is_some_and(|w| w.text == "exec") {
        rest = &rest[1..];
        while let Some(w) = rest.first() {
            match w.text.as_str() {
                "-a" => rest = &rest[rest.len().min(2)..],
                t if t.starts_with('-') => rest = &rest[1..],
                _ => break,
            }
        }
        rest = crate::wrappers::effective_command(rest);
    }
    let Some(first) = rest.first() else {
        return true;
    };
    if first.has_substitution || first.text.starts_with('$') {
        return true;
    }
    let name = first.text.to_ascii_lowercase();
    let name = name.rsplit('/').next().unwrap_or("");
    STDIN_RUNNERS.contains(&name)
}

/// Consume a here-document body up to the line equal to `delim` (leading
/// tabs ignored for `<<-`), or to the end; return it. `in_sub`: read by a
/// `$(…)` frame, where (as in bash 5.3) a line that starts with `delim`
/// and holds a `)` also ends it (`EOF)`, `EOF cmd)`): the rest of that
/// line is left to the lexer. `end_closes`: the input is a substitution
/// body whose closing `)` was cut off, so its last line counts as holding
/// one.
fn read_heredoc(
    chars: &mut Chars,
    delim: &str,
    strip_tabs: bool,
    in_sub: bool,
    end_closes: bool,
) -> String {
    let mut body = String::new();
    loop {
        let line_start = chars.pos;
        let mut line = String::new();
        let mut ended = true;
        for c in chars.by_ref() {
            if c == '\n' {
                ended = false;
                break;
            }
            line.push(c);
        }
        let cmp = if strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line.as_str()
        };
        if cmp == delim {
            return body;
        }
        if in_sub
            && !delim.is_empty()
            && cmp.starts_with(delim)
            && (cmp[delim.len()..].contains(')') || (end_closes && ended))
        {
            chars.pos = line_start + (line.len() - cmp.len()) + delim.len();
            return body;
        }
        body.push_str(&line);
        body.push('\n');
        if ended {
            return body;
        }
    }
}

fn redirect_tok(text: String) -> LexTok {
    LexTok::Word(Word {
        text,
        has_substitution: false,
        redirect: true,
        glob: false,
        assignment: false,
        brace_overflow: false,
        quoted: false,
        dq_substitution: false,
    })
}

/// `NAME`, `NAME+`, `NAME[…]` or `NAME[…]+`: what may stand before the
/// `=` of an assignment word.
fn is_assignment_name(s: &str) -> bool {
    let s = s.strip_suffix('+').unwrap_or(s);
    let name = match s.find('[') {
        Some(i) if s.ends_with(']') => &s[..i],
        Some(_) => return false,
        None => s,
    };
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The rest of a redirection operator after its first `<`/`>`: `>>`,
/// `>|`, `>&`, `<<`, `<<-`, `<<<`, `<>`, `<&`.
fn scan_redirection(chars: &mut Chars, first: char, op: &mut String) {
    let take = |chars: &mut Chars, c: char, op: &mut String| {
        let hit = chars.peek() == Some(c);
        if hit {
            chars.next();
            op.push(c);
        }
        hit
    };
    if first == '>' {
        let _ = take(chars, '>', op) || take(chars, '|', op) || take(chars, '&', op);
    } else if take(chars, '<', op) {
        let _ = take(chars, '<', op) || take(chars, '-', op);
    } else {
        let _ = take(chars, '>', op) || take(chars, '&', op);
    }
}

/// A cursor over the input: a character iterator that can peek, be
/// copied for a look-ahead, and give the text it has not read yet (so a
/// substitution's raw text is a slice of the input, kept verbatim).
#[derive(Clone)]
struct Chars<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Chars<'a> {
    fn new(s: &'a str) -> Chars<'a> {
        Chars { s, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    /// The input not read yet.
    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }

    /// Skip `n` bytes (a length measured on `rest()`).
    fn skip_bytes(&mut self, n: usize) {
        self.pos += n;
    }
}

impl Iterator for Chars<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }
}

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
/// above. Returns whether the region was exactly one substitution
/// (`"$(…)"`).
fn scan_double_quoted(
    chars: &mut Chars,
    out: &mut String,
    has_sub: &mut bool,
    ctx: &mut Ctx,
    depth: usize,
    docs: &mut Vec<PendingDoc>,
) -> bool {
    let mut subs = 0usize;
    let mut other = false;
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => {
                other = true;
                match chars.peek() {
                    Some(e @ ('"' | '\\' | '$' | '`')) => {
                        out.push(e);
                        chars.next();
                    }
                    // Not one of the four escapable characters: the
                    // backslash is literal and the following character (if
                    // any) is read normally on the next loop iteration.
                    _ => out.push('\\'),
                }
            }
            '$' if chars.peek() == Some('(') => {
                chars.next();
                *has_sub = true;
                subs += 1;
                out.push_str("$(");
                out.push_str(scan_substitution(chars, ctx, depth, docs));
                out.push(')');
            }
            '`' => {
                *has_sub = true;
                subs += 1;
                out.push('`');
                out.push_str(&scan_backtick(chars));
                out.push('`');
            }
            c => {
                other = true;
                out.push(c);
            }
        }
    }
    subs == 1 && !other
}

/// Scan a `$(…)` body; the opening `$(` has been consumed. Consumes up to
/// and including the closing `)` and returns the body's raw text, exactly
/// as written. The body is lexed by a nested frame of the lexer itself, so
/// its quotes, comments and here-documents (`$(cat <<'EOF'` / `it's` /
/// `EOF` / `)`) are understood as at the top level; here-documents still
/// open when it closes go to `docs`. `$((…))` is arithmetic when a real
/// `))` closes it (as in bash). An unterminated body runs to the end.
fn scan_substitution<'a>(
    chars: &mut Chars<'a>,
    ctx: &mut Ctx,
    depth: usize,
    docs: &mut Vec<PendingDoc>,
) -> &'a str {
    let start = chars.pos;
    if depth + 1 >= MAX_FRAME_DEPTH {
        ctx.note(TOO_DEEP);
        let closed = scan_paren_flat(chars);
        return &chars.s[start..chars.pos - usize::from(closed)];
    }
    if chars.peek() == Some('(') {
        let mut look = chars.clone();
        look.next();
        match arith_lookahead(&look, ctx, depth + 1) {
            Arith::Closes(len, inner) => {
                // `(` body `))`: the substitution's text is `(body)`.
                docs.extend(inner);
                chars.pos = look.pos + len;
                return &chars.s[start..chars.pos - 1];
            }
            Arith::TooLong => {
                ctx.note(ARITH_TOO_LONG);
                let frame = lex_in(chars, ctx, depth + 1, true, true);
                docs.extend(frame.pending);
                return &chars.s[start..chars.pos - usize::from(frame.closed)];
            }
            Arith::Subshell => {}
        }
    }
    let frame = lex_in(chars, ctx, depth + 1, true, false);
    docs.extend(frame.pending);
    &chars.s[start..chars.pos - usize::from(frame.closed)]
}

/// The fallback for frames nested too deeply: a `$(…)` body by paren
/// depth and quotes alone (no here-documents or comments). Consumes up to
/// and including the closing `)`; returns whether there was one.
fn scan_paren_flat(chars: &mut Chars) -> bool {
    let mut depth = 1u32;
    while let Some(c) = chars.next() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return true;
                }
            }
            '\\' => {
                chars.next();
            }
            '\'' => scan_single_quoted(chars, &mut String::new()),
            '"' => loop {
                match chars.next() {
                    Some('\\') => {
                        chars.next();
                    }
                    Some('"') | None => break,
                    Some(_) => {}
                }
            },
            _ => {}
        }
    }
    false
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

/// The value of a word that is one command substitution printing plain
/// data: `$(cat <<'EOF' … EOF)` (a quoted delimiter, or an unquoted one
/// whose body has no `$`, backtick or backslash), `$(echo [-n] ARGS)`
/// without backslashes, or
/// `$(printf FORMAT)` with literal arguments and a format without `%` or
/// `\`. Trailing newlines are removed, as bash does. `None` for anything
/// else (the value is then unknown).
pub fn literal_substitution(text: &str) -> Option<String> {
    let inner = pure_substitution_body(text)?;
    substitution_value(&inner)
}

/// What a substitution with this body prints, when it is plain data (see
/// `literal_substitution`).
fn substitution_value(inner: &str) -> Option<String> {
    let value = heredoc_cat_value(inner).or_else(|| echo_value(inner))?;
    Some(value.trim_end_matches('\n').to_string())
}

/// The value of a word (its lexed text) whose every substitution prints
/// plain data (see `literal_substitution`), each replaced by its value,
/// and whether the word was exactly one substitution. A word that mixes
/// substitutions with other text gives `None` when a value holds blanks
/// or glob characters: which parts were quoted, and so split or globbed,
/// is not known from the text.
pub fn literal_word(text: &str) -> Option<(String, bool)> {
    if let Some(value) = literal_substitution(text) {
        return Some((value, true));
    }
    let mut out = String::new();
    let mut chars = Chars::new(text);
    let mut ctx = Ctx::new();
    while let Some(c) = chars.next() {
        let inner = match c {
            '$' if chars.peek() == Some('(') => {
                chars.next();
                scan_substitution(&mut chars, &mut ctx, 0, &mut Vec::new()).to_string()
            }
            '`' => scan_backtick(&mut chars),
            c => {
                out.push(c);
                continue;
            }
        };
        let value = substitution_value(&inner)?;
        if value.contains([' ', '\t', '\n', '*', '?', '[']) {
            return None;
        }
        out.push_str(&value);
    }
    Some((out, false))
}

/// `cat <<'X'` (or `<<-`) on the first line, the body, `X`, nothing more.
fn heredoc_cat_value(inner: &str) -> Option<String> {
    let inner = inner.trim_start_matches([' ', '\t']);
    let (first, rest) = inner.split_once('\n')?;
    let after_cat = first.strip_prefix("cat")?.trim_start();
    let op = after_cat.strip_prefix("<<")?;
    let (strip_tabs, op) = match op.strip_prefix('-') {
        Some(o) => (true, o),
        None => (false, op),
    };
    let delim_raw = op.trim();
    let (delim, quoted) = if let Some(d) = delim_raw
        .strip_prefix('\'')
        .and_then(|d| d.strip_suffix('\''))
        .or_else(|| {
            delim_raw
                .strip_prefix('"')
                .and_then(|d| d.strip_suffix('"'))
        })
        .or_else(|| delim_raw.strip_prefix('\\'))
    {
        (d, true)
    } else {
        (delim_raw, false)
    };
    if delim.is_empty()
        || !delim
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    let mut body = String::new();
    let mut lines = rest.split('\n');
    loop {
        let line = lines.next()?;
        let cmp = if strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line
        };
        if cmp == delim {
            break;
        }
        body.push_str(if strip_tabs { cmp } else { line });
        body.push('\n');
    }
    // Only blank space may follow the delimiter line.
    if lines.any(|l| !l.trim().is_empty()) {
        return None;
    }
    if !quoted && body.contains(['$', '`', '\\']) {
        return None;
    }
    Some(body)
}

/// `echo [-neE…] ARGS` or `printf FORMAT`, all literal.
fn echo_value(inner: &str) -> Option<String> {
    let segs = split_segments(inner);
    let [seg] = segs.as_slice() else {
        return None;
    };
    if seg
        .iter()
        .any(|w| w.has_substitution || w.glob || w.redirect || w.brace_overflow)
    {
        return None;
    }
    let (cmd, args) = seg.split_first()?;
    match cmd.text.as_str() {
        "echo" => {
            // Escapes (sh, dash and xpg_echo interpret them even without
            // `-e`) and `-e`/`-E` make the output depend on the shell.
            if args.iter().any(|w| w.text.contains('\\')) {
                return None;
            }
            let mut words = args.iter().map(|w| w.text.as_str()).peekable();
            while let Some(flag) = words.next_if(|a| {
                a.len() > 1 && a.starts_with('-') && a[1..].bytes().all(|b| b"neE".contains(&b))
            }) {
                if flag.contains(['e', 'E']) {
                    return None;
                }
            }
            Some(words.collect::<Vec<_>>().join(" "))
        }
        "printf" => match args {
            [format] if !format.text.contains(['%', '\\']) => Some(format.text.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// If `text` (an already-resolved `Word`'s text, or a slice of one) is
/// *entirely* one command-substitution region — `$(...)` or `` `...` ``,
/// with nothing concatenated before or after it — return the substitution's
/// raw, unevaluated inner text. Returns `None` for anything else, including
/// a substitution that is only part of a larger concatenated word
/// (`prefix$(cmd)suffix`) or a word with no substitution at all.
///
/// Reuses the same balanced-scanning the lexer used to build `text` in the
/// first place (`scan_substitution`/`scan_backtick`), so a nested
/// substitution (`$(echo $(date))`) or one containing a quoted `)` is
/// delimited identically here and during the original tokenization —
/// there's no second, drifting notion of "balanced".
///
/// Used by `crate::subst` to detect a command substitution occupying
/// *command position* (`$(rm -rf /)`, or the value of a `NAME=$(...)`
/// assignment word) — a shape the original tokenizer only ever *flags*
/// (`has_substitution`) but does not otherwise interpret.
pub(crate) fn pure_substitution_body(text: &str) -> Option<String> {
    let mut chars = Chars::new(text);
    let inner = match chars.next()? {
        '$' if chars.peek() == Some('(') => {
            chars.next(); // consume '('
            scan_substitution(&mut chars, &mut Ctx::new(), 0, &mut Vec::new()).to_string()
        }
        '`' => scan_backtick(&mut chars),
        _ => return None,
    };
    // Trailing text after the substitution: not "pure".
    chars.next().is_none().then_some(inner)
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
/// Reuses the lexer's own substitution scanner (`scan_substitution`,
/// `scan_backtick`), so nesting, quotes, comments and here-documents
/// inside a substitution are delimited identically here and during the
/// original tokenization — there is no second, drifting notion of
/// "balanced".
pub(crate) fn find_all_substitutions(text: &str) -> Vec<String> {
    find_subs(text, &mut Ctx::new(), 0)
}

fn find_subs(text: &str, ctx: &mut Ctx, depth: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = Chars::new(text);
    while let Some(c) = chars.next() {
        match c {
            '$' if chars.peek() == Some('(') => {
                chars.next(); // consume '('
                out.push(scan_substitution(&mut chars, ctx, depth, &mut Vec::new()).to_string());
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
/// grouping boundary. Mirrors `scan_paren_flat`'s quote/escape/nesting
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
        assert_eq!(
            segs(r"a \; rm -rf /"),
            vec![vec!["a", ";", "rm", "-rf", "/"]]
        );
        assert_eq!(
            segs(r"a \& rm -rf /"),
            vec![vec!["a", "&", "rm", "-rf", "/"]]
        );
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
        assert_eq!(
            segs("true; rm -rf ~"),
            vec![vec!["true"], vec!["rm", "-rf", "~"]]
        );
        assert_eq!(
            segs("foo | rm -rf /"),
            vec![vec!["foo"], vec!["rm", "-rf", "/"]]
        );
    }

    #[test]
    fn splits_with_no_surrounding_whitespace() {
        assert_eq!(segs("a&&rm -rf /"), vec![vec!["a"], vec!["rm", "-rf", "/"]]);
        assert_eq!(segs("a ;rm -rf /"), vec![vec!["a"], vec!["rm", "-rf", "/"]]);
    }

    #[test]
    fn splits_on_newline() {
        assert_eq!(segs("a\nrm -rf /"), vec![vec!["a"], vec!["rm", "-rf", "/"]]);
    }

    #[test]
    fn does_not_split_a_separator_inside_quotes() {
        assert_eq!(segs(r#"echo "a && b""#), vec![vec!["echo", "a && b"]]);
        assert_eq!(segs(r#"echo "a; b""#), vec![vec!["echo", "a; b"]]);
        assert_eq!(segs("echo 'a; b'"), vec![vec!["echo", "a; b"]]);
    }

    #[test]
    fn drops_empty_segments_from_consecutive_separators() {
        assert_eq!(
            segs("echo hi ;; echo bye"),
            vec![vec!["echo", "hi"], vec!["echo", "bye"]]
        );
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
            vec![
                vec!["for", "i", "in", "1"],
                vec!["echo", "hi"],
                vec!["done"]
            ]
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

    // ---- redirections -------------------------------------------------

    fn flagged(cmd: &str) -> Vec<(String, bool)> {
        split_segments(cmd)
            .into_iter()
            .flatten()
            .map(|w| (w.text, w.redirect))
            .collect()
    }

    #[test]
    fn unspaced_redirections_are_their_own_tokens() {
        assert_eq!(
            words("echo x>.claude/settings.json"),
            vec!["echo", "x", ">", ".claude/settings.json"]
        );
        assert_eq!(words("echo x>>f"), vec!["echo", "x", ">>", "f"]);
        assert_eq!(words("cat .env>/tmp/x"), vec!["cat", ".env", ">", "/tmp/x"]);
        assert_eq!(words("cat<.env"), vec!["cat", "<", ".env"]);
        assert_eq!(words("cat<<<hi"), vec!["cat", "<<<", "hi"]);
        assert_eq!(words("cat <<-EOF"), vec!["cat", "<<-", "EOF"]);
        assert_eq!(words("make 2>err"), vec!["make", "2>", "err"]);
        assert_eq!(words("make 2>&1"), vec!["make", "2>&", "1"]);
        assert_eq!(words("make >&-"), vec!["make", ">&", "-"]);
        assert_eq!(words("make &>log"), vec!["make", "&>", "log"]);
        assert_eq!(words("make &>>log"), vec!["make", "&>>", "log"]);
        assert_eq!(words("x 3<>f"), vec!["x", "3<>", "f"]);
        assert_eq!(words("x >|f"), vec!["x", ">|", "f"]);
        assert_eq!(words("x 0<&3"), vec!["x", "0<&", "3"]);
        // Digits are a descriptor only when they are the whole word so far.
        assert_eq!(words("echo a2>f"), vec!["echo", "a2", ">", "f"]);
        assert_eq!(segs("a && b>f"), vec![vec!["a"], vec!["b", ">", "f"]]);
        // `2>&1` is a redirection, not a background `&`.
        assert_eq!(
            segs("make 2>&1 | tee log"),
            vec![vec!["make", "2>&", "1"], vec!["tee", "log"]]
        );
    }

    #[test]
    fn only_unquoted_redirections_are_flagged() {
        let t = |s: &str, r: bool| (s.to_string(), r);
        assert_eq!(
            flagged(r#"grep ">" f"#),
            vec![t("grep", false), t(">", false), t("f", false)]
        );
        assert_eq!(
            flagged("echo x > f"),
            vec![t("echo", false), t("x", false), t(">", true), t("f", false)]
        );
        assert_eq!(
            flagged(r"echo \> f"),
            vec![t("echo", false), t(">", false), t("f", false)]
        );
        // A quoted digit is not a descriptor number.
        assert_eq!(
            flagged(r#"echo "2">f"#),
            vec![t("echo", false), t("2", false), t(">", true), t("f", false)]
        );
        assert_eq!(flagged("awk '$1>5' f")[1], t("$1>5", false));
    }

    #[test]
    fn process_substitution_is_not_a_redirection() {
        assert_eq!(
            segs("diff <(a) b"),
            vec![vec!["diff"], vec!["a"], vec!["b"]]
        );
        assert!(flagged("tee >(gzip)").iter().all(|(_, r)| !r));
    }

    #[test]
    fn unquoted_glob_characters_are_flagged() {
        let g = |cmd: &str| -> Vec<bool> {
            split_segments(cmd)
                .into_iter()
                .flatten()
                .map(|w| w.glob)
                .collect()
        };
        assert_eq!(g("cat .env* .e?v .[e]nv"), vec![false, true, true, true]);
        assert_eq!(
            g(r#"cat ".env*" '.e?v' \*"#),
            vec![false, false, false, false]
        );
        assert_eq!(g("cat a"), vec![false, false]);
    }

    #[test]
    fn assignment_words_follow_bash() {
        let a = |cmd: &str| -> Vec<bool> {
            split_segments(cmd)
                .into_iter()
                .flatten()
                .map(|w| w.assignment)
                .collect()
        };
        assert_eq!(
            a(r#"A=1 B+=2 c[0]=3 d[i+1]+=4 E="x y" cmd F=5"#),
            vec![true, true, true, true, true, false, true]
        );
        assert_eq!(
            a(r#"a["x"]=1 a[$(id)]=1 a[k=v]=1 a['k']+=1 a[x]"="1"#),
            vec![true, true, true, true, false]
        );
        assert_eq!(
            a(r#""A=1" 'B=2' C"=3" \D=4 1A=5 =6 a-b=7 $(x)=8"#),
            vec![false, false, false, false, false, false, false, false]
        );
    }

    #[test]
    fn brace_expansion_respects_quoting() {
        assert_eq!(words(r#"cat {".env",x}"#), vec!["cat", ".env", "x"]);
        assert_eq!(words("cat {'.env',x}"), vec!["cat", ".env", "x"]);
        assert_eq!(words(r"cat {\.env,x}"), vec!["cat", ".env", "x"]);
        assert_eq!(
            words("cat {$HOME/.ssh/id_rsa,x}"),
            vec!["cat", "$HOME/.ssh/id_rsa", "x"]
        );
        assert_eq!(words(r#"cat {"a,b",c}"#), vec!["cat", "a,b", "c"]);
        assert_eq!(words(r"cat {a\,b,c}"), vec!["cat", "a,b", "c"]);
        assert_eq!(words(r#"echo "{a,b}""#), vec!["echo", "{a,b}"]);
        assert_eq!(words("echo '{a,b}'"), vec!["echo", "{a,b}"]);
        assert_eq!(
            words("find . -exec cat {} ;"),
            vec!["find", ".", "-exec", "cat", "{}"]
        );
        assert_eq!(segs("{ echo a; }"), vec![vec!["echo", "a"]]);
    }

    #[test]
    fn brace_overflow_is_flagged_and_fast() {
        let cmd = format!("cat {}", "{a,b}".repeat(40));
        let t = std::time::Instant::now();
        let seg = split_segments(&cmd).remove(0);
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(seg.len(), 2);
        assert!(seg[1].brace_overflow);
        assert!(!split_segments("cat {a,b}").remove(0)[1].brace_overflow);
        // Many braces in one line stay linear.
        let many = "x{".repeat(20_000);
        let t = std::time::Instant::now();
        let _ = split_segments(&format!("echo {many}"));
        assert!(
            t.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn comments_and_arithmetic() {
        assert_eq!(words("echo hi # note <<EOF"), vec!["echo", "hi"]);
        assert_eq!(segs("# c\ncat x"), vec![vec!["cat", "x"]]);
        assert_eq!(words("echo a#b '#x'"), vec!["echo", "a#b", "#x"]);
        assert_eq!(words("(( x = 1<<2 ))"), vec!["(( x = 1<<2 ))"]);
        assert_eq!(words("y=$[1<<2]"), vec!["y=$[1<<2]"]);
        assert_eq!(words("[[ a < b ]]"), vec!["[[", "a", "<", "b", "]]"]);
        assert!(!split_segments("[[ a < b ]]")[0][2].redirect);
        assert!(split_segments("(( $(id) ))")[0][0].has_substitution);
    }

    #[test]
    fn literal_substitution_values() {
        let v = |t: &str| literal_substitution(t);
        assert_eq!(
            v("$(cat <<'EOF'\nfix: x\n\nbody\nEOF\n)").as_deref(),
            Some("fix: x\n\nbody")
        );
        assert_eq!(v("$(cat <<\"EOF\"\na $b\nEOF\n)").as_deref(), Some("a $b"));
        assert_eq!(v("$(cat <<-EOF\n\tx\n\tEOF\n)").as_deref(), Some("x"));
        assert_eq!(v("$(cat <<EOF\nplain\nEOF\n)").as_deref(), Some("plain"));
        assert_eq!(v("$(echo -n a b)").as_deref(), Some("a b"));
        assert_eq!(v("$(printf 'fix: x')").as_deref(), Some("fix: x"));
        for t in [
            "$(cat <<EOF\n$(id)\nEOF\n)",
            "$(cat <<'EOF' .env\nx\nEOF\n)",
            "$(cat <<'EOF'\nx\nEOF\nrm -rf /\n)",
            "$(cat .env)",
            "$(echo a; rm -rf /)",
            "$(echo $(id))",
            "$(echo *)",
            "$(printf '%s' x)",
            "pre$(echo x)",
            // Escapes (sh, dash and xpg_echo interpret them) or -e.
            r"$(echo -e '.\x65nv')",
            r"$(echo '.\x65nv')",
            r"$(echo -ne x)",
            r"$(echo -E x)",
        ] {
            assert_eq!(v(t), None, "{t}");
        }
    }

    #[test]
    fn many_double_parens_stay_fast() {
        let t = std::time::Instant::now();
        let _ = split_segments(&"((".repeat(20_000));
        let _ = split_segments(&format!("{}x{}", "((".repeat(5_000), "))".repeat(5_000)));
        assert!(
            t.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            t.elapsed()
        );
        assert_eq!(words("((i++))"), vec!["((i++))"]);
        assert_eq!(segs("((cat a) )"), vec![vec!["cat", "a"]]);
    }

    #[test]
    fn substitution_bodies_are_lexed_like_the_line() {
        // Here-documents, quotes and comments inside `$(…)`.
        let body = "cat <<'EOF'\nit's (wip :)\n# x\nEOF\n";
        assert_eq!(
            pure_substitution_body(&format!("$({body})")).as_deref(),
            Some(body)
        );
        assert_eq!(
            segs("echo \"$(cat <<'EOF'\nit's\nEOF\n)\"; cat .env"),
            vec![
                vec!["echo", "$(cat <<'EOF'\nit's\nEOF\n)"],
                vec!["cat", ".env"]
            ]
        );
        assert_eq!(
            segs("echo $(echo a # it's )\n); cat b"),
            vec![vec!["echo", "$(echo a # it's )\n)"], vec!["cat", "b"]]
        );
        // `$((…))` is arithmetic (no here-document at `<<`).
        assert_eq!(
            segs("echo $((1<<3))\ncat b"),
            vec![vec!["echo", "$((1<<3))"], vec!["cat", "b"]]
        );
        assert_eq!(
            find_all_substitutions("x$(echo \")\")y`id`"),
            vec!["echo \")\"", "id"]
        );
        // A here-document opened in a substitution that has closed: its
        // body follows the line, as in bash.
        assert_eq!(
            segs("echo \"$(cat <<EOF)\"\nbody\nEOF\ncat b"),
            vec![vec!["echo", "$(cat <<EOF)"], vec!["cat", "b"]]
        );
    }

    #[test]
    fn only_a_whole_double_quoted_substitution_is_flagged() {
        let dq = |cmd: &str| split_segments(cmd).remove(0)[1].dq_substitution;
        assert!(dq("cat \"$(echo x)\""));
        assert!(dq("cat \"`echo x`\""));
        for cmd in [
            "cat $(echo x)",
            "cat $(echo x)\"\"",
            "cat $(echo x)''",
            "cat \"\"$(echo x)",
            "cat \"$(echo x)\"$(echo y)",
            "cat \"$(echo x)y\"",
            "cat \"a$(echo x)\"",
        ] {
            assert!(!dq(cmd), "{cmd}");
        }
    }

    #[test]
    fn test_brackets_only_where_a_command_starts() {
        let redirect = |cmd: &str| split_segments(cmd).concat().iter().any(|w| w.redirect);
        for cmd in [
            "[[ a < b ]]",
            "! [[ a < b ]]",
            "time -p [[ a < b ]]",
            "if [[ a > b ]]; then :; fi",
            "if ! [[ a > b ]]; then :; fi",
            "while [[ a < b ]]; do :; done",
            "until [[ a < b ]]; do :; done",
            "if x; then [[ a < b ]]; elif [[ a < b ]]; then :; else [[ a > b ]]; fi",
            "x && [[ a < b ]] || [[ a > b ]]",
            "{ [[ a < b ]]; }",
            "([[ a < b ]])",
        ] {
            assert!(!redirect(cmd), "{cmd}");
        }
        for cmd in [
            "FOO=1 [[ a < b ]]",
            "echo [[ a < b ]]",
            "env [[ a < b ]]",
            "echo if [[ a < b ]]",
            "\"if\" [[ a < b ]]",
        ] {
            assert!(redirect(cmd), "{cmd}");
        }
    }

    #[test]
    fn what_cannot_be_lexed_exactly_is_noted() {
        assert_eq!(split_segments_noted("(( i++ )); echo $((1<<3))").1, None);
        let long = format!("(( x = {}1 ))", "1 + ".repeat(2000));
        assert_eq!(split_segments_noted(&long).1, Some(ARITH_TOO_LONG));
        let long = format!("echo $(( {}1 ))", "1 + ".repeat(2000));
        assert_eq!(split_segments_noted(&long).1, Some(ARITH_TOO_LONG));
        // The look-aheads of one line share one budget.
        let many = "(( i++ )); ".repeat(50_000);
        let t = std::time::Instant::now();
        assert_eq!(split_segments_noted(&many).1, Some(ARITH_TOO_LONG));
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
        // Nesting deeper than the frames allow.
        let deep = format!("echo {}x{}", "\"$(".repeat(50_000), ")\"".repeat(50_000));
        let t = std::time::Instant::now();
        assert_eq!(split_segments_noted(&deep).1, Some(TOO_DEEP));
        let deep = format!("echo {}x", "$(".repeat(50_000));
        assert_eq!(split_segments_noted(&deep).1, Some(TOO_DEEP));
        let deep = format!("echo {}x", "$((".repeat(50_000));
        let _ = split_segments_noted(&deep);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn literal_words_mix_text_and_values() {
        assert_eq!(
            literal_word("$(echo .claude)/settings.json"),
            Some((".claude/settings.json".to_string(), false))
        );
        assert_eq!(literal_word("$(echo a b)"), Some(("a b".to_string(), true)));
        assert_eq!(literal_word("x$(echo a b)"), None);
        assert_eq!(literal_word("x$(echo '*')"), None);
        assert_eq!(literal_word("x$(date)"), None);
    }
}
