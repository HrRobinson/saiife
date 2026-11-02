//! The cmd reader (plan 19a, W5): a cmd.exe line as segments of words, in the
//! POSIX forms the packs judge, so `rd /s /q C:\` meets the `rm` rules.
//!
//! cmd's rules, not the shell's:
//!
//! - `^` escapes outside quotes; inside `"…"` it is an ordinary character. A
//!   backslash and `'` are ordinary everywhere.
//! - `%X%` is expanded before the line is parsed, even inside quotes, and the
//!   value may hold `&`. So an unknown `%X%` (or `!X!`, `%%x`, `%1`, `%~dp0`)
//!   makes the word unresolved and the line not fully read. The variables
//!   `winpath` reads stay literal: `%USERPROFILE%\.ssh\id_rsa` is judged as a
//!   path.
//! - The program name ends at `/` (`rd/s/q x`, `cmd/c x`), a builtin's also at
//!   `\` and `.` (`cd\`, `cd..`), and `,`, `;` and `=` separate a builtin's
//!   words (`del,a;b`).
//! - `cd` takes the rest of the line as one path, and `copy a+b c` has two
//!   sources.
//! - cmd has no globbing: the program expands wildcards, quoted or not, and
//!   they match dotfiles.
//!
//! Over-splitting never bypasses, so anything after `&`, `|`, `(` or a newline
//! is a command of its own, even after `rem`. `if` and `for` are read through to
//! the command they run.
//!
//! What cannot be seen is never a silent allow: the word gets
//! `has_substitution`, and the note says the line was not fully read.
//!
//! The words of a nested string stay as they are: `nested` hands those to the
//! engine.

use crate::lexer::{Segment, Word};
use crate::pwsh;
use crate::wintable::{self, CommandName, Context, Dialect, UNRESOLVED};

/// How deep `(` may nest before the rest is left unread: the reader recurses.
const MAX_DEPTH: u32 = 64;

const NOTE_VARIABLE: &str = "a cmd variable may hold anything, operators included";
const NOTE_OPEN: &str = "a cmd quote or block was left open";
const NOTE_DEEP: &str = "cmd nesting too deep to read";
const NOTE_REDIRECT: &str = "a redirection target cannot be read";
const NOTE_LINK: &str = "a link or drive is created: later paths may go through it";
const NOTE_FOR: &str = "a for loop's variable cannot be read";
const NOTE_IF: &str = "an if condition cannot be read";
const NOTE_OPAQUE: &str = "this cmd command cannot be judged";
const NOTE_SCRIPT: &str = "a script's contents cannot be read";
const NOTE_LABEL: &str = "call to a label cannot be read";
const NOTE_NESTED: &str = crate::engine::UNRESOLVED_REASON;
const NOTE_WILDCARD: &str = "a quoted < or > is a wildcard to a file command";

/// Lower case: cmd's own commands. `,`, `;` and `=` separate their words.
const BUILTINS: &[&str] = &[
    "assoc", "break", "call", "cd", "chdir", "cls", "color", "copy", "date", "del", "dir", "echo",
    "endlocal", "erase", "exit", "ftype", "goto", "md", "mkdir", "mklink", "move", "path", "pause",
    "popd", "prompt", "pushd", "rd", "rem", "ren", "rename", "rmdir", "set", "setlocal", "shift",
    "start", "time", "title", "type", "ver", "verify", "vol",
];

/// Commands that change what a later name or path means.
const OPAQUE: &[&str] = &["assoc", "ftype", "doskey", "path"];

/// cmd's split: one reading of the whole line. Each `Segment` is argv-order
/// words after translation; the note is `Some(reason)` when something was not
/// fully read.
pub fn split_segments_noted(cmd: &str) -> (Vec<Segment>, Option<&'static str>) {
    let mut r = Reader {
        c: cmd.chars().collect(),
        i: 0,
        out: Vec::new(),
        note: None,
        depth: 0,
        piped: false,
    };
    r.statements(false);
    (r.out, r.note)
}

/// The nested command of `argv` (`wintable::nested`). For `cmd`, which reads
/// the raw rest of its line, a quoted word keeps its quotes:
/// `cmd /c rd /s "C:\Program Files"` has one path. A sole quoted word loses
/// them (`cmd /c "rd /s C:\"`). A first quoted word among others is cmd's quote
/// stripping, which leaves the line in pieces: unresolved.
pub(crate) fn nested(argv: &[Word]) -> Option<(Dialect, String)> {
    let first = argv.first()?;
    if first.has_substitution || CommandName::of(&first.text).lower() != "cmd" {
        return wintable::nested(argv);
    }
    let Some(at) = argv.iter().skip(1).position(is_run_option) else {
        return wintable::nested(argv);
    };
    let at = at + 2;
    let rest = argv.get(at..).unwrap_or(&[]);
    if rest.len() > 1 && rest[0].quoted {
        return Some((Dialect::PowerShell, UNRESOLVED.to_string()));
    }
    if rest.len() < 2 {
        return wintable::nested(argv);
    }
    let mut quoted = argv.to_vec();
    for w in &mut quoted[at..] {
        if w.quoted && !w.text.contains('"') {
            w.text = format!("\"{}\"", w.text);
        }
    }
    wintable::nested(&quoted)
}

/// `/c`, `/k`, `/r`, alone or in a run (`/s/c`), attached text included.
fn is_run_option(w: &Word) -> bool {
    !w.quoted
        && w.text.starts_with('/')
        && w.text[1..].split('/').any(|p| {
            p.chars()
                .next()
                .is_some_and(|c| matches!(c.to_ascii_lowercase(), 'c' | 'k' | 'r'))
        })
}

fn is_blank(c: char) -> bool {
    c.is_whitespace() && c != '\n'
}

/// cmd's own word separators, for a builtin.
fn is_delim(c: char) -> bool {
    matches!(c, ',' | ';' | '=')
}

fn is_builtin(name: &str) -> bool {
    BUILTINS.contains(&name.to_ascii_lowercase().as_str())
}

/// A name `%NAME%` can hold: no operator, quote or blank decides where it ends.
fn is_var_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '&' | '|' | '<' | '>' | '^' | '"'))
}

/// One word as read.
#[derive(Default)]
struct Read {
    w: Word,
    /// An unquoted `==` is in it, and where.
    eq: Option<usize>,
    /// Raw position and text length of its first unquoted `/`, before any
    /// quote; likewise of its first `\` or `.`.
    slash: Option<(usize, usize)>,
    dot: Option<(usize, usize)>,
    /// A real `"` is in it. A caret-escaped keyword is still the keyword.
    dq: bool,
}

struct Reader {
    c: Vec<char>,
    i: usize,
    out: Vec<Segment>,
    note: Option<&'static str>,
    depth: u32,
    /// The statement being read takes the last one's output.
    piped: bool,
}

impl Reader {
    fn noted(&mut self, why: &'static str) {
        self.note.get_or_insert(why);
    }
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }
    fn at(&self, n: usize) -> Option<char> {
        self.c.get(self.i + n).copied()
    }

    /// Statements up to the end of the line, or `)` when `closing`.
    fn statements(&mut self, closing: bool) {
        loop {
            let before = self.i;
            self.statement(closing);
            self.piped = false;
            match self.peek() {
                None => {
                    if closing {
                        self.noted(NOTE_OPEN);
                    }
                    return;
                }
                Some(')') if closing => {
                    self.i += 1;
                    return;
                }
                Some(c @ ('&' | '|')) => {
                    self.i += 1;
                    if self.peek() == Some(c) {
                        self.i += 1;
                    } else {
                        self.piped = c == '|';
                    }
                }
                Some('\n') => self.i += 1,
                // `if x a else b`: `else` starts the next one.
                Some(_) if self.i == before => self.i += 1,
                Some(_) => {}
            }
        }
    }

    /// Blanks, and what cmd skips in front of a command.
    fn skip_to_command(&mut self) {
        while let Some(c) = self.peek() {
            if is_blank(c) || is_delim(c) || c == '@' {
                self.i += 1;
            } else if c == '^' && self.at(1) == Some('\n') {
                self.i += 2;
            } else {
                return;
            }
        }
    }

    fn skip_blanks(&mut self, delims: bool) {
        while let Some(c) = self.peek() {
            if is_blank(c) || (delims && is_delim(c)) {
                self.i += 1;
            } else if c == '^' && self.at(1) == Some('\n') {
                self.i += 2;
            } else {
                return;
            }
        }
    }

    /// At an operator that ends the statement?
    fn at_end(&self, closing: bool) -> bool {
        match self.peek() {
            None | Some('\n' | '&' | '|') => true,
            Some(')') => closing,
            _ => false,
        }
    }

    /// One statement; stops at the operator that ends it.
    fn statement(&mut self, closing: bool) {
        let mut redirects = Vec::new();
        loop {
            self.skip_to_command();
            if self.at_end(closing) {
                self.emit(redirects);
                return;
            }
            if self.peek() == Some('(') {
                self.i += 1;
                self.block();
                // `(a) > f`, `(a) else b`.
                continue;
            }
            if self.redirect(&mut redirects) {
                continue;
            }
            let Some(first) = self.read_word(true) else {
                self.i += 1;
                continue;
            };
            let first = self.split_name(first);
            let name = first.w.text.to_ascii_lowercase();
            if !first.dq {
                match name.as_str() {
                    "if" => {
                        self.condition(closing);
                        continue;
                    }
                    "else" => continue,
                    "for" => {
                        self.for_loop(closing);
                        continue;
                    }
                    "call" => {
                        self.skip_blanks(true);
                        if self.peek() == Some(':') {
                            self.noted(NOTE_LABEL);
                        }
                        continue;
                    }
                    "set" => {
                        self.set(closing, redirects);
                        return;
                    }
                    _ => {}
                }
            }
            self.command(first, closing, redirects);
            return;
        }
    }

    fn block(&mut self) {
        if self.depth >= MAX_DEPTH {
            self.noted(NOTE_DEEP);
            self.i = self.c.len();
            return;
        }
        self.depth += 1;
        self.statements(true);
        self.depth -= 1;
    }

    /// `rd/s/q` is `rd /s/q`; a builtin's `cd\` and `cd..` are `cd \` and
    /// `cd ..`. The rest is read again as words. `./x`, `C:/x` and `a.b/c`
    /// name a path.
    fn split_name(&mut self, mut first: Read) -> Read {
        if let Some((raw, len)) = first.slash {
            let head = &first.w.text[..len];
            if !head.is_empty() && !head.contains(['.', ':', '\\']) {
                first.w.text.truncate(len);
                self.i = raw;
                return first;
            }
        }
        if let Some((raw, len)) = first.dot {
            if is_builtin(&first.w.text[..len]) {
                first.w.text.truncate(len);
                self.i = raw;
            }
        }
        first
    }

    /// `if` was read: the condition is dropped, and what follows is the
    /// command it runs. A word the forms below do not cover may be a command,
    /// so it is noted and read as one.
    fn condition(&mut self, closing: bool) {
        loop {
            self.skip_blanks(false);
            if self.at_end(closing) {
                self.noted(NOTE_IF);
                return;
            }
            let start = self.i;
            let Some(word) = self.read_word(false) else {
                self.noted(NOTE_IF);
                return;
            };
            let text = word.w.text.to_ascii_lowercase();
            if !word.dq {
                match text.as_str() {
                    "/i" | "not" => continue,
                    "exist" | "defined" | "errorlevel" | "cmdextversion" => {
                        self.skip_word();
                        return;
                    }
                    _ => {}
                }
            }
            // `a==b`, `a== b`, `a ==b`, `a == b`, `a equ b`.
            if let Some(at) = word.eq {
                if at + 2 == word.w.text.len() {
                    self.skip_word();
                }
                return;
            }
            self.skip_blanks(false);
            let op = self.read_word(false);
            let Some(op) = op else {
                self.noted(NOTE_IF);
                self.i = start;
                return;
            };
            if op.eq == Some(0) {
                if op.w.text.len() == 2 {
                    self.skip_word();
                }
                return;
            }
            let lower = op.w.text.to_ascii_lowercase();
            if !op.dq
                && matches!(
                    lower.as_str(),
                    "equ" | "neq" | "lss" | "leq" | "gtr" | "geq"
                )
            {
                self.skip_word();
                return;
            }
            self.noted(NOTE_IF);
            self.i = start;
            return;
        }
    }

    fn skip_word(&mut self) {
        self.skip_blanks(false);
        let _ = self.read_word(false);
    }

    /// `for` was read: `[/d|/r [dir]|/l|/f ["opts"]] %i in (set) do command`.
    /// The set of a `/f` is a command or a file read; the command after `do`
    /// is read as any other. Its variable is noted when it is read.
    fn for_loop(&mut self, closing: bool) {
        self.noted(NOTE_FOR);
        let mut lines = false;
        let start = self.i;
        loop {
            self.skip_blanks(false);
            if self.at_end(closing) {
                self.i = start;
                return;
            }
            let Some(w) = self.read_word(false) else {
                self.i = start;
                return;
            };
            if !w.dq && w.w.text.eq_ignore_ascii_case("/f") {
                lines = true;
            }
            if !w.dq && w.w.text.eq_ignore_ascii_case("in") {
                break;
            }
        }
        self.skip_blanks(false);
        if self.peek() != Some('(') {
            self.i = start;
            return;
        }
        self.i += 1;
        let from = self.i;
        let mut quote = false;
        while let Some(c) = self.peek() {
            match c {
                '"' => quote = !quote,
                ')' if !quote => break,
                _ => {}
            }
            self.i += 1;
        }
        if self.peek().is_none() {
            self.noted(NOTE_OPEN);
            return;
        }
        let set: String = self.c[from..self.i].iter().collect();
        self.i += 1;
        if lines {
            self.for_lines(set.trim());
        }
        self.skip_blanks(false);
        let at = self.i;
        match self.read_word(false) {
            Some(w) if !w.dq && w.w.text.eq_ignore_ascii_case("do") => {}
            _ => self.i = at,
        }
    }

    /// `for /f`'s set: `'command'`, `` `command` `` under `usebackq`, or files.
    fn for_lines(&mut self, set: &str) {
        let inner = ['\'', '`']
            .iter()
            .find_map(|q| set.strip_prefix(*q)?.strip_suffix(*q));
        if let Some(cmd) = inner {
            if self.depth >= MAX_DEPTH {
                self.noted(NOTE_DEEP);
                return;
            }
            let (segments, note) = split_nested(cmd, self.depth + 1);
            self.out.extend(segments);
            if let Some(n) = note {
                self.noted(n);
            }
            return;
        }
        let (mut segments, note) = split_nested(&format!("type {set}"), self.depth + 1);
        self.out.append(&mut segments);
        if let Some(n) = note {
            self.noted(n);
        }
    }

    /// `set NAME=v`, `set "NAME=v"`: an assignment. `/a` and `/p` set a value
    /// that cannot be read. Anything else only prints.
    fn set(&mut self, closing: bool, redirects: Vec<Word>) {
        let mut words: Vec<Word> = Vec::new();
        let mut redirects = redirects;
        self.words(closing, false, &mut words, &mut redirects);
        let mut computed = false;
        while words.first().is_some_and(|w| {
            !w.quoted && (w.text.eq_ignore_ascii_case("/a") || w.text.eq_ignore_ascii_case("/p"))
        }) {
            words.remove(0);
            computed = true;
        }
        let eq = words
            .first()
            .and_then(|w| w.text.find('='))
            .filter(|at| *at > 0);
        let Some(at) = eq else {
            let mut seg = vec![plain("set")];
            seg.append(&mut words);
            seg.append(&mut redirects);
            self.emit(seg);
            return;
        };
        let text = words
            .iter()
            .map(|w| w.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let word = Word {
            has_substitution: computed || words.iter().any(|w| w.has_substitution),
            quoted: words[0].quoted,
            assignment: true,
            text: format!("{}={}", &text[..at], &text[at + 1..]),
            ..Word::default()
        };
        let mut seg = vec![word];
        seg.append(&mut redirects);
        self.emit(seg);
    }

    /// The words of a statement up to its end; redirections go aside.
    fn words(
        &mut self,
        closing: bool,
        delims: bool,
        out: &mut Vec<Word>,
        redirects: &mut Vec<Word>,
    ) {
        loop {
            self.skip_blanks(delims);
            if self.at_end(closing) || self.else_ends_statement() {
                return;
            }
            if self.redirect(redirects) {
                continue;
            }
            match self.read_word(delims) {
                Some(r) => out.push(r.w),
                None => self.i += 1,
            }
        }
    }

    /// `if x (a) else b`, and over-read in `if x a else b`: an unquoted `else`
    /// starts a command of its own.
    fn else_ends_statement(&self) -> bool {
        let is = |n: usize, c: char| self.at(n).is_some_and(|x| x.eq_ignore_ascii_case(&c));
        is(0, 'e') && is(1, 'l') && is(2, 's') && is(3, 'e') && self.at(4).is_some_and(is_blank)
    }

    /// The rest of a command, and the table.
    fn command(&mut self, first: Read, closing: bool, mut redirects: Vec<Word>) {
        let name = first.w.text.clone();
        let lower = name.to_ascii_lowercase();
        let delims = !first.dq && is_builtin(&lower);
        let mut args = Vec::new();
        self.words(closing, delims, &mut args, &mut redirects);
        let base = CommandName::of(&name).lower();
        let piped = self.piped;
        self.notes_for(&lower, &base);
        let mut argv = vec![first.w];
        if let Some(seg) = self.links(&base, &args) {
            self.emit_with(seg, redirects);
            return;
        }
        match base.as_str() {
            "cd" | "chdir" => cd_words(&mut args),
            "copy" => args = split_plus(args),
            _ => {}
        }
        argv.append(&mut args);
        let (mut seg, note) = wintable::translate_noted(&argv, Dialect::Cmd, &Context::default());
        if let Some(n) = note {
            self.noted(n);
        }
        self.check_wildcards(&seg);
        self.check_nested(&mut seg, piped, &redirects);
        self.emit_with(seg, redirects);
    }

    fn notes_for(&mut self, lower: &str, base: &str) {
        if OPAQUE.contains(&base) || pwsh::OPAQUE.contains(&base) {
            self.noted(NOTE_OPAQUE);
        }
        if base == "net" {
            self.noted(NOTE_OPAQUE);
        }
        if [".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".js", ".wsf"]
            .iter()
            .any(|e| lower.ends_with(e))
        {
            self.noted(NOTE_SCRIPT);
        }
    }

    /// `mklink [/d|/h|/j] link target` and `subst X: target` are judged by
    /// their target, as `ln -s`, and noted: what comes after may go through it.
    fn links(&mut self, base: &str, args: &[Word]) -> Option<Vec<Word>> {
        if base != "mklink" && base != "subst" {
            return None;
        }
        self.noted(NOTE_LINK);
        let pos: Vec<&Word> = args.iter().filter(|w| !w.text.starts_with('/')).collect();
        let mut seg = vec![plain("ln"), plain("-s")];
        match pos.as_slice() {
            [link, target, ..] => {
                seg.push((*target).clone());
                seg.push((*link).clone());
            }
            _ => seg.extend(pos.iter().map(|w| (*w).clone())),
        }
        Some(seg)
    }

    /// `type "C:\x\id_rs>"`: Win32's wildcards, which only quotes let through.
    fn check_wildcards(&mut self, seg: &[Word]) {
        let files = seg
            .first()
            .is_some_and(|w| matches!(w.text.as_str(), "rm" | "cat" | "cp" | "mv" | "ls"));
        if files && seg.iter().skip(1).any(|w| w.text.contains(['<', '>'])) {
            self.noted(NOTE_WILDCARD);
        }
    }

    /// A shell fed on stdin, or a nested command it knows is there and cannot
    /// read.
    fn check_nested(&mut self, seg: &mut Segment, piped: bool, redirects: &[Word]) {
        let Some(first) = seg.first() else {
            return;
        };
        let shell = wintable::is_nesting_command(&first.text);
        let found = nested(seg);
        if found.as_ref().is_some_and(|(_, s)| s == UNRESOLVED) {
            self.noted(NOTE_NESTED);
            if let Some(last) = seg.last_mut() {
                last.has_substitution = true;
            }
        }
        let fed = piped
            || redirects
                .iter()
                .any(|w| w.redirect && w.text.starts_with('<'));
        if shell && (seg.iter().skip(1).any(|w| w.has_substitution) || (fed && found.is_none())) {
            self.noted(NOTE_NESTED);
        }
    }

    fn emit_with(&mut self, mut seg: Vec<Word>, mut redirects: Vec<Word>) {
        seg.append(&mut redirects);
        self.emit(seg);
    }

    /// `$` is an ordinary character to cmd, on every word: its live forms are
    /// `%x%` and `!x!`, which set `has_substitution`.
    fn emit(&mut self, mut seg: Segment) {
        for w in &mut seg {
            w.literal_dollars = true;
        }
        if !seg.is_empty() {
            self.out.push(seg);
        }
    }

    /// A redirection at the cursor goes to `redirects`, with its target; `nul`
    /// names no file. `2>` needs its digit alone: `a2>f` writes `a2`.
    fn redirect(&mut self, redirects: &mut Vec<Word>) -> bool {
        let digit = self.peek().filter(char::is_ascii_digit);
        let at = usize::from(digit.is_some());
        let op = match self.at(at) {
            Some(c @ ('>' | '<')) => c,
            _ => return false,
        };
        let mut text = String::new();
        text.extend(digit);
        text.push(op);
        self.i += at + 1;
        if op == '>' && self.peek() == Some('>') {
            text.push('>');
            self.i += 1;
        }
        if self.peek() == Some('&') {
            text.push('&');
            self.i += 1;
        }
        self.skip_blanks(false);
        let target = self.read_word(false);
        let Some(target) = target else {
            self.noted(NOTE_REDIRECT);
            return true;
        };
        let lower = target.w.text.to_ascii_lowercase();
        if matches!(lower.as_str(), "nul" | "nul:") {
            return true;
        }
        if target.w.has_substitution {
            self.noted(NOTE_REDIRECT);
        }
        redirects.push(Word {
            text,
            redirect: true,
            ..Word::default()
        });
        redirects.push(target.w);
        true
    }

    /// One word, or `None` when nothing could be read at the cursor.
    fn read_word(&mut self, delims: bool) -> Option<Read> {
        let mut r = Read::default();
        let mut quote = false;
        let mut seen_quote = false;
        let start = self.i;
        while let Some(c) = self.peek() {
            if quote {
                match c {
                    '"' => {
                        quote = false;
                        self.i += 1;
                    }
                    '\n' => break,
                    '%' => self.percent(&mut r.w),
                    '!' => self.bang(&mut r.w),
                    c => {
                        r.w.text.push(c);
                        self.i += 1;
                    }
                }
                continue;
            }
            if is_blank(c) || c == '\n' || matches!(c, '&' | '|' | '<' | '>') {
                break;
            }
            // Outside a block `)` is text: `cd C:\Program Files (x86)`.
            if c == ')' && self.depth > 0 {
                break;
            }
            if delims && is_delim(c) {
                break;
            }
            match c {
                '"' => {
                    quote = true;
                    seen_quote = true;
                    r.dq = true;
                    r.w.quoted = true;
                    self.i += 1;
                }
                '^' => {
                    self.i += 1;
                    match self.peek() {
                        Some('\n') => {
                            self.i += 1;
                            if let Some(next) = self.peek() {
                                r.w.text.push(next);
                                r.w.quoted = true;
                                self.i += 1;
                            }
                        }
                        Some(next) => {
                            r.w.text.push(next);
                            r.w.quoted = true;
                            self.i += 1;
                        }
                        None => {}
                    }
                }
                '%' => self.percent(&mut r.w),
                '!' => self.bang(&mut r.w),
                c => {
                    if !seen_quote {
                        let at = (self.i, r.w.text.len());
                        if c == '/' {
                            r.slash.get_or_insert(at);
                        } else if c == '\\' || c == '.' {
                            r.dot.get_or_insert(at);
                        }
                    }
                    if c == '=' && self.at(1) == Some('=') && r.eq.is_none() {
                        r.eq = Some(r.w.text.len());
                    }
                    r.w.text.push(c);
                    self.i += 1;
                }
            }
        }
        if quote {
            self.noted(NOTE_OPEN);
        }
        if self.i == start {
            return None;
        }
        if r.w.text.contains(['*', '?']) {
            r.w.glob = true;
            r.w.glob_dots = true;
        }
        Some(r)
    }

    /// `%` at the cursor, in or out of quotes.
    fn percent(&mut self, w: &mut Word) {
        let next = self.at(1);
        // `%%x`, `%1`, `%*`, `%~dp0`: a parameter or a loop's variable.
        if matches!(next, Some('%' | '*' | '~')) || next.is_some_and(|c| c.is_ascii_digit()) {
            self.unknown(w);
            w.text.push('%');
            self.i += 1;
            return;
        }
        // Stops at the next `%`, so a line of them stays linear.
        let close = self.c[self.i + 1..]
            .iter()
            .take_while(|c| **c != '\n')
            .position(|c| *c == '%')
            .map(|n| self.i + 1 + n);
        if let Some(close) = close {
            let name: String = self.c[self.i + 1..close].iter().collect();
            if is_var_name(&name) {
                w.text.push_str(&format!("%{name}%"));
                self.i = close + 1;
                // `%X:~0%` and `%X:a=b%` are not the value of `X`.
                if !pwsh::known_variable(&format!("env:{name}")) {
                    self.unknown(w);
                }
                return;
            }
        }
        // `%i` of a `for`; a `%` with a blank before the next one may still be
        // a variable named so. `100%` at the end of a word is text.
        let word_goes_on = next.is_some_and(|c| !c.is_whitespace() && !"&|<>)\"".contains(c));
        if word_goes_on || close.is_some() {
            self.unknown(w);
        }
        w.text.push('%');
        self.i += 1;
    }

    /// `!` at the cursor: `!NAME!` is delayed expansion when `cmd /v` is on,
    /// which the line cannot show.
    fn bang(&mut self, w: &mut Word) {
        let close = self.c[self.i + 1..]
            .iter()
            .take_while(|c| **c != '\n')
            .position(|c| *c == '!')
            .map(|n| self.i + 1 + n);
        if let Some(close) = close {
            let name: String = self.c[self.i + 1..close].iter().collect();
            if is_var_name(&name) {
                self.unknown(w);
                w.text.push_str(&format!("!{name}!"));
                self.i = close + 1;
                return;
            }
        }
        w.text.push('!');
        self.i += 1;
    }

    fn unknown(&mut self, w: &mut Word) {
        w.has_substitution = true;
        self.noted(NOTE_VARIABLE);
    }
}

/// `split_segments_noted`, already `depth` levels in.
fn split_nested(cmd: &str, depth: u32) -> (Vec<Segment>, Option<&'static str>) {
    let mut r = Reader {
        c: cmd.chars().collect(),
        i: 0,
        out: Vec::new(),
        note: None,
        depth,
        piped: false,
    };
    r.statements(false);
    (r.out, r.note)
}

/// `cd /d C:\x` changes the drive too, and `cd C:\Program Files` is one path.
fn cd_words(args: &mut Vec<Word>) {
    args.retain(|w| w.quoted || !w.text.eq_ignore_ascii_case("/d"));
    if args.len() < 2 {
        return;
    }
    let mut joined = args[0].clone();
    for w in &args[1..] {
        joined.text.push(' ');
        joined.text.push_str(&w.text);
        joined.has_substitution |= w.has_substitution;
    }
    *args = vec![joined];
}

/// `copy a+b c`: `a` and `b` are sources.
fn split_plus(args: Vec<Word>) -> Vec<Word> {
    let mut out = Vec::with_capacity(args.len());
    for w in args {
        if !w.text.contains('+') {
            out.push(w);
            continue;
        }
        for part in w.text.split('+').filter(|p| !p.is_empty()) {
            let mut piece = w.clone();
            piece.text = part.to_string();
            out.push(piece);
        }
    }
    out
}

fn plain(text: &str) -> Word {
    Word {
        text: text.to_string(),
        ..Word::default()
    }
}

#[cfg(test)]
mod tests;
