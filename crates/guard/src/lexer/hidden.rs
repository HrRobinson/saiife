//! Command lines a segment runs that are not where a command starts: what
//! `find -exec` runs, what a shell reads from a pipe or a here-string, and a
//! `trap` action. Each becomes segments of its own, after the segment that
//! runs it, so every rule judges it, as the body of `bash <<EOF` already is.
//! A pipe feeds every command of a group it feeds (`| { true; sh; }`), the
//! commands of a `-c` line (`| bash -c 'sh'`) and what find runs; a shell
//! reads it as its script with no command, with `-s`, or given a path to
//! its stdin (`bash /dev/stdin`).
//! Text a shell runs that the guard cannot read (`echo "$x" | sh`, `curl … |
//! sh`) is noted (`UNREAD_SCRIPT`): a recorded fail-open, which a caller that
//! fails closed denies. Literal text is still judged.
//!
//! The gates are a pass over each segment's words, with no allocation; the
//! rest runs only for a segment that has one of these shapes.

use super::FedScript;
use super::{
    lex_in, printed, strip_leading_keywords, Chars, Ctx, LexTok, Operator, Segment, Word,
    MAX_FRAME_DEPTH, TOO_DEEP,
};
use crate::payload::inline_payload;
use crate::wintable::{unread_shell, without_redirects};
use crate::wrappers::{effective_command, peeled_wrappers};

/// Why a line is not fully judged: a shell runs text the guard cannot read.
pub const UNREAD_SCRIPT: &str =
    "a shell runs text the guard cannot read here (another command's output, a variable or a substitution)";

/// The note for a line whose hidden command lines, nested, come to more than
/// `LINE_BYTES`. The engine denies on it, as on too many brace expansions.
pub const HIDDEN_PAST_LINE_LIMIT: &str =
    "command lines nested in pipes, here-strings or traps past what one line may hold";

/// The bytes of hidden command lines one line may lex, all levels together.
/// Each level is a part of the one above it, so an ordinary line comes nowhere
/// near; only many levels of a long line do.
pub(super) const LINE_BYTES: usize = 1024 * 1024;

/// Split `toks` into segments, with the hidden command lines of each after it.
pub(super) fn segments(toks: Vec<LexTok>, ctx: &mut Ctx) -> Vec<Segment> {
    let mut out = Out {
        segments: Vec::new(),
        traps: Vec::new(),
    };
    out.collect(toks, ctx, 0, None);
    // A trap action runs when its trap fires: at the latest where the line
    // ends, in the directory the line left it in. Judged there, it is judged
    // with all the directories the line may be in.
    let mut i = 0;
    while let Some((action, depth)) = out.traps.get_mut(i).map(std::mem::take) {
        out.splice(&action, ctx, depth, None);
        i += 1;
    }
    out.segments
}

/// Where a command's stdin comes from, when that is a pipe or a here-string.
#[derive(Clone)]
enum Source {
    /// The segment at this index, one simple command, writes the pipe.
    Segment(usize),
    /// A here-string's text, and whether the guard can read it.
    Text(String, bool),
    /// Something else writes it: a group, a compound command, a pipeline.
    Unknown,
}

/// What opened a frame: a group or a compound command a pipe or a
/// here-string feeds, closed by `)`, `}`, `fi`, `done` or `esac`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Opener {
    Paren,
    Brace,
    If,
    /// `while`, `until`, `for`, `select`.
    Loop,
    Case,
}

/// A group (`{ … }`, `( … )`) or compound command (`if`, a loop, `case`) a
/// pipe feeds, or one inside it: what opened it, the source every command in
/// it reads, and the index of the first segment after it opened. A `case`
/// pattern's `)` closes no group: a `case` frame is on top then.
struct Group {
    open: Opener,
    source: Source,
    start: usize,
    /// The openers and closers seen on this line when it opened, its own
    /// opener counted. Inside a fed frame every opener opens a frame, so
    /// while this one is on top they balance unless a closer since closed
    /// nothing; then where it ends is not known.
    seen: (usize, usize),
}

/// A reserved word that opens or closes a compound command, where a command
/// starts.
fn compound_word(text: &str) -> Option<(Opener, bool)> {
    Some(match text {
        "if" => (Opener::If, true),
        "while" | "until" | "for" | "select" => (Opener::Loop, true),
        "case" => (Opener::Case, true),
        "fi" => (Opener::If, false),
        "done" => (Opener::Loop, false),
        "esac" => (Opener::Case, false),
        _ => return None,
    })
}

/// Where the current segment's words so far leave the next word: at a
/// command start, or after the words of `time`, `coproc` or `function` that
/// a command or a compound command may still follow.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Head {
    /// A command starts here (`then if`, `! while`).
    Start,
    /// After `time` and its `-p` or `--`.
    Time,
    /// After `coproc`: its NAME, a command or a compound command.
    Coproc,
    /// After `coproc WORD`: WORD was its NAME when a compound command
    /// follows, else the command, so only an opener counts here.
    CoprocName,
    /// After `function`: its NAME.
    Function,
    /// No command starts here.
    No,
}

impl Head {
    /// Where the word `w` leaves the next word.
    fn next(self, w: &Word) -> Head {
        if w.quoted {
            return Head::No;
        }
        let t = w.text.as_str();
        match self {
            Head::Time if matches!(t, "-p" | "--") => Head::Time,
            Head::Start | Head::Time => match t {
                "!" | "then" | "do" | "else" | "elif" | "if" | "while" | "until" => Head::Start,
                "time" => Head::Time,
                "coproc" => Head::Coproc,
                "function" => Head::Function,
                _ => Head::No,
            },
            Head::Coproc if compound_word(t).is_some() => Head::Start.next(w),
            Head::Coproc => Head::CoprocName,
            Head::CoprocName if compound_word(t).is_some_and(|(_, open)| open) => {
                Head::Start.next(w)
            }
            // `function NAME`: its body comes next (`function f if …`), or
            // `()`, which ends the segment.
            Head::Function => Head::Start,
            Head::CoprocName | Head::No => Head::No,
        }
    }

    /// A compound word here opens a block.
    fn opens(self) -> bool {
        matches!(
            self,
            Head::Start | Head::Time | Head::Coproc | Head::CoprocName
        )
    }

    /// A compound word here closes a block.
    fn closes(self) -> bool {
        matches!(self, Head::Start | Head::Time | Head::Coproc)
    }
}

/// How a shell fed by a pipe or a here-string runs it.
enum Reader {
    /// As its script: no command, `-s`, or a path to its stdin.
    Script,
    /// `-c LINE`, and whether the guard can read the line: the commands of
    /// the line read that stdin.
    Inline(String, bool),
    /// A script path the guard cannot read (`sh "$f"`, `sh /dev/std*`):
    /// it may be its stdin.
    Unread,
    /// A relative script path: whether it is the shell's stdin depends on
    /// the directory, which the engine resolves (`FedScript`).
    Relative(String),
}

struct Out {
    segments: Vec<Segment>,
    /// Trap actions, with the lexer depth they were found at.
    traps: Vec<(String, usize)>,
}

impl Out {
    /// `toks` as segments, read at `depth`. `outer`: every command of the
    /// line reads this, unless a pipe of its own feeds it (`bash -c 'sh'` fed
    /// by a pipe).
    fn collect(&mut self, toks: Vec<LexTok>, ctx: &mut Ctx, depth: usize, outer: Option<Source>) {
        let first = self.segments.len();
        let mut current: Segment = Vec::new();
        // After a `|`: what writes it.
        let mut pipe: Option<Source> = None;
        // What the current segment reads.
        let mut fed: Option<Source> = None;
        // Where the current segment's words so far leave the next word.
        let mut head = Head::Start;
        // The current segment comes right after a group's `)` or `}`.
        let mut after_group = false;
        // Frames a pipe feeds, innermost last: until each closes, every
        // command in it reads that pipe. No allocation until a pipe feeds a
        // group or a compound command.
        let mut groups: Vec<Group> = Vec::new();
        // The unquoted openers and closers of blocks seen so far, wherever
        // they stand: a frame closes only if they balance since it opened.
        let mut seen = (0usize, 0usize);
        for tok in toks {
            match tok {
                LexTok::Word(w) => {
                    if current.is_empty() {
                        fed = pipe
                            .take()
                            .or_else(|| groups.last().map(|g| g.source.clone()))
                            .or_else(|| outer.clone());
                        head = Head::Start;
                    }
                    if !w.quoted {
                        match compound_word(&w.text) {
                            // Inside a fed frame, an opener anywhere opens
                            // one: one that is an argument (`echo if`)
                            // only keeps the pipe fed for longer.
                            Some((open, true)) => {
                                seen.0 += 1;
                                if head.opens() || !groups.is_empty() {
                                    if let Some(source) = fed.clone() {
                                        groups.push(Group {
                                            open,
                                            source,
                                            start: self.segments.len(),
                                            seen,
                                        });
                                    }
                                }
                            }
                            Some((close, false)) if head.closes() => {
                                close_frame(&mut groups, close, &mut seen);
                            }
                            // An argument (`echo done`): it closes nothing.
                            Some(_) => seen.1 += 1,
                            None => {}
                        }
                    }
                    head = head.next(&w);
                    current.push(w);
                }
                LexTok::Operator(op) => {
                    let ended = !current.is_empty();
                    // The segment it ends is a compound command's last
                    // (`fi`), or comes right after a group's: a `}` here
                    // still closes a group, as one with no command before.
                    let closes = after_group
                        || current.first().is_some_and(|w| {
                            !w.quoted && matches!(w.text.as_str(), "fi" | "done" | "esac")
                        });
                    let source = ended.then(|| {
                        let seg = std::mem::take(&mut current);
                        // `fi <<< 'x'`, `} <<< 'x'`: the compound command
                        // before reads the here-string.
                        let at = self.finish(seg, fed.take(), ctx, depth, false);
                        if closes {
                            self.compound_here_string(first, at, ctx, depth);
                        }
                        at
                    });
                    match op {
                        Operator::LParen | Operator::LBrace => {
                            seen.0 += 1;
                            let feeds = pipe
                                .take()
                                .filter(|_| !ended)
                                .or_else(|| groups.last().map(|g| g.source.clone()));
                            if let Some(source) = feeds {
                                groups.push(Group {
                                    open: if op == Operator::LParen {
                                        Opener::Paren
                                    } else {
                                        Opener::Brace
                                    },
                                    source,
                                    start: self.segments.len(),
                                    seen,
                                });
                            }
                        }
                        // A `case` pattern's `)` closes nothing.
                        Operator::RParen
                            if groups.last().is_some_and(|g| g.open == Opener::Case) => {}
                        Operator::RParen => close_frame(&mut groups, Opener::Paren, &mut seen),
                        // `}` after a command's words is one of them, as in
                        // bash (`echo }`): it closes nothing.
                        Operator::RBrace if ended && !closes => seen.1 += 1,
                        Operator::RBrace => close_frame(&mut groups, Opener::Brace, &mut seen),
                        _ => {}
                    }
                    after_group = matches!(op, Operator::RParen | Operator::RBrace);
                    pipe = match op {
                        Operator::Pipe => Some(source.map_or(Source::Unknown, Source::Segment)),
                        // `|&` and a newline after `|` leave the pipe open.
                        Operator::Amp | Operator::Newline if !ended => pipe,
                        _ => None,
                    };
                }
            }
        }
        if !current.is_empty() {
            let closes = after_group
                || current.first().is_some_and(|w| {
                    !w.quoted && matches!(w.text.as_str(), "fi" | "done" | "esac")
                });
            let at = self.finish(current, fed, ctx, depth, false);
            if closes {
                self.compound_here_string(first, at, ctx, depth);
            }
        }
        // A frame that never closed (an unbalanced block, or one a closer
        // could not end because its openers and closers did not balance):
        // what is in it and after it was judged as fed, but where the pipe
        // goes is not known.
        if let Some(open) = groups.first() {
            let start = open.start.min(self.segments.len());
            if self.segments[start..]
                .iter()
                .any(|s| stdin_reader(s).is_some())
            {
                ctx.note(UNREAD_SCRIPT);
            }
        }
    }

    /// The segment at `at` ends a compound command or a group (`fi`, `done`,
    /// `esac`, after `)` or `}`) and may hold a here-string, which every
    /// command of it reads. When a shell that reads stdin is among the
    /// segments of this line since `first`, the here-string is judged as its
    /// script (an over-approximation: the block's own start is not tracked
    /// outside a pipe).
    fn compound_here_string(&mut self, first: usize, at: usize, ctx: &mut Ctx, depth: usize) {
        let Some(i) = self.segments[at]
            .iter()
            .position(|w| w.redirect && w.text.ends_with("<<<"))
        else {
            return;
        };
        let Some((text, readable)) = self.segments[at]
            .get(i + 1)
            .map(|w| (w.text.clone(), readable(w)))
        else {
            return;
        };
        if !spend(ctx, at - first.min(at)) {
            return;
        }
        if !self.segments[first.min(at)..at]
            .iter()
            .any(|s| stdin_reader(s).is_some())
        {
            return;
        }
        if !readable {
            ctx.note(UNREAD_SCRIPT);
        }
        self.splice(&text, ctx, depth, None);
    }

    /// Add `seg`, and after it the command lines it runs. `fed`: what it
    /// reads on stdin. `in_find`: it is what a `find` action runs. Returns
    /// the index of `seg`.
    fn finish(
        &mut self,
        seg: Segment,
        fed: Option<Source>,
        ctx: &mut Ctx,
        depth: usize,
        in_find: bool,
    ) -> usize {
        let seg = strip_leading_keywords(seg);
        let at = self.segments.len();
        // The gates: one pass over the words.
        let mut here = None;
        let mut exec = false;
        let mut trap = false;
        for (i, w) in seg.iter().enumerate() {
            if w.redirect && w.text.ends_with("<<<") && here.is_none() {
                here = Some(i + 1);
            }
            exec |= is_exec(w);
            trap |= w.text == "trap";
        }
        // Its stdin: the here-string, else what fed it.
        let source = match here.and_then(|i| seg.get(i)) {
            Some(w) => Some(Source::Text(w.text.clone(), readable(w))),
            None => fed,
        };
        let reader = if source.is_some() {
            stdin_reader(&seg)
        } else {
            None
        };
        let slices = if exec {
            find_slices(&seg, in_find)
        } else {
            Vec::new()
        };
        let action = if trap { trap_action(&seg) } else { None };
        let mut seg = seg;
        if let (Some(Reader::Relative(path)), Some(src), Some(first)) =
            (&reader, &source, seg.first_mut())
        {
            let known = self.text_of(src);
            first.fed_script = Some(Box::new(FedScript {
                path: path.clone(),
                readable: known.as_ref().is_some_and(|(_, r)| *r),
                text: known.map(|(t, _)| t),
            }));
        }
        self.segments.push(seg);
        match (reader, &source) {
            (Some(Reader::Script), Some(src)) => match self.text_of(src) {
                Some((text, readable)) => {
                    if !readable {
                        ctx.note(UNREAD_SCRIPT);
                    }
                    self.splice(&text, ctx, depth, None);
                }
                None => ctx.note(UNREAD_SCRIPT),
            },
            (Some(Reader::Inline(line, readable)), Some(_)) => {
                if !readable {
                    ctx.note(UNREAD_SCRIPT);
                }
                self.splice(&line, ctx, depth, source.clone());
            }
            (Some(Reader::Unread), Some(_)) => ctx.note(UNREAD_SCRIPT),
            _ => {}
        }
        // What find runs reads find's stdin.
        for slice in slices {
            if depth + 1 >= MAX_FRAME_DEPTH {
                ctx.note(TOO_DEEP);
                break;
            }
            if !spend(ctx, slice.iter().map(|w| w.text.len()).sum()) {
                break;
            }
            self.finish(slice, source.clone(), ctx, depth + 1, true);
        }
        if let Some((text, readable)) = action {
            if !readable {
                ctx.note(UNREAD_SCRIPT);
            }
            self.traps.push((text, depth));
        }
        at
    }

    /// What `src` writes, when the guard can know it, and whether it is
    /// readable.
    fn text_of(&self, src: &Source) -> Option<(String, bool)> {
        match src {
            Source::Segment(i) => {
                let seg = &self.segments[*i];
                printed(seg).map(|t| (t, seg.iter().all(readable)))
            }
            Source::Text(text, readable) => Some((text.clone(), *readable)),
            Source::Unknown => None,
        }
    }

    /// Lex `text` as a command line one level below `depth`, and add its
    /// segments, each reading `outer` unless fed otherwise.
    fn splice(&mut self, text: &str, ctx: &mut Ctx, depth: usize, outer: Option<Source>) {
        if depth + 1 >= MAX_FRAME_DEPTH {
            ctx.note(TOO_DEEP);
            return;
        }
        if !spend(ctx, text.len()) {
            return;
        }
        let toks = lex_in(&mut Chars::new(text), ctx, depth + 1, false, false, false).toks;
        self.collect(toks, ctx, depth + 1, outer);
    }
}

/// A closer of a `kind` block: it ends the innermost frame if that is one,
/// and only if the openers and closers since it opened balance. Otherwise
/// the frame stays and keeps feeding the rest of the line, fail closed: the
/// line is then recorded as unjudged where a shell reads it.
fn close_frame(groups: &mut Vec<Group>, kind: Opener, seen: &mut (usize, usize)) {
    if groups
        .last()
        .is_some_and(|g| g.open == kind && seen.0 - g.seen.0 == seen.1 - g.seen.1)
    {
        groups.pop();
    }
    seen.1 += 1;
}

/// Pay `bytes` from the line's hidden-line bytes; false, and the line is
/// past its limit, when they are spent.
fn spend(ctx: &mut Ctx, bytes: usize) -> bool {
    match ctx.hidden_bytes.checked_sub(bytes) {
        Some(left) => {
            ctx.hidden_bytes = left;
            true
        }
        None => {
            ctx.hidden_spent = true;
            false
        }
    }
}

/// Text the guard can read as it is: no substitution and no `$` a shell
/// expands.
fn readable(w: &Word) -> bool {
    !w.has_substitution && (!w.text.contains('$') || w.literal_dollars)
}

/// `find`'s actions that run a command.
fn is_exec(w: &Word) -> bool {
    matches!(w.text.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir")
}

/// A program's name without its directory and a `.exe`.
fn base_name(text: &str) -> &str {
    let base = text.rsplit(['/', '\\']).next().unwrap_or(text);
    match base
        .len()
        .checked_sub(4)
        .and_then(|n| base.split_at_checked(n))
    {
        Some((stem, ext)) if ext.eq_ignore_ascii_case(".exe") => stem,
        _ => base,
    }
}

/// The POSIX shells, as `wintable::unread_shell` knows them. `cmd` and
/// `powershell` reading a pipe are the Windows engine's (`nested_shell_phase`
/// denies them there); on a POSIX host they stay as they were.
const POSIX_SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "mksh"];

/// A variable that names the shell itself.
fn names_this_shell(text: &str) -> bool {
    matches!(text, "$SHELL" | "${SHELL}" | "$BASH" | "${BASH}")
}

/// How `seg` runs its stdin, when it is a POSIX shell that reads it.
fn stdin_reader(seg: &[Word]) -> Option<Reader> {
    let named = |w: &Word| {
        let base = base_name(&w.text);
        names_this_shell(&w.text) || POSIX_SHELLS.iter().any(|s| base.eq_ignore_ascii_case(s))
    };
    // `xargs` reads the pipe itself, and its command's stdin is /dev/null.
    if !seg.iter().any(named) || peeled_wrappers(seg).iter().any(|w| w == "xargs") {
        return None;
    }
    let mut argv = without_redirects(effective_command(seg));
    let first = argv.first_mut()?;
    if names_this_shell(&first.text) {
        first.text = "sh".to_string();
    }
    let name = base_name(&first.text).to_ascii_lowercase();
    if !POSIX_SHELLS.contains(&name.as_str()) {
        return None;
    }
    if unread_shell(&argv).is_some() {
        return Some(Reader::Script);
    }
    let mut texts: Vec<String> = argv.iter().map(|w| w.text.clone()).collect();
    texts[0] = name;
    if let Some(line) = inline_payload(&texts) {
        let readable = argv.iter().find(|w| w.text == line).is_none_or(readable);
        return Some(Reader::Inline(line, readable));
    }
    // `bash /dev/stdin`, `sh -`: the script is its stdin.
    let at = 1 + script_operand(&texts[1..])?;
    let word = &argv[at];
    match stdin_path(&word.text) {
        PathKind::Stdin => Some(Reader::Script),
        // Its value or its glob decides which file it runs.
        _ if !readable(word) || word.glob => Some(Reader::Unread),
        PathKind::Unread => Some(Reader::Unread),
        PathKind::Relative => Some(Reader::Relative(word.text.clone())),
        PathKind::Other => None,
    }
}

/// The index in `args` of a POSIX shell's script operand: its first word
/// that is no option, the values of `-o`/`-O`/`+o`/`+O`, `--rcfile` and
/// `--init-file` skipped. A lone `-` is one.
fn script_operand(args: &[String]) -> Option<usize> {
    let mut i = 0;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "--" => return (i + 1 < args.len()).then_some(i + 1),
            "--rcfile" | "--init-file" => i += 1,
            a if a.starts_with("--") => {}
            a if (a.starts_with('-') || a.starts_with('+')) && a.len() > 1 => {
                if a[1..].contains(['o', 'O']) {
                    i += 1;
                }
            }
            _ => return Some(i),
        }
        i += 1;
    }
    None
}

/// What a script operand names, read lexically.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PathKind {
    /// The shell's own stdin: `-`, `/dev/stdin`, `/dev/fd/0`, `/proc/ANY/fd/0`.
    Stdin,
    /// Some other file, an ordinary one.
    Other,
    /// It may be the shell's stdin and the guard cannot tell: fail closed.
    Unread,
    /// A relative path with no `..`: the engine resolves it against the
    /// directories the shell may be in (`fed_script_in`).
    Relative,
}

/// Devices under `/dev/` that are no stdin: a script read from one is
/// another file (`/dev/null` is empty).
const PLAIN_DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

/// What `path` names, read lexically: repeated `/` collapsed and `.`
/// dropped. Exactly `-`, `/dev/stdin`, `/dev/fd/0` or `/proc/ANY/fd/0` is
/// stdin. Anything else that could reach it is `Unread`, not matched by
/// shape: a `..` anywhere, and any other path under `/proc/` or `/dev/` but
/// a plain device. A relative path is `Relative`: the directory it starts
/// from is the engine's. A symlink to stdin is not seen: no file is read.
fn stdin_path(path: &str) -> PathKind {
    if path == "-" {
        return PathKind::Stdin;
    }
    let absolute = path.starts_with('/');
    let parts: Vec<&str> = path
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if parts.contains(&"..") {
        return PathKind::Unread;
    }
    if absolute {
        return match parts.as_slice() {
            ["dev", "stdin"] | ["dev", "fd", "0"] | ["proc", _, "fd", "0"] => PathKind::Stdin,
            ["dev", device] if PLAIN_DEVICES.contains(device) => PathKind::Other,
            ["dev" | "proc", ..] => PathKind::Unread,
            _ => PathKind::Other,
        };
    }
    PathKind::Relative
}

/// A relative script path `path` run from `dir`: `dir` joined to it, read
/// as an absolute path by `stdin_path`. `dir` that is not a POSIX absolute
/// path (a Windows one) names no stdin path.
pub(crate) fn fed_script_in(dir: &str, path: &str) -> PathKind {
    if !dir.starts_with('/') {
        return PathKind::Other;
    }
    stdin_path(&format!("{dir}/{path}"))
}

/// A relative script path run from a directory the guard does not know:
/// fail closed when a component could lead to stdin (`fd`, `dev`, `proc`,
/// `self`, `thread-self`, `stdin`) or the last one is a descriptor number.
pub(crate) fn fed_script_may_be_stdin(path: &str) -> bool {
    let parts = || path.split('/').filter(|p| !p.is_empty() && *p != ".");
    parts().any(|p| matches!(p, "fd" | "dev" | "proc" | "self" | "thread-self" | "stdin"))
        || parts()
            .next_back()
            .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()))
}

/// The commands `find -exec`, `-execdir`, `-ok` and `-okdir` run, as find
/// reads them: after an action, every word up to the first `;`, or `+` right
/// after `{}`, words that look like `-exec` too; then the next action. Find
/// refuses an action with no end, which runs nothing. `in_find`: `seg` is
/// what an outer find runs, whose end was the outer action's; an inner action
/// with no end of its own runs to there (`find . -exec find . -exec CMD \;`).
/// Each word of a line is in one command of each level at most.
fn find_slices(seg: &[Word], in_find: bool) -> Vec<Segment> {
    let Some((name, args)) = effective_command(seg).split_first() else {
        return Vec::new();
    };
    if !base_name(&name.text).eq_ignore_ascii_case("find") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if !is_exec(&args[i]) {
            i += 1;
            continue;
        }
        let start = i + 1;
        let ends = |j: usize| {
            let t = args[j].text.as_str();
            t == ";" || (t == "+" && j > start && args[j - 1].text == "{}")
        };
        let stop = match (start..args.len()).find(|&j| ends(j)) {
            Some(j) => j,
            None if in_find => args.len(),
            None => break,
        };
        if start < stop {
            out.push(args[start..stop].to_vec());
        }
        i = stop + 1;
    }
    out
}

/// The action of `trap [--] ACTION SIGNAL…`, and whether it is readable.
/// None for `trap -p`, `trap -l`, `trap SIGNAL` (one operand resets it),
/// `trap - SIGNAL` and `trap '' SIGNAL`.
fn trap_action(seg: &[Word]) -> Option<(String, bool)> {
    let (name, args) = effective_command(seg).split_first()?;
    if name.text != "trap" {
        return None;
    }
    let args = without_redirects(args);
    let mut ops = args.as_slice();
    if ops.first().is_some_and(|w| w.text == "--") {
        ops = &ops[1..];
    } else if ops
        .first()
        .is_some_and(|w| w.text.starts_with('-') && w.text != "-")
    {
        return None;
    }
    let [action, _signal, ..] = ops else {
        return None;
    };
    if action.text.is_empty() || action.text == "-" {
        return None;
    }
    Some((action.text.clone(), readable(action)))
}
