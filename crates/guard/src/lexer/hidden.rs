//! Command lines a segment runs that are not where a command starts: what
//! `find -exec` runs, what a shell reads from a pipe or a here-string, and a
//! `trap` action. Each becomes segments of its own, after the segment that
//! runs it, so every rule judges it, as the body of `bash <<EOF` already is.
//! Text a shell runs that the guard cannot read (`echo "$x" | sh`, `curl … |
//! sh`) is noted (`UNREAD_SCRIPT`): a recorded fail-open, which a caller that
//! fails closed denies. Literal text is still judged.
//!
//! The gates are a pass over each segment's words, with no allocation; the
//! rest runs only for a segment that has one of these shapes.

use super::{
    lex_in, printed, strip_leading_keywords, Chars, Ctx, LexTok, Operator, Segment, Word,
    MAX_FRAME_DEPTH, TOO_DEEP,
};
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
    out.collect(toks, ctx, 0);
    // A trap action runs when its trap fires: at the latest where the line
    // ends, in the directory the line left it in. Judged there, it is judged
    // with all the directories the line may be in.
    let mut i = 0;
    while let Some((action, depth)) = out.traps.get_mut(i).map(std::mem::take) {
        out.splice(&action, ctx, depth);
        i += 1;
    }
    out.segments
}

struct Out {
    segments: Vec<Segment>,
    /// Trap actions, with the lexer depth they were found at.
    traps: Vec<(String, usize)>,
}

impl Out {
    /// `toks` as segments, read at `depth`.
    fn collect(&mut self, toks: Vec<LexTok>, ctx: &mut Ctx, depth: usize) {
        let mut current: Segment = Vec::new();
        // After a `|`: `Some(source)`, where `source` is the index of the
        // segment that writes to it when that is one simple command.
        let mut pipe: Option<Option<usize>> = None;
        // What `pipe` was when the current segment started.
        let mut fed: Option<Option<usize>> = None;
        for tok in toks {
            match tok {
                LexTok::Word(w) => {
                    if current.is_empty() {
                        fed = pipe.take();
                    }
                    current.push(w);
                }
                LexTok::Operator(op) => {
                    let ended = !current.is_empty();
                    let source = if ended {
                        Some(self.finish(std::mem::take(&mut current), fed.take(), ctx, depth))
                    } else {
                        None
                    };
                    pipe = match op {
                        Operator::Pipe => Some(source),
                        // `|&`, a newline after `|`, and a group the pipe
                        // feeds (`| (sh)`) leave the pipe open.
                        Operator::Amp | Operator::Newline | Operator::LParen | Operator::LBrace
                            if !ended =>
                        {
                            pipe
                        }
                        _ => None,
                    };
                }
            }
        }
        if !current.is_empty() {
            self.finish(current, fed, ctx, depth);
        }
    }

    /// Add `seg`, and after it the command lines it runs. `fed`: it reads a
    /// pipe (`Some`), written by the segment at that index when that one is a
    /// simple command. Returns the index of `seg`.
    fn finish(
        &mut self,
        seg: Segment,
        fed: Option<Option<usize>>,
        ctx: &mut Ctx,
        depth: usize,
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
        // Text a shell reads on stdin: from the here-string, else the pipe.
        let mut script: Option<Option<(String, bool)>> = None;
        if (here.is_some() || fed.is_some()) && stdin_shell(&seg) {
            script = Some(match (here.and_then(|i| seg.get(i)), fed) {
                (Some(w), _) => Some((w.text.clone(), readable(w))),
                (None, Some(Some(source))) => {
                    let src = &self.segments[source];
                    printed(src).map(|t| (t, src.iter().all(readable)))
                }
                (None, _) => None,
            });
        }
        let slices = if exec { find_slices(&seg) } else { Vec::new() };
        let action = if trap { trap_action(&seg) } else { None };
        self.segments.push(seg);
        match script {
            Some(Some((text, readable))) => {
                if !readable {
                    ctx.note(UNREAD_SCRIPT);
                }
                self.splice(&text, ctx, depth);
            }
            Some(None) => ctx.note(UNREAD_SCRIPT),
            None => {}
        }
        for slice in slices {
            self.finish(slice, None, ctx, depth);
        }
        if let Some((text, readable)) = action {
            if !readable {
                ctx.note(UNREAD_SCRIPT);
            }
            self.traps.push((text, depth));
        }
        at
    }

    /// Lex `text` as a command line one level below `depth`, and add its
    /// segments.
    fn splice(&mut self, text: &str, ctx: &mut Ctx, depth: usize) {
        if depth + 1 >= MAX_FRAME_DEPTH {
            ctx.note(TOO_DEEP);
            return;
        }
        match ctx.hidden_bytes.checked_sub(text.len()) {
            Some(left) => ctx.hidden_bytes = left,
            None => {
                ctx.hidden_spent = true;
                return;
            }
        }
        let toks = lex_in(&mut Chars::new(text), ctx, depth + 1, false, false, false).toks;
        self.collect(toks, ctx, depth + 1);
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

/// `seg` runs a POSIX shell that reads its commands from stdin.
fn stdin_shell(seg: &[Word]) -> bool {
    let named = |w: &Word| {
        let base = base_name(&w.text);
        names_this_shell(&w.text) || POSIX_SHELLS.iter().any(|s| base.eq_ignore_ascii_case(s))
    };
    // `xargs` reads the pipe itself, and its command's stdin is /dev/null.
    if !seg.iter().any(named) || peeled_wrappers(seg).iter().any(|w| w == "xargs") {
        return false;
    }
    let mut argv = without_redirects(effective_command(seg));
    let Some(first) = argv.first_mut() else {
        return false;
    };
    if names_this_shell(&first.text) {
        first.text = "sh".to_string();
    }
    let posix = POSIX_SHELLS
        .iter()
        .any(|s| base_name(&first.text).eq_ignore_ascii_case(s));
    posix && unread_shell(&argv).is_some()
}

/// The commands `find -exec`, `-execdir`, `-ok` and `-okdir` run: the words
/// after each up to `;`, or `+` right after `{}`. One ends early at the next
/// such action, which has its own; so each word is in one command at most,
/// and `find . -exec find . -exec CMD \; \;` judges `CMD`. Find refuses an
/// action with no end after it: that runs nothing.
fn find_slices(seg: &[Word]) -> Vec<Segment> {
    let Some((name, args)) = effective_command(seg).split_first() else {
        return Vec::new();
    };
    if !base_name(&name.text).eq_ignore_ascii_case("find") {
        return Vec::new();
    }
    let ends = |j: usize| {
        let t = args[j].text.as_str();
        t == ";" || (t == "+" && j > 0 && args[j - 1].text == "{}")
    };
    let Some(last_end) = (0..args.len()).rev().find(|&j| ends(j)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < last_end {
        if !is_exec(&args[i]) {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < args.len() && !ends(j) && !is_exec(&args[j]) {
            j += 1;
        }
        if start < j {
            out.push(args[start..j].to_vec());
        }
        i = j;
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
