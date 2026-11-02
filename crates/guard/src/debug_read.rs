//! What the PowerShell and cmd readers took a line to be, for
//! `scripts/differential-windows.ps1`, which compares it with the real shells.
//! Debug builds only: a shipped binary has no use for it.

use crate::cmdexe;
use crate::lexer::{Segment, Word};
use crate::pwsh;
use crate::wintable::Dialect;

/// How deep `cmd /c "cmd /c …"` is followed, as the engine does.
const MAX_NESTING: u32 = 8;

/// A word of a command as PowerShell's reader saw it, before the table.
#[derive(Debug, Clone)]
pub struct RawWord {
    pub word: Word,
    /// It started with a quote: a value, never a parameter.
    pub from_quote: bool,
    /// A bracket or block. It has no text; what is inside is read on its own.
    pub block: bool,
}

/// One reading of a line.
#[derive(Debug, Default)]
pub struct Read {
    /// The commands in the reader's terms, before translation (PowerShell only).
    pub commands: Vec<Vec<RawWord>>,
    /// The segments the engine judges, in POSIX terms.
    pub segments: Vec<Segment>,
    /// Segments of what the line nests (`cmd /c x`), read in their own dialect.
    pub nested: Vec<Segment>,
    pub note: Option<&'static str>,
}

/// `line` as `dialect` reads it.
pub fn read(line: &str, dialect: Dialect) -> Read {
    let mut out = Read::default();
    match dialect {
        Dialect::PowerShell => {
            let (commands, segments, note) = pwsh::read_with_commands(line);
            out.commands = commands;
            out.segments = segments;
            out.note = note;
        }
        Dialect::Cmd => {
            let (segments, note) = cmdexe::split_segments_noted(line);
            out.segments = segments;
            out.note = note;
        }
        Dialect::Posix => {
            let (segments, note) = crate::lexer::split_segments_noted(line);
            out.segments = segments;
            out.note = note;
        }
    }
    let top = out.segments.clone();
    follow(&top, 0, &mut out);
    out
}

fn follow(segments: &[Segment], depth: u32, out: &mut Read) {
    for seg in segments {
        let Some((dialect, inner)) = cmdexe::nested(seg) else {
            continue;
        };
        if depth >= MAX_NESTING || inner == crate::wintable::UNRESOLVED {
            out.note.get_or_insert(crate::engine::UNRESOLVED_REASON);
            continue;
        }
        let (segs, note) = match dialect {
            Dialect::PowerShell => pwsh::split_segments_noted(&inner),
            Dialect::Cmd => cmdexe::split_segments_noted(&inner),
            Dialect::Posix => crate::lexer::split_segments_noted(&inner),
        };
        if let Some(n) = note {
            out.note.get_or_insert(n);
        }
        follow(&segs, depth + 1, out);
        out.nested.extend(segs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(commands: &[Vec<RawWord>]) -> Vec<Vec<String>> {
        commands
            .iter()
            .map(|c| c.iter().map(|r| r.word.text.clone()).collect())
            .collect()
    }

    #[test]
    fn powershell_commands_are_untranslated() {
        let r = read("Remove-Item -Recurse x; g`it status", Dialect::PowerShell);
        assert_eq!(
            texts(&r.commands),
            [vec!["Remove-Item", "-Recurse", "x"], vec!["git", "status"]]
        );
        assert_eq!(r.segments[0][0].text, "rm");
        assert_eq!(r.note, None);
    }

    #[test]
    fn a_nested_cmd_is_followed() {
        let r = read("cmd /c \"cmd /c stub a\"", Dialect::Cmd);
        assert!(r.nested.iter().any(|s| s[0].text == "stub"));
    }

    #[test]
    fn a_cmd_variable_is_noted() {
        let r = read("%X:~0% a", Dialect::Cmd);
        assert!(r.note.is_some());
    }
}
