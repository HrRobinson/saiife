//! The deterministic never-line extraction (plan 33, D1).
//!
//! Pure text in, candidates out. A candidate is a line that says never,
//! don't, must not and the like, outside fenced blocks and HTML comments.
//! Its targets are the commands and paths it names; a line naming none is a
//! judgement line, listed later as not enforced.

use saiifeguard::pathrule::RuleAccess;
use sha2::{Digest, Sha256};

use super::{Candidate, SourceLine, Target};

/// Hex SHA-256 of a line with its trailing whitespace (`\r` included) removed.
pub fn line_sha256(text: &str) -> String {
    let digest = Sha256::digest(text.trim_end().as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every line of `text`, numbered from 1.
pub fn all_lines(text: &str) -> Vec<SourceLine> {
    text.lines()
        .enumerate()
        .map(|(i, l)| source_line(i, l))
        .collect()
}

fn source_line(index: usize, raw: &str) -> SourceLine {
    let text = raw.trim_end().to_string();
    SourceLine {
        line: u32::try_from(index + 1).unwrap_or(u32::MAX),
        line_sha256: line_sha256(&text),
        text,
    }
}

/// The never-lines of `text`, with the targets each one names.
pub fn candidates(text: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut in_comment = false;
    let mut fence: Option<char> = None;
    for (i, raw) in text.lines().enumerate() {
        let visible = strip_comments(raw, &mut in_comment);
        let t = visible.trim_start();
        if let Some(f) = fence {
            if t.starts_with(&f.to_string().repeat(3)) {
                fence = None;
            }
            continue;
        }
        if let Some(f) = ['`', '~']
            .into_iter()
            .find(|c| t.starts_with(&c.to_string().repeat(3)))
        {
            fence = Some(f);
            continue;
        }
        let (masked, spans) = mask_spans(&visible);
        if !is_never_line(&masked) {
            continue;
        }
        out.push(Candidate {
            src: source_line(i, raw),
            targets: targets(&masked, &spans),
        });
    }
    out
}

/// `raw` without its HTML comments; `in_comment` carries an open one over lines.
fn strip_comments(raw: &str, in_comment: &mut bool) -> String {
    let mut out = String::new();
    let mut rest = raw;
    loop {
        if *in_comment {
            match rest.find("-->") {
                Some(p) => {
                    rest = &rest[p + 3..];
                    *in_comment = false;
                }
                None => return out,
            }
        } else {
            match rest.find("<!--") {
                Some(p) => {
                    out.push_str(&rest[..p]);
                    rest = &rest[p + 4..];
                    *in_comment = true;
                }
                None => {
                    out.push_str(rest);
                    return out;
                }
            }
        }
    }
}

/// The marker standing in for a backtick span in the masked line. It is not a
/// word character, so a masked span never reads as a keyword or a word.
const MASK: char = '\u{1}';

/// `line` with each backtick span (the ticks included) turned into `MASK`s
/// of the same byte length, and the spans' contents in order with the byte
/// offset of their opening tick. An unclosed tick is plain text.
fn mask_spans(line: &str) -> (String, Vec<(usize, String)>) {
    let mut masked = String::new();
    let mut spans = Vec::new();
    let mut rest = line;
    let mut at = 0;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('`') else { break };
        masked.push_str(&rest[..open]);
        let len = close + 2;
        masked.extend(std::iter::repeat_n(MASK, len));
        spans.push((at + open, after[..close].to_string()));
        rest = &rest[open + len..];
        at += open + len;
    }
    masked.push_str(rest);
    (masked, spans)
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whether `word` occurs in `lower` with no word character on either side.
fn has_word(lower: &str, word: &str) -> bool {
    lower.match_indices(word).any(|(i, m)| {
        let before = lower[..i].chars().next_back();
        let after = lower[i + m.len()..].chars().next();
        !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char)
    })
}

fn is_never_line(masked: &str) -> bool {
    let lower = masked.to_lowercase();
    const KEYWORDS: [&str; 8] = [
        "never",
        "don't",
        "don\u{2019}t",
        "do not",
        "must not",
        "mustn't",
        "shall not",
        "may not",
    ];
    if KEYWORDS.iter().any(|k| has_word(&lower, k)) {
        return true;
    }
    // "No sudo, ...": a leading "no" after a list marker and bold marks.
    let mut t = lower.trim_start();
    for marker in ["- ", "* ", "+ "] {
        if let Some(r) = t.strip_prefix(marker) {
            t = r.trim_start();
            break;
        }
    }
    let digits = t.chars().take_while(char::is_ascii_digit).count();
    if digits > 0 {
        if let Some(r) = t[digits..].strip_prefix(". ") {
            t = r.trim_start();
        }
    }
    t.trim_start_matches("**").starts_with("no ")
}

/// A program-like word: `^[A-Za-z0-9][A-Za-z0-9._+-]*$`.
fn is_program_word(w: &str) -> bool {
    let mut chars = w.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
}

/// Starts like an absolute, home or `$NAME/` path, with no whitespace.
fn is_path_like(s: &str) -> bool {
    if s.is_empty() || s.contains(char::is_whitespace) || s.contains("://") {
        return false;
    }
    if s.starts_with('/') || s.starts_with("~/") {
        return true;
    }
    match s.strip_prefix('$') {
        Some(r) => {
            let name = r
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .count();
            name > 0 && r[name..].starts_with('/')
        }
        None => false,
    }
}

pub(crate) fn span_target(span: &str, access: RuleAccess) -> Option<Target> {
    let span = span.trim();
    if is_path_like(span) {
        return Some(Target::Path {
            glob: span.to_string(),
            access,
        });
    }
    let unsafe_char = |c: char| "|;&<>()$`".contains(c);
    if span.chars().any(unsafe_char) {
        return None;
    }
    let words: Vec<String> = span.split_whitespace().map(str::to_string).collect();
    if words.first().is_some_and(|w| is_program_word(w)) {
        Some(Target::Command(words))
    } else {
        None
    }
}

fn access_of(masked: &str) -> RuleAccess {
    const WRITE: [&str; 8] = [
        "write",
        "writes",
        "edit",
        "modify",
        "change",
        "delete",
        "remove",
        "overwrite",
    ];
    const READ: [&str; 6] = ["read", "reads", "open", "cat", "print", "show"];
    let lower = masked.to_lowercase();
    match (
        WRITE.iter().any(|w| has_word(&lower, w)),
        READ.iter().any(|w| has_word(&lower, w)),
    ) {
        (true, false) => RuleAccess::Write,
        (false, true) => RuleAccess::Read,
        _ => RuleAccess::Any,
    }
}

fn targets(masked: &str, spans: &[(usize, String)]) -> Vec<Target> {
    let access = access_of(masked);
    let mut found: Vec<(usize, Target)> = Vec::new();
    for (at, span) in spans {
        if let Some(t) = span_target(span, access) {
            found.push((*at, t));
        }
    }
    // Bare paths: whitespace-separated tokens outside backticks.
    let mut offset = 0;
    for token in masked.split_inclusive(char::is_whitespace) {
        let start = offset;
        offset += token.len();
        let bare = token.trim_matches(|c: char| c.is_whitespace() || ",.;:()\"'".contains(c));
        if is_path_like(bare) && !bare.contains(MASK) {
            found.push((
                start + token.find(bare).unwrap_or(0),
                Target::Path {
                    glob: bare.to_string(),
                    access,
                },
            ));
        }
    }
    // A list after the first colon outside backticks.
    if let Some(colon) = masked.find(':') {
        let list = &masked[colon + 1..];
        let segments = split_list(list);
        if segments.len() >= 2 {
            for (pos, seg) in segments {
                let word = seg
                    .trim()
                    .trim_end_matches('.')
                    .trim_start_matches("or ")
                    .trim_start_matches("and ")
                    .trim();
                if word.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                    && is_program_word(word)
                    && !word.chars().any(|c| c.is_ascii_uppercase())
                {
                    found.push((colon + 1 + pos, Target::Command(vec![word.to_string()])));
                }
            }
        }
    }
    found.sort_by_key(|(at, _)| *at);
    let mut out: Vec<Target> = Vec::new();
    for (_, t) in found {
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Split `list` on `,`, ` or `, ` and ` and `;`, giving each part's offset.
fn split_list(list: &str) -> Vec<(usize, &str)> {
    let mut parts = Vec::new();
    let mut start = 0;
    let bytes = list.as_bytes();
    let mut i = 0;
    while i < list.len() {
        let sep = if matches!(bytes[i], b',' | b';') {
            1
        } else if bytes[i..].starts_with(b" or ") {
            4
        } else if bytes[i..].starts_with(b" and ") {
            5
        } else {
            0
        };
        if sep > 0 {
            parts.push((start, &list[start..i]));
            i += sep;
            start = i;
        } else {
            i += 1;
        }
    }
    parts.push((start, &list[start..]));
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(words: &[&str]) -> Target {
        Target::Command(words.iter().map(|w| w.to_string()).collect())
    }

    fn path(glob: &str, access: RuleAccess) -> Target {
        Target::Path {
            glob: glob.into(),
            access,
        }
    }

    fn one(text: &str) -> Candidate {
        let mut c = candidates(text);
        assert_eq!(c.len(), 1, "{text}");
        c.remove(0)
    }

    #[test]
    fn colon_list_becomes_commands() {
        let c = one("- Never execute process-control or privilege tools, even to probe them: kill, pkill, killall, pgrep, sudo, su, systemctl.");
        let want: Vec<Target> = [
            "kill",
            "pkill",
            "killall",
            "pgrep",
            "sudo",
            "su",
            "systemctl",
        ]
        .iter()
        .map(|w| cmd(&[w]))
        .collect();
        assert_eq!(c.targets, want);
        assert_eq!(c.src.line, 1);
    }

    #[test]
    fn backticks_and_paths() {
        let c = one("- No sudo, no root, no systemd units, systemctl or `systemctl --user`, no writes to /etc, /opt, /var or /run, no docker.");
        assert_eq!(
            c.targets,
            vec![
                cmd(&["systemctl", "--user"]),
                path("/etc", RuleAccess::Write),
                path("/opt", RuleAccess::Write),
                path("/var", RuleAccess::Write),
                path("/run", RuleAccess::Write),
            ]
        );
    }

    #[test]
    fn home_path_any() {
        let c = one("Never touch ~/.claude, and never touch the real desktop keyring.");
        assert_eq!(c.targets, vec![path("~/.claude", RuleAccess::Any)]);
    }

    #[test]
    fn read_words_and_both() {
        let c = one("Never read /etc/shadow.");
        assert_eq!(c.targets, vec![path("/etc/shadow", RuleAccess::Read)]);
        let c = one("Never read or write /etc/shadow.");
        assert_eq!(c.targets, vec![path("/etc/shadow", RuleAccess::Any)]);
    }

    #[test]
    fn judgement_has_no_targets() {
        let c = one("Never put the word \"fix\" in a scratch name.");
        assert!(c.targets.is_empty());
    }

    #[test]
    fn fenced_and_quoted_lines_are_not_candidates() {
        let text = "```\nnever run x\n```\n~~~\nnever run z\n~~~\n<!-- never run y -->\n<!--\nnever run w\n-->\nUse `git push --force-with-lease`; that is fine.\nRun `never-ending-test`\n";
        assert!(candidates(text).is_empty(), "{:?}", candidates(text));
        // After the fence and comment close, lines count again, with their numbers.
        let c = candidates("```\nx\n```\nNever run `ls`.\n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].src.line, 4);
    }

    #[test]
    fn unsafe_span_is_not_a_command() {
        let c = one("Never run `rm -rf $(cat x)`");
        assert!(!c.targets.iter().any(|t| matches!(t, Target::Command(_))));
    }

    #[test]
    fn non_ascii_after_a_colon_does_not_panic() {
        let c = one("Never run: kill \u{2014} now, sudo.");
        assert_eq!(c.targets, vec![cmd(&["sudo"])]);
        let c = one("Never touch: ~/.claude \u{2014} ever, caf\u{e9} or \u{201c}x\u{201d}");
        assert_eq!(c.targets, vec![path("~/.claude", RuleAccess::Any)]);
    }

    #[test]
    fn urls_are_not_paths() {
        let c = one("Never fetch https://x/y");
        assert!(c.targets.is_empty());
    }

    #[test]
    fn targets_are_deduplicated_in_order() {
        let c = one("Never run `docker` or `docker`, nor `ls`.");
        assert_eq!(c.targets, vec![cmd(&["docker"]), cmd(&["ls"])]);
    }

    #[test]
    fn all_lines_are_numbered_and_hashed() {
        let l = all_lines("a\r\nb \n");
        assert_eq!(l.len(), 2);
        assert_eq!((l[1].line, l[1].text.as_str()), (2, "b"));
        assert_eq!(l[0].line_sha256, line_sha256("a"));
    }

    #[test]
    fn line_hash_ignores_trailing_space() {
        assert_eq!(line_sha256("a \r"), line_sha256("a"));
        assert_ne!(line_sha256(" a"), line_sha256("a"));
        assert_eq!(
            line_sha256("a"),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
    }
}
