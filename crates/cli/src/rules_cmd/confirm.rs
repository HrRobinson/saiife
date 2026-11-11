//! The confirm table: enforce, ask, skip or edit each proposal (plan 33 task 4).
//!
//! `table` is the overview printed to stdout; `confirm` asks one question per
//! proposal on `out` (stderr) and reads the answers from `input`. End of
//! input before the last answer is `Err(Eof)`: the caller writes nothing.

use std::io::{BufRead, Write};

use saiifeguard::pack::RuleWhere;
use saiifeguard::pathrule::RuleAccess;

use super::extract::span_target;
use super::{Choice, Decided, Proposal, ProposalKind, SourceLine, Target, Unverified};

/// Input ended (or failed) before the last answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eof;

/// Text from a file or the engine, safe to print: control characters are
/// replaced, so a hostile line cannot drive the terminal.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn access_name(a: RuleAccess) -> &'static str {
    match a {
        RuleAccess::Read => "read",
        RuleAccess::Write => "write",
        RuleAccess::Any => "any",
        _ => "write content",
    }
}

fn rule_text(p: &Proposal) -> String {
    match &p.kind {
        ProposalKind::Command { words, .. } => format!("deny command `{}`", words.join(" ")),
        ProposalKind::Path { globs, access } => {
            format!("deny path {} ({})", globs.join(", "), access_name(*access))
        }
    }
}

/// `file:line` of a proposal, from the start of its reason.
fn location(p: &Proposal) -> String {
    match p.reason.split(' ').next() {
        Some(loc) if loc.contains(':') => clean(loc),
        _ => format!("line {}", p.src.line),
    }
}

pub fn table(props: &[Proposal], unverified: &[Unverified], judgement: &[SourceLine]) -> String {
    let mut out = String::new();
    for (i, p) in props.iter().enumerate() {
        let mut flags = String::new();
        if p.broad.is_some() {
            flags.push_str("  BROAD");
        }
        if p.host_hint {
            flags.push_str("  often host only");
        }
        let list = |v: &[String]| {
            v.iter()
                .map(|e| format!("`{}`", clean(e)))
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "{:>3}  {}  {}  blocks {}  allows {}{}\n",
            i + 1,
            location(p),
            rule_text(p),
            list(&p.block),
            list(&p.allow),
            flags
        ));
    }
    if !unverified.is_empty() || !judgement.is_empty() {
        out.push_str("Not enforced:\n");
        for u in unverified {
            out.push_str(&format!(
                "  line {}  {}  unverified: {}\n",
                u.src.line,
                clean(u.src.text.trim()),
                clean(&u.why)
            ));
        }
        for j in judgement {
            out.push_str(&format!(
                "  line {}  {}  judgement\n",
                j.line,
                clean(j.text.trim())
            ));
        }
    }
    out.push_str(&format!(
        "{} proposed, {} unverified, {} judgement\n",
        props.len(),
        unverified.len(),
        judgement.len()
    ));
    out
}

fn read_answer(input: &mut dyn BufRead) -> Result<String, Eof> {
    let mut line = String::new();
    match input.read_line(&mut line) {
        Ok(0) | Err(_) => Err(Eof),
        Ok(_) => Ok(line.trim().to_string()),
    }
}

fn ask_where(p: &Proposal, input: &mut dyn BufRead, out: &mut dyn Write) -> Result<RuleWhere, Eof> {
    loop {
        let hint = if p.host_hint {
            " (often host only)"
        } else {
            ""
        };
        let _ = write!(out, "everywhere or host only?{hint} [E/h]: ");
        let _ = out.flush();
        match read_answer(input)?.to_lowercase().as_str() {
            "" | "e" => return Ok(RuleWhere::Everywhere),
            "h" => return Ok(RuleWhere::Host),
            _ => {
                let _ = writeln!(out, "answer e or h");
            }
        }
    }
}

pub fn confirm(
    props: Vec<Proposal>,
    ask_ok: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    repropose: &dyn Fn(&SourceLine, Target) -> Result<Proposal, String>,
) -> Result<Vec<Decided>, Eof> {
    let n = props.len();
    let mut decided = Vec::with_capacity(n);
    for (i, mut p) in props.into_iter().enumerate() {
        'question: loop {
            let can_ask = ask_ok && matches!(p.kind, ProposalKind::Command { .. });
            let _ = writeln!(
                out,
                "[{}/{}] {}  {}",
                i + 1,
                n,
                location(&p),
                clean(p.src.text.trim())
            );
            let _ = writeln!(out, "      {}", rule_text(&p));
            let _ = write!(
                out,
                "enforce, {}skip, edit? [e/{}s/x] (s): ",
                if can_ask { "ask, " } else { "" },
                if can_ask { "a/" } else { "" }
            );
            let _ = out.flush();
            let answer = read_answer(input)?.to_lowercase();
            let choice = match answer.as_str() {
                "" | "s" => {
                    decided.push(Decided {
                        p,
                        choice: Choice::Skip,
                        where_: RuleWhere::Everywhere,
                    });
                    break 'question;
                }
                "e" => Choice::Enforce,
                "a" if can_ask => Choice::Ask,
                "x" => {
                    let _ = write!(out, "new command or path (empty keeps): ");
                    let _ = out.flush();
                    let text = read_answer(input)?;
                    if text.is_empty() {
                        continue 'question;
                    }
                    let access = match &p.kind {
                        ProposalKind::Path { access, .. } => *access,
                        ProposalKind::Command { .. } => RuleAccess::Any,
                    };
                    match span_target(&text, access) {
                        None => {
                            let _ = writeln!(out, "not a command or a path: {}", clean(&text));
                        }
                        Some(t) => match repropose(&p.src, t) {
                            Ok(np) => p = np,
                            Err(why) => {
                                let _ = writeln!(out, "refused: {}", clean(&why));
                            }
                        },
                    }
                    continue 'question;
                }
                _ => {
                    let _ = writeln!(out, "answer e, a, s or x");
                    continue 'question;
                }
            };
            if let Some(b) = &p.broad {
                let _ = write!(out, "BROAD: {}. type yes to confirm: ", clean(b));
                let _ = out.flush();
                match read_answer(input)?.as_str() {
                    "yes" => {}
                    "" => {
                        decided.push(Decided {
                            p,
                            choice: Choice::Skip,
                            where_: RuleWhere::Everywhere,
                        });
                        break 'question;
                    }
                    _ => continue 'question,
                }
            }
            let where_ = ask_where(&p, input, out)?;
            decided.push(Decided { p, choice, where_ });
            break 'question;
        }
    }
    Ok(decided)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_cmd::extract::line_sha256;
    use crate::rules_cmd::propose::{propose, verify};
    use crate::rules_cmd::{Candidate, Origin};
    use saiifeguard::canon::PathVars;
    use std::io::Cursor;

    fn vars() -> PathVars {
        PathVars::new()
            .with_cwd("/saiife-test/project")
            .with_var("PROJECT", "/saiife-test/project")
            .with_var("HOME", "/saiife-test/home")
    }

    fn src(line: u32) -> SourceLine {
        let text = format!("- Never do thing {line}.");
        SourceLine {
            line,
            line_sha256: line_sha256(&text),
            text,
        }
    }

    fn make(s: &SourceLine, t: Target) -> Result<Proposal, String> {
        let c = Candidate {
            src: s.clone(),
            targets: vec![t],
        };
        let mut p = propose(&c, "CLAUDE.md", Origin::Rules).remove(0);
        verify(&mut p, &vars())?;
        Ok(p)
    }

    fn cmd(words: &[&str]) -> Target {
        Target::Command(words.iter().map(|w| (*w).to_string()).collect())
    }

    fn prop(line: u32, t: Target) -> Proposal {
        make(&src(line), t).unwrap()
    }

    fn run(props: Vec<Proposal>, ask_ok: bool, input: &str) -> (Result<Vec<Decided>, Eof>, String) {
        let mut out = Vec::new();
        let r = confirm(props, ask_ok, &mut Cursor::new(input), &mut out, &make);
        (r, String::from_utf8(out).unwrap())
    }

    #[test]
    fn defaults_skip_and_everywhere() {
        let ps = vec![prop(1, cmd(&["pkill"])), prop(2, cmd(&["shred"]))];
        let (r, out) = run(ps, true, "\ne\n\n");
        let d = r.unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].choice, Choice::Skip);
        assert_eq!(d[1].choice, Choice::Enforce);
        assert_eq!(d[1].where_, RuleWhere::Everywhere);
        assert!(out.contains("[1/2] CLAUDE.md:1"), "{out}");
        assert!(
            out.contains("enforce, ask, skip, edit? [e/a/s/x] (s): "),
            "{out}"
        );
    }

    #[test]
    fn host_only_answer() {
        let (r, _) = run(vec![prop(1, cmd(&["shred"]))], true, "e\nh\n");
        let d = r.unwrap();
        assert_eq!(
            (d[0].choice, d[0].where_),
            (Choice::Enforce, RuleWhere::Host)
        );
    }

    #[test]
    fn ask_only_where_offered() {
        let (r, out) = run(vec![prop(1, cmd(&["shred"]))], false, "a\ne\n\n");
        assert_eq!(r.unwrap()[0].choice, Choice::Enforce);
        assert!(out.contains("enforce, skip, edit? [e/s/x] (s): "), "{out}");
        let path = Target::Path {
            glob: "/etc/hosts".into(),
            access: RuleAccess::Write,
        };
        let (r, _) = run(vec![prop(1, path)], true, "a\ne\n\n");
        assert_eq!(r.unwrap()[0].choice, Choice::Enforce);
        let (r, _) = run(vec![prop(1, cmd(&["shred"]))], true, "a\n\n");
        assert_eq!(r.unwrap()[0].choice, Choice::Ask);
    }

    #[test]
    fn broad_needs_typed_yes() {
        let broad = prop(1, cmd(&["ls"]));
        assert!(broad.broad.is_some());
        let (r, out) = run(vec![broad.clone()], true, "e\ny\n");
        assert_eq!(r, Err(Eof));
        assert!(out.contains("BROAD: blocks everyday"), "{out}");
        assert!(out.matches("[e/a/s/x]").count() >= 2, "{out}");
        let (r, _) = run(vec![broad.clone()], true, "e\nyes\n\n");
        assert_eq!(r.unwrap()[0].choice, Choice::Enforce);
        let (r, _) = run(vec![broad], true, "e\n\n");
        assert_eq!(r.unwrap()[0].choice, Choice::Skip);
    }

    #[test]
    fn edit_reproposes() {
        let (r, _) = run(
            vec![prop(1, cmd(&["shred"]))],
            true,
            "x\ndocker system prune\ne\n\n",
        );
        let d = r.unwrap();
        assert_eq!(d[0].choice, Choice::Enforce);
        match &d[0].p.kind {
            ProposalKind::Command { words, .. } => {
                assert_eq!(words.join(" "), "docker system prune")
            }
            k => panic!("{k:?}"),
        }
        // A path answer, an empty answer and a refused one.
        let (r, out) = run(
            vec![prop(1, cmd(&["shred"]))],
            true,
            "x\n/etc/hosts\nx\n\nx\na|b\ns\n",
        );
        let d = r.unwrap();
        assert!(matches!(d[0].p.kind, ProposalKind::Path { .. }), "{out}");
        assert!(out.contains("not a command or a path"), "{out}");
    }

    #[test]
    fn eof_is_an_error() {
        let ps = vec![prop(1, cmd(&["shred"])), prop(2, cmd(&["pkill"]))];
        assert_eq!(run(ps.clone(), true, "e\n").0, Err(Eof));
        assert_eq!(run(ps, true, "e\n\n").0, Err(Eof));
        assert_eq!(run(vec![prop(1, cmd(&["shred"]))], true, "e\n").0, Err(Eof));
    }

    #[test]
    fn table_shows_counts_and_unenforced() {
        let ps = vec![prop(1, cmd(&["pkill"])), prop(2, cmd(&["ls"]))];
        let bad = vec![Unverified {
            src: src(3),
            why: "the rule does not block `x`".into(),
        }];
        let j = vec![src(4)];
        let t = table(&ps, &bad, &j);
        assert!(t.contains("deny command `pkill`"), "{t}");
        assert!(t.contains("BROAD"), "{t}");
        assert!(t.contains("often host only"), "{t}");
        assert!(t.contains("Not enforced:"), "{t}");
        assert!(t.contains("unverified: the rule does not block"), "{t}");
        assert!(t.contains("judgement"), "{t}");
        assert!(t.contains("2 proposed, 1 unverified, 1 judgement"), "{t}");
    }
}
