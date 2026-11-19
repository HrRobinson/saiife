//! The opt-in LLM pass over lines the extraction could not use (plan 33 task 3).
//!
//! The user's own `claude -p` turns judgement lines into rule candidates.
//! Nothing it says is trusted: the answer must match a closed schema, every
//! string is checked for control and bidi characters, and each rule goes
//! through the same proposal and verification as a rule found in the text.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use saiifeguard::canon::PathVars;
use saiifeguard::pathrule::RuleAccess;
use serde::Deserialize;

use super::extract::{has_unsafe_char, span_target, UNSAFE_WHY};
use super::{propose, Candidate, Origin, Proposal, SourceLine, Target};

pub const INSTRUCTIONS: &str = r#"Turn each numbered rule line into guard rules. Reply with JSON only: {"rules":[...]}. Each item is {"kind":"command","line":N,"command":"<program and words>","block":["<command it must block>"],"allow":["<similar command it must allow>"]} or {"kind":"path","line":N,"path":"</abs, ~/ or $VAR path>","access":"read|write|any","block":["<path>"],"allow":["<path>"]}. Use only the lines given. Never propose an allow rule. Leave out lines with no concrete command or path."#;

/// The most rules one answer may hold.
const MAX_RULES: usize = 64;
/// The most stdout read from `claude`.
const MAX_OUT: usize = 256 * 1024;
/// The most stderr quoted in an error.
const MAX_ERR: usize = 400;
/// How long `claude` gets (120 s; debug builds read the test override).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LlmOut {
    rules: Vec<LlmRule>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LlmAccess {
    Read,
    Write,
    Any,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LlmRule {
    Command {
        line: u32,
        command: String,
        block: Vec<String>,
        allow: Vec<String>,
    },
    Path {
        line: u32,
        path: String,
        access: LlmAccess,
        block: Vec<String>,
        allow: Vec<String>,
    },
}

impl LlmRule {
    pub fn line(&self) -> u32 {
        match self {
            LlmRule::Command { line, .. } | LlmRule::Path { line, .. } => *line,
        }
    }

    fn examples(&self) -> (&[String], &[String]) {
        match self {
            LlmRule::Command { block, allow, .. } | LlmRule::Path { block, allow, .. } => {
                (block, allow)
            }
        }
    }

    fn target(&self) -> &str {
        match self {
            LlmRule::Command { command, .. } => command,
            LlmRule::Path { path, .. } => path,
        }
    }
}

/// The answer with one ```` ```json ```` (or bare) fence taken off.
fn unfence(out: &str) -> &str {
    let t = out.trim();
    let Some(rest) = t.strip_prefix("```") else {
        return t;
    };
    let rest = rest.strip_prefix("json").unwrap_or(rest);
    rest.trim().strip_suffix("```").map(str::trim).unwrap_or(t)
}

/// Check `rule` alone: sent line, examples present, safe characters.
fn check(rule: &LlmRule, sent: &[u32]) -> Result<(), String> {
    if !sent.contains(&rule.line()) {
        return Err(format!("line {} was not sent", rule.line()));
    }
    let (block, allow) = rule.examples();
    if block.is_empty() || allow.is_empty() {
        return Err("block and allow examples are both required".into());
    }
    let unsafe_str = std::iter::once(rule.target())
        .chain(block.iter().map(String::as_str))
        .chain(allow.iter().map(String::as_str))
        .any(has_unsafe_char);
    if unsafe_str {
        return Err(format!("a string {UNSAFE_WHY}"));
    }
    Ok(())
}

/// Parse the answer. A malformed answer, an unknown kind or field, or more
/// than 64 rules is `Err` for the whole answer; a rule that names a line
/// that was not sent, lacks examples or holds unsafe characters is `Err`
/// for that rule alone.
#[allow(clippy::type_complexity)]
pub fn parse(out: &str, sent: &[u32]) -> Result<Vec<(LlmRule, Result<(), String>)>, String> {
    let parsed: LlmOut = serde_json::from_str(unfence(out))
        .map_err(|e| format!("claude's answer is not valid: {e}"))?;
    if parsed.rules.len() > MAX_RULES {
        return Err(format!(
            "claude proposed {} rules; at most {MAX_RULES} are taken",
            parsed.rules.len()
        ));
    }
    Ok(parsed
        .rules
        .into_iter()
        .map(|r| {
            let status = check(&r, sent);
            (r, status)
        })
        .collect())
}

/// One rule as a verified proposal (origin `Llm`). The target goes through
/// the same checks as a span in the text; the LLM's examples are added to
/// the proposal's own and must hold.
pub fn to_proposal(
    r: &LlmRule,
    line: &SourceLine,
    file_name: &str,
    vars: &PathVars,
) -> Result<Proposal, String> {
    if has_unsafe_char(&line.text) {
        return Err(format!("the line {UNSAFE_WHY}"));
    }
    let (block, allow) = r.examples();
    if [r.target()]
        .into_iter()
        .chain(block.iter().map(String::as_str))
        .chain(allow.iter().map(String::as_str))
        .any(has_unsafe_char)
    {
        return Err(format!("a string {UNSAFE_WHY}"));
    }
    let target = match r {
        LlmRule::Command { command, .. } => match span_target(command, RuleAccess::Any) {
            Some(t @ Target::Command(_)) => t,
            _ => return Err("not a plain command (a program and its words)".into()),
        },
        LlmRule::Path { path, access, .. } => match span_target(path, RuleAccess::Any) {
            Some(Target::Path { glob, .. }) => Target::Path {
                glob,
                access: match access {
                    LlmAccess::Read => RuleAccess::Read,
                    LlmAccess::Write => RuleAccess::Write,
                    LlmAccess::Any => RuleAccess::Any,
                },
            },
            _ => return Err("not an absolute, ~/ or $VAR path".into()),
        },
    };
    let cand = Candidate {
        src: line.clone(),
        targets: vec![target],
    };
    let mut p = propose::propose(&cand, file_name, Origin::Llm)
        .into_iter()
        .next()
        .ok_or_else(|| "no rule for that".to_string())?;
    for b in block {
        if !p.block.contains(b) {
            p.block.push(b.clone());
        }
    }
    for a in allow {
        if !p.allow.contains(a) {
            p.allow.push(a.clone());
        }
    }
    propose::verify(&mut p, vars)?;
    Ok(p)
}

/// The timeout: 120 s; debug builds read `SAIIFE_TEST_LLM_TIMEOUT_MS`.
pub fn timeout() -> Duration {
    if cfg!(debug_assertions) {
        if let Some(ms) = std::env::var("SAIIFE_TEST_LLM_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            return Duration::from_millis(ms);
        }
    }
    DEFAULT_TIMEOUT
}

enum Slurp {
    Done(Vec<u8>),
    TooBig,
}

/// Run the user's `claude -p` over `lines` (`<line>: <text>` on stdin).
pub fn run_claude(lines: &[SourceLine], timeout: Duration) -> Result<String, String> {
    let exe = saiife_agents::detect::which("claude")
        .ok_or("claude is not on PATH; the LLM pass needs Claude Code")?;
    let mut child = Command::new(exe)
        .args(["-p", INSTRUCTIONS, "--tools", ""])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run claude: {e}"))?;
    let deadline = Instant::now() + timeout;
    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().ok_or("claude has no stdout")?;
    let mut stderr = child.stderr.take().ok_or("claude has no stderr")?;

    let input: String = lines
        .iter()
        .map(|l| format!("{}: {}\n", l.line, l.text))
        .collect();
    // Threads, so a full pipe in either direction cannot deadlock us.
    std::thread::spawn(move || {
        if let Some(mut s) = stdin {
            let _ = s.write_all(input.as_bytes());
        }
    });
    let (out_tx, out_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let r = (&mut stdout).take(MAX_OUT as u64 + 1).read_to_end(&mut buf);
        let _ = out_tx.send(match r {
            Ok(_) if buf.len() > MAX_OUT => Slurp::TooBig,
            _ => Slurp::Done(buf),
        });
    });
    let (err_tx, err_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut head = Vec::new();
        let _ = (&mut stderr).take(MAX_ERR as u64).read_to_end(&mut head);
        // Drain the rest so claude never blocks on a full stderr pipe.
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        let _ = err_tx.send(head);
    });

    let left = |d: Instant| d.saturating_duration_since(Instant::now());
    let stop = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };
    let timed_out = |child: &mut std::process::Child| {
        stop(child);
        Err(format!(
            "claude did not answer in {} s",
            timeout.as_secs_f64().ceil() as u64
        ))
    };
    let out = match out_rx.recv_timeout(left(deadline)) {
        Ok(Slurp::Done(b)) => b,
        Ok(Slurp::TooBig) => {
            stop(&mut child);
            return Err("claude answered more than 256 KiB".into());
        }
        Err(_) => return timed_out(&mut child),
    };
    // Stdout is closed: wait for the exit itself, until the deadline. Stderr
    // is never waited on: a grandchild may hold it open long after claude
    // has answered and gone.
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if left(deadline).is_zero() => return timed_out(&mut child),
            Ok(None) => std::thread::sleep(left(deadline).min(Duration::from_millis(10))),
            Err(e) => {
                stop(&mut child);
                return Err(format!("could not wait for claude: {e}"));
            }
        }
    };
    if !status.success() {
        let head = err_rx.recv_timeout(Duration::from_millis(200)).ok();
        let text = String::from_utf8_lossy(&head.unwrap_or_default()).into_owned();
        return Err(format!("claude failed ({status}): {}", text.trim()));
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_cmd::extract::line_sha256;

    use crate::rules_cmd::test_host::vars;

    fn src(line: u32) -> SourceLine {
        let text = "- Never destroy the staging infra".to_string();
        SourceLine {
            line,
            line_sha256: line_sha256(&text),
            text,
        }
    }

    const GOOD: &str = r#"{"rules":[{"kind":"command","line":4,"command":"terraform destroy","block":["terraform destroy"],"allow":["terraform plan"]}]}"#;

    #[test]
    fn llm_parse_accepts_the_schema() {
        let v = parse(GOOD, &[4]).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, Ok(()));
        let fenced = format!("```json\n{GOOD}\n```");
        assert_eq!(parse(&fenced, &[4]).unwrap().len(), 1);
    }

    #[test]
    fn llm_rejects_bad_shapes() {
        let allow_kind =
            r#"{"rules":[{"kind":"allow","line":4,"command":"x","block":["x"],"allow":["y"]}]}"#;
        assert!(parse(allow_kind, &[4]).is_err());
        let extra = r#"{"rules":[{"kind":"command","line":4,"command":"x","regex":"x","block":["x"],"allow":["y"]}]}"#;
        assert!(parse(extra, &[4]).is_err());
        let missing = r#"{"rules":[{"kind":"command","line":4,"command":"x","allow":["y"]}]}"#;
        assert!(parse(missing, &[4]).is_err());
        let v = parse(GOOD, &[2]).unwrap();
        assert!(v[0].1.as_ref().unwrap_err().contains("not sent"));
        let empty =
            r#"{"rules":[{"kind":"command","line":4,"command":"x","block":[],"allow":["y"]}]}"#;
        assert!(parse(empty, &[4]).unwrap()[0].1.is_err());
        let one = r#"{"kind":"command","line":4,"command":"terraform destroy","block":["terraform destroy"],"allow":["terraform plan"]}"#;
        let many = format!("{{\"rules\":[{}]}}", vec![one; 65].join(","));
        assert!(parse(&many, &[4]).is_err());
        let ok64 = format!("{{\"rules\":[{}]}}", vec![one; 64].join(","));
        assert_eq!(parse(&ok64, &[4]).unwrap().len(), 64);
        assert!(parse("not json", &[4]).is_err());
    }

    #[test]
    fn llm_rejects_unsafe_characters() {
        for bad in ["\\u001b[2Jx", "a\\u202eb", "a\\u200bb"] {
            for field in ["command", "block", "allow"] {
                let cmd = if field == "command" {
                    bad
                } else {
                    "terraform destroy"
                };
                let blk = if field == "block" {
                    bad
                } else {
                    "terraform destroy"
                };
                let alw = if field == "allow" {
                    bad
                } else {
                    "terraform plan"
                };
                let j = format!(
                    r#"{{"rules":[{{"kind":"command","line":4,"command":"{cmd}","block":["{blk}"],"allow":["{alw}"]}}]}}"#
                );
                let v = parse(&j, &[4]).unwrap();
                let why = v[0].1.as_ref().unwrap_err();
                assert!(why.contains(UNSAFE_WHY), "{field} {bad}: {why}");
                let e = to_proposal(&v[0].0, &src(4), "CLAUDE.md", &vars()).unwrap_err();
                assert!(e.contains(UNSAFE_WHY), "{e}");
            }
        }
        let p = r#"{"rules":[{"kind":"path","line":4,"path":"/etc/\u202e","access":"any","block":["/etc/x"],"allow":["/usr/x"]}]}"#;
        assert!(parse(p, &[4]).unwrap()[0].1.is_err());
    }

    #[test]
    fn llm_proposal_is_verified_and_marked() {
        let v = parse(GOOD, &[4]).unwrap();
        let p = to_proposal(&v[0].0, &src(4), "CLAUDE.md", &vars()).unwrap();
        assert_eq!(p.origin, Origin::Llm);
        assert!(p.block.contains(&"terraform destroy".to_string()));
        assert!(p.allow.contains(&"terraform plan".to_string()));
    }

    #[test]
    fn llm_examples_must_pass() {
        let j = r#"{"rules":[{"kind":"command","line":4,"command":"terraform destroy","block":["terraform destroy"],"allow":["terraform destroy -auto-approve"]}]}"#;
        let v = parse(j, &[4]).unwrap();
        let e = to_proposal(&v[0].0, &src(4), "CLAUDE.md", &vars()).unwrap_err();
        assert!(e.contains("terraform destroy -auto-approve"), "{e}");
    }

    #[test]
    fn llm_command_must_be_plain_and_path_a_path() {
        let j = r#"{"rules":[{"kind":"command","line":4,"command":"rm -rf $(cat x)","block":["rm -rf x"],"allow":["ls"]},{"kind":"path","line":4,"path":"relative/dir","access":"write","block":["a"],"allow":["b"]}]}"#;
        for (r, _) in parse(j, &[4]).unwrap() {
            assert!(to_proposal(&r, &src(4), "CLAUDE.md", &vars()).is_err());
        }
    }

    #[test]
    fn llm_path_rule_keeps_its_access() {
        // The LLM's path and examples as this host spells them.
        let (dir, k, other) = if cfg!(windows) {
            (
                r"C:\\saiife-test\\secrets",
                r"C:\\saiife-test\\secrets\\k",
                r"C:\\saiife-test\\other\\k",
            )
        } else {
            (
                "/saiife-test/secrets",
                "/saiife-test/secrets/k",
                "/saiife-test/other/k",
            )
        };
        let j = format!(
            r#"{{"rules":[{{"kind":"path","line":4,"path":"{dir}","access":"read","block":["{k}"],"allow":["{other}"]}}]}}"#
        );
        let v = parse(&j, &[4]).unwrap();
        let p = to_proposal(&v[0].0, &src(4), "CLAUDE.md", &vars()).unwrap();
        let super::super::ProposalKind::Path { access, globs } = p.kind else {
            panic!()
        };
        assert_eq!(access, RuleAccess::Read);
        let glob = if cfg!(windows) {
            "c:/saiife-test/secrets"
        } else {
            "/saiife-test/secrets"
        };
        assert_eq!(globs[0], glob);
    }
}
