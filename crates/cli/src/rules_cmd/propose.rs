//! Turn candidates into verified rule proposals (plan 33 task 2).
//!
//! A candidate target becomes a [`Proposal`] (D2) with block and allow
//! examples (D3). Each proposal is compiled alone as a user pack and judged
//! by the real engine: it must block its `block` examples and let its
//! `allow` examples through, or it is listed as unverified and never offered.

use saiifeguard::canon::{PathStyle, PathVars};
use saiifeguard::engine::Engine;
use saiifeguard::pathrule::{Access, RuleAccess};
use saiifeguard::profile::Profile;
use saiifeguard::userpack::{broad_findings, load_user_packs, UserSrc};
use saiifeguard::wrappers::is_transparent;
use saiifeguard::Decision;

use super::{Candidate, CmdRule, Origin, Proposal, ProposalKind, SourceLine, Target, Unverified};

/// The longest quoted line text in a reason.
const REASON_MAX: usize = 160;

/// Programs and paths people often want to stop on the host only.
const HOST_HINT_COMMANDS: &[&str] = &[
    "docker",
    "systemctl",
    "sudo",
    "su",
    "pkill",
    "kill",
    "killall",
    "loginctl",
];

/// `<file>:<line> "<text>"`: the source line quoted as the rule's reason.
pub fn reason(file_name: &str, line: u32, text: &str) -> String {
    let t = text.trim();
    let t = ["- ", "* ", "+ "]
        .iter()
        .find_map(|m| t.strip_prefix(m))
        .map(str::trim_start)
        .unwrap_or(t);
    let digits = t.chars().take_while(char::is_ascii_digit).count();
    let t = match t[digits..].strip_prefix(". ") {
        Some(rest) if digits > 0 => rest.trim_start(),
        _ => t,
    };
    let t = t.replace("**", "");
    let t = t.trim();
    let quoted = if t.chars().count() > REASON_MAX {
        let cut: String = t.chars().take(REASON_MAX).collect();
        format!("{cut}…")
    } else {
        t.to_string()
    };
    format!("{file_name}:{line} \"{quoted}\"")
}

/// `w` as a literal in a regex.
fn escape(w: &str) -> String {
    let mut out = String::with_capacity(w.len());
    for c in w.chars() {
        if r"\.+*?()|[]{}^$#&-~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn has_wildcard(glob: &str) -> bool {
    glob.contains(['*', '?', '[', '{'])
}

fn command_proposal(
    c: &Candidate,
    words: &[String],
    reason: String,
    origin: Origin,
) -> Option<Proposal> {
    let first = words.first()?;
    let joined = words.join(" ");
    let body = words
        .iter()
        .map(|w| escape(w))
        .collect::<Vec<_>>()
        .join(r"\s+");
    let wrapper = is_transparent(first);
    let (rules, carve, block, mut allow) = if wrapper && words.len() == 1 {
        let rules = vec![
            CmdRule {
                pattern: format!(r"(?:^|\s){body}(?:\s|$)"),
                whole_segment: false,
                peeled_wrappers: true,
            },
            CmdRule {
                pattern: format!(r"^{body}(?:\s|$)"),
                whole_segment: false,
                peeled_wrappers: false,
            },
        ];
        let block = vec![format!("{joined} ls"), format!("timeout 5 {joined} ls")];
        (rules, false, block, vec![format!("echo {joined}")])
    } else {
        let rules = vec![CmdRule {
            pattern: format!(r"^{body}(?:\s|$)"),
            whole_segment: wrapper,
            peeled_wrappers: false,
        }];
        let carve = words.len() == 1 && !wrapper;
        (
            rules,
            carve,
            vec![joined.clone()],
            vec![format!("echo {joined}")],
        )
    };
    if carve {
        allow.push(format!("{first} --help"));
    }
    Some(Proposal {
        src: c.src.clone(),
        kind: ProposalKind::Command {
            words: words.to_vec(),
            rules,
            help_carve_out: carve,
        },
        reason,
        block,
        allow,
        broad: None,
        host_hint: HOST_HINT_COMMANDS.contains(&first.as_str()),
        origin,
    })
}

fn path_proposal(
    c: &Candidate,
    glob: &str,
    access: RuleAccess,
    reason: String,
    origin: Origin,
) -> Proposal {
    let (globs, block, parent): (Vec<String>, String, Option<String>) = if has_wildcard(glob) {
        let block = glob
            .replace("**", "saiife-example")
            .replace('*', "saiife-example")
            .replace('?', "x");
        let parent = glob
            .rfind('/')
            .map(|i| glob[..i].to_string())
            .filter(|p| !has_wildcard(p));
        (vec![glob.to_string()], block, parent)
    } else {
        let base = glob.trim_end_matches('/');
        // Plan 32 refuses the glob "/" (empty component), so the root gets
        // only "/**": every path below it (deviation from P2, reported).
        let globs = if base.is_empty() {
            vec!["/**".to_string()]
        } else {
            vec![base.to_string(), format!("{base}/**")]
        };
        // No textual parent ("/", "~", "$VAR"): no near miss to offer (P2).
        let parent = base.rfind('/').map(|i| base[..i].to_string());
        (globs, format!("{base}/saiife-example"), parent)
    };
    let allow = parent
        .map(|p| format!("{p}/saiife-example-other"))
        .into_iter()
        .collect();
    let host_hint = glob == "/etc" || glob.starts_with("/etc/");
    Proposal {
        src: c.src.clone(),
        kind: ProposalKind::Path { globs, access },
        reason,
        block: vec![block],
        allow,
        broad: None,
        host_hint,
        origin,
    }
}

pub fn propose(c: &Candidate, file_name: &str, origin: Origin) -> Vec<Proposal> {
    let why = reason(file_name, c.src.line, &c.src.text);
    c.targets
        .iter()
        .filter_map(|t| match t {
            Target::Command(words) => command_proposal(c, words, why.clone(), origin),
            Target::Path { glob, access } => {
                Some(path_proposal(c, glob, *access, why.clone(), origin))
            }
        })
        .collect()
}

/// A TOML basic string.
fn toml_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn access_word(a: RuleAccess) -> &'static str {
    match a {
        RuleAccess::Read => "read",
        RuleAccess::Write => "write",
        RuleAccess::Any => "any",
        RuleAccess::Replace => "replace",
        RuleAccess::Content => "content",
    }
}

/// The proposal alone as a user pack. It is used only to verify; `store`
/// renders the real pack.
pub fn one_rule_pack(p: &Proposal, id_line: u32) -> String {
    let mut out = String::from("[pack]\nid = \"user.proposal\"\nname = \"proposal\"\n");
    match &p.kind {
        ProposalKind::Command {
            words,
            rules,
            help_carve_out,
        } => {
            let first = words.first().map(String::as_str).unwrap_or("");
            out.push_str(&format!("triggers = [{}]\n", toml_str(first)));
            for (k, r) in rules.iter().enumerate() {
                out.push_str(&format!(
                    "\n[[deny]]\nid = \"l{id_line}-{}\"\npattern = {}\nreason = {}\n",
                    k + 1,
                    toml_str(&r.pattern),
                    toml_str(&p.reason)
                ));
                if r.whole_segment {
                    out.push_str("whole_segment = true\n");
                }
                if r.peeled_wrappers {
                    out.push_str("peeled_wrappers = true\n");
                }
            }
            if *help_carve_out {
                out.push_str(&format!(
                    "\n[[allow]]\npattern = {}\nreason = \"reading help changes nothing\"\nwhole_segment = true\n",
                    toml_str(&format!(r"^{}\s+(?:--help|-h|--version)$", escape(first)))
                ));
            }
        }
        ProposalKind::Path { globs, access } => {
            for g in globs {
                out.push_str(&format!(
                    "\n[[deny_path]]\nglob = {}\naccess = \"{}\"\nreason = {}\n",
                    toml_str(g),
                    access_word(*access),
                    toml_str(&p.reason)
                ));
            }
        }
    }
    out
}

/// Replace `~` and `$NAME` at the start of an example path by a value of
/// `vars`; the name of an unknown variable is the error.
fn bind(path: &str, vars: &PathVars) -> Result<String, String> {
    let (name, rest) = if let Some(rest) = path.strip_prefix('~') {
        ("HOME", rest)
    } else if let Some(r) = path.strip_prefix('$') {
        let n = r
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        (&r[..n], &r[n..])
    } else {
        return Ok(path.to_string());
    };
    match vars.values(name).first() {
        Some(v) => Ok(format!("{}{rest}", v.to_string_lossy())),
        None => Err(format!(
            "unknown variable ${name}: no value on this machine"
        )),
    }
}

fn path_access(a: RuleAccess) -> Access {
    if a == RuleAccess::Read {
        Access::Read
    } else {
        Access::Write
    }
}

/// Compile the proposal alone and judge every example. On success `p.broad`
/// is set from plan 32's everyday probes.
pub fn verify(p: &mut Proposal, vars: &PathVars) -> Result<(), String> {
    if let ProposalKind::Path { globs, .. } = &p.kind {
        for g in globs {
            bind(g, vars)?;
        }
    }
    let text = one_rule_pack(p, p.src.line);
    let packs = load_user_packs(
        &[UserSrc {
            source: "proposal",
            text: &text,
        }],
        PathStyle::host(),
        Profile::Host,
    )
    .map_err(|e| e.message)?;
    let engine = Engine::new(packs.clone()).with_paths(vars.clone());
    let judge = |example: &str| -> Result<bool, String> {
        let denied = match &p.kind {
            ProposalKind::Command { .. } => {
                matches!(engine.evaluate(example), Decision::Deny { .. })
            }
            ProposalKind::Path { access, .. } => {
                let path = bind(example, vars)?;
                matches!(
                    engine.evaluate_path(path_access(*access), &path),
                    Decision::Deny { .. }
                )
            }
        };
        Ok(denied)
    };
    for b in &p.block {
        if !judge(b)? {
            return Err(format!("the rule does not block `{b}`"));
        }
    }
    for a in &p.allow {
        if judge(a)? {
            return Err(format!("the rule blocks `{a}`, which it should allow"));
        }
    }
    p.broad = packs.first().and_then(|pack| {
        broad_findings(pack)
            .first()
            .map(|b| format!("blocks everyday `{}`", b.example))
    });
    Ok(())
}

pub fn proposals_for(
    cands: &[Candidate],
    file_name: &str,
    vars: &PathVars,
) -> (Vec<Proposal>, Vec<Unverified>, Vec<SourceLine>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    let mut judgement = Vec::new();
    for c in cands {
        if c.targets.is_empty() {
            judgement.push(c.src.clone());
            continue;
        }
        for mut p in propose(c, file_name, Origin::Rules) {
            match verify(&mut p, vars) {
                Ok(()) => ok.push(p),
                Err(why) => bad.push(Unverified {
                    src: c.src.clone(),
                    why,
                }),
            }
        }
    }
    (ok, bad, judgement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_cmd::extract::line_sha256;

    fn vars() -> PathVars {
        PathVars::new()
            .with_cwd("/saiife-test/project")
            .with_var("PROJECT", "/saiife-test/project")
            .with_var("HOME", "/saiife-test/home")
    }

    fn cand(targets: Vec<Target>) -> Candidate {
        let text = "- Never do the thing.".to_string();
        Candidate {
            src: SourceLine {
                line: 7,
                line_sha256: line_sha256(&text),
                text,
            },
            targets,
        }
    }

    fn cmd(words: &[&str]) -> Target {
        Target::Command(words.iter().map(|w| (*w).to_string()).collect())
    }

    fn path(glob: &str, access: RuleAccess) -> Target {
        Target::Path {
            glob: glob.to_string(),
            access,
        }
    }

    fn one(t: Target) -> Proposal {
        let mut v = propose(&cand(vec![t]), "CLAUDE.md", Origin::Rules);
        assert_eq!(v.len(), 1);
        v.remove(0)
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn command_rule_shape() {
        let mut p = one(cmd(&["docker", "compose", "down"]));
        let ProposalKind::Command {
            words,
            rules,
            help_carve_out,
        } = &p.kind
        else {
            panic!("not a command")
        };
        assert_eq!(words, &strs(&["docker", "compose", "down"]));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, r"^docker\s+compose\s+down(?:\s|$)");
        assert!(!help_carve_out);
        assert_eq!(p.block, strs(&["docker compose down"]));
        assert_eq!(p.allow, strs(&["echo docker compose down"]));
        assert!(p.broad.is_none() && p.host_hint);
        assert_eq!(verify(&mut p, &vars()), Ok(()));
    }

    #[test]
    fn one_word_gets_help_carve_out() {
        let mut p = one(cmd(&["pkill"]));
        let ProposalKind::Command { help_carve_out, .. } = &p.kind else {
            panic!()
        };
        assert!(help_carve_out);
        assert_eq!(p.block, strs(&["pkill"]));
        assert_eq!(p.allow, strs(&["echo pkill", "pkill --help"]));
        assert_eq!(verify(&mut p, &vars()), Ok(()));
        assert!(p.broad.is_none());
    }

    #[test]
    fn wrapper_gets_two_rules() {
        let mut p = one(cmd(&["sudo"]));
        let ProposalKind::Command {
            rules,
            help_carve_out,
            ..
        } = &p.kind
        else {
            panic!()
        };
        assert!(!help_carve_out);
        assert_eq!(
            rules,
            &vec![
                CmdRule {
                    pattern: r"(?:^|\s)sudo(?:\s|$)".to_string(),
                    whole_segment: false,
                    peeled_wrappers: true
                },
                CmdRule {
                    pattern: r"^sudo(?:\s|$)".to_string(),
                    whole_segment: false,
                    peeled_wrappers: false
                },
            ]
        );
        assert!(p.block.contains(&"sudo ls".to_string()));
        assert!(p.block.contains(&"timeout 5 sudo ls".to_string()));
        assert!(p.allow.contains(&"echo sudo".to_string()));
        assert_eq!(verify(&mut p, &vars()), Ok(()));
    }

    #[test]
    fn wrapper_with_arguments_is_one_whole_segment_rule() {
        let mut p = one(cmd(&["sudo", "rm"]));
        let ProposalKind::Command { rules, .. } = &p.kind else {
            panic!()
        };
        assert_eq!(rules.len(), 1);
        assert!(rules[0].whole_segment);
        assert_eq!(verify(&mut p, &vars()), Ok(()));
    }

    #[test]
    fn path_rule_shape() {
        let mut p = one(path("/etc", RuleAccess::Write));
        let ProposalKind::Path { globs, access } = &p.kind else {
            panic!()
        };
        assert_eq!(globs, &strs(&["/etc", "/etc/**"]));
        assert_eq!(*access, RuleAccess::Write);
        assert_eq!(p.block, strs(&["/etc/saiife-example"]));
        assert_eq!(p.allow, strs(&["/saiife-example-other"]));
        assert_eq!(verify(&mut p, &vars()), Ok(()));

        let mut h = one(path("$PROJECT/.git/hooks", RuleAccess::Write));
        assert_eq!(verify(&mut h, &vars()), Ok(()));
        let mut r = one(path("~/.ssh", RuleAccess::Read));
        assert_eq!(verify(&mut r, &vars()), Ok(()));
    }

    #[test]
    fn unknown_variable_is_unverified() {
        let (ok, bad, judge) = proposals_for(
            &[cand(vec![path("$NOPE/x", RuleAccess::Any)])],
            "CLAUDE.md",
            &vars(),
        );
        assert!(ok.is_empty() && judge.is_empty());
        assert_eq!(bad.len(), 1);
        assert!(bad[0].why.contains("$NOPE"), "{}", bad[0].why);
    }

    #[test]
    fn broad_proposals_are_flagged() {
        let (ok, bad, _) = proposals_for(
            &[
                cand(vec![cmd(&["ls"])]),
                cand(vec![path("/", RuleAccess::Write)]),
                cand(vec![cmd(&["pkill"])]),
            ],
            "CLAUDE.md",
            &vars(),
        );
        assert_eq!(ok.len(), 3, "{bad:?}");
        assert_eq!(ok[0].broad.as_deref(), Some("blocks everyday `ls`"));
        assert!(ok[1].broad.is_some());
        let ProposalKind::Path { globs, .. } = &ok[1].kind else {
            panic!()
        };
        assert_eq!(globs, &strs(&["/**"]));
        assert!(ok[1].allow.is_empty());
        assert!(ok[2].broad.is_none());
    }

    #[test]
    fn prefix_rule_word_order_is_pinned() {
        let mut p = one(cmd(&["git", "push", "--force"]));
        assert_eq!(verify(&mut p, &vars()), Ok(()));
        let packs = load_user_packs(
            &[UserSrc {
                source: "t",
                text: &one_rule_pack(&p, 7),
            }],
            PathStyle::host(),
            Profile::Host,
        )
        .unwrap();
        let e = Engine::new(packs);
        let denied = |c: &str| matches!(e.evaluate(c), Decision::Deny { .. });
        assert!(denied("git push --force origin"));
        assert!(!denied("git push --force-with-lease"));
        // A documented limit, not a wish: the flag after another word.
        assert!(!denied("git push origin --force"));
    }

    #[test]
    fn reason_quotes_the_line() {
        assert_eq!(
            reason("CLAUDE.md", 12, "- **Never** run `pkill`."),
            "CLAUDE.md:12 \"Never run `pkill`.\""
        );
        let long = format!("Never {}", "x".repeat(300));
        let r = reason("A.md", 1, &long);
        assert_eq!(r, format!("A.md:1 \"{}…\"", &long[..160]));
    }

    #[test]
    fn failed_example_names_it() {
        let mut p = one(cmd(&["pkill"]));
        p.block.push("echo pkill".to_string());
        let e = verify(&mut p, &vars()).unwrap_err();
        assert!(e.contains("echo pkill"), "{e}");
    }

    #[test]
    fn judgement_lines_come_back() {
        let (ok, bad, judge) = proposals_for(&[cand(vec![])], "CLAUDE.md", &vars());
        assert!(ok.is_empty() && bad.is_empty());
        assert_eq!(judge.len(), 1);
    }
}
