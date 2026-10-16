//! `saiife packs`: every pack, whether it is on by default and here, its
//! rule count and what it guards. `saiife packs <id>`: one pack's command
//! rules and path rules, each with its reason.

use std::process::ExitCode;

use saiifeguard::canon::PathVars;
use saiifeguard::pathrule::PathRule;
use saiifeguard::Pack;

use crate::project::project_packs;
use crate::warn;

pub fn run(builtin: &[Pack], cli_packs: &[String], vars: &PathVars, id: Option<&str>) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_default();
    let project = project_packs(&cwd, builtin);
    for w in &project.warnings {
        warn(w);
    }
    if let Some(id) = id {
        let Some(pack) = builtin.iter().find(|p| p.id == id) else {
            eprintln!("saiife: unknown pack {id:?} (`saiife packs` lists them)");
            return ExitCode::from(2);
        };
        let here =
            pack.default_on || project.enabled.contains(&pack.id) || cli_packs.contains(&pack.id);
        print!("{}", render_pack_with(pack, here, Some(vars)));
        return ExitCode::SUCCESS;
    }
    match &project.root {
        Some(r) => println!("Project: {}", r.display()),
        None => println!("No .saiife/config.toml here or above; showing the defaults."),
    }
    print!("{}", render(builtin, &project.enabled, cli_packs));
    ExitCode::SUCCESS
}

pub fn render(builtin: &[Pack], project: &[String], cli_packs: &[String]) -> String {
    let row = |id: &str, def: &str, here: &str, rules: &str, summary: &str| {
        format!("{id:<18} {def:<7} {here:<4} {rules:>5}  {summary}\n")
    };
    let mut out = row("ID", "DEFAULT", "HERE", "RULES", "SUMMARY");
    for p in builtin {
        let here = p.default_on || project.contains(&p.id) || cli_packs.contains(&p.id);
        out.push_str(&row(
            &p.id,
            if p.default_on { "on" } else { "off" },
            if here { "on" } else { "off" },
            &p.rule_count().to_string(),
            &p.description,
        ));
    }
    out
}

/// The variable a path glob starts with, if any (`~` is `$HOME`).
fn glob_var(glob: &str) -> Option<&str> {
    if glob == "~" || glob.starts_with("~/") {
        return Some("HOME");
    }
    let after = glob.strip_prefix('$')?;
    Some(&after[..after.find('/').unwrap_or(after.len())])
}

/// The variable a rule needs that has no value on this machine.
fn unbound_var<'a>(r: &'a PathRule, vars: &PathVars) -> Option<&'a str> {
    glob_var(&r.glob).filter(|v| vars.values(v).is_empty())
}

/// One line per unbound variable naming the active packs whose path rules
/// are skipped for it; empty when every rule applies.
pub fn inactive_summary(active: &[Pack], vars: &PathVars) -> String {
    let mut by_var: Vec<(String, Vec<&str>)> = Vec::new();
    for p in active {
        for r in p.allow_path.iter().chain(&p.deny_path) {
            let Some(v) = unbound_var(r, vars) else {
                continue;
            };
            match by_var.iter_mut().find(|(n, _)| n == v) {
                Some((_, ids)) => {
                    if !ids.contains(&p.id.as_str()) {
                        ids.push(&p.id);
                    }
                }
                None => by_var.push((v.to_string(), vec![&p.id])),
            }
        }
    }
    by_var
        .iter()
        .map(|(v, ids)| format!("inactive here: ${v} is not set: {}\n", ids.join(", ")))
        .collect()
}

/// One pack in full: what it is, then each rule with its reason.
#[cfg(test)]
fn render_pack(p: &Pack, here: bool) -> String {
    render_pack_with(p, here, None)
}

/// Like `render_pack`; with `vars`, a path rule whose variable has no
/// value on this machine is marked as inactive instead of looking live.
pub fn render_pack_with(p: &Pack, here: bool, vars: Option<&PathVars>) -> String {
    let yes = |b: bool| if b { "yes" } else { "no" };
    let mut out = format!(
        "{} — {}\n{}\non by default: {}   on here: {}\n",
        p.id,
        p.name,
        p.description,
        yes(p.default_on),
        yes(here)
    );
    if !p.allow.is_empty() || !p.deny.is_empty() {
        out.push_str("\nCommand rules (matched against the command line):\n");
        for (kind, rules) in [("allow", &p.allow), ("deny", &p.deny)] {
            for r in rules {
                out.push_str(&format!(
                    "  {kind:<6} {}\n         {}\n",
                    r.pattern, r.reason
                ));
            }
        }
    }
    if !p.allow_path.is_empty() || !p.deny_path.is_empty() {
        out.push_str("\nPath rules (files read or written by file tools and shell commands):\n");
        for (kind, rules) in [("allow", &p.allow_path), ("deny", &p.deny_path)] {
            for r in rules {
                let note = vars
                    .and_then(|v| unbound_var(r, v))
                    .map(|v| format!("  (inactive here: ${v} is not set)"))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "  {kind:<6} {:<6} {}{note}\n         {}\n",
                    r.access.label(),
                    r.glob,
                    r.reason
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiifeguard::builtins::builtin_packs;

    #[test]
    fn lists_every_pack_with_default_and_here() {
        let (packs, _) = builtin_packs();
        let out = render(&packs, &["db.postgres".to_string()], &[]);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("ID"));
        assert_eq!(lines.len(), packs.len() + 1);
        let git = lines.iter().find(|l| l.starts_with("core.git ")).unwrap();
        assert!(git.contains(" on      on "), "{git}");
        let pg = lines
            .iter()
            .find(|l| l.starts_with("db.postgres "))
            .unwrap();
        assert!(pg.contains(" off     on "), "{pg}");
        let my = lines.iter().find(|l| l.starts_with("db.mysql ")).unwrap();
        assert!(my.contains(" off     off "), "{my}");
        assert!(my.contains("MySQL"), "{my}");
    }

    #[test]
    fn one_pack_lists_command_and_path_rules() {
        let (packs, _) = builtin_packs();
        let secrets = packs.iter().find(|p| p.id == "core.secrets").unwrap();
        let out = render_pack(secrets, true);
        assert!(out.starts_with("core.secrets — Core: secrets\n"), "{out}");
        assert!(out.contains("on by default: yes   on here: yes"), "{out}");
        assert!(out.contains("  deny   ^printenv"), "{out}");
        assert!(out.contains("  deny   read   **/.env\n"), "{out}");
        assert!(out.contains("  allow  read   **/.env.example\n"), "{out}");
        let git = packs.iter().find(|p| p.id == "core.git").unwrap();
        assert!(!render_pack(git, true).contains("Path rules"));
    }
}
