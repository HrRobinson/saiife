//! `saiife packs`: every pack, whether it is on by default and here, its
//! rule count and what it guards.

use std::process::ExitCode;

use saiifeguard::Pack;

use crate::project::project_packs;
use crate::warn;

pub fn run(builtin: &[Pack], cli_packs: &[String]) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_default();
    let project = project_packs(&cwd, builtin);
    for w in &project.warnings {
        warn(w);
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
}
