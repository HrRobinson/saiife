//! `saiife status`: is this project still guarded? Runs the tamper checks
//! of spec §7.5 and exits 1 if any fails, so it can run in scripts and CI.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use saiife_agents::config::CONFIG_REL;
use saiife_agents::detect::which;
use saiife_agents::fingerprint::sha256_hex;
use saiife_agents::integrity::{self, Integrity};
use saiife_agents::Agent;
use saiife_audit::store::{self, Filter};
use saiife_audit::Record;
use saiifeguard::canon::PathVars;
use saiifeguard::Pack;
use time::OffsetDateTime;

use crate::init_cmd::project_root;
use crate::project::project_packs;

/// Month files `status` reads at most when looking for each agent's last call.
const SCAN_MONTHS: usize = 12;

const RESTORE: &str = "run `saiife init` to restore it";

/// One failed check: what is wrong, and what to do.
struct Problem {
    what: String,
    fix: String,
}

pub fn run(builtin: &[Pack]) -> ExitCode {
    let Ok(cwd) = std::env::current_dir() else {
        eprintln!("saiife: cannot read the current directory");
        return ExitCode::from(2);
    };
    let root = status_root(&cwd);
    println!("saiife status for {}", root.display());

    let record = match integrity::record_path(&root) {
        Ok(Some(p)) => Integrity::load(&p).map_err(|e| e.to_string()),
        Ok(None) => Err("could not determine the data directory".to_string()),
        Err(e) => Err(e.to_string()),
    };
    let record = match record {
        Ok(Some(r)) => r,
        Ok(None) => {
            println!(
                "\nWARNING: saiife is not set up for this project on this machine \
                 (no integrity record).\n  Fix: run `saiife init` in {}",
                root.display()
            );
            return ExitCode::from(1);
        }
        Err(e) => {
            println!("\nWARNING: the integrity record cannot be read: {e}\n  Fix: run `saiife init` to write a new one");
            return ExitCode::from(1);
        }
    };

    let mut problems = Vec::new();
    let mut notes = Vec::new();
    // Only a hooked agent can have a last call to look for.
    let hooked: Vec<&str> = record
        .hooks
        .iter()
        .filter(|(_, h)| h.error.is_none())
        .map(|(a, _)| a.as_str())
        .collect();
    let last_calls = last_calls(&root, &hooked, &mut problems, &mut notes);
    let home = dirs::home_dir();

    for agent in Agent::ALL {
        let rel = agent.config_rel();
        let found = agent.entries(&root);
        let Some(rec) = record.hooks.get(agent.name()) else {
            if found.is_ok_and(|f| !f.is_empty()) {
                problems.push(Problem {
                    what: format!(
                        "{rel} has a saiife hook for {} that `saiife init` did not record.",
                        agent.label()
                    ),
                    fix: "run `saiife init` to record it".into(),
                });
            } else {
                println!("  {:<7} not set up", agent.name());
            }
            continue;
        };
        if let (Some(e), true) = (&rec.error, rec.off_failed) {
            problems.push(Problem {
                what: format!(
                    "`saiife init --off` could not remove its hook from {rel}: {e}. Fix the file's permissions and run `saiife init --off` again."
                ),
                fix: String::new(),
            });
            continue;
        }
        if let Some(e) = &rec.error {
            problems.push(Problem {
                what: format!("`saiife init` could not set up {}: {e}", agent.label()),
                fix: format!("repair {rel}, then run `saiife init`"),
            });
            continue;
        }
        match found {
            Err(e) => problems.push(Problem {
                what: format!("{} cannot be checked: {e}", agent.label()),
                fix: format!("repair {rel}, then {RESTORE}"),
            }),
            Ok(f) if f.contains(&rec.sha256) && rec.sha256 != agent.expected_entry() => {
                problems.push(Problem {
                    what: format!(
                        "The saiife hook for {} in {rel} was written by an older saiife and does not cover every tool this version guards.",
                        agent.label()
                    ),
                    fix: "run `saiife init` to update it".into(),
                })
            }
            Ok(f) if f.contains(&rec.sha256) => {
                let last = last_calls
                    .iter()
                    .filter(|r| r.agent == agent.name())
                    .filter_map(Record::timestamp)
                    .max();
                println!(
                    "  {:<7} hooked   {rel:<22} last hook call: {}",
                    agent.name(),
                    last.map(ago)
                        .unwrap_or_else(|| format!("no call in the last {SCAN_MONTHS} months"))
                );
            }
            Ok(f) if f.is_empty() => problems.push(Problem {
                what: format!(
                    "The saiife hook for {} was removed from {rel}.",
                    agent.label()
                ),
                fix: RESTORE.into(),
            }),
            Ok(_) => problems.push(Problem {
                what: format!(
                    "The saiife hook for {} in {rel} was changed.",
                    agent.label()
                ),
                fix: RESTORE.into(),
            }),
        }
        for b in agent.blockers(&root, home.as_deref()) {
            if let Some(e) = &b.error {
                problems.push(Problem {
                    what: format!(
                        "{} cannot be read, so saiife cannot tell whether it switches off {}'s hooks: {e}",
                        b.path.display(),
                        agent.label()
                    ),
                    fix: if b.managed {
                        format!(
                            "ask your administrator to make {} (managed settings) a readable JSON object",
                            b.path.display()
                        )
                    } else {
                        "make it readable so saiife can check it".into()
                    },
                });
                continue;
            }
            let fix = if b.managed {
                format!(
                    "ask your administrator: {} (managed settings) stops hooks on this machine",
                    b.setting
                )
            } else {
                format!("remove `{}` from {}", b.setting, b.path.display())
            };
            problems.push(Problem {
                what: format!(
                    "{} sets {}, which stops {}'s hooks: saiife does not run there.",
                    b.path.display(),
                    b.setting,
                    agent.label()
                ),
                fix,
            });
        }
    }

    // A hook `init --off` could not remove may still guard; otherwise no
    // successful hook means nothing is protected, failed entries or not.
    if !record
        .hooks
        .values()
        .any(|h| h.error.is_none() || h.off_failed)
    {
        problems.push(Problem {
            what: "no agent is hooked in this project, so saiife guards nothing here.".into(),
            fix: "run `saiife init --agent <claude|codex|gemini>`".into(),
        });
    }
    check_config(&root, &record, builtin, &mut problems);
    check_binary(&record, &mut problems);

    if !notes.is_empty() {
        println!();
        for n in &notes {
            println!("Note: {n}");
        }
    }
    for p in &problems {
        if p.fix.is_empty() {
            println!("\nWARNING: {}", p.what);
        } else {
            println!("\nWARNING: {}\n  Fix: {}", p.what, p.fix);
        }
    }
    println!(
        "\nsaiife v1 catches mistakes and makes a switched-off guard visible; it cannot stop a \
         determined agent running as your user."
    );
    if problems.is_empty() {
        println!("All checks passed.");
        ExitCode::SUCCESS
    } else {
        println!("{} check(s) failed.", problems.len());
        ExitCode::from(1)
    }
}

/// The project `status` reports on. Without a `.saiife/config.toml` at or
/// above `cwd` (it was removed), the nearest ancestor with an integrity
/// record is the project, so the removal is named instead of "not set up".
fn status_root(cwd: &Path) -> PathBuf {
    let found = project_root(cwd);
    if found != cwd || cwd.join(CONFIG_REL).is_file() {
        return found;
    }
    cwd.ancestors()
        .find(|d| {
            integrity::record_path(d)
                .ok()
                .flatten()
                .is_some_and(|p| matches!(Integrity::load(&p), Ok(Some(_))))
        })
        .unwrap_or(cwd)
        .to_path_buf()
}

/// Audit records of this project (by its literal and canonical path).
/// An unreadable audit trail is a failed check (spec §1.2 rule 5).
fn last_calls(
    root: &Path,
    hooked: &[&str],
    problems: &mut Vec<Problem>,
    notes: &mut Vec<String>,
) -> Vec<Record> {
    let Some(dir) = store::default_dir() else {
        problems.push(Problem {
            what: "the audit directory cannot be determined, so no decision is recorded".into(),
            fix: format!("set {}", store::DIR_ENV),
        });
        return Vec::new();
    };
    let canonical_root = integrity::canonical_project(root).ok();
    let mut roots = vec![root.display().to_string()];
    if let Some(c) = &canonical_root {
        roots.push(c.display().to_string());
    }
    let filters: Vec<Filter> = roots
        .into_iter()
        .map(|p| Filter {
            project: Some(p),
            ..Default::default()
        })
        .collect();
    // An agent may report its cwd through a symlink to the project: compare
    // each distinct recorded path canonicalized too (once per path). A path
    // that no longer exists, or a relative one (it would resolve against
    // status's own cwd), is only compared literally.
    let mut canonical: HashMap<String, Option<PathBuf>> = HashMap::new();
    let mut is_ours = |r: &Record| {
        if filters.iter().any(|f| f.matches(r)) {
            return true;
        }
        let Some(croot) = &canonical_root else {
            return false;
        };
        canonical
            .entry(r.project.clone())
            .or_insert_with(|| {
                Path::new(&r.project)
                    .is_absolute()
                    .then(|| std::fs::canonicalize(&r.project).ok())
                    .flatten()
            })
            .as_ref()
            .is_some_and(|p| p.starts_with(croot))
    };
    // Newest month files first; stop once every hooked agent has a call.
    let mut missing: Vec<&str> = hooked.to_vec();
    let all = store::read_recent(&dir, SCAN_MONTHS, |r| {
        if missing.is_empty() {
            return false;
        }
        if is_ours(r) {
            missing.retain(|a| *a != r.agent);
        }
        !missing.is_empty()
    });
    if let Some(e) = &all.dir_error {
        problems.push(Problem {
            what: format!("the audit log at {} cannot be read: {e}", dir.display()),
            fix: "make the directory readable by your user again".into(),
        });
    }
    if all.unreadable_files > 0 {
        problems.push(Problem {
            what: format!(
                "{} file(s) in the audit log at {} are not regular files or cannot be read",
                all.unreadable_files,
                dir.display()
            ),
            fix: "check the audit directory for files you did not create".into(),
        });
    }
    if all.skipped_lines > 0 {
        notes.push(format!(
            "{} unreadable audit line(s) skipped (a crash mid-write, or a hand edit)",
            all.skipped_lines
        ));
    }
    all.records.into_iter().filter(|r| is_ours(r)).collect()
}

fn check_config(root: &Path, record: &Integrity, builtin: &[Pack], problems: &mut Vec<Problem>) {
    match std::fs::read(root.join(CONFIG_REL)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => problems.push(Problem {
            what: format!("{CONFIG_REL} was removed."),
            fix: RESTORE.into(),
        }),
        Err(e) => problems.push(Problem {
            what: format!("{CONFIG_REL} cannot be read: {e}"),
            fix: "make it readable so saiife can check it".into(),
        }),
        Ok(bytes) if sha256_hex(&bytes) != record.config_sha256 => problems.push(Problem {
            what: format!("{CONFIG_REL} was changed since `saiife init`."),
            fix: "if you made this change, run `saiife init` to record it; otherwise restore the file and run `saiife init`".into(),
        }),
        Ok(_) => {}
    }
    let project = project_packs(root, builtin);
    for w in project.warnings {
        problems.push(Problem {
            what: w,
            fix: format!("fix {CONFIG_REL} (`saiife packs` lists the pack ids)"),
        });
    }
    let active: Vec<Pack> = builtin
        .iter()
        .filter(|p| p.default_on || project.enabled.contains(&p.id))
        .cloned()
        .collect();
    let ids: Vec<&str> = active.iter().map(|p| p.id.as_str()).collect();
    println!("  packs   {}", ids.join(", "));
    let vars = crate::paths::path_vars(Some(root), Some(root));
    print!("{}", inactive_lines(&active, &vars));
}

/// The `inactive here: …` lines under the packs line (empty when every path
/// rule of the active packs has a value on this machine).
fn inactive_lines(active: &[Pack], vars: &PathVars) -> String {
    crate::packs_cmd::inactive_summary(active, vars)
}

/// The `saiife` on PATH must be the binary that ran `init` (path + version).
fn check_binary(record: &Integrity, problems: &mut Vec<Problem>) {
    let fix =
        "if you moved, upgraded or reinstalled saiife yourself, run `saiife init` to record it";
    let Some(on_path) = which("saiife") else {
        problems.push(Problem {
            what: "`saiife` is not on PATH, so the agents cannot run the hook.".into(),
            fix: "put saiife back in a PATH directory, then run `saiife init`".into(),
        });
        return;
    };
    let on_path = std::fs::canonicalize(&on_path).unwrap_or(on_path);
    if on_path.as_path() != Path::new(&record.saiife_path) {
        problems.push(Problem {
            what: format!(
                "the saiife on PATH ({}) is not the one that ran `saiife init` ({}).",
                on_path.display(),
                record.saiife_path
            ),
            fix: fix.into(),
        });
        return;
    }
    if let (true, Some(e)) = (record.saiife_sha256.is_empty(), &record.saiife_sha256_error) {
        problems.push(Problem {
            what: format!(
                "`saiife init` could not compute the SHA-256 of the saiife binary ({e}), so a replaced binary cannot be detected."
            ),
            fix: "make the saiife binary readable, then run `saiife init`".into(),
        });
    } else if record.saiife_sha256.is_empty() {
        println!("  note: this record has no binary hash (made by an older saiife); run `saiife init` to add it");
    } else {
        match std::fs::read(&on_path) {
            Ok(b) if sha256_hex(&b) == record.saiife_sha256 => {}
            Ok(_) => {
                problems.push(Problem {
                    what: format!(
                        "the saiife binary at {} was replaced since `saiife init` (its contents changed).",
                        on_path.display()
                    ),
                    fix: fix.into(),
                });
                return;
            }
            Err(e) => {
                problems.push(Problem {
                    what: format!(
                        "the saiife binary at {} cannot be read: {e}",
                        on_path.display()
                    ),
                    fix: fix.into(),
                });
                return;
            }
        }
    }
    match binary_version(&on_path) {
        Some(v) if v == record.saiife_version => {
            println!("  binary  {} ({v})", on_path.display());
        }
        Some(v) => problems.push(Problem {
            what: format!(
                "the saiife on PATH is version {v}; `saiife init` ran with {}.",
                record.saiife_version
            ),
            fix: fix.into(),
        }),
        None => problems.push(Problem {
            what: format!("could not read the version of {}.", on_path.display()),
            fix: fix.into(),
        }),
    }
}

/// `<path> --version` -> the version after "saiife ". Gives up after 2 s,
/// also when a grandchild keeps the output pipe open: the first line is read
/// on a helper thread (at most 4 KiB) and waited for with a deadline.
fn binary_version(path: &Path) -> Option<String> {
    use std::io::{BufRead, BufReader};

    let mut child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let r = BufReader::new(stdout.take(4096)).read_line(&mut line);
        let _ = tx.send(r.ok().map(|_| line));
    });
    let got = rx.recv_timeout(Duration::from_secs(2)).ok().flatten();
    let _ = child.kill();
    let _ = child.wait();
    got?.trim().strip_prefix("saiife ").map(str::to_string)
}

fn ago(t: OffsetDateTime) -> String {
    let secs = (OffsetDateTime::now_utc() - t).whole_seconds().max(0);
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_lines_name_the_unbound_variable_and_its_packs() {
        let (packs, _) = saiifeguard::builtins::builtin_packs();
        let active: Vec<Pack> = packs.into_iter().filter(|p| p.default_on).collect();
        let bound = PathVars::new()
            .with_var("HOME", "/home/u")
            .with_var("PROJECT", "/home/u/app")
            .with_var("SAIIFE_DATA_DIR", "/home/u/.local/share/saiife")
            .with_var("CLAUDE_CONFIG_DIR", "/home/u/.claude")
            .with_var("CODEX_HOME", "/home/u/.codex")
            .with_var("SAIIFE_BIN", "/usr/bin/saiife");
        let text = inactive_lines(&active, &bound);
        assert!(
            text.starts_with("inactive here: $SAIIFE_AUDIT_DIR is not set: "),
            "{text}"
        );
        assert!(text.contains("core.self"), "{text}");
        let all = bound.with_var("SAIIFE_AUDIT_DIR", "/home/u/.local/share/saiife/audit");
        assert_eq!(inactive_lines(&active, &all), "");
    }
}
