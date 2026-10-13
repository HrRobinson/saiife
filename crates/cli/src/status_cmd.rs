//! `saiife status`: is this project still guarded? Runs the tamper checks
//! of spec §7.5 and exits 1 if any fails, so it can run in scripts and CI.

use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use saiife_agents::config::CONFIG_REL;
use saiife_agents::detect::which;
use saiife_agents::fingerprint::sha256_hex;
use saiife_agents::integrity::{self, Integrity};
use saiife_agents::Agent;
use saiife_audit::store::{self, Filter};
use saiife_audit::Record;
use saiifeguard::Pack;
use time::OffsetDateTime;

use crate::init_cmd::project_root;
use crate::project::project_packs;

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
    let root = project_root(&cwd);
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
    let last_calls = last_calls(&root, &mut problems, &mut notes);
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
        match found {
            Err(e) => problems.push(Problem {
                what: format!("{} cannot be checked: {e}", agent.label()),
                fix: format!("repair {rel}, then {RESTORE}"),
            }),
            Ok(f) if f.contains(&rec.sha256) => {
                let last = last_calls
                    .iter()
                    .filter(|r| r.agent == agent.name())
                    .filter_map(Record::timestamp)
                    .max();
                println!(
                    "  {:<7} hooked   {rel:<22} last hook call: {}",
                    agent.name(),
                    last.map(ago).unwrap_or_else(|| "never".into())
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
                    fix: "make it readable so saiife can check it".into(),
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

    check_config(&root, &record, builtin, &mut problems);
    check_binary(&record, &mut problems);

    if !notes.is_empty() {
        println!();
        for n in &notes {
            println!("Note: {n}");
        }
    }
    for p in &problems {
        println!("\nWARNING: {}\n  Fix: {}", p.what, p.fix);
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

/// Audit records of this project (by its literal and canonical path).
/// An unreadable audit trail is a failed check (spec §1.2 rule 5).
fn last_calls(root: &Path, problems: &mut Vec<Problem>, notes: &mut Vec<String>) -> Vec<Record> {
    let Some(dir) = store::default_dir() else {
        problems.push(Problem {
            what: "the audit directory cannot be determined, so no decision is recorded".into(),
            fix: format!("set {}", store::DIR_ENV),
        });
        return Vec::new();
    };
    let all = store::read_all(&dir);
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
    let mut roots = vec![root.display().to_string()];
    if let Ok(c) = integrity::canonical_project(root) {
        roots.push(c.display().to_string());
    }
    let filters: Vec<Filter> = roots
        .into_iter()
        .map(|p| Filter {
            project: Some(p),
            ..Default::default()
        })
        .collect();
    all.records
        .into_iter()
        .filter(|r| filters.iter().any(|f| f.matches(r)))
        .collect()
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
    let active: Vec<&str> = builtin
        .iter()
        .filter(|p| p.default_on || project.enabled.contains(&p.id))
        .map(|p| p.id.as_str())
        .collect();
    println!("  packs   {}", active.join(", "));
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
    if record.saiife_sha256.is_empty() {
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
    use std::os::unix::process::CommandExt;

    let mut child = Command::new(path)
        .arg("--version")
        .process_group(0)
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
