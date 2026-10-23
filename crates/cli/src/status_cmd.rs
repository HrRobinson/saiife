//! `saiife status`: is this project still guarded? Runs the tamper checks
//! of spec §7.5 and exits 1 if any fails, so it can run in scripts and CI.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use saiife_agents::config::{self, CONFIG_REL};
use saiife_agents::detect::which;
use saiife_agents::fingerprint::sha256_hex;
use saiife_agents::integrity::{self, Integrity};
use saiife_agents::{lock, Agent};
use saiife_audit::store::{self, Filter};
use saiife_audit::Record;
use saiife_policy::installed::{read_installed, FileKind, Installed};
use saiife_policy::{active_packs, effective_policy, load_system, policy_hash, PackInfo};
use saiife_system::layout::{CONFIG, INSTALLED};
use saiife_system::{host_for, Host, Layout};
use saiifeguard::canon::PathVars;
use saiifeguard::Pack;
use time::OffsetDateTime;

use crate::project::{project_packs, project_root};
use crate::text::sanitize;

/// Month files `status` reads at most when looking for each agent's last call.
const SCAN_MONTHS: usize = 12;

/// Directory entries the nested-config scan reads at most.
const SCAN_LIMIT: usize = 20_000;

/// Directories the nested-config scan never enters.
const SCAN_SKIP: [&str; 3] = [".git", "target", "node_modules"];

/// A path as status prints it: sanitized, since directory names (and the
/// paths built from them) are anything anyone can create.
fn shown(path: &Path) -> String {
    sanitize(&path.display().to_string())
}

/// The fix for a removed or changed hook or config: `init` in the project
/// status reported on (`project_root`, the same rule `init` uses).
fn restore(root: &Path) -> String {
    format!("run `saiife init` in {} to restore it", shown(root))
}

/// The integrity record of `dir`: `Ok(None)` when there is none, `Err`
/// (the reason) when it cannot be located or read.
fn load_record(dir: &Path) -> Result<Option<Integrity>, String> {
    match integrity::record_path(dir) {
        Ok(Some(p)) => Integrity::load(&p).map_err(|e| e.to_string()),
        Ok(None) => Err("could not determine the data directory".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// One failed check: what is wrong, and what to do.
struct Problem {
    what: String,
    fix: String,
}

/// `system_root`: the hidden `--root` (tests); the real `/` otherwise.
pub fn run(builtin: &[Pack], system_root: Option<PathBuf>) -> ExitCode {
    let Ok(cwd) = std::env::current_dir() else {
        eprintln!("saiife: cannot read the current directory");
        return ExitCode::from(2);
    };
    let root = project_root(&cwd);
    outln!("saiife status for {}", shown(&root));
    let layout = system_root
        .map(Layout::under)
        .unwrap_or_else(Layout::system);
    let locked = locked_block(&layout, builtin);
    let locked_failed = locked.as_ref().is_some_and(|l| l.failed);
    // Agents with a managed hook need no project hook (spec §7 `init`).
    let managed = locked.map(|l| l.managed).unwrap_or_default();

    let record = match load_record(&root) {
        Ok(Some(r)) => r,
        Ok(None) if !managed.is_empty() => {
            outln!(
                "\n  project hooks: none (`saiife init` was not run here); the managed hooks guard {}",
                managed.join(", ")
            );
            return if locked_failed {
                outln!("\nLocked mode check(s) failed.");
                ExitCode::from(1)
            } else {
                outln!("\nAll checks passed.");
                ExitCode::SUCCESS
            };
        }
        Ok(None) => {
            outln!(
                "\nWARNING: saiife is not set up for this project on this machine \
                 (no integrity record).\n  Fix: run `saiife init` in {}",
                shown(&root)
            );
            return ExitCode::from(1);
        }
        Err(e) => {
            outln!("\nWARNING: the integrity record cannot be read: {e}\n  Fix: run `saiife init` to write a new one");
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
    let (last_calls, scan) = last_calls(&root, &hooked, &mut problems, &mut notes);
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
                outln!("  {:<7} not set up", agent.name());
            }
            continue;
        };
        if let (Some(e), true) = (&rec.error, rec.off_failed) {
            if let Some(target) = &rec.off_outside {
                problems.push(if rec.init_failed {
                    Problem {
                        what: format!(
                            "{rel} is a symlink to {target}, outside the project, so `saiife init --off` did not change it. The earlier `saiife init` for {} failed, so the saiife hook may still be in place.",
                            agent.label()
                        ),
                        fix: format!(
                            "check {target} by hand and remove the saiife hook entry (the `saiife check` command) if it is there"
                        ),
                    }
                } else {
                    Problem {
                        what: format!(
                            "{rel} is a symlink to {target}, outside the project, so `saiife init --off` did not change it and the saiife hook is still in place."
                        ),
                        fix: format!(
                            "remove the saiife hook entry (the `saiife check` command) from {target} by hand"
                        ),
                    }
                });
                continue;
            }
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
                fix: format!("repair {rel}, then {}", restore(&root)),
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
                outln!(
                    "  {:<7} hooked   {rel:<22} last hook call: {}",
                    agent.name(),
                    last.map(ago).unwrap_or_else(|| match scan {
                        Scan::Unreadable => "unknown (audit log could not be read)".into(),
                        Scan::CutShort => format!("no call in the last {SCAN_MONTHS} months"),
                        Scan::Complete => "no call yet".into(),
                    })
                );
            }
            Ok(f) if f.is_empty() => problems.push(Problem {
                what: format!(
                    "The saiife hook for {} was removed from {rel}.",
                    agent.label()
                ),
                fix: restore(&root),
            }),
            Ok(_) => problems.push(Problem {
                what: format!(
                    "The saiife hook for {} in {rel} was changed.",
                    agent.label()
                ),
                fix: restore(&root),
            }),
        }
        for b in agent.blockers(&root, home.as_deref()) {
            if let Some(e) = &b.error {
                problems.push(Problem {
                    what: format!(
                        "{} cannot be read, so saiife cannot tell whether it switches off {}'s hooks: {e}",
                        shown(&b.path),
                        agent.label()
                    ),
                    fix: if b.managed {
                        format!(
                            "ask your administrator to make {} (managed settings) a readable JSON object",
                            shown(&b.path)
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
                format!("remove `{}` from {}", b.setting, shown(&b.path))
            };
            problems.push(Problem {
                what: format!(
                    "{} sets {}, which stops {}'s hooks: saiife does not run there.",
                    shown(&b.path),
                    b.setting,
                    agent.label()
                ),
                fix,
            });
        }
    }

    // A hook `init --off` could not remove may still guard; otherwise no
    // successful hook means nothing is protected, failed entries or not.
    if managed.is_empty()
        && !record
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
    check_nested_configs(&root, &mut problems, &mut notes);
    check_binary(&record, &mut problems);

    if !notes.is_empty() {
        outln!();
        for n in &notes {
            outln!("Note: {n}");
        }
    }
    for p in &problems {
        if p.fix.is_empty() {
            outln!("\nWARNING: {}", p.what);
        } else {
            outln!("\nWARNING: {}\n  Fix: {}", p.what, p.fix);
        }
    }
    if managed.is_empty() {
        outln!(
            "\nsaiife v1 catches mistakes and makes a switched-off guard visible; it cannot stop a \
             determined agent running as your user."
        );
    }
    if locked_failed {
        problems.push(Problem {
            what: "the locked mode checks above failed.".into(),
            fix: String::new(),
        });
    }
    if problems.is_empty() {
        outln!("All checks passed.");
        ExitCode::SUCCESS
    } else {
        outln!("{} check(s) failed.", problems.len());
        ExitCode::from(1)
    }
}

/// How far `last_calls` got through the audit log.
#[derive(Clone, Copy)]
enum Scan {
    /// Every month file was read: no record means no call yet.
    Complete,
    /// Older month files were left unread (`ReadResult::cut_short`).
    CutShort,
    /// The audit dir could not be determined or listed.
    Unreadable,
}

/// Audit records of this project (by its literal and canonical path).
/// An unreadable audit trail is a failed check (spec §1.2 rule 5).
fn last_calls(
    root: &Path,
    hooked: &[&str],
    problems: &mut Vec<Problem>,
    notes: &mut Vec<String>,
) -> (Vec<Record>, Scan) {
    let Some(dir) = store::default_dir() else {
        problems.push(Problem {
            what: "the audit directory cannot be determined, so no decision is recorded".into(),
            fix: format!("set {}", store::DIR_ENV),
        });
        return (Vec::new(), Scan::Unreadable);
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
            what: format!("the audit log at {} cannot be read: {e}", shown(&dir)),
            fix: "make the directory readable by your user again".into(),
        });
    }
    if all.unreadable_files > 0 {
        problems.push(Problem {
            what: format!(
                "{} file(s) in the audit log at {} are not regular files or cannot be read",
                all.unreadable_files,
                shown(&dir)
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
    let scan = if all.dir_error.is_some() {
        Scan::Unreadable
    } else if all.cut_short {
        Scan::CutShort
    } else {
        Scan::Complete
    };
    let ours = all.records.into_iter().filter(|r| is_ours(r)).collect();
    (ours, scan)
}

/// Compare the config in `dir` with the hash `init` recorded. `shown` is
/// the config path as printed, `init` the init command to suggest (both
/// already safe to print), `restore_fix` the fix for a removed config.
fn config_drift(
    dir: &Path,
    recorded: &str,
    shown: &str,
    init: &str,
    restore_fix: String,
) -> Option<Problem> {
    match config::read_config_bytes(dir) {
        Ok(None) => Some(Problem {
            what: format!("{shown} was removed."),
            fix: restore_fix,
        }),
        Err(e) => Some(Problem {
            what: format!("{shown} cannot be read: {}", sanitize(&e.to_string())),
            fix: "make it readable so saiife can check it".into(),
        }),
        Ok(Some(bytes)) if sha256_hex(&bytes) != recorded => Some(Problem {
            what: format!("{shown} was changed since `saiife init`."),
            fix: format!(
                "if you made this change, run {init} to record it; otherwise restore the file and run {init}"
            ),
        }),
        Ok(_) => None,
    }
}

fn check_config(root: &Path, record: &Integrity, builtin: &[Pack], problems: &mut Vec<Problem>) {
    problems.extend(config_drift(
        root,
        &record.config_sha256,
        CONFIG_REL,
        "`saiife init`",
        restore(root),
    ));
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
    outln!("{}", packs_line(root, project.root.as_deref(), &ids));
    let vars = crate::paths::path_vars(Some(root), Some(root));
    out!("{}", inactive_lines(&active, &vars));
}

/// `SCAN_LIMIT`; debug builds (tests) may lower it with `SAIIFE_SCAN_LIMIT`.
fn scan_limit() -> usize {
    #[cfg(debug_assertions)]
    if let Some(n) = std::env::var("SAIIFE_SCAN_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return n;
    }
    SCAN_LIMIT
}

/// Check `.saiife/` directories below `root`: the hook's own lookup takes
/// the nearest config, so hooks run under a nested one ignore this
/// project's. A config `saiife init` did not set up (no integrity record)
/// fails; one with a record is held to its recorded hash like the project's
/// own (changed, removed, or a record that cannot be read all fail). Paths
/// are directory names anyone can create, so they are printed sanitized.
fn check_nested_configs(root: &Path, problems: &mut Vec<Problem>, notes: &mut Vec<String>) {
    let limit = scan_limit();
    let scan = nested_configs(root, limit);
    for dir in scan.found {
        let abs = root.join(&dir);
        let rel = sanitize(&dir.display().to_string());
        let has_config = abs.join(CONFIG_REL).is_file();
        match load_record(&abs) {
            Ok(Some(record)) => problems.extend(config_drift(
                &abs,
                &record.config_sha256,
                &format!("{rel}/{CONFIG_REL}"),
                &format!("`saiife init` in {rel}"),
                format!("run `saiife init` in {rel} to restore it"),
            )),
            // A stray `.saiife/` without a config or a record is harmless.
            Ok(None) if !has_config => {}
            Ok(None) => problems.push(Problem {
                what: format!(
                    "{rel}/{CONFIG_REL} is a separate saiife config that was not set up with saiife init; hooks run in {rel} use it instead of this project's config."
                ),
                fix: format!("delete it, or run saiife init in {rel}"),
            }),
            Err(e) => problems.push(Problem {
                what: format!(
                    "the integrity record for {rel} cannot be read, so {rel}/{CONFIG_REL} cannot be checked: {}",
                    sanitize(&e)
                ),
                fix: format!("run `saiife init` in {rel} to restore it"),
            }),
        }
    }
    if scan.cut_short {
        notes.push(format!("nested-config scan stopped after {limit} entries"));
    }
}

struct NestedScan {
    /// Directories below the root (relative to it) holding a `.saiife/`
    /// directory (with or without a config file in it).
    found: Vec<PathBuf>,
    /// The walk stopped at the entry limit.
    cut_short: bool,
}

/// Breadth-first walk of `root`'s subdirectories (sorted, so the output is
/// stable), reading at most `limit` directory entries. Symlinks are never
/// followed, `SCAN_SKIP` directories and unreadable ones are skipped. The
/// root's own config is not nested.
fn nested_configs(root: &Path, limit: usize) -> NestedScan {
    let mut found = Vec::new();
    let mut queue = std::collections::VecDeque::from([PathBuf::new()]);
    let mut seen = 0usize;
    while let Some(rel) = queue.pop_front() {
        let dir = root.join(&rel);
        // Followed like the hook's own lookup (a `.saiife` symlink counts).
        if !rel.as_os_str().is_empty() && dir.join(".saiife").is_dir() {
            found.push(rel.clone());
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut subdirs = Vec::new();
        for e in entries {
            if seen == limit {
                found.sort();
                return NestedScan {
                    found,
                    cut_short: true,
                };
            }
            seen += 1;
            let Ok(e) = e else { continue };
            // `DirEntry::file_type` does not follow symlinks.
            if !e.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let name = e.file_name();
            if SCAN_SKIP.iter().any(|s| name == *s) {
                continue;
            }
            subdirs.push(rel.join(name));
        }
        subdirs.sort();
        queue.extend(subdirs);
    }
    found.sort();
    NestedScan {
        found,
        cut_short: false,
    }
}

/// The `packs …` line. When the config it was read from sits in another
/// directory than the project in the header, the line says where from.
fn packs_line(root: &Path, config_root: Option<&Path>, ids: &[&str]) -> String {
    match config_root {
        Some(dir) if dir != root => format!(
            "  packs (from {}/{CONFIG_REL}): {}",
            shown(dir),
            ids.join(", ")
        ),
        _ => format!("  packs   {}", ids.join(", ")),
    }
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
                shown(&on_path),
                sanitize(&record.saiife_path)
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
        outln!("  note: this record has no binary hash (made by an older saiife); run `saiife init` to add it");
    } else {
        match std::fs::read(&on_path) {
            Ok(b) if sha256_hex(&b) == record.saiife_sha256 => {}
            Ok(_) => {
                problems.push(Problem {
                    what: format!(
                        "the saiife binary at {} was replaced since `saiife init` (its contents changed).",
                        shown(&on_path)
                    ),
                    fix: fix.into(),
                });
                return;
            }
            Err(e) => {
                problems.push(Problem {
                    what: format!(
                        "the saiife binary at {} cannot be read: {e}",
                        shown(&on_path)
                    ),
                    fix: fix.into(),
                });
                return;
            }
        }
    }
    match binary_version(&on_path) {
        Some(v) if v == record.saiife_version => {
            outln!("  binary  {} ({v})", shown(&on_path));
        }
        Some(v) => problems.push(Problem {
            what: format!(
                "the saiife on PATH is version {v}; `saiife init` ran with {}.",
                record.saiife_version
            ),
            fix: fix.into(),
        }),
        None => problems.push(Problem {
            what: format!("could not read the version of {}.", shown(&on_path)),
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

// ------------------------------------------------------------ locked mode

/// What the `Locked mode` block found.
struct LockedState {
    /// Something makes every managed hook call fail or the install differ
    /// from its record: status exits 1.
    failed: bool,
    /// Agents with a managed hook.
    managed: Vec<String>,
}

/// The `Locked mode` block (spec §7 `status`), printed when
/// `<root>/etc/saiife/installed.toml` exists; `None` otherwise (developer
/// mode). Pending approvals and lockdown come in plan 11.
fn locked_block(layout: &Layout, builtin: &[Pack]) -> Option<LockedState> {
    let installed_path = layout.at(INSTALLED);
    // A dangling or symlinked record still means locked mode (and fails).
    std::fs::symlink_metadata(&installed_path).ok()?;
    let mut st = LockedState {
        failed: false,
        managed: Vec::new(),
    };
    outln!("\nLocked mode");
    let installed = match read_installed(&installed_path) {
        Ok(Some(i)) => {
            outln!(
                "  mode: locked (installed {}, saiife {})",
                sanitize(&i.installed_at),
                sanitize(&i.saiife)
            );
            Some(i)
        }
        Ok(None) => None,
        Err(e) => {
            st.failed = true;
            outln!(
                "  mode: locked (the install record cannot be read: {}); ask your administrator to run `sudo saiife system install`",
                sanitize(&e)
            );
            None
        }
    };

    let config = load_system(&layout.at(CONFIG))
        .map_err(|e| e.to_string())
        .and_then(|l| {
            if l.config.locked {
                Ok(l)
            } else {
                Err(format!("{CONFIG}: locked is not true"))
            }
        });
    let host = host_for(layout);
    let daemon = match &host {
        Ok(h) => daemon_status(layout, h.as_ref(), config.as_ref().ok().map(|l| &l.config)),
        Err(e) => Err(e.to_string()),
    };
    match daemon {
        Ok(line) => outln!("  daemon: running, {line}"),
        Err(e) => {
            st.failed = true;
            outln!(
                "  daemon: not answering ({}): every managed hook call is denied",
                sanitize(&e)
            );
        }
    }
    match &config {
        Ok(l) => {
            let catalog: Vec<PackInfo> = builtin
                .iter()
                .map(|p| PackInfo {
                    id: p.id.clone(),
                    version: p.version,
                    default_on: p.default_on,
                })
                .collect();
            let (packs, _) = active_packs(&l.config, &catalog, None);
            outln!(
                "  policy: {}",
                policy_hash(&effective_policy(&l.config, &packs, None))
            );
        }
        Err(e) => {
            st.failed = true;
            outln!(
                "  policy: invalid ({}): every managed hook call is denied and nothing is recorded",
                sanitize(e)
            );
        }
    }
    if let Some(i) = &installed {
        for a in &i.agents {
            let wording = Agent::from_name(&a.agent)
                .map(|ag| lock::label(ag).wording())
                .unwrap_or("unknown agent");
            outln!("  agent {}: managed hook, {wording}", sanitize(&a.agent));
            st.managed.push(a.agent.clone());
        }
        for problem in fingerprint_problems(layout, i) {
            st.failed = true;
            outln!(
                "  WARNING: {}\n    Fix: ask your administrator to run `sudo saiife system install` (or `sudo saiife doctor`)",
                sanitize(&problem)
            );
        }
    }
    if let Ok(l) = &config {
        for s in &l.config.guard.mcp.allow_servers {
            outln!(
                "  warning: MCP server {} bypasses saiife: its requests are not brokered or limited",
                sanitize(s)
            );
        }
    }
    Some(st)
}

/// `chain <id>, head seq <n>, last checkpoint seq <m>` from the daemon's
/// `status`, or why it did not answer.
#[cfg(target_os = "linux")]
fn daemon_status(
    layout: &Layout,
    host: &dyn Host,
    cfg: Option<&saiife_policy::SystemConfig>,
) -> Result<String, String> {
    use saiife_ipc::client::Client;
    use saiife_ipc::msg::OP_STATUS;
    use saiife_system::layout::{DAEMON_USER, RUN_DIR};
    use serde_json::{Map, Value};
    use std::time::Instant;
    // The §5.2 default lies under the layout's root; any other value is
    // taken as written (as `doctor` does).
    let configured = |value: &Path, default: &str| {
        if value == Path::new(default) {
            layout.at(default)
        } else {
            value.to_path_buf()
        }
    };
    let (user, dir) = match cfg {
        Some(c) => (
            c.daemon.user.clone(),
            configured(&c.daemon.socket_dir, RUN_DIR),
        ),
        None => (DAEMON_USER.to_string(), layout.at(RUN_DIR)),
    };
    let Some(uid) = host.user(&user).map(|u| u.uid) else {
        return Err(format!("the daemon user {user} does not exist"));
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    let m = Client::connect(&dir, uid, deadline)
        .and_then(|mut c| c.call(OP_STATUS, Map::new(), deadline))
        .map_err(|e| e.to_string())?;
    let show = |k: &str| match m.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => "none".to_string(),
        Some(v) => v.to_string(),
    };
    Ok(format!(
        "chain {}, head seq {}, last checkpoint seq {}",
        show("chain"),
        show("head_seq"),
        show("last_checkpoint_seq")
    ))
}

#[cfg(not(target_os = "linux"))]
fn daemon_status(
    _layout: &Layout,
    _host: &dyn Host,
    _cfg: Option<&saiife_policy::SystemConfig>,
) -> Result<String, String> {
    Err(saiife_system::NOT_LINUX.to_string())
}

/// Installed files whose fingerprint differs from `installed.toml`: the
/// binary, the unit and the managed agent configs. The config is the
/// admin's to edit, and the vault key has no digest on record.
fn fingerprint_problems(layout: &Layout, i: &Installed) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |listed: &Path, got: Result<Option<String>, String>, want: &str| {
        let shown = listed.display();
        match got {
            Ok(Some(g)) if g == want => {}
            Ok(Some(_)) => out.push(format!("{shown}: changed since install")),
            Ok(None) => out.push(format!("{shown}: missing")),
            Err(e) => out.push(format!("{shown}: cannot be checked: {e}")),
        }
    };
    let file_sha = |listed: &Path| -> Result<Option<String>, String> {
        let at = layout.try_at(listed).map_err(|e| e.to_string())?;
        match std::fs::symlink_metadata(&at) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
            Ok(m) if !m.is_file() => return Err("not a regular file".into()),
            Ok(_) => {}
        }
        std::fs::read(&at)
            .map(|b| Some(sha256_hex(&b)))
            .map_err(|e| e.to_string())
    };
    for f in &i.files {
        if matches!(f.kind, FileKind::Config | FileKind::VaultKey) {
            continue;
        }
        if let Some(want) = &f.sha256 {
            check(&f.path, file_sha(&f.path), want);
        }
    }
    for a in &i.agents {
        let got = if a.whole_file {
            file_sha(&a.path)
        } else {
            layout
                .try_at(&a.path)
                .map_err(|e| e.to_string())
                .and_then(|at| {
                    match a.agent.as_str() {
                        "codex" => saiife_agents::codex::managed_entry(&at),
                        "gemini" => saiife_agents::gemini::managed_entry(&at),
                        other => return Err(format!("unknown managed agent {other:?}")),
                    }
                    .map_err(|e| e.to_string())
                })
        };
        check(&a.path, got, &a.sha256);
    }
    out
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
