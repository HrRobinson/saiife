//! `saiife init` and `saiife init --off` (spec §5, §5.1, §5.2, §7.5).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use saiife_agents::config::{self, CONFIG_REL};
use saiife_agents::detect::{detect_agents, which};
use saiife_agents::fingerprint::sha256_hex;
use saiife_agents::integrity::{self, HookRecord, Integrity, INTEGRITY_VERSION};
use saiife_agents::{Agent, Change};
use saiifeguard::Pack;

/// The project `init`, `--off` and `status` work on: the nearest directory
/// at or above `cwd` with `.saiife/config.toml`, else `cwd` itself.
pub fn project_root(cwd: &Path) -> PathBuf {
    config::find_project_root(cwd).unwrap_or_else(|| cwd.to_path_buf())
}

pub fn run(builtin: &[Pack], agent_names: &[String], pack_ids: &[String]) -> ExitCode {
    let Ok(cwd) = std::env::current_dir() else {
        eprintln!("saiife: cannot read the current directory");
        return ExitCode::from(2);
    };
    let root = project_root(&cwd);
    if root != cwd {
        println!("Using the saiife project at {}", root.display());
    }

    // Which agents.
    let agents = if agent_names.is_empty() {
        let found = detect_agents();
        if found.is_empty() {
            eprintln!(
                "saiife: no supported agent found on PATH (looked for claude, codex, gemini).\n\
                 Install one, or name it: saiife init --agent claude"
            );
            return ExitCode::from(2);
        }
        found
    } else {
        let mut out = Vec::new();
        for name in agent_names {
            match Agent::from_name(name) {
                Some(a) if !out.contains(&a) => out.push(a),
                Some(_) => {}
                None => {
                    eprintln!("saiife: unknown agent {name:?} (choose claude, codex or gemini)");
                    return ExitCode::from(2);
                }
            }
        }
        out
    };

    // Which packs.
    let mut requested = Vec::new();
    for id in pack_ids {
        if builtin.iter().any(|p| &p.id == id) {
            if !requested.contains(id) {
                requested.push(id.clone());
            }
        } else {
            eprintln!("saiife: unknown pack {id:?} ignored (`saiife packs` lists them)");
        }
    }
    let config_existed = root.join(CONFIG_REL).exists();
    let mut packs: Vec<String> = if config_existed {
        Vec::new()
    } else {
        builtin
            .iter()
            .filter(|p| p.default_on)
            .map(|p| p.id.clone())
            .collect()
    };
    for id in requested {
        if !packs.contains(&id) {
            packs.push(id);
        }
    }

    let record_path = match integrity::record_path(&root) {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!("saiife: could not determine the data directory; set SAIIFE_DATA_DIR");
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("saiife: {e}");
            return ExitCode::from(1);
        }
    };
    let previous = match Integrity::load(&record_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "saiife: WARNING: the integrity record is unreadable ({e}); starting a new one. \
                 What the earlier init created is no longer tracked, so `saiife init --off` \
                 will not delete those files."
            );
            None
        }
    };
    let mut created = previous
        .as_ref()
        .map(|p| p.created.clone())
        .unwrap_or_default();
    let mut config_written_sha256 = previous
        .as_ref()
        .map(|p| p.config_written_sha256.clone())
        .unwrap_or_default();
    let mut hooks = previous.map(|p| p.hooks).unwrap_or_default();

    // Was the config still exactly what saiife wrote, before this run?
    let config_was_ours = !config_written_sha256.is_empty()
        && std::fs::read(root.join(CONFIG_REL))
            .is_ok_and(|b| sha256_hex(&b) == config_written_sha256);

    // Project config first: if it cannot be written, touch nothing else.
    let config_change = match config::ensure(&root, &packs) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("saiife: {e}");
            return ExitCode::from(1);
        }
    };
    note_created(&mut created, &config_change, CONFIG_REL);
    let mut failed = false;
    match config_change {
        Change::Created { .. } => {
            if let Ok(bytes) = std::fs::read(root.join(CONFIG_REL)) {
                config_written_sha256 = sha256_hex(&bytes);
            }
        }
        // Appending packs to a file the user edited must not make their
        // edits look like saiife's own content.
        Change::Updated if config_was_ours => {
            if let Ok(bytes) = std::fs::read(root.join(CONFIG_REL)) {
                config_written_sha256 = sha256_hex(&bytes);
            }
        }
        Change::Updated => config_written_sha256.clear(),
        _ => {}
    }
    let mut lines = vec![format!(
        "  config  {CONFIG_REL} ({})",
        describe(&config_change, "packs added", "already set up")
    )];

    let mut installed = Vec::new();
    for agent in &agents {
        match agent.install(&root) {
            Ok(change) => {
                note_created(&mut created, &change, agent.config_rel());
                hooks.insert(
                    agent.name().to_string(),
                    HookRecord {
                        file: agent.config_rel().to_string(),
                        sha256: agent.expected_entry(),
                        error: None,
                    },
                );
                installed.push(*agent);
                lines.push(format!(
                    "  {:<7} {} ({})",
                    agent.name(),
                    agent.config_rel(),
                    describe(&change, "hook added", "already set up")
                ));
            }
            Err(e) => {
                failed = true;
                // Recorded, so `status` reports the agent as not guarded
                // instead of "not set up".
                hooks.insert(
                    agent.name().to_string(),
                    HookRecord {
                        file: agent.config_rel().to_string(),
                        sha256: String::new(),
                        error: Some(e.to_string()),
                    },
                );
                lines.push(format!("  {:<7} FAILED: {e}", agent.name()));
            }
        }
    }

    let config_sha256 = match std::fs::read(root.join(CONFIG_REL)) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(e) => {
            failed = true;
            lines.push(format!("  config  FAILED to read {CONFIG_REL}: {e}"));
            String::new()
        }
    };
    let mut warnings = Vec::new();
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .unwrap_or_default();
    let (saiife_sha256, saiife_sha256_error) = match std::fs::read(&exe) {
        Ok(b) => (sha256_hex(&b), None),
        Err(e) => {
            let reason = format!("{}: {e}", exe.display());
            warnings.push(format!(
                "WARNING: could not compute the SHA-256 of the saiife binary ({reason}), so \
                 `saiife status` cannot detect if it is replaced and will report a failed check. \
                 Make the binary readable, then run `saiife init` again."
            ));
            (String::new(), Some(reason))
        }
    };
    let record = Integrity {
        v: INTEGRITY_VERSION,
        project: integrity::canonical_project(&root)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| root.display().to_string()),
        saiife_path: exe.display().to_string(),
        saiife_version: env!("CARGO_PKG_VERSION").to_string(),
        saiife_sha256,
        saiife_sha256_error,
        config_sha256,
        config_written_sha256,
        hooks,
        created,
    };
    if let Err(e) = record.save(&record_path) {
        failed = true;
        lines.push(format!("  integrity record FAILED: {e}"));
    }

    println!("saiife is on for {}", root.display());
    for l in &lines {
        println!("{l}");
    }
    if let Ok(cfg) = config::load(&root) {
        let active: Vec<&str> = builtin
            .iter()
            .filter(|p| p.default_on || cfg.packs.contains(&p.id))
            .map(|p| p.id.as_str())
            .collect();
        println!("  packs   {}", active.join(", "));
    }
    for w in &warnings {
        println!("\n{w}");
    }
    path_warning(&exe);
    if !installed.is_empty() {
        println!("\nNext steps:");
        for agent in &installed {
            println!("  - {}: {}", agent.label(), agent.next_step());
        }
    }
    println!("Check the setup any time with `saiife status`.");
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// The hooks run whatever `saiife` is on PATH. Say so plainly when that is
/// nothing, or a different binary.
fn path_warning(exe: &Path) {
    match which("saiife").map(|p| std::fs::canonicalize(&p).unwrap_or(p)) {
        None => println!(
            "\nWARNING: `saiife` is not on your PATH, so the agents cannot run the hook and \
             their actions are NOT guarded. Put saiife in a PATH directory (e.g. ~/.local/bin), \
             then run `saiife init` again."
        ),
        Some(p) if p != exe => println!(
            "\nWARNING: the hooks will run {} (the saiife on your PATH), not this binary ({}). \
             Run `saiife init` with the saiife on your PATH.",
            p.display(),
            exe.display()
        ),
        Some(_) => {}
    }
}

pub fn off() -> ExitCode {
    let Ok(cwd) = std::env::current_dir() else {
        eprintln!("saiife: cannot read the current directory");
        return ExitCode::from(2);
    };
    let root = project_root(&cwd);
    let record_path = integrity::record_path(&root).ok().flatten();
    let mut record_unreadable = false;
    let mut failed = false;
    let record = match record_path.as_deref().map(Integrity::load) {
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            record_unreadable = true;
            failed = true;
            eprintln!(
                "saiife: WARNING: the integrity record is unreadable ({e}); it is kept for \
                 inspection. Without it saiife cannot tell what init created, so files are \
                 only un-hooked, never deleted."
            );
            None
        }
        None => None,
    };
    let created: Vec<String> = record
        .as_ref()
        .map(|r| r.created.clone())
        .unwrap_or_default();
    let mut lines = Vec::new();
    // Agents whose hook could not be removed, with the reason.
    let mut failed_agents: Vec<(Agent, String)> = Vec::new();

    for agent in Agent::ALL {
        let ours = created.iter().any(|c| c == agent.config_rel());
        match agent.remove(&root, ours) {
            Ok(Change::Unchanged) => {}
            Ok(Change::Deleted) => lines.push(format!(
                "  {:<7} hook removed; {} deleted (saiife created it)",
                agent.name(),
                agent.config_rel()
            )),
            Ok(_) => lines.push(format!(
                "  {:<7} hook removed from {}",
                agent.name(),
                agent.config_rel()
            )),
            Err(e) => {
                failed = true;
                let mut line = format!("  {:<7} FAILED: {e}", agent.name());
                if let saiife_agents::AgentError::Layout { detail, .. } = &e {
                    if detail.contains("outside the project") {
                        line.push_str(
                            "\n          saiife did not change that file. To finish, remove the \
                             saiife hook entry (the `saiife check` command) from it by hand.",
                        );
                    }
                }
                lines.push(line);
                failed_agents.push((agent, e.to_string()));
            }
        }
    }

    let config_path = root.join(CONFIG_REL);
    if config_path.exists() {
        let unchanged = record.as_ref().is_some_and(|r| {
            !r.config_written_sha256.is_empty()
                && std::fs::read(&config_path)
                    .is_ok_and(|b| sha256_hex(&b) == r.config_written_sha256)
        });
        if created.iter().any(|c| c == CONFIG_REL) && unchanged {
            match std::fs::remove_file(&config_path) {
                Ok(()) => lines.push(format!("  config  {CONFIG_REL} deleted")),
                Err(e) => {
                    failed = true;
                    lines.push(format!("  config  FAILED to delete {CONFIG_REL}: {e}"));
                }
            }
        } else {
            lines.push(format!(
                "  config  {CONFIG_REL} kept (saiife did not create it, or it was edited); \
                 delete it yourself if you no longer need it"
            ));
        }
    }
    // Directories saiife created, innermost first; only empty ones go.
    for rel in created.iter().rev() {
        let p = root.join(rel);
        if p.is_dir() {
            let _ = std::fs::remove_dir(&p);
        }
    }
    if !failed && !record_unreadable {
        if let Some(p) = &record_path {
            if let Err(e) = Integrity::delete(p) {
                failed = true;
                lines.push(format!("  integrity record FAILED: {e}"));
            }
        }
    } else if let (Some(mut rec), Some(p), false) = (record, &record_path, failed_agents.is_empty())
    {
        // Partly off: keep the record for the agents still hooked, so
        // `status` warns about them and nothing else.
        rec.hooks = failed_agents
            .iter()
            .map(|(a, e)| {
                (
                    a.name().to_string(),
                    HookRecord {
                        file: a.config_rel().to_string(),
                        sha256: String::new(),
                        error: Some(format!(
                            "`saiife init --off` could not remove its hook: {e}"
                        )),
                    },
                )
            })
            .collect();
        rec.created.retain(|rel| root.join(rel).exists());
        if let Err(e) = rec.save(p) {
            lines.push(format!("  integrity record FAILED: {e}"));
        }
    }

    println!("saiife is off for {}", root.display());
    if lines.is_empty() {
        println!("  nothing to remove");
    }
    for l in &lines {
        println!("{l}");
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Remember what a write created: its new directories, then the file.
fn note_created(created: &mut Vec<String>, change: &Change, file: &str) {
    if let Change::Created { created_dirs } = change {
        for rel in created_dirs.iter().map(String::as_str).chain([file]) {
            if !created.iter().any(|c| c == rel) {
                created.push(rel.to_string());
            }
        }
    }
}

fn describe(change: &Change, updated: &str, unchanged: &str) -> String {
    match change {
        Change::Created { .. } => "created".into(),
        Change::Updated => updated.into(),
        Change::Unchanged => unchanged.into(),
        Change::Deleted => "deleted".into(),
    }
}
