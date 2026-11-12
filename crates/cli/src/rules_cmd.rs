//! `saiife rules import | sync | list` (plan 33): never-rules from CLAUDE.md,
//! AGENTS.md, GEMINI.md and rules files, as enforced user packs.
//!
//! This module holds the clap surface and the types the submodules share.
// The shared types and the extraction are used by tasks 2 to 7; until they
// land, only the tests use them. Remove this allow when the last task does.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;
use saiifeguard::pack::RuleWhere;
use saiifeguard::pathrule::RuleAccess;

mod confirm;
pub mod extract;
mod list;
mod llm;
mod propose;
mod store;
mod sync;

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// Propose rules from these files and confirm each one.
    Import {
        files: Vec<PathBuf>,
        #[arg(long)]
        llm: bool,
        #[arg(long, value_name = "SLUG")]
        name: Option<String>,
    },
    /// Follow changes to the imported files.
    ///
    /// Only the pack(s) named by the global `--pack <ID>` when given.
    Sync {
        #[arg(long)]
        llm: bool,
    },
    /// List the rules, where they apply and what is not enforced (the default).
    List {
        #[arg(long)]
        json: bool,
    },
}

/// One line of a source file, pinned by the hash of its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLine {
    pub line: u32,
    pub text: String,
    pub line_sha256: String,
}

/// What a candidate line names. `Command` holds the words of a command
/// prefix; `Path` a path or glob and the access it is denied for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Command(Vec<String>),
    Path {
        glob: String,
        access: RuleAccess,
    },
    /// A span with control, bidi or format characters (the sanitized text):
    /// never proposed, listed as not enforced.
    Rejected(String),
}

/// A never-line and what it names. No targets: a judgement line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub src: SourceLine,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Rules,
    Llm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdRule {
    pub pattern: String,
    pub whole_segment: bool,
    pub peeled_wrappers: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalKind {
    Command {
        words: Vec<String>,
        rules: Vec<CmdRule>,
        help_carve_out: bool,
    },
    Path {
        globs: Vec<String>,
        access: RuleAccess,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub src: SourceLine,
    pub kind: ProposalKind,
    pub reason: String,
    pub block: Vec<String>,
    pub allow: Vec<String>,
    pub broad: Option<String>,
    pub host_hint: bool,
    pub origin: Origin,
}

/// A proposal that failed its own examples: listed, never offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unverified {
    pub src: SourceLine,
    pub why: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Enforce,
    Ask,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decided {
    pub p: Proposal,
    pub choice: Choice,
    pub where_: RuleWhere,
}

/// The stub for the actions later tasks fill.
fn todo_unavailable(action: &str) -> ExitCode {
    eprintln!("saiife: rules {action} is not built yet");
    ExitCode::from(1)
}

/// `packs` is the global `--pack` list: `sync` follows only those packs.
pub fn run(config: Option<PathBuf>, packs: Vec<String>, action: Option<RulesAction>) -> ExitCode {
    match action.unwrap_or(RulesAction::List { json: false }) {
        RulesAction::Import { files, llm, name } => import(config, files, llm, name),
        RulesAction::Sync { llm } => sync(config, packs, llm),
        RulesAction::List { .. } => todo_unavailable("list"),
    }
}

/// The files `import` looks for when none is named (D6).
const DEFAULT_FILES: [&str; 3] = ["CLAUDE.md", "AGENTS.md", "GEMINI.md"];

/// Why `import` stopped: the exit code (1 stopped or refused, 2 bad input)
/// and the message.
struct Stop(u8, String);

fn shown(p: &Path) -> String {
    extract::clean(&p.display().to_string())
}

/// `saiife rules import`: one pack per file, written only after every
/// question is answered and the packs load with it, for host and box.
fn import(
    config: Option<PathBuf>,
    files: Vec<PathBuf>,
    llm: bool,
    name: Option<String>,
) -> ExitCode {
    let stop = |Stop(code, m): Stop| {
        eprintln!("saiife: {m}");
        ExitCode::from(code)
    };
    // 1. The target.
    let target = match crate::broker::resolve_here(config.as_deref()) {
        Ok(t) => t,
        Err(e) => return stop(Stop(1, extract::clean(&e))),
    };
    let cwd = std::env::current_dir().ok();
    let project = cwd
        .as_deref()
        .and_then(saiife_agents::config::find_project_root);
    // 2. The files.
    let files = if files.is_empty() {
        let root = project.clone().or_else(|| cwd.clone()).unwrap_or_default();
        let found: Vec<PathBuf> = DEFAULT_FILES
            .iter()
            .map(|n| root.join(n))
            .filter(|p| std::fs::symlink_metadata(p).is_ok())
            .collect();
        if found.is_empty() {
            return stop(Stop(
                2,
                format!(
                    "no {} in {}; name the rules file",
                    DEFAULT_FILES.join(", "),
                    shown(&root)
                ),
            ));
        }
        found
    } else {
        files
    };
    if name.is_some() && files.len() > 1 {
        return stop(Stop(2, "--name names one pack; give one file".into()));
    }
    let vars = crate::paths::path_vars(cwd.as_deref(), project.as_deref());
    for f in &files {
        if let Err(s) = import_one(&target, f, name.as_deref(), llm, &vars) {
            return stop(s);
        }
    }
    ExitCode::SUCCESS
}

/// The opt-in LLM pass (`--llm`) over the judgement lines: the one place it
/// joins the import. Each verified answer becomes an offered proposal and
/// its line leaves `judgement`; a rule that fails its checks is listed as
/// unverified. Any failure of the pass itself is one warning, and the
/// import goes on with what the rules found.
fn llm_pass(
    llm: bool,
    file_name: &str,
    vars: &saiifeguard::canon::PathVars,
    props: &mut Vec<Proposal>,
    unverified: &mut Vec<Unverified>,
    judgement: &mut Vec<SourceLine>,
) {
    use std::io::Write as _;
    if !llm || judgement.is_empty() {
        return;
    }
    let skip = |msg: &str| {
        crate::warn(&format!(
            "warning: {}; continuing without the LLM pass",
            extract::clean(msg)
        ));
    };
    let _ = writeln!(
        std::io::stderr(),
        "sending {} lines of {} to claude -p (your Claude Code login)",
        judgement.len(),
        extract::clean(file_name)
    );
    let sent: Vec<u32> = judgement.iter().map(|j| j.line).collect();
    let answer = match llm::run_claude(judgement, llm::timeout()) {
        Ok(a) => a,
        Err(e) => return skip(&e),
    };
    let rules = match llm::parse(&answer, &sent) {
        Ok(r) => r,
        Err(e) => return skip(&e),
    };
    let mut done = Vec::new();
    for (rule, status) in rules {
        let Some(line) = judgement.iter().find(|j| j.line == rule.line()).cloned() else {
            crate::warn(&format!(
                "warning: llm: a rule names line {}, which was not sent; dropped",
                rule.line()
            ));
            continue;
        };
        match status.and_then(|()| llm::to_proposal(&rule, &line, file_name, vars)) {
            Ok(p) => props.push(p),
            Err(why) => unverified.push(Unverified {
                src: line.clone(),
                why: format!("llm: {}", extract::clean(&why)),
            }),
        }
        done.push(line.line);
    }
    judgement.retain(|j| !done.contains(&j.line));
}

/// `file` as an absolute path, the one an import is known by: its directory
/// resolved (so `../p/CLAUDE.md` and `/p/CLAUDE.md` are one source), its
/// last component kept as is (a symlink there is refused when it is read).
fn source_path(file: &Path) -> std::io::Result<PathBuf> {
    let abs = std::path::absolute(file)?;
    #[cfg(unix)]
    if let (Some(dir), Some(name)) = (abs.parent(), abs.file_name()) {
        return Ok(std::fs::canonicalize(dir)?.join(name));
    }
    Ok(abs)
}

fn import_one(
    target: &crate::broker::Target,
    file: &Path,
    name: Option<&str>,
    llm: bool,
    vars: &saiifeguard::canon::PathVars,
) -> Result<(), Stop> {
    use saiifeguard::canon::PathStyle;
    use saiifeguard::profile::Profile;
    use saiifeguard::userpack::{load_user_packs, view, UnenforcedWhy, UserSrc};

    let abs = source_path(file).map_err(|e| Stop(2, format!("{}: {e}", shown(file))))?;
    match std::fs::symlink_metadata(&abs) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Stop(2, format!("{}: no such file", shown(&abs))))
        }
        _ => {}
    }
    let abs_text = abs.display().to_string();
    let file_name = abs
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| abs_text.clone());
    let id = store::pack_id(&abs, name).map_err(|e| Stop(2, e))?;
    let dir = store::packs_dir(target);

    // 3. A source already imported is synced, not imported again.
    let existing = saiife_policy::userpacks::read_user_packs(&dir, &mut Vec::new())
        .map_err(|e| Stop(1, extract::clean(&format!("user pack {e}"))))?;
    for e in &existing {
        if let Ok(v) = view(&e.text) {
            if v.import.as_ref().is_some_and(|i| i.file == abs_text) {
                return Err(Stop(
                    1,
                    format!(
                        "{} is already imported as {}; use saiife rules sync",
                        shown(&abs),
                        extract::clean(&v.id)
                    ),
                ));
            }
        }
    }
    store::check_writable(&dir).map_err(|e| Stop(1, extract::clean(&e)))?;

    // 4. The source. 5. The never-lines.
    let (text, sha) =
        store::read_source(&abs).map_err(|e| Stop(1, format!("{}: {}", shown(&abs), e)))?;
    let cands = extract::candidates(&text);
    // 6. Proposals that pass their own examples (and the LLM pass).
    let (mut props, mut unverified, mut judgement) =
        propose::proposals_for(&cands, &file_name, vars);
    llm_pass(
        llm,
        &file_name,
        vars,
        &mut props,
        &mut unverified,
        &mut judgement,
    );

    // 7. The table, then one question per proposal.
    outln!("{}", shown(&abs));
    print!("{}", confirm::table(&props, &unverified, &judgement));
    let repropose = |src: &SourceLine, t: Target| repropose(src, t, &file_name, vars);
    let stdin = std::io::stdin();
    let decided = confirm::confirm(
        props,
        target.is_locked(),
        &mut stdin.lock(),
        &mut std::io::stderr(),
        &repropose,
    )
    .map_err(|confirm::Eof| Stop(1, "stopped before the last rule; nothing written".into()))?;
    if decided.iter().all(|d| d.choice == Choice::Skip) {
        outln!("no rule confirmed; nothing written");
        return Ok(());
    }

    // 8. The pack.
    let pack = store::render(&store::NewPack {
        id: id.clone(),
        file: abs_text,
        file_sha256: sha,
        decided,
        unverified,
        judgement,
    });
    // 9. Every user pack with the new one must load, for host and box, or
    // nothing is written (a broken pack would deny or fail open later).
    let new_path = dir.join(format!("{id}.toml")).display().to_string();
    let refuse = |m: String| Stop(1, format!("{}; nothing written", extract::clean(&m)));
    if existing.len() + 1 > saiife_policy::userpacks::MAX_USER_PACKS {
        return Err(refuse(format!(
            "{} pack files; at most {}",
            existing.len() + 1,
            saiife_policy::userpacks::MAX_USER_PACKS
        )));
    }
    let bytes = existing.iter().map(|e| e.text.len()).sum::<usize>() + pack.len();
    if bytes > saiife_policy::userpacks::MAX_USER_PACK_BYTES {
        return Err(refuse(format!(
            "pack files would total more than {} KiB",
            saiife_policy::userpacks::MAX_USER_PACK_BYTES / 1024
        )));
    }
    let mut srcs: Vec<UserSrc> = existing
        .iter()
        .map(|e| UserSrc {
            source: &e.path,
            text: &e.text,
        })
        .collect();
    srcs.push(UserSrc {
        source: &new_path,
        text: &pack,
    });
    for profile in [Profile::Host, Profile::Box] {
        load_user_packs(&srcs, PathStyle::host(), profile).map_err(|e| refuse(e.to_string()))?;
    }

    // 10. Write. 11. Say what was written.
    let path = store::write_pack(&dir, &id, &pack, target.is_locked()).map_err(|e| Stop(1, e))?;
    let v = view(&pack).map_err(|e| Stop(1, extract::clean(&e.to_string())))?;
    let ask = v.rules.iter().filter(|r| r.ask).count();
    let why = |w: UnenforcedWhy| v.unenforced.iter().filter(|u| u.why == w).count();
    outln!(
        "wrote {}: {} rules ({ask} ask), {} not enforced ({} judgement, {} skipped, {} unverified)",
        shown(&path),
        v.rules.len(),
        v.unenforced.len(),
        why(UnenforcedWhy::Judgement),
        why(UnenforcedWhy::Skipped),
        why(UnenforcedWhy::Unverified)
    );
    if target.is_locked() && ask > 0 {
        outln!("next: saiife policy reload");
    }
    Ok(())
}

/// An edited answer in the confirm loop: one new target for `src`.
fn repropose(
    src: &SourceLine,
    t: Target,
    file_name: &str,
    vars: &saiifeguard::canon::PathVars,
) -> Result<Proposal, String> {
    let c = Candidate {
        src: src.clone(),
        targets: vec![t],
    };
    let mut p = propose::propose(&c, file_name, Origin::Rules)
        .into_iter()
        .next()
        .ok_or_else(|| "no rule for that".to_string())?;
    propose::verify(&mut p, vars)?;
    Ok(p)
}

/// `saiife rules sync`: each imported pack follows its source file (D7).
fn sync(config: Option<PathBuf>, packs: Vec<String>, llm: bool) -> ExitCode {
    let stop = |Stop(code, m): Stop| {
        eprintln!("saiife: {m}");
        ExitCode::from(code)
    };
    let target = match crate::broker::resolve_here(config.as_deref()) {
        Ok(t) => t,
        Err(e) => return stop(Stop(1, extract::clean(&e))),
    };
    let cwd = std::env::current_dir().ok();
    let project = cwd
        .as_deref()
        .and_then(saiife_agents::config::find_project_root);
    let vars = crate::paths::path_vars(cwd.as_deref(), project.as_deref());
    let dir = store::packs_dir(&target);
    let existing = match saiife_policy::userpacks::read_user_packs(&dir, &mut Vec::new()) {
        Ok(e) => e,
        Err(e) => return stop(Stop(1, extract::clean(&format!("user pack {e}")))),
    };
    // The imported packs, by id.
    let mut imported: Vec<String> = Vec::new();
    for e in &existing {
        if let Ok(v) = saiifeguard::userpack::view(&e.text) {
            if v.import.is_some() {
                imported.push(e.path.clone());
            }
        }
    }
    let chosen: Vec<String> = if packs.is_empty() {
        imported
    } else {
        let mut out = Vec::new();
        for id in &packs {
            match existing
                .iter()
                .find(|e| &e.id == id && imported.contains(&e.path))
            {
                Some(e) => out.push(e.path.clone()),
                None => {
                    return stop(Stop(
                        2,
                        format!(
                            "no imported pack {}; see saiife rules list",
                            extract::clean(id)
                        ),
                    ))
                }
            }
        }
        out
    };
    if chosen.is_empty() {
        outln!("no imported packs; nothing to sync");
        return ExitCode::SUCCESS;
    }
    let mut updated: Vec<String> = Vec::new();
    for path in chosen {
        if let Err(Stop(code, m)) = sync_one(&target, &dir, &path, llm, &vars, &mut updated) {
            if updated.is_empty() {
                return stop(Stop(code, m));
            }
            // Say what really happened: "nothing written" is no longer true.
            let reason = m.strip_suffix("; nothing written").unwrap_or(&m);
            return stop(Stop(
                code,
                format!(
                    "{reason}; earlier packs updated: {}; this and later packs unchanged",
                    updated.join(", ")
                ),
            ));
        }
    }
    ExitCode::SUCCESS
}

fn sync_one(
    target: &crate::broker::Target,
    dir: &Path,
    path: &str,
    llm: bool,
    vars: &saiifeguard::canon::PathVars,
    updated: &mut Vec<String>,
) -> Result<(), Stop> {
    use saiifeguard::canon::PathStyle;
    use saiifeguard::profile::Profile;
    use saiifeguard::userpack::{load_user_packs, view, UnenforcedWhy, UserSrc};

    // Read again: the pack may have changed since the directory was listed.
    let existing = saiife_policy::userpacks::read_user_packs(dir, &mut Vec::new())
        .map_err(|e| Stop(1, extract::clean(&format!("user pack {e}"))))?;
    let me = existing
        .iter()
        .find(|e| e.path == path)
        .ok_or_else(|| Stop(1, format!("{} is gone", extract::clean(path))))?;
    let v = view(&me.text).map_err(|e| Stop(1, extract::clean(&e.to_string())))?;
    let import = v
        .import
        .clone()
        .ok_or_else(|| Stop(1, "pack has no [import]".into()))?;
    let id = extract::clean(&v.id);
    let src_path = Path::new(&import.file);
    let shown_src = shown(src_path);
    let file_name = src_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| import.file.clone());

    // 1. The source.
    if matches!(std::fs::symlink_metadata(src_path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        crate::warn(&format!("warning: {shown_src}: source gone; rules kept"));
        return Ok(());
    }
    let (text, sha) = store::read_source(src_path)
        .map_err(|e| Stop(1, format!("{shown_src}: {}", extract::clean(&e))))?;
    outln!("{id}: {shown_src}");
    if sha == import.sha256 {
        outln!("unchanged");
        return Ok(());
    }

    // 2. What changed.
    let plan = sync::plan(&v, &text);
    for (h, from, to) in &plan.moved {
        let _ = h;
        outln!("~ line {from} \u{2192} {to}");
    }
    for (s, t, k) in &plan.gone {
        outln!(
            "- line {} gone: \"{}\" ({k} rules)",
            s.line,
            extract::clean(t)
        );
    }
    let lines =
        |c: &Candidate| outln!("+ line {}: \"{}\"", c.src.line, extract::clean(&c.src.text));
    for c in &plan.new {
        lines(c);
    }

    // 3. The gone lines that carry rules: keep (default) or remove.
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let eof = |confirm::Eof| {
        Stop(
            1,
            "stopped before the last question; nothing written".into(),
        )
    };
    let mut removed: Vec<String> = Vec::new();
    for (s, t, k) in plan.gone.iter().filter(|(_, _, k)| *k > 0) {
        loop {
            eprint!(
                "line {} is gone: \"{}\" ({k} rules). keep? [K/r]: ",
                s.line,
                extract::clean(t)
            );
            let a = confirm::read_answer(&mut input)
                .map_err(eof)?
                .to_lowercase();
            match a.as_str() {
                "" | "k" => break,
                "r" => {
                    removed.push(s.line_sha256.clone());
                    break;
                }
                _ => eprintln!("answer k or r"),
            }
        }
    }

    // 4. The new lines: proposed and confirmed like an import.
    let (mut props, mut unverified, mut judgement) =
        propose::proposals_for(&plan.new, &file_name, vars);
    llm_pass(
        llm,
        &file_name,
        vars,
        &mut props,
        &mut unverified,
        &mut judgement,
    );
    let mut decided = Vec::new();
    if !(props.is_empty() && unverified.is_empty() && judgement.is_empty()) {
        print!("{}", confirm::table(&props, &unverified, &judgement));
        let rp = |src: &SourceLine, t: Target| repropose(src, t, &file_name, vars);
        decided = confirm::confirm(
            props,
            target.is_locked(),
            &mut input,
            &mut std::io::stderr(),
            &rp,
        )
        .map_err(eof)?;
    }
    let mut unenforced: Vec<(SourceLine, UnenforcedWhy)> = Vec::new();
    for u in &unverified {
        unenforced.push((u.src.clone(), UnenforcedWhy::Unverified));
    }
    for j in &judgement {
        unenforced.push((j.clone(), UnenforcedWhy::Judgement));
    }

    // 5. The new pack text; every pack with it must load, host and box.
    let new_text = sync::apply(&me.text, &plan, &removed, &decided, &unenforced)
        .map_err(|e| Stop(1, format!("{}; nothing written", extract::clean(&e))))?;
    let nv = view(&new_text).map_err(|e| Stop(1, extract::clean(&e.to_string())))?;
    let remove_pack = nv.rules.is_empty();
    let refuse = |m: String| Stop(1, format!("{}; nothing written", extract::clean(&m)));
    let bytes = existing
        .iter()
        .filter(|e| e.path != path)
        .map(|e| e.text.len())
        .sum::<usize>()
        + if remove_pack { 0 } else { new_text.len() };
    if bytes > saiife_policy::userpacks::MAX_USER_PACK_BYTES {
        return Err(refuse(format!(
            "pack files would total more than {} KiB",
            saiife_policy::userpacks::MAX_USER_PACK_BYTES / 1024
        )));
    }
    let mut srcs: Vec<UserSrc> = existing
        .iter()
        .filter(|e| e.path != path)
        .map(|e| UserSrc {
            source: &e.path,
            text: &e.text,
        })
        .collect();
    if !remove_pack {
        srcs.push(UserSrc {
            source: path,
            text: &new_text,
        });
    }
    for profile in [Profile::Host, Profile::Box] {
        load_user_packs(&srcs, PathStyle::host(), profile).map_err(|e| refuse(e.to_string()))?;
    }

    // 6. Write (or delete).
    let shown_pack = extract::clean(path);
    if remove_pack {
        std::fs::remove_file(path)
            .map_err(|e| Stop(1, format!("cannot remove {shown_pack}: {e}")))?;
        updated.push(id.clone());
        outln!("{id} removed: no rules left");
        return Ok(());
    }
    store::replace_pack(Path::new(path), &new_text, target.is_locked()).map_err(|e| Stop(1, e))?;
    updated.push(id.clone());
    let ask = nv.rules.iter().filter(|r| r.ask).count();
    outln!(
        "updated {shown_pack}: {} rules ({ask} ask), {} not enforced",
        nv.rules.len(),
        nv.unenforced.len()
    );
    if target.is_locked() && ask > 0 {
        outln!("next: saiife policy reload");
    }
    Ok(())
}
