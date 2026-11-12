//! `saiife rules list`: the rules, where they apply and what is not enforced
//! (plan 33 task 7). Everything derived from a pack or a source file is
//! printed through `extract::clean` in text mode; JSON is escaped by serde.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use saiifeguard::canon::PathStyle;
use saiifeguard::pathrule::RuleAccess;
use saiifeguard::profile::Profile;
use saiifeguard::userpack::{
    box_status, broad_findings, load_user_packs, view, Broad, ImportRef, RuleKind, UnenforcedWhy,
    UserPackView, UserRuleView, UserSrc,
};

use super::extract::clean;
use super::store;

/// How an imported source compares with the hash recorded at import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    Same,
    Changed,
    Gone,
}

impl SourceState {
    fn word(self) -> &'static str {
        match self {
            SourceState::Same => "same",
            SourceState::Changed => "changed",
            SourceState::Gone => "gone",
        }
    }
}

/// The state of `import`'s source file on disk. A file that cannot be read
/// (a symlink, too big, not UTF-8) counts as changed: sync reports why.
pub fn source_state(import: &ImportRef) -> SourceState {
    let path = Path::new(&import.file);
    match store::read_source(path) {
        Ok((_, sha)) if sha == import.sha256 => SourceState::Same,
        Ok(_) => SourceState::Changed,
        Err(_) => match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => SourceState::Gone,
            _ => SourceState::Changed,
        },
    }
}

fn access(a: RuleAccess) -> &'static str {
    match a {
        RuleAccess::Read => "read",
        RuleAccess::Write => "write",
        RuleAccess::Any => "any",
        RuleAccess::Replace => "replace",
        RuleAccess::Content => "content",
    }
}

fn kind(r: &UserRuleView) -> String {
    match &r.kind {
        RuleKind::Allow => "allow".into(),
        RuleKind::Deny => "deny".into(),
        RuleKind::AllowPath(a) => format!("allow path ({})", access(*a)),
        RuleKind::DenyPath(a) => format!("deny path ({})", access(*a)),
    }
}

fn where_(r: &UserRuleView) -> &'static str {
    match r.where_ {
        saiifeguard::pack::RuleWhere::Host => "host",
        saiifeguard::pack::RuleWhere::Everywhere => "everywhere",
    }
}

fn host_status(r: &UserRuleView, locked: bool) -> &'static str {
    match (r.ask, locked) {
        (false, _) => "enforced",
        (true, true) => "ask",
        (true, false) => "ask (denied: approvals need locked mode)",
    }
}

fn why(w: UnenforcedWhy) -> &'static str {
    match w {
        UnenforcedWhy::Judgement => "judgement",
        UnenforcedWhy::Skipped => "skipped",
        UnenforcedWhy::Unverified => "unverified",
    }
}

/// `<file name>:<line>`: the pack header carries the full path.
fn at(file: &str, line: u32) -> String {
    let name = Path::new(file)
        .file_name()
        .map_or_else(|| file.to_string(), |n| n.to_string_lossy().into_owned());
    format!("{}:{line}", clean(&name))
}

pub fn render_list(
    packs: &[(PathBuf, UserPackView, Vec<Broad>)],
    locked: bool,
    source_state: &dyn Fn(&ImportRef) -> SourceState,
) -> String {
    let mut out = String::new();
    for (_, v, broad) in packs {
        let (file, note) = match &v.import {
            Some(i) => (
                clean(&i.file),
                match source_state(i) {
                    SourceState::Same => "",
                    SourceState::Changed => " [source changed: run saiife rules sync]",
                    SourceState::Gone => " [source gone]",
                },
            ),
            None => ("-".to_string(), ""),
        };
        let ask = v.rules.iter().filter(|r| r.ask).count();
        out.push_str(&format!(
            "{}  {file}  {} rules ({ask} ask), {} not enforced{note}\n",
            clean(&v.id),
            v.rules.len(),
            v.unenforced.len()
        ));
        for r in &v.rules {
            let src = r
                .source
                .as_ref()
                .map(|s| at(&s.file, s.line))
                .unwrap_or_else(|| "-".into());
            out.push_str(&format!(
                "  {}  {}  {}  where={}  host: {}  box: {}  {src}\n",
                clean(r.id.as_deref().unwrap_or("-")),
                kind(r),
                clean(&r.text),
                where_(r),
                host_status(r, locked),
                box_status(r).label(),
            ));
            if matches!(r.kind, RuleKind::Deny | RuleKind::DenyPath(_)) {
                if let Some(b) = broad.iter().find(|b| b.rule == r.text) {
                    out.push_str(&format!("  BROAD: blocks everyday {}\n", clean(&b.example)));
                }
            }
        }
        for u in &v.unenforced {
            out.push_str(&format!(
                "  not enforced: {} {}: \"{}\"\n",
                at(&u.source.file, u.source.line),
                why(u.why),
                clean(&u.text)
            ));
        }
    }
    out
}

fn render_json(
    packs: &[(PathBuf, UserPackView, Vec<Broad>)],
    locked: bool,
    source_state: &dyn Fn(&ImportRef) -> SourceState,
) -> String {
    use serde_json::json;
    let packs: Vec<_> = packs
        .iter()
        .map(|(path, v, _)| {
            let import = v.import.as_ref().map(|i| {
                json!({"file": i.file, "sha256": i.sha256, "state": source_state(i).word()})
            });
            let rules: Vec<_> = v
                .rules
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "kind": kind(r),
                        "text": r.text,
                        "where": where_(r),
                        "mode": if r.ask { "ask" } else { "enforce" },
                        "host": host_status(r, locked),
                        "box": box_status(r).label(),
                        "source": r.source.as_ref().map(|s| json!({"file": s.file, "line": s.line})),
                    })
                })
                .collect();
            let unenforced: Vec<_> = v
                .unenforced
                .iter()
                .map(|u| json!({"line": u.source.line, "why": why(u.why), "text": u.text}))
                .collect();
            json!({
                "id": v.id,
                "path": path.display().to_string(),
                "import": import,
                "rules": rules,
                "unenforced": unenforced,
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({ "packs": packs })).unwrap_or_default()
}

/// `saiife rules` / `saiife rules list [--json]`.
pub fn run(config: Option<PathBuf>, json: bool) -> ExitCode {
    let target = match crate::broker::resolve_here(config.as_deref()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("saiife: {}", clean(&e));
            return ExitCode::from(1);
        }
    };
    let dir = store::packs_dir(&target);
    let files = match saiife_policy::userpacks::read_user_packs(&dir, &mut Vec::new()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("saiife: {}", clean(&format!("user pack {e}")));
            return ExitCode::from(1);
        }
    };
    // Broad rules need the compiled packs; a pack set that does not load is
    // said once, and the listing goes on without the BROAD marks.
    let srcs: Vec<UserSrc> = files
        .iter()
        .map(|f| UserSrc {
            source: &f.path,
            text: &f.text,
        })
        .collect();
    let compiled = load_user_packs(&srcs, PathStyle::host(), Profile::Host).unwrap_or_else(|e| {
        crate::warn(&format!(
            "warning: {}; BROAD marks left out",
            clean(&e.to_string())
        ));
        Vec::new()
    });
    let mut packs = Vec::new();
    for f in &files {
        match view(&f.text) {
            Ok(v) => {
                let broad = compiled
                    .iter()
                    .find(|p| p.id == v.id)
                    .map(broad_findings)
                    .unwrap_or_default();
                packs.push((PathBuf::from(&f.path), v, broad));
            }
            Err(e) => crate::warn(&format!(
                "warning: {}: {}; skipped",
                clean(&f.path),
                clean(&e.to_string())
            )),
        }
    }
    if json {
        outln!("{}", render_json(&packs, target.is_locked(), &source_state));
    } else if packs.is_empty() {
        outln!("no user packs; saiife rules import <file> makes one");
    } else {
        out!("{}", render_list(&packs, target.is_locked(), &source_state));
    }
    ExitCode::SUCCESS
}
