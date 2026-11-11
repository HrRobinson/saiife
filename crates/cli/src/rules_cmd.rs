//! `saiife rules import | sync | list` (plan 33): never-rules from CLAUDE.md,
//! AGENTS.md, GEMINI.md and rules files, as enforced user packs.
//!
//! This module holds the clap surface and the types the submodules share.
// The shared types and the extraction are used by tasks 2 to 7; until they
// land, only the tests use them. Remove this allow when the last task does.
#![allow(dead_code)]

use std::path::PathBuf;
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
    Sync {
        #[arg(long, value_name = "PACK_ID")]
        pack: Option<String>,
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

pub fn run(config: Option<PathBuf>, action: Option<RulesAction>) -> ExitCode {
    let _ = &config;
    match action.unwrap_or(RulesAction::List { json: false }) {
        RulesAction::Import { .. } => todo_unavailable("import"),
        RulesAction::Sync { .. } => todo_unavailable("sync"),
        RulesAction::List { .. } => todo_unavailable("list"),
    }
}
