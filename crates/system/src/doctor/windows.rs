//! `saiife doctor` on Windows (plan 19b Task 8, W10, W14, W15, W24, W26, W27, W28): how an
//! admin learns whether the lock is really on. Every read goes through [`Host`] and
//! `std::fs`, so Linux tests drive all of it against `Layout::under_for(tmp,
//! Platform::Windows)`. Nothing here has run on Windows outside CI's `locked-windows`.
//!
//! A check that passes wrongly is the worst thing here, so what cannot be read is never a
//! pass: from an elevated token it is a failure, and from a plain shell it is "not checked",
//! with a warning that keeps the exit code off 0.
//!
//! [`Host`]: crate::host::Host

use super::common::{
    agent_label, allow_server_warnings, claude_installed, cloud_sts, config_valid, cosign_asker,
    cosign_listen, cosign_rejudge, entry_fingerprint, fmt_version, forwarding_detail, health_check,
    hooks_no_verdict, hooks_rejudge_denied, install_record, mcp_restrictions, parse_agent_version,
    proxy_check, DaemonStatus, EnvLayer, CLAUDE_MIN, NOT_INSTALLED,
};
use super::report::{Check, Status};
use super::Ctx;
use crate::binary::{authenticode_verdict, inspect_pe, Authenticode, PE_IMPORT_ALLOWLIST};
use crate::layout::*;
use crate::supported::{check_supported, Support, NOT_ELEVATED, REG_PROFILE_LIST};
use crate::winacl::{
    actual_file_ok, actual_ok, ancestor_ok, expected, protected_ok, refuse_reparse,
};
use crate::winservice::{ServiceOp, ServiceSpec, ServiceState};
use saiife_agents::claude::{self, HklmPolicy};
use saiife_policy::installed::{FileKind, Installed, VaultKeyMode};
use saiife_win::sddl::{parse, Sd};
use saiife_win::sid::{service_sid, ADMINISTRATORS};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

const NOT_CHECKED: &str = "not checked (run from an elevated terminal)";
/// The key of the UAC values, below HKLM.
const REG_UAC: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
/// Largest binary read (256 MiB), as on Linux and macOS.
const MAX_BINARY: u64 = 256 * 1024 * 1024;
/// Largest other file fingerprinted (16 MiB), as on Linux and macOS.
const MAX_FINGERPRINT: u64 = 16 * 1024 * 1024;
const VAULT_KEY_LEN: u64 = 32;
const HEALTH_WAIT: Duration = Duration::from_secs(2);
const VERSION_WAIT: Duration = Duration::from_secs(5);
const AUDIT_KEY_LEN: u64 = 32;

/// What the lock does not do yet. It is said on every locked run, and fails nothing: an admin
/// who reads only PASS lines must still have been told.
const PREVIEW_LIMITS: &str = "Windows locked mode is a preview: a process running as the \
     agent's user can end a hook with TerminateProcess(hook, 0), which the agent reads as \
     allow. Since plan 20 the daemon then writes a no_verdict hook record and doctor warns \
     (hooks.no-verdict): recorded, not prevented (measured in CI on Windows Server 2022 and \
     2025). Codex \
     and Gemini CLI on Windows are preview too, and every Windows lock label is unverified; \
     see docs/windows.md#locked-mode";

/// `locked.preview` for an install whose agents have no co-signer (plan 21): their hook
/// can still be ended with exit 0. `{agents}` names them; `{claude}` is empty, or says
/// why Claude Code is no preview.
fn preview_for(agents: &str, claude: &str) -> String {
    format!(
        "Windows locked mode is a preview for {agents}: a process of the agent's user can \
         end their hook with exit 0, which the agent reads as allow (recorded, not \
         prevented; measured in CI on Windows Server 2022 and 2025).{claude} Every Windows \
         lock label is unverified; see docs/windows.md#locked-mode"
    )
}

/// `locked.preview` with only Claude Code installed and its co-signer whole.
const CLAUDE_JUDGED: &str =
    "Windows locked mode for Claude Code: each call is judged by the hook and by the service";

/// Said after [`PREVIEW_LIMITS`] when all that keeps Claude Code a preview is that no
/// `agent-version` check showed its version.
const CLAUDE_VERSION_UNCHECKED: &str = " Claude Code leaves the preview only once its \
     version is shown to be new enough: run saiife doctor --user <name> as that user, from \
     a plain shell";

/// Whether Claude Code is shown to call the co-signer, which `locked.preview` needs before
/// it says Claude Code is no preview (whole-branch review, F2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CosignWhole {
    /// `cosign.listen`, `cosign.rejudge`, `cosign.asker` and `agents.claude.policy` pass
    /// (the drop-in carries the HTTP hook, and no HKLM policy overrides or weakens it),
    /// and every `agent-version` check that ran passed, at least one of them.
    Yes,
    /// All of that but the version: no `agent-version` check ran (an elevated doctor,
    /// or no agent user named), or none found Claude Code.
    VersionUnchecked,
    No,
}

/// [`CosignWhole`] from the checks it rests on. `versions` are the `agent-version`
/// checks of this run.
fn cosign_whole(cosign: &[Check], policy: Option<&Check>, versions: &[&Check]) -> CosignWhole {
    let pass = |c: &Check| c.status == Status::Pass;
    if !cosign.iter().all(pass) || !policy.is_some_and(pass) {
        return CosignWhole::No;
    }
    if versions
        .iter()
        .any(|c| matches!(c.status, Status::Fail | Status::Warn))
    {
        return CosignWhole::No;
    }
    if versions.iter().any(|c| pass(c)) {
        CosignWhole::Yes
    } else {
        CosignWhole::VersionUnchecked
    }
}

/// `locked.preview` (plan 21 Task 6). Claude Code leaves the preview only when
/// `cosign_whole` is [`CosignWhole::Yes`]. Until then it is the plan 19b text, Info. Codex
/// and Gemini CLI have no co-signer, so they stay preview, named when installed.
fn locked_preview(installed: Option<&Installed>, cosign_whole: CosignWhole) -> Check {
    const ID: &str = "locked.preview";
    const TITLE: &str = "Windows locked mode";
    let has = |name: &str| installed.is_some_and(|i| i.agents.iter().any(|a| a.agent == name));
    let claude = has("claude");
    match cosign_whole {
        _ if !claude => {}
        CosignWhole::Yes => {}
        CosignWhole::No => return Check::new(ID, Status::Info, TITLE, PREVIEW_LIMITS),
        CosignWhole::VersionUnchecked => {
            return Check::new(
                ID,
                Status::Info,
                TITLE,
                format!("{PREVIEW_LIMITS}.{CLAUDE_VERSION_UNCHECKED}"),
            )
        }
    }
    let others: Vec<&str> = [("codex", "Codex"), ("gemini", "Gemini CLI")]
        .into_iter()
        .filter(|(name, _)| has(name))
        .map(|(_, label)| label)
        .collect();
    match (claude, others.is_empty()) {
        (true, true) => Check::new(ID, Status::Pass, TITLE, CLAUDE_JUDGED),
        // No agent at all (or an unreadable record): nothing is shown to be whole.
        (false, true) => Check::new(ID, Status::Info, TITLE, PREVIEW_LIMITS),
        (_, false) => {
            let note = if claude {
                " Claude Code is not: each call is judged by the hook and by the service."
            } else {
                ""
            };
            Check::new(
                ID,
                Status::Info,
                TITLE,
                preview_for(&others.join(" and "), note),
            )
        }
    }
}

/// The Linux checks with no Windows form in this version. Said, so that their absence does
/// not read as "fine".
const NOT_PORTED: &str = "not checked on Windows in this version: plaintext credentials, \
     model logins, leftover project hooks, hard links in the install's tree, and who is in the \
     local group saiife-audit, who may read the audit log";

/// W27: the local groups whose members can become an administrator, by SID. Their names are
/// localized, so a name says nothing.
const ADMIN_LIKE: [(&str, &str); 4] = [
    ("S-1-5-32-551", "Backup Operators"),
    ("S-1-5-32-549", "Server Operators"),
    ("S-1-5-32-578", "Hyper-V Administrators"),
    ("S-1-5-32-548", "Account Operators"),
];

/// Where user-level installers put the agents, below the profile.
const USER_BIN_DIRS: [&str; 2] = [r".local\bin", r"AppData\Roaming\npm"];
const AGENT_PROGRAMS: [&str; 3] = ["claude", "codex", "gemini"];
const PROGRAM_SUFFIXES: [&str; 4] = ["", ".exe", ".cmd", ".ps1"];

pub fn checks(ctx: &Ctx) -> Vec<Check> {
    let mut out = vec![supported(ctx)];
    if !ctx.locked() {
        out.push(record_when_unlocked(ctx));
        return out;
    }
    // `daemon.health`, the `cosign.*` checks and the `hooks.*` counts read one `status`
    // answer, and so does `locked.preview`: Claude Code leaves the preview only when its
    // co-signer is whole, its machine policy carries it, and its version is new enough.
    let status: DaemonStatus = ctx
        .host
        .daemon_status(HEALTH_WAIT)
        .map_err(|e| e.to_string());
    let claude = claude_installed(ctx);
    let cosign = [
        cosign_listen(claude, &status),
        cosign_rejudge(claude, &status),
        cosign_asker(claude, &status, Platform::Windows),
    ];
    let policy = ctx
        .installed
        .as_ref()
        .filter(|i| lists_claude(i))
        .map(|_| claude_policy(ctx));
    let user_checks = users(ctx);
    let versions: Vec<&Check> = user_checks
        .iter()
        .filter(|c| c.id.ends_with(".agent-version"))
        .collect();
    out.push(locked_preview(
        ctx.installed.as_ref(),
        cosign_whole(&cosign, policy.as_ref(), &versions),
    ));
    if !ctx.as_root {
        out.push(Check::new(
            "doctor.elevation",
            Status::Warn,
            "not elevated",
            format!(
                "only part of the lock can be read from this shell, and a clean result would \
                 say nothing about the rest: {NOT_ELEVATED}"
            ),
        ));
    }
    out.push(install_record(ctx));
    out.push(config_valid(ctx));
    out.push(files_acl(ctx));
    if let Some(i) = &ctx.installed {
        out.push(files_installed(ctx, i));
    }
    out.push(files_binary(ctx));
    out.extend(files_package(ctx));
    out.push(keys(ctx));
    out.push(daemon_unit(ctx));
    out.push(health_check(status.clone()));
    out.extend(cosign);
    out.push(hooks_no_verdict(&status));
    out.push(hooks_rejudge_denied(claude, &status));
    if let Some(i) = &ctx.installed {
        if i.agents.is_empty() {
            out.push(Check::new("agents", Status::Warn, "agents", NO_AGENTS));
        }
        out.extend(i.agents.iter().map(|a| agent_label(ctx, &a.agent)));
    }
    out.extend(policy);
    out.extend(allow_server_warnings(ctx));
    out.push(Check::new(
        "mcp.landlock",
        Status::Info,
        "MCP gateway: Linux only in this version",
        "",
    ));
    if let Some(i) = &ctx.installed {
        out.extend(mcp_restrictions(ctx, i));
        if lists_claude(i) {
            out.push(claude_allowlist(ctx, i));
        }
    }
    if let Ok(p) = &ctx.config {
        out.extend(cloud_sts(&p.config));
    }
    if let Some(i) = &ctx.installed {
        out.push(vault_key(ctx, i));
    }
    out.push(Check::new(
        "peer.pidfd",
        Status::Info,
        "peer identity",
        "named pipe; caller identity from its token (the pid is used for attribution only)",
    ));
    out.push(Check::new(
        "reauth",
        Status::Info,
        "re-authentication",
        WIN_SAME_USER_OFF,
    ));
    out.push(Check::new(
        "disk.encryption",
        Status::Info,
        "disk encryption",
        "see docs/windows.md#disk-encryption for BitLocker",
    ));
    out.push(Check::new(
        "forwarding",
        Status::Info,
        "audit forwarding",
        forwarding_detail(&ctx.config),
    ));
    out.extend(user_checks);
    out.push(Check::new(
        "host.not-ported",
        Status::Info,
        "other host checks",
        NOT_PORTED,
    ));
    out
}

fn lists_claude(i: &Installed) -> bool {
    i.agents.iter().any(|a| a.agent == "claude")
}

// ---------------------------------------------------------------- the machine

/// The build and the edition. Whether the caller is elevated is no fact about the machine
/// (W26), and has its own line.
fn supported(ctx: &Ctx) -> Check {
    const TITLE: &str = "supported system";
    match check_supported(ctx.layout, ctx.host) {
        Support::Supported { distro, .. } => {
            Check::new("system.supported", Status::Pass, TITLE, distro)
        }
        // Without locked mode installed, an unsupported machine is only a fact: developer
        // mode does not need it.
        Support::Refused(why) => Check::new(
            "system.supported",
            if ctx.locked() {
                Status::Fail
            } else {
                Status::Info
            },
            TITLE,
            format!("locked mode is not supported here: {why}"),
        ),
    }
}

/// No record, so this reads as developer mode, unless the service says otherwise: a record
/// removed by hand must not make a host with hooks on it look like one without.
fn record_when_unlocked(ctx: &Ctx) -> Check {
    const TITLE: &str = "install record";
    match ctx.host.service(ServiceOp::Query) {
        Ok(ServiceState::Missing) => {
            Check::new("install.record", Status::Info, TITLE, NOT_INSTALLED)
        }
        Err(e) => Check::new(
            "install.record",
            Status::Warn,
            TITLE,
            format!("{NOT_INSTALLED}, but the service manager could not say so too: {e}"),
        ),
        Ok(_) => Check::new(
            "install.record",
            Status::Fail,
            TITLE,
            format!(
                "the service {WIN_SERVICE} exists and {} does not: run saiife system install again",
                ctx.layout.logical(INSTALLED)
            ),
        ),
    }
}

// ---------------------------------------------------------------- a tally

/// Offenders and what the caller could not look at, for one check.
#[derive(Default)]
struct Tally {
    bad: Vec<String>,
    unchecked: Vec<String>,
}

impl Tally {
    fn bad(&mut self, what: String) {
        if !self.bad.contains(&what) {
            self.bad.push(what);
        }
    }

    fn unchecked(&mut self, what: &str) {
        if !self.unchecked.iter().any(|u| u == what) {
            self.unchecked.push(what.to_string());
        }
    }

    /// An error reading `shown`: from a plain shell a denial is only "not checked". From an
    /// elevated token nothing excuses it.
    fn error(&mut self, ctx: &Ctx, shown: &str, doing: &str, e: &io::Error) {
        if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root {
            self.unchecked(shown);
        } else {
            self.bad(format!("{shown}: cannot {doing}: {e}"));
        }
    }

    /// Fail naming every offender; else Info when something could not be looked at; else
    /// Pass. An Info counts for nothing in the exit code, which `doctor.elevation` covers.
    fn check(self, id: &str, title: &str) -> Check {
        if !self.bad.is_empty() {
            Check::new(id, Status::Fail, title, self.bad.join("; "))
        } else if !self.unchecked.is_empty() {
            Check::new(
                id,
                Status::Info,
                title,
                format!("{NOT_CHECKED}: {}", self.unchecked.join(", ")),
            )
        } else {
            Check::new(id, Status::Pass, title, "")
        }
    }
}

// ---------------------------------------------------------------- reading files

/// The parent of `C:\a\b`, as text: a Windows path means nothing to `Path` on Linux.
fn parent_of(logical: &str) -> &str {
    logical.rsplit_once('\\').map_or(logical, |(p, _)| p)
}

/// Whether `logical` lies strictly below `dir`, as Windows compares names.
fn below(logical: &str, dir: &str) -> bool {
    let (l, d) = (logical.to_ascii_lowercase(), dir.to_ascii_lowercase());
    l.starts_with(&format!("{d}\\"))
}

fn at_or_below(logical: &str, dir: &str) -> bool {
    logical.eq_ignore_ascii_case(dir) || below(logical, dir)
}

/// The plain file at `path`, at most `max` bytes. A reparse point is an error.
fn read_plain(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)?;
    refuse_reparse(path, &meta)?;
    let oversized = || io::Error::new(io::ErrorKind::InvalidData, "file too large");
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if meta.len() > max {
        return Err(oversized());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(oversized());
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------------------------------------------------------------- files.acl

/// The W14 checks, reading only.
struct Acl<'c, 'a> {
    ctx: &'c Ctx<'a>,
    /// The SID of `saiife-audit`, once it is known to be a group of this machine.
    audit: Option<String>,
    t: Tally,
}

impl Acl<'_, '_> {
    fn at(&mut self, logical: &str) -> Option<PathBuf> {
        match self.ctx.layout.try_at(Path::new(logical)) {
            Ok(p) => Some(p),
            Err(e) => {
                self.t.bad(format!("{logical}: {e}"));
                None
            }
        }
    }

    /// The parsed descriptor of `real`. A reparse point is an error, from the host.
    fn read(&mut self, logical: &str, real: &Path) -> Option<Sd> {
        let text = match self.ctx.host.get_sddl(real) {
            Ok(t) => t,
            Err(e) => {
                self.t.error(self.ctx, logical, "read its descriptor", &e);
                return None;
            }
        };
        match parse(&text) {
            Ok(sd) => Some(sd),
            Err(e) => {
                self.t.bad(format!("{logical}: its descriptor {text}: {e}"));
                None
            }
        }
    }

    /// Whether `sd` is what `logical` must have. A path with a row must read as its row,
    /// except below `etc`, by the ruling: what an admin puts there reads back with inherited
    /// entries, so there the test is who can really write. With no row, it is that too.
    fn verdict(&self, logical: &str, real: &Path, is_dir: bool, sd: &Sd) -> Result<(), String> {
        let layout = self.ctx.layout;
        let names_audit_group = at_or_below(logical, layout.logical(AUDIT_DIR))
            || at_or_below(logical, parent_of(layout.logical(DAEMON_LOG)));
        let Some(audit) = self
            .audit
            .as_deref()
            .or((!names_audit_group).then_some(ADMINISTRATORS))
        else {
            // The group's absence is reported once. What else is wrong here still shows.
            let service = service_sid(WIN_SERVICE);
            return protected_ok(sd, &[service.as_str()]);
        };
        let Some(want) = expected(layout, real, audit)? else {
            return protected_ok(sd, &[]);
        };
        let exact = if is_dir {
            actual_ok(&want, sd)
        } else {
            actual_file_ok(&want, sd)
        };
        if exact.is_err() && below(logical, layout.logical(ETC_DIR)) {
            return protected_ok(sd, &[]);
        }
        exact
    }

    fn entry(&mut self, logical: &str, real: &Path, is_dir: bool) {
        let Some(sd) = self.read(logical, real) else {
            return;
        };
        if let Err(e) = self.verdict(logical, real, is_dir, &sd) {
            self.t.bad(format!("{logical}: {e}"));
        }
    }

    /// Everything from `logical` down. The tree's rows cover all of it, and an entry with no
    /// row must still be protected: nothing in there is passed over.
    fn tree(&mut self, logical: &str, real: &Path) {
        let meta = match std::fs::symlink_metadata(real) {
            Ok(m) => m,
            // Gone since it was listed, or [`Acl::required`] reports it.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(e) => return self.t.error(self.ctx, logical, "look at it", &e),
        };
        if refuse_reparse(real, &meta).is_err() {
            return self.t.bad(format!("{logical}: is a reparse point"));
        }
        self.entry(logical, real, meta.is_dir());
        if !meta.is_dir() {
            return;
        }
        let entries = match std::fs::read_dir(real) {
            Ok(rd) => rd,
            Err(e) => return self.t.error(self.ctx, logical, "list it", &e),
        };
        let mut names: Vec<std::ffi::OsString> = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => names.push(entry.file_name()),
                Err(e) => self.t.error(self.ctx, logical, "list it", &e),
            }
        }
        names.sort();
        for name in names {
            let child = format!("{logical}\\{}", name.to_string_lossy());
            // Held with no sharing while install runs its doctor; it goes with the handle.
            if !child.eq_ignore_ascii_case(WIN_INSTALL_LOCK) {
                self.tree(&child, &real.join(&name));
            }
        }
    }

    /// `logical` must exist, as a directory or a file. Its descriptor is the walk's matter.
    fn required(&mut self, logical: &str, is_dir: bool) {
        let Some(real) = self.at(logical) else {
            return;
        };
        match std::fs::symlink_metadata(&real) {
            Ok(m) if m.is_dir() != is_dir => self.t.bad(format!(
                "{logical}: is not a {}",
                if is_dir { "directory" } else { "regular file" }
            )),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.t.bad(format!("{logical}: missing"));
            }
            Err(e) => self.t.error(self.ctx, logical, "look at it", &e),
        }
    }

    fn ancestor(&mut self, logical: &str) {
        let Some(real) = self.at(logical) else {
            return;
        };
        if let Some(sd) = self.read(logical, &real) {
            if let Err(e) = ancestor_ok(&sd) {
                self.t.bad(format!("{logical}: {e}"));
            }
        }
    }

    /// A dir of an agent's managed file. One install made is on its row. One already there
    /// stays as it was, and must be fit to rely on: a leaf, where the agent reads files,
    /// must let no one else add one (`protected_ok`, by the ruling on W14); another
    /// product's parent needs only that its entries cannot be replaced (`ancestor_ok`).
    fn managed_dir(&mut self, i: &Installed, logical: &str, leaf: bool) {
        let Some(real) = self.at(logical) else {
            return;
        };
        self.required(logical, true);
        if !real.is_dir() {
            return;
        }
        if i.dirs.iter().any(|d| d == Path::new(logical)) {
            return self.entry(logical, &real, true);
        }
        let Some(sd) = self.read(logical, &real) else {
            return;
        };
        let fit = if leaf {
            protected_ok(&sd, &[])
        } else {
            ancestor_ok(&sd)
        };
        if let Err(e) = fit {
            self.t.bad(format!("{logical}: {e}"));
        }
    }

    fn managed_file(&mut self, logical: &str) {
        self.required(logical, false);
        if let Some(real) = self.at(logical) {
            if real.is_file() {
                self.entry(logical, &real, false);
            }
        }
    }

    fn agent(&mut self, i: &Installed, agent: &str) {
        let layout = self.ctx.layout;
        match agent {
            "claude" => {
                let leaf = layout.logical(CLAUDE_MANAGED_DIR);
                self.ancestor(parent_of(parent_of(leaf)));
                self.managed_dir(i, parent_of(leaf), true);
                self.managed_dir(i, leaf, true);
                self.managed_file(layout.logical(CLAUDE_MANAGED));
                self.managed_file(layout.logical(CLAUDE_MCP));
            }
            "codex" => {
                let leaf = layout.logical(CODEX_DIR);
                self.managed_dir(i, parent_of(leaf), false);
                self.managed_dir(i, leaf, true);
                self.managed_file(layout.logical(CODEX_REQUIREMENTS));
            }
            "gemini" => {
                self.managed_dir(i, layout.logical(GEMINI_DIR), true);
                self.managed_file(layout.logical(GEMINI_SETTINGS));
            }
            // `agents.<name>.label` warns of it.
            _ => {}
        }
    }

    /// Everything from a moved audit dir down: no row covers it, so each entry is asked who
    /// may write it.
    fn moved_tree(&mut self, logical: &str, real: &Path) {
        let meta = match std::fs::symlink_metadata(real) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(e) => return self.t.error(self.ctx, logical, "look at it", &e),
        };
        if refuse_reparse(real, &meta).is_err() {
            return self.t.bad(format!("{logical}: is a reparse point"));
        }
        if let Some(sd) = self.read(logical, real) {
            let service = service_sid(WIN_SERVICE);
            if let Err(e) = protected_ok(&sd, &[service.as_str()]) {
                self.t.bad(format!("{logical}: {e}"));
            }
        }
        if !meta.is_dir() {
            return;
        }
        let entries = match std::fs::read_dir(real) {
            Ok(rd) => rd,
            Err(e) => return self.t.error(self.ctx, logical, "list it", &e),
        };
        let mut names = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => names.push(entry.file_name()),
                Err(e) => self.t.error(self.ctx, logical, "list it", &e),
            }
        }
        names.sort();
        for name in names {
            let child = format!("{logical}\\{}", name.to_string_lossy());
            self.moved_tree(&child, &real.join(&name));
        }
    }

    /// An audit dir the config moved out of the tree has no row, and must still be the
    /// service's and the admins' alone: it, what is in it, and the folders above it.
    fn moved_audit_dir(&mut self) {
        let layout = self.ctx.layout;
        let Ok(p) = &self.ctx.config else {
            return;
        };
        let dir = &p.config.audit.dir;
        let shown = dir.display().to_string();
        // The Linux default stands in on a Linux test build, and a test tree's config names
        // the dir below its root.
        if dir == Path::new(AUDIT_DIR)
            || dir == &layout.at(AUDIT_DIR)
            || shown.eq_ignore_ascii_case(layout.logical(AUDIT_DIR))
        {
            return;
        }
        let Some((drive, names)) = layout.windows_location(dir) else {
            return self
                .t
                .bad(format!("{shown}: not plainly a path of this machine"));
        };
        let logical = format!("{drive}:\\{}", names.join("\\"));
        let Some(real) = self.at(&logical) else {
            return;
        };
        self.required(&logical, true);
        let mut above = parent_of(&logical);
        while above.len() > 2 {
            self.ancestor(above);
            above = parent_of(above);
        }
        self.ancestor(&format!("{above}\\"));
        self.moved_tree(&logical, &real);
    }
}

/// `saiife-audit` must be a group of this machine: its row hands it the audit log.
fn audit_group_sid(ctx: &Ctx, t: &mut Tally) -> Option<String> {
    let name = ctx.layout.audit_group();
    match ctx.host.lookup_local_group(name) {
        Ok(Some(sid)) if sid.starts_with("S-1-5-21-") => return Some(sid),
        Ok(Some(sid)) => t.bad(format!(
            "local group {name}: {sid} is no group of this machine"
        )),
        Ok(None) => t.bad(format!("local group {name} does not exist")),
        Err(e) => t.bad(format!("local group {name}: {e}")),
    }
    None
}

/// W14: every path of the table has its descriptor, what is below it too, and the folders
/// above pass `ancestor_ok`.
fn files_acl(ctx: &Ctx) -> Check {
    let layout = ctx.layout;
    let mut t = Tally::default();
    let audit = audit_group_sid(ctx, &mut t);
    let mut acl = Acl { ctx, audit, t };
    let root = layout.logical(OPT_DIR);
    acl.ancestor(parent_of(root));
    // `C:` is `C:\`.
    acl.ancestor(&format!("{}\\", parent_of(parent_of(root))));
    for dir in [
        root,
        layout.logical(BIN_DIR),
        layout.logical(ETC_DIR),
        layout.logical(POLICY_D),
        layout.logical(STATE_DIR),
        layout.logical(KEYS_DIR),
        layout.logical(LOG_DIR),
        layout.logical(AUDIT_DIR),
        parent_of(layout.logical(DAEMON_LOG)),
    ] {
        acl.required(dir, true);
    }
    for file in [BINARY, CONFIG, INSTALLED, VAULT_KEY, AUDIT_KEY, DAEMON_LOG] {
        acl.required(layout.logical(file), false);
    }
    if let Some(real) = acl.at(root) {
        acl.tree(root, &real);
    }
    if let Some(i) = &ctx.installed {
        for a in &i.agents {
            acl.agent(i, &a.agent);
        }
    }
    acl.moved_audit_dir();
    acl.t.check("files.acl", "descriptors of the install")
}

// ---------------------------------------------------------------- files

/// The file listed as `listed` still exists, and when `want` is given, still has that hash.
fn verify_file(ctx: &Ctx, listed: &Path, want: Option<&str>, max: u64, t: &mut Tally) {
    let shown = listed.display().to_string();
    let at = match ctx.layout.try_at(listed) {
        Ok(p) => p,
        Err(e) => return t.bad(format!("{shown}: {e}")),
    };
    let Some(want) = want else {
        match std::fs::symlink_metadata(&at) {
            Ok(m) if refuse_reparse(&at, &m).is_err() => {
                t.bad(format!("{shown}: is a reparse point"));
            }
            Ok(m) if !m.is_file() => t.bad(format!("{shown}: is not a regular file")),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => t.bad(format!("{shown}: missing")),
            Err(e) => t.error(ctx, &shown, "look at it", &e),
        }
        return;
    };
    match read_plain(&at, max) {
        Ok(bytes) if sha256_hex(&bytes) == want => {}
        Ok(_) => t.bad(format!("{shown}: changed since install")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => t.bad(format!("{shown}: missing")),
        Err(e) => t.error(ctx, &shown, "read it", &e),
    }
}

fn files_installed(ctx: &Ctx, i: &Installed) -> Check {
    let mut t = Tally::default();
    for f in &i.files {
        let (want, max) = match f.kind {
            // No file is behind it: `daemon.unit` compares the service itself.
            FileKind::Service => continue,
            // The admin edits the config: `config.valid` reads it. The vault key has no
            // digest on record: `vault.key` and `files.acl` check it.
            FileKind::Config | FileKind::VaultKey => (None, MAX_FINGERPRINT),
            FileKind::Binary => (f.sha256.as_deref(), MAX_BINARY),
            _ => (f.sha256.as_deref(), MAX_FINGERPRINT),
        };
        if want.is_none() && matches!(f.kind, FileKind::Binary | FileKind::Managed) {
            // Listed before it was written, and never finished.
            t.bad(format!("{}: no fingerprint on record", f.path.display()));
            continue;
        }
        verify_file(ctx, &f.path, want, max, &mut t);
    }
    for a in &i.agents {
        if a.whole_file {
            verify_file(ctx, &a.path, Some(&a.sha256), MAX_FINGERPRINT, &mut t);
            continue;
        }
        let shown = a.path.display().to_string();
        let at = match ctx.layout.try_at(&a.path) {
            Ok(p) => p,
            Err(e) => {
                t.bad(format!("{shown}: {e}"));
                continue;
            }
        };
        match entry_fingerprint(&a.agent, &at) {
            Ok(Some(got)) if got == a.sha256 => {}
            Ok(Some(_)) => t.bad(format!("{shown}: changed since install")),
            Ok(None) => t.bad(format!("{shown}: missing")),
            Err(e) => t.bad(format!("{shown}: {e}")),
        }
    }
    t.check("files.installed", "installed files")
}

/// W28. `inspect_pe`'s problems fail and its warnings warn. A file that says it is signed
/// must be valid by Windows' own reading: a refusal fails, and no answer warns, since the
/// signature was then seen neither good nor bad.
///
/// Read in this process, with `WinVerifyTrust`, not by asking PowerShell. An elevated doctor
/// holds the full token, and the caller's user controls `HKCU`: clearing PowerShell's
/// environment does not reach the CLR's settings there or the user's own module folder, so
/// an agent running as that user could have run its code with that token.
fn files_binary(ctx: &Ctx) -> Check {
    const ID: &str = "files.binary";
    const TITLE: &str = "installed binary";
    let shown = ctx.layout.logical(BINARY);
    let fail = |d: String| Check::new(ID, Status::Fail, TITLE, d);
    let bytes = match read_plain(&ctx.layout.at(BINARY), MAX_BINARY) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            return Check::new(ID, Status::Info, TITLE, format!("{NOT_CHECKED}: {shown}"))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return fail(format!("{shown}: missing")),
        Err(e) => return fail(format!("{shown}: cannot read: {e}")),
    };
    let info = match inspect_pe(&bytes) {
        Ok(i) => i,
        Err(e) => return fail(format!("{shown}: not a PE executable ({e})")),
    };
    let (problems, mut notes) = pe_findings(&info, cfg!(debug_assertions));
    if !problems.is_empty() {
        return fail(format!("{shown}: {}", problems.join("; ")));
    }
    if info.signed {
        match ctx
            .host
            .authenticode_status(&ctx.layout.at(BINARY))
            .map(authenticode_verdict)
        {
            Ok(Authenticode::Valid) => {}
            Ok(Authenticode::Rejected(why)) => {
                return fail(format!(
                    "{shown}: Windows refuses its Authenticode signature: {why}"
                ))
            }
            Ok(Authenticode::Unknown(why)) => {
                notes.push(format!("could not read its Authenticode signature: {why}"))
            }
            Err(e) => notes.push(format!("could not read its Authenticode signature: {e}")),
        }
    }
    if notes.is_empty() {
        let detail = if info.signed {
            "release build, DLLs from System32 only, Authenticode Valid"
        } else {
            "release build, DLLs from System32 only"
        };
        Check::new(ID, Status::Pass, TITLE, detail)
    } else {
        Check::new(
            ID,
            Status::Warn,
            TITLE,
            format!("{shown}: {}", notes.join("; ")),
        )
    }
}

/// `files.binary`'s problems (they fail) and notes (they warn) for `info`.
///
/// A test build (debug assertions on) fails when the doctor is a release build: a real
/// install never has one. A doctor that is itself a test build is the `ci-locked` binary
/// that `locked-windows` installs with `--allow-test-build`, and there it warns, as
/// doctor's Linux and macOS check always does. Only a test build carries the test seams,
/// so a release doctor cannot be talked into the warning.
fn pe_findings(
    info: &crate::binary::PeInfo,
    doctor_is_test_build: bool,
) -> (Vec<String>, Vec<String>) {
    use crate::binary::{PeInfo, Profile};
    let tolerated = doctor_is_test_build && info.profile == Profile::DebugAssertions;
    if !tolerated {
        return (info.problems(PE_IMPORT_ALLOWLIST), info.warnings());
    }
    let as_release = PeInfo {
        profile: Profile::Release,
        ..info.clone()
    };
    let mut notes = vec![
        "test build installed: debug assertions are on (the SAIIFE_EVAL_FAULT test seam can \
         hang the guard); install the release build"
            .to_string(),
    ];
    notes.extend(as_release.warnings());
    (as_release.problems(PE_IMPORT_ALLOWLIST), notes)
}

/// What is unsafe about `logical` as a place SYSTEM runs a program from.
fn package_path_problem(
    ctx: &Ctx,
    logical: &str,
    fit: &dyn Fn(&Sd) -> Result<(), String>,
) -> Option<String> {
    let judged = ctx
        .layout
        .try_at(Path::new(logical))
        .map_err(|e| e.to_string())
        .and_then(|real| ctx.host.get_sddl(&real).map_err(|e| e.to_string()))
        .and_then(|text| parse(&text))
        .and_then(|sd| fit(&sd));
    judged.err().map(|e| format!("{logical}: {e}"))
}

/// The MSI's copy (W20), when there is one: it must be what install copied, and SYSTEM runs
/// it on the next package install. So only admins may change it, or its folder, and the
/// folders above must not let anyone replace that. As `package_path_problem` on Linux, a
/// finding warns. Only a copy that is not there drops the check.
fn files_package(ctx: &Ctx) -> Option<Check> {
    const ID: &str = "files.package";
    const TITLE: &str = "package binary";
    let package = ctx.layout.at(PACKAGE_BINARY);
    let shown = ctx.layout.logical(PACKAGE_BINARY);
    let warn = |d: String| Some(Check::new(ID, Status::Warn, TITLE, d));
    match std::fs::symlink_metadata(&package) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => return warn(format!("{shown}: cannot look at it: {e}")),
    }
    let own = |sd: &Sd| protected_ok(sd, &[]);
    let folder = parent_of(shown);
    let above = parent_of(folder);
    let drive = format!("{}\\", parent_of(above));
    let problems: Vec<String> = [
        package_path_problem(ctx, shown, &own),
        package_path_problem(ctx, folder, &own),
        package_path_problem(ctx, above, &ancestor_ok),
        package_path_problem(ctx, &drive, &ancestor_ok),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !problems.is_empty() {
        return warn(format!(
            "{}: SYSTEM runs this copy on the next package install",
            problems.join("; ")
        ));
    }
    let read = |p: &Path| read_plain(p, MAX_BINARY).map(|b| sha256_hex(&b));
    match (read(&package), read(&ctx.layout.at(BINARY))) {
        (Ok(a), Ok(b)) if a == b => Some(Check::new(ID, Status::Pass, TITLE, "")),
        (Ok(_), Ok(_)) => warn(format!(
            "the package's {shown} differs from {}: install the package again",
            ctx.layout.logical(BINARY)
        )),
        (Err(e), _) | (_, Err(e)) => warn(format!("cannot compare: {e}")),
    }
}

/// The key the daemon signs the audit log with, which it makes at its first start. Who may
/// write it is `files.acl`'s matter; this says it is there and whole.
fn keys(ctx: &Ctx) -> Check {
    const ID: &str = "keys";
    const TITLE: &str = "audit signing key";
    let shown = ctx.layout.logical(AUDIT_KEY);
    let real = ctx.layout.at(AUDIT_KEY);
    let fail = |d: String| Check::new(ID, Status::Fail, TITLE, d);
    match std::fs::symlink_metadata(&real) {
        Ok(m) if refuse_reparse(&real, &m).is_err() => fail(format!("{shown}: is a reparse point")),
        Ok(m) if !m.is_file() => fail(format!("{shown}: is not a regular file")),
        Ok(m) if m.len() != AUDIT_KEY_LEN => fail(format!(
            "{shown}: is {} bytes, must be {AUDIT_KEY_LEN} bytes",
            m.len()
        )),
        Ok(_) => Check::new(ID, Status::Pass, TITLE, ""),
        Err(e) if e.kind() == io::ErrorKind::NotFound => fail(format!("{shown}: missing")),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            Check::new(ID, Status::Info, TITLE, format!("{NOT_CHECKED}: {shown}"))
        }
        Err(e) => fail(format!("{shown}: cannot look at it: {e}")),
    }
}

// ---------------------------------------------------------------- the service

/// The DACL part of what `sc.exe sdshow` prints: W10 sets no SACL, the service has one
/// Windows gave it, and `parse` refuses a SACL on purpose.
fn dacl_part(text: &str) -> &str {
    let text = text.trim();
    let mut depth = 0usize;
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'S' if depth == 0 && text[i..].starts_with("S:") => return &text[..i],
            _ => {}
        }
    }
    text
}

/// What differs between W10 and the service as it is, one phrase per field. Windows ignores
/// the case of a path and of an account, and may hand them back in another. The descriptor
/// compares parsed: W10's text is not necessarily what Windows prints.
fn service_drift(want: &ServiceSpec, live: &ServiceSpec) -> Vec<String> {
    let mut out = Vec::new();
    let mut differs = |field: &str, got: String, expected: String| {
        out.push(format!("{field} reads {got}, expected {expected}"));
    };
    if live.display != want.display {
        differs("display name", live.display.clone(), want.display.clone());
    }
    let (got_binary, want_binary) = (
        live.binary.to_string_lossy().into_owned(),
        want.binary.to_string_lossy().into_owned(),
    );
    if !got_binary.eq_ignore_ascii_case(&want_binary) {
        differs("binary", got_binary, want_binary);
    }
    if live.args != want.args {
        differs(
            "arguments",
            format!("{:?}", live.args),
            format!("{:?}", want.args),
        );
    }
    if !live.account.eq_ignore_ascii_case(&want.account) {
        differs("account", live.account.clone(), want.account.clone());
    }
    if live.start != want.start {
        differs(
            "start",
            format!("{:?}", live.start),
            format!("{:?}", want.start),
        );
    }
    if live.sid_type != want.sid_type {
        differs(
            "SID type",
            format!("{:?}", live.sid_type),
            format!("{:?}", want.sid_type),
        );
    }
    if live.failure != want.failure {
        differs(
            "failure policy",
            format!("{:?}", live.failure),
            format!("{:?}", want.failure),
        );
    }
    match (parse(dacl_part(&live.sddl)), parse(&want.sddl)) {
        (Ok(a), Ok(b)) if a == b => {}
        _ => differs(
            "its descriptor",
            live.sddl.trim().to_string(),
            want.sddl.clone(),
        ),
    }
    out
}

/// W10: the record's fingerprint is this build's spec, the service as it is now is that spec,
/// and it is running. The fingerprint alone would say nothing of a service someone changed
/// after install, which is what this is here to see.
fn daemon_unit(ctx: &Ctx) -> Check {
    const ID: &str = "daemon.unit";
    const TITLE: &str = "saiifed service";
    let fail = |d: String| Check::new(ID, Status::Fail, TITLE, d);
    let want = ServiceSpec::saiifed(ctx.layout);
    let recorded = ctx
        .installed
        .as_ref()
        .and_then(|i| i.files.iter().find(|f| f.kind == FileKind::Service))
        .and_then(|f| f.sha256.clone());
    let again = "run saiife system install again";
    match recorded {
        None => return fail(format!("no fingerprint of the service on record: {again}")),
        Some(r) if r != want.fingerprint() => {
            return fail(format!(
                "the fingerprint on record is not this build's service: {again}"
            ))
        }
        Some(_) => {}
    }
    let live = match ctx.host.service_spec() {
        Ok(Some(l)) => l,
        Ok(None) => return fail(format!("the service {WIN_SERVICE} does not exist: {again}")),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            return Check::new(ID, Status::Info, TITLE, NOT_CHECKED)
        }
        Err(e) => return fail(format!("the service could not be read: {e}")),
    };
    let drift = service_drift(&want, &live);
    if !drift.is_empty() {
        return fail(format!(
            "the service differs from its install: {}; {again}",
            drift.join("; ")
        ));
    }
    match ctx.host.service(ServiceOp::Query) {
        Ok(ServiceState::Running { .. }) => Check::new(ID, Status::Pass, TITLE, "running"),
        Ok(other) => fail(format!("{WIN_SERVICE} is not running: {other:?}")),
        Err(e) => fail(format!("{WIN_SERVICE}: {e}")),
    }
}

// ---------------------------------------------------------------- the vault key

/// W15: what is said must be what is there, so the Info line is earned by reading it.
fn vault_key(ctx: &Ctx, i: &Installed) -> Check {
    const ID: &str = "vault.key";
    const TITLE: &str = "vault key";
    let fail = |d: String| Check::new(ID, Status::Fail, TITLE, d);
    let info = |d: String| Check::new(ID, Status::Info, TITLE, d);
    if i.vault_key != VaultKeyMode::DaemonFile {
        return fail("the install record holds a vault key mode of another OS".to_string());
    }
    let says = format!("daemon key file, readable only by {WIN_DAEMON_ACCOUNT}");
    let shown = ctx.layout.logical(VAULT_KEY);
    let real = ctx.layout.at(VAULT_KEY);
    let text = match ctx.host.get_sddl(&real) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            return info(format!("{says}: {NOT_CHECKED}"))
        }
        Err(e) => return fail(format!("{shown}: cannot read its descriptor: {e}")),
    };
    let row = match expected(ctx.layout, &real, ADMINISTRATORS) {
        Ok(Some(row)) => row,
        Ok(None) => return fail(format!("{shown}: no row in the ACL table")),
        Err(e) => return fail(format!("{shown}: {e}")),
    };
    if let Err(e) = parse(&text).and_then(|sd| actual_file_ok(&row, &sd)) {
        return fail(format!("{shown}: {e}"));
    }
    match std::fs::symlink_metadata(&real) {
        Ok(m) if m.len() != VAULT_KEY_LEN => fail(format!(
            "{shown}: is {} bytes, must be {VAULT_KEY_LEN} bytes",
            m.len()
        )),
        Ok(_) => info(says),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            info(format!("{says}: {NOT_CHECKED}"))
        }
        Err(e) => fail(format!("{shown}: {e}")),
    }
}

// ---------------------------------------------------------------- Claude Code

/// W24: HKLM's settings win over saiife's drop-in unless they say to merge. The read fails
/// closed (`hklm_policy_live`). Before that, the drop-in itself must carry the co-signer
/// HTTP hook and its URL allow-list (plan 20): one from an older saiife does not.
fn claude_policy(ctx: &Ctx) -> Check {
    const ID: &str = "agents.claude.policy";
    const TITLE: &str = "Claude Code machine policy";
    let drop_in = read_plain(&ctx.layout.at(CLAUDE_MANAGED), 1 << 20);
    if !drop_in.is_ok_and(|b| std::str::from_utf8(&b).is_ok_and(claude::carries_cosign)) {
        return Check::new(ID, Status::Fail, TITLE, claude::COSIGN_MISSING_TEXT);
    }
    match ctx.host.claude_hklm_policy() {
        HklmPolicy::Overrides => Check::new(ID, Status::Fail, TITLE, claude::HKLM_OVERRIDES_TEXT),
        HklmPolicy::Merge => Check::new(ID, Status::Pass, TITLE, "merged with saiife's drop-in"),
        HklmPolicy::Absent => Check::new(ID, Status::Pass, TITLE, ""),
        HklmPolicy::WeakensHooks => {
            Check::new(ID, Status::Fail, TITLE, claude::HKLM_WEAKENS_HOOKS_TEXT)
        }
    }
}

/// The Windows MCP drop-in: who may change it first, since a drop-in others can write pins
/// nothing (the hook's `claude_pin_ok` denies then), then that it says what policy says.
fn claude_allowlist(ctx: &Ctx, i: &Installed) -> Check {
    const ID: &str = "mcp.claude.allowlist";
    const TITLE: &str = "Claude Code MCP allowlist";
    const DRIFT: &str =
        "the Claude Code MCP allowlist differs from policy; run saiife system install again";
    let shown = ctx.layout.logical(CLAUDE_MCP);
    let at = ctx.layout.at(CLAUDE_MCP);
    let warn = |d: String| Check::new(ID, Status::Warn, DRIFT, d);
    match ctx.host.get_sddl(&at) {
        Ok(text) => {
            if let Err(e) = parse(&text).and_then(|sd| protected_ok(&sd, &[])) {
                return Check::new(
                    ID,
                    Status::Fail,
                    TITLE,
                    format!("{shown}: {e}: it pins the saiife MCP server, and pins nothing if others can change it"),
                );
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return warn(format!("{shown}: missing")),
        Err(e) => return warn(format!("{shown}: cannot read its descriptor: {e}")),
    }
    let Ok(p) = &ctx.config else {
        return Check::new(
            ID,
            Status::Info,
            TITLE,
            "not checked: the config does not load",
        );
    };
    let want = claude::managed_mcp_settings_for(true, &p.config.guard.mcp.allow_servers);
    let got = match read_plain(&at, 1 << 20) {
        Ok(g) => g,
        Err(e) => return warn(format!("{shown}: {e}")),
    };
    if got != want.as_bytes() {
        return warn(format!("{shown}: content differs from policy"));
    }
    let recorded = i.files.iter().find(|f| f.path == Path::new(shown));
    if recorded
        .and_then(|f| f.sha256.as_deref())
        .is_some_and(|sha| sha != sha256_hex(&got))
    {
        return warn(format!("{shown}: differs from its install record"));
    }
    Check::new(
        ID,
        Status::Pass,
        "Claude Code MCP allowlist matches policy",
        "",
    )
}

// ---------------------------------------------------------------- agent users

/// Each user a `[[scope]]` names, groups expanded, and a failure for a group that cannot be
/// listed: then the users checked may be partial.
fn scoped_names(ctx: &Ctx, out: &mut Vec<Check>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Ok(p) = &ctx.config else {
        return names;
    };
    for entry in p.config.scope.iter().flat_map(|s| &s.users) {
        let Some(group) = entry.strip_prefix("group:") else {
            names.insert(entry.clone());
            continue;
        };
        let id = format!("scope.group.{group}");
        let title = format!("members of group {group}");
        let members = ctx.host.group_members(group);
        let unnamed = members
            .as_ref()
            .is_some_and(|m| m.iter().any(|u| u.starts_with('<')));
        match members {
            Some(m) if !unnamed => names.extend(m),
            Some(_) => out.push(Check::new(
                id,
                Status::Fail,
                title,
                format!("group {group} has a member without a name, which cannot be checked"),
            )),
            None => out.push(Check::new(
                id,
                Status::Fail,
                title,
                format!("could not list members of group {group}"),
            )),
        }
    }
    names
}

fn users(ctx: &Ctx) -> Vec<Check> {
    let mut out = Vec::new();
    let names = match &ctx.opts.user {
        Some(u) => BTreeSet::from([u.clone()]),
        None if ctx.as_root => scoped_names(ctx, &mut out),
        None => BTreeSet::new(),
    };
    if names.is_empty() {
        out.push(Check::new(
            "users.none",
            Status::Warn,
            "agent users",
            "no agent user was checked, so W27 went unevaluated: an agent user who can become \
             an administrator would not show here. A [[scope]] names them, or use --user",
        ));
    }
    for name in &names {
        let id = |what: &str| format!("user.{name}.{what}");
        let title = format!("user {name} is known to this machine");
        let Some(sid) = ctx.host.lookup_sid(name) else {
            out.push(Check::new(
                id("passwd"),
                Status::Fail,
                title,
                format!("{name} is not a known user: saiife cannot check this user"),
            ));
            continue;
        };
        out.push(Check::new(id("passwd"), Status::Pass, title, ""));
        out.push(elevation(ctx, name, &sid, id("root")));
        out.push(agent_binaries(ctx, name, &sid, id("agent-binaries")));
        out.push(agent_version(ctx, name, &sid, id("agent-version")));
        if claude_installed(ctx) {
            out.push(proxy(ctx, &sid, id("proxy")));
        }
        out.push(Check::new(
            id("egress"),
            Status::Info,
            format!("egress rules for {name}"),
            "the egress recipe is Linux only",
        ));
    }
    out
}

/// W27. `ConsentPromptBehaviorAdmin = 1` with `PromptOnSecureDesktop = 1` asks an admin for
/// credentials on the secure desktop, and UAC must be on for that to mean anything: with
/// `EnableLUA = 0` every process of the user holds the full token and nothing prompts. A
/// value that cannot be read is no such policy.
fn elevation_needs_password(ctx: &Ctx) -> bool {
    let is = |value: &str, want: u32| ctx.host.reg_dword(REG_UAC, value) == Some(want);
    is("EnableLUA", 1) && is("ConsentPromptBehaviorAdmin", 1) && is("PromptOnSecureDesktop", 1)
}

/// The agent's user must not be able to become an administrator (W27, Review Focus 3).
/// Compared by SID, as group names are localized. What cannot be read counts as in the group.
fn elevation(ctx: &Ctx, name: &str, sid: &str, id: String) -> Check {
    const TITLE: &str = "no administrator rights without a password";
    let groups = match ctx.host.local_groups_of(name) {
        Ok(g) => g,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            return Check::new(
                id,
                Status::Warn,
                TITLE,
                format!("{NOT_CHECKED}: its groups"),
            )
        }
        Err(e) => {
            return Check::new(
                id,
                Status::Fail,
                TITLE,
                format!(
                "the local groups of {name} could not be read, so it may be an administrator: {e}"
            ),
            )
        }
    };
    let mut bad = Vec::new();
    let mut admin = false;
    for group in &groups {
        match ctx.host.lookup_sid(group) {
            None => bad.push(format!(
                "{name} is in group {group}, whose SID could not be read"
            )),
            Some(g) if g == ADMINISTRATORS => admin = true,
            Some(g) => {
                if let Some((_, known)) = ADMIN_LIKE.iter().find(|(s, _)| *s == g) {
                    bad.push(format!(
                        "{name} is in {known}, which is as good as an administrator"
                    ));
                }
            }
        }
    }
    // The built-in Administrator (RID 500) gets the full token at logon by default, whatever
    // the prompt for other admins says.
    let built_in = sid.starts_with("S-1-5-21-") && sid.ends_with("-500");
    if admin && (built_in || !elevation_needs_password(ctx)) {
        bad.push(format!(
            "agent user {name} is an administrator: UAC elevates it without a password"
        ));
    }
    if !bad.is_empty() {
        Check::new(id, Status::Fail, TITLE, bad.join("; "))
    } else if admin {
        Check::new(
            id,
            Status::Warn,
            TITLE,
            format!("agent user {name} is an administrator: elevation needs its password"),
        )
    } else {
        Check::new(id, Status::Pass, TITLE, "")
    }
}

/// Where Windows keeps the machine's environment variables, below HKLM.
pub(crate) const REG_MACHINE_ENV: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

/// The proxy Claude Code would use for the co-sign request (plan 20): the machine's
/// environment, then the `env` of the user's `.claude\settings.json`, which overwrites it.
/// Never this process's environment, which is the caller's.
fn proxy(ctx: &Ctx, sid: &str, id: String) -> Check {
    let mut layers = vec![EnvLayer::from_lookup(
        "the machine environment".into(),
        |k| ctx.host.reg_string(REG_MACHINE_ENV, k),
    )];
    let settings = profile_dir(ctx, sid)
        .and_then(|p| {
            ctx.layout
                .try_at(Path::new(&format!(r"{p}\.claude\settings.json")))
                .ok()
        })
        .and_then(|p| read_plain(&p, 1 << 20).ok());
    if let Some(b) = settings {
        layers.push(EnvLayer::from_settings(
            r"%USERPROFILE%\.claude\settings.json".into(),
            &b,
        ));
    }
    proxy_check(id, &layers)
}

/// The user's profile, from the registry by SID. Never from the environment, which is the
/// caller's and says nothing of another user. A profile that does not plainly name a folder
/// of this machine is `None`.
fn profile_dir(ctx: &Ctx, sid: &str) -> Option<String> {
    let key = format!(r"{REG_PROFILE_LIST}\{sid}");
    let value = ctx.host.reg_string(&key, "ProfileImagePath")?;
    const VARIABLE: &str = "%SystemDrive%";
    let value = match value.get(..VARIABLE.len()) {
        Some(head) if head.eq_ignore_ascii_case(VARIABLE) => {
            format!("C:{}", &value[VARIABLE.len()..])
        }
        _ => value,
    };
    (!value.contains('%') && ctx.layout.try_at(Path::new(&value)).is_ok()).then_some(value)
}

/// Why `logical` is no safe place for a program: someone other than an administrator may
/// change it. A descriptor that cannot be read is said too, and is not a pass.
fn change_risk(ctx: &Ctx, logical: &str, user: &str) -> Option<String> {
    let real = ctx.layout.try_at(Path::new(logical)).ok()?;
    let judged = ctx
        .host
        .get_sddl(&real)
        .map_err(|e| e.to_string())
        .and_then(|text| parse(&text))
        .and_then(|sd| protected_ok(&sd, &[]));
    judged.err().map(|e| {
        format!(
            "{logical} may be writable by {user} ({e}): the agent can patch itself and skip \
             hooks (install agents system-wide)"
        )
    })
}

fn agent_binaries(ctx: &Ctx, name: &str, sid: &str, id: String) -> Check {
    const TITLE: &str = "agent binaries not writable by the agent user";
    let Some(profile) = profile_dir(ctx, sid) else {
        return Check::new(
            id,
            Status::Info,
            TITLE,
            format!("the profile of {name} is not known: not scanned"),
        );
    };
    let mut found = Vec::new();
    let mut risks = Vec::new();
    for dir in USER_BIN_DIRS {
        let dir = format!(r"{profile}\{dir}");
        let mut any = false;
        // One line for a folder doctor may not read, not one per name in it.
        let mut denied = false;
        for program in AGENT_PROGRAMS {
            for suffix in PROGRAM_SUFFIXES {
                let logical = format!(r"{dir}\{program}{suffix}");
                let Ok(real) = ctx.layout.try_at(Path::new(&logical)) else {
                    continue;
                };
                match std::fs::symlink_metadata(&real) {
                    Ok(_) => {
                        any = true;
                        risks.extend(change_risk(ctx, &logical, name));
                        found.push(logical);
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) if !denied => {
                        denied = true;
                        risks.push(format!("{dir}: cannot look in it: {e}"));
                    }
                    Err(_) => {}
                }
            }
        }
        // Whoever may write the folder may swap what is in it.
        if any {
            risks.extend(change_risk(ctx, &dir, name));
        }
    }
    if !risks.is_empty() {
        Check::new(id, Status::Warn, TITLE, risks.join("; "))
    } else if found.is_empty() {
        Check::new(id, Status::Info, TITLE, "no agent binary found")
    } else {
        Check::new(id, Status::Pass, TITLE, found.join(", "))
    }
}

/// `claude.exe --version`, run only by the agent user itself from a plain shell. The agent's
/// own binary may be whatever its user made it, so it never runs with an elevated token, nor
/// as anyone else. A token that cannot be read counts as elevated.
fn agent_version(ctx: &Ctx, name: &str, sid: &str, id: String) -> Check {
    const TITLE: &str = "agent versions";
    let elevated = || {
        Check::new(
            id.clone(),
            Status::Info,
            TITLE,
            format!("not checked elevated: an agent's binary never runs elevated (run saiife doctor as {name})"),
        )
    };
    if ctx.as_root {
        return elevated();
    }
    let not_found = || Check::new(id.clone(), Status::Info, TITLE, "Claude Code not found");
    let Some(profile) = profile_dir(ctx, sid) else {
        return not_found();
    };
    let Ok(exe) = ctx
        .layout
        .try_at(Path::new(&format!(r"{profile}\.local\bin\claude.exe")))
    else {
        return not_found();
    };
    if std::fs::symlink_metadata(&exe).is_err() {
        return not_found();
    }
    match ctx.host.own_token() {
        Ok(t) if t.elevated => return elevated(),
        Ok(t) if t.sid != sid => {
            return Check::new(
                id,
                Status::Info,
                TITLE,
                format!("not checked: an agent's binary runs only as its own user (run saiife doctor as {name})"),
            )
        }
        Ok(_) => {}
        Err(e) => {
            return Check::new(
                id,
                Status::Info,
                TITLE,
                format!("not checked: this shell's token cannot be read ({e}), so it counts as elevated (run saiife doctor as {name})"),
            )
        }
    }
    let program = exe.display().to_string();
    let warn = |d: String| Check::new(id.clone(), Status::Warn, TITLE, d);
    let out = match ctx.host.run(&program, &["--version"], VERSION_WAIT) {
        Ok(o) if o.status == 0 => o.stdout,
        Ok(o) => return warn(format!("{program} --version failed (exit {})", o.status)),
        Err(e) => return warn(format!("{program} --version: {e}")),
    };
    match parse_agent_version(&out) {
        None => warn(format!("no version in the output of {program} --version")),
        Some(v) if v < CLAUDE_MIN => Check::new(
            id,
            Status::Fail,
            TITLE,
            format!(
                "Claude Code {} is older than {} (onFailure: \"block\")",
                fmt_version(v),
                fmt_version(CLAUDE_MIN)
            ),
        ),
        Some(v) => Check::new(
            id,
            Status::Pass,
            TITLE,
            format!("Claude Code {}", fmt_version(v)),
        ),
    }
}

#[cfg(all(test, unix))]
#[path = "windows_tests.rs"]
mod tests;
