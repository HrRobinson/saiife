//! The system checks of `saiife doctor`: supported system, install record,
//! config, root-owned paths, installed files, owners and modes, the audit
//! key, the daemon, lock labels, MCP servers and host facts. Each check id
//! is fixed; fleet tools match on it.

use super::report::{Check, Status};
use super::Ctx;
use crate::host::SECURITY;
use crate::install::MACOS_TOOL_TIMEOUT;
use crate::launchd;
use crate::layout::*;
use crate::supported::{check_supported, Support};
use saiife_agents::lock::{label_for, LockLabel};
use saiife_agents::Agent;
use saiife_audit::sign::{judge, Kind};
use saiife_policy::installed::{FileKind, Installed, VaultKeyMode};
use sha2::{Digest, Sha256};
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

const NOT_INSTALLED: &str = "locked mode is not installed: developer mode checks only";
const NOT_CHECKED: &str = "not checked (run as root)";
/// Largest file `files.installed` fingerprints (16 MiB), the binary
/// excepted ([`MAX_BINARY`]).
const MAX_FINGERPRINT: u64 = 16 * 1024 * 1024;
/// Largest binary `files.installed` fingerprints and `files.binary` reads
/// (256 MiB): a saiife build can outgrow 16 MiB.
const MAX_BINARY: u64 = 256 * 1024 * 1024;
/// The audit key seed length.
const KEY_LEN: u64 = 32;

pub fn checks(ctx: &Ctx) -> Vec<Check> {
    let mut out = vec![supported(ctx)];
    if !ctx.locked() {
        out.push(Check::new(
            "install.record",
            Status::Info,
            "install record",
            NOT_INSTALLED,
        ));
        return out;
    }
    out.push(install_record(ctx));
    out.push(config_valid(ctx));
    out.push(paths_owner(ctx));
    if let Some(i) = &ctx.installed {
        out.push(files_installed(ctx, i));
    }
    out.push(files_binary(ctx));
    #[cfg(target_os = "linux")]
    if ctx.installed.is_some() {
        out.extend(files_package(ctx));
    }
    out.push(files_modes(ctx));
    out.push(keys(ctx));
    out.push(audit_group(ctx));
    out.push(daemon_group(ctx));
    out.push(daemon_unit(ctx));
    out.push(daemon_health(ctx));
    if let Some(i) = &ctx.installed {
        if i.agents.is_empty() {
            out.push(Check::new("agents", Status::Warn, "agents", NO_AGENTS));
        }
        out.extend(i.agents.iter().map(|a| agent_label(ctx, &a.agent)));
    }
    if let Ok(p) = &ctx.config {
        // A listed `saiife` changes nothing on Claude Code (pinned by
        // command there). On Codex and Gemini CLI it allows any server a
        // project or user config registers under that name.
        let unpinned = ctx
            .installed
            .as_ref()
            .is_some_and(|i| i.agents.iter().any(|a| unpinned_saiife(&a.agent)));
        out.extend(p.config.guard.mcp.allow_servers.iter().filter_map(|s| {
            let title = if s != "saiife" {
                format!("MCP server {s} bypasses saiife: its requests are not brokered or limited")
            } else if unpinned {
                SAIIFE_LISTED_UNPINNED.to_string()
            } else {
                return None;
            };
            Some(Check::new(format!("mcp.{s}"), Status::Warn, title, ""))
        }));
    }
    out.extend(mcp_checks(ctx));
    if let Ok(p) = &ctx.config {
        out.extend(cloud_sts(&p.config));
    }
    if let Some(i) = &ctx.installed {
        out.push(vault_key(ctx, i));
        out.extend(claude_mdm(ctx, i));
    }
    out.push(peer_pidfd(ctx));
    out.push(reauth(ctx));
    out.push(Check::new(
        "forwarding",
        Status::Info,
        "audit forwarding",
        forwarding_detail(&ctx.config),
    ));
    out
}

/// The vault key's mode on record, which must be the platform's.
fn vault_key(ctx: &Ctx, i: &Installed) -> Check {
    const TITLE: &str = "vault key";
    let text = match i.vault_key {
        VaultKeyMode::Credential => "encrypted systemd credential",
        VaultKeyMode::File => "plain key file (systemd < 250)",
        VaultKeyMode::DaemonFile => {
            return if mac(ctx) {
                Check::new(
                    "vault.key",
                    Status::Info,
                    TITLE,
                    format!("daemon key file, 0400 {}", ctx.layout.daemon_user()),
                )
            } else {
                Check::new(
                    "vault.key",
                    Status::Fail,
                    TITLE,
                    "the install record holds a macOS vault key mode on Linux",
                )
            };
        }
    };
    if mac(ctx) {
        Check::new(
            "vault.key",
            Status::Fail,
            TITLE,
            format!("the install record holds a Linux vault key mode ({text}) on macOS"),
        )
    } else {
        Check::new("vault.key", Status::Info, TITLE, text)
    }
}

/// An MDM profile may also deliver Claude Code managed settings, and then
/// Claude Code may ignore the drop-in directory saiife writes.
fn claude_mdm(ctx: &Ctx, i: &Installed) -> Option<Check> {
    if !mac(ctx) || !i.agents.iter().any(|a| a.agent == "claude") {
        return None;
    }
    let at = ctx.layout.at(CLAUDE_MDM_PROFILE);
    fs::symlink_metadata(at).ok()?;
    Some(Check::new(
        "agents.claude.mdm",
        Status::Warn,
        "Claude Code managed settings",
        format!(
            "an MDM profile sets Claude Code managed settings ({CLAUDE_MDM_PROFILE}); \
             Claude Code may ignore saiife's managed-settings.d drop-in"
        ),
    ))
}

/// Whether this layout is macOS's.
fn mac(ctx: &Ctx) -> bool {
    ctx.layout.platform() == Platform::Macos
}

/// A path constant as this platform names it.
fn shown<'a>(ctx: &Ctx, c: &'a str) -> &'a str {
    ctx.layout.logical(c)
}

/// One `warn` per service in STS mode (plan 15): `run --cloud` hands a
/// short-lived AWS credential to agent-controlled code, which can copy it.
/// With any, one `info` notes how far `run_allow` is checked.
fn cloud_sts(config: &saiife_policy::SystemConfig) -> Vec<Check> {
    use saiife_policy::CloudMode;
    let mut out: Vec<Check> = config
        .services
        .iter()
        .filter(|(_, s)| s.mode == CloudMode::Sts)
        .map(|(name, _)| {
            Check::new(
                format!("cloud_sts.{name}"),
                Status::Warn,
                format!(
                    "service {name} is in STS mode: run --cloud hands a 15-minute AWS credential to agent-controlled code, which can copy it"
                ),
                "",
            )
        })
        .collect();
    if !out.is_empty() {
        out.push(Check::new(
            "cloud_sts.run_allow",
            Status::Info,
            "STS run_allow entries are checked by basename only",
            "a symlink to an interpreter is not caught at config time; run --cloud checks the resolved path at runtime",
        ));
    }
    out
}

/// The `[audit.forward.*]` targets of the system config, by name and
/// type. Their live state (`connected`, `failing`, ...) is in the audit
/// log as `forward` records, not here: doctor does not ask the targets.
fn forwarding_detail(config: &Result<saiife_policy::LoadedPolicy, String>) -> String {
    use saiife_policy::ForwardCfg;
    let Ok(p) = config else {
        return "unknown: the system config does not load".into();
    };
    let targets = &p.config.audit.forward;
    if targets.is_empty() {
        return "not configured".into();
    }
    let names: Vec<String> = targets
        .iter()
        .map(|(name, t)| {
            let kind = match t {
                ForwardCfg::Syslog { .. } => "syslog",
                ForwardCfg::File { .. } => "file",
                ForwardCfg::Https { .. } => "https",
            };
            format!("{name} ({kind})")
        })
        .collect();
    let s = if names.len() == 1 { "" } else { "s" };
    format!(
        "{} target{s}: {}; their state is in the audit log (forward records)",
        names.len(),
        names.join(", ")
    )
}

// ------------------------------------------------------------ helpers

/// Offenders and paths the caller could not look at, for one check.
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

    /// Fail naming every offender; else Info when something could not be
    /// looked at; else Pass.
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

enum Stat {
    Found(Metadata),
    Missing,
    /// Not visible to this caller; recorded in the tally.
    Skipped,
}

/// `lstat` of `path` (shown as `shown`). A permission error without root
/// is "not checked"; any other error is an offender.
fn lstat(ctx: &Ctx, shown: &str, path: &Path, t: &mut Tally) -> Stat {
    match fs::symlink_metadata(path) {
        Ok(m) => Stat::Found(m),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Stat::Missing,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            t.unchecked.push(shown.to_string());
            Stat::Skipped
        }
        Err(e) => {
            t.bad(format!("{shown}: cannot stat: {e}"));
            Stat::Skipped
        }
    }
}

/// A configured path: the §5.2 default lies under the layout's root; any
/// other value is taken as written (a test or `--root` config names its
/// own absolute paths).
fn configured(ctx: &Ctx, value: &Path, default: &str) -> PathBuf {
    if value == Path::new(default) || value == Path::new(ctx.layout.logical(default)) {
        ctx.layout.at(default)
    } else {
        value.to_path_buf()
    }
}

fn socket_dir(ctx: &Ctx) -> (String, PathBuf) {
    match &ctx.config {
        Ok(p) => {
            let v = &p.config.daemon.socket_dir;
            (v.display().to_string(), configured(ctx, v, RUN_DIR))
        }
        Err(_) => (shown(ctx, RUN_DIR).to_string(), ctx.layout.at(RUN_DIR)),
    }
}

fn audit_dir(ctx: &Ctx) -> (String, PathBuf) {
    match &ctx.config {
        Ok(p) => {
            let v = &p.config.audit.dir;
            (v.display().to_string(), configured(ctx, v, AUDIT_DIR))
        }
        Err(_) => (shown(ctx, AUDIT_DIR).to_string(), ctx.layout.at(AUDIT_DIR)),
    }
}

fn kind_of(m: &Metadata) -> &'static str {
    let t = m.file_type();
    if t.is_symlink() {
        "a symlink"
    } else if t.is_dir() {
        "a directory"
    } else if t.is_file() {
        "a regular file"
    } else if t.is_socket() {
        "a socket"
    } else {
        "a special file"
    }
}

// ------------------------------------------------------------ checks

fn supported(ctx: &Ctx) -> Check {
    const TITLE: &str = "supported system";
    match check_supported(ctx.layout, ctx.host) {
        Support::Supported { distro, systemd } => Check::new(
            "system.supported",
            Status::Pass,
            TITLE,
            if mac(ctx) {
                format!("{distro}, launchd")
            } else {
                format!("{distro}, systemd {systemd}")
            },
        ),
        // Without locked mode installed, an unsupported machine is only a
        // fact: developer mode does not need it.
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

fn install_record(ctx: &Ctx) -> Check {
    const TITLE: &str = "install record";
    match (&ctx.installed, &ctx.installed_error) {
        (_, Some(e)) => Check::new("install.record", Status::Fail, TITLE, e.clone()),
        (Some(i), None) => Check::new(
            "install.record",
            Status::Pass,
            TITLE,
            format!("saiife {}, installed {}", i.saiife, i.installed_at),
        ),
        (None, None) => Check::new("install.record", Status::Info, TITLE, NOT_INSTALLED),
    }
}

fn config_valid(ctx: &Ctx) -> Check {
    const TITLE: &str = "system config";
    match &ctx.config {
        Ok(p) if p.warnings.is_empty() => Check::new("config.valid", Status::Pass, TITLE, ""),
        Ok(p) => Check::new("config.valid", Status::Warn, TITLE, p.warnings.join("; ")),
        Err(e) => Check::new(
            "config.valid",
            Status::Fail,
            TITLE,
            format!("{e}. Every managed hook call is denied, and nothing is recorded"),
        ),
    }
}

/// §5.6 item 2: every directory from `/` down to the binary, and the
/// `/etc/saiife` files, owned by root and not writable by group or others.
fn paths_owner(ctx: &Ctx) -> Check {
    const ID: &str = "paths.owner";
    const TITLE: &str = "root-owned paths";
    let mut t = Tally::default();
    let Some(root) = ctx.host.user("root") else {
        t.bad("user root is not in /etc/passwd".into());
        return t.check(ID, TITLE);
    };
    // (shown, path under the root)
    let fixed = |p: &str| (p.to_string(), ctx.layout.at(p));
    let mut paths: Vec<(String, PathBuf)> = Path::new(BINARY)
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|p| fixed(&p.display().to_string()))
        .collect();
    paths.extend([ETC_DIR, CONFIG, POLICY_D].map(fixed));
    let policy_d = ctx.layout.at(POLICY_D);
    match fs::read_dir(&policy_d) {
        Ok(rd) => {
            let mut names = Vec::new();
            for e in rd {
                match e {
                    Ok(e) => names.push(e.file_name()),
                    Err(e) => t.bad(format!("{POLICY_D}: cannot list: {e}")),
                }
            }
            // Every drop-in the loader reads, whatever its name's encoding.
            names.retain(|n| Path::new(n).extension().is_some_and(|x| x == "toml"));
            names.sort();
            paths.extend(names.into_iter().map(|n| {
                let shown = format!("{POLICY_D}/{}", n.to_string_lossy());
                (shown, policy_d.join(n))
            }));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            t.unchecked.push(format!("{POLICY_D}/*.toml"))
        }
        Err(e) => t.bad(format!("{POLICY_D}: cannot list: {e}")),
    }
    paths.extend([INSTALLED, CREDSTORE].map(fixed));
    for (shown, at) in &paths {
        let Stat::Found(m) = lstat(ctx, shown, at, &mut t) else {
            // A missing path is reported by the checks that need it.
            continue;
        };
        if m.file_type().is_symlink() {
            t.bad(format!("{shown}: is a symlink"));
            continue;
        }
        for problem in crate::fsops::root_owned_problems(&m, root.uid) {
            t.bad(format!("{shown}: {problem}"));
        }
    }
    t.check(ID, TITLE)
}

/// The regular file `path`, opened without following a symlink or
/// blocking on a FIFO, with its metadata.
fn open_regular(path: &Path) -> io::Result<(fs::File, Metadata)> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let f = fs::File::from(fd);
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok((f, md))
}

/// The SHA-256 of the regular file `path` (see [`open_regular`]) of at
/// most `max` bytes.
fn sha256_file(path: &Path, max: u64) -> io::Result<String> {
    let (f, md) = open_regular(path)?;
    let too_large = || io::Error::new(io::ErrorKind::InvalidData, "file too large to fingerprint");
    if md.len() > max {
        return Err(too_large());
    }
    let mut h = Sha256::new();
    // Bounded even when the file grows after the size check.
    if io::copy(&mut io::Read::take(f, max + 1), &mut h)? > max {
        return Err(too_large());
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Whether the file listed as `listed` still exists (and, when `want` is
/// given, still has that SHA-256; read up to `max` bytes).
fn verify_file(ctx: &Ctx, listed: &Path, want: Option<&str>, max: u64, t: &mut Tally) {
    let shown = listed.display().to_string();
    let at = match ctx.layout.try_at(listed) {
        Ok(p) => p,
        Err(e) => return t.bad(format!("{shown}: {e}")),
    };
    match lstat(ctx, &shown, &at, t) {
        Stat::Missing => return t.bad(format!("{shown}: missing")),
        Stat::Skipped => return,
        Stat::Found(m) if !m.is_file() => {
            return t.bad(format!("{shown}: is {}, not a regular file", kind_of(&m)))
        }
        Stat::Found(_) => {}
    }
    let Some(want) = want else { return };
    match sha256_file(&at, max) {
        Ok(got) if got == want => {}
        Ok(_) => t.bad(format!("{shown}: changed since install")),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            t.unchecked.push(shown)
        }
        Err(e) if e.kind() == io::ErrorKind::InvalidData => t.bad(format!("{shown}: {e}")),
        Err(e) => t.bad(format!("{shown}: cannot read: {e}")),
    }
}

/// The fingerprint of saiife's entry in a shared managed file (Codex,
/// Gemini CLI; §8.3), as `system install` recorded it.
fn entry_fingerprint(agent: &str, file: &Path) -> Result<Option<String>, String> {
    let r = match agent {
        "codex" => saiife_agents::codex::managed_entry(file),
        "gemini" => saiife_agents::gemini::managed_entry(file),
        other => return Err(format!("unknown managed agent {other:?}")),
    };
    r.map_err(|e| e.to_string())
}

/// The installed binary must be the static release build (spec §9.2 A4): a
/// dynamic one honours `LD_PRELOAD` from an environment the agent shapes, a
/// debug-assertions build the `SAIIFE_EVAL_FAULT` test seam.
fn files_binary(ctx: &Ctx) -> Check {
    use crate::binary::{inspect, Linking, Profile};
    const ID: &str = "files.binary";
    const TITLE: &str = "installed binary";
    let fail = |d: String| Check::new(ID, Status::Fail, TITLE, d);
    let read = open_regular(&ctx.layout.at(BINARY)).and_then(|(f, md)| {
        if md.len() > MAX_BINARY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
        }
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut io::Read::take(f, MAX_BINARY + 1), &mut bytes)?;
        if bytes.len() as u64 > MAX_BINARY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
        }
        Ok(bytes)
    });
    let bytes = match read {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {
            return Check::new(ID, Status::Info, TITLE, format!("{NOT_CHECKED}: {BINARY}"))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return fail(format!("{BINARY}: missing")),
        Err(e) => return fail(format!("{BINARY}: cannot read: {e}")),
    };
    if mac(ctx) {
        return macho_binary(&bytes);
    }
    let info = match inspect(&bytes) {
        Ok(i) => i,
        Err(e) => return fail(format!("{BINARY}: not a static ELF executable ({e})")),
    };
    if let Linking::Dynamic(why) = &info.linking {
        return fail(format!(
            "{BINARY}: dynamically linked ({why}); an agent can inject code into the \
             managed hook through LD_PRELOAD: install the static release build"
        ));
    }
    match info.profile {
        Profile::Release => Check::new(ID, Status::Pass, TITLE, "static release build"),
        Profile::DebugAssertions => Check::new(
            ID,
            Status::Warn,
            TITLE,
            format!(
                "test build installed: {BINARY} has debug assertions on (the \
                 SAIIFE_EVAL_FAULT test seam can hang the guard); install the release build"
            ),
        ),
        Profile::Unknown => Check::new(
            ID,
            Status::Warn,
            TITLE,
            format!("{BINARY}: no saiife build marker; its build is unknown"),
        ),
    }
}

/// The macOS binary (spec 5.3): code-signed with the hardened runtime, so
/// `DYLD_INSERT_LIBRARIES` is ignored. Without the runtime, or unsigned, it
/// fails. An ad-hoc signature (or none the certificate chain backs) warns:
/// the file's claimed flags are read, the signature is not verified.
fn macho_binary(bytes: &[u8]) -> Check {
    use crate::binary::{inspect_macho, Profile, Signature};
    const ID: &str = "files.binary";
    const TITLE: &str = "installed binary";
    let fail = |d: String| Check::new(ID, Status::Fail, TITLE, d);
    let info = match inspect_macho(bytes) {
        Ok(i) => i,
        Err(e) => return fail(format!("{BINARY}: not a thin Mach-O executable ({e})")),
    };
    if info.signature == Signature::Unsigned {
        return fail(format!("{BINARY}: it is not code-signed"));
    }
    if !info.hardened_runtime {
        return fail(format!(
            "{BINARY}: signed without the hardened runtime: an agent could inject code into \
             the managed hook through DYLD_INSERT_LIBRARIES; sign with the hardened runtime"
        ));
    }
    let mut notes = info.warnings();
    match info.profile {
        Profile::Release => {}
        Profile::DebugAssertions => notes.push(
            "test build installed: debug assertions are on (the SAIIFE_EVAL_FAULT test seam \
             can hang the guard); install the release build"
                .to_string(),
        ),
        Profile::Unknown => notes.push("no saiife build marker; its build is unknown".to_string()),
    }
    if notes.is_empty() {
        Check::new(
            ID,
            Status::Pass,
            TITLE,
            "release build, hardened runtime, code-signed",
        )
    } else {
        Check::new(
            ID,
            Status::Warn,
            TITLE,
            format!("{BINARY}: {}", notes.join("; ")),
        )
    }
}

/// A package's staging copy ([`PACKAGE_BINARY`]) must be what install
/// copied to [`BINARY`]: after a package upgrade whose `postinst` did not
/// run (or failed), the hooks still run the old binary. Only when the
/// package binary exists (a package install).
#[cfg(target_os = "linux")]
fn files_package(ctx: &Ctx) -> Option<Check> {
    const ID: &str = "files.package";
    const TITLE: &str = "package binary";
    let package = ctx.layout.at(PACKAGE_BINARY);
    if fs::symlink_metadata(&package).is_err() {
        return None;
    }
    let read = |p: &Path| crate::fsops::sha256_file(p);
    let (pkg, opt) = match (read(&package), read(&ctx.layout.at(BINARY))) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            let status = if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root {
                Status::Info
            } else {
                Status::Warn
            };
            return Some(Check::new(
                ID,
                status,
                TITLE,
                format!("cannot compare: {e}"),
            ));
        }
    };
    if pkg.is_some() && pkg == opt {
        return Some(Check::new(ID, Status::Pass, TITLE, ""));
    }
    Some(Check::new(
        ID,
        Status::Warn,
        TITLE,
        format!(
            "the package's {PACKAGE_BINARY} differs from {BINARY}: \
             run sudo {PACKAGE_BINARY} system install --fleet"
        ),
    ))
}

/// Re-authentication for approvals needs polkit: `pkcheck` and `polkitd`
/// present and sound, and the `com.saiife.approve` action file installed as
/// a root-owned 0644 regular file with exactly the expected content. A
/// polkit rule that mentions the action is a warning: it may pre-authorize
/// approvals.
fn reauth(ctx: &Ctx) -> Check {
    const ID: &str = "reauth";
    const TITLE: &str = "re-authentication";
    if mac(ctx) {
        return auth_right(ctx);
    }
    let (rules, unreadable) = crate::polkit::scan_rules(ctx.layout);
    let problems = crate::polkit::action_problems(ctx.layout, ctx.host);
    let sound = crate::polkit::polkit_present(ctx.layout, ctx.host) && problems.is_empty();
    // Every finding is reported; one never hides another.
    let mut notes = Vec::new();
    if !sound {
        notes.push(REAUTH_UNAVAILABLE.to_string());
    }
    if !rules.is_empty() {
        notes.push(format!(
            "{} ({})",
            crate::polkit::RULE_MENTIONS_ACTION,
            rules.join(", ")
        ));
    }
    for d in &unreadable {
        notes.push(format!("cannot read {d} (run as root)"));
    }
    if notes.is_empty() {
        Check::new(ID, Status::Pass, TITLE, "polkit action com.saiife.approve")
    } else {
        Check::new(ID, Status::Warn, TITLE, notes.join("; "))
    }
}

/// macOS: the authorization right `com.saiife.approve` is registered as
/// installed (asks the session owner every time). Read through the host
/// (`security authorizationdb read`); doctor never writes it.
/// Same-user approval is off on macOS on purpose ([`MAC_SAME_USER_OFF`]):
/// the prompt cannot show what is being approved, so `same_user = "reauth"`
/// acts as `deny`.
fn auth_right(ctx: &Ctx) -> Check {
    use crate::authright::{read_args, read_ok, RIGHT};
    const ID: &str = "reauth";
    const TITLE: &str = "re-authentication";
    let why = match ctx.host.run(SECURITY, &read_args(), MACOS_TOOL_TIMEOUT) {
        Ok(o) if o.status == 0 => match read_ok(&o.stdout) {
            Ok(()) => {
                return Check::new(
                    ID,
                    Status::Info,
                    TITLE,
                    format!("{MAC_SAME_USER_OFF}; authorization right {RIGHT} is registered"),
                )
            }
            Err(e) => format!("weakened: {e}"),
        },
        Ok(o) => format!(
            "the right {RIGHT} is missing (authorizationdb read exited {})",
            o.status
        ),
        Err(e) => format!("the right {RIGHT} could not be read: {e}"),
    };
    Check::new(
        ID,
        Status::Warn,
        TITLE,
        format!("{MAC_SAME_USER_OFF}; {REAUTH_UNAVAILABLE}; {why}"),
    )
}

fn files_installed(ctx: &Ctx, i: &Installed) -> Check {
    let mut t = Tally::default();
    for f in &i.files {
        // The admin edits the config; only its presence is checked here,
        // its content by `config.valid`. The vault key has no digest on
        // record (installed.toml is world-readable); `files.modes` checks
        // its owner and mode.
        let want = match f.kind {
            FileKind::Config | FileKind::VaultKey => None,
            _ => f.sha256.as_deref(),
        };
        let max = if f.kind == FileKind::Binary {
            MAX_BINARY
        } else {
            MAX_FINGERPRINT
        };
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ty {
    Dir,
    File,
    Socket,
}

struct Want {
    shown: String,
    at: PathBuf,
    user: &'static str,
    group: &'static str,
    mode: u32,
    ty: Ty,
    /// Made by the running daemon (systemd's `RuntimeDirectory=`): absent
    /// while it is stopped, which `daemon.health` reports.
    while_running: bool,
    /// The group is not compared (another check reports it).
    loose_group: bool,
}

fn want(
    shown: &str,
    at: PathBuf,
    (user, group): (&'static str, &'static str),
    mode: u32,
    ty: Ty,
    while_running: bool,
) -> Want {
    Want {
        shown: shown.to_string(),
        at,
        user,
        group,
        mode,
        ty,
        while_running,
        loose_group: false,
    }
}

/// The §5.2 owner, group and mode of the paths systemd, the daemon and
/// install make.
fn files_modes(ctx: &Ctx) -> Check {
    let mut t = Tally::default();
    let l = |p: &str| ctx.layout.at(p);
    let (audit_shown, audit_at) = audit_dir(ctx);
    let (sock_shown, sock_at) = socket_dir(ctx);
    let socket_shown = format!("{}/saiife.sock", sock_shown.trim_end_matches('/'));
    let socket_at = sock_at.join("saiife.sock");
    let (du, dg, ag) = (
        ctx.layout.daemon_user(),
        ctx.layout.daemon_group(),
        ctx.layout.audit_group(),
    );
    let daemon = (du, dg);
    let root = ("root", if mac(ctx) { "wheel" } else { "root" });
    let sh = |c: &'static str| shown(ctx, c);
    let mut audit = want(&audit_shown, audit_at, (du, ag), 0o2750, Ty::Dir, false);
    // On macOS a missing or wrong audit group is a warning of its own
    // (`daemon.audit_group`): the month files would end up in `wheel`.
    audit.loose_group = mac(ctx);
    let mut wants = vec![
        want(sh(STATE_DIR), l(STATE_DIR), daemon, 0o700, Ty::Dir, false),
        want(sh(KEYS_DIR), l(KEYS_DIR), daemon, 0o700, Ty::Dir, false),
        want(sh(AUDIT_KEY), l(AUDIT_KEY), daemon, 0o600, Ty::File, false),
        audit,
        want(&sock_shown, sock_at, daemon, 0o755, Ty::Dir, true),
        want(&socket_shown, socket_at, daemon, 0o666, Ty::Socket, true),
    ];
    if let Some(i) = &ctx.installed {
        let vault = sh(VAULT_KEY);
        wants.push(match i.vault_key {
            VaultKeyMode::Credential => want(vault, l(VAULT_KEY), root, 0o600, Ty::File, false),
            VaultKeyMode::File => want(
                vault,
                l(VAULT_KEY),
                ("root", DAEMON_GROUP),
                0o640,
                Ty::File,
                false,
            ),
            VaultKeyMode::DaemonFile => want(vault, l(VAULT_KEY), daemon, 0o400, Ty::File, false),
        });
    }
    wants.push(want(sh(UNIT), l(UNIT), root, 0o644, Ty::File, false));

    for w in &wants {
        let m = match lstat(ctx, &w.shown, &w.at, &mut t) {
            Stat::Found(m) => m,
            Stat::Missing if w.while_running => continue,
            Stat::Missing => {
                t.bad(format!("{}: missing", w.shown));
                continue;
            }
            Stat::Skipped => continue,
        };
        let uid = ctx.host.user(w.user).map(|u| u.uid);
        let gid = if w.loose_group {
            Some(m.gid())
        } else {
            ctx.host.group_id(w.group)
        };
        let (Some(uid), Some(gid)) = (uid, gid) else {
            if uid.is_none() {
                t.bad(format!("user {} does not exist", w.user));
            }
            if gid.is_none() {
                t.bad(format!("group {} does not exist", w.group));
            }
            continue;
        };
        let ft = m.file_type();
        let ty_ok = match w.ty {
            Ty::Dir => ft.is_dir(),
            Ty::File => ft.is_file(),
            Ty::Socket => ft.is_socket(),
        };
        let perm = m.mode() & 0o7777;
        if !ty_ok || m.uid() != uid || m.gid() != gid || perm != w.mode {
            t.bad(format!(
                "{}: want {}:{} {:04o}, found {} uid {} gid {} mode {perm:04o}",
                w.shown,
                w.user,
                w.group,
                w.mode,
                kind_of(&m),
                m.uid(),
                m.gid(),
            ));
        }
    }
    t.check("files.modes", "file owners and modes")
}

/// The 9a follow-up: the key dir and key file the daemon signs with, by
/// the daemon's own start-up rules, plus the key's length.
fn keys(ctx: &Ctx) -> Check {
    const ID: &str = "keys";
    const TITLE: &str = "audit signing key";
    let mut t = Tally::default();
    let du = ctx.layout.daemon_user();
    let (keys_dir, audit_key) = (shown(ctx, KEYS_DIR), shown(ctx, AUDIT_KEY));
    let Some(owner) = ctx.host.user(du).map(|u| u.uid) else {
        t.bad(format!("user {du} does not exist"));
        return t.check(ID, TITLE);
    };
    let keys_at = ctx.layout.at(KEYS_DIR);
    match lstat(ctx, keys_dir, &keys_at, &mut t) {
        Stat::Found(m) => {
            if let Err(e) = judge(&keys_at, Kind::KeyDir, m.uid(), m.mode(), owner) {
                t.bad(e.to_string());
                return t.check(ID, TITLE);
            }
        }
        Stat::Missing => {
            t.bad(format!("{keys_dir}: missing"));
            return t.check(ID, TITLE);
        }
        Stat::Skipped => return t.check(ID, TITLE),
    }
    let key_at = ctx.layout.at(AUDIT_KEY);
    match lstat(ctx, audit_key, &key_at, &mut t) {
        Stat::Found(m) => {
            if let Err(e) = judge(&key_at, Kind::KeyFile, m.uid(), m.mode(), owner) {
                t.bad(e.to_string());
            } else if m.len() != KEY_LEN {
                t.bad(format!(
                    "{audit_key}: is {} bytes, must be {KEY_LEN} bytes",
                    m.len()
                ));
            }
        }
        Stat::Missing => t.bad(format!("{audit_key}: missing")),
        Stat::Skipped => {}
    }
    t.check(ID, TITLE)
}

/// The daemon gives the audit dir to the audit group at start, which needs
/// the daemon user in that group. On macOS a missing group, or an audit
/// dir in another group, is a warning: the month files then end up in
/// `wheel`, which the audit readers cannot use.
fn audit_group(ctx: &Ctx) -> Check {
    const ID: &str = "daemon.audit_group";
    let (du, ag) = (ctx.layout.daemon_user(), ctx.layout.audit_group());
    let title = format!("daemon user in {ag}");
    let fail = |d: String| Check::new(ID, Status::Fail, title.clone(), d);
    let Some(user) = ctx.host.user(du) else {
        return fail(format!("user {du} does not exist"));
    };
    let (Some(gid), Some(members)) = (ctx.host.group_id(ag), ctx.host.group_members(ag)) else {
        let why = format!("group {ag} does not exist");
        return if mac(ctx) {
            Check::new(
                ID,
                Status::Warn,
                title,
                format!("{why}: the audit month files end up in group wheel"),
            )
        } else {
            fail(why)
        };
    };
    if !(user.gid == gid || members.iter().any(|m| m == du)) {
        return fail(format!(
            "{du} is not a member of {ag}: the daemon cannot give the audit log to {ag}"
        ));
    }
    if mac(ctx) {
        let (dir_shown, dir_at) = audit_dir(ctx);
        if let Ok(m) = fs::symlink_metadata(&dir_at) {
            if m.gid() != gid {
                return Check::new(
                    ID,
                    Status::Warn,
                    title,
                    format!(
                        "{dir_shown} is in group {}, not {ag}: the audit month files end up in group wheel",
                        m.gid()
                    ),
                );
            }
        }
    }
    Check::new(ID, Status::Pass, title, "")
}

/// No user but the daemon's is in the `saiife` group, listed in
/// `/etc/group` or by primary gid: the plain vault key (systemd < 250) is
/// readable by that group (§5.2).
fn daemon_group(ctx: &Ctx) -> Check {
    const ID: &str = "daemon.group";
    const TITLE: &str = "saiife group holds only the daemon user";
    let (du, dg) = (ctx.layout.daemon_user(), ctx.layout.daemon_group());
    let Some(gid) = ctx.host.group_id(dg) else {
        return Check::new(
            ID,
            Status::Fail,
            TITLE,
            format!("group {dg} does not exist"),
        );
    };
    let primary = match ctx.host.users_with_primary_gid(gid) {
        Ok(p) => p,
        Err(e) => {
            return Check::new(
                ID,
                Status::Fail,
                TITLE,
                format!("the members of group {dg} could not be read: {e}"),
            )
        }
    };
    let mut others: Vec<String> = ctx
        .host
        .group_members(dg)
        .unwrap_or_default()
        .into_iter()
        .chain(primary)
        .filter(|u| u != du)
        .collect();
    others.sort();
    others.dedup();
    if others.is_empty() {
        Check::new(ID, Status::Pass, TITLE, "")
    } else {
        Check::new(
            ID,
            Status::Fail,
            TITLE,
            format!(
                "{} in group {dg}: they can read what the daemon's group can, including a plain vault key",
                others.join(", ")
            ),
        )
    }
}

fn daemon_unit(ctx: &Ctx) -> Check {
    const TITLE: &str = "saiifed.service active";
    if mac(ctx) {
        return launchd_unit(ctx);
    }
    match ctx.host.systemctl(&["is-active", UNIT_NAME]) {
        Ok(out) if out.stdout.trim() == "active" => {
            Check::new("daemon.unit", Status::Pass, TITLE, "")
        }
        Ok(out) => {
            let state = out.stdout.trim();
            Check::new(
                "daemon.unit",
                Status::Fail,
                TITLE,
                format!(
                    "systemctl is-active {UNIT_NAME}: {}",
                    if state.is_empty() { "no answer" } else { state }
                ),
            )
        }
        Err(e) => Check::new("daemon.unit", Status::Fail, TITLE, e.to_string()),
    }
}

/// macOS: the plist is the one install recorded, and launchd has the job
/// loaded (`launchctl print system/com.saiife.saiifed` exits 0).
fn launchd_unit(ctx: &Ctx) -> Check {
    const ID: &str = "daemon.unit";
    const TITLE: &str = "saiifed loaded in launchd";
    let fail = |d: String| Check::new(ID, Status::Fail, TITLE, d);
    let plist = shown(ctx, UNIT);
    let recorded = ctx
        .installed
        .as_ref()
        .and_then(|i| i.files.iter().find(|f| f.kind == FileKind::Unit))
        .and_then(|f| f.sha256.as_deref());
    match (recorded, sha256_file(&ctx.layout.at(UNIT), MAX_FINGERPRINT)) {
        (Some(want), Ok(got)) if want != got => {
            return fail(format!("{plist}: differs from its install record"))
        }
        (None, _) => return fail(format!("{plist}: no fingerprint in the install record")),
        (_, Err(e)) if e.kind() == io::ErrorKind::PermissionDenied && !ctx.as_root => {}
        (_, Err(e)) => return fail(format!("{plist}: cannot read: {e}")),
        _ => {}
    }
    match ctx.host.launchctl(&["print", launchd::SERVICE]) {
        Ok(o) if o.status == 0 => Check::new(ID, Status::Pass, TITLE, ""),
        Ok(o) => fail(format!(
            "launchctl print {}: exited {}: the daemon is not loaded",
            launchd::SERVICE,
            o.status
        )),
        Err(e) => fail(e.to_string()),
    }
}

#[cfg(unix)]
fn daemon_health(ctx: &Ctx) -> Check {
    use saiife_ipc::client::Client;
    use saiife_ipc::msg::OP_STATUS;
    use serde_json::{Map, Value};
    use std::time::{Duration, Instant};
    const TITLE: &str = "daemon health";
    let fail = |d: String| Check::new("daemon.health", Status::Fail, TITLE, d);
    let user = match &ctx.config {
        Ok(p) => p.config.daemon.user.clone(),
        Err(_) => ctx.layout.daemon_user().to_string(),
    };
    let Some(uid) = ctx.host.user(&user).map(|u| u.uid) else {
        return fail(format!("daemon user {user} is not in /etc/passwd"));
    };
    let (_, dir) = socket_dir(ctx);
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = Client::connect(&dir, uid, deadline)
        .and_then(|mut c| c.call(OP_STATUS, Map::new(), deadline));
    let m = match status {
        Ok(m) => m,
        Err(e) => return fail(e.to_string()),
    };
    if m.get("policy_ok").and_then(Value::as_bool) != Some(true) {
        return fail("policy not loaded: connector calls are denied".into());
    }
    let show = |k: &str| match m.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => "none".to_string(),
        Some(v) => v.to_string(),
    };
    Check::new(
        "daemon.health",
        Status::Pass,
        TITLE,
        format!(
            "chain {}, head seq {}, last checkpoint seq {}",
            show("chain"),
            show("head_seq"),
            show("last_checkpoint_seq")
        ),
    )
}

// ------------------------------------------------------------ MCP gateway

/// The Landlock ABI this machine offers; 0 where there is none.
fn landlock_abi() -> u32 {
    #[cfg(target_os = "linux")]
    {
        crate::sandbox::landlock_abi()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// What a partial Landlock ABI leaves unenforced, from the sandbox's own
/// wording; `None` at no Landlock (a per-server failure) or full strength.
fn landlock_gap(abi: u32) -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        if abi == 0 {
            return None;
        }
        crate::sandbox::Strength::from_abi(abi).gap()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = abi;
        None
    }
}

type McpStatus = Result<Vec<serde_json::Value>, String>;

/// The daemon's `mcp` status list (`[{name, state, tools, since,
/// last_error}]`), or why the daemon did not answer.
#[cfg(unix)]
fn daemon_mcp_status(ctx: &Ctx) -> McpStatus {
    use saiife_ipc::client::Client;
    use saiife_ipc::msg::OP_STATUS;
    use serde_json::{Map, Value};
    use std::time::{Duration, Instant};
    let user = match &ctx.config {
        Ok(p) => p.config.daemon.user.clone(),
        Err(_) => ctx.layout.daemon_user().to_string(),
    };
    let Some(uid) = ctx.host.user(&user).map(|u| u.uid) else {
        return Err(format!("daemon user {user} is not in /etc/passwd"));
    };
    let (_, dir) = socket_dir(ctx);
    let deadline = Instant::now() + Duration::from_secs(2);
    let m = Client::connect(&dir, uid, deadline)
        .and_then(|mut c| c.call(OP_STATUS, Map::new(), deadline))
        .map_err(|e| e.to_string())?;
    Ok(match m.get("mcp") {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    })
}

/// The warning for `saiife` in `[guard.mcp] allow_servers` while an agent
/// that does not pin its command (Codex, Gemini CLI) is installed: there
/// the listing allows any server registered under that name.
pub const SAIIFE_LISTED_UNPINNED: &str = "MCP server saiife is listed: on Codex and Gemini CLI any server named saiife is allowed, and nothing pins its command";

/// Whether `agent` may run any MCP server named `saiife` (nothing pins its
/// command): every agent but Claude Code, whose managed drop-in pins it.
pub fn unpinned_saiife(agent: &str) -> bool {
    agent != "claude"
}

fn mcp_checks(ctx: &Ctx) -> Vec<Check> {
    if mac(ctx) {
        let mut out = vec![Check::new(
            "mcp.landlock",
            Status::Info,
            "MCP gateway: Linux only in this version",
            "",
        )];
        // The gateway checks do not apply; the agent checks do.
        out.extend(
            mcp_checks_with(ctx, &Ok(Vec::new()), 0)
                .into_iter()
                .filter(|c| {
                    !(c.id == "mcp.landlock"
                        || c.id == "mcp.sandbox"
                        || c.id.starts_with("mcp.gateway."))
                }),
        );
        return out;
    }
    let has_gateway = ctx.config.as_ref().is_ok_and(|p| !p.config.mcp.is_empty());
    let (status, abi) = if has_gateway {
        (daemon_mcp_status(ctx), landlock_abi())
    } else {
        (Ok(Vec::new()), 0)
    };
    mcp_checks_with(ctx, &status, abi)
}

/// The MCP checks with the daemon's answer and the Landlock ABI given, so
/// tests need neither a daemon nor a kernel.
fn mcp_checks_with(ctx: &Ctx, status: &McpStatus, abi: u32) -> Vec<Check> {
    let mut out = Vec::new();
    if let Ok(p) = &ctx.config {
        if !p.config.mcp.is_empty() {
            for (name, cfg) in &p.config.mcp {
                out.push(mcp_gateway(ctx, name, cfg, status, abi));
            }
            out.push(Check::new(
                "mcp.landlock",
                Status::Info,
                format!("Landlock ABI {abi}"),
                "",
            ));
            // Only a server that runs under Landlock has a sandbox to weaken.
            let uses_landlock = p
                .config
                .mcp
                .values()
                .any(|c| c.sandbox != saiife_policy::mcp::Sandbox::Off);
            if let Some(gap) = landlock_gap(abi).filter(|_| uses_landlock) {
                out.push(Check::new(
                    "mcp.sandbox",
                    Status::Warn,
                    "MCP server sandbox is weaker than full",
                    gap,
                ));
            }
        }
    }
    if let Some(i) = &ctx.installed {
        let saiife_listed = ctx.config.as_ref().is_ok_and(|p| {
            p.config
                .guard
                .mcp
                .allow_servers
                .iter()
                .any(|s| s == "saiife")
        });
        let saiife = if saiife_listed {
            "the saiife server is not brokered here (nothing pins its command); it is in [guard.mcp] allow_servers, so its calls are allowed by name; nothing checks which program serves them"
        } else {
            "the saiife server is not brokered here (nothing pins its command); its tools are denied unless [guard.mcp] allow_servers lists \"saiife\""
        };
        for a in &i.agents {
            if matches!(a.agent.as_str(), "codex" | "gemini") {
                if let Some(ag) = Agent::from_name(&a.agent) {
                    out.push(Check::new(
                        format!("mcp.{}.restriction", a.agent),
                        Status::Info,
                        format!(
                            "MCP servers for {} are restricted by the hook only",
                            ag.label()
                        ),
                        saiife,
                    ));
                }
            }
        }
        if i.agents.iter().any(|a| a.agent == "claude") {
            out.push(claude_allowlist(ctx, i));
        }
    }
    out
}

fn mcp_gateway(
    ctx: &Ctx,
    name: &str,
    cfg: &saiife_policy::McpServerCfg,
    status: &McpStatus,
    abi: u32,
) -> Check {
    use saiife_policy::Sandbox;
    let id = format!("mcp.gateway.{name}");
    // (status, text, the text is the whole title)
    let mut problems: Vec<(Status, String, bool)> = Vec::new();
    let mut tools = 0;
    match status {
        Err(e) => problems.push((
            Status::Fail,
            format!("MCP server {name} is not running: the daemon is unreachable ({e})"),
            true,
        )),
        Ok(list) => {
            let entry = list
                .iter()
                .find(|s| s.get("name").and_then(|v| v.as_str()) == Some(name));
            let state = entry.and_then(|s| s.get("state")).and_then(|v| v.as_str());
            tools = entry
                .and_then(|s| s.get("tools"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if state != Some("running") {
                let why = entry
                    .and_then(|s| s.get("last_error"))
                    .and_then(|v| v.as_str())
                    .filter(|e| !e.is_empty())
                    .or(state)
                    .unwrap_or("the daemon does not list it; reload the policy");
                problems.push((
                    Status::Fail,
                    format!("MCP server {name} is not running: {why}"),
                    true,
                ));
            }
        }
    }
    match cfg.sandbox {
        Sandbox::Off => problems.push((Status::Warn, "sandbox is off".into(), false)),
        Sandbox::Landlock if abi == 0 => {
            problems.push((Status::Fail, "sandbox unavailable".into(), false))
        }
        Sandbox::Landlock => {}
    }
    for arg in &cfg.args {
        if arg.starts_with('/') {
            let bad = match ctx.layout.try_at(Path::new(arg)) {
                Ok(at) => crate::fsops::root_owned_chain(&at).err(),
                Err(e) => Some(e.to_string()),
            };
            if let Some(e) = bad {
                problems.push((
                    Status::Warn,
                    format!("argument {arg} is not root-owned ({e})"),
                    false,
                ));
            }
        }
    }
    let launcher = |s: &str| matches!(s.rsplit('/').next(), Some("npx" | "uvx"));
    if launcher(&cfg.command.to_string_lossy()) || cfg.args.iter().any(|a| launcher(a)) {
        problems.push((
            Status::Warn,
            "npx/uvx download code at run time; install the server as a root-owned file".into(),
            false,
        ));
    }
    if problems.is_empty() {
        return Check::new(
            id,
            Status::Pass,
            format!("MCP server {name} is brokered ({tools} tools)"),
            "",
        );
    }
    let worst = if problems.iter().any(|p| p.0 == Status::Fail) {
        Status::Fail
    } else {
        Status::Warn
    };
    let (_, first, whole) = problems.iter().find(|p| p.0 == worst).cloned().unwrap();
    let title = if whole {
        first
    } else {
        format!("MCP server {name}: {first}")
    };
    let detail: Vec<&str> = problems.iter().map(|p| p.1.as_str()).collect();
    Check::new(id, worst, title, detail.join("; "))
}

/// The managed Claude Code allowlist against what policy would install now.
/// Reads only; the install step is what writes it.
fn claude_allowlist(ctx: &Ctx, i: &Installed) -> Check {
    const ID: &str = "mcp.claude.allowlist";
    const DRIFT: &str =
        "the Claude Code MCP allowlist differs from policy; run saiife system install again";
    let Ok(p) = &ctx.config else {
        return Check::new(
            ID,
            Status::Info,
            "Claude Code MCP allowlist",
            "not checked: the config does not load",
        );
    };
    let want = saiife_agents::claude::managed_mcp_settings(&p.config.guard.mcp.allow_servers);
    let warn = |d: String| Check::new(ID, Status::Warn, DRIFT, d);
    let mcp = shown(ctx, CLAUDE_MCP);
    let at = ctx.layout.at(CLAUDE_MCP);
    let read = match fs::symlink_metadata(&at) {
        Ok(m) if m.is_file() && m.len() <= 1 << 20 => fs::read(&at),
        Ok(_) => return warn(format!("{mcp}: not a regular file of sane size")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return warn(format!("{mcp}: missing")),
        Err(e) => return warn(format!("{mcp}: {e}")),
    };
    let got = match read {
        Ok(g) => g,
        Err(e) => return warn(format!("{mcp}: {e}")),
    };
    if got != want.as_bytes() {
        return warn(format!("{mcp}: content differs from policy"));
    }
    let recorded = i.files.iter().find(|f| f.path == Path::new(mcp));
    if let Some(want_sha) = recorded.and_then(|f| f.sha256.as_deref()) {
        if want_sha != crate::fsops::sha256_hex(&got) {
            return warn(format!("{mcp}: differs from its install record"));
        }
    }
    Check::new(
        ID,
        Status::Pass,
        "Claude Code MCP allowlist matches policy",
        "",
    )
}

/// The label recorded for the layout's platform (the host's, outside
/// tests), so a macOS tree checked from Linux reads as a Mac reads it.
fn agent_label(ctx: &Ctx, name: &str) -> Check {
    let id = format!("agents.{name}.label");
    match Agent::from_name(name) {
        Some(a) => {
            let l = label_for(a, mac(ctx));
            let title = format!("{} lock label", a.label());
            let status = if l == LockLabel::Lockable {
                Status::Pass
            } else {
                Status::Warn
            };
            Check::new(id, status, title, l.wording())
        }
        None => Check::new(
            id,
            Status::Warn,
            format!("{name} lock label"),
            "unknown agent",
        ),
    }
}

/// `SO_PEERPIDFD` arrived in Linux 6.5.
pub(crate) fn pidfd_release(release: &str) -> bool {
    let mut parts = release.split(['.', '-']);
    let mut num = || parts.next().and_then(|s| s.parse::<u32>().ok());
    match (num(), num()) {
        (Some(major), Some(minor)) => (major, minor) >= (6, 5),
        _ => false,
    }
}

fn peer_pidfd(ctx: &Ctx) -> Check {
    if mac(ctx) {
        return Check::new(
            "peer.pidfd",
            Status::Info,
            "peer identity",
            "LOCAL_PEERCRED and LOCAL_PEERPID (the pid is used for attribution only)",
        );
    }
    let uname = rustix::system::uname();
    let release = uname.release().to_string_lossy();
    let linux = cfg!(target_os = "linux");
    Check::new(
        "peer.pidfd",
        Status::Info,
        "peer identity",
        if linux && pidfd_release(&release) {
            "SO_PEERPIDFD available"
        } else {
            "SO_PEERCRED only"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::super::{run, DoctorOptions, Report, Status};
    use crate::host::{FakeHost, Host, UserInfo};
    use crate::layout::*;
    use crate::testing::fake_install;
    use saiife_policy::installed::{read_installed, write_installed, ManagedAgent, VaultKeyMode};
    use saiife_policy::FixedDirectory;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn forwarding_names_the_configured_targets() {
        let d = TempDir::new().unwrap();
        let cfg = d.path().join("config.toml");
        let load = |text: &str| {
            fs::write(&cfg, text).unwrap();
            saiife_policy::load_system(&cfg).map_err(|e| e.to_string())
        };
        let detail = |text: &str| super::forwarding_detail(&load(text));
        assert_eq!(detail("version = 2\n"), "not configured");
        assert_eq!(
            detail(
                "version = 2\n[audit.forward.siem]\ntype = \"https\"\nurl = \"https://h.test/e\"\n\
                 [audit.forward.copy]\ntype = \"file\"\npath = \"/mnt/x\"\n"
            ),
            "2 targets: copy (file), siem (https); their state is in the audit log (forward records)"
        );
        assert!(super::forwarding_detail(&Err("bad".into())).starts_with("unknown"));
    }

    struct T {
        _dir: TempDir,
        layout: Layout,
        host: FakeHost,
    }

    impl T {
        fn installed() -> T {
            let dir = tempfile::tempdir().unwrap();
            fake_install(dir.path());
            T::open(dir)
        }

        fn empty() -> T {
            T::open(tempfile::tempdir().unwrap())
        }

        fn open(dir: TempDir) -> T {
            // The Linux tree `fake_install` makes, whatever the build host.
            let layout = Layout::under_for(dir.path(), Platform::Linux);
            let host = FakeHost::open(dir.path()).unwrap();
            T {
                _dir: dir,
                layout,
                host,
            }
        }

        fn at(&self, p: &str) -> std::path::PathBuf {
            self.layout.at(p)
        }

        fn chmod(&self, p: &str, mode: u32) {
            fs::set_permissions(self.at(p), fs::Permissions::from_mode(mode)).unwrap();
        }

        fn doctor(&self) -> Report {
            run(
                &self.layout,
                &self.host,
                &FixedDirectory::from_text("", ""),
                &DoctorOptions::default(),
            )
        }

        fn edit_installed(&self, f: impl FnOnce(&mut saiife_policy::installed::Installed)) {
            let p = self.at(INSTALLED);
            let mut i = read_installed(&p).unwrap().unwrap();
            f(&mut i);
            write_installed(&p, &i).unwrap();
        }

        fn append_config(&self, text: &str) {
            let p = self.at(CONFIG);
            let mut c = fs::read_to_string(&p).unwrap();
            c.push_str(text);
            fs::write(&p, c).unwrap();
        }
    }

    fn get<'r>(r: &'r Report, id: &str) -> &'r super::Check {
        r.checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no check {id} in\n{}", r.to_text()))
    }

    fn assert_status(r: &Report, id: &str, s: Status) {
        let c = get(r, id);
        assert_eq!(c.status, s, "{id}: {c:?}\n{}", r.to_text());
    }

    #[cfg(target_os = "linux")]
    fn add_polkit(t: &T, action: bool) {
        let p = t.at(PKCHECK);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        let d = t.at(crate::polkit::POLKITD_PATHS[1]);
        fs::create_dir_all(d.parent().unwrap()).unwrap();
        fs::write(&d, b"polkitd").unwrap();
        if action {
            let a = t.at(POLKIT_ACTION);
            fs::create_dir_all(a.parent().unwrap()).unwrap();
            fs::write(&a, crate::layout::POLKIT_POLICY).unwrap();
            fs::set_permissions(&a, fs::Permissions::from_mode(0o644)).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn doctor_warns_reauth_unavailable() {
        let t = T::installed();
        let r = t.doctor();
        assert_status(&r, "reauth", Status::Warn);
        assert_eq!(
            get(&r, "reauth").detail,
            "re-authentication unavailable: approvals need a second account"
        );
        // pkcheck without the action file still warns.
        add_polkit(&t, false);
        assert_status(&t.doctor(), "reauth", Status::Warn);
        add_polkit(&t, true);
        assert_status(&t.doctor(), "reauth", Status::Pass);
        // A wrong mode, a symlink, or a non-root owner each warn.
        t.chmod(POLKIT_ACTION, 0o664);
        assert_status(&t.doctor(), "reauth", Status::Warn);
        t.chmod(POLKIT_ACTION, 0o644);
        assert_status(&t.doctor(), "reauth", Status::Pass);
        let a = t.at(POLKIT_ACTION);
        let real = a.with_extension("real");
        fs::rename(&a, &real).unwrap();
        std::os::unix::fs::symlink(&real, &a).unwrap();
        assert_status(&t.doctor(), "reauth", Status::Warn);
        fs::remove_file(&a).unwrap();
        fs::rename(&real, &a).unwrap();
        assert_status(&t.doctor(), "reauth", Status::Pass);
        // Other content (an older file without the owner annotation).
        fs::write(
            &a,
            crate::layout::POLKIT_POLICY.replace("unix-user:saiife", "unix-user:root"),
        )
        .unwrap();
        assert_status(&t.doctor(), "reauth", Status::Warn);
        fs::write(&a, crate::layout::POLKIT_POLICY).unwrap();
        assert_status(&t.doctor(), "reauth", Status::Pass);
        // A polkit rule naming the action.
        let rules = t.at("/etc/polkit-1/rules.d");
        fs::create_dir_all(&rules).unwrap();
        fs::write(
            rules.join("49-saiife.rules"),
            "if (action.id == \"com.saiife.approve\") return polkit.Result.YES;",
        )
        .unwrap();
        let r = t.doctor();
        assert_status(&r, "reauth", Status::Warn);
        assert!(
            get(&r, "reauth").detail.contains(
                "a polkit rule mentions com.saiife.approve; it may pre-authorize approvals"
            ),
            "{:?}",
            get(&r, "reauth")
        );
        // A rule does not hide an action-file problem (both reported).
        fs::write(&a, "tampered").unwrap();
        let r = t.doctor();
        let d = &get(&r, "reauth").detail;
        assert!(
            d.contains(REAUTH_UNAVAILABLE) && d.contains("mentions com.saiife.approve"),
            "{d}"
        );
        fs::write(&a, crate::layout::POLKIT_POLICY).unwrap();
        fs::remove_file(rules.join("49-saiife.rules")).unwrap();
        assert_status(&t.doctor(), "reauth", Status::Pass);
        // A rules directory that cannot be read is not a silent pass.
        if !rustix::process::geteuid().is_root() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rules, fs::Permissions::from_mode(0o000)).unwrap();
            let r = t.doctor();
            fs::set_permissions(&rules, fs::Permissions::from_mode(0o755)).unwrap();
            assert_status(&r, "reauth", Status::Warn);
            assert!(
                get(&r, "reauth")
                    .detail
                    .contains("cannot read /etc/polkit-1/rules.d (run as root)"),
                "{:?}",
                get(&r, "reauth")
            );
        }
        let uid = t.host.user("root").unwrap().uid;
        crate::testing::set_root_uid(&t.host, uid + 1);
        assert_status(&t.doctor(), "reauth", Status::Warn);
    }

    // Linux only: on macOS `system.supported` fails (locked mode needs Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn fake_install_fails_only_daemon_checks() {
        let t = T::installed();
        let r = t.doctor();
        for id in [
            "system.supported",
            "install.record",
            "config.valid",
            "paths.owner",
            "files.installed",
            "files.binary",
            "files.modes",
            "keys",
            "daemon.audit_group",
            "daemon.group",
            "agents.claude.label",
        ] {
            assert_status(&r, id, Status::Pass);
        }
        assert_status(&r, "daemon.unit", Status::Fail);
        assert_status(&r, "daemon.health", Status::Fail);
        let fails: Vec<&str> = r
            .checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(fails, ["daemon.unit", "daemon.health"], "{}", r.to_text());
        for id in ["vault.key", "peer.pidfd", "forwarding"] {
            assert_status(&r, id, Status::Info);
        }
        assert_status(&r, "reauth", Status::Warn);
        assert_eq!(get(&r, "reauth").detail, REAUTH_UNAVAILABLE);
        assert_eq!(get(&r, "forwarding").detail, "not configured");
        // No gateway servers and no allow_servers: only the allowlist
        // check, and it agrees with policy.
        let mcp: Vec<&str> = r
            .checks
            .iter()
            .filter(|c| c.id.starts_with("mcp."))
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(mcp, ["mcp.claude.allowlist"]);
        assert_status(&r, "mcp.claude.allowlist", Status::Pass);
        // Doctor asked systemd, through the host, and changed nothing.
        let calls = t.host.state().calls;
        assert_eq!(calls, ["systemctl is-active saiifed.service"]);
        assert!(t.host.state().chowns.is_empty());
    }

    #[test]
    fn invalid_config_fails_and_says_no_records() {
        let t = T::installed();
        t.append_config("bogus = 1\n");
        let r = t.doctor();
        assert_status(&r, "config.valid", Status::Fail);
        let d = &get(&r, "config.valid").detail;
        assert!(
            d.ends_with(". Every managed hook call is denied, and nothing is recorded"),
            "{d}"
        );
        assert!(d.contains("config.toml"), "{d}");
    }

    #[test]
    fn group_writable_etc_fails() {
        let t = T::installed();
        t.chmod(ETC_DIR, 0o775);
        let r = t.doctor();
        assert_status(&r, "paths.owner", Status::Fail);
        let d = &get(&r, "paths.owner").detail;
        assert!(d.contains("/etc/saiife"), "{d}");
        assert!(!d.contains("/opt/saiife"), "{d}");
    }

    #[test]
    fn group_writable_policy_drop_in_fails() {
        let t = T::installed();
        let p = t.at(POLICY_D).join("10-team.toml");
        fs::write(&p, "").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
        let r = t.doctor();
        assert_status(&r, "paths.owner", Status::Fail);
        assert!(get(&r, "paths.owner")
            .detail
            .contains("/etc/saiife/policy.d/10-team.toml"));
    }

    #[test]
    fn hostile_policy_drop_in_name_is_named_safely() {
        use std::os::unix::ffi::OsStrExt;
        let t = T::installed();
        // APFS (macOS) refuses a name that is not UTF-8 (EILSEQ); there the
        // name keeps the escape and the newline but not the 0xff byte.
        let name: &[u8] = if cfg!(target_os = "macos") {
            b"\x1b[31mevil\n.toml"
        } else {
            b"\x1b[31mevil\n\xff.toml"
        };
        let raw = std::ffi::OsStr::from_bytes(name);
        let p = t.at(POLICY_D).join(raw);
        fs::write(&p, "").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
        let r = t.doctor();
        assert_status(&r, "paths.owner", Status::Fail);
        assert!(get(&r, "paths.owner").detail.contains("evil"));
        let text = r.to_text();
        assert!(!text.contains('\x1b') && !text.contains("evil\n"), "{text}");
        let json = serde_json::to_string(&r.to_json()).unwrap();
        assert!(
            !json.contains('\x1b') && json.contains("\\u001b[31mevil\\n"),
            "{json}"
        );
    }

    #[test]
    fn unlistable_policy_dir_is_reported() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let t = T::installed();
        t.chmod(POLICY_D, 0o000);
        let r = t.doctor();
        t.chmod(POLICY_D, 0o755);
        // A dir its owner (here: "root") cannot list is not checked.
        let d = &get(&r, "paths.owner").detail;
        assert!(d.contains("/etc/saiife/policy.d/*.toml"), "{d}");
    }

    #[test]
    fn oversized_file_is_not_fingerprinted() {
        let t = T::installed();
        let f = fs::File::options().write(true).open(t.at(UNIT)).unwrap();
        f.set_len(super::MAX_FINGERPRINT + 1).unwrap();
        let f = fs::File::options().write(true).open(t.at(BINARY)).unwrap();
        f.set_len(super::MAX_BINARY + 1).unwrap();
        let r = t.doctor();
        assert_status(&r, "files.installed", Status::Fail);
        let d = &get(&r, "files.installed").detail;
        for p in [UNIT, BINARY] {
            assert!(
                d.contains(&format!("{p}: file too large to fingerprint")),
                "{d}"
            );
        }
    }

    /// A binary may be larger than the 16 MiB other files are held to.
    #[test]
    fn large_binary_is_fingerprinted() {
        let t = T::installed();
        let mut big = crate::binary::fake_elf(None, 0, Some(false));
        big.resize(super::MAX_FINGERPRINT as usize + 4096, 0x5a);
        put_binary(&t, &big);
        let r = t.doctor();
        assert_status(&r, "files.installed", Status::Pass);
        assert_status(&r, "files.binary", Status::Pass);
        // Still compared: one byte changed is a changed file.
        let mut f = fs::File::options().write(true).open(t.at(BINARY)).unwrap();
        std::io::Seek::seek(&mut f, std::io::SeekFrom::End(-1)).unwrap();
        std::io::Write::write_all(&mut f, b"x").unwrap();
        let d = get(&t.doctor(), "files.installed").detail.clone();
        assert!(
            d.contains(&format!("{BINARY}: changed since install")),
            "{d}"
        );
    }

    /// Replaces the installed binary (and its digest on record).
    fn put_binary(t: &T, bytes: &[u8]) {
        fs::write(t.at(BINARY), bytes).unwrap();
        let sha = crate::fsops::sha256_hex(bytes);
        t.edit_installed(|i| {
            for f in &mut i.files {
                if f.kind == saiife_policy::installed::FileKind::Binary {
                    f.sha256 = Some(sha.clone());
                }
            }
        });
    }

    #[test]
    fn dynamic_binary_fails() {
        let t = T::installed();
        put_binary(
            &t,
            &crate::binary::fake_elf(Some("/lib64/ld-linux-x86-64.so.2"), 3, Some(false)),
        );
        let r = t.doctor();
        assert_status(&r, "files.binary", Status::Fail);
        assert_status(&r, "files.installed", Status::Pass);
        let d = &get(&r, "files.binary").detail;
        assert!(
            d.contains("dynamically linked (interpreter /lib64/ld-linux-x86-64.so.2)")
                && d.contains("LD_PRELOAD"),
            "{d}"
        );
        // Without an interpreter, a needed library is just as dynamic.
        put_binary(&t, &crate::binary::fake_elf(None, 1, Some(false)));
        assert_status(&t.doctor(), "files.binary", Status::Fail);
    }

    #[test]
    fn debug_build_warns_test_build_installed() {
        let t = T::installed();
        put_binary(&t, &crate::binary::fake_elf(None, 0, Some(true)));
        let r = t.doctor();
        assert_status(&r, "files.binary", Status::Warn);
        assert!(
            get(&r, "files.binary")
                .detail
                .starts_with("test build installed"),
            "{}",
            r.to_text()
        );
    }

    #[test]
    fn non_elf_or_missing_binary_fails() {
        let t = T::installed();
        put_binary(&t, b"#!/bin/sh\nexit 0\n");
        let r = t.doctor();
        assert_status(&r, "files.binary", Status::Fail);
        assert!(get(&r, "files.binary").detail.contains("not an ELF file"));
        fs::remove_file(t.at(BINARY)).unwrap();
        let r = t.doctor();
        assert_eq!(get(&r, "files.binary").detail, format!("{BINARY}: missing"));
    }

    #[cfg(target_os = "linux")]
    fn put_package(t: &T, bytes: &[u8]) {
        let p = t.at(PACKAGE_BINARY);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn package_binary_same_passes() {
        let t = T::installed();
        put_package(&t, &fs::read(t.at(BINARY)).unwrap());
        let r = t.doctor();
        assert_status(&r, "files.package", Status::Pass);
        assert_eq!(get(&r, "files.package").title, "package binary");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn package_binary_drift_warns() {
        let t = T::installed();
        let mut newer = fs::read(t.at(BINARY)).unwrap();
        newer.extend_from_slice(b"v2");
        put_package(&t, &newer);
        let r = t.doctor();
        assert_status(&r, "files.package", Status::Warn);
        assert_eq!(
            get(&r, "files.package").detail,
            "the package's /usr/libexec/saiife/saiife differs from /opt/saiife/bin/saiife: \
             run sudo /usr/libexec/saiife/saiife system install --fleet"
        );
        // A missing /opt binary is drift too.
        fs::remove_file(t.at(BINARY)).unwrap();
        assert_status(&t.doctor(), "files.package", Status::Warn);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_package_binary_no_check() {
        let t = T::installed();
        assert!(!t.doctor().checks.iter().any(|c| c.id == "files.package"));
        // Nor without installed.toml.
        put_package(&t, &fs::read(t.at(BINARY)).unwrap());
        fs::remove_file(t.at(INSTALLED)).unwrap();
        assert!(!t.doctor().checks.iter().any(|c| c.id == "files.package"));
    }

    #[test]
    fn no_agents_warns() {
        let t = T::installed();
        assert!(!t.doctor().checks.iter().any(|c| c.id == "agents"));
        t.edit_installed(|i| i.agents.clear());
        let r = t.doctor();
        assert_status(&r, "agents", Status::Warn);
        assert_eq!(
            get(&r, "agents").detail,
            "no agents listed: no agent is guarded"
        );
    }

    #[test]
    fn ancestor_owned_by_other_uid_fails() {
        let t = T::installed();
        let uid = rustix::process::getuid().as_raw() + 1;
        t.host.set(|s| {
            s.users.insert(
                "root".into(),
                UserInfo {
                    uid,
                    gid: 0,
                    home: "/root".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        let r = t.doctor();
        assert_status(&r, "paths.owner", Status::Fail);
        let d = &get(&r, "paths.owner").detail;
        for p in [
            "/opt/saiife/bin/saiife",
            "/opt/saiife/bin",
            "/opt",
            "/etc/saiife",
        ] {
            assert!(d.contains(&format!("{p}: owned by uid")), "{p}: {d}");
        }
    }

    #[test]
    fn changed_managed_file_fails() {
        let t = T::installed();
        fs::write(t.at(CLAUDE_MANAGED), "{}\n").unwrap();
        fs::remove_file(t.at(BINARY)).unwrap();
        let r = t.doctor();
        assert_status(&r, "files.installed", Status::Fail);
        let d = &get(&r, "files.installed").detail;
        assert!(
            d.contains(&format!("{CLAUDE_MANAGED}: changed since install")),
            "{d}"
        );
        assert!(d.contains(&format!("{BINARY}: missing")), "{d}");
    }

    #[test]
    fn edited_config_is_not_a_changed_file() {
        let t = T::installed();
        t.append_config("\n# an admin's note\n");
        let r = t.doctor();
        assert_status(&r, "files.installed", Status::Pass);
    }

    #[test]
    fn missing_unit_fails() {
        let t = T::installed();
        fs::remove_file(t.at(UNIT)).unwrap();
        let r = t.doctor();
        for id in ["files.installed", "files.modes"] {
            assert_status(&r, id, Status::Fail);
            let d = &get(&r, id).detail;
            assert!(d.contains(&format!("{UNIT}: missing")), "{id}: {d}");
        }
    }

    #[test]
    fn wrong_unit_mode_fails() {
        let t = T::installed();
        t.chmod(UNIT, 0o664);
        let r = t.doctor();
        assert_status(&r, "files.modes", Status::Fail);
        let d = &get(&r, "files.modes").detail;
        assert!(d.contains(&format!("{UNIT}: want root:root 0644")), "{d}");
    }

    #[test]
    fn key_dir_0750_fails() {
        let t = T::installed();
        t.chmod(KEYS_DIR, 0o750);
        let r = t.doctor();
        assert_status(&r, "keys", Status::Fail);
        let d = &get(&r, "keys").detail;
        assert!(d.contains("keys") && d.contains("0750"), "{d}");
        assert_status(&r, "files.modes", Status::Fail);
    }

    #[test]
    fn key_file_wrong_size_fails() {
        let t = T::installed();
        fs::write(t.at(AUDIT_KEY), [1u8; 31]).unwrap();
        let r = t.doctor();
        assert_status(&r, "keys", Status::Fail);
        let d = &get(&r, "keys").detail;
        assert!(d.contains("31 bytes, must be 32"), "{d}");
    }

    #[test]
    fn key_file_symlink_fails() {
        let t = T::installed();
        let real = t.at(KEYS_DIR).join("real");
        fs::rename(t.at(AUDIT_KEY), &real).unwrap();
        std::os::unix::fs::symlink(&real, t.at(AUDIT_KEY)).unwrap();
        let r = t.doctor();
        assert_status(&r, "keys", Status::Fail);
        assert!(get(&r, "keys").detail.contains("symlink"));
    }

    #[test]
    fn unreadable_key_dir_is_info_when_not_root() {
        if rustix::process::geteuid().is_root() {
            return; // root reads through the 0000 dir
        }
        let t = T::installed();
        t.chmod(STATE_DIR, 0o000);
        let r = t.doctor();
        t.chmod(STATE_DIR, 0o700);
        assert_status(&r, "keys", Status::Info);
        assert!(get(&r, "keys").detail.contains("not checked (run as root)"));
    }

    #[test]
    fn daemon_user_outside_audit_group_fails() {
        let t = T::installed();
        t.host.set(|s| {
            s.members.clear();
            s.users.get_mut(DAEMON_USER).unwrap().gid = 4_000_000;
        });
        let r = t.doctor();
        assert_status(&r, "daemon.audit_group", Status::Fail);
        assert!(get(&r, "daemon.audit_group")
            .detail
            .contains("saiife is not a member of saiife-audit"));
    }

    #[test]
    fn other_users_in_the_saiife_group_fail() {
        let t = T::installed();
        assert_status(&t.doctor(), "daemon.group", Status::Pass);
        // A user whose primary group is saiife.
        let gid = t.host.group_id(DAEMON_GROUP).unwrap();
        t.host.set(|s| {
            s.users.insert(
                "alice".into(),
                UserInfo {
                    uid: 1000,
                    gid,
                    home: "/home/alice".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        let r = t.doctor();
        assert_status(&r, "daemon.group", Status::Fail);
        assert!(get(&r, "daemon.group")
            .detail
            .starts_with("alice in group saiife"));
        // A listed member.
        let t = T::installed();
        t.host.set(|s| {
            s.members
                .insert(DAEMON_GROUP.into(), vec!["bob".to_string()]);
        });
        assert_status(&t.doctor(), "daemon.group", Status::Fail);
    }

    #[test]
    fn active_unit_passes() {
        let t = T::installed();
        t.host.set(|s| {
            s.run.insert(
                "systemctl is-active saiifed.service".into(),
                crate::host::CmdOutput {
                    status: 0,
                    stdout: "active\n".into(),
                    stderr: String::new(),
                },
            );
        });
        assert_status(&t.doctor(), "daemon.unit", Status::Pass);
    }

    #[test]
    fn unverified_agent_warns() {
        let t = T::installed();
        t.edit_installed(|i| {
            i.agents.push(ManagedAgent {
                agent: "codex".into(),
                path: CODEX_REQUIREMENTS.into(),
                sha256: "0".repeat(64),
                whole_file: false,
                created_file: true,
            })
        });
        let r = t.doctor();
        assert_status(&r, "agents.claude.label", Status::Pass);
        assert_status(&r, "agents.codex.label", Status::Warn);
        assert_eq!(get(&r, "agents.codex.label").detail, "unverified");
        assert_eq!(r.exit_code(), 2);
    }

    #[test]
    fn mcp_server_warns_with_exact_text() {
        let t = T::installed();
        t.append_config("\n[guard.mcp]\nallow_servers = [\"github\", \"jira\"]\n");
        let r = t.doctor();
        assert_status(&r, "config.valid", Status::Pass);
        for s in ["github", "jira"] {
            let c = get(&r, &format!("mcp.{s}"));
            assert_eq!(c.status, Status::Warn);
            assert_eq!(
                c.title,
                format!("MCP server {s} bypasses saiife: its requests are not brokered or limited")
            );
        }
    }

    // ---- MCP gateway checks (plan 17, task 10)

    fn mcp_ctx_checks(
        t: &T,
        status: Result<Vec<serde_json::Value>, String>,
        abi: u32,
    ) -> Vec<super::Check> {
        let dir = FixedDirectory::from_text("", "");
        let opts = DoctorOptions::default();
        let (installed, installed_error) = match read_installed(&t.layout.at(INSTALLED)) {
            Ok(i) => (i, None),
            Err(e) => (None, Some(e)),
        };
        let ctx = super::Ctx {
            layout: &t.layout,
            host: &t.host,
            dir: &dir,
            installed,
            installed_error,
            config: saiife_policy::load_and_check(&t.layout.at(CONFIG), &dir)
                .map_err(|e| e.to_string()),
            as_root: false,
            opts: &opts,
        };
        super::mcp_checks_with(&ctx, &status, abi)
    }

    fn pick<'c>(cs: &'c [super::Check], id: &str) -> &'c super::Check {
        cs.iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no check {id}"))
    }

    #[cfg(target_os = "linux")]
    fn with_server(t: &T, extra: &str) {
        t.append_config(&format!(
            "\n[mcp.fs]\ncommand = \"/usr/bin/true\"\n{extra}\n"
        ));
    }

    #[cfg(target_os = "linux")]
    fn running(tools: u64) -> Result<Vec<serde_json::Value>, String> {
        Ok(vec![
            serde_json::json!({"name":"fs","state":"running","tools":tools,"since":"t","last_error":null}),
        ])
    }

    // `[mcp.*]` is Linux only (plan 13, decision 7): a load error on macOS.
    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_server_pass_with_tool_count() {
        let t = T::installed();
        with_server(&t, "");
        let cs = mcp_ctx_checks(&t, running(3), 6);
        let c = pick(&cs, "mcp.gateway.fs");
        assert_eq!(c.status, Status::Pass, "{c:?}");
        assert_eq!(c.title, "MCP server fs is brokered (3 tools)");
        let l = pick(&cs, "mcp.landlock");
        assert_eq!(l.status, Status::Info);
        assert_eq!(l.title, "Landlock ABI 6");
        assert!(cs.iter().all(|c| c.id != "mcp.sandbox"));
        // The unbrokered warning never appears for a gateway server.
        assert!(cs.iter().all(|c| c.id != "mcp.fs"));
    }

    // `[mcp.*]` is Linux only (plan 13, decision 7): a load error on macOS.
    #[cfg(target_os = "linux")]
    #[test]
    fn gateway_server_not_running_fails() {
        let t = T::installed();
        with_server(&t, "");
        let st = Ok(vec![
            serde_json::json!({"name":"fs","state":"failed","tools":0,"since":"t","last_error":"command_not_root_owned"}),
        ]);
        let cs = mcp_ctx_checks(&t, st, 6);
        let c = pick(&cs, "mcp.gateway.fs");
        assert_eq!(c.status, Status::Fail);
        assert_eq!(
            c.title,
            "MCP server fs is not running: command_not_root_owned"
        );
        // A daemon that is down is reported, not a crash.
        let cs = mcp_ctx_checks(&t, Err("no socket".into()), 6);
        let c = pick(&cs, "mcp.gateway.fs");
        assert_eq!(c.status, Status::Fail);
        assert!(c.title.contains("daemon is unreachable"), "{c:?}");
    }

    // `[mcp.*]` is Linux only (plan 13, decision 7): a load error on macOS.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_landlock_fails_unless_off() {
        let t = T::installed();
        with_server(&t, "");
        let cs = mcp_ctx_checks(&t, running(1), 0);
        let c = pick(&cs, "mcp.gateway.fs");
        assert_eq!(c.status, Status::Fail);
        assert!(c.title.contains("sandbox unavailable"), "{c:?}");
        let t = T::installed();
        with_server(&t, "sandbox = \"off\"");
        let cs = mcp_ctx_checks(&t, running(1), 0);
        let c = pick(&cs, "mcp.gateway.fs");
        assert_eq!(c.status, Status::Warn);
        assert!(c.title.contains("sandbox is off"), "{c:?}");
        assert_eq!(pick(&cs, "mcp.landlock").title, "Landlock ABI 0");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn weaker_sandbox_warns_with_the_sandbox_wording() {
        let t = T::installed();
        with_server(&t, "");
        let cs = mcp_ctx_checks(&t, running(1), 3);
        let c = pick(&cs, "mcp.sandbox");
        assert_eq!(c.status, Status::Warn);
        assert_eq!(
            c.detail,
            crate::sandbox::Strength::from_abi(3).gap().unwrap()
        );
        assert_eq!(pick(&cs, "mcp.gateway.fs").status, Status::Pass);
    }

    /// No server under Landlock: no `mcp.sandbox` warning, whatever the ABI.
    #[cfg(target_os = "linux")]
    #[test]
    fn weaker_sandbox_not_warned_when_every_server_is_off() {
        let t = T::installed();
        with_server(&t, "sandbox = \"off\"");
        let cs = mcp_ctx_checks(&t, running(1), 3);
        assert!(cs.iter().all(|c| c.id != "mcp.sandbox"), "{cs:?}");
    }

    // `[mcp.*]` is Linux only (plan 13, decision 7): a load error on macOS.
    #[cfg(target_os = "linux")]
    #[test]
    fn npx_and_unowned_args_warn() {
        let t = T::installed();
        t.append_config(
            "\n[mcp.fs]\ncommand = \"/usr/bin/env\"\nargs = [\"npx\", \"/srv/x.js\"]\n",
        );
        let cs = mcp_ctx_checks(&t, running(1), 6);
        let c = pick(&cs, "mcp.gateway.fs");
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("npx/uvx"), "{c:?}");
        assert!(c.detail.contains("/srv/x.js is not root-owned"), "{c:?}");
    }

    #[test]
    fn allowlist_drift_warns() {
        let t = T::installed();
        let want = saiife_agents::claude::managed_mcp_settings(&[]);
        let p = t.at(CLAUDE_MCP);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, &want).unwrap();
        let cs = mcp_ctx_checks(&t, Ok(vec![]), 6);
        assert_eq!(pick(&cs, "mcp.claude.allowlist").status, Status::Pass);
        // Policy gains a server: the file no longer matches.
        t.append_config("\n[guard.mcp]\nallow_servers = [\"github\"]\n");
        let cs = mcp_ctx_checks(&t, Ok(vec![]), 6);
        let c = pick(&cs, "mcp.claude.allowlist");
        assert_eq!(c.status, Status::Warn);
        assert_eq!(
            c.title,
            "the Claude Code MCP allowlist differs from policy; run saiife system install again"
        );
        // The pinned serverCommand changed in the file is drift too.
        let want = saiife_agents::claude::managed_mcp_settings(&["github".into()]);
        fs::write(&p, want.replace("serverCommand", "serverCommandX")).unwrap();
        let cs = mcp_ctx_checks(&t, Ok(vec![]), 6);
        assert_eq!(pick(&cs, "mcp.claude.allowlist").status, Status::Warn);
        fs::write(&p, &want).unwrap();
        let cs = mcp_ctx_checks(&t, Ok(vec![]), 6);
        assert_eq!(pick(&cs, "mcp.claude.allowlist").status, Status::Pass);
        // A missing file warns, and doctor wrote nothing.
        fs::remove_file(&p).unwrap();
        let cs = mcp_ctx_checks(&t, Ok(vec![]), 6);
        assert_eq!(pick(&cs, "mcp.claude.allowlist").status, Status::Warn);
        assert!(!p.exists());
    }

    #[test]
    fn codex_gemini_restriction_info() {
        let t = T::installed();
        for a in ["codex", "gemini"] {
            t.edit_installed(|i| {
                i.agents.push(ManagedAgent {
                    agent: a.into(),
                    path: CODEX_REQUIREMENTS.into(),
                    sha256: "0".repeat(64),
                    whole_file: false,
                    created_file: true,
                })
            });
        }
        let cs = mcp_ctx_checks(&t, Ok(vec![]), 6);
        for id in ["codex", "gemini"] {
            let c = pick(&cs, &format!("mcp.{id}.restriction"));
            assert_eq!(c.status, Status::Info);
            assert!(
                c.title.starts_with("MCP servers for ")
                    && c.title.ends_with(" are restricted by the hook only"),
                "{c:?}"
            );
            assert_eq!(
                c.detail,
                "the saiife server is not brokered here (nothing pins its command); its tools are denied unless [guard.mcp] allow_servers lists \"saiife\""
            );
        }
        // Listed, any server named saiife is allowed by name on these
        // agents: `mcp.saiife` warns.
        t.append_config("\n[guard.mcp]\nallow_servers = [\"saiife\"]\n");
        let cs = mcp_ctx_checks(&t, Ok(vec![]), 6);
        for id in ["codex", "gemini"] {
            let c = pick(&cs, &format!("mcp.{id}.restriction"));
            assert_eq!(
                c.detail,
                "the saiife server is not brokered here (nothing pins its command); it is in [guard.mcp] allow_servers, so its calls are allowed by name; nothing checks which program serves them"
            );
        }
        let r = t.doctor();
        assert_status(&r, "config.valid", Status::Pass);
        let c = get(&r, "mcp.saiife");
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.title, super::SAIIFE_LISTED_UNPINNED);
        assert_eq!(
            c.title,
            "MCP server saiife is listed: on Codex and Gemini CLI any server named saiife is allowed, and nothing pins its command"
        );
    }

    /// On Claude Code alone a listed `saiife` changes nothing (the drop-in
    /// pins it by command and leaves the name out): no warning.
    #[test]
    fn listed_saiife_quiet_with_claude_only() {
        let t = T::installed();
        t.edit_installed(|i| i.agents.retain(|a| a.agent == "claude"));
        t.append_config("\n[guard.mcp]\nallow_servers = [\"saiife\"]\n");
        let r = t.doctor();
        assert_status(&r, "config.valid", Status::Pass);
        assert!(r.checks.iter().all(|c| c.id != "mcp.saiife"));
        assert!(r
            .checks
            .iter()
            .all(|c| !c.title.contains("MCP server saiife")));
    }

    const STS_SVC: &str = "\n[services.aws]\nconnector = \"aws-s3\"\nmode = \"sts\"\n\
        [services.aws.cloud]\nrole_arn = \"arn:aws:iam::123456789012:role/saiife\"\n\
        run_allow = [\"/usr/bin/aws-sync\"]\n";

    #[test]
    fn doctor_lists_every_sts_service() {
        let t = T::installed();
        t.append_config(STS_SVC);
        t.append_config(&STS_SVC.replace("services.aws", "services.aws2"));
        let r = t.doctor();
        assert_status(&r, "config.valid", Status::Pass);
        for s in ["aws", "aws2"] {
            let c = get(&r, &format!("cloud_sts.{s}"));
            assert_eq!(c.status, Status::Warn);
            assert_eq!(
                c.title,
                format!("service {s} is in STS mode: run --cloud hands a 15-minute AWS credential to agent-controlled code, which can copy it")
            );
        }
        assert!(get(&r, "cloud_sts.run_allow").detail.contains("symlink"));
    }

    #[test]
    fn doctor_silent_without_sts() {
        let t = T::installed();
        t.append_config("\n[services.aws]\nconnector = \"aws-s3\"\n");
        let r = t.doctor();
        assert!(!r.checks.iter().any(|c| c.id.starts_with("cloud_sts")));
    }

    #[test]
    fn not_installed_is_info_only() {
        let t = T::empty();
        let r = t.doctor();
        let ids: Vec<&str> = r.checks.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            ["system.supported", "install.record"],
            "{}",
            r.to_text()
        );
        let c = get(&r, "install.record");
        assert_eq!(c.status, Status::Info);
        assert_eq!(
            c.detail,
            "locked mode is not installed: developer mode checks only"
        );
        // An unsupported dev machine without locked mode is not a failure.
        assert_status(&r, "system.supported", Status::Info);
        assert_eq!(r.exit_code(), 0);
    }

    // Linux only: on macOS `system.supported` fails (locked mode needs Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_system_fails_when_installed() {
        let t = T::installed();
        fs::write(t.at("/etc/os-release"), "ID=alpine\nVERSION_ID=3.20\n").unwrap();
        let r = t.doctor();
        assert_status(&r, "system.supported", Status::Fail);
        assert!(get(&r, "system.supported").detail.contains("Alpine"));
    }

    #[test]
    fn bad_install_record_fails() {
        let t = T::installed();
        fs::write(t.at(INSTALLED), "version = 99\n").unwrap();
        let r = t.doctor();
        assert_status(&r, "install.record", Status::Fail);
    }

    #[test]
    fn vault_key_mode_reported() {
        let t = T::installed();
        let r = t.doctor();
        assert_eq!(get(&r, "vault.key").detail, "encrypted systemd credential");
        t.edit_installed(|i| {
            i.vault_key = VaultKeyMode::File;
            i.systemd = 249;
        });
        // root:saiife 0640 on systemd < 250; 0600 is now wrong.
        let r = t.doctor();
        assert_eq!(
            get(&r, "vault.key").detail,
            "plain key file (systemd < 250)"
        );
        assert_status(&r, "files.modes", Status::Fail);
        assert!(get(&r, "files.modes")
            .detail
            .contains(&format!("{VAULT_KEY}: want root:saiife 0640")));
        t.chmod(VAULT_KEY, 0o640);
        assert_status(&t.doctor(), "files.modes", Status::Pass);
    }

    #[test]
    fn audit_dir_without_setgid_fails() {
        let t = T::installed();
        t.chmod(AUDIT_DIR, 0o750);
        let r = t.doctor();
        assert_status(&r, "files.modes", Status::Fail);
        assert!(get(&r, "files.modes")
            .detail
            .contains("/var/log/saiife/audit: want saiife:saiife-audit 2750"));
    }

    #[test]
    fn pidfd_from_release() {
        assert!(super::pidfd_release("6.5.0-1-generic"));
        assert!(super::pidfd_release("7.2.4-arch1-2"));
        assert!(super::pidfd_release("6.10.3"));
        assert!(!super::pidfd_release("6.4.16"));
        assert!(!super::pidfd_release("5.15.0-91-generic"));
        assert!(!super::pidfd_release("junk"));
    }
}

/// The macOS checks, on a tree `system install` made through the fake host
/// (`Layout::under_for(.., Platform::Macos)`). Nothing here runs a macOS
/// tool: the host answers from canned output.
#[cfg(all(test, unix))]
mod macos_tests {
    use super::super::{run, DoctorOptions, Report, Status};
    use crate::authright::{RIGHT, RIGHT_PLIST};
    use crate::binary::fake_macho;
    use crate::host::{CmdOutput, UserInfo, SECURITY};
    use crate::install::macos_tests::{exit, mac_env, ok, MacEnv, PRINT};
    use crate::layout::*;
    use saiife_policy::installed::VaultKeyMode;
    use saiife_policy::FixedDirectory;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn read_line() -> String {
        format!("{SECURITY} authorizationdb read {RIGHT}")
    }

    /// A finished macOS install: the fake records chowns without applying
    /// them, so the accounts take the ids the test user's files have.
    fn installed() -> MacEnv {
        let e = mac_env();
        e.install();
        e.settle();
        // The first daemon start makes the audit key.
        let key = e.layout.at(AUDIT_KEY);
        fs::write(&key, [7u8; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let gid = rustix::process::getgid().as_raw();
        e.host.set(|s| {
            for g in [MACOS_DAEMON_GROUP, MACOS_AUDIT_GROUP] {
                s.groups.insert(g.to_string(), gid);
            }
            s.users.get_mut(MACOS_DAEMON_USER).unwrap().gid = gid;
            // launchd does not have the job yet.
            s.run
                .insert(PRINT.into(), exit(113, "Could not find service"));
        });
        e
    }

    fn doctor_with(e: &MacEnv, dir: &FixedDirectory, opts: &DoctorOptions) -> Report {
        run(&e.layout, &e.host, dir, opts)
    }

    fn doctor(e: &MacEnv) -> Report {
        doctor_with(
            e,
            &FixedDirectory::from_text("", ""),
            &DoctorOptions::default(),
        )
    }

    fn get<'r>(r: &'r Report, id: &str) -> &'r super::Check {
        r.checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no check {id} in\n{}", r.to_text()))
    }

    fn assert_status(r: &Report, id: &str, s: Status) {
        let c = get(r, id);
        assert_eq!(c.status, s, "{id}: {c:?}\n{}", r.to_text());
    }

    fn put_binary(e: &MacEnv, bytes: &[u8]) {
        let p = e.layout.at(BINARY);
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn macos_doctor_after_fake_install_fails_only_daemon_checks() {
        let e = installed();
        let r = doctor(&e);
        for id in [
            "system.supported",
            "install.record",
            "config.valid",
            "paths.owner",
            "files.installed",
            "files.binary",
            "files.modes",
            "keys",
            "daemon.audit_group",
            "daemon.group",
        ] {
            assert_status(&r, id, Status::Pass);
        }
        // No macOS lock-check recording yet: unverified on a macOS tree,
        // whichever host checks it.
        assert_status(&r, "agents.claude.label", Status::Warn);
        assert_eq!(get(&r, "agents.claude.label").detail, "unverified");
        assert_status(&r, "reauth", Status::Info);
        let fails: Vec<&str> = r
            .checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(fails, ["daemon.unit", "daemon.health"], "{}", r.to_text());
        // macOS names and launchd, not systemd.
        assert_eq!(get(&r, "system.supported").detail, "macOS 15.0, launchd");
        assert_eq!(get(&r, "daemon.unit").title, "saiifed loaded in launchd");
        assert!(get(&r, "daemon.unit").detail.contains(
            "launchctl print system/com.saiife.saiifed: exited 113: the daemon is not loaded"
        ));
        assert_eq!(
            get(&r, "daemon.audit_group").title,
            "daemon user in _saiifeaudit"
        );
        assert_status(&r, "vault.key", Status::Info);
        assert_eq!(get(&r, "vault.key").detail, "daemon key file, 0400 _saiife");
        assert_eq!(
            get(&r, "reauth").detail,
            "same-user approval is off on macOS: approvals need a second account; \
             authorization right com.saiife.approve is registered"
        );
        assert_status(&r, "mcp.landlock", Status::Info);
        assert_eq!(
            get(&r, "mcp.landlock").title,
            "MCP gateway: Linux only in this version"
        );
        assert!(!r.to_text().contains("systemd"), "{}", r.to_text());
        // A loaded job passes.
        e.host.set(|s| {
            s.run.remove(PRINT);
        });
        assert_status(&doctor(&e), "daemon.unit", Status::Pass);
        // Doctor read through the host and changed nothing.
        let st = e.host.state();
        let print = format!("launchctl print {}", crate::launchd::SERVICE);
        assert!(
            st.calls.iter().all(|c| c == &print || c == &read_line()),
            "{:?}",
            st.calls
        );
        let chowns = st.chowns.len();
        doctor(&e);
        assert_eq!(e.host.state().chowns.len(), chowns);
    }

    #[test]
    fn plist_changed_since_install_fails_the_unit() {
        let e = installed();
        e.host.set(|s| {
            s.run.remove(PRINT);
        });
        let p = e.layout.at(UNIT);
        let mut text = fs::read_to_string(&p).unwrap();
        text.push_str("<!-- edited -->\n");
        fs::write(&p, text).unwrap();
        let r = doctor(&e);
        assert_status(&r, "daemon.unit", Status::Fail);
        assert!(get(&r, "daemon.unit")
            .detail
            .contains("differs from its install record"));
        assert_status(&r, "files.installed", Status::Fail);
    }

    #[test]
    fn adhoc_binary_warns() {
        let e = installed();
        put_binary(&e, &fake_macho(Some((true, true, false))));
        let r = doctor(&e);
        assert_status(&r, "files.binary", Status::Warn);
        assert!(get(&r, "files.binary").detail.contains("ad-hoc signature"));
        // Signed without the ad-hoc flag but with no CMS blob.
        put_binary(&e, &fake_macho(Some((false, true, false))));
        let r = doctor(&e);
        assert_status(&r, "files.binary", Status::Warn);
        assert!(get(&r, "files.binary")
            .detail
            .contains("no CMS signature present"));
    }

    #[test]
    fn no_runtime_binary_fails() {
        let e = installed();
        put_binary(&e, &fake_macho(Some((false, false, true))));
        let r = doctor(&e);
        assert_status(&r, "files.binary", Status::Fail);
        assert!(get(&r, "files.binary")
            .detail
            .contains("without the hardened runtime"));
        // Ad-hoc without the runtime is a failure too.
        put_binary(&e, &fake_macho(Some((true, false, false))));
        assert_status(&doctor(&e), "files.binary", Status::Fail);
        put_binary(&e, &fake_macho(None));
        let r = doctor(&e);
        assert_status(&r, "files.binary", Status::Fail);
        assert!(get(&r, "files.binary").detail.contains("not code-signed"));
        // An ELF file is no macOS binary.
        put_binary(&e, &crate::binary::fake_elf(None, 0, Some(false)));
        assert_status(&doctor(&e), "files.binary", Status::Fail);
    }

    #[test]
    fn auth_right_missing_warns_reauth_unavailable() {
        let e = installed();
        e.host.set(|s| {
            s.run.remove(&read_line());
        });
        let r = doctor(&e);
        assert_status(&r, "reauth", Status::Warn);
        let d = &get(&r, "reauth").detail;
        assert!(
            d.contains(REAUTH_UNAVAILABLE) && d.contains(super::MAC_SAME_USER_OFF),
            "{d}"
        );
        assert!(d.contains("is missing"), "{d}");
        e.host.set(|s| {
            s.run.insert(read_line(), exit(1, "no such right"));
        });
        assert_status(&doctor(&e), "reauth", Status::Warn);
    }

    #[test]
    fn auth_right_with_timeout_nonzero_warns() {
        let e = installed();
        let weak = RIGHT_PLIST.replace(
            "<key>timeout</key>\n\t<integer>0</integer>",
            "<key>timeout</key>\n\t<integer>300</integer>",
        );
        assert_ne!(weak, RIGHT_PLIST);
        e.host.set(|s| {
            s.run.insert(read_line(), ok(&weak));
        });
        let r = doctor(&e);
        assert_status(&r, "reauth", Status::Warn);
        let d = &get(&r, "reauth").detail;
        assert!(
            d.contains(REAUTH_UNAVAILABLE) && d.contains("weakened"),
            "{d}"
        );
        // Shared across sessions, or not the session owner's.
        for (from, to) in [
            (
                "<key>shared</key>\n\t<false/>",
                "<key>shared</key>\n\t<true/>",
            ),
            (
                "<key>session-owner</key>\n\t<true/>",
                "<key>session-owner</key>\n\t<false/>",
            ),
        ] {
            let weak = RIGHT_PLIST.replace(from, to);
            assert_ne!(weak, RIGHT_PLIST, "{from}");
            e.host.set(|s| {
                s.run.insert(read_line(), ok(&weak));
            });
            assert_status(&doctor(&e), "reauth", Status::Warn);
        }
        // Doctor only ever reads the right.
        let writes: Vec<String> = e
            .host
            .state()
            .calls
            .into_iter()
            .filter(|c| c.contains("write") || c.contains("remove"))
            .collect();
        assert!(writes.is_empty(), "{writes:?}");
    }

    #[test]
    fn claude_mdm_profile_warns() {
        let e = installed();
        assert!(doctor(&e)
            .checks
            .iter()
            .all(|c| c.id != "agents.claude.mdm"));
        let p = e.layout.at(CLAUDE_MDM_PROFILE);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "<plist/>").unwrap();
        let r = doctor(&e);
        assert_status(&r, "agents.claude.mdm", Status::Warn);
        assert_eq!(
            get(&r, "agents.claude.mdm").detail,
            "an MDM profile sets Claude Code managed settings \
             (/Library/Managed Preferences/com.anthropic.claudecode.plist); \
             Claude Code may ignore saiife's managed-settings.d drop-in"
        );
    }

    /// An agent user `agent` in the fake host and the directory, checked as
    /// root (`--user agent`).
    fn with_agent(e: &MacEnv) -> (FixedDirectory, DoctorOptions) {
        let home = std::path::PathBuf::from("/Users/agent");
        fs::create_dir_all(e.layout.try_at(&home).unwrap()).unwrap();
        e.host.set(|s| {
            s.euid = 0;
            s.users.insert(
                "agent".into(),
                UserInfo {
                    uid: 501,
                    gid: 20,
                    home: home.clone(),
                    shell: "/bin/zsh".into(),
                },
            );
            // `admin` as on a Mac (gid 80, no members). Unnamed, the fake
            // gives it the caller's gid, which is 20 (staff) on a Mac
            // runner: the agent's primary group, so "an admin".
            s.groups.insert("admin".into(), 80);
        });
        (
            FixedDirectory::from_text("agent:x:501:20::/Users/agent:/bin/zsh\n", ""),
            DoctorOptions {
                user: Some("agent".into()),
                home: None,
            },
        )
    }

    #[test]
    fn admin_agent_user_warns() {
        let e = installed();
        let (dir, opts) = with_agent(&e);
        let r = doctor_with(&e, &dir, &opts);
        assert_status(&r, "user.agent.root", Status::Pass);
        assert_status(&r, "user.agent.passwd", Status::Pass);
        assert_eq!(
            get(&r, "user.agent.passwd").title,
            "user agent in Directory Services"
        );
        e.host.set(|s| {
            s.groups.insert("admin".into(), 80);
            s.members.insert("admin".into(), vec!["agent".into()]);
        });
        let r = doctor_with(&e, &dir, &opts);
        assert_status(&r, "user.agent.root", Status::Warn);
        assert_eq!(
            get(&r, "user.agent.root").detail,
            "agent user agent is an admin: sudo needs its password"
        );
        // NOPASSWD stays a failure.
        fs::create_dir_all(e.layout.at("/usr/bin")).unwrap();
        fs::write(e.layout.at(crate::host::SUDO), "").unwrap();
        e.host.set(|s| {
            s.run.insert(
                "/usr/bin/sudo -n -l -U agent".into(),
                CmdOutput {
                    status: 0,
                    stdout: "(ALL) NOPASSWD: ALL".into(),
                    stderr: String::new(),
                },
            );
        });
        let r = doctor_with(&e, &dir, &opts);
        assert_status(&r, "user.agent.root", Status::Fail);
        assert!(get(&r, "user.agent.root").detail.contains("NOPASSWD"));
        assert!(get(&r, "user.agent.root").detail.contains("is an admin"));
    }

    #[test]
    fn macos_agent_user_checks_have_no_linux_leftovers() {
        let e = installed();
        let (dir, opts) = with_agent(&e);
        let r = doctor_with(&e, &dir, &opts);
        assert_status(&r, "user.agent.egress", Status::Info);
        assert_eq!(
            get(&r, "user.agent.egress").detail,
            "macOS has no per-uid firewall in pf; the egress recipe is Linux only"
        );
        assert!(r.checks.iter().all(|c| c.id != "proc.hidepid"));
        assert!(
            r.checks.iter().all(|c| !c.detail.contains("/proc")),
            "{}",
            r.to_text()
        );
    }

    #[test]
    fn macos_peer_identity_info() {
        let e = installed();
        let r = doctor(&e);
        assert_status(&r, "peer.pidfd", Status::Info);
        assert_eq!(
            get(&r, "peer.pidfd").detail,
            "LOCAL_PEERCRED and LOCAL_PEERPID (the pid is used for attribution only)"
        );
    }

    #[test]
    fn missing_audit_group_warns_that_month_files_get_wheel() {
        let e = installed();
        e.host.set(|s| {
            s.groups.remove(MACOS_AUDIT_GROUP);
        });
        let r = doctor(&e);
        assert_status(&r, "daemon.audit_group", Status::Warn);
        assert_eq!(
            get(&r, "daemon.audit_group").detail,
            "group _saiifeaudit does not exist: the audit month files end up in group wheel"
        );
        // The audit dir is not reported as a failure of its own.
        assert_status(&r, "files.modes", Status::Pass);
    }

    #[test]
    fn audit_dir_in_another_group_warns() {
        let e = installed();
        let gid = rustix::process::getgid().as_raw();
        e.host.set(|s| {
            s.groups.insert(MACOS_AUDIT_GROUP.into(), gid + 1);
            s.members
                .insert(MACOS_AUDIT_GROUP.into(), vec![MACOS_DAEMON_USER.into()]);
        });
        let r = doctor(&e);
        assert_status(&r, "daemon.audit_group", Status::Warn);
        assert!(get(&r, "daemon.audit_group")
            .detail
            .contains("not _saiifeaudit: the audit month files end up in group wheel"));
        // The daemon user outside the group is still a failure.
        e.host.set(|s| {
            s.members.clear();
            s.users.get_mut(MACOS_DAEMON_USER).unwrap().gid = gid;
        });
        assert_status(&doctor(&e), "daemon.audit_group", Status::Fail);
    }

    #[test]
    fn vault_key_is_the_daemon_file() {
        let e = installed();
        let key = e.layout.at(VAULT_KEY);
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o7777,
            0o400
        );
        // Wrong mode is named with the macOS path.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        let r = doctor(&e);
        assert_status(&r, "files.modes", Status::Fail);
        assert!(
            get(&r, "files.modes")
                .detail
                .contains("/var/db/saiife/keys/vault.key: want _saiife:_saiife 0400"),
            "{}",
            get(&r, "files.modes").detail
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
        assert_status(&doctor(&e), "files.modes", Status::Pass);
        // A Linux key mode on a Mac is wrong.
        let p = e.layout.at(INSTALLED);
        let mut i = saiife_policy::installed::read_installed(&p)
            .unwrap()
            .unwrap();
        i.vault_key = VaultKeyMode::Credential;
        saiife_policy::installed::write_installed(&p, &i).unwrap();
        assert_status(&doctor(&e), "vault.key", Status::Fail);
    }

    #[test]
    fn macos_doctor_json_exit_codes() {
        let e = installed();
        // Daemon checks fail: exit 2.
        let r = doctor(&e);
        assert_eq!(r.exit_code(), 2);
        let j = r.to_json();
        assert_eq!(j["exit"], 2);
        assert!(j["checks"].as_array().unwrap().len() > 10);
        // Only a warning left: exit 1.
        let p = e.layout.at(CLAUDE_MDM_PROFILE);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "<plist/>").unwrap();
        let mut warned = Report {
            checks: r
                .checks
                .iter()
                .filter(|c| c.status != Status::Fail)
                .cloned()
                .collect(),
        };
        warned
            .checks
            .push(get(&doctor(&e), "agents.claude.mdm").clone());
        assert_eq!(warned.exit_code(), 1);
        assert_eq!(warned.to_json()["exit"], 1);
        // Nothing installed: developer mode, exit 0.
        let r = doctor(&mac_env());
        assert_eq!(r.exit_code(), 0, "{}", r.to_text());
        assert_eq!(r.to_json()["exit"], 0);
        assert_status(&r, "install.record", Status::Info);
    }
}
