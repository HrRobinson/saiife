//! `saiife secret import --user <name>` (spec §6.6, §12 step 3): moves the
//! plaintext credentials found by the doctor's scan (§6.16) of an agent
//! user's home and project roots into the vault, then removes them from the
//! file they were in. Linux, admin only.
//!
//! For each credential the admin is asked `store as <name>? [y/N/e(dit
//! name)]`; `--yes-to <path>` answers yes for one file, and with no
//! terminal everything else is skipped and listed. A credential value is
//! never printed: the prompt shows the path, what was found and a name.
//!
//! The file is changed only after the daemon acked the add *and* wrote a
//! backup of the original bytes (it keeps them 7 days). The rewrite keeps
//! the owner and mode, goes through a temp file and a rename in the same
//! dir, and never follows a symlink: every directory below the home (or the
//! project root) is opened `O_NOFOLLOW`, and the file must still be the
//! regular file (same device and inode, same bytes) that was read.
//!
//! Only a file owned by the agent user with one link is read or changed
//! (as root, a link or a file of someone else's would be read or rewritten
//! on the agent's behalf). A secret is stored only for a known service (a
//! configured one or a built-in connector): the guess, `--service
//! <path>=<svc>` or `s(ervice)` at the prompt; without one it is skipped.
//!
//! Cloud and kube files are listed and never touched (plan 15).

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use rustix::fs::{fstat, openat, renameat, unlinkat, AtFlags, FileType, Mode, OFlags, CWD};
use saiife_system::doctor::secrets::{scan_report, Finding, CREDENTIAL_KEYS, SYMLINK};
use saiife_system::host::{Host, RealHost};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::secret_cmd::linux::{call, Stop};
use crate::text::sanitize;

/// The largest file imported: its backup travels base64 in one frame.
pub const MAX_SOURCE_BYTES: u64 = 700 * 1024;
pub const CLOUD: &str = "cloud credentials come with plan 15; remove or rotate by hand";
const MANUAL: &str = "no importer for this file in this version; remove or rotate by hand";
const UNREADABLE: &str = "no credential the importer can read; remove or rotate by hand";

pub struct ImportArgs {
    pub user: String,
    pub projects: Vec<PathBuf>,
    pub yes_to: Vec<PathBuf>,
    /// `<path>=<service>`.
    pub services: Vec<String>,
    /// The test seam for the home (debug builds only; `None` otherwise).
    pub home: Option<PathBuf>,
}

/// The services a secret may be stored for: the configured ones and the
/// built-in connector ids.
fn known_services(config: &Path) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = saiife_broker::manifest::builtin()
        .iter()
        .map(|m| m.id.clone())
        .collect();
    if let Ok(l) = saiife_policy::load_system(config) {
        out.extend(l.config.services.keys().cloned());
    }
    out
}

/// `--service <path>=<svc>` entries, checked.
fn parse_services(
    raw: &[String],
    known: &BTreeSet<String>,
) -> Result<Vec<(PathBuf, String)>, Stop> {
    let mut out = Vec::new();
    for r in raw {
        let Some((p, s)) = r.rsplit_once('=') else {
            return Err(Stop::Refused("--service takes <path>=<service>".into()));
        };
        let p = PathBuf::from(p);
        if !p.is_absolute() {
            return Err(Stop::Refused("--service takes an absolute path".into()));
        }
        if !known.contains(s) {
            let list: Vec<&str> = known.iter().map(String::as_str).collect();
            return Err(Stop::Refused(format!(
                "--service: unknown service {} (known: {})",
                sanitize(s),
                list.join(", ")
            )));
        }
        out.push((p, s.to_string()));
    }
    Ok(out)
}

/// The agent user's uid and home: `/etc/passwd`, else NSS for the uid.
/// Test seams, debug builds only: `--home` and `SAIIFE_IMPORT_TARGET_UID`.
fn target(a: &ImportArgs, user: &str) -> Result<(u32, PathBuf), Stop> {
    use saiife_policy::Directory as _;
    let info = RealHost.user(&a.user);
    let uid = info
        .as_ref()
        .map(|u| u.uid)
        .or_else(|| saiife_policy::Getent.user(&a.user).map(|u| u.uid));
    #[cfg(debug_assertions)]
    let uid = std::env::var("SAIIFE_IMPORT_TARGET_UID")
        .ok()
        .and_then(|v| v.parse().ok())
        .or(uid);
    let home = a.home.clone().or(info.map(|u| u.home));
    match (uid, home) {
        (Some(uid), Some(home)) if home.is_absolute() => Ok((uid, home)),
        (Some(_), Some(_)) => Err(Stop::Refused(format!(
            "the home of {user} is not an absolute path"
        ))),
        _ => Err(Stop::Refused(format!("no user {user} in /etc/passwd"))),
    }
}

/// What kind of file a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Cloud,
    Symlink,
    Manual,
    Env,
    GitCredentials,
    GhHosts,
    Npmrc,
    VaultToken,
}

fn classify(home: &Path, f: &Finding) -> Class {
    if f.what == SYMLINK {
        return Class::Symlink;
    }
    match f.path.strip_prefix(home).ok().and_then(Path::to_str) {
        Some(
            ".aws/credentials"
            | ".config/gcloud"
            | ".azure"
            | ".kube/config"
            | ".docker/config.json",
        ) => Class::Cloud,
        Some(".git-credentials") => Class::GitCredentials,
        Some(".config/gh/hosts.yml") => Class::GhHosts,
        Some(".npmrc") => Class::Npmrc,
        Some(".vault-token") => Class::VaultToken,
        _ if f.what.starts_with("is an environment file")
            && f.path
                .file_name()
                .is_some_and(|n| n.as_bytes().starts_with(b".env")) =>
        {
            Class::Env
        }
        _ => Class::Manual,
    }
}

/// One credential in a file.
struct Cand {
    /// What it is, without the value (`credential in GITHUB_TOKEN`).
    what: String,
    name: String,
    /// The guessed connector (only a built-in id).
    service: Option<&'static str>,
    value: Zeroizing<String>,
    /// The line it is on; `None` when the whole file is the secret.
    line: Option<usize>,
}

pub fn run(config: &Path, a: ImportArgs) -> Result<(), Stop> {
    let user = sanitize(&a.user);
    let (target_uid, home) = target(&a, &user)?;
    if a.projects.iter().any(|p| !p.is_absolute()) {
        return Err(Stop::Refused("--project takes an absolute path".into()));
    }
    if a.yes_to.iter().any(|p| !p.is_absolute()) {
        return Err(Stop::Refused("--yes-to takes an absolute path".into()));
    }
    // A project root outside the home is opened as given: it may not be a
    // symlink (the agent may own it and point it anywhere).
    for p in a.projects.iter().filter(|p| !p.starts_with(&home)) {
        if std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(Stop::Refused(format!(
                "--project {} is a symlink; give the real path",
                sanitize(&p.display().to_string())
            )));
        }
    }
    let known = known_services(config);
    let services = parse_services(&a.services, &known)?;
    // Admin first: nothing is read before the daemon says so. A vault that
    // cannot be read still lets the scan run; each add then says why.
    let mut taken: BTreeSet<String> = match call(config, "secret.list", Map::new()) {
        Ok(l) => l
            .get("secrets")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        Err(Stop::Refused(m)) => {
            eprintln!("saiife: warning: {m}");
            BTreeSet::new()
        }
        Err(e) => return Err(e),
    };
    let scan = scan_report(&home, &a.projects);
    for r in &scan.incomplete {
        outln!("note: not fully scanned: {}", sanitize(r));
    }
    if scan.findings.is_empty() {
        outln!("no plaintext credentials found for {user}");
    }
    let mut run = Run {
        config,
        user: &user,
        tty: std::io::stdin().is_terminal(),
        taken: &mut taken,
        known: &known,
        home: &home,
        target_uid,
        failed: 0,
        skipped: Vec::new(),
    };
    let mut down = None;
    for f in &scan.findings {
        let disp = sanitize(&f.path.display().to_string());
        let what = sanitize(&f.what);
        let class = classify(&home, f);
        match class {
            Class::Cloud => outln!("{disp}: {what}: {CLOUD}"),
            Class::Symlink => outln!("{disp}: {what}; not imported"),
            Class::Manual => outln!("{disp}: {what}: {MANUAL}"),
            _ => {
                let Some(base) = base_for(&home, &a.projects, &f.path) else {
                    outln!("{disp}: {what}: {MANUAL}");
                    continue;
                };
                let yes = a.yes_to.iter().any(|p| p == &f.path);
                let service = services
                    .iter()
                    .find(|(p, _)| p == &f.path)
                    .map(|(_, s)| s.clone());
                if let Err(m) = run.file(f, class, &base, yes, service) {
                    down = Some(m);
                    break;
                }
            }
        }
    }
    if !run.skipped.is_empty() {
        outln!("skipped:");
        for s in &run.skipped {
            outln!("  {s}");
        }
    }
    if let Some(m) = down {
        return Err(Stop::Unavailable(m));
    }
    match run.failed {
        0 => Ok(()),
        n => Err(Stop::Refused(format!("{n} credential(s) not imported"))),
    }
}

/// The base a finding is opened from: the home, or the (longest) project
/// root it lies below.
fn base_for(home: &Path, projects: &[PathBuf], path: &Path) -> Option<PathBuf> {
    if path.starts_with(home) {
        return Some(home.to_path_buf());
    }
    projects
        .iter()
        .filter(|p| path.starts_with(p))
        .max_by_key(|p| p.as_os_str().len())
        .cloned()
}

struct Run<'a> {
    config: &'a Path,
    user: &'a str,
    tty: bool,
    taken: &'a mut BTreeSet<String>,
    known: &'a BTreeSet<String>,
    home: &'a Path,
    target_uid: u32,
    failed: usize,
    skipped: Vec<String>,
}

impl Run<'_> {
    /// One importable file. `Err` only when the daemon cannot be reached.
    fn file(
        &mut self,
        f: &Finding,
        class: Class,
        base: &Path,
        yes: bool,
        service: Option<String>,
    ) -> Result<(), String> {
        let disp = sanitize(&f.path.display().to_string());
        let what = sanitize(&f.what);
        let rel = f.path.strip_prefix(base).unwrap_or(&f.path);
        let src = match Source::open(base, rel, self.target_uid, base == self.home) {
            Ok(s) => s,
            Err(m) => {
                outln!("{disp}: not imported: {m}");
                self.failed += 1;
                return Ok(());
            }
        };
        let cands = parse(class, &src.bytes, self.user);
        if cands.is_empty() {
            outln!("{disp}: {what}: {UNREADABLE}");
            return Ok(());
        }
        let mut chosen: Vec<(Cand, String, String)> = Vec::new();
        for c in cands {
            let name = unique(&c.name, self.taken);
            let svc = service.clone().or_else(|| {
                c.service
                    .filter(|s| self.known.contains(*s))
                    .map(str::to_string)
            });
            let q = Question {
                disp: &disp,
                what: &c.what,
                yes,
                tty: self.tty,
                taken: self.taken,
                known: self.known,
            };
            match q.ask(name, svc) {
                Answer::Yes(n, s) => {
                    self.taken.insert(n.clone());
                    chosen.push((c, n, s));
                }
                Answer::No => outln!("{disp}: {}: left in place", c.what),
                Answer::NoTty => self.skipped.push(format!(
                    "{disp}: {} (no terminal; pass --yes-to <path>)",
                    c.what
                )),
                Answer::NoService => self.skipped.push(format!(
                    "{disp}: {} (no known service; pass --service <path>=<service>)",
                    c.what
                )),
            }
        }
        if chosen.is_empty() {
            return Ok(());
        }
        let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&src.bytes[..]));
        let source = f.path.to_string_lossy().into_owned();
        let mut stored: Vec<&(Cand, String, String)> = Vec::new();
        let mut backed = false;
        let mut down = None;
        for pair in &chosen {
            let (c, n, service) = pair;
            let mut args = Map::new();
            args.insert("name".into(), json!(n));
            args.insert("kind".into(), json!("token"));
            args.insert("fields".into(), json!({ "token": c.value.as_str() }));
            args.insert("allowed_services".into(), json!([service]));
            // The backup goes with every add until one is acked.
            if !backed {
                args.insert(
                    "backup".into(),
                    json!({ "path": source, "bytes_b64": b64.as_str() }),
                );
            }
            match call(self.config, "secret.add", args) {
                Ok(ans) => {
                    if !backed && ans.get("backup") != Some(&Value::Bool(true)) {
                        outln!(
                            "{disp}: stored {n}, but the daemon kept no backup; the file is not changed"
                        );
                        self.failed += 1;
                        continue;
                    }
                    backed = true;
                    stored.push(pair);
                }
                Err(Stop::Unavailable(m)) => {
                    down = Some(m);
                    break;
                }
                Err(Stop::Unrecorded(m)) => {
                    outln!(
                        "{disp}: stored {n}, but {}; the file is not changed, remove it by hand",
                        sanitize(&m)
                    );
                    self.failed += 1;
                }
                Err(Stop::Refused(m) | Stop::Forbidden(m) | Stop::NotFound(m)) => {
                    outln!("{disp}: {}: not stored: {}", c.what, sanitize(&m));
                    self.failed += 1;
                }
            }
        }
        if !stored.is_empty() {
            let whole = stored.iter().any(|(c, _, _)| c.line.is_none());
            let gone: BTreeSet<usize> = stored.iter().filter_map(|(c, _, _)| c.line).collect();
            let new = if whole {
                Zeroizing::new(Vec::new())
            } else {
                without_lines(&src.bytes, &gone)
            };
            let changed = src.rewrite(&new);
            for (c, n, service) in &stored {
                match &changed {
                    Ok(()) => outln!("stored {n} from {disp} ({}); removed it from the file", c.what),
                    Err(m) => outln!(
                        "stored {n} from {disp} ({}), but the file was not changed: {m}; remove it by hand",
                        c.what
                    ),
                }
                outln!("next: saiife connect {service} --secret {n}");
                outln!("rotate this credential: it was readable by {}", self.user);
            }
            if changed.is_err() {
                self.failed += stored.len();
            }
        }
        match down {
            Some(m) => Err(m),
            None => Ok(()),
        }
    }
}

enum Answer {
    /// Store it under this name for this service.
    Yes(String, String),
    No,
    NoTty,
    /// `--yes-to`, but no known service for it.
    NoService,
}

struct Question<'a> {
    disp: &'a str,
    what: &'a str,
    yes: bool,
    tty: bool,
    taken: &'a BTreeSet<String>,
    known: &'a BTreeSet<String>,
}

/// One line from stdin, trimmed; `None` at the end.
fn read_answer(label: &str) -> Option<String> {
    eprint!("{label}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

impl Question<'_> {
    /// `--yes-to`, else the terminal, else skipped. A secret is never
    /// stored without a known service.
    fn ask(&self, mut name: String, mut service: Option<String>) -> Answer {
        if self.yes {
            return match service {
                Some(s) => Answer::Yes(name, s),
                None => Answer::NoService,
            };
        }
        if !self.tty {
            return Answer::NoTty;
        }
        loop {
            let svc = match &service {
                Some(s) => format!("service {s}"),
                None => "no service yet".to_string(),
            };
            let Some(a) = read_answer(&format!(
                "{}: {}\nstore as {name} ({svc})? [y/N/e(dit name)/s(ervice)] ",
                self.disp, self.what
            )) else {
                return Answer::No;
            };
            match a.as_str() {
                "y" | "Y" | "yes" => match &service {
                    Some(s) => return Answer::Yes(name, s.clone()),
                    None => eprintln!("saiife: choose a service first (s)"),
                },
                "e" | "E" => {
                    let Some(n) = read_answer("name: ") else {
                        return Answer::No;
                    };
                    if !valid_name(&n) {
                        eprintln!("saiife: a name is a-z, 0-9, `.`, `_`, `-`; up to 64 characters");
                    } else if self.taken.contains(&n) {
                        eprintln!("saiife: secret {n} exists");
                    } else {
                        name = n;
                    }
                }
                "s" | "S" => {
                    let Some(s) = read_answer("service: ") else {
                        return Answer::No;
                    };
                    if self.known.contains(&s) {
                        service = Some(s);
                    } else {
                        let list: Vec<&str> = self.known.iter().map(String::as_str).collect();
                        eprintln!(
                            "saiife: unknown service {} (known: {})",
                            sanitize(&s),
                            list.join(", ")
                        );
                    }
                }
                _ => return Answer::No,
            }
        }
    }
}

// ---- names ----

/// The vault's name rule.
fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..].iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// `<user>-<part>` made into a valid name.
fn suggest(user: &str, part: &str) -> String {
    let mut out = String::new();
    for c in format!("{user}-{part}").chars() {
        let c = c.to_ascii_lowercase();
        let c = if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' {
            c
        } else {
            '-'
        };
        if c == '-' && (out.is_empty() || out.ends_with('-')) {
            continue;
        }
        out.push(c);
    }
    let mut out: String = out
        .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .chars()
        .take(64)
        .collect();
    while out.ends_with('-') {
        out.pop();
    }
    if valid_name(&out) {
        out
    } else {
        "imported".into()
    }
}

/// `name`, or `name-2`, `name-3`... when taken.
fn unique(name: &str, taken: &BTreeSet<String>) -> String {
    if !taken.contains(name) {
        return name.to_string();
    }
    for n in 2..1000 {
        let suffix = format!("-{n}");
        let base: String = name.chars().take(64 - suffix.len()).collect();
        let cand = format!("{base}{suffix}");
        if !taken.contains(&cand) {
            return cand;
        }
    }
    name.to_string()
}

/// The connector a host is for: exact names only.
fn guess_host(host: &str) -> Option<&'static str> {
    let h = host.to_ascii_lowercase();
    let h = h.rsplit_once(':').map_or(h.as_str(), |(h, _)| h);
    if h == "github.com" || h.ends_with(".github.com") {
        Some("github")
    } else if h.ends_with(".myshopify.com") {
        Some("shopify")
    } else if h == "api.hubapi.com" {
        Some("hubspot")
    } else {
        None
    }
}

/// The connector an environment variable name is likely for.
fn guess(hay: &str) -> Option<&'static str> {
    let h = hay.to_ascii_lowercase();
    if h.contains("github") || h.starts_with("gh_") {
        Some("github")
    } else if h.contains("shopify") {
        Some("shopify")
    } else if h.contains("hubspot") {
        Some("hubspot")
    } else {
        None
    }
}

// ---- parsing ----

fn parse(class: Class, bytes: &[u8], user: &str) -> Vec<Cand> {
    let lines: Vec<&[u8]> = bytes.split_inclusive(|&b| b == b'\n').collect();
    match class {
        Class::Env => parse_env(&lines, user),
        Class::GitCredentials => parse_git(&lines, user),
        Class::GhHosts => parse_gh(&lines, user),
        Class::Npmrc => parse_npmrc(&lines, user),
        Class::VaultToken => parse_vault(bytes, user),
        _ => Vec::new(),
    }
}

fn is_credential_key(k: &str) -> bool {
    let up = k.to_ascii_uppercase();
    CREDENTIAL_KEYS.iter().any(|c| up.contains(c))
}

/// Set and not just a reference to a variable (`$NAME`, `${NAME}`).
fn is_plain_value(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    let var = |n: &str| !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    let reference = match s.strip_prefix('$') {
        Some(r) => match r.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
            Some(inner) => var(inner),
            None => var(r),
        },
        None => false,
    };
    !reference
}

/// A value without its quotes; `None` for an unclosed quote.
fn unquote(v: &str, comments: bool) -> Option<Zeroizing<String>> {
    let v = v.trim();
    for q in ['"', '\''] {
        if let Some(rest) = v.strip_prefix(q) {
            return rest
                .strip_suffix(q)
                .map(|inner| Zeroizing::new(inner.to_string()));
        }
    }
    let v = match v.find(" #") {
        Some(i) if comments => v[..i].trim_end(),
        _ => v,
    };
    Some(Zeroizing::new(v.to_string()))
}

fn text(line: &[u8]) -> Option<&str> {
    std::str::from_utf8(line).ok()
}

fn parse_env(lines: &[&[u8]], user: &str) -> Vec<Cand> {
    let mut out = Vec::new();
    for (i, raw) in lines.iter().enumerate() {
        let Some(l) = text(raw) else { continue };
        let l = l.trim();
        if l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").map(str::trim_start).unwrap_or(l);
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let key_ok = !k.is_empty()
            && !k.as_bytes()[0].is_ascii_digit()
            && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !key_ok || !is_credential_key(k) {
            continue;
        }
        let Some(value) = unquote(v, true).filter(|v| is_plain_value(v)) else {
            continue;
        };
        out.push(Cand {
            what: format!("credential in {k}"),
            name: suggest(user, k),
            service: guess(k),
            value,
            line: Some(i),
        });
    }
    out
}

/// `%XX` decoded; `None` when not UTF-8.
fn percent_decode(s: &str) -> Option<Zeroizing<String>> {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out.to_vec()).ok().map(Zeroizing::new)
}

fn parse_git(lines: &[&[u8]], user: &str) -> Vec<Cand> {
    let mut out = Vec::new();
    for (i, raw) in lines.iter().enumerate() {
        let Some(l) = text(raw) else { continue };
        let Some((_, rest)) = l.trim().split_once("://") else {
            continue;
        };
        let authority = rest.split('/').next().unwrap_or("");
        let Some((userinfo, host)) = authority.rsplit_once('@') else {
            continue;
        };
        let Some((_, pass)) = userinfo.split_once(':') else {
            continue;
        };
        let Some(value) = percent_decode(pass).filter(|v| !v.is_empty()) else {
            continue;
        };
        let host = sanitize(host);
        out.push(Cand {
            what: format!("git credential for {host}"),
            name: suggest(user, &format!("git-{host}")),
            service: guess_host(&host),
            value,
            line: Some(i),
        });
    }
    out
}

fn parse_gh(lines: &[&[u8]], user: &str) -> Vec<Cand> {
    let mut out = Vec::new();
    let mut host = String::from("github.com");
    for (i, raw) in lines.iter().enumerate() {
        let Some(l) = text(raw) else { continue };
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if !l.starts_with([' ', '\t']) {
            if let Some(h) = t.strip_suffix(':') {
                host = sanitize(h.trim_matches(['"', '\'']));
            }
            continue;
        }
        let Some(v) = t.strip_prefix("oauth_token:") else {
            continue;
        };
        let Some(value) = unquote(v, true).filter(|v| !v.is_empty()) else {
            continue;
        };
        out.push(Cand {
            what: format!("GitHub CLI token for {host}"),
            name: suggest(user, &format!("gh-{host}")),
            service: guess_host(&host),
            value,
            line: Some(i),
        });
    }
    out
}

fn parse_npmrc(lines: &[&[u8]], user: &str) -> Vec<Cand> {
    let mut out = Vec::new();
    for (i, raw) in lines.iter().enumerate() {
        let Some(l) = text(raw) else { continue };
        let t = l.trim();
        if t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let Some(reg) = k.strip_suffix("_authToken") else {
            continue;
        };
        let Some(value) = unquote(v, false).filter(|v| is_plain_value(v)) else {
            continue;
        };
        let reg = reg.trim_start_matches('/').trim_end_matches([':', '/']);
        let host = match reg.split('/').next() {
            Some(h) if !h.is_empty() => sanitize(h),
            _ => "default".to_string(),
        };
        out.push(Cand {
            what: format!("npm auth token for {host}"),
            name: suggest(user, &format!("npm-{host}")),
            service: None,
            value,
            line: Some(i),
        });
    }
    out
}

fn parse_vault(bytes: &[u8], user: &str) -> Vec<Cand> {
    let Ok(t) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let t = t.trim();
    if t.is_empty() || t.contains('\n') {
        return Vec::new();
    }
    vec![Cand {
        what: "Vault token".into(),
        name: suggest(user, "vault-token"),
        service: None,
        value: Zeroizing::new(t.to_string()),
        line: None,
    }]
}

fn without_lines(bytes: &[u8], gone: &BTreeSet<usize>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    for (i, l) in bytes.split_inclusive(|&b| b == b'\n').enumerate() {
        if !gone.contains(&i) {
            out.extend_from_slice(l);
        }
    }
    out
}

// ---- the file ----

/// A file read through a directory handle reached without a symlink.
struct Source {
    dir: OwnedFd,
    name: OsString,
    target_uid: u32,
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    bytes: Zeroizing<Vec<u8>>,
}

fn errno(e: rustix::io::Errno) -> String {
    std::io::Error::from(e).to_string()
}

/// A regular file opened `O_NOFOLLOW` in `dir`, owned by `uid` and with
/// no other link (as root, a link would read or rewrite someone else's
/// file): its handle and status.
fn open_regular(
    dir: &OwnedFd,
    name: &OsStr,
    uid: u32,
) -> Result<(OwnedFd, rustix::fs::Stat), String> {
    let fd = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        rustix::io::Errno::LOOP => "it is a symlink: not followed".to_string(),
        e => errno(e),
    })?;
    let st = fstat(&fd).map_err(errno)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err("not a regular file".into());
    }
    if st.st_uid != uid {
        return Err(format!("owned by uid {}; remove by hand", st.st_uid));
    }
    if st.st_nlink != 1 {
        return Err("has other links; remove by hand".into());
    }
    Ok((fd, st))
}

fn read_bounded(fd: OwnedFd, size: u64) -> Result<Zeroizing<Vec<u8>>, String> {
    if size > MAX_SOURCE_BYTES {
        return Err("larger than 700 KiB; remove or rotate it by hand".into());
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(size as usize + 1));
    File::from(fd)
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > MAX_SOURCE_BYTES {
        return Err("larger than 700 KiB; remove or rotate it by hand".into());
    }
    Ok(buf)
}

// `st_dev` and `st_ino` are not `u64` on every target.
#[allow(clippy::unnecessary_cast)]
impl Source {
    /// `rel` below `base`: the home (from `/etc/passwd`) is opened as is, a
    /// project root outside it `O_NOFOLLOW`; every directory below
    /// `O_NOFOLLOW | O_DIRECTORY`, the file `O_NOFOLLOW` and owned by `uid`.
    fn open(base: &Path, rel: &Path, uid: u32, is_home: bool) -> Result<Source, String> {
        let mut parts: Vec<&OsStr> = Vec::new();
        for c in rel.components() {
            match c {
                Component::Normal(n) => parts.push(n),
                _ => return Err("not a plain path below the home or project".into()),
            }
        }
        let Some(name) = parts.pop() else {
            return Err("not a file".into());
        };
        let mut flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        if !is_home {
            flags |= OFlags::NOFOLLOW;
        }
        let mut dir = openat(CWD, base, flags, Mode::empty()).map_err(|e| match e {
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
                "the project root is a symlink: not followed".to_string()
            }
            e => errno(e),
        })?;
        for p in parts {
            dir = openat(
                &dir,
                p,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| match e {
                rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
                    "a directory on the way is a symlink: not followed".to_string()
                }
                e => errno(e),
            })?;
        }
        let (fd, st) = open_regular(&dir, name, uid)?;
        let bytes = read_bounded(fd, st.st_size.max(0) as u64)?;
        Ok(Source {
            dir,
            name: name.to_os_string(),
            target_uid: uid,
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            uid: st.st_uid,
            gid: st.st_gid,
            mode: st.st_mode & 0o7777,
            bytes,
        })
    }

    /// Replaces the file with `new`, keeping its owner and mode: a temp
    /// file in the same dir, synced, renamed over it, the dir synced. The
    /// file must still be the one read, byte for byte.
    fn rewrite(&self, new: &[u8]) -> Result<(), String> {
        let (fd, st) = open_regular(&self.dir, &self.name, self.target_uid)?;
        if st.st_dev as u64 != self.dev || st.st_ino as u64 != self.ino {
            return Err("it was replaced since it was read".into());
        }
        let now = read_bounded(fd, st.st_size.max(0) as u64)?;
        if now[..] != self.bytes[..] {
            return Err("it changed since it was read".into());
        }
        let mut made = None;
        for n in 0..100u32 {
            let tmp = format!(".saiife-import-{}-{n}.tmp", std::process::id());
            match openat(
                &self.dir,
                tmp.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => {
                    made = Some((fd, tmp));
                    break;
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(e) => return Err(format!("cannot create a temp file: {}", errno(e))),
            }
        }
        let Some((fd, tmp)) = made else {
            return Err("cannot create a temp file".into());
        };
        let mut f = File::from(fd);
        let done = (|| -> std::io::Result<()> {
            f.write_all(new)?;
            let t = fstat(&f)?;
            if t.st_uid != self.uid || t.st_gid != self.gid {
                std::os::unix::fs::fchown(&f, Some(self.uid), Some(self.gid))?;
            }
            f.set_permissions(std::fs::Permissions::from_mode(self.mode))?;
            f.sync_all()?;
            // A write to the file between the check above and here is lost
            // (accepted: the agent's own file in its own dir).
            renameat(&self.dir, tmp.as_str(), &self.dir, &self.name)?;
            rustix::fs::fsync(&self.dir)?;
            Ok(())
        })();
        if let Err(e) = done {
            let _ = unlinkat(&self.dir, tmp.as_str(), AtFlags::empty());
            return Err(e.to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> Vec<&[u8]> {
        s.as_bytes().split_inclusive(|&b| b == b'\n').collect()
    }

    #[test]
    fn env_takes_credential_keys_only() {
        let c = parse_env(
            &lines("# x\nGITHUB_TOKEN=ghp_abc\nPORT=80\nexport API_KEY=\"q v\"\nX_SECRET=${OTHER}\nDB_PASSWORD=pw1 # c\n"),
            "alice",
        );
        let got: Vec<(String, &str, Option<usize>)> = c
            .iter()
            .map(|c| (c.name.clone(), c.value.as_str(), c.line))
            .collect();
        assert_eq!(
            got,
            vec![
                ("alice-github-token".into(), "ghp_abc", Some(1)),
                ("alice-api-key".into(), "q v", Some(3)),
                ("alice-db-password".into(), "pw1", Some(5)),
            ]
        );
        assert_eq!(c[0].service, Some("github"));
        assert!(!c[0].what.contains("ghp_abc"));
    }

    #[test]
    fn git_gh_npm_vault() {
        let g = parse_git(
            &lines("https://bob:tok%40en1@github.com/x\nhttps://nopass@h\n"),
            "u",
        );
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].value.as_str(), "tok@en1");
        assert_eq!(g[0].name, "u-git-github.com");
        assert_eq!(g[0].service, Some("github"));
        let h = parse_gh(
            &lines(
                "github.com:\n    user: bob\n    oauth_token: gho_123\n    git_protocol: https\n",
            ),
            "u",
        );
        assert_eq!(h.len(), 1);
        assert_eq!((h[0].value.as_str(), h[0].line), ("gho_123", Some(2)));
        let n = parse_npmrc(
            &lines("//registry.npmjs.org/:_authToken=npm_1234\n//x/:_authToken=${NPM_TOKEN}\n"),
            "u",
        );
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].name, "u-npm-registry.npmjs.org");
        let v = parse_vault(b"hvs.abcd\n", "u");
        assert_eq!((v[0].value.as_str(), v[0].line), ("hvs.abcd", None));
    }

    #[test]
    fn host_guess_is_exact() {
        assert_eq!(guess_host("github.com"), Some("github"));
        assert_eq!(guess_host("api.github.com:443"), Some("github"));
        assert_eq!(guess_host("github.com.evil.example"), None);
        assert_eq!(guess_host("notgithub.com"), None);
        assert_eq!(guess_host("acme.myshopify.com"), Some("shopify"));
        assert_eq!(guess_host("myshopify.com.evil"), None);
        assert_eq!(guess_host("api.hubapi.com"), Some("hubspot"));
        assert_eq!(guess_host("x.api.hubapi.com"), None);
        assert_eq!(
            parse_npmrc(&lines("_authToken=abcd1234\n"), "u")[0].service,
            None
        );
        assert_eq!(parse_vault(b"hvs.abcd", "u")[0].service, None);
    }

    #[test]
    fn names_are_valid_and_unique() {
        assert_eq!(suggest("Alice", "GITHUB__TOKEN"), "alice-github-token");
        assert!(valid_name(&suggest("u", &"x".repeat(200))));
        assert_eq!(suggest("", "--"), "imported");
        let taken = BTreeSet::from(["a".to_string(), "a-2".to_string()]);
        assert_eq!(unique("a", &taken), "a-3");
        assert_eq!(unique("b", &taken), "b");
    }

    #[test]
    fn lines_are_removed_exactly() {
        let out = without_lines(b"A=1\nB=2\nC=3", &BTreeSet::from([1]));
        assert_eq!(&out[..], b"A=1\nC=3");
    }
}
