//! The per-user host checks of `saiife doctor` (spec §5.6, §6.16): for
//! each agent user, local passwd entry, no password-less way to root, agent
//! binaries out of the user's reach, agent versions, plaintext credentials,
//! model login and leftover project hooks; once per host, `hidepid`.
//! Read-only. Agent binaries never run as root.

use super::report::{Check, Status};
use super::secrets::{self, read_at, read_under};
use super::Ctx;
use crate::host::{valid_name, SUDO};
use saiife_agents::integrity::Integrity;
use saiife_ipc::client::{entry_by_name, entry_by_uid, uid_by_name};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One user doctor checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentUser {
    pub name: String,
    pub uid: u32,
    /// The home under the layout's root (the caller's `$HOME` for a
    /// self-check); empty when unknown.
    pub home: PathBuf,
    pub in_passwd: bool,
}

/// Groups whose members can get root (spec §5.6 item 1).
pub const ROOT_EQUIVALENT_GROUPS: [&str; 5] = ["docker", "lxd", "incus", "libvirt", "disk"];

/// Claude Code needs `onFailure: "block"` (spec §5.6).
pub const CLAUDE_MIN: (u32, u32, u32) = (2, 1, 295);

/// The agent programs doctor looks for.
const AGENT_BINARIES: [&str; 3] = ["claude", "codex", "gemini"];
/// Where user-level installers put them, below the home.
const USER_BIN_DIRS: [&str; 4] = [".local/bin", ".claude/local", ".npm-global/bin", ".bun/bin"];
/// Where `saiife init` keeps its integrity records, below the home.
const RECORDS: &str = ".local/share/saiife/projects";
const PASSWD: &str = "/etc/passwd";
const MOUNTS: &str = "/proc/mounts";
const GROUP_PREFIX: &str = "group:";
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const SUDO_TIMEOUT: Duration = Duration::from_secs(10);
const LOCAL_MODEL: &str = "local model";
const OWN_LOGIN: &str = "the agent holds its own model-provider login (not brokered in v2)";
const NO_SECRETS: &str = "no plaintext credentials found";

/// The first `N.N.N` in `out`.
pub fn parse_agent_version(out: &str) -> Option<(u32, u32, u32)> {
    out.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find_map(|word| {
            let mut n = word.split('.').map(|p| p.parse::<u32>().ok());
            Some((n.next()??, n.next()??, n.next()??))
        })
}

fn passwd_text(ctx: &Ctx) -> String {
    let mut text = String::new();
    // `/etc/passwd` is root's; the bound only guards a broken test tree.
    if let Ok(f) = fs::File::open(ctx.layout.at(PASSWD)) {
        let _ = f.take(16 * 1024 * 1024).read_to_string(&mut text);
    }
    text
}

fn real_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// The calling user's name (not root): `--user` (which the CLI checked is
/// the caller), else the directory's name for the uid, else
/// `/etc/passwd`'s.
fn caller(ctx: &Ctx, passwd: &str) -> Option<String> {
    ctx.opts
        .user
        .clone()
        .or_else(|| ctx.dir.name_of(real_uid()))
        .or_else(|| entry_by_uid(passwd, real_uid()).map(|e| e.name))
}

/// The members of `group:<g>`: its listed members plus the local users
/// whose primary group it is.
fn group_users(ctx: &Ctx, g: &str) -> Vec<String> {
    let Some(entry) = ctx.dir.group(g) else {
        return Vec::new();
    };
    let mut out = entry.members;
    out.extend(ctx.host.users_with_primary_gid(entry.gid));
    out
}

/// Every user named by a `[[scope]]`, groups expanded.
fn scoped_names(ctx: &Ctx) -> BTreeSet<String> {
    let Ok(p) = &ctx.config else {
        return BTreeSet::new();
    };
    let mut out = BTreeSet::new();
    for scope in &p.config.scope {
        for entry in &scope.users {
            match entry.strip_prefix(GROUP_PREFIX) {
                Some(g) => out.extend(group_users(ctx, g)),
                None => {
                    out.insert(entry.clone());
                }
            }
        }
    }
    out
}

/// A path from `/etc/passwd` or the config, below the layout's root.
fn rooted(ctx: &Ctx, p: &Path) -> Option<PathBuf> {
    ctx.layout.try_at(p).ok()
}

fn agent_user(ctx: &Ctx, passwd: &str, name: &str, is_self: bool) -> Option<AgentUser> {
    let entry = entry_by_name(passwd, name);
    let dir_uid = ctx.dir.user(name).map(|u| u.uid);
    if dir_uid.is_none() && entry.is_none() && !is_self {
        return None;
    }
    let info = ctx.host.user(name);
    let uid = dir_uid
        .or_else(|| uid_by_name(passwd, name))
        .or_else(|| info.as_ref().map(|i| i.uid))
        .unwrap_or(if is_self { real_uid() } else { u32::MAX });
    let home = match (&ctx.opts.home, is_self) {
        (Some(h), true) => Some(h.clone()),
        _ => info
            .map(|i| i.home)
            .or_else(|| entry.as_ref().map(|e| e.home.clone()))
            .filter(|h| h.is_absolute())
            .and_then(|h| rooted(ctx, &h)),
    };
    Some(AgentUser {
        name: name.to_string(),
        uid,
        home: home.unwrap_or_default(),
        in_passwd: entry.is_some(),
    })
}

/// The users to check. As root: `--user`, else every scoped user (groups
/// expanded through the directory). Otherwise: the caller only. Unknown
/// names are left out; deduplicated and sorted.
pub fn agent_users(ctx: &Ctx) -> Vec<AgentUser> {
    let passwd = passwd_text(ctx);
    if !ctx.as_root {
        return caller(ctx, &passwd)
            .and_then(|n| agent_user(ctx, &passwd, &n, true))
            .into_iter()
            .collect();
    }
    let names = match &ctx.opts.user {
        Some(u) => BTreeSet::from([u.clone()]),
        None => scoped_names(ctx),
    };
    names
        .iter()
        .filter_map(|n| agent_user(ctx, &passwd, n, false))
        .collect()
}

pub fn checks(ctx: &Ctx) -> Vec<Check> {
    if !ctx.locked() {
        return Vec::new();
    }
    let users = agent_users(ctx);
    let mut out = Vec::new();
    if let Some(u) = ctx.opts.user.as_ref().filter(|_| ctx.as_root) {
        if !users.iter().any(|x| &x.name == u) {
            out.push(Check::new(
                format!("user.{u}.passwd"),
                Status::Fail,
                format!("user {u} in /etc/passwd"),
                format!("{u} is not a known user"),
            ));
        }
    }
    let mut any_finding = false;
    for u in &users {
        let id = |what: &str| format!("user.{}.{what}", u.name);
        out.push(passwd_check(u, id("passwd")));
        out.push(root_check(ctx, u, id("root")));
        let found = binaries(ctx, u);
        out.push(binaries_check(u, &found, id("agent-binaries")));
        out.push(version_check(ctx, u, &found, id("agent-version")));
        if u.home.as_os_str().is_empty() {
            out.push(Check::new(
                id("secrets"),
                Status::Info,
                "plaintext credentials",
                "home directory unknown: not scanned",
            ));
        } else {
            let findings = secrets::scan(&u.home, &project_roots(ctx, u));
            any_finding |= !findings.is_empty();
            out.extend(findings.into_iter().map(|f| {
                Check::new(
                    id("secrets"),
                    Status::Warn,
                    "plaintext credential",
                    format!("{}: {}", f.path.display(), f.what),
                )
            }));
        }
        out.push(model_login(u, id("model-login")));
        out.push(leftover_hooks(ctx, u, id("leftover-hooks")));
    }
    out.push(hidepid(ctx));
    if !any_finding {
        out.push(Check::new(
            "secrets.none",
            Status::Info,
            "plaintext credentials",
            NO_SECRETS,
        ));
    }
    out
}

// ------------------------------------------------------------ checks

fn passwd_check(u: &AgentUser, id: String) -> Check {
    let title = format!("user {} in /etc/passwd", u.name);
    if u.in_passwd {
        Check::new(id, Status::Pass, title, "")
    } else {
        Check::new(
            id,
            Status::Fail,
            title,
            format!(
                "{} is not in /etc/passwd (NSS-only): locked-mode hooks deny every call for this user",
                u.name
            ),
        )
    }
}

/// `u` is in group `g`: listed in `/etc/group`, or it is `u`'s primary
/// group in `/etc/passwd`; on the real machine also by the directory
/// (NSS). A test tree uses the fake host's groups only.
fn in_group(ctx: &Ctx, u: &AgentUser, g: &str) -> bool {
    let listed = ctx
        .host
        .group_members(g)
        .is_some_and(|m| m.iter().any(|x| x == &u.name));
    let primary = ctx
        .host
        .group_id(g)
        .is_some_and(|gid| ctx.host.users_with_primary_gid(gid).contains(&u.name));
    listed
        || primary
        || (ctx.layout.is_system() && ctx.dir.groups_of(&u.name).iter().any(|x| x == g))
}

/// §5.6 item 1: no root-equivalent group, no `NOPASSWD` rule (as root),
/// `sudo -n true` fails (as the user).
fn root_check(ctx: &Ctx, u: &AgentUser, id: String) -> Check {
    const TITLE: &str = "no root without a password";
    let mut bad = Vec::new();
    let mut warn = Vec::new();
    let mut notes = Vec::new();
    for g in ROOT_EQUIVALENT_GROUPS {
        if in_group(ctx, u, g) {
            bad.push(format!("{} is in group {g} (root-equivalent)", u.name));
        }
    }
    if !ctx.layout.at(SUDO).exists() {
        notes.push("sudo not installed".to_string());
    } else if ctx.as_root {
        if !valid_name(&u.name) {
            warn.push(format!(
                "sudo rules not checked: {:?} is not a plain user name",
                u.name
            ));
        } else {
            match ctx
                .host
                .run(SUDO, &["-n", "-l", "-U", &u.name], SUDO_TIMEOUT)
            {
                Ok(o) if o.stdout.contains("NOPASSWD") => bad.push(format!(
                    "sudo lists a NOPASSWD rule for {}: it gets root without a password",
                    u.name
                )),
                Ok(_) => notes.push("no NOPASSWD sudo rule".to_string()),
                Err(e) => warn.push(format!("could not list sudo rules: {e}")),
            }
        }
    } else {
        match ctx.host.run(SUDO, &["-n", "true"], SUDO_TIMEOUT) {
            Ok(o) if o.status == 0 => bad.push(format!(
                "sudo -n true succeeds: {} gets root without a password",
                u.name
            )),
            Ok(_) => notes.push("sudo needs a password".to_string()),
            Err(e) => warn.push(format!("could not run sudo -n true: {e}")),
        }
    }
    if !bad.is_empty() {
        bad.extend(warn);
        Check::new(id, Status::Fail, TITLE, bad.join("; "))
    } else if !warn.is_empty() {
        Check::new(id, Status::Warn, TITLE, warn.join("; "))
    } else {
        Check::new(id, Status::Pass, TITLE, notes.join("; "))
    }
}

/// Agent binaries found, in search order: the current `PATH`, then the
/// user's own install dirs. (name, path)
fn binaries(ctx: &Ctx, u: &AgentUser) -> Vec<(&'static str, PathBuf)> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(
            std::env::split_paths(&path)
                .filter(|d| d.is_absolute())
                .filter_map(|d| rooted(ctx, &d)),
        );
    }
    if !u.home.as_os_str().is_empty() {
        dirs.extend(USER_BIN_DIRS.iter().map(|d| u.home.join(d)));
    }
    let mut out: Vec<(&'static str, PathBuf)> = Vec::new();
    for d in dirs {
        for name in AGENT_BINARIES {
            let p = d.join(name);
            if fs::symlink_metadata(&p).is_ok() && !out.iter().any(|(_, x)| x == &p) {
                out.push((name, p));
            }
        }
    }
    out
}

/// Owned by `uid`, or writable by group or others.
fn writable_by(p: &Path, uid: u32) -> bool {
    fs::metadata(p).is_ok_and(|m| m.uid() == uid || m.mode() & 0o022 != 0)
}

/// The binary, its directory, and (through a symlink) its target and the
/// target's directory: none may be writable by the agent user.
fn binary_writable(p: &Path, uid: u32) -> bool {
    let mut paths = vec![p.to_path_buf()];
    paths.extend(p.parent().map(Path::to_path_buf));
    if let Ok(target) = fs::canonicalize(p) {
        paths.extend(target.parent().map(Path::to_path_buf));
        paths.push(target);
    }
    paths.iter().any(|x| writable_by(x, uid))
}

fn binaries_check(u: &AgentUser, found: &[(&str, PathBuf)], id: String) -> Check {
    const TITLE: &str = "agent binaries not writable by the agent user";
    if found.is_empty() {
        return Check::new(id, Status::Info, TITLE, "no agent binary found");
    }
    let writable: Vec<String> = found
        .iter()
        .filter(|(_, p)| binary_writable(p, u.uid))
        .map(|(_, p)| {
            format!(
                "{} is writable by {}: the agent can patch itself and skip hooks (install agents system-wide)",
                p.display(),
                u.name
            )
        })
        .collect();
    if writable.is_empty() {
        let list: Vec<String> = found.iter().map(|(_, p)| p.display().to_string()).collect();
        Check::new(id, Status::Pass, TITLE, list.join(", "))
    } else {
        Check::new(id, Status::Warn, TITLE, writable.join("; "))
    }
}

fn fmt_version((a, b, c): (u32, u32, u32)) -> String {
    format!("{a}.{b}.{c}")
}

/// `claude --version`, only when the caller checks itself: doctor never
/// runs an agent's binary as root (or as anyone else).
fn version_check(ctx: &Ctx, u: &AgentUser, found: &[(&str, PathBuf)], id: String) -> Check {
    const TITLE: &str = "agent versions";
    if ctx.as_root || rustix::process::geteuid().is_root() || u.uid != real_uid() {
        return Check::new(
            id,
            Status::Info,
            TITLE,
            format!("not checked as root (run saiife doctor as {})", u.name),
        );
    }
    let Some((_, bin)) = found.iter().find(|(n, _)| *n == "claude") else {
        return Check::new(id, Status::Info, TITLE, "Claude Code not found");
    };
    let Some(prog) = bin.to_str() else {
        return Check::new(
            id,
            Status::Warn,
            TITLE,
            format!("{}: not a UTF-8 path", bin.display()),
        );
    };
    let out = match ctx.host.run(prog, &["--version"], VERSION_TIMEOUT) {
        Ok(o) if o.status == 0 => o.stdout,
        Ok(o) => {
            return Check::new(
                id,
                Status::Warn,
                TITLE,
                format!("{prog} --version failed (exit {})", o.status),
            )
        }
        Err(e) => return Check::new(id, Status::Warn, TITLE, format!("{prog} --version: {e}")),
    };
    match parse_agent_version(&out) {
        None => Check::new(
            id,
            Status::Warn,
            TITLE,
            format!("no version in the output of {prog} --version"),
        ),
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

/// A scope's `projects` glob up to its first wildcard, as a directory.
fn glob_root(glob: &str) -> Option<&str> {
    let Some(i) = glob.find(['*', '?', '[', '{']) else {
        return Some(glob.trim_end_matches('/'))
            .filter(|s| !s.is_empty())
            .or(Some("/"));
    };
    let cut = glob[..i].rfind('/')?;
    Some(if cut == 0 { "/" } else { &glob[..cut] })
}

/// The project roots of every scope `u` belongs to, below the layout's
/// root (`~/` is `u`'s home).
fn project_roots(ctx: &Ctx, u: &AgentUser) -> Vec<PathBuf> {
    let Ok(p) = &ctx.config else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = Vec::new();
    for scope in &p.config.scope {
        let member = scope
            .users
            .iter()
            .any(|e| match e.strip_prefix(GROUP_PREFIX) {
                Some(g) => group_users(ctx, g).contains(&u.name),
                None => e == &u.name,
            });
        if !member {
            continue;
        }
        for glob in &scope.projects {
            let Some(root) = glob_root(glob) else {
                continue;
            };
            let path = match root.strip_prefix("~/") {
                Some(rel) if !u.home.as_os_str().is_empty() => Some(u.home.join(rel)),
                Some(_) => None,
                None if root.starts_with('/') => rooted(ctx, Path::new(root)),
                None => None,
            };
            if let Some(path) = path.filter(|p| !out.contains(p)) {
                out.push(path);
            }
        }
    }
    out
}

/// The URL's host is this machine.
fn is_local_url(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    let host = match auth.strip_prefix('[') {
        Some(r) => r.split(']').next().unwrap_or(""),
        None => auth.split(':').next().unwrap_or(""),
    };
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

/// Decision 5: the model login is information, never a failure.
fn model_login(u: &AgentUser, id: String) -> Check {
    const TITLE: &str = "model login";
    let mut local = false;
    if !u.home.as_os_str().is_empty() {
        if let Some(v) = read_under(&u.home, ".claude/settings.json")
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        {
            local |= v["env"]["ANTHROPIC_BASE_URL"]
                .as_str()
                .is_some_and(is_local_url);
        }
        if let Some(t) = read_under(&u.home, ".codex/config.toml")
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|t| t.parse::<toml::Table>().ok())
        {
            local |= t
                .get("model_providers")
                .and_then(|m| m.as_table())
                .is_some_and(|m| {
                    m.values().any(|p| {
                        p.get("base_url")
                            .and_then(|b| b.as_str())
                            .is_some_and(is_local_url)
                    })
                });
        }
    }
    Check::new(
        id,
        Status::Info,
        TITLE,
        if local { LOCAL_MODEL } else { OWN_LOGIN },
    )
}

/// §12: project hooks of a managed agent left from developer mode.
fn leftover_hooks(ctx: &Ctx, u: &AgentUser, id: String) -> Check {
    const TITLE: &str = "no leftover project hooks";
    let managed: Vec<String> = match &ctx.installed {
        Some(i) => i.agents.iter().map(|a| a.agent.clone()).collect(),
        None => AGENT_BINARIES.iter().map(|a| a.to_string()).collect(),
    };
    let mut projects: Vec<String> = Vec::new();
    if !u.home.as_os_str().is_empty() {
        if let Some((dir, names)) = secrets::list_under(&u.home, RECORDS) {
            for name in names
                .iter()
                .filter(|n| n.to_string_lossy().ends_with(".json"))
            {
                let Some(rec) =
                    read_at(&dir, name).and_then(|b| serde_json::from_slice::<Integrity>(&b).ok())
                else {
                    continue;
                };
                let hooked = rec.hooks.iter().any(|(agent, h)| {
                    managed.contains(agent) && (h.error.is_none() || h.off_failed)
                });
                if hooked && !projects.contains(&rec.project) {
                    projects.push(rec.project);
                }
            }
        }
    }
    projects.sort();
    if projects.is_empty() {
        Check::new(id, Status::Pass, TITLE, "")
    } else {
        let list: Vec<String> = projects
            .iter()
            .map(|p| format!("run saiife init --off in {p}"))
            .collect();
        Check::new(id, Status::Warn, TITLE, list.join("; "))
    }
}

/// §5.6: `/proc` must not hide agent processes from the daemon.
fn hidepid(ctx: &Ctx) -> Check {
    const ID: &str = "proc.hidepid";
    const TITLE: &str = "/proc shows every process to the daemon";
    let mut text = String::new();
    let read = fs::File::open(ctx.layout.at(MOUNTS))
        .and_then(|f| f.take(secrets::MAX_READ).read_to_string(&mut text));
    if let Err(e) = read {
        return Check::new(
            ID,
            Status::Info,
            TITLE,
            format!("cannot read {MOUNTS}: {e}"),
        );
    }
    let hiding = text.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() >= 4
            && f[1] == "/proc"
            && f[2] == "proc"
            && f[3].split(',').any(|o| {
                matches!(
                    o,
                    "hidepid=1" | "hidepid=2" | "hidepid=invisible" | "hidepid=noaccess"
                )
            })
    });
    if hiding {
        Check::new(
            ID,
            Status::Warn,
            TITLE,
            "/proc is mounted with hidepid: the daemon cannot see agent processes to attribute sessions",
        )
    } else {
        Check::new(ID, Status::Pass, TITLE, "")
    }
}

#[cfg(test)]
mod tests {
    use super::super::{run, Ctx, DoctorOptions, Report, Status};
    use super::*;
    use crate::host::{CmdOutput, FakeHost, Host, UserInfo};
    use crate::layout::*;
    use crate::testing::fake_install;
    use saiife_agents::integrity::{HookRecord, Integrity, INTEGRITY_VERSION};
    use saiife_policy::installed::read_installed;
    use saiife_policy::{load_and_check, FixedDirectory};
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tempfile::TempDir;

    fn me() -> (u32, u32) {
        (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
    }

    /// A fake install with agent users whose homes live under the root.
    struct T {
        _dir: TempDir,
        layout: Layout,
        host: FakeHost,
        passwd: String,
        group: String,
    }

    impl T {
        /// `as_root`: the fake host reports euid 0 (the real process never
        /// is root).
        fn new(as_root: bool) -> T {
            let dir = tempfile::tempdir().unwrap();
            fake_install(dir.path());
            let layout = Layout::under(dir.path());
            let host = FakeHost::open(dir.path()).unwrap();
            if as_root {
                host.set(|s| s.euid = 0);
            }
            let t = T {
                _dir: dir,
                layout,
                host,
                passwd: String::new(),
                group: String::new(),
            };
            fs::write(t.at("/etc/passwd"), "").unwrap();
            t
        }

        fn at(&self, p: &str) -> PathBuf {
            self.layout.at(p)
        }

        /// A user in the directory, the fake host and (`local`) the
        /// root's `/etc/passwd`, with a home at `<root>/home/<name>`.
        fn user(&mut self, name: &str, uid: u32, gid: u32, local: bool) -> PathBuf {
            let line = format!("{name}:x:{uid}:{gid}::/home/{name}:/bin/sh\n");
            self.passwd.push_str(&line);
            if local {
                let mut p = fs::read_to_string(self.at("/etc/passwd")).unwrap();
                p.push_str(&line);
                fs::write(self.at("/etc/passwd"), p).unwrap();
            }
            let home = PathBuf::from(format!("/home/{name}"));
            self.host.set(|s| {
                s.users.insert(
                    name.to_string(),
                    UserInfo {
                        uid,
                        gid,
                        home: home.clone(),
                        shell: "/bin/sh".into(),
                    },
                );
            });
            let h = self.layout.try_at(&home).unwrap();
            fs::create_dir_all(&h).unwrap();
            h
        }

        /// The calling user (the test process's uid). Its primary gid is
        /// not the test gid, which the fake host gives every unknown group.
        fn me(&mut self, name: &str) -> PathBuf {
            let (uid, _) = me();
            self.user(name, uid, 4242, true)
        }

        fn group_line(&mut self, line: &str) {
            self.group.push_str(line);
            self.group.push('\n');
        }

        fn append_config(&self, text: &str) {
            let p = self.at(CONFIG);
            let mut c = fs::read_to_string(&p).unwrap();
            c.push_str(text);
            fs::write(&p, c).unwrap();
        }

        fn canned(&self, line: &str, status: i32, stdout: &str) {
            self.host.set(|s| {
                s.run.insert(
                    line.to_string(),
                    CmdOutput {
                        status,
                        stdout: stdout.to_string(),
                        stderr: String::new(),
                    },
                );
            });
        }

        fn sudo_installed(&self) {
            fs::create_dir_all(self.at("/usr/bin")).unwrap();
            fs::write(self.at(crate::host::SUDO), "").unwrap();
        }

        fn dir(&self) -> FixedDirectory {
            FixedDirectory::from_text(&self.passwd, &self.group)
        }

        fn doctor_opts(&self, opts: DoctorOptions) -> Report {
            run(&self.layout, &self.host, &self.dir(), &opts)
        }

        fn doctor(&self) -> Report {
            self.doctor_opts(DoctorOptions::default())
        }

        fn users(&self) -> Vec<String> {
            let dir = self.dir();
            let opts = DoctorOptions::default();
            let ctx = Ctx {
                layout: &self.layout,
                host: &self.host,
                dir: &dir,
                installed: read_installed(&self.at(INSTALLED)).unwrap(),
                installed_error: None,
                config: load_and_check(&self.at(CONFIG), &dir).map_err(|e| e.to_string()),
                as_root: self.host.euid() == 0,
                opts: &opts,
            };
            agent_users(&ctx).into_iter().map(|u| u.name).collect()
        }
    }

    fn get<'r>(r: &'r Report, id: &str) -> &'r Check {
        r.checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no check {id} in\n{}", r.to_text()))
    }

    fn status(r: &Report, id: &str) -> Status {
        get(r, id).status
    }

    #[test]
    fn version_parse() {
        assert_eq!(
            parse_agent_version("2.1.294 (Claude Code)"),
            Some((2, 1, 294))
        );
        assert_eq!(parse_agent_version("codex-cli v0.45.0\n"), Some((0, 45, 0)));
        assert_eq!(
            parse_agent_version("version 1.2 then 3.4.5.6"),
            Some((3, 4, 5))
        );
        assert_eq!(parse_agent_version("no version"), None);
        assert_eq!(parse_agent_version("1.2"), None);
    }

    #[test]
    fn nss_only_user_fails() {
        let mut t = T::new(true);
        t.user("ldapuser", 5001, 5001, false);
        t.user("local", 5002, 5002, true);
        t.append_config(
            "\n[[scope]]\nname = \"a\"\nusers = [\"ldapuser\"]\n[[scope]]\nname = \"b\"\nusers = [\"local\"]\n",
        );
        let r = t.doctor();
        let c = get(&r, "user.ldapuser.passwd");
        assert_eq!(c.status, Status::Fail, "{}", r.to_text());
        assert_eq!(
            c.detail,
            "ldapuser is not in /etc/passwd (NSS-only): locked-mode hooks deny every call for this user"
        );
        assert_eq!(status(&r, "user.local.passwd"), Status::Pass);
    }

    #[test]
    fn unknown_user_option_fails() {
        let t = T::new(true);
        let r = t.doctor_opts(DoctorOptions {
            user: Some("ghost".into()),
            ..Default::default()
        });
        assert_eq!(
            status(&r, "user.ghost.passwd"),
            Status::Fail,
            "{}",
            r.to_text()
        );
    }

    #[test]
    fn docker_group_member_fails() {
        let mut t = T::new(true);
        t.user("agent", 5001, 5001, true);
        t.append_config("\n[[scope]]\nname = \"a\"\nusers = [\"agent\"]\n");
        t.host.set(|s| {
            s.groups.insert("docker".into(), 990);
            s.members.insert("docker".into(), vec!["agent".into()]);
        });
        let r = t.doctor();
        let c = get(&r, "user.agent.root");
        assert_eq!(c.status, Status::Fail, "{}", r.to_text());
        assert!(c.detail.contains("docker"), "{c:?}");
    }

    #[test]
    fn primary_group_root_equivalent_fails() {
        let mut t = T::new(true);
        t.user("agent", 5001, 6, true);
        t.append_config("\n[[scope]]\nname = \"a\"\nusers = [\"agent\"]\n");
        t.host.set(|s| {
            s.groups.insert("disk".into(), 6);
        });
        let r = t.doctor();
        let c = get(&r, "user.agent.root");
        assert_eq!(c.status, Status::Fail, "{}", r.to_text());
        assert!(c.detail.contains("disk"), "{c:?}");
    }

    #[test]
    fn nopasswd_rule_fails() {
        let mut t = T::new(true);
        t.user("agent", 5001, 5001, true);
        t.append_config("\n[[scope]]\nname = \"a\"\nusers = [\"agent\"]\n");
        t.sudo_installed();
        t.canned(
            "/usr/bin/sudo -n -l -U agent",
            0,
            "User agent may run the following commands on host:\n    (ALL) NOPASSWD: ALL\n",
        );
        let r = t.doctor();
        let c = get(&r, "user.agent.root");
        assert_eq!(c.status, Status::Fail, "{}", r.to_text());
        assert!(c.detail.contains("NOPASSWD"), "{c:?}");
        // As root, the user's own `sudo -n true` is never tried.
        let calls = t.host.state().calls;
        assert!(
            !calls.iter().any(|c| c == "/usr/bin/sudo -n true"),
            "{calls:?}"
        );
    }

    #[test]
    fn password_sudo_passes() {
        // As root: rules that need a password.
        let mut t = T::new(true);
        t.user("agent", 5001, 5001, true);
        t.append_config("\n[[scope]]\nname = \"a\"\nusers = [\"agent\"]\n");
        t.sudo_installed();
        t.canned(
            "/usr/bin/sudo -n -l -U agent",
            0,
            "User agent may run the following commands on host:\n    (ALL) ALL\n",
        );
        let r = t.doctor();
        assert_eq!(
            status(&r, "user.agent.root"),
            Status::Pass,
            "{}",
            r.to_text()
        );

        // As the user: `sudo -n true` fails (needs a password).
        let mut t = T::new(false);
        t.me("me");
        t.sudo_installed();
        t.canned("/usr/bin/sudo -n true", 1, "");
        let r = t.doctor();
        assert_eq!(status(&r, "user.me.root"), Status::Pass, "{}", r.to_text());
        // And succeeds without one: fail.
        t.canned("/usr/bin/sudo -n true", 0, "");
        let r = t.doctor();
        assert_eq!(status(&r, "user.me.root"), Status::Fail, "{}", r.to_text());
    }

    #[test]
    fn sudo_missing_passes_with_detail() {
        let mut t = T::new(false);
        t.me("me");
        let r = t.doctor();
        let c = get(&r, "user.me.root");
        assert_eq!(c.status, Status::Pass, "{}", r.to_text());
        assert!(c.detail.contains("sudo not installed"), "{c:?}");
        let calls = t.host.state().calls;
        assert!(!calls.iter().any(|c| c.contains("sudo")), "{calls:?}");
    }

    #[test]
    fn user_writable_agent_binary_warns() {
        let mut t = T::new(true);
        let (uid, gid) = me();
        let home = t.user("agent", uid, gid, true);
        t.append_config("\n[[scope]]\nname = \"a\"\nusers = [\"agent\"]\n");
        let bin = home.join(".local/bin/claude");
        fs::create_dir_all(bin.parent().unwrap()).unwrap();
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let r = t.doctor();
        let c = get(&r, "user.agent.agent-binaries");
        assert_eq!(c.status, Status::Warn, "{}", r.to_text());
        assert!(
            c.detail.contains(&format!(
                "{} is writable by agent: the agent can patch itself and skip hooks (install agents system-wide)",
                bin.display()
            )),
            "{c:?}"
        );
        // Root never runs the agent's binary.
        let a = get(&r, "user.agent.agent-version");
        assert_eq!(a.status, Status::Info);
        assert_eq!(a.detail, "not checked as root (run saiife doctor as agent)");
        assert!(t.host.state().calls.iter().all(|c| !c.contains("claude")));
    }

    #[test]
    fn claude_version_gate() {
        let mut t = T::new(false);
        let home = t.me("me");
        let bin = home.join(".local/bin/claude");
        fs::create_dir_all(bin.parent().unwrap()).unwrap();
        fs::write(&bin, "").unwrap();
        let line = format!("{} --version", bin.display());

        t.canned(&line, 0, "2.1.294 (Claude Code)\n");
        let r = t.doctor();
        let c = get(&r, "user.me.agent-version");
        assert_eq!(c.status, Status::Fail, "{}", r.to_text());
        assert_eq!(
            c.detail,
            "Claude Code 2.1.294 is older than 2.1.295 (onFailure: \"block\")"
        );

        t.canned(&line, 0, "2.1.308 (Claude Code)\n");
        let r = t.doctor();
        assert_eq!(
            status(&r, "user.me.agent-version"),
            Status::Pass,
            "{}",
            r.to_text()
        );
    }

    #[test]
    fn hidepid_warns() {
        let t = T::new(true);
        fs::create_dir_all(t.at("/proc")).unwrap();
        fs::write(
            t.at("/proc/mounts"),
            "sysfs /sys sysfs rw 0 0\nproc /proc proc rw,hidepid=invisible 0 0\n",
        )
        .unwrap();
        let r = t.doctor();
        assert_eq!(status(&r, "proc.hidepid"), Status::Warn, "{}", r.to_text());

        fs::write(t.at("/proc/mounts"), "proc /proc proc rw,nosuid 0 0\n").unwrap();
        let r = t.doctor();
        assert_eq!(status(&r, "proc.hidepid"), Status::Pass, "{}", r.to_text());
    }

    #[test]
    fn scope_group_users_expanded() {
        let mut t = T::new(true);
        t.user("alice", 5001, 5001, true);
        t.user("bob", 5002, 3000, true);
        t.user("carol", 5003, 5003, true);
        t.group_line("devs:x:3000:alice");
        t.append_config(
            "\n[[scope]]\nname = \"d\"\nusers = [\"group:devs\"]\n[[scope]]\nname = \"c\"\nusers = [\"carol\", \"carol\"]\n",
        );
        assert_eq!(t.users(), ["alice", "bob", "carol"]);
        // Not root: only the caller.
        let mut t = T::new(false);
        t.me("me");
        t.user("alice", 5001, 5001, true);
        t.append_config("\n[[scope]]\nname = \"a\"\nusers = [\"alice\"]\n");
        assert_eq!(t.users(), ["me"]);
    }

    #[test]
    fn local_model_detected() {
        let mut t = T::new(true);
        let a = t.user("alice", 5001, 5001, true);
        let b = t.user("bob", 5002, 5002, true);
        let c = t.user("carol", 5003, 5003, true);
        t.append_config("\n[[scope]]\nname = \"a\"\nusers = [\"alice\", \"bob\", \"carol\"]\n");
        fs::create_dir_all(a.join(".claude")).unwrap();
        fs::write(
            a.join(".claude/settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:11434"}}"#,
        )
        .unwrap();
        fs::create_dir_all(b.join(".codex")).unwrap();
        fs::write(
            b.join(".codex/config.toml"),
            "[model_providers.ollama]\nbase_url = \"http://[::1]:11434/v1\"\n",
        )
        .unwrap();
        fs::create_dir_all(c.join(".claude")).unwrap();
        fs::write(
            c.join(".claude/settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://localhost.evil.example"}}"#,
        )
        .unwrap();
        let r = t.doctor();
        for u in ["alice", "bob"] {
            let x = get(&r, &format!("user.{u}.model-login"));
            assert_eq!((x.status, x.detail.as_str()), (Status::Info, "local model"));
        }
        let x = get(&r, "user.carol.model-login");
        assert_eq!(
            x.detail,
            "the agent holds its own model-provider login (not brokered in v2)"
        );
    }

    #[test]
    fn leftover_project_hook_listed() {
        let mut t = T::new(true);
        let home = t.user("agent", 5001, 5001, true);
        t.append_config("\n[[scope]]\nname = \"a\"\nusers = [\"agent\"]\n");
        let r = t.doctor();
        assert_eq!(status(&r, "user.agent.leftover-hooks"), Status::Pass);

        let record = |project: &str, hooks: &[(&str, Option<&str>)]| Integrity {
            v: INTEGRITY_VERSION,
            project: project.into(),
            saiife_path: "/usr/bin/saiife".into(),
            saiife_version: "0".into(),
            saiife_sha256: String::new(),
            saiife_sha256_error: None,
            config_sha256: String::new(),
            config_written_sha256: String::new(),
            hooks: hooks
                .iter()
                .map(|(a, err)| {
                    (
                        a.to_string(),
                        HookRecord {
                            file: ".claude/settings.json".into(),
                            sha256: "x".into(),
                            error: err.map(str::to_string),
                            off_failed: false,
                            off_outside: None,
                            init_failed: false,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            created: vec![],
        };
        let dir = home.join(".local/share/saiife/projects");
        fs::create_dir_all(&dir).unwrap();
        let save = |name: &str, i: &Integrity| {
            fs::write(dir.join(name), serde_json::to_vec(i).unwrap()).unwrap()
        };
        save("a.json", &record("/work/shop", &[("claude", None)]));
        // `init` failed for this agent: no hook was written.
        save(
            "b.json",
            &record("/work/failed", &[("claude", Some("boom"))]),
        );
        // Codex is not a managed agent of this install.
        save("c.json", &record("/work/codex", &[("codex", None)]));
        let r = t.doctor();
        let c = get(&r, "user.agent.leftover-hooks");
        assert_eq!(c.status, Status::Warn, "{}", r.to_text());
        assert_eq!(c.detail, "run saiife init --off in /work/shop");
    }

    #[test]
    fn secrets_reported_per_user_and_none_once() {
        let mut t = T::new(true);
        let home = t.user("agent", 5001, 5001, true);
        let proj = t.at("/srv/proj/shop");
        fs::create_dir_all(&proj).unwrap();
        fs::write(proj.join(".env"), "TOKEN=s3cr3t-VALUE\n").unwrap();
        t.append_config(
            "\n[[scope]]\nname = \"a\"\nusers = [\"agent\"]\nprojects = [\"/srv/proj/*\"]\n",
        );
        fs::write(home.join(".netrc"), "machine m password s3cr3t-VALUE\n").unwrap();
        let r = t.doctor();
        let text = r.to_text();
        assert!(!text.contains("s3cr3t-VALUE"), "{text}");
        let found: Vec<&Check> = r
            .checks
            .iter()
            .filter(|c| c.id == "user.agent.secrets")
            .collect();
        assert_eq!(found.len(), 2, "{text}");
        assert!(found.iter().all(|c| c.status == Status::Warn));
        assert!(found.iter().any(|c| c
            .detail
            .starts_with(&home.join(".netrc").display().to_string())));
        assert!(found.iter().any(|c| c
            .detail
            .starts_with(&proj.join(".env").display().to_string())));
        assert!(!r.checks.iter().any(|c| c.id == "secrets.none"), "{text}");

        fs::remove_file(home.join(".netrc")).unwrap();
        fs::remove_file(proj.join(".env")).unwrap();
        let r = t.doctor();
        let c = get(&r, "secrets.none");
        assert_eq!(
            (c.status, c.detail.as_str()),
            (Status::Info, "no plaintext credentials found")
        );
    }

    #[test]
    fn not_installed_runs_no_user_checks() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::under(dir.path());
        let host = FakeHost::open(dir.path()).unwrap();
        let r = run(
            &layout,
            &host,
            &FixedDirectory::from_text("", ""),
            &DoctorOptions::default(),
        );
        assert!(r.checks.iter().all(|c| !c.id.starts_with("user.")));
        let _ = Path::new("/");
    }
}
