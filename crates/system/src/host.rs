//! Every privileged action of locked mode goes through [`Host`]:
//! [`RealHost`] acts on the machine, [`FakeHost`] keeps a record in
//! `<root>/.fakehost.json` instead (tests and the hidden `--root` flag).
//! Programs always run from absolute paths.

use crate::layout::{Layout, AUDIT_GROUP, DAEMON_GROUP, DAEMON_USER};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const USERADD: &str = "/usr/sbin/useradd";
pub const GROUPADD: &str = "/usr/sbin/groupadd";
pub const USERMOD: &str = "/usr/sbin/usermod";
pub const USERDEL: &str = "/usr/sbin/userdel";
pub const GROUPDEL: &str = "/usr/sbin/groupdel";
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
pub const SYSTEMD_CREDS: &str = "/usr/bin/systemd-creds";
pub const DETECT_VIRT: &str = "/usr/bin/systemd-detect-virt";
pub const GPASSWD: &str = "/usr/bin/gpasswd";
pub const SUDO: &str = "/usr/bin/sudo";

/// Every program locked mode runs (plan 9b global constraints), always by
/// absolute path.
pub const PROGRAMS: &[&str] = &[
    USERADD,
    GROUPADD,
    USERMOD,
    USERDEL,
    GROUPDEL,
    GPASSWD,
    SYSTEMCTL,
    SYSTEMD_CREDS,
    DETECT_VIRT,
    SUDO,
];

/// How long the user and group tools may take.
const ADMIN_TIMEOUT: Duration = Duration::from_secs(30);
/// `systemctl enable --now` waits for the daemon's start-up notification.
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(90);
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Most bytes kept of a program's stdout and of its stderr (64 KiB).
const OUTPUT_CAP: usize = 64 * 1024;
/// How long to wait for the pipes to close once the program has exited.
const PIPE_GRACE: Duration = Duration::from_millis(200);

/// What a program printed and how it ended (`128 + signal` when killed).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CmdOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: String,
}

pub trait Host: Send + Sync {
    fn euid(&self) -> u32;
    /// The user from `/etc/passwd` (not NSS: a locked-mode user must be
    /// local).
    fn user(&self, name: &str) -> Option<UserInfo>;
    /// The group id from `/etc/group`.
    fn group_id(&self, name: &str) -> Option<u32>;
    /// The supplementary members of the group from `/etc/group` (primary
    /// members are not listed there); `None` when the group does not exist.
    fn group_members(&self, name: &str) -> Option<Vec<String>>;
    /// Users in `/etc/passwd` whose primary group is `gid` (they are not
    /// listed as members in `/etc/group`).
    fn users_with_primary_gid(&self, gid: u32) -> Vec<String>;
    fn create_system_group(&self, name: &str) -> io::Result<()>;
    /// A system user with primary group `group`, no home and no login shell.
    fn create_system_user(&self, name: &str, group: &str) -> io::Result<()>;
    fn add_to_group(&self, user: &str, group: &str) -> io::Result<()>;
    fn delete_user(&self, name: &str) -> io::Result<()>;
    fn delete_group(&self, name: &str) -> io::Result<()>;
    /// Removes `user` from the supplementary group `group`.
    fn remove_from_group(&self, user: &str, group: &str) -> io::Result<()>;
    /// Changes owner and group of `path` itself; never follows a symlink.
    fn chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()>;
    /// Runs `systemctl <args>`. A non-zero exit is an `Ok` with its status.
    fn systemctl(&self, args: &[&str]) -> io::Result<CmdOutput>;
    fn systemd_version(&self) -> io::Result<u32>;
    /// Encrypts `secret` as the systemd credential `name` into `out`.
    fn encrypt_credential(&self, name: &str, secret: &[u8], out: &Path) -> io::Result<()>;
    /// The container technology when running inside one.
    fn container(&self) -> Option<String>;
    /// Runs `program` (an absolute path) with no stdin; killed after
    /// `timeout`. A non-zero exit is an `Ok` with its status.
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> io::Result<CmdOutput>;
}

/// What `container` reports when it cannot tell (systemd-detect-virt
/// missing or not answering on a systemd host). The supported check refuses
/// it: locked mode fails closed.
pub const CONTAINER_UNKNOWN: &str = "unknown";

/// Which host a resolved root gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    Real,
    Fake,
}

/// The decision behind [`host_for`]: `/` is the machine; any other root is
/// a fake tree, which root may not use (a fake tree run as root would mix
/// fake bookkeeping with real privileges).
pub fn host_kind(canonical_root: &Path, euid: u32) -> Result<HostKind, String> {
    if canonical_root == Path::new("/") {
        Ok(HostKind::Real)
    } else if euid == 0 {
        Err(format!(
            "refusing --root {} as root: a test root is only for unprivileged runs",
            canonical_root.display()
        ))
    } else {
        Ok(HostKind::Fake)
    }
}

/// The host for `layout`: the machine itself for the real root, a
/// [`FakeHost`] for any other root. Refuses a root that could not be
/// resolved, and a test root when running as root.
pub fn host_for(layout: &Layout) -> io::Result<Box<dyn Host>> {
    if !layout.is_resolved() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "root {} cannot be resolved (`..` below a missing directory)",
                layout.root().display()
            ),
        ));
    }
    let euid = rustix::process::geteuid().as_raw();
    match host_kind(layout.root(), euid) {
        Ok(HostKind::Real) => Ok(Box::new(RealHost)),
        Ok(HostKind::Fake) => Ok(Box::new(FakeHost::open(layout.root())?)),
        Err(msg) => Err(io::Error::new(io::ErrorKind::PermissionDenied, msg)),
    }
}

// ---------------------------------------------------------------- RealHost

/// The machine. These are the only calls in saiife that need root.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealHost;

impl Host for RealHost {
    fn euid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn user(&self, name: &str) -> Option<UserInfo> {
        find_passwd(&std::fs::read_to_string("/etc/passwd").ok()?, name)
    }

    fn group_id(&self, name: &str) -> Option<u32> {
        find_group(&std::fs::read_to_string("/etc/group").ok()?, name)
    }

    fn group_members(&self, name: &str) -> Option<Vec<String>> {
        find_group_members(&std::fs::read_to_string("/etc/group").ok()?, name)
    }

    fn users_with_primary_gid(&self, gid: u32) -> Vec<String> {
        std::fs::read_to_string("/etc/passwd")
            .map(|t| find_primary_gid_users(&t, gid))
            .unwrap_or_default()
    }

    fn create_system_group(&self, name: &str) -> io::Result<()> {
        admin(&argv_create_group(name)?)
    }

    fn create_system_user(&self, name: &str, group: &str) -> io::Result<()> {
        admin(&argv_create_user(name, group)?)
    }

    fn add_to_group(&self, user: &str, group: &str) -> io::Result<()> {
        admin(&argv_add_to_group(user, group)?)
    }

    fn delete_user(&self, name: &str) -> io::Result<()> {
        admin(&argv_delete_user(name)?)
    }

    fn delete_group(&self, name: &str) -> io::Result<()> {
        admin(&argv_delete_group(name)?)
    }

    fn remove_from_group(&self, user: &str, group: &str) -> io::Result<()> {
        admin(&argv_remove_from_group(user, group)?)
    }

    fn chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()> {
        if uid == u32::MAX || gid == u32::MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid id -1"));
        }
        rustix::fs::chownat(
            rustix::fs::CWD,
            path,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(gid)),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|e| {
            io::Error::new(
                io::Error::from(e).kind(),
                format!("chown {}: {e}", path.display()),
            )
        })
    }

    fn systemctl(&self, args: &[&str]) -> io::Result<CmdOutput> {
        exec(SYSTEMCTL, args, None, SYSTEMCTL_TIMEOUT)
    }

    fn systemd_version(&self) -> io::Result<u32> {
        let out = exec(SYSTEMCTL, &["--version"], None, QUERY_TIMEOUT)?;
        parse_systemd_version(&out.stdout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{SYSTEMCTL} --version printed no version"),
            )
        })
    }

    fn encrypt_credential(&self, name: &str, secret: &[u8], out: &Path) -> io::Result<()> {
        let argv = argv_encrypt(name, out)?;
        let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
        let res = exec(&argv[0], &args, Some(secret), ADMIN_TIMEOUT)?;
        check_status(&argv, &res)
    }

    fn container(&self) -> Option<String> {
        container_from(
            exec(DETECT_VIRT, &["--container"], None, QUERY_TIMEOUT),
            Path::new("/run/systemd/system").is_dir(),
        )
    }

    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> io::Result<CmdOutput> {
        exec(program, args, None, timeout)
    }
}

/// `systemd-detect-virt --container`'s answer. Exit 0 names the container;
/// `none` means none. Anything else (missing program, timeout, an error)
/// is [`CONTAINER_UNKNOWN`] on a systemd host, so the check fails closed;
/// without systemd the systemd check refuses anyway.
pub(crate) fn container_from(res: io::Result<CmdOutput>, systemd_running: bool) -> Option<String> {
    if let Ok(out) = &res {
        let name = out.stdout.trim();
        if name == "none" {
            return None;
        }
        if out.status == 0 && !name.is_empty() {
            return Some(name.to_string());
        }
    }
    systemd_running.then(|| CONTAINER_UNKNOWN.to_string())
}

/// A user or group name safe to pass to the user tools:
/// `^[a-z_][a-z0-9_-]{0,31}$`. No option injection (`-`), no lists (`,`
/// for `usermod -aG`), no all-digit names (read as ids, `0` = root).
pub(crate) fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && matches!(b[0], b'a'..=b'z' | b'_')
        && b[1..]
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

fn check_names(names: &[&str]) -> io::Result<()> {
    match names.iter().find(|n| !valid_name(n)) {
        Some(bad) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid user or group name {bad:?}"),
        )),
        None => Ok(()),
    }
}

fn owned(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|s| s.to_string()).collect()
}

pub(crate) fn argv_create_user(name: &str, group: &str) -> io::Result<Vec<String>> {
    check_names(&[name, group])?;
    Ok(owned(&[
        USERADD,
        "--system",
        "--no-create-home",
        "--home-dir",
        "/nonexistent",
        "--shell",
        "/usr/sbin/nologin",
        "--gid",
        group,
        name,
    ]))
}

pub(crate) fn argv_create_group(name: &str) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    Ok(owned(&[GROUPADD, "--system", name]))
}

pub(crate) fn argv_add_to_group(user: &str, group: &str) -> io::Result<Vec<String>> {
    check_names(&[user, group])?;
    Ok(owned(&[USERMOD, "-aG", group, user]))
}

pub(crate) fn argv_delete_user(name: &str) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    Ok(owned(&[USERDEL, name]))
}

pub(crate) fn argv_remove_from_group(user: &str, group: &str) -> io::Result<Vec<String>> {
    check_names(&[user, group])?;
    Ok(owned(&[GPASSWD, "-d", user, group]))
}

pub(crate) fn argv_delete_group(name: &str) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    Ok(owned(&[GROUPDEL, name]))
}

pub(crate) fn argv_encrypt(name: &str, out: &Path) -> io::Result<Vec<String>> {
    check_names(&[name])?;
    let out_s = out.to_str().filter(|_| out.is_absolute()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("credential path {} must be absolute UTF-8", out.display()),
        )
    })?;
    Ok(vec![
        SYSTEMD_CREDS.to_string(),
        "encrypt".to_string(),
        format!("--name={name}"),
        "-".to_string(),
        out_s.to_string(),
    ])
}

/// Runs an admin tool and turns a non-zero exit into an error.
fn admin(argv: &[String]) -> io::Result<()> {
    let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    let out = exec(&argv[0], &args, None, ADMIN_TIMEOUT)?;
    check_status(argv, &out)
}

fn check_status(argv: &[String], out: &CmdOutput) -> io::Result<()> {
    if out.status == 0 {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{} failed (exit {}): {}",
        argv.join(" "),
        out.status,
        out.stderr.trim()
    )))
}

/// Spawns `program` (absolute) with `stdin` (or none), collects its output
/// and kills it after `timeout`.
fn exec(
    program: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> io::Result<CmdOutput> {
    if !Path::new(program).is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{program}: programs run from an absolute path only"),
        ));
    }
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => {
                io::Error::new(io::ErrorKind::NotFound, format!("{program} not found"))
            }
            k => io::Error::new(k, format!("{program}: {e}")),
        })?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // A failed write shows as the program's own error below.
        let _ = pipe.write_all(bytes);
    }
    // Each pipe is read on its own thread: the first OUTPUT_CAP bytes are
    // kept, the rest drained so the program never blocks on a full pipe.
    let reader = |pipe: Option<Box<dyn Read + Send>>| {
        let buf = std::sync::Arc::new(Mutex::new(Vec::new()));
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let shared = buf.clone();
        std::thread::spawn(move || {
            if let Some(mut p) = pipe {
                let mut chunk = [0u8; 8192];
                loop {
                    match p.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            let mut b = shared.lock().unwrap_or_else(|e| e.into_inner());
                            let room = OUTPUT_CAP.saturating_sub(b.len());
                            b.extend_from_slice(&chunk[..n.min(room)]);
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            }
            let _ = done_tx.send(());
        });
        (buf, done_rx)
    };
    let out_t = reader(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let err_t = reader(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // The reader threads end when the last holder of the pipes exits.
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{program} did not finish within {} ms", timeout.as_millis()),
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // A grandchild may keep the pipes open: wait for their end only a
    // little after the program itself exits.
    let collect = |(buf, done): (
        std::sync::Arc<Mutex<Vec<u8>>>,
        std::sync::mpsc::Receiver<()>,
    )| {
        let _ = done.recv_timeout(PIPE_GRACE);
        let b = buf.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&b).into_owned()
    };
    let stdout = collect(out_t);
    let stderr = collect(err_t);
    let code = status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        128 + status.signal().unwrap_or(0)
    });
    Ok(CmdOutput {
        status: code,
        stdout,
        stderr,
    })
}

/// The `N` of `systemctl --version`'s first line, `systemd N (…)`.
pub(crate) fn parse_systemd_version(out: &str) -> Option<u32> {
    let mut words = out.lines().next()?.split_whitespace();
    if words.next()? != "systemd" {
        return None;
    }
    words.next()?.parse().ok()
}

/// The `name` entry of `/etc/passwd` text.
pub(crate) fn find_passwd(text: &str, name: &str) -> Option<UserInfo> {
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 || f[0] != name {
            return None;
        }
        Some(UserInfo {
            uid: f[2].parse().ok()?,
            gid: f[3].parse().ok()?,
            home: PathBuf::from(f[5]),
            shell: f[6].to_string(),
        })
    })
}

/// The gid of `name` in `/etc/group` text.
pub(crate) fn find_group(text: &str, name: &str) -> Option<u32> {
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 3 || f[0] != name {
            return None;
        }
        f[2].parse().ok()
    })
}

/// The member list of `name` in `/etc/group` text.
/// Names in `/etc/passwd` text whose primary gid (field 4) is `gid`.
pub(crate) fn find_primary_gid_users(text: &str, gid: u32) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split(':').collect();
            (f.len() >= 7 && f[3].parse::<u32>().ok() == Some(gid)).then(|| f[0].to_string())
        })
        .collect()
}

pub(crate) fn find_group_members(text: &str, name: &str) -> Option<Vec<String>> {
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 || f[0] != name || f[2].parse::<u32>().is_err() {
            return None;
        }
        Some(
            f[3].split(',')
                .filter(|m| !m.is_empty())
                .map(str::to_string)
                .collect(),
        )
    })
}

// ---------------------------------------------------------------- FakeHost

const STATE_FILE: &str = ".fakehost.json";

/// The names install creates. In a [`FakeHost`] they exist only once
/// created; every other name resolves to the test user.
const CREATED_NAMES: [&str; 3] = [DAEMON_USER, DAEMON_GROUP, AUDIT_GROUP];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chown {
    pub path: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

/// What a [`FakeHost`] remembers, in `<root>/.fakehost.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FakeState {
    /// Default: this process's euid.
    pub euid: u32,
    /// Created or set users. A name not here resolves to the test user
    /// (`getuid()`/`getgid()`), except the names install creates.
    pub users: BTreeMap<String, UserInfo>,
    /// Created or set groups, by the same rule.
    pub groups: BTreeMap<String, u32>,
    /// Supplementary members added with `add_to_group`, by group.
    pub members: BTreeMap<String, Vec<String>>,
    /// Every chown, in order. None is applied.
    pub chowns: Vec<Chown>,
    /// Every `systemctl`, `run` and `encrypt_credential` call, as one line.
    pub calls: Vec<String>,
    /// What `systemd_version` returns (default 255).
    pub systemd: u32,
    /// What `container` returns (default none).
    pub container: Option<String>,
    /// Canned outputs by call line (`"systemctl enable --now saiifed.service"`,
    /// `"/usr/bin/sudo -n true"`). A `run` without one exits 1 with no
    /// output; a `systemctl` without one exits 0.
    pub run: BTreeMap<String, CmdOutput>,
    /// Paths whose `chown` fails (tests of a step failing part-way).
    pub fail_chown: Vec<PathBuf>,
}

impl Default for FakeState {
    fn default() -> FakeState {
        FakeState {
            euid: rustix::process::geteuid().as_raw(),
            users: BTreeMap::new(),
            groups: BTreeMap::new(),
            members: BTreeMap::new(),
            chowns: Vec::new(),
            calls: Vec::new(),
            systemd: 255,
            container: None,
            run: BTreeMap::new(),
            fail_chown: Vec::new(),
        }
    }
}

impl FakeState {
    fn user(&self, name: &str) -> Option<UserInfo> {
        if let Some(u) = self.users.get(name) {
            return Some(u.clone());
        }
        if CREATED_NAMES.contains(&name) {
            return None;
        }
        Some(UserInfo {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            home: if name == "root" {
                PathBuf::from("/root")
            } else {
                PathBuf::from("/home").join(name)
            },
            shell: "/bin/bash".to_string(),
        })
    }

    fn group_id(&self, name: &str) -> Option<u32> {
        if let Some(g) = self.groups.get(name) {
            return Some(*g);
        }
        if CREATED_NAMES.contains(&name) {
            return None;
        }
        Some(rustix::process::getgid().as_raw())
    }
}

/// A host that records instead of acting. Its state survives across
/// processes, so a test can run the CLI with `--root` and then read what it
/// did.
#[derive(Debug)]
pub struct FakeHost {
    root: PathBuf,
    lock: Mutex<()>,
}

fn call_line(program: &str, args: &[&str]) -> String {
    std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

fn already(what: &str, name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("{what} {name} already exists"),
    )
}

fn missing(what: &str, name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("{what} {name} does not exist"),
    )
}

impl FakeHost {
    /// Opens the fake host of `root`, creating `root` and a default state
    /// file when they are missing.
    pub fn open(root: &Path) -> io::Result<FakeHost> {
        std::fs::create_dir_all(root)?;
        // The same spelling as `Layout::under` gives its paths.
        let h = FakeHost::unopened(&std::fs::canonicalize(root)?);
        let state = h.load()?;
        if !h.state_path().exists() {
            h.save(&state)?;
        }
        Ok(h)
    }

    fn unopened(root: &Path) -> FakeHost {
        FakeHost {
            root: root.to_path_buf(),
            lock: Mutex::new(()),
        }
    }

    fn state_path(&self) -> PathBuf {
        self.root.join(STATE_FILE)
    }

    fn load(&self) -> io::Result<FakeState> {
        match std::fs::read(self.state_path()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", self.state_path().display()),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(FakeState::default()),
            Err(e) => Err(e),
        }
    }

    fn save(&self, s: &FakeState) -> io::Result<()> {
        let tmp = self
            .root
            .join(format!("{STATE_FILE}.tmp.{}", std::process::id()));
        let json = serde_json::to_vec_pretty(s).map_err(io::Error::other)?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, self.state_path())
    }

    /// Load, change, save, under the in-process lock.
    fn update<T>(&self, f: impl FnOnce(&mut FakeState) -> io::Result<T>) -> io::Result<T> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut s = self.load()?;
        let r = f(&mut s)?;
        self.save(&s)?;
        Ok(r)
    }

    fn read(&self) -> io::Result<FakeState> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        self.load()
    }

    /// The current state (for tests). Panics when the state file cannot be
    /// read.
    pub fn state(&self) -> FakeState {
        self.read()
            .unwrap_or_else(|e| panic!("fake host state: {e}"))
    }

    /// Changes the state (for tests). Panics when the state file cannot be
    /// read or written.
    pub fn set(&self, f: impl FnOnce(&mut FakeState)) {
        self.update(|s| {
            f(s);
            Ok(())
        })
        .unwrap_or_else(|e| panic!("fake host state: {e}"))
    }

    /// `path` lies below the root (lexically, no `..`).
    fn inside(&self, path: &Path) -> bool {
        path.starts_with(&self.root) && !path.components().any(|c| c == Component::ParentDir)
    }
}

impl Host for FakeHost {
    fn euid(&self) -> u32 {
        self.read()
            .map(|s| s.euid)
            .unwrap_or_else(|_| rustix::process::geteuid().as_raw())
    }

    fn user(&self, name: &str) -> Option<UserInfo> {
        self.read().ok()?.user(name)
    }

    fn group_id(&self, name: &str) -> Option<u32> {
        self.read().ok()?.group_id(name)
    }

    fn users_with_primary_gid(&self, gid: u32) -> Vec<String> {
        self.read()
            .map(|s| {
                s.users
                    .iter()
                    .filter(|(_, u)| u.gid == gid)
                    .map(|(n, _)| n.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn group_members(&self, name: &str) -> Option<Vec<String>> {
        let s = self.read().ok()?;
        s.group_id(name)?;
        Some(s.members.get(name).cloned().unwrap_or_default())
    }

    fn create_system_group(&self, name: &str) -> io::Result<()> {
        check_names(&[name])?;
        self.update(|s| {
            if s.group_id(name).is_some() {
                return Err(already("group", name));
            }
            s.groups
                .insert(name.to_string(), rustix::process::getgid().as_raw());
            Ok(())
        })
    }

    fn create_system_user(&self, name: &str, group: &str) -> io::Result<()> {
        check_names(&[name, group])?;
        self.update(|s| {
            if s.user(name).is_some() {
                return Err(already("user", name));
            }
            let gid = s.group_id(group).ok_or_else(|| missing("group", group))?;
            s.users.insert(
                name.to_string(),
                UserInfo {
                    uid: rustix::process::getuid().as_raw(),
                    gid,
                    home: PathBuf::from("/nonexistent"),
                    shell: "/usr/sbin/nologin".to_string(),
                },
            );
            Ok(())
        })
    }

    fn add_to_group(&self, user: &str, group: &str) -> io::Result<()> {
        check_names(&[user, group])?;
        self.update(|s| {
            s.user(user).ok_or_else(|| missing("user", user))?;
            s.group_id(group).ok_or_else(|| missing("group", group))?;
            let m = s.members.entry(group.to_string()).or_default();
            if !m.iter().any(|u| u == user) {
                m.push(user.to_string());
            }
            Ok(())
        })
    }

    fn delete_user(&self, name: &str) -> io::Result<()> {
        check_names(&[name])?;
        self.update(|s| {
            s.users.remove(name).ok_or_else(|| missing("user", name))?;
            for m in s.members.values_mut() {
                m.retain(|u| u != name);
            }
            Ok(())
        })
    }

    fn delete_group(&self, name: &str) -> io::Result<()> {
        check_names(&[name])?;
        self.update(|s| {
            s.groups
                .remove(name)
                .ok_or_else(|| missing("group", name))?;
            s.members.remove(name);
            Ok(())
        })
    }

    fn remove_from_group(&self, user: &str, group: &str) -> io::Result<()> {
        check_names(&[user, group])?;
        self.update(|s| {
            s.group_id(group).ok_or_else(|| missing("group", group))?;
            if let Some(m) = s.members.get_mut(group) {
                m.retain(|u| u != user);
            }
            Ok(())
        })
    }

    fn chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()> {
        // Like the real call: the path itself must exist (a symlink counts).
        std::fs::symlink_metadata(path)
            .map_err(|e| io::Error::new(e.kind(), format!("chown {}: {e}", path.display())))?;
        self.update(|s| {
            if s.fail_chown.iter().any(|p| p == path) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("chown {}: fake failure", path.display()),
                ));
            }
            s.chowns.push(Chown {
                path: path.to_path_buf(),
                uid,
                gid,
            });
            Ok(())
        })
    }

    fn systemctl(&self, args: &[&str]) -> io::Result<CmdOutput> {
        let line = call_line("systemctl", args);
        self.update(|s| {
            let out = s.run.get(&line).cloned().unwrap_or_default();
            s.calls.push(line);
            Ok(out)
        })
    }

    fn systemd_version(&self) -> io::Result<u32> {
        Ok(self.read()?.systemd)
    }

    fn encrypt_credential(&self, name: &str, secret: &[u8], out: &Path) -> io::Result<()> {
        check_names(&[name])?;
        if !self.inside(out) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "fake host writes only below {}: {}",
                    self.root.display(),
                    out.display()
                ),
            ));
        }
        let line = format!("systemd-creds encrypt --name={name} - {}", out.display());
        let canned = self.update(|s| {
            let c = s.run.get(&line).cloned();
            s.calls.push(line.clone());
            Ok(c)
        })?;
        if let Some(c) = canned.filter(|c| c.status != 0) {
            return Err(io::Error::other(format!(
                "{line} failed (exit {}): {}",
                c.status,
                c.stderr.trim()
            )));
        }
        // Not the secret: a stand-in for the encrypted blob.
        let digest: String = Sha256::digest(secret)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let mut f = opts.open(out)?;
        writeln!(f, "saiife fake credential name={name} sha256={digest}")?;
        f.sync_all()
    }

    fn container(&self) -> Option<String> {
        self.read().ok()?.container
    }

    fn run(&self, program: &str, args: &[&str], _timeout: Duration) -> io::Result<CmdOutput> {
        let line = call_line(program, args);
        self.update(|s| {
            let out = s.run.get(&line).cloned().unwrap_or(CmdOutput {
                status: 1,
                stdout: String::new(),
                stderr: String::new(),
            });
            s.calls.push(line);
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn own_ids() -> (u32, u32) {
        (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
    }

    #[test]
    fn fake_host_state_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert!(dir.path().join(".fakehost.json").is_file());
        h.set(|s| {
            s.systemd = 249;
            s.container = Some("podman".into());
        });
        h.create_system_group("saiife").unwrap();
        h.create_system_user("saiife", "saiife").unwrap();
        drop(h);
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.systemd_version().unwrap(), 249);
        assert_eq!(h.container().as_deref(), Some("podman"));
        let u = h.user("saiife").unwrap();
        assert_eq!(u.shell, "/usr/sbin/nologin");
        assert_eq!(u.home, PathBuf::from("/nonexistent"));
        assert!(h.group_id("saiife").is_some());
    }

    #[test]
    fn fake_host_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.systemd_version().unwrap(), 255);
        assert_eq!(h.container(), None);
        assert_eq!(h.euid(), rustix::process::geteuid().as_raw());
        let out = h
            .run("/usr/bin/sudo", &["-n", "true"], Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            out,
            CmdOutput {
                status: 1,
                stdout: String::new(),
                stderr: String::new()
            }
        );
    }

    #[test]
    fn fake_host_records_systemctl_calls() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.systemctl(&["daemon-reload"]).unwrap().status, 0);
        h.set(|s| {
            s.run.insert(
                "systemctl enable --now saiifed.service".into(),
                CmdOutput {
                    status: 1,
                    stdout: String::new(),
                    stderr: "boom".into(),
                },
            );
            s.run.insert(
                "/usr/bin/sudo -n true".into(),
                CmdOutput {
                    status: 0,
                    stdout: "ok\n".into(),
                    stderr: String::new(),
                },
            );
        });
        let out = h
            .systemctl(&["enable", "--now", "saiifed.service"])
            .unwrap();
        assert_eq!((out.status, out.stderr.as_str()), (1, "boom"));
        let out = h
            .run("/usr/bin/sudo", &["-n", "true"], Duration::from_secs(1))
            .unwrap();
        assert_eq!((out.status, out.stdout.as_str()), (0, "ok\n"));
        // Another process sees the same log.
        let again = FakeHost::open(dir.path()).unwrap();
        assert_eq!(
            again.state().calls,
            vec![
                "systemctl daemon-reload".to_string(),
                "systemctl enable --now saiifed.service".to_string(),
                "/usr/bin/sudo -n true".to_string(),
            ]
        );
    }

    #[test]
    fn fake_host_ids_default_to_own_uid() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        let (uid, gid) = own_ids();
        // Names saiife creates are absent until created.
        assert_eq!(h.user(DAEMON_USER), None);
        assert_eq!(h.group_id(DAEMON_GROUP), None);
        assert_eq!(h.group_id(AUDIT_GROUP), None);
        // Any other name resolves to the test user.
        let root = h.user("root").unwrap();
        assert_eq!((root.uid, root.gid), (uid, gid));
        assert_eq!(h.group_id("root"), Some(gid));
        assert_eq!(h.user("alice").unwrap().uid, uid);
        // Created names too.
        h.create_system_group(DAEMON_GROUP).unwrap();
        h.create_system_group(AUDIT_GROUP).unwrap();
        h.create_system_user(DAEMON_USER, DAEMON_GROUP).unwrap();
        h.add_to_group(DAEMON_USER, AUDIT_GROUP).unwrap();
        let u = h.user(DAEMON_USER).unwrap();
        assert_eq!((u.uid, u.gid), (uid, gid));
        assert_eq!(h.group_id(AUDIT_GROUP), Some(gid));
        assert_eq!(
            h.state().members[AUDIT_GROUP],
            vec![DAEMON_USER.to_string()]
        );
        // Tests can change them.
        h.set(|s| {
            s.users.get_mut("saiife").unwrap().uid = 1001;
            s.users.insert(
                "root".into(),
                UserInfo {
                    uid: uid + 1,
                    gid,
                    home: "/root".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        assert_eq!(h.user("saiife").unwrap().uid, 1001);
        assert_eq!(h.user("root").unwrap().uid, uid + 1);
        // Delete makes them absent again.
        h.delete_user(DAEMON_USER).unwrap();
        h.delete_group(AUDIT_GROUP).unwrap();
        assert_eq!(h.user(DAEMON_USER), None);
        assert_eq!(h.group_id(AUDIT_GROUP), None);
        // A second create of an existing name fails, like useradd.
        assert!(h.create_system_group(DAEMON_GROUP).is_err());
        // A user's primary group must exist (saiife-audit was deleted).
        assert!(h.create_system_user(DAEMON_USER, AUDIT_GROUP).is_err());
    }

    #[test]
    fn fake_chown_is_recorded_not_applied() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        let f = dir.path().join("f");
        fs::write(&f, "x").unwrap();
        let before = fs::metadata(&f).unwrap();
        h.chown(&f, 0, 0).unwrap();
        let after = fs::metadata(&f).unwrap();
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
        assert_eq!(
            h.state().chowns,
            vec![Chown {
                path: f.clone(),
                uid: 0,
                gid: 0
            }]
        );
    }

    #[test]
    fn fake_encrypt_writes_under_root_only() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        // Spelled as `Layout::under` spells it: canonical (on macOS the temp
        // dir is below the /var -> /private/var symlink).
        let out = fs::canonicalize(dir.path()).unwrap().join("vault-key");
        h.encrypt_credential("vault-key", &[7u8; 32], &out).unwrap();
        let bytes = fs::read(&out).unwrap();
        assert!(!bytes.is_empty());
        assert!(
            !bytes.windows(32).any(|w| w == [7u8; 32]),
            "plain secret written"
        );
        assert!(h.state().calls[0].starts_with("systemd-creds encrypt --name=vault-key - "));
        let outside = tempfile::tempdir().unwrap();
        assert!(h
            .encrypt_credential("vault-key", b"k", &outside.path().join("k"))
            .is_err());
        assert!(!outside.path().join("k").exists());
    }

    #[test]
    fn host_kind_decision() {
        let tmp = Path::new("/home/u/t");
        assert_eq!(host_kind(Path::new("/"), 0), Ok(HostKind::Real));
        assert_eq!(host_kind(Path::new("/"), 1000), Ok(HostKind::Real));
        assert_eq!(host_kind(tmp, 1000), Ok(HostKind::Fake));
        let e = host_kind(tmp, 0).unwrap_err();
        assert!(e.contains("as root") && e.contains("/home/u/t"), "{e}");
    }

    #[test]
    fn host_for_refuses_an_unresolvable_root() {
        let dir = tempfile::tempdir().unwrap();
        let l = Layout::under(dir.path().join("missing/../../.."));
        assert!(host_for(&l).is_err());
    }

    #[test]
    fn names_follow_the_portable_pattern() {
        for ok in ["saiife", "saiife-audit", "_svc", "a", "u2", &"a".repeat(32)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "saiife-audit,docker",
            "0",
            "123",
            "Saiife",
            "-o",
            "",
            "a b",
            "a:b",
            "a/b",
            "1abc",
            &"a".repeat(33),
            "sa\u{e9}",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
        assert!(argv_add_to_group("saiife", "saiife-audit,docker").is_err());
        assert!(argv_create_group("0").is_err());
    }

    #[test]
    fn fake_delete_validates_names() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        h.set(|s| {
            s.users.insert(
                "-r".into(),
                UserInfo {
                    uid: 1,
                    gid: 1,
                    home: "/".into(),
                    shell: "/bin/sh".into(),
                },
            );
            s.groups.insert("a,b".into(), 1);
        });
        assert_eq!(
            h.delete_user("-r").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            h.delete_group("a,b").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn container_detection_fails_closed() {
        let out = |status: i32, stdout: &str| -> io::Result<CmdOutput> {
            Ok(CmdOutput {
                status,
                stdout: stdout.into(),
                stderr: String::new(),
            })
        };
        assert_eq!(
            container_from(out(0, "docker\n"), true).as_deref(),
            Some("docker")
        );
        assert_eq!(container_from(out(1, "none\n"), true), None);
        let missing = || Err(io::Error::new(io::ErrorKind::NotFound, "x not found"));
        let timeout = || Err(io::Error::new(io::ErrorKind::TimedOut, "slow"));
        assert_eq!(
            container_from(missing(), true).as_deref(),
            Some(CONTAINER_UNKNOWN)
        );
        assert_eq!(
            container_from(timeout(), true).as_deref(),
            Some(CONTAINER_UNKNOWN)
        );
        assert_eq!(
            container_from(out(2, ""), true).as_deref(),
            Some(CONTAINER_UNKNOWN)
        );
        // Without systemd, the systemd check refuses anyway.
        assert_eq!(container_from(missing(), false), None);
    }

    #[test]
    fn host_for_picks_fake_under_a_root() {
        let dir = tempfile::tempdir().unwrap();
        let h = host_for(&Layout::under(dir.path())).unwrap();
        assert_eq!(h.systemd_version().unwrap(), 255);
        assert!(dir.path().join(".fakehost.json").is_file());
    }

    #[test]
    fn real_systemd_version_parses() {
        assert_eq!(
            parse_systemd_version("systemd 249 (249.11-0ubuntu3)\n+PAM +AUDIT -SELINUX\n"),
            Some(249)
        );
        assert_eq!(
            parse_systemd_version("systemd 255 (255.4-1ubuntu8)\n"),
            Some(255)
        );
        assert_eq!(parse_systemd_version("garbage"), None);
        assert_eq!(parse_systemd_version(""), None);
        assert_eq!(parse_systemd_version("systemd x (y)"), None);
    }

    #[test]
    fn real_argv_is_exact() {
        assert_eq!(
            argv_create_user("saiife", "saiife").unwrap(),
            [
                "/usr/sbin/useradd",
                "--system",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "--gid",
                "saiife",
                "saiife",
            ]
        );
        assert_eq!(
            argv_create_group("saiife-audit").unwrap(),
            ["/usr/sbin/groupadd", "--system", "saiife-audit"]
        );
        assert_eq!(
            argv_add_to_group("saiife", "saiife-audit").unwrap(),
            ["/usr/sbin/usermod", "-aG", "saiife-audit", "saiife"]
        );
        assert_eq!(
            argv_delete_user("saiife").unwrap(),
            ["/usr/sbin/userdel", "saiife"]
        );
        assert_eq!(
            argv_remove_from_group("saiife", "saiife-audit").unwrap(),
            ["/usr/bin/gpasswd", "-d", "saiife", "saiife-audit"]
        );
        assert!(argv_remove_from_group("saiife", "a,b").is_err());
        assert!(argv_remove_from_group("-r", "g").is_err());
        assert_eq!(
            argv_delete_group("saiife").unwrap(),
            ["/usr/sbin/groupdel", "saiife"]
        );
        assert_eq!(
            argv_encrypt("vault-key", Path::new("/etc/saiife/credstore/vault-key")).unwrap(),
            [
                "/usr/bin/systemd-creds",
                "encrypt",
                "--name=vault-key",
                "-",
                "/etc/saiife/credstore/vault-key",
            ]
        );
        assert_eq!(SYSTEMCTL, "/usr/bin/systemctl");
        assert_eq!(DETECT_VIRT, "/usr/bin/systemd-detect-virt");
        assert_eq!(GPASSWD, "/usr/bin/gpasswd");
        // Every argv this module builds starts with a listed program.
        let p = Path::new("/etc/saiife/credstore/vault-key");
        for argv in [
            argv_create_user("saiife", "saiife").unwrap(),
            argv_create_group("saiife").unwrap(),
            argv_add_to_group("saiife", "saiife-audit").unwrap(),
            argv_remove_from_group("saiife", "saiife-audit").unwrap(),
            argv_delete_user("saiife").unwrap(),
            argv_delete_group("saiife").unwrap(),
            argv_encrypt("vault-key", p).unwrap(),
        ] {
            assert!(PROGRAMS.contains(&argv[0].as_str()), "{argv:?}");
        }
        assert!(PROGRAMS.iter().all(|p| p.starts_with('/')));
    }

    #[test]
    fn real_argv_refuses_option_like_names() {
        assert!(argv_create_user("-o", "saiife").is_err());
        assert!(argv_create_user("saiife", "a b").is_err());
        assert!(argv_create_group("").is_err());
        assert!(argv_add_to_group("x:y", "g").is_err());
        assert!(argv_encrypt("--name", Path::new("/x")).is_err());
        assert!(argv_encrypt("vault-key", Path::new("relative")).is_err());
    }

    #[test]
    fn passwd_and_group_lines_parse() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nsaiife:x:998:997::/nonexistent:/usr/sbin/nologin\nbad\n";
        let u = find_passwd(passwd, "saiife").unwrap();
        assert_eq!(
            u,
            UserInfo {
                uid: 998,
                gid: 997,
                home: "/nonexistent".into(),
                shell: "/usr/sbin/nologin".into()
            }
        );
        assert_eq!(find_passwd(passwd, "nobody"), None);
        assert_eq!(
            find_group("root:x:0:\nsaiife-audit:x:996:saiife\n", "saiife-audit"),
            Some(996)
        );
        assert_eq!(find_group("root:x:0:\n", "saiife"), None);
        let group = "root:x:0:\nsaiife-audit:x:996:saiife,alice\nempty:x:5:\n";
        assert_eq!(
            find_group_members(group, "saiife-audit"),
            Some(vec!["saiife".to_string(), "alice".to_string()])
        );
        assert_eq!(find_group_members(group, "empty"), Some(vec![]));
        assert_eq!(find_group_members(group, "nogroup"), None);
    }

    #[test]
    fn fake_group_members_follow_add_to_group() {
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        assert_eq!(h.group_members(AUDIT_GROUP), None);
        h.create_system_group(DAEMON_GROUP).unwrap();
        h.create_system_group(AUDIT_GROUP).unwrap();
        h.create_system_user(DAEMON_USER, DAEMON_GROUP).unwrap();
        assert_eq!(h.group_members(AUDIT_GROUP), Some(vec![]));
        h.add_to_group(DAEMON_USER, AUDIT_GROUP).unwrap();
        assert_eq!(
            h.group_members(AUDIT_GROUP),
            Some(vec![DAEMON_USER.to_string()])
        );
    }

    #[test]
    fn real_run_needs_an_absolute_program_and_names_a_missing_one() {
        let e = RealHost.run("ls", &[], Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = RealHost
            .run(
                "/nonexistent/saiife-no-such-program",
                &[],
                Duration::from_secs(1),
            )
            .unwrap_err();
        assert!(
            e.to_string()
                .contains("/nonexistent/saiife-no-such-program"),
            "{e}"
        );
    }

    #[test]
    fn real_run_captures_output_and_times_out() {
        let out = RealHost
            .run(
                "/bin/sh",
                &["-c", "echo hi; echo err >&2; exit 3"],
                Duration::from_secs(5),
            )
            .unwrap();
        assert_eq!(
            out,
            CmdOutput {
                status: 3,
                stdout: "hi\n".into(),
                stderr: "err\n".into()
            }
        );
        let start = std::time::Instant::now();
        let e = RealHost
            .run("/bin/sh", &["-c", "sleep 5"], Duration::from_millis(200))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn primary_gid_users_parse_and_fake() {
        let passwd = "root:x:0:0::/root:/bin/bash\nsaiife:x:990:990::/nonexistent:/usr/sbin/nologin\nalice:x:1000:990::/home/alice:/bin/bash\nbad:x\n";
        assert_eq!(find_primary_gid_users(passwd, 990), ["saiife", "alice"]);
        assert!(find_primary_gid_users(passwd, 5).is_empty());
        let dir = tempfile::tempdir().unwrap();
        let h = FakeHost::open(dir.path()).unwrap();
        h.set(|s| {
            s.users.insert(
                "alice".into(),
                UserInfo {
                    uid: 1000,
                    gid: 990,
                    home: "/home/alice".into(),
                    shell: "/bin/bash".into(),
                },
            );
        });
        assert_eq!(h.users_with_primary_gid(990), ["alice"]);
        assert!(h.users_with_primary_gid(991).is_empty());
    }
}
