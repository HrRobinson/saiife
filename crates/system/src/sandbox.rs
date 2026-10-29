//! The sandbox of an MCP gateway child (plan 17, decision 12).
//!
//! The daemon starts a third-party server through `saiife __mcp-spawn`,
//! which reads a [`SpawnSpec`] from its stdin, confines itself with
//! [`apply`] and then execs the server. The server inherits the
//! confinement: `no_new_privs`, and a Landlock ruleset that allows reading
//! and executing the system's program and library dirs, a few files under
//! `/etc`, its own `/proc/<pid>`, `/dev/null`, `/dev/urandom` and its
//! `read_paths`, and writing (never executing) only its home and
//! `/dev/null`. Everything else (`/etc/saiife`, the vault, the
//! credentials, the audit and state dirs, the sockets dir listing) is
//! denied; policy load refuses `read_paths` that would reach saiife's own
//! dirs. Network access is not restricted: servers call their APIs.
//!
//! **Weaker on older kernels.** Signal and abstract Unix socket scoping
//! needs Landlock ABI 6 (Linux 6.12). Below that the child is confined on
//! the filesystem only: it may still signal processes of the daemon user
//! and connect to abstract Unix sockets. [`sandbox_strength`] reports this
//! (`filesystem` vs `filesystem+scopes`) for doctor and status, and the
//! helper says so on stderr when it starts a server.
//!
//! The spec travels on the helper's stdin as one frame (a 4-byte
//! big-endian length, then JSON), read with unbuffered reads so the rest
//! of stdin is left for the server. Everything here is safe code: the
//! daemon and the helper need no `unsafe` to hand over a descriptor.

use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd,
    RestrictionStatus, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use saiife_policy::mcp::{child_env_var_allowed, PROTECTED_DIRS};
pub use saiife_policy::Sandbox;
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The highest inherited descriptor the helper can close: it closes them
/// with a POSIX shell redirection (`N<&-`), and POSIX shells such as dash
/// take only one digit there. A higher one makes the helper refuse.
pub const MAX_CLOSABLE_FD: i32 = 9;

/// The largest spec frame the helper reads.
pub const MAX_SPEC_BYTES: usize = 64 * 1024;

/// The installed helper (`saiife __mcp-spawn`).
pub const SPAWN_HELPER: &str = crate::layout::BINARY;

/// Debug builds only: the helper binary to run instead of
/// [`SPAWN_HELPER`], so the gateway tests run without an install.
pub const SPAWN_HELPER_SEAM: &str = "SAIIFE_TEST_MCP_SPAWN";

/// `PATH` of every child.
pub const CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
/// `LANG` of every child.
pub const CHILD_LANG: &str = "C.UTF-8";

/// Read and execute, beneath each of these (when it exists).
const READ_EXEC: [&str; 6] = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt"];
/// Read only: the files and dirs under `/etc` a TLS client and libc need.
const READ_ETC: [&str; 10] = [
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/localtime",
    "/etc/passwd",
    "/etc/group",
    "/etc/gai.conf",
];

/// What `__mcp-spawn` starts, and how it confines it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnSpec {
    /// Absolute path of the server program.
    pub command: PathBuf,
    pub args: Vec<String>,
    /// Secret variables: name, value. Nothing else of the daemon's
    /// environment reaches the child.
    pub env: Vec<(String, Zeroizing<String>)>,
    /// The child's `HOME` and working dir, `<state>/mcp/<name>/` (0700).
    pub home: PathBuf,
    /// Extra read-only paths (`[mcp.<name>] read_paths`).
    pub read_paths: Vec<PathBuf>,
    pub sandbox: Sandbox,
    /// The daemon's own dirs as it really runs (config, state, audit log,
    /// sockets, credentials): no read path may reach them. Added to
    /// [`PROTECTED_DIRS`] and `$CREDENTIALS_DIRECTORY`, never instead.
    #[serde(default)]
    pub protected: Vec<PathBuf>,
}

/// Names only: never the secret values.
impl fmt::Debug for SpawnSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.env.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("SpawnSpec")
            .field("command", &self.command)
            .field("args", &self.args)
            .field("env", &names)
            .field("home", &self.home)
            .field("read_paths", &self.read_paths)
            .field("sandbox", &self.sandbox)
            .field("protected", &self.protected)
            .finish()
    }
}

/// Why the sandbox or the spec failed. The texts hold no values: they go
/// to the daemon's journal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxError {
    #[error("bad spec: {0}")]
    BadSpec(&'static str),
    #[error("cannot set no_new_privs")]
    NoNewPrivs,
    /// The kernel has no Landlock and `sandbox` is not `off`.
    #[error("sandbox unavailable: the kernel has no Landlock (set sandbox = \"off\" to run this server unconfined)")]
    Unavailable,
    #[error("cannot build the Landlock ruleset")]
    Ruleset,
    #[error("the Landlock ruleset is not fully enforced")]
    NotEnforced,
    /// A `read_paths` entry, checked at spawn.
    #[error("a read path {0}")]
    ReadPath(&'static str),
}

impl SandboxError {
    /// The stable code (`sandbox_unavailable`, ...).
    pub fn code(&self) -> &'static str {
        match self {
            SandboxError::BadSpec(_) => "bad_spec",
            SandboxError::NoNewPrivs => "no_new_privs_failed",
            SandboxError::Unavailable => "sandbox_unavailable",
            SandboxError::Ruleset | SandboxError::NotEnforced => "sandbox_failed",
            SandboxError::ReadPath(_) => "read_path_refused",
        }
    }
}

impl SpawnSpec {
    /// The checks the helper makes before it uses a spec.
    pub fn validate(&self) -> Result<(), SandboxError> {
        let bad = |why| Err(SandboxError::BadSpec(why));
        if !self.command.is_absolute() {
            return bad("command is not an absolute path");
        }
        if !self.home.is_absolute() {
            return bad("home is not an absolute path");
        }
        if self.read_paths.iter().any(|p| !p.is_absolute()) {
            return bad("a read path is not absolute");
        }
        if self.protected.iter().any(|p| !p.is_absolute()) {
            return bad("a protected dir is not absolute");
        }
        if self.args.iter().any(|a| a.contains('\0')) {
            return bad("an argument holds a NUL");
        }
        let mut seen = std::collections::BTreeSet::new();
        for (name, value) in &self.env {
            if !child_env_var_allowed(name) {
                return bad("an env variable name is not allowed");
            }
            if !seen.insert(name.as_str()) {
                return bad("an env variable is listed twice");
            }
            if value.contains('\0') {
                return bad("an env value holds a NUL");
            }
        }
        Ok(())
    }

    /// The child's whole environment: `PATH`, `HOME`, `LANG`, `TMPDIR`
    /// (the home: /tmp is not writable under the sandbox or the unit),
    /// then the secrets. Borrowed: the values are copied only into the
    /// exec.
    pub fn child_env(&self) -> Vec<(&str, &OsStr)> {
        let mut out = vec![
            ("PATH", OsStr::new(CHILD_PATH)),
            ("HOME", self.home.as_os_str()),
            ("LANG", OsStr::new(CHILD_LANG)),
            ("TMPDIR", self.home.as_os_str()),
        ];
        for (k, v) in &self.env {
            out.push((k.as_str(), OsStr::new(v.as_str())));
        }
        out
    }
}

/// The frame the daemon writes to the helper's stdin.
pub fn encode_spec(spec: &SpawnSpec) -> Result<Zeroizing<Vec<u8>>, SandboxError> {
    let json = Zeroizing::new(
        serde_json::to_vec(spec).map_err(|_| SandboxError::BadSpec("cannot encode"))?,
    );
    if json.len() > MAX_SPEC_BYTES {
        return Err(SandboxError::BadSpec("over 64 KiB"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(4 + json.len()));
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Reads one frame from `r` (unbuffered: `r` must not read ahead, so the
/// bytes after the frame stay for the server) and validates it.
pub fn read_spec(mut r: impl Read) -> Result<SpawnSpec, SandboxError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .map_err(|_| SandboxError::BadSpec("no frame length"))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_SPEC_BYTES {
        return Err(SandboxError::BadSpec("over 64 KiB"));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf)
        .map_err(|_| SandboxError::BadSpec("short frame"))?;
    let spec: SpawnSpec =
        serde_json::from_slice(&buf).map_err(|_| SandboxError::BadSpec("not a spawn spec"))?;
    spec.validate()?;
    Ok(spec)
}

/// Reads the spec from the process's stdin, one `read(2)` at a time.
pub fn read_spec_from_stdin() -> Result<SpawnSpec, SandboxError> {
    struct Raw(io::Stdin);
    impl Read for Raw {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            use std::os::fd::AsFd;
            rustix::io::read(self.0.as_fd(), buf).map_err(io::Error::from)
        }
    }
    read_spec(Raw(io::stdin()))
}

/// The helper binary the gateway runs. Debug builds honour
/// [`SPAWN_HELPER_SEAM`]; release builds never read it.
pub fn spawn_helper() -> PathBuf {
    #[cfg(debug_assertions)]
    let seam = std::env::var_os(SPAWN_HELPER_SEAM);
    #[cfg(not(debug_assertions))]
    let seam = None;
    spawn_helper_from(seam)
}

fn spawn_helper_from(seam: Option<OsString>) -> PathBuf {
    match seam {
        Some(p) if cfg!(debug_assertions) && !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(SPAWN_HELPER),
    }
}

/// The open descriptors above 2 that an exec would keep (no
/// `FD_CLOEXEC`), from `/proc/self/fdinfo`. The helper closes them before
/// it execs the server, or refuses to start it when one is above
/// [`MAX_CLOSABLE_FD`].
///
/// [`MAX_CLOSABLE_FD`]: crate::sandbox::MAX_CLOSABLE_FD
pub fn inherited_fds() -> io::Result<Vec<i32>> {
    const O_CLOEXEC: u32 = 0o2_000_000;
    let mut out = Vec::new();
    for e in std::fs::read_dir("/proc/self/fdinfo")? {
        let e = e?;
        let Some(fd) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if fd <= 2 {
            continue;
        }
        // The dir handle itself is gone by the time it is read: skip.
        let Ok(info) = std::fs::read_to_string(e.path()) else {
            continue;
        };
        let flags = info
            .lines()
            .find_map(|l| l.strip_prefix("flags:"))
            .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
            .ok_or_else(|| io::Error::other("fdinfo without flags"))?;
        if flags & O_CLOEXEC == 0 {
            out.push(fd);
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// The kernel's Landlock ABI as far as saiife uses it: 0 when there is
/// none, at most 6 (6 means "6 or later": scopes are the newest feature
/// saiife asks for).
pub fn landlock_abi() -> u32 {
    let probes = [
        (ABI::V6, 6),
        (ABI::V5, 5),
        (ABI::V4, 4),
        (ABI::V3, 3),
        (ABI::V2, 2),
        (ABI::V1, 1),
    ];
    probes
        .into_iter()
        .find(|(abi, _)| supports(*abi))
        .map_or(0, |(_, n)| n)
}

/// How strongly a `sandbox = "landlock"` child is confined on this kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// No Landlock (ABI 0): the child does not start.
    None,
    /// ABI 1 to 5: the filesystem rules only. The child may still signal
    /// processes and connect to abstract Unix sockets outside its domain.
    Filesystem,
    /// ABI 6 or later: the filesystem rules, plus signal and abstract Unix
    /// socket scoping.
    FilesystemAndScopes,
}

impl Strength {
    pub fn from_abi(abi: u32) -> Strength {
        match abi {
            0 => Strength::None,
            1..=5 => Strength::Filesystem,
            _ => Strength::FilesystemAndScopes,
        }
    }

    /// Stable, machine-readable: `none`, `filesystem`, `filesystem+scopes`.
    pub fn as_str(self) -> &'static str {
        match self {
            Strength::None => "none",
            Strength::Filesystem => "filesystem",
            Strength::FilesystemAndScopes => "filesystem+scopes",
        }
    }

    /// What is missing, for doctor and status; `None` at full strength.
    pub fn gap(self) -> Option<&'static str> {
        match self {
            Strength::None => Some("no Landlock: sandboxed servers do not start"),
            Strength::Filesystem => {
                Some("Landlock ABI below 6: no signal or abstract Unix socket scoping")
            }
            Strength::FilesystemAndScopes => None,
        }
    }
}

/// The confinement this kernel gives a sandboxed child (doctor, status).
pub fn sandbox_strength() -> Strength {
    Strength::from_abi(landlock_abi())
}

/// Whether the kernel takes every right of `abi`, as a hard requirement.
fn supports(abi: ABI) -> bool {
    let probe = || -> Result<(), landlock::RulesetError> {
        let mut r = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))?;
        if abi as i32 >= ABI::V4 as i32 {
            r = r.handle_access(AccessNet::from_all(abi))?;
        }
        if abi as i32 >= ABI::V6 as i32 {
            r = r.scope(Scope::from_all(abi))?;
        }
        r.create()?;
        Ok(())
    };
    probe().is_ok()
}

fn abi_of(n: u32) -> ABI {
    match n {
        1 => ABI::V1,
        2 => ABI::V2,
        3 => ABI::V3,
        4 => ABI::V4,
        5 => ABI::V5,
        _ => ABI::V6,
    }
}

/// Confines the calling process for `spec`: `no_new_privs`, then (unless
/// `sandbox = "off"`) the Landlock ruleset, then the scopes when the ABI
/// is 6 or later. Call it single-threaded, right before the exec.
pub fn apply(spec: &SpawnSpec) -> Result<(), SandboxError> {
    rustix::thread::set_no_new_privs(true).map_err(|_| SandboxError::NoNewPrivs)?;
    if spec.sandbox == Sandbox::Off {
        return Ok(());
    }
    let n = landlock_abi();
    if n == 0 {
        return Err(SandboxError::Unavailable);
    }
    let abi = abi_of(n);
    let extra = checked_read_paths(spec, abi)?;
    let status = restrict(spec, abi, extra).map_err(|_| SandboxError::Ruleset)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(SandboxError::NotEnforced);
    }
    Ok(())
}

/// The dirs no `read_paths` entry may equal, sit beneath or contain:
/// [`PROTECTED_DIRS`] (the fallback defaults), `$CREDENTIALS_DIRECTORY`
/// when the helper inherited it, and the daemon's own layout from the
/// spec ([`SpawnSpec::protected`]), each also as resolved on disk.
pub fn protected_dirs(spec: &SpawnSpec) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = PROTECTED_DIRS.iter().map(PathBuf::from).collect();
    if let Some(c) = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from) {
        if c.is_absolute() {
            out.push(c);
        }
    }
    out.extend(spec.protected.iter().cloned());
    let resolved: Vec<PathBuf> = out
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    out.extend(resolved);
    out.sort();
    out.dedup();
    out
}

fn overlaps(real: &Path, protected: &[PathBuf]) -> bool {
    real == Path::new("/")
        || protected
            .iter()
            .any(|d| real.starts_with(d) || d.starts_with(real))
}

/// The `read_paths` rules, checked against the protected dirs at spawn
/// time (policy load checked the names; a symlink may have changed since).
/// Each path is opened once (`O_PATH`); its real location is read back
/// from that descriptor (`/proc/self/fd/N`) and compared by path and by
/// device and inode; the Landlock rule is built from the same descriptor,
/// so what was checked is what is allowed. A path that cannot be opened
/// or resolved fails closed.
fn checked_read_paths(
    spec: &SpawnSpec,
    abi: ABI,
) -> Result<Vec<PathBeneath<PathFd>>, SandboxError> {
    use std::os::fd::{AsFd, AsRawFd};
    let protected = protected_dirs(spec);
    let protected_ids: Vec<(u64, u64)> = protected
        .iter()
        .filter_map(|d| rustix::fs::stat(d).ok())
        .map(|s| (s.st_dev, s.st_ino))
        .collect();
    let read = AccessFs::from_read(abi);
    let mut rules = Vec::with_capacity(spec.read_paths.len());
    for p in &spec.read_paths {
        let fd = PathFd::new(p).map_err(|_| SandboxError::ReadPath("cannot be opened"))?;
        let real = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()))
            .map_err(|_| SandboxError::ReadPath("cannot be resolved"))?;
        let st =
            rustix::fs::fstat(&fd).map_err(|_| SandboxError::ReadPath("cannot be resolved"))?;
        if !real.is_absolute()
            || overlaps(&real, &protected)
            || protected_ids.contains(&(st.st_dev, st.st_ino))
        {
            return Err(SandboxError::ReadPath("reaches saiife's own files"));
        }
        let is_dir =
            rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory;
        let access = if is_dir {
            read
        } else {
            read & AccessFs::from_file(abi)
        };
        rules.push(PathBeneath::new(fd, access));
    }
    Ok(rules)
}

fn restrict(
    spec: &SpawnSpec,
    abi: ABI,
    checked: Vec<PathBeneath<PathFd>>,
) -> Result<RestrictionStatus, landlock::RulesetError> {
    let read = AccessFs::from_read(abi);
    let all = AccessFs::from_all(abi);
    // Home and /dev/null are writable but never executable: a server may
    // not drop a program into its home and run it.
    let rw = all & !AccessFs::Execute;
    // `/proc/self` is resolved here: the helper's pid is the server's,
    // since exec keeps it.
    let proc_self = std::fs::read_link("/proc/self")
        .map(|p| Path::new("/proc").join(p))
        .ok();
    let mut read_paths: Vec<PathBuf> = READ_EXEC
        .iter()
        .chain(READ_ETC.iter())
        .chain(["/dev/urandom"].iter())
        .map(PathBuf::from)
        .collect();
    read_paths.extend(proc_self);
    let rw_paths = [spec.home.clone(), PathBuf::from("/dev/null")];

    let mut r = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(all)?;
    if abi as i32 >= ABI::V6 as i32 {
        r = r.scope(Scope::from_all(abi))?;
    }
    // Paths that do not exist are left out: nothing there to allow.
    r.create()?
        .add_rules(path_beneath_rules(&read_paths, read))?
        .add_rules(checked.into_iter().map(Ok::<_, landlock::RulesetError>))?
        .add_rules(path_beneath_rules(&rw_paths, rw))?
        .restrict_self()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> SpawnSpec {
        SpawnSpec {
            command: PathBuf::from("/usr/bin/true"),
            args: vec!["a".into()],
            env: vec![(
                "API_TOKEN".into(),
                Zeroizing::new(concat!("sec", "ret-value").to_string()),
            )],
            home: PathBuf::from("/var/lib/saiife/mcp/x"),
            read_paths: vec![],
            protected: vec![],
            sandbox: Sandbox::Landlock,
        }
    }

    #[test]
    fn release_ignores_spawn_path_seam() {
        let got = spawn_helper_from(Some(OsString::from("/x/saiife")));
        if cfg!(debug_assertions) {
            assert_eq!(got, PathBuf::from("/x/saiife"));
        } else {
            assert_eq!(got, PathBuf::from("/opt/saiife/bin/saiife"));
        }
        assert_eq!(spawn_helper_from(None), PathBuf::from(SPAWN_HELPER));
        assert_eq!(
            spawn_helper_from(Some(OsString::new())),
            PathBuf::from(SPAWN_HELPER)
        );
    }

    #[test]
    fn debug_shows_names_only() {
        let d = format!("{:?}", spec());
        assert!(d.contains("API_TOKEN"));
        assert!(!d.contains(concat!("sec", "ret-value")));
    }

    #[test]
    fn frame_round_trips() {
        let f = encode_spec(&spec()).unwrap();
        let mut r: &[u8] = &f;
        let got = read_spec(&mut r).unwrap();
        assert_eq!(got.env[0].0, "API_TOKEN");
        assert_eq!(&*got.env[0].1, concat!("sec", "ret-value"));
        assert!(r.is_empty());
    }

    #[test]
    fn frame_leaves_the_rest() {
        let mut f = encode_spec(&spec()).unwrap().to_vec();
        f.extend_from_slice(b"{\"jsonrpc\":\"2.0\"}\n");
        let mut r: &[u8] = &f;
        read_spec(&mut r).unwrap();
        assert_eq!(r, b"{\"jsonrpc\":\"2.0\"}\n");
    }

    #[test]
    fn bad_frames_refused_without_values() {
        let too_long = ((MAX_SPEC_BYTES + 1) as u32).to_be_bytes();
        assert_eq!(
            read_spec(&too_long[..]).unwrap_err(),
            SandboxError::BadSpec("over 64 KiB")
        );
        let body = br#"{"command":"rel","args":[],"env":[["A","sekrit"]],"home":"/h","read_paths":[],"sandbox":"landlock"}"#;
        let mut f = (body.len() as u32).to_be_bytes().to_vec();
        f.extend_from_slice(body);
        let e = read_spec(&f[..]).unwrap_err();
        assert!(!e.to_string().contains("sekrit"));
        assert!(!e.to_string().contains("rel"));
    }

    #[test]
    fn reserved_and_bad_env_names_refused() {
        for name in ["PATH", "HOME", "LANG", "LD_PRELOAD", "lower", "A=B", ""] {
            let mut s = spec();
            s.env = vec![(name.into(), Zeroizing::new("v".into()))];
            assert!(s.validate().is_err(), "{name}");
        }
        let mut s = spec();
        s.env.push(s.env[0].clone());
        assert!(s.validate().is_err());
    }

    #[test]
    fn child_env_is_path_home_lang_tmpdir_and_secrets() {
        let s = spec();
        let env = s.child_env();
        let names: Vec<_> = env.iter().map(|(k, _)| *k).collect();
        assert_eq!(names, ["PATH", "HOME", "LANG", "TMPDIR", "API_TOKEN"]);
        assert_eq!(env[0].1, CHILD_PATH);
        assert_eq!(env[3].1, s.home.as_os_str());
    }

    #[test]
    fn abi_is_in_range() {
        assert!(landlock_abi() <= 6);
        assert_eq!(sandbox_strength(), Strength::from_abi(landlock_abi()));
    }

    #[test]
    fn strength_below_abi_6_is_filesystem_only() {
        assert_eq!(Strength::from_abi(0), Strength::None);
        for n in 1..=5 {
            let s = Strength::from_abi(n);
            assert_eq!(s.as_str(), "filesystem");
            assert!(s
                .gap()
                .unwrap()
                .contains("no signal or abstract Unix socket"));
        }
        assert_eq!(Strength::from_abi(6).as_str(), "filesystem+scopes");
        assert_eq!(Strength::from_abi(6).gap(), None);
    }
}
