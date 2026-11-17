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
//!
//! **Confined helpers** (plan 45 R45-12, plan 46): [`confine_helper`]
//! confines a process that keeps running (the Data Shield calculator
//! `saiife __blind-calc`, the name helper) to reading a few named files,
//! with no network and a seccomp allowlist per helper ([`Profile`]): no
//! socket, tracing, exec, namespace, io_uring or BPF call. It fails closed.
//! The allowlist was traced on the glibc build; its musl entries come from
//! musl's source, so it must also be proven on the static musl build that
//! ships (owner smoke, CI).

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

/// The highest inherited descriptor a POSIX shell can close with `N<&-`
/// (dash takes only one digit there). The helper closes a higher one with
/// bash, and refuses when bash is missing.
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
    /// A resource limit of a confined helper could not be set.
    #[error("cannot set the resource limits")]
    Rlimit,
    /// The new network namespace failed for another reason than `EPERM`.
    #[error("cannot enter a new network namespace")]
    Netns,
    /// The seccomp filter could not be built or loaded.
    #[error("cannot load the seccomp filter")]
    Seccomp,
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
            SandboxError::Rlimit | SandboxError::Netns | SandboxError::Seccomp => "sandbox_failed",
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
/// it execs the server (with bash when one is above [`MAX_CLOSABLE_FD`]).
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

// --- Confined helpers: the Data Shield calculator (plan 45 R45-12) and the
// name helper (plan 46). Unlike an MCP child, a helper confines itself and
// keeps running: no exec, so no program or library dirs are allowed. ---

/// Status and every `blind_run` say this when the calculator could not run
/// in its box (plan 47). Nothing here runs a method unconfined.
pub const CALC_LABEL: &str = "calculator not in a box (weaker)";

/// The confinement a helper got, as [`confine_helper`] applied it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confinement {
    /// The Landlock ABI in force (1 to 6; 6 means "6 or later").
    pub landlock_abi: u32,
    /// TCP bind and connect denied by Landlock (ABI 4 or later).
    pub net_denied: bool,
    /// Signal and abstract Unix socket scoping (ABI 6 or later).
    pub scopes: bool,
    /// The seccomp filter is loaded (always true when `Ok`).
    pub seccomp: bool,
    /// An empty network namespace: false when unprivileged user namespaces
    /// are not allowed on this kernel (`EPERM`).
    pub netns: bool,
}

/// Resource limits of a confined helper. [`apply_rlimits`] also sets
/// `RLIMIT_FSIZE`, `RLIMIT_CORE` and `RLIMIT_NPROC` to 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimits {
    /// `RLIMIT_CPU` in seconds; 0 leaves the CPU limit alone (the
    /// long-lived name helper).
    pub cpu_secs: u64,
    /// `RLIMIT_AS` in bytes.
    pub as_bytes: u64,
    /// `RLIMIT_NOFILE`.
    pub nofile: u64,
}

/// Lowers `res` to `v` (soft and hard). Never raises it: a hard limit
/// already below `v` stays.
fn lower_rlimit(res: rustix::process::Resource, v: u64) -> Result<(), SandboxError> {
    use rustix::process::{getrlimit, setrlimit, Rlimit};
    let now = getrlimit(res);
    let v = now.maximum.map_or(v, |m| m.min(v));
    setrlimit(
        res,
        Rlimit {
            current: Some(v),
            maximum: Some(v),
        },
    )
    .map_err(|_| SandboxError::Rlimit)
}

/// Sets the helper's resource limits: CPU (unless 0), address space and
/// open files from `r`; file size, core size and process count 0 (no file
/// written, no core dumped, no process started).
pub fn apply_rlimits(r: &Rlimits) -> Result<(), SandboxError> {
    use rustix::process::Resource;
    if r.cpu_secs > 0 {
        lower_rlimit(Resource::Cpu, r.cpu_secs)?;
    }
    lower_rlimit(Resource::As, r.as_bytes)?;
    lower_rlimit(Resource::Nofile, r.nofile)?;
    lower_rlimit(Resource::Fsize, 0)?;
    lower_rlimit(Resource::Core, 0)?;
    lower_rlimit(Resource::Nproc, 0)
}

/// Which confined helper a seccomp allowlist is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// `saiife __blind-calc`: one thread, SQLite on one read-only file.
    Calc,
    /// Plan 46's name helper: [`Profile::Calc`] plus what threads need.
    Ner,
}

/// A condition on a syscall's arguments; any other value is `EPERM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgRule {
    /// Any arguments (each such entry says in its `why` why that is safe).
    Any,
    /// `prot` (argument 2) without `PROT_EXEC`: nothing becomes executable
    /// after confinement.
    NoExec,
    /// The target (argument 0) is this process (`tgkill`), or its main
    /// thread (`tkill`: tid == pid while single-threaded): a signal to
    /// itself only.
    OwnPid,
    /// `clone` flags (argument 0) make a thread: `CLONE_THREAD` set, and
    /// nothing outside [`THREAD_CLONE_FLAGS`] (no namespace, no exit signal).
    ThreadFlags,
    /// `prctl(PR_SET_NAME, ..)` only (a thread names itself).
    SetName,
    /// The open flags (this argument) are read-only: no `O_WRONLY`,
    /// `O_RDWR`, `O_CREAT`, `O_TRUNC` or `O_APPEND` (`O_TMPFILE` needs a
    /// write mode). Landlock still decides which file.
    ReadOnlyOpen(u8),
    /// `fcntl` commands (argument 1) `F_GETFD`, `F_SETFD` and `F_GETFL`
    /// only: no `F_SETFL` (`O_ASYNC`), `F_SETOWN*`, `F_SETSIG`,
    /// `F_SETLEASE`, `F_NOTIFY` (signals at another process) nor locks.
    FcntlCmds,
    /// File descriptor (argument 0) 1 or 2: the answer frame and stderr.
    StdoutStderr,
}

/// One allowed syscall: name, x86_64 number, aarch64 number (-1: the arch
/// has no such call; the kernel's numbers, checked against `libc::SYS_*`
/// for the running arch in the tests and taken from seccompiler 0.5.0's
/// tables), the argument rule and why.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Allowed {
    // `name` and `why` document the entry; the tests read them.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) name: &'static str,
    pub(crate) x86_64: i64,
    pub(crate) aarch64: i64,
    pub(crate) arg: ArgRule,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) why: &'static str,
}

const fn allow(
    name: &'static str,
    x86_64: i64,
    aarch64: i64,
    arg: ArgRule,
    why: &'static str,
) -> Allowed {
    Allowed {
        name,
        x86_64,
        aarch64,
        arg,
        why,
    }
}

/// The calculator's allowlist. Everything else is `EPERM`.
///
/// Evidence: gdb `catch syscall` (with arguments) on the debug glibc
/// `saiife __blind-calc` for every job of the `blind_calc` tests and for
/// list-cap, step-cap, heap-cap, time-cap, self-check and empty-for-key
/// jobs, also on a 600 000-row snapshot. After the filter loads they make
/// exactly: read, write (fd 1), pread64, openat (`O_RDONLY|O_CLOEXEC`,
/// `|O_NOFOLLOW`), close, fstat, newfstatat, fcntl (`F_GETFD`: std's debug
/// check of a closed descriptor), getpid, mmap and mprotect (prot 0 or 3),
/// munmap, brk (large snapshot) and exit_group. The other entries are
/// marked: the runtime's paths the fixture is too small to reach, and the
/// calls static musl (the shipped Linux build) makes instead of glibc's.
///
/// **The allowlist must also be proven on the musl build** (the owner's
/// smoke runs the release binary; CI should run `blind_calc` on
/// `x86_64-unknown-linux-musl`): the musl entries come from musl's source,
/// not from a trace.
const CALC_ALLOWED: [Allowed; 34] = [
    allow("read", 0, 63, ArgRule::Any, "traced: the hash check reads the snapshot; reads only descriptors it has"),
    allow("write", 1, 64, ArgRule::StdoutStderr, "traced: the answer frame on fd 1; stderr lines on fd 2"),
    allow("pread64", 17, 67, ArgRule::Any, "traced: SQLite page reads; reads only descriptors it has"),
    allow("openat", 257, 56, ArgRule::ReadOnlyOpen(2), "traced: SQLite and the hash open the snapshot read-only (Landlock decides which file)"),
    allow("close", 3, 57, ArgRule::Any, "traced: closing the snapshot; own descriptors only"),
    allow("fstat", 5, 80, ArgRule::Any, "traced: SQLite sizes the file; metadata of own descriptors"),
    allow("newfstatat", 262, 79, ArgRule::Any, "traced: SQLite's lstat of the path (musl stat/fstatat too); metadata only (M6)"),
    allow("fcntl", 72, 25, ArgRule::FcntlCmds, "traced: F_GETFD (std); F_SETFD: musl open's FD_CLOEXEC; F_GETFL"),
    allow("getpid", 39, 172, ArgRule::Any, "traced: SQLite's unix VFS; no argument"),
    allow("mmap", 9, 222, ArgRule::NoExec, "traced: allocations, prot 0 or 3 (never executable)"),
    allow("munmap", 11, 215, ArgRule::Any, "traced: frees; own address space only"),
    allow("mprotect", 10, 226, ArgRule::NoExec, "traced: glibc arenas, prot 3 (never executable)"),
    allow("exit_group", 231, 94, ArgRule::Any, "traced: the exit"),
    allow("brk", 12, 214, ArgRule::Any, "traced (a 600 000-row snapshot): the heap grows; own address space only"),
    allow("mremap", 25, 216, ArgRule::Any, "runtime: realloc of large blocks (glibc, musl mallocng); keeps prot, own memory"),
    allow("madvise", 28, 233, ArgRule::Any, "runtime: freed memory returned (glibc, musl); own memory; the harmful advice needs CAP_SYS_ADMIN"),
    allow("futex", 202, 98, ArgRule::Any, "runtime: a lock's slow path; no memory is shared with another process"),
    allow("getrandom", 318, 278, ArgRule::Any, "runtime: std's HashMap keys (the /dev/urandom fallback is not readable); no effect outside"),
    allow("clock_gettime", 228, 113, ArgRule::Any, "runtime: the wall cap's clock without the vDSO; read-only"),
    allow("sched_yield", 24, 124, ArgRule::Any, "runtime: lock spinning; no argument"),
    allow("exit", 60, 93, ArgRule::Any, "runtime: musl _Exit after exit_group; a thread's exit"),
    allow("rt_sigreturn", 15, 139, ArgRule::Any, "runtime: return from std's stack-overflow handler; own frame"),
    allow("rt_sigaction", 13, 134, ArgRule::Any, "runtime: the overflow handler resets itself, abort; own handlers only"),
    allow("rt_sigprocmask", 14, 135, ArgRule::Any, "runtime: abort (glibc, musl) blocks and unblocks; own mask only"),
    allow("gettid", 186, 178, ArgRule::Any, "runtime: abort raises SIGABRT on itself; no argument"),
    allow("tgkill", 234, 131, ArgRule::OwnPid, "runtime: glibc abort's raise, to this process only"),
    allow("tkill", 200, 130, ArgRule::OwnPid, "musl: raise() uses tkill on its own tid (== pid, one thread)"),
    allow("faccessat", 269, 48, ArgRule::Any, "musl aarch64 and glibc aarch64: SQLite's access() (-journal/-wal check); metadata only (M6)"),
    allow("readlinkat", 267, 78, ArgRule::Any, "musl aarch64: SQLite resolves a symlinked path; metadata only (M6)"),
    allow("open", 2, -1, ArgRule::ReadOnlyOpen(1), "musl x86_64: open() and std's File::open use SYS_open; read-only like openat"),
    allow("stat", 4, -1, ArgRule::Any, "musl x86_64: stat() can use SYS_stat (depends on the musl version); metadata only (M6)"),
    allow("lstat", 6, -1, ArgRule::Any, "musl x86_64: SQLite's lstat (unixFullPathname) can use SYS_lstat; metadata only (M6)"),
    allow("access", 21, -1, ArgRule::Any, "musl x86_64: SQLite's access() uses SYS_access; metadata only (M6)"),
    allow("readlink", 89, -1, ArgRule::Any, "musl x86_64: SQLite resolves a symlinked path; metadata only (M6)"),
];

/// What the name helper adds for its threads (plan 46 proves the list with
/// its own suite under the filter and extends it from evidence;
/// `profiles_install_for_real` proves a std thread starts and joins).
const NER_EXTRA: [Allowed; 7] = [
    allow("clone", 56, 220, ArgRule::ThreadFlags, "threads: pthread_create falls back to clone"),
    allow("clone3", 435, 435, ArgRule::Any, "threads: listed only so that the clone3 -> ENOSYS filter installed before the allowlist answers it (no call gets through)"),
    allow("set_robust_list", 273, 99, ArgRule::Any, "threads: a new thread's robust futex list; own memory"),
    allow("rseq", 334, 293, ArgRule::Any, "threads: glibc registers restartable sequences; own thread"),
    allow("sched_getaffinity", 204, 123, ArgRule::Any, "threads: available_parallelism; read-only"),
    allow("sigaltstack", 131, 132, ArgRule::Any, "threads: std's overflow stack per thread; own thread"),
    allow("prctl", 157, 167, ArgRule::SetName, "threads: std names its threads"),
];

/// Never allowed to any helper (asserted against both allowlists, with one
/// scoped exception: Ner lists clone3 under the ENOSYS filter): name,
/// x86_64 number, aarch64 number (-1: the arch has no such call).
pub(crate) const FORBIDDEN_SYSCALLS: [(&str, i64, i64); 46] = [
    ("socket", 41, 198),
    ("socketpair", 53, 199),
    ("connect", 42, 203),
    ("bind", 49, 200),
    ("listen", 50, 201),
    ("accept", 43, 202),
    ("accept4", 288, 242),
    ("sendto", 44, 206),
    ("sendmsg", 46, 211),
    ("sendmmsg", 307, 269),
    ("recvfrom", 45, 207),
    ("recvmsg", 47, 212),
    ("recvmmsg", 299, 243),
    ("ptrace", 101, 117),
    ("process_vm_readv", 310, 270),
    ("process_vm_writev", 311, 271),
    ("execve", 59, 221),
    ("execveat", 322, 281),
    ("fork", 57, -1),
    ("vfork", 58, -1),
    ("clone3", 435, 435),
    ("unshare", 272, 97),
    ("setns", 308, 268),
    ("io_uring_setup", 425, 425),
    ("io_uring_enter", 426, 426),
    ("io_uring_register", 427, 427),
    ("bpf", 321, 280),
    ("perf_event_open", 298, 241),
    ("userfaultfd", 323, 282),
    ("keyctl", 250, 219),
    ("add_key", 248, 217),
    ("request_key", 249, 218),
    ("pidfd_open", 434, 434),
    ("pidfd_getfd", 438, 438),
    ("pidfd_send_signal", 424, 424),
    ("process_madvise", 440, 440),
    ("mount", 165, 40),
    ("umount2", 166, 39),
    ("pivot_root", 155, 41),
    ("chroot", 161, 51),
    ("init_module", 175, 105),
    ("finit_module", 313, 273),
    ("delete_module", 176, 106),
    ("kexec_load", 246, 104),
    ("seccomp", 317, 277),
    ("kill", 62, 129),
];

/// `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
/// CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
/// CLONE_CHILD_CLEARTID`: what glibc's pthread_create passes.
const THREAD_CLONE_FLAGS: u64 =
    0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x10_0000 | 0x20_0000;
const CLONE_THREAD: u64 = 0x1_0000;
const PROT_EXEC: u64 = 0x4;
const PR_SET_NAME: u64 = 15;
/// `O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND` (the same values on
/// x86_64 and aarch64).
const OPEN_WRITE_FLAGS: u64 = 0o1 | 0o2 | 0o100 | 0o1000 | 0o2000;
/// `F_GETFD`, `F_SETFD`, `F_GETFL`.
const FCNTL_CMDS: [u64; 3] = [1, 2, 3];
/// `clone3` (the same number on both arches).
const SYS_CLONE3: i64 = 435;

impl Profile {
    pub(crate) fn allowed(self) -> impl Iterator<Item = &'static Allowed> {
        let extra: &'static [Allowed] = match self {
            Profile::Calc => &[],
            Profile::Ner => &NER_EXTRA,
        };
        CALC_ALLOWED.iter().chain(extra.iter())
    }
}

/// The seccomp arch for an arch name; any but x86_64 and aarch64 fails
/// closed (no tables for it).
pub(crate) fn arch_of(name: &str) -> Result<seccompiler::TargetArch, SandboxError> {
    match name {
        "x86_64" => Ok(seccompiler::TargetArch::x86_64),
        "aarch64" => Ok(seccompiler::TargetArch::aarch64),
        _ => Err(SandboxError::Seccomp),
    }
}

/// The rules of one entry; several rules are alternatives (any may match).
fn arg_rules(
    arg: ArgRule,
    pid: u32,
) -> Result<Vec<seccompiler::SeccompRule>, seccompiler::BackendError> {
    use seccompiler::SeccompRule as R;
    use seccompiler::{SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as C};
    let one = |conds| R::new(conds).map(|r| vec![r]);
    match arg {
        ArgRule::Any => Ok(vec![]),
        ArgRule::NoExec => one(vec![C::new(2, Len::Qword, Op::MaskedEq(PROT_EXEC), 0)?]),
        ArgRule::OwnPid => one(vec![C::new(0, Len::Dword, Op::Eq, u64::from(pid))?]),
        ArgRule::ThreadFlags => one(vec![
            C::new(0, Len::Qword, Op::MaskedEq(!THREAD_CLONE_FLAGS), 0)?,
            C::new(0, Len::Qword, Op::MaskedEq(CLONE_THREAD), CLONE_THREAD)?,
        ]),
        ArgRule::SetName => one(vec![C::new(0, Len::Dword, Op::Eq, PR_SET_NAME)?]),
        ArgRule::ReadOnlyOpen(i) => one(vec![C::new(
            i,
            Len::Dword,
            Op::MaskedEq(OPEN_WRITE_FLAGS),
            0,
        )?]),
        ArgRule::FcntlCmds => FCNTL_CMDS
            .iter()
            .map(|&cmd| R::new(vec![C::new(1, Len::Dword, Op::Eq, cmd)?]))
            .collect(),
        ArgRule::StdoutStderr => [1u64, 2]
            .iter()
            .map(|&fd| R::new(vec![C::new(0, Len::Dword, Op::Eq, fd)?]))
            .collect(),
    }
}

/// The helper's filters for `arch`, compiled to BPF, in install order.
///
/// [`Profile::Ner`] first gets a filter that answers `clone3` with `ENOSYS`
/// (glibc then falls back to `clone`) and allows everything else: it must
/// come first, while installing the allowlist (`prctl` and `seccomp`) is
/// still allowed. The allowlist comes last: the profile's calls with their
/// argument rules are allowed, everything else fails with `EPERM`; a call
/// from another arch (the i386 ABI on x86_64) kills the process, and x32
/// numbers (not listed) fail. For `clone3` the earlier filter's `ENOSYS`
/// is more restrictive than the allowlist's allow, so it wins.
/// `pid` is this process (for [`ArgRule::OwnPid`]).
pub(crate) fn seccomp_programs(
    profile: Profile,
    arch: seccompiler::TargetArch,
    pid: u32,
) -> Result<Vec<seccompiler::BpfProgram>, SandboxError> {
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;
    let bad = |_| SandboxError::Seccomp;
    let mut out = Vec::new();
    if profile == Profile::Ner {
        let enosys = rustix::io::Errno::NOSYS.raw_os_error() as u32;
        let clone3 = SeccompFilter::new(
            [(SYS_CLONE3, vec![])].into_iter().collect(),
            SeccompAction::Allow,
            SeccompAction::Errno(enosys),
            arch,
        )
        .map_err(bad)?;
        out.push(clone3.try_into().map_err(bad)?);
    }
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for e in profile.allowed() {
        let n = match arch {
            TargetArch::x86_64 => e.x86_64,
            TargetArch::aarch64 => e.aarch64,
            _ => return Err(SandboxError::Seccomp),
        };
        if n < 0 {
            continue;
        }
        // Belt and braces: a forbidden call in a table refuses the filter,
        // but for Ner's clone3, which the earlier filter answers.
        let ner_clone3 = profile == Profile::Ner && n == SYS_CLONE3;
        let forbidden = FORBIDDEN_SYSCALLS.iter().any(|f| match arch {
            TargetArch::x86_64 => f.1 == n,
            _ => f.2 == n,
        });
        if forbidden && !ner_clone3 {
            return Err(SandboxError::Seccomp);
        }
        rules.insert(n, arg_rules(e.arg, pid).map_err(bad)?);
    }
    let eperm = rustix::io::Errno::PERM.raw_os_error() as u32;
    let allowlist = SeccompFilter::new(
        rules,
        SeccompAction::Errno(eperm),
        SeccompAction::Allow,
        arch,
    )
    .map_err(bad)?;
    out.push(allowlist.try_into().map_err(bad)?);
    Ok(out)
}

/// Loads `programs` in order, synced to every thread (it also sets
/// `no_new_privs`).
fn load_programs(programs: &[seccompiler::BpfProgram]) -> Result<(), SandboxError> {
    for p in programs {
        seccompiler::apply_filter_all_threads(p).map_err(|_| SandboxError::Seccomp)?;
    }
    Ok(())
}

/// Debug and tests only: the child of `profiles_install_for_real` installs
/// a profile's filters for real when this is set.
#[cfg(test)]
pub(crate) const SECCOMP_CHILD_ENV: &str = "SAIIFE_TEST_SECCOMP_CHILD";

/// Builds and loads `profile`'s filters on this process (the seccomp part
/// of [`confine_helper`] alone; the tests' child process uses it).
#[cfg(test)]
pub(crate) fn install_seccomp(profile: Profile) -> Result<(), SandboxError> {
    let pid = rustix::process::getpid().as_raw_nonzero().get() as u32;
    load_programs(&seccomp_programs(
        profile,
        arch_of(std::env::consts::ARCH)?,
        pid,
    )?)
}

/// Confines the calling helper process for good. Order (R45-12):
/// `no_new_privs`; an empty network namespace (best effort: `EPERM` or
/// `ENOSPC`, user namespaces disabled, goes on with `netns: false`; any
/// other failure refuses); a Landlock ruleset that handles every filesystem
/// right of the ABI, TCP bind and connect (ABI 4 or later) and the scopes
/// (ABI 6 or later), and allows only reading `read_files` (regular files)
/// and the files beneath `read_dirs`; then the `profile`'s seccomp
/// allowlist.
///
/// Fails closed: no Landlock ([`SandboxError::Unavailable`]), a ruleset
/// that is not fully enforced, an arch without tables or a filter that does
/// not load is an error, and the caller must not go on. Call it
/// single-threaded (the namespace needs it; the filter is synced to every
/// thread anyway).
pub fn confine_helper(
    profile: Profile,
    read_files: &[&Path],
    read_dirs: &[&Path],
) -> Result<Confinement, SandboxError> {
    confine_helper_with_abi(landlock_abi(), profile, read_files, read_dirs)
}

/// [`confine_helper`] at a given Landlock ABI (the test seam). ABI 0
/// refuses before anything is changed. An ABI above the kernel's fails
/// (the ruleset is a hard requirement).
pub fn confine_helper_with_abi(
    abi: u32,
    profile: Profile,
    read_files: &[&Path],
    read_dirs: &[&Path],
) -> Result<Confinement, SandboxError> {
    if abi == 0 {
        return Err(SandboxError::Unavailable);
    }
    let pid = rustix::process::getpid().as_raw_nonzero().get() as u32;
    let programs = seccomp_programs(profile, arch_of(std::env::consts::ARCH)?, pid)?;
    rustix::thread::set_no_new_privs(true).map_err(|_| SandboxError::NoNewPrivs)?;
    let netns = enter_empty_netns()?;
    let n = abi.min(6);
    let rules = helper_rules(abi_of(n), read_files, read_dirs)?;
    let status = restrict_helper(abi_of(n), rules).map_err(|_| SandboxError::Ruleset)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(SandboxError::NotEnforced);
    }
    load_programs(&programs)?;
    Ok(Confinement {
        landlock_abi: n,
        net_denied: n >= 4,
        scopes: n >= 6,
        seccomp: true,
        netns,
    })
}

/// A new user and network namespace: the helper then has no network
/// interface but a down loopback. rustix's `unshare` is deprecated for
/// `unshare_unsafe` (it is unsound when `CLONE_FILES` races other threads);
/// the helper is single-threaded and does not pass `FILES`, and the
/// workspace forbids `unsafe`.
#[allow(deprecated)]
fn enter_empty_netns() -> Result<bool, SandboxError> {
    use rustix::thread::{unshare, UnshareFlags};
    netns_outcome(unshare(UnshareFlags::NEWUSER | UnshareFlags::NEWNET))
}

/// `EPERM` (unprivileged user namespaces off) and `ENOSPC`
/// (`user.max_user_namespaces` is 0) both mean no user namespaces here:
/// go on without (`false`). Anything else refuses.
pub(crate) fn netns_outcome(r: rustix::io::Result<()>) -> Result<bool, SandboxError> {
    use rustix::io::Errno;
    match r {
        Ok(()) => Ok(true),
        Err(Errno::PERM | Errno::NOSPC) => Ok(false),
        Err(_) => Err(SandboxError::Netns),
    }
}

/// One read rule per path, from an `O_PATH` descriptor opened now: a
/// `read_files` entry must be a regular file (read only, never execute),
/// a `read_dirs` entry a directory. A path that cannot be opened fails.
fn helper_rules(
    abi: ABI,
    read_files: &[&Path],
    read_dirs: &[&Path],
) -> Result<Vec<PathBeneath<PathFd>>, SandboxError> {
    use rustix::fs::FileType;
    let read = AccessFs::from_read(abi);
    let mut rules = Vec::with_capacity(read_files.len() + read_dirs.len());
    let mut add = |p: &Path, want: FileType, access| {
        let fd = PathFd::new(p).map_err(|_| SandboxError::ReadPath("cannot be opened"))?;
        let st =
            rustix::fs::fstat(&fd).map_err(|_| SandboxError::ReadPath("cannot be resolved"))?;
        if FileType::from_raw_mode(st.st_mode) != want {
            return Err(SandboxError::ReadPath("is not of the expected type"));
        }
        rules.push(PathBeneath::new(fd, access));
        Ok(())
    };
    for f in read_files {
        add(f, FileType::RegularFile, read & AccessFs::from_file(abi))?;
    }
    for d in read_dirs {
        add(d, FileType::Directory, read)?;
    }
    Ok(rules)
}

fn restrict_helper(
    abi: ABI,
    rules: Vec<PathBeneath<PathFd>>,
) -> Result<RestrictionStatus, landlock::RulesetError> {
    let mut r = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))?;
    if abi as i32 >= ABI::V4 as i32 {
        r = r.handle_access(AccessNet::from_all(abi))?;
    }
    if abi as i32 >= ABI::V6 as i32 {
        r = r.scope(Scope::from_all(abi))?;
    }
    r.create()?
        .add_rules(rules.into_iter().map(Ok::<_, landlock::RulesetError>))?
        .restrict_self()
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
    use seccompiler::TargetArch;

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

    #[test]
    fn confine_refuses_without_landlock() {
        // ABI 0 refuses before anything is changed (this test process stays
        // unconfined): fail closed, never run unconfined.
        let f = Path::new("/nonexistent/snapshot.sqlite");
        assert_eq!(
            confine_helper_with_abi(0, Profile::Calc, &[f], &[]).unwrap_err(),
            SandboxError::Unavailable
        );
        assert_eq!(SandboxError::Unavailable.code(), "sandbox_unavailable");
        assert_eq!(CALC_LABEL, "calculator not in a box (weaker)");
    }

    #[test]
    fn seccomp_filter_builds() {
        for arch in [TargetArch::x86_64, TargetArch::aarch64] {
            for profile in [Profile::Calc, Profile::Ner] {
                let progs = seccomp_programs(profile, arch, 4242).unwrap();
                // The allowlist is installed last: the arch check, one chain
                // per allowed number, the default.
                let allowlist = progs.last().unwrap();
                assert!(allowlist.len() > 3 + profile.allowed().count(), "{arch:?}");
                // Ner installs the clone3 -> ENOSYS filter first (glibc then
                // uses clone), while installing a filter is still allowed.
                assert_eq!(progs.len(), if profile == Profile::Ner { 2 } else { 1 });
            }
        }
    }

    #[test]
    fn allowlists_exclude_forbidden_syscalls() {
        for profile in [Profile::Calc, Profile::Ner] {
            for (name, x86, arm) in FORBIDDEN_SYSCALLS {
                // The one scoped exception: Ner lists clone3 so that the
                // earlier ENOSYS filter answers it (ner_threads_and_clone3_enosys).
                if profile == Profile::Ner && name == "clone3" {
                    continue;
                }
                for e in profile.allowed() {
                    assert!(e.x86_64 != x86, "{profile:?} allows {name} on x86_64");
                    assert!(
                        arm < 0 || e.aarch64 != arm,
                        "{profile:?} allows {name} on aarch64"
                    );
                }
            }
        }
        // clone only for the name helper's threads, never unconditional.
        assert!(Profile::Calc.allowed().all(|e| e.name != "clone"));
        let clone = Profile::Ner.allowed().find(|e| e.name == "clone").unwrap();
        assert_eq!(clone.arg, ArgRule::ThreadFlags);
        // Every entry says why it is there; no number twice.
        for profile in [Profile::Calc, Profile::Ner] {
            let mut seen = std::collections::BTreeSet::new();
            for e in profile.allowed() {
                assert!(!e.why.is_empty(), "{}", e.name);
                assert!(seen.insert(e.x86_64), "{} twice", e.name);
            }
        }
        let forbidden: Vec<&str> = FORBIDDEN_SYSCALLS.iter().map(|f| f.0).collect();
        for must in [
            "socket",
            "socketpair",
            "connect",
            "bind",
            "listen",
            "accept",
            "accept4",
            "sendto",
            "sendmsg",
            "sendmmsg",
            "recvfrom",
            "recvmsg",
            "recvmmsg",
            "clone3",
            "unshare",
            "setns",
            "execve",
            "execveat",
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            "bpf",
            "perf_event_open",
            "userfaultfd",
            "keyctl",
            "pidfd_open",
            "pidfd_getfd",
            "pidfd_send_signal",
        ] {
            assert!(forbidden.contains(&must), "{must}");
        }
    }

    /// The hand-written numbers are the kernel's, as libc has them for the
    /// running arch (the other arch's column is from seccompiler's table).
    #[test]
    fn syscall_numbers_match_libc() {
        let col = |x86: i64, arm: i64| {
            if cfg!(target_arch = "aarch64") {
                arm
            } else {
                x86
            }
        };
        let all = Profile::Ner
            .allowed()
            .map(|e| (e.name, col(e.x86_64, e.aarch64)))
            .chain(FORBIDDEN_SYSCALLS.iter().map(|f| (f.0, col(f.1, f.2))));
        for (name, n) in all {
            if n < 0 {
                continue;
            }
            assert_eq!(Some(n), libc_number(name), "{name}");
        }
    }

    #[test]
    fn arch_table_refuses_other_arches() {
        assert_eq!(arch_of("x86_64"), Ok(TargetArch::x86_64));
        assert_eq!(arch_of("aarch64"), Ok(TargetArch::aarch64));
        for other in ["riscv64", "x86", "arm", "powerpc64", "s390x", ""] {
            assert_eq!(arch_of(other), Err(SandboxError::Seccomp), "{other}");
        }
    }

    #[test]
    fn netns_tolerates_eperm_and_enospc_only() {
        use rustix::io::Errno;
        assert_eq!(netns_outcome(Ok(())), Ok(true));
        assert_eq!(netns_outcome(Err(Errno::PERM)), Ok(false));
        assert_eq!(netns_outcome(Err(Errno::NOSPC)), Ok(false));
        for e in [Errno::INVAL, Errno::NOMEM, Errno::USERS, Errno::NOSYS] {
            assert_eq!(netns_outcome(Err(e)), Err(SandboxError::Netns), "{e:?}");
        }
    }

    // --- A small classic-BPF interpreter for the subset seccompiler emits,
    // so the compiled rules can be checked call by call on both arches. ---

    const RET_ALLOW: u32 = 0x7fff_0000;
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_KILL_PROCESS: u32 = 0x8000_0000;
    const AUDIT_X86_64: u32 = 0xC000_003E;
    const AUDIT_AARCH64: u32 = 0xC000_00B7;
    const EPERM: u32 = 1;
    const ENOSYS: u32 = 38;

    /// `struct seccomp_data` (little-endian): nr, arch, ip, args[6].
    fn seccomp_data(arch: u32, nr: i64, args: [u64; 6]) -> Vec<u8> {
        let mut d = Vec::with_capacity(64);
        d.extend_from_slice(&(nr as i32).to_le_bytes());
        d.extend_from_slice(&arch.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
        for a in args {
            d.extend_from_slice(&a.to_le_bytes());
        }
        d
    }

    fn run_bpf(prog: &[seccompiler::sock_filter], data: &[u8]) -> u32 {
        let mut a: u32 = 0;
        let mut pc = 0usize;
        loop {
            let i = &prog[pc];
            pc += 1;
            match i.code {
                0x20 => {
                    let k = i.k as usize;
                    a = u32::from_le_bytes(data[k..k + 4].try_into().unwrap());
                }
                0x54 => a &= i.k,
                0x15 => pc += usize::from(if a == i.k { i.jt } else { i.jf }),
                0x25 => pc += usize::from(if a > i.k { i.jt } else { i.jf }),
                0x35 => pc += usize::from(if a >= i.k { i.jt } else { i.jf }),
                0x05 => pc += i.k as usize,
                0x06 => return i.k,
                c => panic!("BPF opcode {c:#x} not modelled"),
            }
        }
    }

    /// The kernel's verdict over stacked filters: the most restrictive
    /// action wins; on a tie the newest (installed last) filter's.
    fn verdict(profile: Profile, arch: TargetArch, nr: &str, args: [u64; 6], pid: u32) -> u32 {
        let progs = seccomp_programs(profile, arch, pid).unwrap();
        let (audit, n) = match arch {
            TargetArch::x86_64 => (AUDIT_X86_64, number(nr, true)),
            _ => (AUDIT_AARCH64, number(nr, false)),
        };
        let data = seccomp_data(audit, n, args);
        let mut ret = RET_ALLOW;
        for p in progs.iter().rev() {
            let cur = run_bpf(p, &data);
            if ((cur & 0xffff_0000) as i32) < ((ret & 0xffff_0000) as i32) {
                ret = cur;
            }
        }
        ret
    }

    /// The number of `name` on x86_64 (`true`) or aarch64, from the tables.
    fn number(name: &str, x86: bool) -> i64 {
        let pick = |a: i64, b: i64| if x86 { a } else { b };
        if let Some(e) = Profile::Ner.allowed().find(|e| e.name == name) {
            return pick(e.x86_64, e.aarch64);
        }
        if let Some(f) = FORBIDDEN_SYSCALLS.iter().find(|f| f.0 == name) {
            return pick(f.1, f.2);
        }
        match name {
            "ioctl" => pick(16, 29),
            "fcntl_unknown" => pick(72, 25),
            _ => panic!("no number for {name}"),
        }
    }

    fn a(args: &[u64]) -> [u64; 6] {
        let mut out = [0u64; 6];
        out[..args.len()].copy_from_slice(args);
        out
    }

    const PID: u32 = 4242;
    const ARCHES: [TargetArch; 2] = [TargetArch::x86_64, TargetArch::aarch64];

    #[test]
    fn calc_rules_match_only_traced_arguments() {
        let allow = RET_ALLOW;
        let eperm = RET_ERRNO | EPERM;
        for arch in ARCHES {
            let v = |nr, args: &[u64]| verdict(Profile::Calc, arch, nr, a(args), PID);
            // fcntl: F_GETFD, F_SETFD, F_GETFL only (A1); F_SETFL (O_ASYNC),
            // F_SETOWN, F_SETSIG, F_SETOWN_EX, F_SETLEASE and the locks refused.
            for cmd in [1, 2, 3] {
                assert_eq!(v("fcntl", &[3, cmd]), allow, "{arch:?} fcntl {cmd}");
            }
            for cmd in [0, 4, 5, 6, 7, 8, 10, 15, 36, 37, 38, 1024, 1025, 1030] {
                assert_eq!(v("fcntl", &[3, cmd]), eperm, "{arch:?} fcntl {cmd}");
            }
            // mmap / mprotect never executable (A2).
            for prot in [0, 1, 3] {
                assert_eq!(v("mmap", &[0, 4096, prot, 0x22]), allow);
                assert_eq!(v("mprotect", &[0, 4096, prot]), allow);
            }
            for prot in [4, 5, 7] {
                assert_eq!(v("mmap", &[0, 4096, prot, 0x22]), eperm);
                assert_eq!(v("mprotect", &[0, 4096, prot]), eperm);
            }
            // openat read-only only: O_WRONLY, O_RDWR, O_CREAT, O_TRUNC,
            // O_APPEND refused before Landlock even looks.
            for flags in [0, 0o2_000_000, 0o2_400_000] {
                assert_eq!(v("openat", &[0, 0, flags]), allow, "{flags:o}");
            }
            for flags in [0o1, 0o2, 0o100, 0o1000, 0o2000, 0o2_000_101] {
                assert_eq!(v("openat", &[0, 0, flags]), eperm, "{flags:o}");
            }
            // write: stdout and stderr only.
            assert_eq!(v("write", &[1]), allow);
            assert_eq!(v("write", &[2]), allow);
            for fd in [0, 3, 9] {
                assert_eq!(v("write", &[fd]), eperm, "write {fd}");
            }
            // Signals to itself only (abort).
            assert_eq!(v("tgkill", &[u64::from(PID), u64::from(PID), 6]), allow);
            assert_eq!(v("tgkill", &[1, 1, 9]), eperm);
            assert_eq!(v("tkill", &[u64::from(PID), 6]), allow);
            assert_eq!(v("tkill", &[1, 9]), eperm);
            // Not listed at all.
            for nr in [
                "socket",
                "execve",
                "ptrace",
                "io_uring_setup",
                "clone",
                "clone3",
                "unshare",
                "prctl",
                "seccomp",
                "ioctl",
            ] {
                assert_eq!(v(nr, &[]), eperm, "{arch:?} {nr}");
            }
        }
        // Another arch's call (the i386 ABI) kills the process.
        let progs = seccomp_programs(Profile::Calc, TargetArch::x86_64, PID).unwrap();
        let i386 = seccomp_data(0x4000_0003, 0, a(&[]));
        assert_eq!(run_bpf(&progs[0], &i386), RET_KILL_PROCESS);
    }

    #[test]
    fn ner_threads_and_clone3_enosys() {
        let thread = THREAD_CLONE_FLAGS;
        for arch in ARCHES {
            let v = |nr, args: &[u64]| verdict(Profile::Ner, arch, nr, a(args), PID);
            assert_eq!(v("clone", &[thread]), RET_ALLOW, "{arch:?}");
            // A fork (SIGCHLD exit signal), namespaces, no CLONE_THREAD.
            for flags in [
                17,
                thread | 0x1000_0000,
                thread | 0x4000_0000,
                thread & !CLONE_THREAD,
            ] {
                assert_eq!(v("clone", &[flags]), RET_ERRNO | EPERM, "{flags:#x}");
            }
            // The earlier filter's ENOSYS wins over the allowlist's allow.
            assert_eq!(v("clone3", &[]), RET_ERRNO | ENOSYS, "{arch:?}");
            assert_eq!(v("prctl", &[PR_SET_NAME]), RET_ALLOW);
            assert_eq!(v("prctl", &[38]), RET_ERRNO | EPERM);
            assert_eq!(v("socket", &[]), RET_ERRNO | EPERM);
        }
    }

    /// R1: the shipped Linux binaries are static musl. On x86_64 musl uses
    /// the legacy calls; on aarch64 there are none and it uses the `*at` ones.
    #[test]
    fn musl_forms_are_listed() {
        let calc: Vec<&Allowed> = Profile::Calc.allowed().collect();
        let find = |n: &str| calc.iter().find(|e| e.name == n).copied();
        for legacy in ["open", "stat", "lstat", "access", "readlink"] {
            let e = find(legacy).unwrap_or_else(|| panic!("{legacy}"));
            assert!(e.x86_64 > 0 && e.aarch64 < 0, "{legacy}");
        }
        for at in ["openat", "newfstatat", "faccessat", "readlinkat", "tkill"] {
            let e = find(at).unwrap_or_else(|| panic!("{at}"));
            assert!(e.x86_64 > 0 && e.aarch64 > 0, "{at}");
        }
        assert_eq!(find("open").unwrap().arg, ArgRule::ReadOnlyOpen(1));
        assert_eq!(find("openat").unwrap().arg, ArgRule::ReadOnlyOpen(2));
        assert_eq!(find("tkill").unwrap().arg, ArgRule::OwnPid);
        // open on x86_64 is read-only too.
        let v = |flags| {
            verdict(
                Profile::Calc,
                TargetArch::x86_64,
                "open",
                a(&[0, flags]),
                PID,
            )
        };
        assert_eq!(v(0o2_000_000), RET_ALLOW);
        assert_eq!(v(0o1), RET_ERRNO | EPERM);
    }

    /// Run by `profiles_install_for_real` in a child test process only:
    /// installs a profile's filters for real (no Landlock, no namespace:
    /// libtest is multi-threaded) and reports what still works.
    #[test]
    fn seccomp_child() {
        let Some(name) = std::env::var_os(SECCOMP_CHILD_ENV) else {
            return;
        };
        let profile = match name.to_str() {
            Some("calc") => Profile::Calc,
            Some("ner") => Profile::Ner,
            _ => panic!("unknown profile"),
        };
        let installed = install_seccomp(profile);
        let socket = std::net::TcpListener::bind(("127.0.0.1", 0))
            .err()
            .and_then(|e| e.raw_os_error());
        let thread = std::thread::Builder::new()
            .name("p45-ner".into())
            .spawn(|| 7)
            .map(|h| h.join().unwrap_or(0))
            .map_err(|e| e.raw_os_error());
        let async_io = rustix::fs::fcntl_setfl(std::io::stdin(), rustix::fs::OFlags::ASYNC)
            .err()
            .map(|e| e.raw_os_error());
        println!(
            "P45-CHILD installed={:?} socket={socket:?} thread={thread:?} setfl={async_io:?}",
            installed.is_ok()
        );
    }

    #[test]
    fn profiles_install_for_real() {
        let exe = std::env::current_exe().unwrap();
        for (name, thread) in [("calc", "thread=Err("), ("ner", "thread=Ok(7)")] {
            let out = std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "sandbox::tests::seccomp_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(SECCOMP_CHILD_ENV, name)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            // libtest prints the report after "test ... " on the same line.
            let line = stdout
                .lines()
                .find_map(|l| l.find("P45-CHILD").map(|i| &l[i..]))
                .unwrap_or_else(|| panic!("{name}: no report: {stdout} {:?}", out.status));
            assert!(line.contains("installed=true"), "{name}: {line}");
            assert!(line.contains("socket=Some(1)"), "{name}: {line}");
            assert!(line.contains(thread), "{name}: {line}");
            assert!(line.contains("setfl=Some(1)"), "{name}: {line}");
            assert!(out.status.success(), "{name}: {:?} {stdout}", out.status);
        }
    }

    /// `libc::SYS_*` of the running arch by name.
    fn libc_number(name: &str) -> Option<i64> {
        #[cfg(target_arch = "x86_64")]
        match name {
            "fork" => return Some(libc::SYS_fork),
            "vfork" => return Some(libc::SYS_vfork),
            "open" => return Some(libc::SYS_open),
            "stat" => return Some(libc::SYS_stat),
            "lstat" => return Some(libc::SYS_lstat),
            "access" => return Some(libc::SYS_access),
            "readlink" => return Some(libc::SYS_readlink),
            _ => {}
        }
        Some(match name {
            "read" => libc::SYS_read,
            "write" => libc::SYS_write,
            "pread64" => libc::SYS_pread64,
            "openat" => libc::SYS_openat,
            "close" => libc::SYS_close,
            "fstat" => libc::SYS_fstat,
            "newfstatat" => libc::SYS_newfstatat,
            "mmap" => libc::SYS_mmap,
            "munmap" => libc::SYS_munmap,
            "mprotect" => libc::SYS_mprotect,
            "brk" => libc::SYS_brk,
            "mremap" => libc::SYS_mremap,
            "madvise" => libc::SYS_madvise,
            "fcntl" => libc::SYS_fcntl,
            "getpid" => libc::SYS_getpid,
            "gettid" => libc::SYS_gettid,
            "tgkill" => libc::SYS_tgkill,
            "rt_sigaction" => libc::SYS_rt_sigaction,
            "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
            "rt_sigreturn" => libc::SYS_rt_sigreturn,
            "futex" => libc::SYS_futex,
            "getrandom" => libc::SYS_getrandom,
            "clock_gettime" => libc::SYS_clock_gettime,
            "exit" => libc::SYS_exit,
            "exit_group" => libc::SYS_exit_group,
            "sched_yield" => libc::SYS_sched_yield,
            "clone" => libc::SYS_clone,
            "clone3" => libc::SYS_clone3,
            "set_robust_list" => libc::SYS_set_robust_list,
            "rseq" => libc::SYS_rseq,
            "sched_getaffinity" => libc::SYS_sched_getaffinity,
            "sigaltstack" => libc::SYS_sigaltstack,
            "prctl" => libc::SYS_prctl,
            "unshare" => libc::SYS_unshare,
            "setns" => libc::SYS_setns,
            "bpf" => libc::SYS_bpf,
            "perf_event_open" => libc::SYS_perf_event_open,
            "userfaultfd" => libc::SYS_userfaultfd,
            "keyctl" => libc::SYS_keyctl,
            "add_key" => libc::SYS_add_key,
            "request_key" => libc::SYS_request_key,
            "pidfd_open" => libc::SYS_pidfd_open,
            "pidfd_getfd" => libc::SYS_pidfd_getfd,
            "pidfd_send_signal" => libc::SYS_pidfd_send_signal,
            "io_uring_setup" => libc::SYS_io_uring_setup,
            "io_uring_enter" => libc::SYS_io_uring_enter,
            "io_uring_register" => libc::SYS_io_uring_register,
            "mount" => libc::SYS_mount,
            "umount2" => libc::SYS_umount2,
            "pivot_root" => libc::SYS_pivot_root,
            "chroot" => libc::SYS_chroot,
            "init_module" => libc::SYS_init_module,
            "finit_module" => libc::SYS_finit_module,
            "delete_module" => libc::SYS_delete_module,
            "kexec_load" => libc::SYS_kexec_load,
            "process_madvise" => libc::SYS_process_madvise,
            "seccomp" => libc::SYS_seccomp,
            "kill" => libc::SYS_kill,
            "tkill" => libc::SYS_tkill,
            "faccessat" => libc::SYS_faccessat,
            "readlinkat" => libc::SYS_readlinkat,
            "socket" => libc::SYS_socket,
            "socketpair" => libc::SYS_socketpair,
            "connect" => libc::SYS_connect,
            "bind" => libc::SYS_bind,
            "listen" => libc::SYS_listen,
            "accept" => libc::SYS_accept,
            "accept4" => libc::SYS_accept4,
            "sendto" => libc::SYS_sendto,
            "sendmsg" => libc::SYS_sendmsg,
            "sendmmsg" => libc::SYS_sendmmsg,
            "recvfrom" => libc::SYS_recvfrom,
            "recvmsg" => libc::SYS_recvmsg,
            "recvmmsg" => libc::SYS_recvmmsg,
            "ptrace" => libc::SYS_ptrace,
            "process_vm_readv" => libc::SYS_process_vm_readv,
            "process_vm_writev" => libc::SYS_process_vm_writev,
            "execve" => libc::SYS_execve,
            "execveat" => libc::SYS_execveat,
            _ => return None,
        })
    }
}
