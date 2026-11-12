//! The box's repo disk, built by the CLI as the user (plan 37 Task 3, spec
//! §7.5 In): a snapshot of the work tree (tracked and untracked, not
//! ignored, uncommitted edits included) copied into a private staging dir,
//! its [`BaseManifest`], the snapshot commit in the user's repo (D9) and the
//! `mke2fs -d` image of the staging dir (D4).
//!
//! The work tree is user-controlled data: nothing in it is followed on the
//! host. Each path is walked from the repo root one component at a time
//! with `O_NOFOLLOW` (a tracked `a/b` whose `a` became a symlink is skipped
//! with a warning), sources are opened `O_NOFOLLOW|O_NONBLOCK` (a FIFO never
//! blocks) and `fstat`ed (a regular file, the same dev/ino as the `lstat`),
//! and the copy is bounded by the `fstat` size. Staging entries are created
//! relative to directory fds, `O_CREAT|O_EXCL`, never through a symlink.
//!
//! Staging layout (ruling R2): `<cache>/box-spawn/<16 hex>/` (0700) holds
//! `tree/` (the snapshot), `repo.img` and the snapshot commit's temporary
//! `index`. Removing the staging means removing that whole dir.

use rustix::fs::{AtFlags, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;
use saiife_boxhost::tools::{Tool, ToolError, Tools};
use saiife_boxproto::manifest::{self, check_path, BaseManifest, Entry, EntryKind};
use saiife_wire::source::BoxId;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// D5: the most a box repo may hold, summed as in D4.
pub const REPO_MAX_BYTES: u64 = 8 << 30;
/// D5: the most files (and symlinks) a box repo may hold.
pub const REPO_MAX_FILES: u64 = 200_000;

const BLOCK: u64 = 4096;
const MIB: u64 = 1 << 20;
/// The longest `mke2fs -d` may take (an 8 GiB repo on a slow disk).
const MKE2FS_TIMEOUT: Duration = Duration::from_secs(1800);
/// How many of the biggest top-level entries an oversized refusal names.
const TOP: usize = 5;

/// Git's own location variables a caller's environment may carry (from a
/// hook, say); every git call here runs against `-C <repo>` alone.
const GIT_SCRUB: [&str; 8] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
];

/// A staged snapshot. `staging` is `<cache>/box-spawn/<16 hex>/tree`; the
/// caller removes the staging with [`Snapshot::remove`] once the disk has
/// gone to the daemon (or the spawn failed).
#[derive(Debug)]
pub struct Snapshot {
    pub staging: PathBuf,
    pub manifest: BaseManifest,
    pub warnings: Vec<String>,
}

impl Snapshot {
    /// The `<16 hex>` dir that holds `tree/`, `repo.img` and `index`.
    pub fn dir(&self) -> &Path {
        self.staging.parent().unwrap_or(&self.staging)
    }

    /// Remove the whole staging dir (best effort). std's `remove_dir_all`
    /// does not follow symlinks.
    pub fn remove(self) {
        remove_tree(self.dir());
    }
}

fn remove_tree(p: &Path) {
    let _ = std::fs::remove_dir_all(p);
}

/// Removes the staging dir when dropped, unless disarmed.
struct Cleanup(Option<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            remove_tree(&p);
        }
    }
}

fn max_files() -> u64 {
    #[cfg(debug_assertions)]
    if let Some(n) = std::env::var("SAIIFE_TEST_REPO_MAX_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return n;
    }
    REPO_MAX_FILES
}

fn round_up(n: u64) -> u64 {
    n.div_ceil(BLOCK).saturating_mul(BLOCK)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn esc(bytes: &[u8]) -> String {
    bytes.escape_ascii().to_string()
}

fn human(n: u64) -> String {
    if n >= 1 << 30 {
        format!("{:.1} GiB", n as f64 / (1u64 << 30) as f64)
    } else if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else {
        format!("{} KiB", n.div_ceil(1024))
    }
}

// ---------------------------------------------------------------- git

fn git_cmd(tools: &Tools, repo: &Path, index: Option<&Path>) -> Command {
    let mut c = Command::new(tools.path(Tool::Git));
    c.arg("-C").arg(repo).args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
    ]);
    for v in GIT_SCRUB {
        c.env_remove(v);
    }
    c.env("GIT_TERMINAL_PROMPT", "0");
    if let Some(i) = index {
        c.env("GIT_INDEX_FILE", i);
    }
    c
}

/// Run git with `input` on stdin; the exit status and stdout, or why it
/// could not run.
fn git_run(
    tools: &Tools,
    repo: &Path,
    index: Option<&Path>,
    args: &[&OsStr],
    input: Option<Vec<u8>>,
) -> Result<std::process::Output, String> {
    git_run_env(tools, repo, index, args, input, &[])
}

/// [`git_run`] with `env` set for this one call.
fn git_run_env(
    tools: &Tools,
    repo: &Path,
    index: Option<&Path>,
    args: &[&OsStr],
    input: Option<Vec<u8>>,
    env: &[(&str, &str)],
) -> Result<std::process::Output, String> {
    let mut c = git_cmd(tools, repo, index);
    c.envs(env.iter().copied());
    c.args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c
        .spawn()
        .map_err(|e| format!("cannot run git ({}): {e}", tools.path(Tool::Git).display()))?;
    let writer = match (input, child.stdin.take()) {
        (Some(body), Some(mut stdin)) => Some(std::thread::spawn(move || {
            let _ = stdin.write_all(&body);
        })),
        _ => None,
    };
    let out = child.wait_with_output().map_err(|e| format!("git: {e}"))?;
    if let Some(w) = writer {
        let _ = w.join();
    }
    Ok(out)
}

fn git_ok(
    tools: &Tools,
    repo: &Path,
    index: Option<&Path>,
    args: &[&str],
    input: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    git_ok_env(tools, repo, index, args, input, &[])
}

/// [`git_ok`] with `env` set for this one call.
fn git_ok_env(
    tools: &Tools,
    repo: &Path,
    index: Option<&Path>,
    args: &[&str],
    input: Option<Vec<u8>>,
    env: &[(&str, &str)],
) -> Result<Vec<u8>, String> {
    let a: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let out = git_run_env(tools, repo, index, &a, input, env)?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            err.trim()
        ));
    }
    Ok(out.stdout)
}

fn trim_nl(mut b: Vec<u8>) -> Vec<u8> {
    while b.last().is_some_and(|c| *c == b'\n' || *c == b'\r') {
        b.pop();
    }
    b
}

fn one_oid(b: Vec<u8>, what: &str) -> Result<String, String> {
    let s = String::from_utf8(trim_nl(b)).map_err(|_| format!("git {what}: not an id"))?;
    if manifest::is_oid(&s) {
        Ok(s)
    } else {
        Err(format!("git {what}: {s:?} is not an object id"))
    }
}

// ---------------------------------------------------------------- walk

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// The parent dir of a path, walked from `root` one component at a time
/// without following a symlink; with `create`, missing dirs are made 0755
/// (`made` counts them). The last walk is cached: `ls-files` is sorted.
struct Parents {
    root: OwnedFd,
    last: Option<(String, OwnedFd)>,
    create: bool,
    made: u64,
}

impl Parents {
    fn new(root: OwnedFd, create: bool) -> Parents {
        Parents {
            root,
            last: None,
            create,
            made: 0,
        }
    }

    /// The fd of `parent` ("" is the root).
    fn get(&mut self, parent: &str) -> Result<&OwnedFd, Errno> {
        if parent.is_empty() {
            return Ok(&self.root);
        }
        if self.last.as_ref().map(|(p, _)| p.as_str()) != Some(parent) {
            let mut cur: Option<OwnedFd> = None;
            for comp in parent.split('/') {
                let at = cur.as_ref().unwrap_or(&self.root).as_fd();
                let fd = match rustix::fs::openat(at, comp, dir_flags(), Mode::empty()) {
                    Err(Errno::NOENT) if self.create => {
                        rustix::fs::mkdirat(at, comp, Mode::from_raw_mode(0o755))?;
                        self.made += 1;
                        let fd = rustix::fs::openat(at, comp, dir_flags(), Mode::empty())?;
                        rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o755))?;
                        fd
                    }
                    r => r?,
                };
                cur = Some(fd);
            }
            self.last = Some((parent.to_string(), cur.expect("a non-empty parent")));
        }
        Ok(&self.last.as_ref().expect("just set").1)
    }
}

fn split(p: &str) -> (&str, &str) {
    p.rsplit_once('/').unwrap_or(("", p))
}

/// What one listed path is on disk, seen without following anything.
enum Seen {
    /// Gone (deleted but still tracked): skipped silently.
    Gone,
    /// Skipped, with the warning.
    Skip(String),
    File(rustix::fs::Stat),
    Link,
}

fn look(repo: &mut Parents, p: &str) -> Result<Seen, String> {
    let (parent, name) = split(p);
    let dir = match repo.get(parent) {
        Ok(d) => d,
        Err(Errno::NOENT) => return Ok(Seen::Gone),
        Err(Errno::LOOP | Errno::NOTDIR) => {
            return Ok(Seen::Skip(format!(
                "{p:?}: skipped, a parent directory is now a symlink or a file"
            )))
        }
        Err(e) => return Err(format!("{p:?}: {e}")),
    };
    let st = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Ok(Seen::Gone),
        Err(e) => return Err(format!("{p:?}: {e}")),
    };
    Ok(match FileType::from_raw_mode(st.st_mode) {
        FileType::RegularFile => Seen::File(st),
        FileType::Symlink => Seen::Link,
        FileType::Directory => Seen::Skip(format!(
            "{p:?}: skipped, a directory (a submodule or a nested repo)"
        )),
        _ => Seen::Skip(format!(
            "{p:?}: skipped, not a file or symlink (a FIFO, socket or device)"
        )),
    })
}

/// The listed paths: UTF-8 (else refused, bytes escaped), passing
/// `check_path` (else refused), deduplicated; a trailing `/` (an untracked
/// nested repo) is skipped with a warning.
fn listed(raw: &[u8], warnings: &mut Vec<String>) -> Result<Vec<String>, String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for p in raw.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        if p.ends_with(b"/") {
            warnings.push(format!(
                "\"{}\": skipped, a directory (a nested repo)",
                esc(p)
            ));
            continue;
        }
        let s = std::str::from_utf8(p).map_err(|_| {
            format!(
                "the path \"{}\" in the repo is not UTF-8; rename it, a box repo holds UTF-8 paths only",
                esc(p)
            )
        })?;
        check_path(s).map_err(|e| format!("{e}; rename it to spawn a box from this repo"))?;
        if seen.insert(s.to_string()) {
            out.push(s.to_string());
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cap {
    Files,
    Bytes,
}

/// The refusal of an oversized repo: the cap and the biggest top-level
/// entries (measured without following anything).
fn oversized(root: &Path, paths: &[String], cap: Cap) -> String {
    let mut top: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    if let Ok(fd) = rustix::fs::openat(CWD, root, dir_flags(), Mode::empty()) {
        let mut repo = Parents::new(fd, false);
        for p in paths {
            let size = match look(&mut repo, p) {
                Ok(Seen::File(st)) => round_up(st.st_size.max(0) as u64),
                Ok(Seen::Link) => BLOCK,
                _ => continue,
            };
            let key = match p.split_once('/') {
                Some((first, _)) => format!("{first}/"),
                None => p.clone(),
            };
            let t = top.entry(key).or_default();
            t.0 += 1;
            t.1 = t.1.saturating_add(size);
        }
    }
    let mut v: Vec<(String, (u64, u64))> = top.into_iter().collect();
    v.sort_by(|a, b| match cap {
        Cap::Files => b.1 .0.cmp(&a.1 .0).then(b.1 .1.cmp(&a.1 .1)),
        Cap::Bytes => b.1 .1.cmp(&a.1 .1).then(b.1 .0.cmp(&a.1 .0)),
    });
    let names: Vec<String> = v
        .iter()
        .take(TOP)
        .map(|(k, (n, b))| {
            let s = if *n == 1 { "" } else { "s" };
            format!("{k} ({n} file{s}, {})", human(*b))
        })
        .collect();
    let what = match cap {
        Cap::Files => format!("more than {} files (REPO_MAX_FILES)", max_files()),
        Cap::Bytes => format!("more than {} GiB (REPO_MAX_BYTES)", REPO_MAX_BYTES >> 30),
    };
    format!(
        "the repo is too big for a box: {what}; the biggest top-level entries: {}. \
         Is an ignore rule missing (build output, say)? Add it to .gitignore and spawn again",
        names.join(", ")
    )
}

struct Walk {
    repo: Parents,
    stage: Parents,
    entries: BTreeMap<String, Entry>,
    warnings: Vec<String>,
    bytes: u64,
    d4: u64,
}

impl Walk {
    fn over(&self, more_d4: u64) -> Option<Cap> {
        let dirs = self.stage.made.saturating_mul(BLOCK);
        if self.entries.len() as u64 + 1 > max_files() {
            Some(Cap::Files)
        } else if self.d4.saturating_add(dirs).saturating_add(more_d4) > REPO_MAX_BYTES {
            Some(Cap::Bytes)
        } else {
            None
        }
    }

    /// The staging parent of `p`, or a warning when it resolves through
    /// something that is not a directory we made.
    fn stage_parent(&mut self, p: &str) -> Result<Option<OwnedFd>, String> {
        let (parent, _) = split(p);
        match self.stage.get(parent) {
            Ok(fd) => Ok(Some(fd.try_clone().map_err(|e| format!("staging: {e}"))?)),
            Err(Errno::LOOP | Errno::NOTDIR | Errno::EXIST) => {
                self.warnings.push(format!(
                    "{p:?}: skipped, its parent in the snapshot is a symlink or a file"
                ));
                Ok(None)
            }
            Err(e) => Err(format!("staging {p:?}: {e}")),
        }
    }

    fn copy_file(&mut self, p: &str, lst: &rustix::fs::Stat) -> Result<Option<Cap>, String> {
        let (parent, name) = split(p);
        let changed = || format!("{p:?} changed while it was copied; spawn again");
        let dir = self.repo.get(parent).map_err(|_| changed())?;
        let fd = match rustix::fs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::LOOP) => return Err(changed()),
            Err(e) => return Err(format!("cannot read {p:?}: {e}")),
        };
        let st = rustix::fs::fstat(&fd).map_err(|e| format!("{p:?}: {e}"))?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
            || st.st_dev != lst.st_dev
            || st.st_ino != lst.st_ino
        {
            return Err(changed());
        }
        let size = st.st_size.max(0) as u64;
        if let Some(cap) = self.over(round_up(size)) {
            return Ok(Some(cap));
        }
        let Some(sdir) = self.stage_parent(p)? else {
            return Ok(None);
        };
        let mode = if st.st_mode & 0o111 != 0 {
            0o755
        } else {
            0o644
        };
        let out = rustix::fs::openat(
            &sdir,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| format!("staging {p:?}: {e}"))?;
        let mut out = std::fs::File::from(out);
        let mut src = std::fs::File::from(fd).take(size);
        let mut ctx = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut n_total = 0u64;
        loop {
            let n = src
                .read(&mut buf)
                .map_err(|e| format!("cannot read {p:?}: {e}"))?;
            if n == 0 {
                break;
            }
            ctx.update(&buf[..n]);
            out.write_all(&buf[..n])
                .map_err(|e| format!("staging {p:?}: {e}"))?;
            n_total += n as u64;
        }
        rustix::fs::fchmod(&out, Mode::from_raw_mode(mode))
            .map_err(|e| format!("staging {p:?}: {e}"))?;
        self.bytes += n_total;
        self.d4 = self.d4.saturating_add(round_up(n_total));
        self.entries.insert(
            p.to_string(),
            Entry {
                kind: EntryKind::File,
                mode,
                size: n_total,
                sha256: hex(&ctx.finalize()),
            },
        );
        Ok(None)
    }

    fn copy_link(&mut self, p: &str) -> Result<Option<Cap>, String> {
        if let Some(cap) = self.over(BLOCK) {
            return Ok(Some(cap));
        }
        let (parent, name) = split(p);
        let dir = self.repo.get(parent).map_err(|e| format!("{p:?}: {e}"))?;
        let target = match rustix::fs::readlinkat(dir, name, Vec::new()) {
            Ok(t) => t.into_bytes(),
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::INVAL) => {
                return Err(format!("{p:?} changed while it was copied; spawn again"))
            }
            Err(e) => return Err(format!("{p:?}: {e}")),
        };
        let Some(sdir) = self.stage_parent(p)? else {
            return Ok(None);
        };
        rustix::fs::symlinkat(OsStr::from_bytes(&target), &sdir, name)
            .map_err(|e| format!("staging {p:?}: {e}"))?;
        self.bytes += target.len() as u64;
        self.d4 = self.d4.saturating_add(BLOCK);
        self.entries.insert(
            p.to_string(),
            Entry {
                kind: EntryKind::Symlink,
                mode: 0,
                size: target.len() as u64,
                sha256: hex(&Sha256::digest(&target)),
            },
        );
        Ok(None)
    }
}

fn random_hex() -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "no randomness for the staging dir name".to_string())?;
    Ok(hex(&b))
}

fn display_name(top: &Path) -> String {
    let raw = top
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut s: String = raw
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    while s.len() > manifest::NAME_MAX {
        s.pop();
    }
    if s.is_empty() {
        s = "repo".into();
    }
    s
}

/// Snapshot the work tree of the git repo at `repo` (its top level; a
/// subdirectory is refused with a hint) into a fresh staging dir under
/// `cache` (`$XDG_CACHE_HOME/saiife`, resolved by the caller). The list is
/// `git ls-files -z -co --exclude-standard`: deleted paths are skipped
/// silently; directories (submodules, nested repos), FIFOs, sockets,
/// devices and paths under a symlinked parent with a warning; a non-UTF-8
/// path, a path `check_path` refuses, and a repo over the D5 caps (checked
/// before each copy) are refused. Every failure leaves no staging dir.
pub fn snapshot(tools: &Tools, repo: &Path, cache: &Path) -> Result<Snapshot, String> {
    let canon = repo
        .canonicalize()
        .map_err(|e| format!("cannot open the repo {}: {e}", repo.display()))?;
    let top =
        git_ok(tools, &canon, None, &["rev-parse", "--show-toplevel"], None).map_err(|e| {
            if e.starts_with("cannot run git") {
                e
            } else {
                format!("{} is not a git repo ({e})", canon.display())
            }
        })?;
    let top = PathBuf::from(OsString::from_vec(trim_nl(top)));
    if top != canon {
        return Err(format!(
            "{} is inside the git repo {}; spawn a box from the repo's top level: cd {}",
            canon.display(),
            top.display(),
            top.display()
        ));
    }
    let head = git_run(
        tools,
        &canon,
        None,
        &[
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("-q"),
            OsStr::new("HEAD"),
        ],
        None,
    )?;
    let base_commit = if head.status.success() {
        Some(one_oid(head.stdout, "rev-parse HEAD")?)
    } else {
        None
    };
    let raw = git_ok(
        tools,
        &canon,
        None,
        &["ls-files", "-z", "-co", "--exclude-standard"],
        None,
    )?;
    let mut warnings = Vec::new();
    let paths = listed(&raw, &mut warnings)?;

    let spawn = cache.join("box-spawn");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&spawn)
        .map_err(|e| format!("cannot make {}: {e}", spawn.display()))?;
    // Absolute: git runs with `-C <repo>` and reads the index and the
    // staged paths relative to it otherwise.
    let spawn = spawn
        .canonicalize()
        .map_err(|e| format!("cannot open {}: {e}", spawn.display()))?;
    let dir = spawn.join(random_hex()?);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    let mut guard = Cleanup(Some(dir.clone()));
    let staging = dir.join("tree");
    let sfd = (|| -> rustix::io::Result<OwnedFd> {
        let dfd = rustix::fs::openat(CWD, &dir, dir_flags(), Mode::empty())?;
        rustix::fs::mkdirat(&dfd, "tree", Mode::from_raw_mode(0o755))?;
        let t = rustix::fs::openat(&dfd, "tree", dir_flags(), Mode::empty())?;
        rustix::fs::fchmod(&t, Mode::from_raw_mode(0o755))?;
        Ok(t)
    })()
    .map_err(|e| format!("cannot make {}: {e}", staging.display()))?;
    let rfd = rustix::fs::openat(CWD, &canon, dir_flags(), Mode::empty())
        .map_err(|e| format!("cannot open the repo {}: {e}", canon.display()))?;

    let mut w = Walk {
        repo: Parents::new(rfd, false),
        stage: Parents::new(sfd, true),
        entries: BTreeMap::new(),
        warnings,
        bytes: 0,
        d4: 0,
    };
    for p in &paths {
        let cap = match look(&mut w.repo, p)? {
            Seen::Gone => None,
            Seen::Skip(why) => {
                w.warnings.push(why);
                None
            }
            Seen::File(st) => w.copy_file(p, &st)?,
            Seen::Link => w.copy_link(p)?,
        };
        if let Some(cap) = cap {
            return Err(oversized(&canon, &paths, cap));
        }
    }
    guard.0 = None;
    let manifest = BaseManifest {
        version: manifest::VERSION,
        repo: display_name(&canon),
        base_commit,
        snapshot_commit: String::new(),
        files: w.entries.len() as u64,
        bytes: w.bytes,
        entries: w.entries,
    };
    Ok(Snapshot {
        staging,
        manifest,
        warnings: w.warnings,
    })
}

/// D4: `ceil((2 × bytes + 256 MiB) / 1 MiB)`, where `bytes` is the sum of
/// the files' sizes, each rounded up to 4096, plus 4096 per symlink and per
/// directory. `dirs` counts the directories under the staging root; the
/// root itself is not counted.
pub fn repo_image_mib(m: &BaseManifest, dirs: u64) -> u64 {
    let mut bytes = dirs.saturating_mul(BLOCK);
    for e in m.entries.values() {
        bytes = bytes.saturating_add(match e.kind {
            EntryKind::File => round_up(e.size),
            EntryKind::Symlink => BLOCK,
        });
    }
    bytes
        .saturating_mul(2)
        .saturating_add(256 * MIB)
        .div_ceil(MIB)
}

/// The directories the staging holds below its root: every proper parent
/// of an entry.
fn staging_dirs(m: &BaseManifest) -> u64 {
    let mut dirs = BTreeSet::new();
    for p in m.entries.keys() {
        let mut cur = p.as_str();
        while let Some((up, _)) = cur.rsplit_once('/') {
            if !dirs.insert(up) {
                break;
            }
            cur = up;
        }
    }
    dirs.len() as u64
}

fn describe(e: &ToolError) -> String {
    match e {
        ToolError::Missing { path, .. } => {
            format!(
                "mke2fs is missing at {} (install e2fsprogs)",
                path.display()
            )
        }
        ToolError::Failed { status, stderr, .. } => {
            format!("mke2fs failed ({status:?}): {}", stderr.trim())
        }
        ToolError::Timeout { secs, .. } => format!("mke2fs took more than {secs} s"),
        ToolError::Io(e) => format!("mke2fs: {e}"),
    }
}

/// Build `<staging>/../repo.img` with `mke2fs -q -t ext4 -L repo -d
/// <staging> <img> <mib>M` (D4). On failure the whole staging dir is
/// removed.
pub fn make_repo_image(tools: &Tools, s: &Snapshot) -> Result<PathBuf, String> {
    let img = s.dir().join("repo.img");
    let mib = repo_image_mib(&s.manifest, staging_dirs(&s.manifest));
    let size = format!("{mib}M");
    let args: [&OsStr; 9] = [
        OsStr::new("-q"),
        OsStr::new("-t"),
        OsStr::new("ext4"),
        OsStr::new("-L"),
        OsStr::new("repo"),
        OsStr::new("-d"),
        s.staging.as_os_str(),
        img.as_os_str(),
        OsStr::new(&size),
    ];
    let fail = |why: String| {
        remove_tree(s.dir());
        Err(format!("cannot build the box's repo disk: {why}"))
    };
    if let Err(e) = tools.run(Tool::Mke2fs, &args, MKE2FS_TIMEOUT) {
        return fail(describe(&e));
    }
    match std::fs::symlink_metadata(&img) {
        Ok(m) if m.file_type().is_file() => Ok(img),
        Ok(_) => fail(format!("{} is not a file", img.display())),
        Err(e) => fail(format!("{}: {e}", img.display())),
    }
}

/// A path for `git hash-object --stdin-paths`, C-quoted (git unquotes a
/// line that starts with `"`), so newlines and the like survive.
fn quote(p: &Path) -> Vec<u8> {
    let mut v = vec![b'"'];
    for &b in p.as_os_str().as_bytes() {
        match b {
            b'"' => v.extend_from_slice(b"\\\""),
            b'\\' => v.extend_from_slice(b"\\\\"),
            0x20..=0x7e => v.push(b),
            _ => v.extend_from_slice(format!("\\{b:03o}").as_bytes()),
        }
    }
    v.extend_from_slice(b"\"\n");
    v
}

/// D9: write the snapshot as a commit in the user's repo with plumbing
/// only (no hooks, no filters, HEAD, the index and the work tree left
/// alone): blobs from the staged files and symlink targets, a temporary
/// index `<staging>/../index`, `write-tree`, `commit-tree [-p base]`. Fills
/// `manifest.snapshot_commit` and returns it.
pub fn snapshot_commit(tools: &Tools, repo: &Path, s: &mut Snapshot) -> Result<String, String> {
    let dir = s.dir().to_path_buf();
    let index = dir.join("index");
    let links = dir.join("links");
    let r = commit_in(tools, repo, s, &index, &links);
    let _ = std::fs::remove_file(&index);
    remove_tree(&links);
    let c = r?;
    s.manifest.snapshot_commit = c.clone();
    Ok(c)
}

fn commit_in(
    tools: &Tools,
    repo: &Path,
    s: &Snapshot,
    index: &Path,
    links: &Path,
) -> Result<String, String> {
    let ix = Some(index);
    let _ = std::fs::remove_file(index);
    git_ok(tools, repo, ix, &["read-tree", "--empty"], None)?;
    // Symlink targets go through files of their own, so one hash-object
    // call covers every entry.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(links)
        .map_err(|e| format!("{}: {e}", links.display()))?;
    let mut input = Vec::new();
    for (i, (p, e)) in s.manifest.entries.iter().enumerate() {
        let src = match e.kind {
            EntryKind::File => s.staging.join(p),
            EntryKind::Symlink => {
                let target = std::fs::read_link(s.staging.join(p))
                    .map_err(|e| format!("staging {p:?}: {e}"))?;
                let t = target.as_os_str().as_bytes();
                if hex(&Sha256::digest(t)) != e.sha256 {
                    return Err(format!("staging {p:?}: the symlink changed"));
                }
                let f = links.join(i.to_string());
                std::fs::write(&f, t).map_err(|e| format!("{}: {e}", f.display()))?;
                f
            }
        };
        input.extend_from_slice(&quote(&src));
    }
    let oids = if s.manifest.entries.is_empty() {
        Vec::new()
    } else {
        git_ok(
            tools,
            repo,
            ix,
            &["hash-object", "-w", "--no-filters", "--stdin-paths"],
            Some(input),
        )?
    };
    let oids: Vec<&[u8]> = oids
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    if oids.len() != s.manifest.entries.len() {
        return Err(format!(
            "git hash-object gave {} ids for {} entries",
            oids.len(),
            s.manifest.entries.len()
        ));
    }
    let mut info = Vec::new();
    for ((p, e), oid) in s.manifest.entries.iter().zip(oids) {
        let oid = one_oid(oid.to_vec(), "hash-object")?;
        let mode = match (&e.kind, e.mode) {
            (EntryKind::Symlink, _) => "120000",
            (EntryKind::File, 0o755) => "100755",
            (EntryKind::File, _) => "100644",
        };
        info.extend_from_slice(format!("{mode} {oid}\t{p}\0").as_bytes());
    }
    git_ok(
        tools,
        repo,
        ix,
        &["update-index", "-z", "--index-info"],
        Some(info),
    )?;
    let tree = one_oid(
        git_ok(tools, repo, ix, &["write-tree"], None)?,
        "write-tree",
    )?;
    let msg = format!(
        "saiife box snapshot\n\nSaiife-Box-Snapshot: {}\n",
        s.manifest.sha256()
    );
    let mut args = vec!["commit-tree", tree.as_str()];
    if let Some(b) = &s.manifest.base_commit {
        args.extend(["-p", b.as_str()]);
    }
    args.extend(["-F", "-"]);
    // The user's own identity when git has one; otherwise (no user.email,
    // say) the snapshot is saiife's, for this call only (R13).
    let has_ident = git_run(
        tools,
        repo,
        ix,
        &[OsStr::new("var"), OsStr::new("GIT_COMMITTER_IDENT")],
        None,
    )?
    .status
    .success();
    let env: &[(&str, &str)] = if has_ident { &[] } else { &FALLBACK_IDENT };
    one_oid(
        git_ok_env(tools, repo, ix, &args, Some(msg.into_bytes()), env)?,
        "commit-tree",
    )
}

/// The snapshot commit's identity when the user has none (R13).
const FALLBACK_IDENT: [(&str, &str); 4] = [
    ("GIT_AUTHOR_NAME", "saiife"),
    ("GIT_AUTHOR_EMAIL", "saiife@localhost"),
    ("GIT_COMMITTER_NAME", "saiife"),
    ("GIT_COMMITTER_EMAIL", "saiife@localhost"),
];

/// Point `refs/saiife/box-<id>/base` at `commit`, create only (`git
/// update-ref <ref> <commit> ""`). When the ref already points at `commit`
/// (plan 39 recreating a missing one, or a retry), that is fine; pointing
/// elsewhere is refused and the ref left alone.
pub fn set_base_ref(tools: &Tools, repo: &Path, id: &BoxId, commit: &str) -> Result<(), String> {
    if !manifest::is_oid(commit) {
        return Err(format!("{commit:?} is not a commit id"));
    }
    let r = format!("refs/saiife/box-{}/base", id.as_str());
    let made = git_run(
        tools,
        repo,
        None,
        &[
            OsStr::new("update-ref"),
            OsStr::new(&r),
            OsStr::new(commit),
            OsStr::new(""),
        ],
        None,
    )?;
    if made.status.success() {
        return Ok(());
    }
    let cur = git_run(
        tools,
        repo,
        None,
        &[
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("-q"),
            OsStr::new(&r),
        ],
        None,
    )?;
    let cur = String::from_utf8_lossy(&trim_nl(cur.stdout)).into_owned();
    if cur == commit {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&made.stderr);
    Err(if cur.is_empty() {
        format!("cannot set {r}: {}", err.trim())
    } else {
        format!("{r} already points at {cur}, not {commit}")
    })
}
