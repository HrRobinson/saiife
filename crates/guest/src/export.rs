//! The base snapshot and the export of `/work` (plan 39, spec §7.5 Out).
//!
//! The guest keeps its own git repository at [`BASE_GIT`] (root-owned,
//! outside `/work`, so the agent cannot touch it). `refs/base` is the tree
//! the host last landed (first: `/work` as set up); an export snapshots
//! `/work` as `refs/exports/<n>` and writes the tree delta
//! (`saiife_boxproto::delta`) of `refs/base..refs/exports/<n>`; an advance
//! moves `refs/base` to the export, or takes only the listed paths from it.
//!
//! Nothing in `/work` steers this git (R-T2a): every call runs with a
//! cleared environment, no system or global config, hooks off, no
//! fsmonitor, and `info/attributes` unsetting every content-changing
//! attribute (it beats any `/work/.gitattributes`).
//!
//! Git run as root never reads `/work` content (R-T2d): it only lists the
//! paths the base tracks (`ls-files -c` of the base). The untracked ones
//! (`ls-files -o`, honoring every `/work/**/.gitignore`; a file the base
//! already tracks stays tracked) are listed by a git run as the agent's
//! uid and gid, against [`LIST_GIT`] (root-owned, readable, holding only
//! the `.git` exclude) and an empty index: it reads the ignore files with
//! the agent's rights, so a hard link to a root-only file is not read, and
//! its output is only a list of names, each checked below like any other.
//! Every git child is killed at the call's deadline (`Timing`, well under
//! the host's own), so a FIFO named `.gitignore` cannot wedge the guest's
//! control loop. Each path is then read by this
//! module with `openat2` beneath a dirfd of `/work`, no symlink or magic
//! link resolved: a symlink is recorded as its target (`readlinkat`), a
//! file must be regular with a single link (a hard link could name a
//! root-only file outside `/work`; the export fails naming the path), its
//! mode is 0o644 or 0o755 from the owner exec bit, and its size is bounded
//! before a byte is read. The bytes go on a pipe to `git fast-import`,
//! raw; the tree is built with `update-index --index-info`. A path gone
//! mid-walk, or below a directory that became a symlink, counts as
//! deleted (the symlink is its own entry); a final component that turns
//! into a symlink between the stat and the open fails the export.
//!
//! Nested repositories (R-T2b): a directory of `/work` holding a `.git`
//! (directory or file, valid or not) is taken for another repository. Its
//! untracked files are skipped entirely (none is exported, whether git
//! lists the directory as one entry or file by file); no gitlink is ever
//! recorded. Files the base already tracks stay tracked like any other, so
//! an agent's `git init` over existing files does not make them vanish
//! from the export. A `.git` file or directory itself never is exported
//! (`info/exclude`), and neither is any path with a component a Windows
//! host could resolve to `.git` (`.GIT`, `.git.`, `git~1`, ...).
//!
//! The export bounds itself (R-T2c): it stops with an error, before writing
//! a frame, when the delta would pass `delta::Limits` (entries, a file's
//! size on either side, the new and the old totals) or a symlink target is
//! longer than `LINK_MAX`. Every subprocess is spawned without a shell,
//! with explicit arguments.

use crate::env::{GuestEnv, WORK};
use saiife_boxproto::delta::{EntryHead, Limits, Op};
use saiife_boxproto::frame::{write_frame, Frame, MAX_FRAME};
use saiife_boxproto::manifest::{check_path, EntryKind, LINK_MAX, REPO_MAX_BYTES};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// The guest's base repository.
pub const BASE_GIT: &str = "/var/lib/saiife-guest/base.git";
/// The repository the agent-uid listing of untracked paths runs against
/// (I-2): root-owned, world-readable, no objects, no index, the `.git`
/// exclude only. Outside `/var/lib/saiife-guest` so the agent needs no way
/// into the base's parent.
pub const LIST_GIT: &str = "/var/lib/saiife-guest-list.git";
/// The last landed tree.
pub const BASE_REF: &str = "refs/base";
/// R-T2a: unsets every attribute that would change bytes on the way in.
pub const BASE_ATTRIBUTES: &str =
    "* -text -filter -ident -eol -diff -merge -working-tree-encoding\n";
/// R-T2b: a `.git` file or directory anywhere in `/work` is never added.
pub const BASE_EXCLUDE: &str = ".git\n";

/// The export ref of `n`.
pub fn export_ref(n: u32) -> String {
    format!("refs/exports/{n}")
}

/// The `-c` flags of every git call (brief + R-T2a, plus the knobs that
/// would otherwise come from a user's config).
const FLAGS: &[&str] = &[
    "core.hooksPath=/dev/null",
    "core.autocrlf=false",
    "core.symlinks=true",
    "core.attributesFile=/dev/null",
    "core.fsmonitor=false",
    "safe.directory=*",
    "core.excludesFile=/dev/null",
    "core.fileMode=true",
    "core.ignoreCase=false",
    "core.untrackedCache=false",
    "core.safecrlf=false",
    "gc.auto=0",
    "maintenance.auto=false",
    "commit.gpgSign=false",
    "init.defaultBranch=main",
    "advice.addEmbeddedRepo=false",
];

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// A git child killed at its call's deadline by a watchdog thread (I-2): a
/// git blocked on something in `/work` (a FIFO) cannot wedge the guest.
struct Timed {
    child: Arc<Mutex<Child>>,
    stop: Option<mpsc::Sender<()>>,
    fired: Arc<AtomicBool>,
}

impl Timed {
    fn new(child: Child, deadline: Instant, name: &str) -> Result<Timed, String> {
        let child = Arc::new(Mutex::new(child));
        let fired = Arc::new(AtomicBool::new(false));
        let (stop, rx) = mpsc::channel::<()>();
        let (c, f) = (child.clone(), fired.clone());
        let spawned = std::thread::Builder::new()
            .name("guest-git-deadline".into())
            .spawn(move || {
                let left = deadline.saturating_duration_since(Instant::now());
                if let Err(mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(left) {
                    f.store(true, Ordering::SeqCst);
                    // Our own child; a reaped one is not signalled again.
                    let _ = lock(&c).kill();
                }
            });
        if let Err(e) = spawned {
            let mut c = lock(&child);
            let _ = c.kill();
            let _ = c.wait();
            return Err(format!("git {name}: {e}"));
        }
        Ok(Timed {
            child,
            stop: Some(stop),
            fired,
        })
    }

    /// Waits for the child (killed at the deadline at the latest).
    fn wait(&self) -> io::Result<ExitStatus> {
        let mut pause = Duration::from_millis(1);
        loop {
            if let Some(st) = lock(&self.child).try_wait()? {
                return Ok(st);
            }
            std::thread::sleep(pause);
            pause = (pause * 2).min(Duration::from_millis(20));
        }
    }

    fn kill(&self) {
        let _ = lock(&self.child).kill();
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl Drop for Timed {
    fn drop(&mut self) {
        // Ends the watchdog (its receiver sees the sender gone).
        drop(self.stop.take());
    }
}

/// The error of a git child that broke: a deadline kill says so.
fn broke(name: &str, fired: bool, within: Duration, e: impl std::fmt::Display) -> String {
    if fired {
        format!(
            "git {name} took longer than {} s and was stopped; nothing was exported",
            within.as_secs()
        )
    } else {
        format!("git {name}: {e}")
    }
}

/// Reads a child's pipe to the end on its own thread.
fn drain<R: Read + Send + 'static>(
    r: Option<R>,
) -> Result<std::thread::JoinHandle<Vec<u8>>, String> {
    std::thread::Builder::new()
        .name("guest-git-pipe".into())
        .spawn(move || {
            let mut v = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut v);
            }
            v
        })
        .map_err(|e| format!("git: {e}"))
}

/// One git invocation context: the base dir, `/work`, this call's index,
/// and the deadline every git child of the call is killed at.
struct Git<'a> {
    env: &'a GuestEnv,
    dir: PathBuf,
    work: PathBuf,
    index: PathBuf,
    within: Duration,
    deadline: Instant,
}

impl<'a> Git<'a> {
    fn new(env: &'a GuestEnv, call: &str, within: Duration) -> Git<'a> {
        let dir = env.path(BASE_GIT);
        let index = dir.join(format!("index-{call}"));
        Git {
            env,
            dir,
            work: env.path(WORK),
            index,
            within,
            deadline: Instant::now() + within,
        }
    }

    /// Wraps a spawned child of this call in its deadline.
    fn timed(&self, child: Child, name: &str) -> Result<Timed, String> {
        Timed::new(child, self.deadline, name)
    }

    fn cmd<S: AsRef<OsStr>>(&self, args: &[S]) -> Command {
        let mut c = Command::new(&self.env.tools.git);
        c.env_clear()
            .env("GIT_DIR", &self.dir)
            .env("GIT_WORK_TREE", &self.work)
            .env("GIT_INDEX_FILE", &self.index)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_LITERAL_PATHSPECS", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("HOME", &self.dir)
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_NAME", "saiife")
            .env("GIT_AUTHOR_EMAIL", "saiife@box.invalid")
            .env("GIT_COMMITTER_NAME", "saiife")
            .env("GIT_COMMITTER_EMAIL", "saiife@box.invalid")
            .current_dir(&self.work);
        if args.first().is_some_and(|a| a.as_ref() == "init") {
            // `init` makes the repository: no work tree, no index yet.
            c.env_remove("GIT_WORK_TREE").env_remove("GIT_INDEX_FILE");
        }
        for f in FLAGS {
            c.arg("-c").arg(f);
        }
        c.args(args);
        c
    }

    /// Runs git to completion, feeding `input` on stdin; returns stdout.
    fn run_in<S: AsRef<OsStr>>(&self, args: &[S], input: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let name = args
            .first()
            .map(|a| a.as_ref().to_string_lossy().into_owned())
            .unwrap_or_default();
        self.run_cmd(&name, self.cmd(args), input)
    }

    /// Runs `c` to completion within the call's deadline, feeding `input`
    /// on stdin; returns stdout.
    fn run_cmd(&self, name: &str, mut c: Command, input: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let mut child = c
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("git {name}: {e}"))?;
        let (stdin, stdout, stderr) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take());
        let child = self.timed(child, name)?;
        let feeder = match (input, stdin) {
            (Some(b), Some(mut w)) => {
                let b = b.to_vec();
                match std::thread::Builder::new()
                    .name("guest-git-stdin".into())
                    .spawn(move || w.write_all(&b))
                {
                    Ok(h) => Some(h),
                    Err(e) => {
                        child.kill();
                        let _ = child.wait();
                        return Err(format!("git {name}: {e}"));
                    }
                }
            }
            _ => None,
        };
        let pipes = drain(stdout).and_then(|o| drain(stderr).map(|e| (o, e)));
        let (out, err) = match pipes {
            Ok(p) => p,
            Err(e) => {
                child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let status = child.wait();
        let out = out.join().unwrap_or_default();
        let err = err.join().unwrap_or_default();
        if let Some(f) = feeder {
            let _ = f.join();
        }
        if child.fired() {
            return Err(broke(name, true, self.within, ""));
        }
        let status = status.map_err(|e| format!("git {name}: {e}"))?;
        if !status.success() {
            let err = String::from_utf8_lossy(&err);
            return Err(format!(
                "git {name} failed ({status}): {}",
                err.lines().next().unwrap_or("")
            ));
        }
        Ok(out)
    }

    /// The untracked paths of `/work` (`ls-files -o`, honoring every
    /// `.gitignore`), listed by a git run as the agent (I-2): root never
    /// opens an ignore file the agent planted. An empty index, so the
    /// tracked paths come back too (the caller keeps them tracked).
    #[cfg(target_os = "linux")]
    fn list_as_agent(&self) -> Result<Vec<u8>, String> {
        use std::os::unix::process::CommandExt;
        let ids = crate::setup::agent_ids(self.env)?;
        let list = self.list_repo()?;
        let mut c = self.cmd(&["ls-files", "-o", "-z", "--exclude-standard"]);
        c.env("GIT_DIR", &list)
            .env("GIT_INDEX_FILE", list.join("index-none"))
            .env("HOME", &list)
            .uid(ids.uid)
            .gid(ids.gid);
        self.run_cmd("ls-files", c, None)
    }

    #[cfg(not(target_os = "linux"))]
    fn list_as_agent(&self) -> Result<Vec<u8>, String> {
        Err("the export runs only inside the Linux box VM".into())
    }

    /// [`LIST_GIT`], made on first use: an empty bare repository, every
    /// directory 0755 and file 0644, `info/exclude` (written last, the mark
    /// of a whole one) holding [`BASE_EXCLUDE`].
    #[cfg(target_os = "linux")]
    fn list_repo(&self) -> Result<PathBuf, String> {
        use std::os::unix::fs::PermissionsExt;
        let dir = self.env.path(LIST_GIT);
        let exclude = dir.join("info/exclude");
        if std::fs::symlink_metadata(&exclude).is_ok_and(|m| m.is_file()) {
            return Ok(dir);
        }
        let fail = |e: io::Error| format!("{LIST_GIT}: {e}");
        if std::fs::symlink_metadata(&dir).is_ok() {
            std::fs::remove_dir_all(&dir).map_err(fail)?;
        }
        std::fs::create_dir_all(&dir).map_err(fail)?;
        let mut c = self.cmd(&["init", "-q", "--bare", "--template="]);
        c.env("GIT_DIR", &dir).env("HOME", &dir);
        self.run_cmd("init", c, None)?;
        std::fs::create_dir_all(dir.join("info")).map_err(fail)?;
        fn open_up(p: &std::path::Path) -> io::Result<()> {
            let m = std::fs::symlink_metadata(p)?;
            if m.is_dir() {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))?;
                for e in std::fs::read_dir(p)? {
                    open_up(&e?.path())?;
                }
            } else if m.is_file() {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644))?;
            }
            Ok(())
        }
        open_up(&dir).map_err(fail)?;
        let tmp = dir.join("info/exclude.new");
        std::fs::write(&tmp, BASE_EXCLUDE).map_err(fail)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).map_err(fail)?;
        std::fs::rename(&tmp, &exclude).map_err(fail)?;
        Ok(dir)
    }

    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Vec<u8>, String> {
        self.run_in(args, None)
    }

    /// One line of output (an object id), trimmed.
    fn oid<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<String, String> {
        let out = self.run(args)?;
        let s = String::from_utf8_lossy(&out).trim().to_string();
        if s.is_empty() {
            return Err("git printed no object id".into());
        }
        Ok(s)
    }

    /// The commit a ref names, or an error naming `what`.
    fn commit(&self, r: &str, what: &str) -> Result<String, String> {
        self.oid(&["rev-parse", "--verify", "-q", &format!("{r}^{{commit}}")])
            .map_err(|_| format!("{what} does not exist"))
    }

    fn drop_index(&self) {
        let _ = std::fs::remove_file(&self.index);
        let _ = std::fs::remove_file(self.index.with_extension("lock"));
    }

    /// Commits `tree` (with `parent`) and points `r` at it.
    fn commit_to(
        &self,
        tree: &str,
        parent: Option<&str>,
        msg: &str,
        r: &str,
    ) -> Result<(), String> {
        let mut args = vec!["commit-tree", tree, "-m", msg];
        if let Some(p) = parent {
            args.extend(["-p", p]);
        }
        let c = self.oid(&args)?;
        self.run(&["update-ref", "--no-deref", r, &c])?;
        Ok(())
    }
}

/// Records `/work` as `refs/base` (first setup only): a fresh base
/// repository holding every file `/work` has (even ignored ones: the host
/// wrote exactly the snapshot there).
pub fn init_base(env: &GuestEnv) -> Result<(), String> {
    let git = Git::new(env, "base", env.timing.git_deadline);
    if std::fs::symlink_metadata(&git.dir).is_ok() {
        // A setup that died before its marker: start over.
        std::fs::remove_dir_all(&git.dir).map_err(|e| format!("{BASE_GIT}: {e}"))?;
    }
    std::fs::create_dir_all(&git.dir).map_err(|e| format!("{BASE_GIT}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&git.dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{BASE_GIT}: {e}"))?;
    }
    // `--template=` with nothing: no sample hooks, no template info files.
    git.run(&["init", "-q", "--bare", "--template="])?;
    let info = git.dir.join("info");
    std::fs::create_dir_all(&info).map_err(|e| format!("{BASE_GIT}/info: {e}"))?;
    std::fs::write(info.join("attributes"), BASE_ATTRIBUTES)
        .map_err(|e| format!("{BASE_GIT}/info/attributes: {e}"))?;
    std::fs::write(info.join("exclude"), BASE_EXCLUDE)
        .map_err(|e| format!("{BASE_GIT}/info/exclude: {e}"))?;
    let tree = snapshot(&git, None, true)?;
    git.commit_to(&tree, None, "saiife base", BASE_REF)
}

/// R-T1e, R-T3i: a component a Windows or macOS host could resolve to
/// `.git`, by the host validator's own rule (a non-UTF-8 name is no alias;
/// the host refuses it anyway).
fn is_git_alias(c: &[u8]) -> bool {
    std::str::from_utf8(c).is_ok_and(saiife_boxproto::delta::is_git_alias)
}

/// Snapshots `/work` and returns the tree id (R-T2d). Git only lists
/// paths: the paths `start` tracks and the untracked ones (`ls-files -o`;
/// unless `force`, honoring `.gitignore` and run as the agent, I-2; with
/// `force`, the first setup before the agent ever ran, reading no ignore
/// file at all); a nested repository's untracked
/// files and `.git`-alias paths are skipped (R-T2b). Every content byte is
/// read by [`work::Work`] (openat2 beneath `/work`, no symlink followed)
/// and fed to `git fast-import` on a pipe; the tree is built with
/// `update-index --index-info`. A path gone mid-walk counts as deleted.
fn snapshot(git: &Git, start: Option<&str>, force: bool) -> Result<String, String> {
    git.drop_index();
    let listed = (|| {
        let tracked = match start {
            Some(s) => {
                git.run(&["read-tree", s])?;
                git.run(&["ls-files", "-c", "-z"])?
            }
            None => Vec::new(),
        };
        let others = if force {
            git.run(&["ls-files", "-o", "-z"])?
        } else {
            git.list_as_agent()?
        };
        Ok::<_, String>((tracked, others))
    })();
    git.drop_index();
    let (tracked, untracked) = listed?;

    // path -> the most bytes it may hold (R-T2c): a tracked file is bounded
    // by the repo cap (an unchanged large base file must not fail every
    // export; the delta caps apply to what changed), a new file by the
    // delta's per-file cap, as its export would be refused past it anyway.
    let mut paths: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    let plain = |p: &[u8]| !p.is_empty() && !p.split(|&b| b == b'/').any(is_git_alias);
    for p in tracked.split(|&b| b == 0).filter(|p| plain(p)) {
        paths.insert(p.to_vec(), REPO_MAX_BYTES);
    }
    let new_max = if force {
        REPO_MAX_BYTES
    } else {
        Limits::default().file_bytes
    };
    let mut nested = NestedRepos::new(&git.work);
    for p in untracked.split(|&b| b == 0) {
        if plain(p) && !p.ends_with(b"/") && !nested.inside(p) {
            paths.entry(p.to_vec()).or_insert(new_max);
        }
    }

    let work = work::Work::open(&git.work)?;
    let mut blobs = Blobs::spawn(git)?;
    let mut total = 0u64;
    let mut found = Vec::new();
    for (p, max) in &paths {
        let Some(item) = work.read(p, *max)? else {
            continue;
        };
        total = total.saturating_add(item.size());
        if total > REPO_MAX_BYTES {
            return Err(format!(
                "/work holds more than {REPO_MAX_BYTES} bytes; nothing was exported"
            ));
        }
        let mark = blobs.add(p, item)?;
        found.push((p, mark));
    }
    let oids = blobs.finish()?;
    let mut info = Vec::new();
    for (p, (mark, mode)) in found {
        let oid = oids
            .get(&mark)
            .ok_or_else(|| format!("git fast-import lost the blob of {}", esc(p)))?;
        info.extend_from_slice(format!("{mode} {oid}\t").as_bytes());
        info.extend_from_slice(p);
        info.push(0);
    }
    git.drop_index();
    let r = (|| {
        if !info.is_empty() {
            git.run_in(&["update-index", "-z", "--index-info"], Some(&info))?;
        }
        git.oid(&["write-tree"])
    })();
    git.drop_index();
    r
}

/// A guest path for an error message: lossy UTF-8, quoted, every control,
/// bidi or invisible char escaped.
fn esc(p: &[u8]) -> String {
    let q = format!("{:?}", String::from_utf8_lossy(p));
    let mut out = String::with_capacity(q.len());
    for c in q.chars() {
        if saiife_wire::text::is_unsafe_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// What one `/work` path holds, opened without following any symlink.
/// (Only the Linux reader builds one; elsewhere the export is refused.)
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Item {
    /// A symlink's target bytes.
    Link(Vec<u8>),
    /// A regular file (single link), its size at open, and its exec bit.
    File {
        file: std::fs::File,
        size: u64,
        exec: bool,
    },
}

impl Item {
    fn size(&self) -> u64 {
        match self {
            Item::Link(t) => t.len() as u64,
            Item::File { size, .. } => *size,
        }
    }
}

/// One `git fast-import` that stores the blobs it is fed on its stdin
/// (it reads nothing else of `/work`); its marks give the object ids.
struct Blobs {
    child: Timed,
    stdin: Option<std::io::BufWriter<ChildStdin>>,
    marks: PathBuf,
    next: u64,
    within: Duration,
}

impl Blobs {
    fn spawn(git: &Git) -> Result<Blobs, String> {
        let marks = git.dir.join(format!(
            "marks-{}",
            git.index
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        let _ = std::fs::remove_file(&marks);
        let mut arg = std::ffi::OsString::from("--export-marks=");
        arg.push(&marks);
        let mut child = git
            .cmd(&[
                OsStr::new("fast-import"),
                OsStr::new("--quiet"),
                OsStr::new("--done"),
                &arg,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("git fast-import: {e}"))?;
        let stdin = child.stdin.take().map(std::io::BufWriter::new);
        Ok(Blobs {
            child: git.timed(child, "fast-import")?,
            stdin,
            marks,
            next: 0,
            within: git.within,
        })
    }

    /// Feeds one blob; returns its mark and git mode.
    fn add(&mut self, p: &[u8], item: Item) -> Result<(u64, &'static str), String> {
        let (fired, within) = (self.child.fired.clone(), self.within);
        let broke = |e: io::Error| broke("fast-import", fired.load(Ordering::SeqCst), within, e);
        self.next += 1;
        let mark = self.next;
        let w = self.stdin.as_mut().ok_or("git fast-import: closed")?;
        let size = item.size();
        write!(w, "blob\nmark :{mark}\ndata {size}\n").map_err(broke)?;
        let mode = match item {
            Item::Link(t) => {
                w.write_all(&t).map_err(broke)?;
                "120000"
            }
            Item::File { file, exec, .. } => {
                let copied = io::copy(&mut (&file).take(size), w).map_err(|e| {
                    if self.child.fired() {
                        broke(e)
                    } else {
                        format!("{}: {e}", esc(p))
                    }
                })?;
                if copied != size {
                    return Err(format!(
                        "{} changed while it was read; export again",
                        esc(p)
                    ));
                }
                if exec {
                    "100755"
                } else {
                    "100644"
                }
            }
        };
        w.write_all(b"\n").map_err(broke)?;
        Ok((mark, mode))
    }

    /// Ends the import; mark -> object id.
    fn finish(mut self) -> Result<BTreeMap<u64, String>, String> {
        let (fired, within) = (self.child.fired.clone(), self.within);
        let broke = |e: io::Error| broke("fast-import", fired.load(Ordering::SeqCst), within, e);
        if let Some(mut w) = self.stdin.take() {
            w.write_all(b"done\n").map_err(broke)?;
            w.flush().map_err(broke)?;
        }
        let st = self.child.wait().map_err(broke)?;
        if self.child.fired() {
            return Err(broke(io::Error::other("killed")));
        }
        if !st.success() {
            return Err(format!("git fast-import failed ({st})"));
        }
        let text = std::fs::read_to_string(&self.marks).unwrap_or_default();
        let _ = std::fs::remove_file(&self.marks);
        let mut out = BTreeMap::new();
        for line in text.lines() {
            let mut f = line.split(' ');
            if let (Some(m), Some(oid)) = (f.next(), f.next()) {
                if let Ok(m) = m.trim_start_matches(':').parse::<u64>() {
                    out.insert(m, oid.to_string());
                }
            }
        }
        Ok(out)
    }
}

impl Drop for Blobs {
    fn drop(&mut self) {
        if self.stdin.take().is_some() {
            // Not finished (an error mid-way): our own child.
            self.child.kill();
        }
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.marks);
    }
}

#[cfg(target_os = "linux")]
mod work {
    //! Reading `/work` as root without following anything the agent
    //! planted (R-T2d): every open is an `openat2` beneath a dirfd of
    //! `/work` with no symlink or magic link resolved.
    use super::{esc, Item};
    use rustix::fs::{
        fstat, open, openat2, readlinkat, statat, AtFlags, FileType, Mode, OFlags, ResolveFlags,
    };
    use rustix::io::Errno;
    use saiife_boxproto::manifest::LINK_MAX;
    use std::ffi::OsStr;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS);

    pub(super) struct Work {
        dir: OwnedFd,
    }

    fn gone(e: Errno) -> bool {
        e == Errno::NOENT || e == Errno::NOTDIR
    }

    impl Work {
        pub(super) fn open(work: &Path) -> Result<Work, String> {
            let dir = open(
                work,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| format!("/work: {e}"))?;
            Ok(Work { dir })
        }

        /// What `p` holds now: `None` when it is gone, a directory, below a
        /// symlinked directory (not a path of this tree; the symlink is its
        /// own entry), or not a file or symlink. A file must be a single
        /// link and at most `max` bytes.
        pub(super) fn read(&self, p: &[u8], max: u64) -> Result<Option<Item>, String> {
            let fail = |why: String| Err(format!("{}: {why}", esc(p)));
            let (parent, name) = match p.iter().rposition(|&b| b == b'/') {
                Some(i) => (Some(&p[..i]), &p[i + 1..]),
                None => (None, p),
            };
            let name = OsStr::from_bytes(name);
            let held;
            let dir = match parent {
                None => &self.dir,
                Some(d) => {
                    let opened = openat2(
                        &self.dir,
                        OsStr::from_bytes(d),
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                        RESOLVE,
                    );
                    match opened {
                        Ok(fd) => {
                            held = fd;
                            &held
                        }
                        Err(e) if gone(e) => return Ok(None),
                        // A directory replaced by a symlink: nothing below
                        // it is read; `ls-files` lists the link itself.
                        Err(Errno::LOOP) => return Ok(None),
                        Err(e) => return fail(format!("cannot open its directory: {e}")),
                    }
                }
            };
            let st = match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => st,
                Err(e) if gone(e) => return Ok(None),
                Err(e) => return fail(format!("{e}")),
            };
            match FileType::from_raw_mode(st.st_mode) {
                FileType::Symlink => {
                    let t = match readlinkat(dir, name, Vec::new()) {
                        Ok(t) => t.into_bytes(),
                        Err(e) if gone(e) => return Ok(None),
                        Err(e) => return fail(format!("readlink: {e}")),
                    };
                    if t.len() as u64 > LINK_MAX || t.len() as u64 > max {
                        return fail(format!("symlink target is longer than {LINK_MAX} bytes"));
                    }
                    Ok(Some(Item::Link(t)))
                }
                FileType::RegularFile => {
                    let fd = match openat2(
                        dir,
                        name,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                        Mode::empty(),
                        RESOLVE,
                    ) {
                        Ok(fd) => fd,
                        Err(e) if gone(e) => return Ok(None),
                        Err(e) => return fail(format!("cannot open it beneath /work: {e}")),
                    };
                    let st = fstat(&fd).map_err(|e| format!("{}: {e}", esc(p)))?;
                    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                        return fail("is not a regular file".into());
                    }
                    if st.st_nlink != 1 {
                        return fail(format!(
                            "has {} hard links; a file with more than one is not exported",
                            st.st_nlink
                        ));
                    }
                    let size = st.st_size as u64;
                    if size > max {
                        return fail(format!("is {size} bytes, over the export's limit of {max}"));
                    }
                    Ok(Some(Item::File {
                        file: std::fs::File::from(fd),
                        size,
                        exec: st.st_mode & 0o100 != 0,
                    }))
                }
                // Directories (their files are listed on their own), FIFOs,
                // sockets and devices are not entries.
                _ => Ok(None),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod work {
    use super::Item;
    use std::path::Path;

    pub(super) struct Work;

    impl Work {
        pub(super) fn open(_work: &Path) -> Result<Work, String> {
            Err("the export runs only inside the Linux box VM".into())
        }

        pub(super) fn read(&self, p: &[u8], max: u64) -> Result<Option<Item>, String> {
            let _ = (p, max);
            Err("the export runs only inside the Linux box VM".into())
        }
    }
}

/// Which directories of `/work` hold a `.git` (another repository),
/// looked up once each.
struct NestedRepos<'w> {
    work: &'w std::path::Path,
    seen: BTreeMap<Vec<u8>, bool>,
}

impl<'w> NestedRepos<'w> {
    fn new(work: &'w std::path::Path) -> Self {
        NestedRepos {
            work,
            seen: BTreeMap::new(),
        }
    }

    /// Whether `path` (relative, `/`-separated) lies in a directory that
    /// holds a `.git`.
    fn inside(&mut self, path: &[u8]) -> bool {
        let ends = path
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == b'/')
            .map(|(i, _)| i);
        for i in ends {
            let dir = &path[..i];
            let work = self.work;
            let hit = *self.seen.entry(dir.to_vec()).or_insert_with(|| {
                let d = work.join(rel(dir)).join(".git");
                std::fs::symlink_metadata(d).is_ok()
            });
            if hit {
                return true;
            }
        }
        false
    }
}

/// A git path (raw bytes) as a relative filesystem path.
#[cfg(unix)]
fn rel(p: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(p))
}

#[cfg(not(unix))]
fn rel(p: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(p).into_owned())
}

/// One side of a change: kind, delta mode, blob id.
#[derive(Debug, Clone)]
struct Side {
    kind: EntryKind,
    mode: u32,
    oid: String,
}

fn side(mode: &str, oid: &str, path: &str) -> Result<Option<Side>, String> {
    let (kind, mode) = match mode {
        "000000" => return Ok(None),
        "100644" => (EntryKind::File, 0o644),
        "100755" => (EntryKind::File, 0o755),
        "120000" => (EntryKind::Symlink, 0),
        // Never in a snapshot (dropped); refuse rather than guess.
        m => return Err(format!("{path:?}: git mode {m} cannot be exported")),
    };
    Ok(Some(Side {
        kind,
        mode,
        oid: oid.to_string(),
    }))
}

struct Change {
    path: String,
    old: Option<Side>,
    new: Option<Side>,
}

/// Parses `diff-tree -r -z --raw` output.
fn parse_raw(raw: &[u8]) -> Result<Vec<Change>, String> {
    let mut out = Vec::new();
    let mut it = raw.split(|&b| b == 0);
    while let Some(meta) = it.next() {
        if meta.is_empty() {
            continue;
        }
        let path = it.next().ok_or("git diff-tree: a record without a path")?;
        let path = String::from_utf8(path.to_vec()).map_err(|_| {
            format!(
                "{:?} is not UTF-8 and cannot be exported",
                String::from_utf8_lossy(path)
            )
        })?;
        let meta = std::str::from_utf8(meta).map_err(|_| "git diff-tree: bad record")?;
        let f: Vec<&str> = meta.trim_start_matches(':').split(' ').collect();
        let [om, nm, oo, no, _status] = f[..] else {
            return Err(format!("git diff-tree: bad record {meta:?}"));
        };
        out.push(Change {
            old: side(om, oo, &path)?,
            new: side(nm, no, &path)?,
            path,
        });
    }
    Ok(out)
}

/// One `git cat-file --batch` for the whole export.
struct CatFile {
    child: Timed,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    within: Duration,
}

impl CatFile {
    fn spawn(git: &Git) -> Result<CatFile, String> {
        let mut child = git
            .cmd(&["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("git cat-file: {e}"))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().map(BufReader::new);
        let child = git.timed(child, "cat-file")?;
        match stdout {
            Some(stdout) => Ok(CatFile {
                child,
                stdin,
                stdout,
                within: git.within,
            }),
            None => Err("git cat-file: no stdout".into()),
        }
    }

    /// The error of a broken pipe to or from the child.
    fn broke(&self, e: io::Error) -> String {
        broke("cat-file", self.child.fired(), self.within, e)
    }

    /// Asks for a blob; returns its size (refused above `max` before any
    /// content is read).
    fn open(&mut self, oid: &str, path: &str, max: u64) -> Result<u64, String> {
        let w = self.stdin.as_mut().ok_or("git cat-file: closed")?;
        let sent = w
            .write_all(format!("{oid}\n").as_bytes())
            .and_then(|()| w.flush());
        sent.map_err(|e| self.broke(e))?;
        let mut line = Vec::new();
        let got = (&mut self.stdout).take(256).read_until(b'\n', &mut line);
        got.map_err(|e| self.broke(e))?;
        if line.is_empty() && self.child.fired() {
            return Err(self.broke(io::ErrorKind::UnexpectedEof.into()));
        }
        let line = String::from_utf8_lossy(&line);
        let f: Vec<&str> = line.trim_end().split(' ').collect();
        let [got, "blob", size] = f[..] else {
            return Err(format!("git cat-file: {oid} is not a blob ({path:?})"));
        };
        if got != oid {
            return Err(format!("git cat-file: asked {oid}, got {got}"));
        }
        let size: u64 = size
            .parse()
            .map_err(|_| format!("git cat-file: bad size {size:?}"))?;
        if size > max {
            return Err(format!(
                "{path:?} is {size} bytes, over the export's limit of {max}"
            ));
        }
        Ok(size)
    }

    /// Reads the opened blob's `size` bytes, giving each chunk to `each`;
    /// returns the SHA-256.
    fn read(
        &mut self,
        size: u64,
        each: &mut dyn FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<String, String> {
        let mut h = Sha256::new();
        let mut left = size;
        let mut buf = vec![0u8; MAX_FRAME.min(size.max(1) as usize)];
        while left > 0 {
            let want = (left.min(buf.len() as u64)) as usize;
            let got = self.stdout.read_exact(&mut buf[..want]);
            got.map_err(|e| self.broke(e))?;
            h.update(&buf[..want]);
            each(&buf[..want])?;
            left -= want as u64;
        }
        let mut nl = [0u8; 1];
        let got = self.stdout.read_exact(&mut nl);
        got.map_err(|e| self.broke(e))?;
        if nl[0] != b'\n' {
            return Err("git cat-file: bad blob terminator".into());
        }
        Ok(hex(&h.finalize()))
    }

    /// Size and SHA-256 of a blob, bounded by `max`.
    fn hash(&mut self, oid: &str, path: &str, max: u64) -> Result<(u64, String), String> {
        let size = self.open(oid, path, max)?;
        let sha = self.read(size, &mut |_| Ok(()))?;
        Ok((size, sha))
    }

    fn close(mut self) -> Result<(), String> {
        drop(self.stdin.take());
        let st = self.child.wait().map_err(|e| self.broke(e))?;
        if self.child.fired() {
            return Err(self.broke(io::Error::other("killed")));
        }
        if !st.success() {
            return Err(format!("git cat-file failed ({st})"));
        }
        Ok(())
    }
}

impl Drop for CatFile {
    fn drop(&mut self) {
        if self.stdin.take().is_some() {
            // Not closed cleanly (an error mid-way): our own child.
            self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Snapshots `/work` as `refs/exports/<n>` and writes the delta of
/// `refs/base..refs/exports/<n>` to `out`, within `Limits::default()`.
pub fn export(env: &GuestEnv, n: u32, out: &mut dyn Write) -> Result<(), String> {
    export_within(env, n, Limits::default(), out)
}

/// [`export`] with explicit caps (tests lower them). Nothing is written
/// when the delta would pass them.
pub fn export_within(
    env: &GuestEnv,
    n: u32,
    limits: Limits,
    out: &mut dyn Write,
) -> Result<(), String> {
    let git = Git::new(env, "export", env.timing.export_deadline);
    let base = git.commit(BASE_REF, "the box's base")?;
    let tree = snapshot(&git, Some(&base), false)?;
    let to = export_ref(n);
    git.commit_to(&tree, Some(&base), &format!("saiife export {n}"), &to)?;
    let raw = git.run(&["diff-tree", "-r", "-z", "--no-renames", "--raw", &base, &to])?;
    let mut changes = parse_raw(&raw)?;
    changes.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    if changes.len() > limits.entries {
        return Err(format!(
            "the export has {} changed paths, over the limit of {}",
            changes.len(),
            limits.entries
        ));
    }

    // Pass 1: every header (sizes and hashes), bounded, before any frame.
    let mut cat = CatFile::spawn(&git)?;
    let (mut total_new, mut total_old) = (0u64, 0u64);
    let mut heads = Vec::with_capacity(changes.len());
    for c in &changes {
        let p = c.path.as_str();
        let old = match &c.old {
            Some(o) => {
                // A delete's old bytes are not sent: only hashed.
                let max = if c.new.is_some() {
                    limits.file_bytes
                } else {
                    u64::MAX
                };
                let (size, sha) = cat.hash(&o.oid, p, max)?;
                if c.new.is_some() {
                    total_old += size;
                    if total_old > limits.total_bytes {
                        return Err(format!(
                            "the export's old content passes the limit of {} bytes",
                            limits.total_bytes
                        ));
                    }
                }
                Some((o.kind.clone(), size, sha))
            }
            None => None,
        };
        let head = match (&c.new, old) {
            (Some(nw), old) => {
                let max = if nw.kind == EntryKind::Symlink {
                    LINK_MAX.min(limits.file_bytes)
                } else {
                    limits.file_bytes
                };
                let (size, sha) = cat.hash(&nw.oid, p, max)?;
                total_new += size;
                if total_new > limits.total_bytes {
                    return Err(format!(
                        "the export's new content passes the limit of {} bytes",
                        limits.total_bytes
                    ));
                }
                let (op, old_kind, old_size, old_sha256) = match old {
                    Some((k, s, h)) => (Op::Modify, Some(k), Some(s), Some(h)),
                    None => (Op::Add, None, None, None),
                };
                EntryHead {
                    path: c.path.clone(),
                    op,
                    kind: nw.kind.clone(),
                    mode: nw.mode,
                    size,
                    sha256: sha,
                    old_kind,
                    old_size,
                    old_sha256,
                }
            }
            (None, Some((k, s, h))) => EntryHead {
                path: c.path.clone(),
                op: Op::Delete,
                kind: k.clone(),
                mode: 0,
                size: 0,
                sha256: String::new(),
                old_kind: Some(k),
                old_size: Some(s),
                old_sha256: Some(h),
            },
            (None, None) => return Err(format!("{p:?}: git reported an empty change")),
        };
        heads.push(head);
    }

    // Pass 2: the frames; content streamed from the same cat-file, its hash
    // checked against pass 1.
    let io = |e: io::Error| format!("the export stream: {e}");
    let mut out = out;
    write_frame(
        &mut out,
        &Frame::Json(serde_json::json!({"t": "delta", "n": n, "entries": heads.len()})),
    )
    .map_err(io)?;
    for (c, h) in changes.iter().zip(&heads) {
        let mut v = serde_json::to_value(h).map_err(|e| format!("the export stream: {e}"))?;
        v["t"] = "entry".into();
        write_frame(&mut out, &Frame::Json(v)).map_err(io)?;
        let mut sides = Vec::new();
        if h.op == Op::Modify {
            if let (Some(o), Some(s), Some(sha)) = (&c.old, h.old_size, &h.old_sha256) {
                sides.push((&o.oid, s, sha));
            }
        }
        if let Some(nw) = &c.new {
            sides.push((&nw.oid, h.size, &h.sha256));
        }
        for (oid, size, sha) in sides {
            let got = cat.open(oid, &c.path, size)?;
            if got != size {
                return Err(format!("{:?}: the blob changed size", c.path));
            }
            let w = &mut out;
            let got = cat.read(size, &mut |b| {
                write_frame(w, &Frame::Bytes(b.to_vec())).map_err(io)
            })?;
            if &got != sha {
                return Err(format!("{:?}: the blob changed content", c.path));
            }
        }
    }
    write_frame(
        &mut out,
        &Frame::Json(serde_json::json!({"t": "end", "entries": heads.len()})),
    )
    .map_err(io)?;
    cat.close()
}

/// A tree's files: path -> "<mode> <oid>".
fn tree_entries(git: &Git, commit: &str) -> Result<BTreeMap<Vec<u8>, String>, String> {
    let ls = git.run(&["ls-tree", "-r", "-z", "--full-tree", commit])?;
    let mut out = BTreeMap::new();
    for rec in ls.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        // "<mode> SP <type> SP <oid> TAB <path>"
        let tab = rec
            .iter()
            .position(|&b| b == b'\t')
            .ok_or("git ls-tree: a record without a path")?;
        let meta = String::from_utf8_lossy(&rec[..tab]).into_owned();
        let mut f = meta.split(' ');
        let (Some(mode), Some(_), Some(oid)) = (f.next(), f.next(), f.next()) else {
            return Err(format!("git ls-tree: bad record {meta:?}"));
        };
        out.insert(rec[tab + 1..].to_vec(), format!("{mode} {oid}"));
    }
    Ok(out)
}

/// Moves `refs/base` to `refs/exports/<n>` (`paths` `None`), or to the base
/// with only `paths` taken from the export (a listed path the export lacks
/// is removed from the base). Refused, with nothing changed, when a listed
/// path is not a change of the export or the result would make a path both
/// a file and a directory.
pub fn advance(env: &GuestEnv, n: u32, paths: Option<&[String]>) -> Result<(), String> {
    let git = Git::new(env, "advance", env.timing.git_deadline);
    let base = git.commit(BASE_REF, "the box's base")?;
    let exp = git.commit(&export_ref(n), &format!("export {n}"))?;
    let Some(paths) = paths else {
        return git
            .run(&["update-ref", "--no-deref", BASE_REF, &exp])
            .map(|_| ());
    };
    for p in paths {
        check_path(p)?;
    }
    let have = tree_entries(&git, &exp)?;
    let was = tree_entries(&git, &base)?;
    // Every listed path must be a change of this export.
    for p in paths {
        let k = p.as_bytes();
        if have.get(k) == was.get(k) {
            return Err(format!("{} is not a change of export {n}", esc(k)));
        }
    }
    // The resulting tree must still be a tree: no path both a file and a
    // directory of another (`update-index --index-info` would silently
    // replace one with the other). Base and export are each valid, so a
    // conflict always involves a listed path; checking the whole result
    // covers both directions.
    let listed: std::collections::BTreeSet<&[u8]> = paths.iter().map(|p| p.as_bytes()).collect();
    let mut result: std::collections::BTreeSet<&[u8]> = was
        .keys()
        .map(Vec::as_slice)
        .filter(|k| !listed.contains(k))
        .collect();
    result.extend(listed.iter().copied().filter(|k| have.contains_key(*k)));
    for p in &result {
        for (i, _) in p.iter().enumerate().filter(|(_, &b)| b == b'/') {
            let up = &p[..i];
            if result.contains(up) {
                return Err(format!(
                    "taking only the listed paths would make {} both a file and a directory (of {})",
                    esc(up),
                    esc(p)
                ));
            }
        }
    }
    let mut remove = Vec::new();
    let mut add = Vec::new();
    for p in paths {
        remove.extend_from_slice(p.as_bytes());
        remove.push(0);
        if let Some(mo) = have.get(p.as_bytes()) {
            add.extend_from_slice(format!("{mo}\t{p}").as_bytes());
            add.push(0);
        }
    }
    git.drop_index();
    let r = (|| {
        git.run(&["read-tree", &base])?;
        if !remove.is_empty() {
            git.run_in(
                &["update-index", "-z", "--force-remove", "--stdin"],
                Some(&remove),
            )?;
        }
        if !add.is_empty() {
            git.run_in(&["update-index", "-z", "--index-info"], Some(&add))?;
        }
        git.oid(&["write-tree"])
    })();
    git.drop_index();
    let tree = r?;
    git.commit_to(&tree, Some(&base), &format!("saiife advance {n}"), BASE_REF)
}
