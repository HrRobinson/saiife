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
//! attribute (it beats any `/work/.gitattributes`), so the snapshot stores
//! the raw bytes. `/work/.gitignore` is honored for untracked files; a file
//! the base already tracks stays tracked.
//!
//! Nested repositories (R-T2b): a directory of `/work` holding a `.git`
//! (directory or file, valid or not) is taken for another repository; git would record it as a gitlink (mode 160000),
//! which the delta cannot carry. Its untracked files are skipped entirely
//! (none is exported, whether git lists the directory as one entry or file
//! by file), and a gitlink is dropped from every snapshot. Files
//! the base already tracks stay tracked like any other, so an agent's `git
//! init` over existing files does not make them vanish from the export.
//! A `.git` file or directory itself never is
//! (`info/exclude`), and neither is any path with a component a Windows host
//! could resolve to `.git` (`.GIT`, `.git.`, `git~1`, ...): those are
//! dropped from the snapshot so they never reach the base either.
//!
//! The export bounds itself (R-T2c): it stops with an error, before writing
//! a frame, when the delta would pass `delta::Limits` (entries, a file's
//! size on either side, the new and the old totals) or a symlink target is
//! longer than `LINK_MAX`. Every subprocess is spawned without a shell,
//! with explicit arguments.

use crate::env::{GuestEnv, WORK};
use saiife_boxproto::delta::{EntryHead, Limits, Op};
use saiife_boxproto::frame::{write_frame, Frame, MAX_FRAME};
use saiife_boxproto::manifest::{check_path, EntryKind, LINK_MAX};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// The guest's base repository.
pub const BASE_GIT: &str = "/var/lib/saiife-guest/base.git";
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

/// One git invocation context: the base dir, `/work`, and this call's index.
struct Git<'a> {
    env: &'a GuestEnv,
    dir: PathBuf,
    work: PathBuf,
    index: PathBuf,
}

impl<'a> Git<'a> {
    fn new(env: &'a GuestEnv, call: &str) -> Git<'a> {
        let dir = env.path(BASE_GIT);
        let index = dir.join(format!("index-{call}"));
        Git {
            env,
            dir,
            work: env.path(WORK),
            index,
        }
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
        let mut child = self
            .cmd(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("git {name}: {e}"))?;
        let feeder = match (input, child.stdin.take()) {
            (Some(b), Some(mut w)) => {
                let b = b.to_vec();
                Some(std::thread::spawn(move || w.write_all(&b)))
            }
            _ => None,
        };
        let out = child
            .wait_with_output()
            .map_err(|e| format!("git {name}: {e}"))?;
        if let Some(f) = feeder {
            let _ = f.join();
        }
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "git {name} failed ({}): {}",
                out.status,
                err.lines().next().unwrap_or("")
            ));
        }
        Ok(out.stdout)
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
    let git = Git::new(env, "base");
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

/// R-T1e mirrored: a component a Windows host could resolve to `.git`.
fn is_git_alias(c: &[u8]) -> bool {
    let mut t = c;
    while let [rest @ .., b'.' | b' '] = t {
        t = rest;
    }
    if t.eq_ignore_ascii_case(b".git") {
        return true;
    }
    t.len() > 4 && t[..4].eq_ignore_ascii_case(b"git~") && t[4..].iter().all(u8::is_ascii_digit)
}

/// Snapshots `/work` into this call's index (starting from `start`, so
/// what that tree tracks stays tracked) and returns the tree id. Gitlinks
/// (nested repositories) and `.git`-alias paths are dropped (R-T2b).
fn snapshot(git: &Git, start: Option<&str>, force: bool) -> Result<String, String> {
    git.drop_index();
    let r = (|| {
        if let Some(s) = start {
            git.run(&["read-tree", s])?;
        }
        // Not `git add -A`: it refuses a nested repository without a
        // commit. Tracked paths are refreshed (`add -u`), then the untracked
        // files `ls-files` lists are added; it lists a nested repository as
        // `dir/`, which is skipped (R-T2b).
        if start.is_some() {
            git.run(&["add", "-u"])?;
        }
        let mut others = vec!["ls-files", "-o", "-z"];
        if !force {
            others.push("--exclude-standard");
        }
        let listed = git.run(&others)?;
        let mut add = Vec::new();
        let mut nested = NestedRepos::new(&git.work);
        for p in listed.split(|&b| b == 0) {
            if !p.is_empty() && !p.ends_with(b"/") && !nested.inside(p) {
                add.extend_from_slice(p);
                add.push(0);
            }
        }
        if !add.is_empty() {
            git.run_in(&["update-index", "-z", "--add", "--stdin"], Some(&add))?;
        }
        let ls = git.run(&["ls-files", "-s", "-z"])?;
        let mut drop = Vec::new();
        for rec in ls.split(|&b| b == 0).filter(|r| !r.is_empty()) {
            // "<mode> <oid> <stage>\t<path>"
            let tab = rec
                .iter()
                .position(|&b| b == b'\t')
                .ok_or("git ls-files: a record without a path")?;
            let (meta, path) = (&rec[..tab], &rec[tab + 1..]);
            let mode = meta.split(|&b| b == b' ').next().unwrap_or_default();
            let keep = matches!(mode, b"100644" | b"100755" | b"120000")
                && !path.split(|&b| b == b'/').any(is_git_alias);
            if !keep {
                drop.extend_from_slice(path);
                drop.push(0);
            }
        }
        if !drop.is_empty() {
            git.run_in(
                &["update-index", "-z", "--force-remove", "--stdin"],
                Some(&drop),
            )?;
        }
        git.oid(&["write-tree"])
    })();
    git.drop_index();
    r
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
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
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
        match stdout {
            Some(stdout) => Ok(CatFile {
                child,
                stdin,
                stdout,
            }),
            None => Err("git cat-file: no stdout".into()),
        }
    }

    /// Asks for a blob; returns its size (refused above `max` before any
    /// content is read).
    fn open(&mut self, oid: &str, path: &str, max: u64) -> Result<u64, String> {
        let err = |e: io::Error| format!("git cat-file: {e}");
        let w = self.stdin.as_mut().ok_or("git cat-file: closed")?;
        w.write_all(format!("{oid}\n").as_bytes()).map_err(err)?;
        w.flush().map_err(err)?;
        let mut line = Vec::new();
        (&mut self.stdout)
            .take(256)
            .read_until(b'\n', &mut line)
            .map_err(err)?;
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
        let err = |e: io::Error| format!("git cat-file: {e}");
        let mut h = Sha256::new();
        let mut left = size;
        let mut buf = vec![0u8; MAX_FRAME.min(size.max(1) as usize)];
        while left > 0 {
            let want = (left.min(buf.len() as u64)) as usize;
            self.stdout.read_exact(&mut buf[..want]).map_err(err)?;
            h.update(&buf[..want]);
            each(&buf[..want])?;
            left -= want as u64;
        }
        let mut nl = [0u8; 1];
        self.stdout.read_exact(&mut nl).map_err(err)?;
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
        let st = self
            .child
            .wait()
            .map_err(|e| format!("git cat-file: {e}"))?;
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
            let _ = self.child.kill();
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
    let git = Git::new(env, "export");
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

/// Moves `refs/base` to `refs/exports/<n>` (`paths` `None`), or to the base
/// with only `paths` taken from the export (a listed path the export lacks
/// is removed from the base).
pub fn advance(env: &GuestEnv, n: u32, paths: Option<&[String]>) -> Result<(), String> {
    let git = Git::new(env, "advance");
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
    // The export's tree, path -> "<mode> <oid>".
    let ls = git.run(&["ls-tree", "-r", "-z", "--full-tree", &exp])?;
    let mut have = BTreeMap::new();
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
        have.insert(rec[tab + 1..].to_vec(), format!("{mode} {oid}"));
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
