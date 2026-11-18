//! The local name detector (plan 47 Task 4; spec §2.4, §5.1, R47-11): the
//! pinned model fetch and the client of the sandboxed `saiife-ner` helper
//! (plan 46), which the daemon uses as its [`NameDetector`].
//!
//! **Fetch** (`blind.ner.fetch`): each of the three `[blind.ner]` files is
//! got over https through the daemon's upstream client, read up to
//! `max_bytes` (at most [`MODEL_CAP`], the most the helper can load under
//! its 4 GiB address-space limit), and its SHA-256 must equal its pin
//! before anything is written. It is stored as `<blind>/models/<sha256>`,
//! 0400 in a 0700 dir, through a temp file and a rename. A stored file
//! whose hash still matches is kept and not fetched again.
//!
//! **Client**: one helper at a time, one request at a time (the helper is
//! single-threaded). Every helper start re-hashes the three files first
//! (spec §2.4 "checked on every start"; the pin is each file's name), then
//! checks the helper file ([`check_helper`], R47-11), runs it with an empty
//! environment and cwd `/`, and reads its hello within [`HELLO_TIMEOUT`]:
//! protocol 1, labels among PER/ORG/LOC/MISC and holding PER (a subset is
//! fine). An answer must come within [`ANSWER_TIMEOUT`]. Any failure of the
//! helper fails the request closed ([`DetectError::Unavailable`], never "no
//! names") and stops the helper; the next request starts a new one, at
//! most [`MAX_RESTARTS`] times within [`RESTART_WINDOW`], then the detector
//! stays off until the window passes or [`NerClient::configure`] runs.
//!
//! **Never logged**: the text sent to the helper and the spans' text. Only
//! the helper's first stderr line is logged (its lines are fixed texts).

use super::ops::role;
use super::{lock, private_dir, Refusal};
use crate::ops::{Ctx, Mode};
use bytes::Bytes;
use http::{HeaderMap, Method, Uri};
use saiife_broker::request::Built;
use saiife_fido::client::{check_helper, HelperError};
use saiife_ipc::msg::ErrorCode;
use saiife_ipc::peer::PeerCred;
use saiife_policy::blind::{NerCfg, DEFAULT_NER_MAX_BYTES};
use saiife_shield::ner::{DetectError, NameDetector, NameSpan};
use saiife_shield::ner_proto::{decode, encode, Answer, Request, MAX_LINE, MAX_TEXT, PROTO};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The models' directory under the blind root.
pub const MODELS_DIR: &str = "models";
/// The largest model file the helper can load (tied to its 4 GiB
/// `RLIMIT_AS`, plan 46 R46-6). `[blind.ner] max_bytes` may not exceed it.
pub const MODEL_CAP: u64 = 1 << 30;
/// One whole fetch of one file.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// The helper's hello must come this soon after its start (loading a model
/// takes a while).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(60);
/// Each answer must come this soon after its request.
pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);
/// Helper starts after the first, within [`RESTART_WINDOW`].
pub const MAX_RESTARTS: usize = 3;
pub const RESTART_WINDOW: Duration = Duration::from_secs(60);
/// Debug builds only: the helper to run (checked as owned by this process's
/// uid, up to its own directory).
pub const HELPER_SEAM: &str = "SAIIFE_TEST_NER_HELPER";
/// Debug builds only: [`ANSWER_TIMEOUT`] in milliseconds.
pub const ANSWER_MS_SEAM: &str = "SAIIFE_TEST_NER_ANSWER_MS";
/// What every "fetch the model" text ends with.
pub const FETCH_HINT: &str = "saiife blind ner fetch";

/// The helper beside `saiife` in personal mode.
const HELPER_NAME: &str = "saiife-ner";
/// The labels a hello may name; PER must be among them.
const KNOWN_LABELS: [&str; 4] = ["PER", "ORG", "LOC", "MISC"];
/// A text over [`MAX_TEXT`] is sent in parts that overlap by this much, so
/// a name across a cut is whole in one part.
const OVERLAP: usize = 256;
/// The helper's stderr kept (the rest is read and dropped).
const STDERR_CAP: usize = 4096;
/// The longest stderr line logged, in chars.
const LOG_CHARS: usize = 200;

/// The three files, at `<blind>/models/<sha256>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NerFiles {
    pub model: PathBuf,
    pub vocab: PathBuf,
    pub labels: PathBuf,
}

impl NerFiles {
    fn parts(&self) -> [(&'static str, &Path); 3] {
        [
            ("model", &self.model),
            ("vocab", &self.vocab),
            ("labels", &self.labels),
        ]
    }
}

/// Where `cfg`'s files are kept under `root` (`<blind>`); nothing checked.
pub fn files_for(root: &Path, cfg: &NerCfg) -> NerFiles {
    let d = root.join(MODELS_DIR);
    NerFiles {
        model: d.join(&cfg.model_sha256),
        vocab: d.join(&cfg.vocab_sha256),
        labels: d.join(&cfg.labels_sha256),
    }
}

/// (which, url, pin) of each file.
fn pins(cfg: &NerCfg) -> [(&'static str, &str, &str); 3] {
    [
        ("model", &cfg.model_url, &cfg.model_sha256),
        ("vocab", &cfg.vocab_url, &cfg.vocab_sha256),
        ("labels", &cfg.labels_url, &cfg.labels_sha256),
    ]
}

/// The read limit of each file: `max_bytes`, 1 GiB by default, never more.
fn limit(cfg: &NerCfg) -> Result<u64, String> {
    let m = cfg.max_bytes.unwrap_or(DEFAULT_NER_MAX_BYTES);
    if m > MODEL_CAP {
        return Err(format!(
            "[blind.ner] max_bytes is {m}, over the 1 GiB ({MODEL_CAP} bytes) the name detector can load"
        ));
    }
    Ok(m)
}

fn sha256_hex(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

/// The SHA-256 of the regular file at `p` (never through a link), which
/// may hold at most `max` bytes.
fn hash_file(p: &Path, max: u64) -> io::Result<String> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(p)?;
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    if md.len() > max {
        return Err(io::Error::other("larger than allowed"));
    }
    let mut h = Sha256::new();
    let mut r = f.take(max.saturating_add(1));
    let mut buf = vec![0u8; 64 * 1024];
    let mut n_total: u64 = 0;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        n_total = n_total.saturating_add(n as u64);
        if n_total > max {
            return Err(io::Error::other("larger than allowed"));
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

/// One stored file checked against its pin; the fixed refusal if not.
fn verify(which: &str, path: &Path, pin: &str, max: u64) -> Result<(), String> {
    match hash_file(path, max) {
        Ok(h) if h == pin => Ok(()),
        Ok(_) => Err(format!(
            "the name-detector {which} has changed since it was fetched: {FETCH_HINT}"
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(format!(
            "the name-detector {which} is missing: {FETCH_HINT}"
        )),
        Err(e) => Err(format!(
            "the name-detector {which} cannot be used ({e}): {FETCH_HINT}"
        )),
    }
}

/// The three files of `cfg` under `root`, each re-hashed against its pin.
pub fn present(root: &Path, cfg: &NerCfg) -> Result<NerFiles, String> {
    let max = limit(cfg)?;
    let files = files_for(root, cfg);
    for ((which, _, pin), (_, path)) in pins(cfg).into_iter().zip(files.parts()) {
        verify(which, path, pin, max)?;
    }
    Ok(files)
}

/// The client's check at every start: each file's name is its pin.
fn rehash(files: &NerFiles) -> Result<(), String> {
    for (which, path) in files.parts() {
        let pin = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        verify(which, path, pin, MODEL_CAP)?;
    }
    Ok(())
}

/// One fetch at a time: two would share the temp files.
static FETCH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `blind.ner.fetch`: the three files of `cfg`, pinned, under
/// `<blind>/models/`. An error names the file and why; nothing is stored
/// for a file whose hash does not match its pin.
pub async fn fetch(ctx: &Ctx, cfg: &NerCfg) -> Result<NerFiles, String> {
    let _one = FETCH_LOCK.lock().await;
    let max = limit(cfg)?;
    let root = ctx.blind.root.clone();
    let dir = root.join(MODELS_DIR);
    private_dir(&dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    let up = ctx
        .upstream
        .as_ref()
        .map_err(|e| format!("cannot fetch the name-detector model: no upstream client ({e})"))?
        .with_timeout(FETCH_TIMEOUT);
    let read_limit = usize::try_from(max).unwrap_or(usize::MAX);
    for (which, url, pin) in pins(cfg) {
        let path = dir.join(pin);
        // A file already stored with the right hash is kept.
        let (p, pin_s) = (path.clone(), pin.to_string());
        let kept = tokio::task::spawn_blocking(move || keep_if_good(&p, &pin_s, max))
            .await
            .unwrap_or(false);
        if kept {
            continue;
        }
        let uri: Uri = url
            .parse()
            .map_err(|_| format!("[blind.ner] {which}_url is not a URL"))?;
        let b = Built {
            method: Method::GET,
            uri,
            headers: HeaderMap::new(),
            body: None,
        };
        let r = up
            .send(b, read_limit)
            .await
            .map_err(|e| format!("cannot fetch the name-detector {which}: {e}"))?;
        if r.status != 200 {
            return Err(format!(
                "cannot fetch the name-detector {which}: HTTP {}",
                r.status
            ));
        }
        if r.truncated {
            return Err(format!(
                "the name-detector {which} is larger than [blind.ner] max_bytes ({max} bytes)"
            ));
        }
        let got = sha256_hex(&r.body);
        if got != pin {
            return Err(format!(
                "the name-detector {which} does not match its pinned sha256 (got {got}): \
                 nothing was stored"
            ));
        }
        let body: Bytes = r.body;
        tokio::task::spawn_blocking(move || write_readonly(&path, &body))
            .await
            .map_err(|e| format!("cannot store the name-detector {which}: {e}"))?
            .map_err(|e| format!("cannot store the name-detector {which}: {e}"))?;
    }
    Ok(files_for(&root, cfg))
}

/// True when `path` holds `pin`'s bytes (then made 0400); a file that does
/// not is removed, so the fetch replaces it.
fn keep_if_good(path: &Path, pin: &str, max: u64) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match hash_file(path, max) {
        Ok(h) if h == pin => {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400));
            true
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        _ => {
            let _ = std::fs::remove_file(path);
            false
        }
    }
}

/// `bytes` at `path`, 0400: a new temp file beside it (never through a
/// link), fsync, rename, fsync of the dir. A failure removes the temp file.
fn write_readonly(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("no file name"))?;
    let mut part = name.to_os_string();
    part.push(".part");
    let part = dir.join(part);
    match std::fs::remove_file(&part) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let done = (|| {
        let mut f = crate::fsx::new_private_file(&part)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        f.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        drop(f);
        std::fs::rename(&part, path)
    })();
    if done.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    done?;
    crate::fsx::sync_dir(dir)
}

// ---------------------------------------------------------------- client ----

/// Where the detector is (`blind status`). The texts hold no values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NerState {
    /// No `[blind.ner]` in policy.
    NotConfigured,
    /// A model file is missing or changed: why (it names the fetch).
    Missing(String),
    /// A helper is running.
    Ready { pid: u32, labels: Vec<String> },
    /// The helper cannot run, or stopped: why.
    Failed(String),
}

impl NerState {
    /// The short word `blind.ner.fetch` and `status` show.
    pub fn word(&self) -> &'static str {
        match self {
            NerState::NotConfigured => "not configured",
            NerState::Missing(_) => "missing",
            NerState::Ready { .. } => "ready",
            NerState::Failed(_) => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Setup {
    files: NerFiles,
    mode: Mode,
    own_uid: u32,
}

#[derive(Default)]
struct Inner {
    setup: Option<Setup>,
    helper: Option<Helper>,
    /// The restarts within the window.
    restarts: VecDeque<Instant>,
}

/// The `saiife-ner` client: the daemon's [`NameDetector`]. Blocking: call
/// [`NameDetector::detect`] and [`NerClient::configure`] from a blocking
/// thread.
pub struct NerClient {
    /// Held across a whole request: one at a time.
    inner: Mutex<Inner>,
    /// Kept apart, so `state` never waits for a request.
    state: Mutex<NerState>,
}

impl Default for NerClient {
    fn default() -> Self {
        NerClient::new()
    }
}

impl NerClient {
    pub fn new() -> NerClient {
        NerClient {
            inner: Mutex::new(Inner::default()),
            state: Mutex::new(NerState::NotConfigured),
        }
    }

    pub fn state(&self) -> NerState {
        lock(&self.state).clone()
    }

    fn set_state(&self, s: NerState) {
        *lock(&self.state) = s;
    }

    /// Uses `files` (None: no detector) from now on and starts the helper
    /// (blocking, up to [`HELLO_TIMEOUT`]); the restart count starts over.
    /// The same files with a helper running change nothing.
    pub fn configure(&self, files: Option<NerFiles>, mode: Mode, own_uid: u32) {
        let mut g = lock(&self.inner);
        let setup = files.map(|files| Setup {
            files,
            mode,
            own_uid,
        });
        if setup.is_some() && g.setup == setup && g.helper.is_some() {
            return;
        }
        g.helper = None;
        g.restarts.clear();
        g.setup = setup;
        let Some(s) = g.setup.clone() else {
            self.set_state(NerState::NotConfigured);
            return;
        };
        match start(&s) {
            Ok(h) => {
                self.set_state(h.ready());
                g.helper = Some(h);
            }
            Err(st) => self.set_state(st),
        }
    }

    /// The running helper, started when there is none (a restart, counted).
    fn helper<'a>(&self, g: &'a mut Inner) -> Result<&'a mut Helper, DetectError> {
        if g.helper.is_none() {
            let Some(s) = g.setup.clone() else {
                return Err(DetectError::Unavailable(format!(
                    "no name-detector model is configured: {FETCH_HINT}"
                )));
            };
            let now = Instant::now();
            while g
                .restarts
                .front()
                .is_some_and(|t| now.duration_since(*t) >= RESTART_WINDOW)
            {
                g.restarts.pop_front();
            }
            if g.restarts.len() >= MAX_RESTARTS {
                let why = format!(
                    "the name detector stopped {MAX_RESTARTS} times within a minute; \
                     it stays off for a while"
                );
                self.set_state(NerState::Failed(why.clone()));
                return Err(DetectError::Unavailable(why));
            }
            g.restarts.push_back(now);
            match start(&s) {
                Ok(h) => {
                    self.set_state(h.ready());
                    g.helper = Some(h);
                }
                Err(st) => {
                    let why = match &st {
                        NerState::Missing(w) | NerState::Failed(w) => w.clone(),
                        _ => "the name detector did not start".to_string(),
                    };
                    self.set_state(st);
                    return Err(DetectError::Unavailable(why));
                }
            }
        }
        g.helper
            .as_mut()
            .ok_or_else(|| DetectError::Unavailable("the name detector did not start".into()))
    }
}

impl NameDetector for NerClient {
    fn detect(&self, text: &str) -> Result<Vec<NameSpan>, DetectError> {
        let mut g = lock(&self.inner);
        let limit = answer_timeout();
        let res = {
            let h = self.helper(&mut g)?;
            let mut all = Vec::new();
            let mut res = Ok(());
            for (at, part) in parts(text) {
                match h.call(part, limit) {
                    Ok(spans) => all.extend(spans.into_iter().map(|s| NameSpan {
                        start: s.start + at,
                        end: s.end + at,
                        label: s.label,
                    })),
                    Err(f) => {
                        res = Err(f);
                        break;
                    }
                }
            }
            res.map(|()| all)
        };
        match res {
            Ok(all) => Ok(merge(all)),
            Err(Fail::Request) => Err(DetectError::Failed),
            Err(Fail::Helper(why)) => {
                // Our own child: stopped (killed and reaped on drop).
                if let Some(h) = g.helper.take() {
                    h.log_stderr();
                }
                self.set_state(NerState::Failed(why.to_string()));
                Err(DetectError::Unavailable(why.to_string()))
            }
        }
    }
}

/// [`ANSWER_TIMEOUT`]; debug builds honour [`ANSWER_MS_SEAM`].
fn answer_timeout() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var(ANSWER_MS_SEAM)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    ANSWER_TIMEOUT
}

/// `text` as parts of at most [`MAX_TEXT`] bytes (their byte offsets), cut
/// on char boundaries, each overlapping the one before by [`OVERLAP`].
fn parts(text: &str) -> Vec<(usize, &str)> {
    if text.len() <= MAX_TEXT {
        return vec![(0, text)];
    }
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let mut end = (start + MAX_TEXT).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        out.push((start, &text[start..end]));
        if end == text.len() {
            return out;
        }
        let mut next = end.saturating_sub(OVERLAP).max(start + 1);
        while !text.is_char_boundary(next) {
            next += 1;
        }
        start = next;
    }
}

/// Leftmost first, the longer on a tie; a span overlapping one kept is
/// dropped (the parts' overlap finds some names twice).
fn merge(mut all: Vec<NameSpan>) -> Vec<NameSpan> {
    all.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out: Vec<NameSpan> = Vec::new();
    for s in all {
        if out.last().is_none_or(|l| s.start >= l.end) {
            out.push(s);
        }
    }
    out
}

// -------------------------------------------------------------- helper ----

/// The helper path (R47-11) and its check: locked mode
/// [`saiife_system::layout::NER_HELPER`], root-owned up to `/`; personal
/// mode that one if present, else `saiife-ner` beside this binary, owned by
/// the own user up to its directory. Debug builds honour [`HELPER_SEAM`].
fn locate(mode: Mode, own_uid: u32) -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os(HELPER_SEAM).filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        let root = p.parent().map(Path::to_path_buf).unwrap_or_default();
        return checked(p, crate::fsx::process_uid(), &root);
    }
    let system = PathBuf::from(saiife_system::layout::NER_HELPER);
    match mode {
        Mode::Locked => checked(system, 0, Path::new("/")),
        Mode::Personal => {
            if std::fs::symlink_metadata(&system).is_ok() {
                return checked(system, 0, Path::new("/"));
            }
            let exe = std::env::current_exe()
                .map_err(|e| format!("cannot find the saiife binary for the name detector: {e}"))?;
            let p = exe.with_file_name(HELPER_NAME);
            let root = p.parent().map(Path::to_path_buf).unwrap_or_default();
            checked(p, own_uid, &root)
        }
    }
}

fn checked(p: PathBuf, owner: u32, root: &Path) -> Result<PathBuf, String> {
    match check_helper(&p, owner, root) {
        Ok(()) => Ok(p),
        Err(HelperError::Missing) => Err(format!(
            "no name-detector helper at {}: install saiife-ner",
            p.display()
        )),
        Err(HelperError::Unsafe(why)) => Err(format!(
            "the name-detector helper {} is refused: {why}",
            p.display()
        )),
        Err(_) => Err(format!(
            "the name-detector helper {} cannot be checked",
            p.display()
        )),
    }
}

/// The files re-hashed, the helper checked and run, its hello read.
fn start(s: &Setup) -> Result<Helper, NerState> {
    rehash(&s.files).map_err(NerState::Missing)?;
    let path = locate(s.mode, s.own_uid).map_err(NerState::Failed)?;
    Helper::spawn(&path, &s.files).map_err(NerState::Failed)
}

/// One stdout line, or why reading stopped.
type Line = Result<Vec<u8>, &'static str>;

/// Why a request got no spans.
enum Fail {
    /// The helper answered an error for this request; it is fine.
    Request,
    /// The helper misbehaved or stopped: it is stopped.
    Helper(&'static str),
}

/// A running helper, ours to kill.
struct Helper {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<Line>,
    stderr: Arc<Mutex<Vec<u8>>>,
    /// Request ids start at 1 (0 is the helper's "no request" id).
    next_id: u64,
    pid: u32,
    labels: Vec<String>,
}

impl Drop for Helper {
    fn drop(&mut self) {
        // Our own child only: the one signal sent, then reaped.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Helper {
    fn spawn(path: &Path, files: &NerFiles) -> Result<Helper, String> {
        let sum = |p: &Path| p.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        let mut child = Command::new(path)
            .arg("--model")
            .arg(&files.model)
            .arg("--vocab")
            .arg(&files.vocab)
            .arg("--labels")
            .arg(&files.labels)
            .arg("--sha256-model")
            .arg(sum(&files.model))
            .arg("--sha256-vocab")
            .arg(sum(&files.vocab))
            .arg("--sha256-labels")
            .arg(sum(&files.labels))
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start the name detector: {}", e.kind()))?;
        let (Some(stdin), Some(stdout), Some(errout)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("cannot start the name detector: no pipes".into());
        };
        let (tx, lines) = mpsc::channel::<Line>();
        std::thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match (&mut r)
                    .take(MAX_LINE as u64 + 1)
                    .read_until(b'\n', &mut line)
                {
                    Ok(0) => return,
                    Ok(_) if line.len() > MAX_LINE => {
                        let _ = tx.send(Err("the name detector sent a line too long"));
                        return;
                    }
                    Ok(_) => {
                        if tx.send(Ok(line)).is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        let _ = tx.send(Err("cannot read the name detector"));
                        return;
                    }
                }
            }
        });
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let keep = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut err = errout;
            let mut buf = [0u8; 1024];
            loop {
                match err.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut k = lock(&keep);
                        let room = STDERR_CAP.saturating_sub(k.len());
                        k.extend_from_slice(&buf[..n.min(room)]);
                    }
                }
            }
        });
        let pid = child.id();
        let mut h = Helper {
            child,
            stdin,
            lines,
            stderr,
            next_id: 1,
            pid,
            labels: Vec::new(),
        };
        match h.hello() {
            Ok(labels) => {
                h.labels = labels;
                Ok(h)
            }
            Err(why) => {
                h.log_stderr();
                Err(why)
            }
        }
    }

    fn ready(&self) -> NerState {
        NerState::Ready {
            pid: self.pid,
            labels: self.labels.clone(),
        }
    }

    /// The hello within [`HELLO_TIMEOUT`]: protocol 1, labels among the
    /// four, PER among them.
    fn hello(&mut self) -> Result<Vec<String>, String> {
        let line = match self.lines.recv_timeout(HELLO_TIMEOUT) {
            Ok(Ok(l)) => l,
            Ok(Err(why)) => return Err(why.to_string()),
            Err(RecvTimeoutError::Timeout) => {
                return Err(format!(
                    "the name detector sent no hello within {} s",
                    HELLO_TIMEOUT.as_secs()
                ))
            }
            Err(RecvTimeoutError::Disconnected) => {
                // Reaped on drop; the status says how it ended.
                let code = wait_briefly(&mut self.child);
                return Err(match code {
                    Some(c) => format!("the name detector exited ({c}) before its hello"),
                    None => "the name detector exited before its hello".to_string(),
                });
            }
        };
        match decode::<Answer>(&line) {
            Ok(Answer::Hello { proto, labels, .. }) => {
                if proto != PROTO {
                    return Err(format!(
                        "the name detector speaks protocol {proto}, not {PROTO}"
                    ));
                }
                if labels.is_empty() || labels.iter().any(|l| !KNOWN_LABELS.contains(&l.as_str())) {
                    return Err("the name detector names labels it should not".into());
                }
                if !labels.iter().any(|l| l == "PER") {
                    return Err(
                        "the name detector does not report people's names (no PER label)".into(),
                    );
                }
                Ok(labels)
            }
            Ok(Answer::Error { .. }) => Err(format!(
                "the name detector cannot load the model: {FETCH_HINT}"
            )),
            Ok(_) | Err(_) => Err("the name detector sent no hello first".into()),
        }
    }

    /// One request; its spans, checked against `text`.
    fn call(&mut self, text: &str, limit: Duration) -> Result<Vec<NameSpan>, Fail> {
        let id = self.next_id;
        self.next_id += 1;
        let line = encode(&Request::Detect {
            id,
            text: text.to_string(),
        });
        if self
            .stdin
            .write_all(&line)
            .and_then(|()| self.stdin.flush())
            .is_err()
        {
            return Err(Fail::Helper("the name detector stopped"));
        }
        let line = match self.lines.recv_timeout(limit) {
            Ok(Ok(l)) => l,
            Ok(Err(why)) => return Err(Fail::Helper(why)),
            Err(RecvTimeoutError::Timeout) => {
                return Err(Fail::Helper("the name detector did not answer in time"))
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(Fail::Helper("the name detector stopped"))
            }
        };
        match decode::<Answer>(&line) {
            Ok(Answer::Spans { id: got, spans }) if got == id => spans
                .iter()
                .map(|s| s.to_span(text))
                .collect::<Option<Vec<_>>>()
                .ok_or(Fail::Helper(
                    "the name detector answered a span outside the text",
                )),
            Ok(Answer::Error { id: got, .. }) if got == id => Err(Fail::Request),
            Ok(Answer::Error { id: 0, .. }) => {
                Err(Fail::Helper("the name detector could not read a request"))
            }
            Ok(_) => Err(Fail::Helper("the name detector answered out of turn")),
            Err(_) => Err(Fail::Helper("the name detector sent a malformed answer")),
        }
    }

    /// Logs the helper's first stderr line (its lines are fixed texts),
    /// printable ASCII only and cut.
    fn log_stderr(&self) {
        let kept = lock(&self.stderr).clone();
        let line = kept.split(|b| *b == b'\n').next().unwrap_or_default();
        let shown: String = line
            .iter()
            .map(|b| match b {
                0x20..=0x7e => *b as char,
                _ => '?',
            })
            .take(LOG_CHARS)
            .collect();
        if !shown.trim().is_empty() {
            eprintln!("saiifed: name detector: {shown}");
        }
    }
}

/// The exit code of a child whose stdout closed, if it ends within 1 s.
fn wait_briefly(child: &mut Child) -> Option<i32> {
    let end = Instant::now() + Duration::from_secs(1);
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s.code(),
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(10)),
            _ => return None,
        }
    }
}

// ------------------------------------------------------------------ ops ----

/// Puts the policy's `[blind.ner]` in force: configures the client (on a
/// blocking thread: a start re-hashes the files and waits for the hello)
/// and fills the build's detector slot (ruling P47-6) while a model is
/// configured and its files are there.
pub async fn apply(ctx: Arc<Ctx>) {
    let cfg = ctx.policy().system.and_then(|s| s.blind.ner.clone());
    let _ = tokio::task::spawn_blocking(move || {
        let files = cfg.as_ref().map(|c| files_for(&ctx.blind.root, c));
        ctx.blind.ner.configure(files, ctx.mode, ctx.own_uid);
        let slot: Option<Arc<dyn NameDetector>> = match ctx.blind.ner.state() {
            NerState::NotConfigured | NerState::Missing(_) => None,
            NerState::Ready { .. } | NerState::Failed(_) => {
                Some(Arc::clone(&ctx.blind.ner) as Arc<dyn NameDetector>)
            }
        };
        ctx.blind.set_detector(slot);
    })
    .await;
}

/// R47-3: root, the `[admin]` groups and `[approval] approvers`, or an
/// approver of any dataset in policy (the personal broker: its own user).
async fn may_fetch(ctx: &Ctx, peer: &PeerCred) -> bool {
    if role(ctx, peer, None).await.may_manage() {
        return true;
    }
    let datasets = ctx
        .policy()
        .system
        .map(|s| s.blind.dataset.clone())
        .unwrap_or_default();
    for d in &datasets {
        if role(ctx, peer, Some(d)).await.approver {
            return true;
        }
    }
    false
}

/// `blind.ner.fetch {}`: fetches the pinned files, then starts the
/// detector. Answers the three hashes and the detector's state.
pub async fn fetch_op(ctx: &Arc<Ctx>, peer: &PeerCred) -> Result<Value, Refusal> {
    if !may_fetch(ctx, peer).await {
        return Err(Refusal::new(
            ErrorCode::Forbidden,
            "only an admin or an approver may fetch the name-detector model",
        ));
    }
    let Some(cfg) = ctx.policy().system.and_then(|s| s.blind.ner.clone()) else {
        return Err(Refusal::new(
            ErrorCode::BadRequest,
            "no [blind.ner] in policy: name the model files and their sha256 there, then reload",
        ));
    };
    fetch(ctx, &cfg)
        .await
        .map_err(|e| Refusal::new(ErrorCode::Unavailable, e))?;
    apply(Arc::clone(ctx)).await;
    let state = ctx.blind.ner.state();
    let mut v = json!({
        "model": cfg.model_sha256,
        "vocab": cfg.vocab_sha256,
        "labels": cfg.labels_sha256,
        "detector": state.word(),
    });
    if let NerState::Missing(why) | NerState::Failed(why) = &state {
        v["reason"] = Value::from(why.as_str());
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_shield::ner::SpanLabel;

    #[test]
    fn parts_cover_the_text_on_char_boundaries() {
        assert_eq!(parts("abc"), vec![(0, "abc")]);
        let t = "ø".repeat(MAX_TEXT); // 2 * MAX_TEXT bytes
        let ps = parts(&t);
        assert!(ps.len() >= 3);
        let mut covered = 0;
        for (at, p) in &ps {
            assert!(p.len() <= MAX_TEXT);
            assert!(*at <= covered, "a gap before {at}");
            assert_eq!(&t[*at..*at + p.len()], *p);
            covered = at + p.len();
        }
        assert_eq!(covered, t.len());
        // Each part after the first overlaps the one before.
        for w in ps.windows(2) {
            assert!(w[1].0 + OVERLAP <= w[0].0 + w[0].1.len() + 1);
        }
    }

    #[test]
    fn merge_drops_repeats_and_overlaps() {
        let s = |a, b| NameSpan {
            start: a,
            end: b,
            label: SpanLabel::Person,
        };
        assert_eq!(
            merge(vec![s(10, 20), s(0, 5), s(10, 20), s(12, 15), s(10, 22)]),
            vec![s(0, 5), s(10, 22)]
        );
    }

    #[test]
    fn limit_is_capped() {
        let mut c = NerCfg {
            model_url: "https://x/m".into(),
            model_sha256: "0".repeat(64),
            vocab_url: "https://x/v".into(),
            vocab_sha256: "1".repeat(64),
            labels_url: "https://x/l".into(),
            labels_sha256: "2".repeat(64),
            max_bytes: None,
        };
        assert_eq!(limit(&c), Ok(MODEL_CAP));
        assert_eq!(DEFAULT_NER_MAX_BYTES, MODEL_CAP);
        c.max_bytes = Some(10);
        assert_eq!(limit(&c), Ok(10));
        c.max_bytes = Some(MODEL_CAP + 1);
        assert!(limit(&c).unwrap_err().contains("1 GiB"));
    }

    #[test]
    fn locked_mode_uses_the_system_helper() {
        if std::env::var_os(HELPER_SEAM).is_some() {
            return;
        }
        let e = match locate(Mode::Locked, 1000) {
            Ok(p) => {
                assert_eq!(p, Path::new(saiife_system::layout::NER_HELPER));
                return;
            }
            Err(e) => e,
        };
        assert!(e.contains(saiife_system::layout::NER_HELPER), "{e}");
    }

    #[test]
    fn not_configured_is_unavailable() {
        let c = NerClient::new();
        assert_eq!(c.state(), NerState::NotConfigured);
        match c.detect("Søren") {
            Err(DetectError::Unavailable(why)) => assert!(why.contains(FETCH_HINT), "{why}"),
            other => panic!("{other:?}"),
        }
    }
}
