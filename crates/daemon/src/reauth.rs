//! Same-user re-authentication through polkit (spec §6.10.2, plan 11
//! decision 7). The daemon runs
//! `pkcheck --action-id com.saiife.approve --process <pid>,<start>,<uid>
//! --allow-user-interaction --detail request <what>` for the approving CLI
//! process, with an empty environment except `PATH`, and kills it (its own
//! child) at the timeout. The action file names the daemon user as the
//! action's owner (`org.freedesktop.policykit.owner`): polkit lets only
//! root or an action owner check another user's process, and the daemon
//! runs as `saiife`. The first line of pkcheck's stderr goes into the
//! result, so a refusal says why.
//! Exit 0 is authorized; 1 and 3 and a signal are denied; 2 and 127 are
//! unavailable; 126 and any other code, a spawn failure or a timeout are an
//! error (see [`exit_result`]). Every non-`Authorized` result refuses the
//! approval.
//!
//! On macOS same-user re-authentication is off in this version
//! ([`PromptWithoutDetail`]): the prompt cannot show which request is
//! approved. [`MacAuthorize`] is built and tested for when it can be: per
//! plan 13 decisions 3 to 5 the approving CLI
//! sends the external form of an empty authorization reference, and the
//! daemon runs `/usr/bin/security authorize -u -i -d com.saiife.approve`
//! with that form on stdin, the same way: its own child, `PATH` only,
//! killed at the timeout. The check rests on the reference and never on the
//! peer pid (`LOCAL_PEERPID` is the socket's last pid); the approver is
//! `LOCAL_PEERCRED`'s uid.

use crate::sessions::Proc;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The polkit action id `system install` registers.
pub const ACTION_ID: &str = "com.saiife.approve";
/// Where `system install` writes the polkit action file.
pub const ACTION_FILE: &str = "/usr/share/polkit-1/actions/com.saiife.approve.policy";
/// The production `pkcheck`.
pub const PKCHECK: &str = "/usr/bin/pkcheck";
/// How long a password prompt may take (decision 7).
pub const REAUTH_TIMEOUT: Duration = Duration::from_secs(120);
/// The only environment `pkcheck` gets.
pub const PKCHECK_PATH_ENV: &str = "/usr/bin:/bin";

/// Where a polkit daemon binary may live: the one list shared with
/// `system install` and `doctor`.
pub use saiife_system::polkit::POLKITD_PATHS;
/// pkcheck(1) exit statuses.
const EXIT_AUTHORIZED: i32 = 0;
const EXIT_NOT_AUTHORIZED: i32 = 1;
const EXIT_CHALLENGE: i32 = 2;
const EXIT_DISMISSED: i32 = 3;
const EXIT_BAD_OPTIONS: i32 = 126;
const EXIT_ERROR: i32 = 127;

/// Maps a pkcheck exit to a result (pkcheck(1)): 0 authorized; 1 (not
/// authorized) and 3 (dismissed) denied; 2 (authentication needed, no agent
/// answered) and 127 (an error, e.g. polkitd down) unavailable; 126 (bad
/// options) and any other code an error; killed by a signal (`None`) denied.
/// `stderr` is the first line pkcheck wrote there (cleaned, maybe empty).
fn exit_result(code: Option<i32>, stderr: &str) -> ReauthResult {
    let with = |m: String| {
        if stderr.is_empty() {
            m
        } else {
            format!("{m}: {stderr}")
        }
    };
    match code {
        Some(EXIT_AUTHORIZED) => ReauthResult::Authorized,
        Some(EXIT_NOT_AUTHORIZED | EXIT_DISMISSED) | None => ReauthResult::Denied(stderr.into()),
        Some(EXIT_CHALLENGE | EXIT_ERROR) => ReauthResult::Unavailable(stderr.into()),
        Some(EXIT_BAD_OPTIONS) => ReauthResult::Error(with("pkcheck: bad options".into())),
        Some(c) => ReauthResult::Error(with(format!("pkcheck: unexpected exit {c}"))),
    }
}

/// The tool whose answer a refusal quotes.
#[cfg(target_os = "macos")]
pub const TOOL: &str = "security";
#[cfg(not(target_os = "macos"))]
pub const TOOL: &str = "pkcheck";

/// The longest stderr line kept, in characters.
pub const MAX_STDERR_CHARS: usize = 200;
/// How much of pkcheck's stderr is read at most.
const MAX_STDERR_BYTES: u64 = 8 * 1024;

/// The first non-empty line of `raw`: printable characters only, at most
/// [`MAX_STDERR_CHARS`].
pub fn first_line(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_STDERR_CHARS)
        .collect()
}

/// The longest `--detail request` value, in characters.
pub const MAX_DETAIL_CHARS: usize = 120;

/// Unicode Cf (format) characters, bidi controls among them: they can
/// reorder or hide text in the prompt.
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
        | '\u{08E2}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2028}' | '\u{2029}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
        | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{1D173}'..='\u{1D17A}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

/// A `--detail request` value: control characters become spaces, at most
/// [`MAX_DETAIL_CHARS`] characters. polkit shows it in the prompt.
pub fn clean_detail(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || is_format_char(c) {
                ' '
            } else {
                c
            }
        })
        .take(MAX_DETAIL_CHARS)
        .collect()
}

/// After a re-authentication that did not succeed (denied, dismissed, timed
/// out, an error), the uid waits this long before polkit is asked again;
/// each further failure doubles the wait, up to [`COOLDOWN_MAX`]. A success
/// resets it. So an agent cannot flood its user with password prompts.
pub const COOLDOWN_FIRST: Duration = Duration::from_secs(30);
pub const COOLDOWN_MAX: Duration = Duration::from_secs(600);

/// Per-uid re-authentication cooldowns.
#[derive(Debug, Default)]
pub struct Cooldowns {
    /// uid -> (no prompt before, the next wait).
    map: HashMap<u32, (Instant, Duration)>,
}

impl Cooldowns {
    /// How long `uid` must still wait at `now`, if at all.
    pub fn remaining(&self, uid: u32, now: Instant) -> Option<Duration> {
        let (until, _) = self.map.get(&uid)?;
        (*until > now).then(|| *until - now)
    }

    /// A failed re-authentication of `uid` at `now`.
    pub fn failed(&mut self, uid: u32, now: Instant) {
        let wait = self.map.get(&uid).map_or(COOLDOWN_FIRST, |(_, n)| *n);
        self.map
            .insert(uid, (now + wait, (wait * 2).min(COOLDOWN_MAX)));
    }

    /// A successful re-authentication of `uid`.
    pub fn succeeded(&mut self, uid: u32) {
        self.map.remove(&uid);
    }
}

/// How often a running `pkcheck` is polled for its exit.
const POLL: Duration = Duration::from_millis(10);

/// The uids with a re-authentication in flight: at most one each, so one
/// password prompt cannot authorize several queued approvals.
fn in_flight() -> &'static Mutex<HashSet<u64>> {
    static IN_FLIGHT: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();
    IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Held while `uid`'s re-authentication runs; dropping it frees the slot.
#[derive(Debug)]
pub struct InFlight(u64);

impl InFlight {
    /// `None` when `uid` already has a re-authentication in flight.
    pub fn begin(uid: u32) -> Option<InFlight> {
        let key = slot_key(uid);
        let inserted = in_flight()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key);
        // Built only on success, after the lock is released: a dropped
        // `InFlight` frees its uid's slot.
        inserted.then_some(InFlight(key))
    }
}

/// Test only: uids at or above this keep one global slot (tests that need
/// two threads to meet on one slot use them); lower fixture uids are scoped
/// per test thread. Caveat: the scope is the thread's name, so unnamed
/// threads (spawned helpers) share one scope per uid; the test harness
/// names its test threads.
#[cfg(test)]
const GLOBAL_UID_FLOOR: u32 = 990_000;

/// The slot for `uid`. In production that is the uid itself. Under test the
/// slot set would be shared by every parallel test, so a uid below
/// [`GLOBAL_UID_FLOOR`] (the shared fixture users) is scoped to the calling test's
/// thread; the high uids stay global for the tests that need two threads
/// to meet on one slot.
#[cfg(not(test))]
fn slot_key(uid: u32) -> u64 {
    u64::from(uid)
}

#[cfg(test)]
fn slot_key(uid: u32) -> u64 {
    use std::hash::{Hash, Hasher};
    if uid >= GLOBAL_UID_FLOOR {
        return u64::from(uid);
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().name().hash(&mut h);
    (h.finish() << 32) | u64::from(uid)
}

impl Drop for InFlight {
    fn drop(&mut self) {
        in_flight()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReauthResult {
    Authorized,
    /// Not authorized or dismissed; pkcheck's first stderr line, if any.
    Denied(String),
    /// No agent answered, or polkit could not check (e.g. it refused an
    /// untrusted caller); pkcheck's first stderr line, if any.
    Unavailable(String),
    Error(String),
}

/// Who re-authenticates: the approving CLI as the daemon saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subject {
    /// The peer pid (polkit's subject on Linux; never used on macOS).
    pub pid: u32,
    /// The peer's start time, read when the connection was accepted.
    pub start: u64,
    /// The approver's uid (the peer credential).
    pub uid: u32,
    /// macOS: the external form of the CLI's authorization reference.
    pub auth: Option<[u8; 32]>,
}

/// The re-authentication seam: production is [`PkCheck`] (Linux) or
/// [`MacAuthorize`] (macOS), tests use fakes.
pub trait Reauth: Send + Sync {
    /// Whether re-authentication can run at all on this host.
    fn available(&self) -> bool;
    /// Asks whether `who` proved a human is present, within `timeout`.
    /// `detail` names what is approved; polkit shows it in the prompt.
    fn check(&self, who: &Subject, detail: &str, timeout: Duration) -> ReauthResult;
}

/// The host's re-authentication: polkit on Linux; on macOS, none in this
/// version ([`PromptWithoutDetail`]: `same_user = "reauth"` acts as
/// `"deny"`).
pub fn host_reauth() -> std::sync::Arc<dyn Reauth> {
    #[cfg(target_os = "macos")]
    {
        std::sync::Arc::new(PromptWithoutDetail)
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::sync::Arc::new(PkCheck::new())
    }
}

/// `pkcheck` from polkit.
#[derive(Debug, Clone)]
pub struct PkCheck {
    pkcheck: PathBuf,
    action_file: PathBuf,
    polkitd: Vec<PathBuf>,
}

impl Default for PkCheck {
    fn default() -> Self {
        PkCheck::new()
    }
}

impl PkCheck {
    /// `/usr/bin/pkcheck` and the installed action file.
    pub fn new() -> PkCheck {
        PkCheck::with_paths(PKCHECK, ACTION_FILE)
    }

    /// Other paths, for tests (a fake `pkcheck` in a tempdir).
    pub fn with_paths(pkcheck: impl Into<PathBuf>, action_file: impl Into<PathBuf>) -> PkCheck {
        PkCheck {
            pkcheck: pkcheck.into(),
            action_file: action_file.into(),
            polkitd: POLKITD_PATHS.iter().map(PathBuf::from).collect(),
        }
    }

    /// Other polkit daemon locations than [`POLKITD_PATHS`], for tests.
    pub fn with_polkitd(mut self, candidates: Vec<PathBuf>) -> PkCheck {
        self.polkitd = candidates;
        self
    }

    /// The argv after the program name (decision 7).
    pub fn argv(pid: u32, start: u64, uid: u32, detail: &str) -> Vec<String> {
        vec![
            "--action-id".to_string(),
            ACTION_ID.to_string(),
            "--process".to_string(),
            format!("{pid},{start},{uid}"),
            "--allow-user-interaction".to_string(),
            "--detail".to_string(),
            "request".to_string(),
            clean_detail(detail),
        ]
    }
}

impl Reauth for PkCheck {
    /// `pkcheck` and the action file are regular files whose whole paths are
    /// root-owned and not group/other-writable, and a polkit daemon binary
    /// is installed.
    fn available(&self) -> bool {
        // polkit's subject is the pid; outside Linux (macOS: the socket's
        // last pid, not strictly its connector) no approval may rest on a
        // pid, so polkit is never used there (plan 13, Task 7).
        cfg!(target_os = "linux")
            && root_owned_file(&self.pkcheck)
            && root_owned_file(&self.action_file)
            && polkitd_present(&self.polkitd)
    }

    fn check(&self, who: &Subject, detail: &str, timeout: Duration) -> ReauthResult {
        let mut cmd = Command::new(&self.pkcheck);
        cmd.args(PkCheck::argv(who.pid, who.start, who.uid, detail))
            .env_clear()
            .env("PATH", PKCHECK_PATH_ENV)
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        match run_bounded(&mut cmd, &self.pkcheck, "pkcheck", None, timeout) {
            Ok(ran) => exit_result(ran.code, &first_line(&ran.stderr)),
            Err(e) => ReauthResult::Error(e),
        }
    }
}

/// What a bounded child run gave.
struct Ran {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Reads a child pipe on the side (bounded), so a chatty child never blocks
/// on a full pipe; the rest is drained and dropped.
fn side_reader<R: std::io::Read + Send + 'static>(
    pipe: Option<R>,
) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    pipe.map(|mut p| {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut b = Vec::new();
            let _ = (&mut p).take(MAX_STDERR_BYTES).read_to_end(&mut b);
            let _ = std::io::copy(&mut p, &mut std::io::sink());
            b
        })
    })
}

/// Runs `cmd` (spawned from `path`, called `name` in errors) as our own
/// child: `input` is written to its stdin, which is then closed; at
/// `timeout` it is killed and reaped through its handle. An `Err` is a
/// spawn failure, a wait failure or the timeout.
fn run_bounded(
    cmd: &mut Command,
    path: &Path,
    name: &str,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Ran, String> {
    let mut child = spawn(cmd).map_err(|e| format!("{}: {e}", path.display()))?;
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        use std::io::Write;
        // 32 bytes always fit the pipe; a child that already exited only
        // makes this fail (EPIPE), and its answer still decides.
        let _ = stdin.write_all(bytes);
    }
    let stdout = side_reader(child.stdout.take());
    let stderr = side_reader(child.stderr.take());
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // The child has exited and does not fork: its pipes are at
                // EOF, so the joins return.
                let join = |t: Option<std::thread::JoinHandle<Vec<u8>>>| {
                    t.and_then(|t| t.join().ok()).unwrap_or_default()
                };
                return Ok(Ran {
                    code: status.code(),
                    stdout: join(stdout),
                    stderr: join(stderr),
                });
            }
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("waiting for {name}: {e}"));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            // Our own child: kill and reap it.
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{name} timed out after {} ms", timeout.as_millis()));
        }
        std::thread::sleep(POLL.min(deadline - now));
    }
}

/// The production `security` (macOS).
pub const SECURITY: &str = "/usr/bin/security";
/// The authorization right `system install` registers on macOS.
pub use saiife_system::authright::RIGHT;
/// How long `security authorizationdb read` may take in `available()`.
pub const RIGHT_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// The refusal detail when a same-user approval came without `auth`.
pub const NO_AUTH: &str = "the approving CLI sent no authorization";
/// `security authorize` status codes (Authorization Services).
const ERR_DENIED: i32 = -60005;
const ERR_CANCELED: i32 = -60006;
const ERR_INTERACTION_NOT_ALLOWED: i32 = -60007;

/// Maps `security authorize`'s answer to a result (decision 5). `out` is
/// its stdout, then its stderr; the first line matching
/// `^(YES|NO) \((-?\d+)\)` is the answer. `YES (0)` with exit 0 is
/// authorized; `NO (-60005)` (denied) and `NO (-60006)` (canceled) are
/// denied; `NO (-60007)` (interaction not allowed: SSH, no GUI) is
/// unavailable; any other code, no answer or a signal is an error.
pub fn parse_answer(code: Option<i32>, out: &str) -> ReauthResult {
    let Some(code) = code else {
        return ReauthResult::Error("security: killed by a signal".into());
    };
    let answer = out.lines().find_map(|l| answer_of(l).map(|a| (l, a)));
    let Some((line, (yes, status))) = answer else {
        let first = first_line(out.as_bytes());
        return ReauthResult::Error(if first.is_empty() {
            format!("security: no answer (exit {code})")
        } else {
            format!("security: no answer (exit {code}): {first}")
        });
    };
    let line = first_line(line.as_bytes());
    match (yes, status) {
        (true, 0) if code == 0 => ReauthResult::Authorized,
        (true, _) => ReauthResult::Error(format!("security: {line} (exit {code})")),
        (false, ERR_DENIED | ERR_CANCELED) => ReauthResult::Denied(line),
        (false, ERR_INTERACTION_NOT_ALLOWED) => ReauthResult::Unavailable(line),
        (false, _) => ReauthResult::Error(format!("security: {line}")),
    }
}

/// `(yes, status)` of a line `YES (<n>)` or `NO (<n>)`.
fn answer_of(line: &str) -> Option<(bool, i32)> {
    let (yes, rest) = if let Some(r) = line.strip_prefix("YES (") {
        (true, r)
    } else {
        (false, line.strip_prefix("NO (")?)
    };
    let (num, _) = rest.split_once(')')?;
    let digits = num.strip_prefix('-').unwrap_or(num);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((yes, num.parse().ok()?))
}

/// The `auth` argument: exactly 64 lowercase hex characters, the 32-byte
/// external form of an authorization reference.
pub fn parse_auth_hex(s: &str) -> Result<[u8; 32], String> {
    const BAD: &str = "auth is 64 lowercase hex characters";
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(BAD.into());
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(b[2 * i]).ok_or(BAD)? << 4) | nib(b[2 * i + 1]).ok_or(BAD)?;
    }
    Ok(out)
}

/// The refusal detail of a same-user approval on macOS.
pub const MAC_NO_DETAIL: &str =
    "the macOS password prompt cannot show which request is approved, so same-user approval is off on macOS";

/// macOS in this version: same-user re-authentication is off, so
/// `same_user = "reauth"` acts as `"deny"` (a second account approves).
///
/// Why (security review of plan 13, Task 8): `security authorize` shows
/// only the right's fixed `default-prompt`, never which request is
/// approved, so a same-user agent could start an approval of its own
/// request while the human believes they confirm another one. A prompt
/// text the CLI supplies (`kAuthorizationEnvironmentPrompt`) would be
/// chosen by a process the agent can imitate, so it binds nothing either.
/// polkit on Linux shows the daemon's `--detail`. Until a macOS prompt can
/// carry a detail the daemon chooses, [`MacAuthorize`] stays unused.
#[derive(Debug, Clone, Copy, Default)]
pub struct PromptWithoutDetail;

impl Reauth for PromptWithoutDetail {
    fn available(&self) -> bool {
        false
    }
    fn check(&self, _who: &Subject, _detail: &str, _timeout: Duration) -> ReauthResult {
        ReauthResult::Unavailable(MAC_NO_DETAIL.into())
    }
}

/// How many used external forms [`MacAuthorize`] remembers.
const USED_FORMS: usize = 1024;

/// `security authorize` on the CLI's authorization reference (macOS). It
/// builds on every unix, so the Linux tests run it with fake scripts.
/// Not wired in yet: see [`PromptWithoutDetail`]. Each external form is
/// single-use: it arrives with the request it decides, and a second check
/// with the same form is an error, never another prompt.
#[derive(Debug, Clone)]
pub struct MacAuthorize {
    security: PathBuf,
    used: std::sync::Arc<Mutex<std::collections::VecDeque<[u8; 32]>>>,
}

impl Default for MacAuthorize {
    fn default() -> Self {
        MacAuthorize::new()
    }
}

impl MacAuthorize {
    /// `/usr/bin/security`.
    pub fn new() -> MacAuthorize {
        MacAuthorize::with_path(SECURITY)
    }

    /// Another `security`, for tests (a fake script in a tempdir).
    pub fn with_path(security: impl Into<PathBuf>) -> MacAuthorize {
        MacAuthorize {
            security: security.into(),
            used: std::sync::Arc::default(),
        }
    }

    /// The argv after the program name: user interaction allowed (`-u`),
    /// the reference read from stdin (`-i`), the acquired right destroyed
    /// afterwards (`-d`). No pid: the reference names the session.
    pub fn argv() -> Vec<String> {
        ["authorize", "-u", "-i", "-d", RIGHT]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn command(&self, args: &[String], stdin: bool) -> Command {
        let mut cmd = Command::new(&self.security);
        cmd.args(args)
            .env_clear()
            .env("PATH", PKCHECK_PATH_ENV)
            .current_dir("/")
            .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// `security authorizationdb read com.saiife.approve` exits 0 within
    /// [`RIGHT_READ_TIMEOUT`] and prints a right that passes `read_ok`.
    fn right_registered(&self) -> bool {
        let args: Vec<String> = saiife_system::authright::read_args()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut cmd = self.command(&args, false);
        match run_bounded(
            &mut cmd,
            &self.security,
            "security",
            None,
            RIGHT_READ_TIMEOUT,
        ) {
            Ok(ran) => {
                ran.code == Some(0)
                    && saiife_system::authright::read_ok(&String::from_utf8_lossy(&ran.stdout))
                        .is_ok()
            }
            Err(_) => false,
        }
    }
}

impl Reauth for MacAuthorize {
    /// `security` is a root-owned regular file (its whole path), and the
    /// right is registered as decision 4 writes it. A missing right makes
    /// `same_user = "reauth"` act as `"deny"`.
    fn available(&self) -> bool {
        root_owned_file(&self.security) && self.right_registered()
    }

    /// Decides by the reference alone: `who.pid` and `who.start` are never
    /// used (macOS `LOCAL_PEERPID` is the socket's last pid). `detail` is
    /// not passed either: the prompt is the right's `default-prompt`.
    fn check(&self, who: &Subject, _detail: &str, timeout: Duration) -> ReauthResult {
        let Some(auth) = who.auth else {
            return ReauthResult::Unavailable(NO_AUTH.into());
        };
        {
            let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
            if used.contains(&auth) {
                return ReauthResult::Error("this authorization was already used".into());
            }
            if used.len() >= USED_FORMS {
                used.pop_front();
            }
            used.push_back(auth);
        }
        let mut cmd = self.command(&MacAuthorize::argv(), true);
        match run_bounded(&mut cmd, &self.security, "security", Some(&auth), timeout) {
            Ok(ran) => {
                let out = format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&ran.stdout),
                    String::from_utf8_lossy(&ran.stderr)
                );
                parse_answer(ran.code, &out)
            }
            Err(e) => ReauthResult::Error(e),
        }
    }
}

/// Spawns `cmd`, retrying a few times on `ETXTBSY`. The retry exists for
/// the tests' fake `pkcheck` scripts: a script just written can be briefly
/// held open for writing by another test thread's fork. The real
/// `/usr/bin/pkcheck` is never written, so production never retries.
fn spawn(cmd: &mut Command) -> std::io::Result<std::process::Child> {
    const ETXTBSY: i32 = 26;
    let mut tries = 0;
    loop {
        match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(ETXTBSY) && tries < 5 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            other => return other,
        }
    }
}

fn is_regular(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

fn root_owned_file(p: &Path) -> bool {
    is_regular(p) && saiife_system::fsops::root_owned_chain(p).is_ok()
}

/// Whether any of `candidates` is a regular file (a polkit daemon binary).
pub fn polkitd_present<P: AsRef<Path>>(candidates: &[P]) -> bool {
    candidates.iter().any(|p| is_regular(p.as_ref()))
}

/// The start time (field 22 of `/proc/<pid>/stat`) of the approving CLI,
/// for `--process <pid>,<start>,<uid>`. `None` when the process is gone.
pub fn start_time_of(proc: &dyn Proc, pid: u32) -> Option<u64> {
    proc.stat(pid).map(|s| s.start_time)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;

    /// A fake `pkcheck`: records its argv and its initial environment (from
    /// `/proc/$$/environ`, so nothing the shell adds), then exits `code`, or
    /// sleeps `sleep` seconds when that is not 0.
    #[cfg(target_os = "linux")]
    fn fake(dir: &Path, code: i32, sleep: u32) -> PathBuf {
        let script = dir.join("pkcheck");
        let out = dir.display();
        // `exec` so the timeout kill reaches the sleeper itself.
        let tail = if sleep > 0 {
            format!("exec sleep {sleep}")
        } else {
            format!("exit {code}")
        };
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$@\" > '{out}/argv'\n\
                 tr '\\000' '\\n' < /proc/$$/environ > '{out}/env'\n\
                 {tail}\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A subject without an authorization (the polkit shape).
    #[cfg(target_os = "linux")]
    fn subj(pid: u32, start: u64, uid: u32) -> Subject {
        Subject {
            pid,
            start,
            uid,
            auth: None,
        }
    }

    // polkit (Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn pkcheck_argv_exact() {
        let d = tmp();
        let pk = PkCheck::with_paths(fake(d.path(), 0, 0), d.path().join("action"));
        let r = pk.check(
            &subj(4242, 987654, 1000),
            "#7 erp invoices.create\n",
            Duration::from_secs(10),
        );
        assert_eq!(r, ReauthResult::Authorized);
        let argv = fs::read_to_string(d.path().join("argv")).unwrap();
        assert_eq!(
            argv,
            "--action-id\ncom.saiife.approve\n--process\n4242,987654,1000\n--allow-user-interaction\n--detail\nrequest\n#7 erp invoices.create \n"
        );
        let env = fs::read_to_string(d.path().join("env")).unwrap();
        assert_eq!(env, "PATH=/usr/bin:/bin\n");
    }

    // polkit (Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn pkcheck_exit_codes() {
        use ReauthResult as R;
        let d = tmp();
        let bad_options = R::Error("pkcheck: bad options".into());
        for (code, want) in [
            (1, R::Denied(String::new())),
            (3, R::Denied(String::new())),
            (2, R::Unavailable(String::new())),
            (127, R::Unavailable(String::new())),
            (126, bad_options),
        ] {
            let pk = PkCheck::with_paths(fake(d.path(), code, 0), d.path().join("action"));
            assert_eq!(
                pk.check(&subj(1, 2, 3), "x", Duration::from_secs(10)),
                want,
                "{code}"
            );
        }
        for code in [4, 5, 125, 255] {
            let pk = PkCheck::with_paths(fake(d.path(), code, 0), d.path().join("action"));
            match pk.check(&subj(1, 2, 3), "x", Duration::from_secs(10)) {
                R::Error(e) => assert!(e.contains(&format!("exit {code}")), "{code}: {e}"),
                other => panic!("{code}: expected Error, got {other:?}"),
            }
        }
        // Killed by a signal (no exit code): denied. Mapped directly, since
        // the tests never signal a process other than through `Child`.
        assert_eq!(exit_result(None, ""), R::Denied(String::new()));
    }

    /// A fake `pkcheck` that writes `stderr` there, then exits `code`.
    #[cfg(target_os = "linux")]
    fn fake_stderr(dir: &Path, code: i32, stderr: &str) -> PathBuf {
        let script = dir.join("pkcheck-err");
        fs::write(
            &script,
            format!("#!/bin/sh\nprintf '%s' '{stderr}' >&2\nexit {code}\n"),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    // polkit (Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn pkcheck_stderr_first_line_is_the_reason() {
        use ReauthResult as R;
        let d = tmp();
        let trusted = "Error checking for authorization com.saiife.approve: GDBus.Error:org.freedesktop.PolicyKit1.Error.NotAuthorized: Only trusted callers (e.g. uid 0 or an action owner) can use CheckAuthorization() for a subject belonging to another user";
        let pk = PkCheck::with_paths(
            fake_stderr(d.path(), 127, &format!("\n{trusted}\nsecond line\n")),
            d.path().join("action"),
        );
        match pk.check(&subj(1, 2, 3), "x", Duration::from_secs(10)) {
            R::Unavailable(e) => {
                assert!(e.contains("trusted callers"), "{e}");
                assert!(!e.contains("second line"), "{e}");
                assert!(e.chars().count() <= MAX_STDERR_CHARS, "{e}");
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
        let pk = PkCheck::with_paths(
            fake_stderr(d.path(), 1, "Not authorized.\u{1b}[2J"),
            d.path().join("action"),
        );
        assert_eq!(
            pk.check(&subj(1, 2, 3), "x", Duration::from_secs(10)),
            R::Denied("Not authorized.[2J".into())
        );
        let pk = PkCheck::with_paths(fake_stderr(d.path(), 126, "bad"), d.path().join("action"));
        assert_eq!(
            pk.check(&subj(1, 2, 3), "x", Duration::from_secs(10)),
            R::Error("pkcheck: bad options: bad".into())
        );
    }

    #[test]
    fn first_line_and_detail_are_cleaned_and_cut() {
        assert_eq!(first_line(b"\n  \n a\tb \nc"), "ab");
        assert_eq!(first_line(&[b'x'; 1000]).chars().count(), MAX_STDERR_CHARS);
        assert_eq!(first_line(b""), "");
        assert_eq!(clean_detail("#1 a\nb"), "#1 a b");
        assert_eq!(
            clean_detail("a\u{202E}b\u{200B}c\u{2066}d\u{FEFF}e\u{E0041}f"),
            "a b c d e f"
        );
        assert_eq!(clean_detail("p\u{2028}q\u{2029}r"), "p q r");
        assert_eq!(
            clean_detail(&"y".repeat(500)).chars().count(),
            MAX_DETAIL_CHARS
        );
    }

    #[test]
    fn cooldown_doubles_up_to_ten_minutes_and_resets() {
        let mut c = Cooldowns::default();
        let t0 = Instant::now();
        assert_eq!(c.remaining(1, t0), None);
        c.failed(1, t0);
        assert_eq!(c.remaining(1, t0), Some(Duration::from_secs(30)));
        assert_eq!(c.remaining(2, t0), None);
        let t1 = t0 + Duration::from_secs(30);
        assert_eq!(c.remaining(1, t1), None);
        c.failed(1, t1);
        assert_eq!(c.remaining(1, t1), Some(Duration::from_secs(60)));
        let mut t = t1;
        for _ in 0..10 {
            t += Duration::from_secs(3600);
            c.failed(1, t);
        }
        assert_eq!(c.remaining(1, t), Some(COOLDOWN_MAX));
        c.succeeded(1);
        assert_eq!(c.remaining(1, t), None);
        c.failed(1, t);
        assert_eq!(c.remaining(1, t), Some(COOLDOWN_FIRST));
    }

    #[test]
    fn in_flight_is_one_per_uid() {
        // A uid no other test uses: the set is process-wide.
        let a = InFlight::begin(990_001).unwrap();
        assert!(InFlight::begin(990_001).is_none());
        let b = InFlight::begin(990_002).unwrap();
        drop(a);
        let again = InFlight::begin(990_001).unwrap();
        drop((b, again));
    }

    // polkit (Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn pkcheck_timeout_is_error() {
        let d = tmp();
        let pk = PkCheck::with_paths(fake(d.path(), 0, 30), d.path().join("action"));
        let t0 = Instant::now();
        let r = pk.check(&subj(1, 2, 3), "x", Duration::from_millis(200));
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
        match r {
            ReauthResult::Error(e) => assert!(e.contains("timed out"), "{e}"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn fixture_uid_slots_are_per_test_thread() {
        let mine = InFlight::begin(1000).unwrap();
        assert!(InFlight::begin(1000).is_none());
        // Another (parallel) test using the same fixture uid is not busy.
        std::thread::Builder::new()
            .name("some-other-test".into())
            .spawn(|| assert!(InFlight::begin(1000).is_some()))
            .unwrap()
            .join()
            .unwrap();
        drop(mine);
        assert!(InFlight::begin(1000).is_some());
    }

    // polkit (Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn missing_pkcheck_is_error() {
        let d = tmp();
        let pk = PkCheck::with_paths(d.path().join("nope"), d.path().join("action"));
        assert!(matches!(
            pk.check(&subj(1, 2, 3), "x", Duration::from_secs(1)),
            ReauthResult::Error(_)
        ));
    }

    // polkit (Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn available_needs_root_owned_binary_and_action_file() {
        let d = tmp();
        let action = d.path().join("action");
        // Missing binary and action file.
        assert!(!PkCheck::with_paths(d.path().join("nope"), &action).available());
        // A binary owned by the test user is not root-owned.
        let bin = fake(d.path(), 0, 0);
        fs::write(&action, "<policyconfig/>").unwrap();
        assert!(!PkCheck::with_paths(&bin, &action).available());
        // Relative paths never pass the chain check.
        assert!(!PkCheck::with_paths("pkcheck", &action).available());

        // Root-owned stand-ins that are never executed: available() only
        // inspects the paths.
        let root_file = PathBuf::from("/etc/passwd");
        // In a user namespace (scripts/test-offline.sh) root's files show
        // the overflow uid: there is no root-owned stand-in to test with.
        {
            use std::os::unix::fs::MetadataExt;
            let owner = fs::metadata(&root_file).map(|m| m.uid()).ok();
            if owner != Some(0) {
                eprintln!(
                    "skipped the root-owned half: {} is owned by {owner:?} here, not uid 0 (a user namespace?)",
                    root_file.display()
                );
                return;
            }
        }
        let polkitd = vec![d.path().join("no-polkitd"), root_file.clone()];
        assert!(PkCheck::with_paths(&root_file, &root_file)
            .with_polkitd(polkitd.clone())
            .available());
        // The action file must be root-owned too.
        assert!(!PkCheck::with_paths(&root_file, &action)
            .with_polkitd(polkitd)
            .available());
        // No polkit daemon binary.
        assert!(!PkCheck::with_paths(&root_file, &root_file)
            .with_polkitd(vec![d.path().join("no-polkitd")])
            .available());
    }

    /// Outside Linux polkit is never used: its subject is a pid, and no
    /// approval may rest on a pid there (macOS `LOCAL_PEERPID`).
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn pkcheck_never_available_off_linux() {
        let root_file = PathBuf::from("/etc/passwd");
        assert!(!PkCheck::with_paths(&root_file, &root_file)
            .with_polkitd(vec![root_file.clone()])
            .available());
        assert!(!PkCheck::new().available());
    }

    #[test]
    fn polkitd_present_needs_a_regular_file() {
        let d = tmp();
        let f = d.path().join("polkitd");
        assert!(!polkitd_present(&[&f]));
        fs::write(&f, "").unwrap();
        assert!(polkitd_present(&[d.path().join("x"), f.clone()]));
        assert!(!polkitd_present(&[d.path()]));
    }

    #[test]
    fn start_time_from_proc() {
        use crate::sessions::RealProc;
        let d = tmp();
        let p = d.path().join("77");
        fs::create_dir(&p).unwrap();
        fs::write(
            p.join("stat"),
            format!("77 (saiife) S 1 {}31337 0 0", "0 ".repeat(17)),
        )
        .unwrap();
        let rp = RealProc::new(d.path());
        assert_eq!(start_time_of(&rp, 77), Some(31337));
        assert_eq!(start_time_of(&rp, 78), None);
    }

    // ------------------------------------------------ macOS (`security`)

    /// 32 bytes standing in for an external form.
    pub(crate) const EXT: [u8; 32] = {
        let mut b = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            b[i] = (i as u8).wrapping_mul(37).wrapping_add(1);
            i += 1;
        }
        b
    };

    fn mac_subject(pid: u32, auth: Option<[u8; 32]>) -> Subject {
        Subject {
            pid,
            start: 7,
            uid: 501,
            auth,
        }
    }

    #[test]
    fn mac_argv_exact() {
        assert_eq!(
            MacAuthorize::argv(),
            ["authorize", "-u", "-i", "-d", "com.saiife.approve"]
        );
        assert_eq!(RIGHT, "com.saiife.approve");
        assert_eq!(
            MacAuthorize::new().security,
            PathBuf::from("/usr/bin/security")
        );
    }

    #[test]
    fn yes_is_authorized() {
        let d = tmp();
        let sec = MacAuthorize::with_path(fakes::security(d.path(), "YES (0)", false, 0, 0));
        let r = sec.check(&mac_subject(4242, Some(EXT)), "#7", Duration::from_secs(10));
        assert_eq!(r, ReauthResult::Authorized);
        let argv = fs::read_to_string(d.path().join("argv")).unwrap();
        assert_eq!(argv, "authorize\n-u\n-i\n-d\ncom.saiife.approve\n");
    }

    #[test]
    fn canceled_is_denied() {
        let d = tmp();
        let sec = MacAuthorize::with_path(fakes::security(d.path(), "NO (-60006)", false, 1, 0));
        assert_eq!(
            sec.check(&mac_subject(1, Some(EXT)), "x", Duration::from_secs(10)),
            ReauthResult::Denied("NO (-60006)".into())
        );
    }

    #[test]
    fn denied_is_denied() {
        let d = tmp();
        // On stderr: either stream carries the answer.
        let sec = MacAuthorize::with_path(fakes::security(d.path(), "NO (-60005)", true, 1, 0));
        assert_eq!(
            sec.check(&mac_subject(1, Some(EXT)), "x", Duration::from_secs(10)),
            ReauthResult::Denied("NO (-60005)".into())
        );
    }

    #[test]
    fn interaction_not_allowed_is_unavailable() {
        let d = tmp();
        let sec = MacAuthorize::with_path(fakes::security(d.path(), "NO (-60007)", true, 1, 0));
        assert_eq!(
            sec.check(&mac_subject(1, Some(EXT)), "x", Duration::from_secs(10)),
            ReauthResult::Unavailable("NO (-60007)".into())
        );
    }

    #[test]
    fn other_code_is_error() {
        use ReauthResult as R;
        let d = tmp();
        for (answer, code) in [
            ("NO (-60008)", 1),
            ("NO (-2)", 1),
            ("YES (0)", 1),
            ("YES (-60005)", 0),
            ("garbage", 0),
            ("", 0),
            ("NO (x)", 1),
        ] {
            let sec = MacAuthorize::with_path(fakes::security(d.path(), answer, false, code, 0));
            match sec.check(&mac_subject(1, Some(EXT)), "x", Duration::from_secs(10)) {
                R::Error(e) => assert!(e.starts_with("security: "), "{answer}: {e}"),
                other => panic!("{answer}: expected Error, got {other:?}"),
            }
        }
        // Killed by a signal; the answer line need not be first.
        assert!(matches!(parse_answer(None, "YES (0)"), R::Error(_)));
        assert_eq!(parse_answer(Some(0), "noise\nYES (0)\n"), R::Authorized);
        assert_eq!(
            parse_answer(Some(1), "\nNO (-60006)\nYES (0)"),
            R::Denied("NO (-60006)".into())
        );
        // Anchored at the line start.
        assert!(matches!(parse_answer(Some(0), " x YES (0)"), R::Error(_)));
    }

    #[test]
    fn external_form_written_on_stdin_exactly() {
        let d = tmp();
        let sec = MacAuthorize::with_path(fakes::security(d.path(), "YES (0)", false, 0, 0));
        sec.check(&mac_subject(1, Some(EXT)), "x", Duration::from_secs(10));
        assert_eq!(fs::read(d.path().join("stdin")).unwrap(), EXT.to_vec());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn env_is_path_only() {
        let d = tmp();
        let sec = MacAuthorize::with_path(fakes::security(d.path(), "YES (0)", false, 0, 0));
        sec.check(&mac_subject(1, Some(EXT)), "x", Duration::from_secs(10));
        let env = fs::read_to_string(d.path().join("env")).unwrap();
        assert_eq!(env, "PATH=/usr/bin:/bin\n");
    }

    #[test]
    fn hung_security_is_killed_at_timeout() {
        let d = tmp();
        let sec = MacAuthorize::with_path(fakes::security(d.path(), "", false, 0, 30));
        let t0 = Instant::now();
        let r = sec.check(&mac_subject(1, Some(EXT)), "x", Duration::from_millis(200));
        assert!(t0.elapsed() < Duration::from_secs(10), "{:?}", t0.elapsed());
        match r {
            ReauthResult::Error(e) => assert!(e.contains("timed out"), "{e}"),
            other => panic!("expected Error, got {other:?}"),
        }
        // Reaped: our child's pid has no /proc entry, not even a zombie.
        #[cfg(target_os = "linux")]
        {
            let pid = fs::read_to_string(d.path().join("pid")).unwrap();
            let pid = pid.trim();
            assert!(!pid.is_empty());
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "{pid} not reaped"
            );
        }
    }

    #[test]
    fn missing_auth_is_unavailable_without_running_security() {
        let d = tmp();
        let sec = MacAuthorize::with_path(fakes::security(d.path(), "YES (0)", false, 0, 0));
        assert_eq!(
            sec.check(&mac_subject(1, None), "x", Duration::from_secs(10)),
            ReauthResult::Unavailable(NO_AUTH.into())
        );
        assert!(!d.path().join("argv").exists());
    }

    /// macOS `LOCAL_PEERPID` is the socket's last pid: the check must not
    /// depend on it. Any pid (none, ours, a foreign one) gives the same
    /// answer and the same argv and stdin.
    #[test]
    fn foreign_pid_does_not_change_the_outcome() {
        for answer in ["YES (0)", "NO (-60006)"] {
            let mut seen = Vec::new();
            for pid in [0, 1, std::process::id(), 99_999, u32::MAX] {
                let d = tmp();
                let code = if answer.starts_with("YES") { 0 } else { 1 };
                let sec =
                    MacAuthorize::with_path(fakes::security(d.path(), answer, false, code, 0));
                let mut who = mac_subject(pid, Some(EXT));
                who.start = u64::from(pid) * 3;
                let r = sec.check(&who, "x", Duration::from_secs(10));
                let argv = fs::read_to_string(d.path().join("argv")).unwrap();
                let stdin = fs::read(d.path().join("stdin")).unwrap();
                seen.push((r, argv, stdin));
            }
            assert!(seen.windows(2).all(|w| w[0] == w[1]), "{answer}: {seen:?}");
        }
    }

    #[test]
    fn auth_hex_is_exactly_64_lowercase() {
        let hex: String = EXT.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_auth_hex(&hex), Ok(EXT));
        assert_eq!(parse_auth_hex(&"0".repeat(64)), Ok([0; 32]));
        for bad in [
            String::new(),
            "0".repeat(63),
            "0".repeat(65),
            hex.to_uppercase(),
            format!("{}g", &hex[..63]),
            format!(" {}", &hex[1..]),
            format!("{}é", &hex[..62]),
        ] {
            assert!(parse_auth_hex(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn right_read_needs_the_full_dictionary() {
        let d = tmp();
        let full = "<plist><dict>\n<key>class</key><string>user</string>\n\
            <key>session-owner</key>\n\t<true/>\n<key>shared</key> <false/>\n\
            <key>timeout</key><integer>0</integer></dict></plist>";
        let sec = MacAuthorize::with_path(fakes::security(d.path(), full, false, 0, 0));
        assert!(sec.right_registered());
        assert_eq!(
            fs::read_to_string(d.path().join("argv")).unwrap(),
            "authorizationdb\nread\ncom.saiife.approve\n"
        );
        // A right that is shared, or remembered, or missing.
        for (out, code) in [
            (full.replace("<false/>", "<true/>"), 0),
            (
                full.replace("<integer>0</integer>", "<integer>300</integer>"),
                0,
            ),
            (full.replace("session-owner", "x"), 0),
            (full.to_string(), 1),
            (String::new(), 0),
        ] {
            let sec = MacAuthorize::with_path(fakes::security(d.path(), &out, false, code, 0));
            assert!(!sec.right_registered(), "{code} {out}");
        }
    }

    #[test]
    fn mac_available_needs_root_owned_security() {
        let d = tmp();
        let full = "<key>session-owner</key><true/><key>shared</key><false/>\
            <key>timeout</key><integer>0</integer>";
        // Registered, but the binary is the test user's.
        let sec = MacAuthorize::with_path(fakes::security(d.path(), full, false, 0, 0));
        assert!(sec.right_registered());
        assert!(!sec.available());
        assert!(!MacAuthorize::with_path(d.path().join("nope")).available());
        assert!(!MacAuthorize::with_path("security").available());
    }

    /// The security fix: on macOS the prompt cannot show the request, so
    /// same-user re-authentication is off and never prompts.
    #[test]
    fn macos_same_user_reauth_is_off() {
        let off = PromptWithoutDetail;
        assert!(!off.available());
        assert_eq!(
            off.check(&mac_subject(1, Some(EXT)), "#7 x", Duration::from_secs(1)),
            ReauthResult::Unavailable(MAC_NO_DETAIL.into())
        );
        #[cfg(target_os = "macos")]
        assert!(!host_reauth().available());
    }

    /// An external form decides one check: the same form again is an
    /// error, and `security` is not run for it.
    #[test]
    fn reused_external_form_is_refused() {
        let d = tmp();
        let sec = MacAuthorize::with_path(fakes::security(d.path(), "YES (0)", false, 0, 0));
        let who = mac_subject(1, Some(EXT));
        assert_eq!(
            sec.check(&who, "x", Duration::from_secs(10)),
            ReauthResult::Authorized
        );
        fs::remove_file(d.path().join("argv")).unwrap();
        // A clone (another connection's view) shares the record.
        match sec.clone().check(&who, "x", Duration::from_secs(10)) {
            ReauthResult::Error(e) => assert!(e.contains("already used"), "{e}"),
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(!d.path().join("argv").exists());
        // Another form is fine.
        let mut other = who;
        other.auth = Some([0xee; 32]);
        assert_eq!(
            sec.check(&other, "x", Duration::from_secs(10)),
            ReauthResult::Authorized
        );
    }

    /// polkit ignores `auth`: the same argv with or without it.
    #[cfg(target_os = "linux")]
    #[test]
    fn pkcheck_unchanged_with_subject() {
        let d = tmp();
        let pk = PkCheck::with_paths(fake(d.path(), 0, 0), d.path().join("action"));
        let mut who = subj(4242, 987654, 1000);
        assert_eq!(
            pk.check(&who, "#7", Duration::from_secs(10)),
            ReauthResult::Authorized
        );
        let without = fs::read_to_string(d.path().join("argv")).unwrap();
        who.auth = Some(EXT);
        assert_eq!(
            pk.check(&who, "#7", Duration::from_secs(10)),
            ReauthResult::Authorized
        );
        assert_eq!(fs::read_to_string(d.path().join("argv")).unwrap(), without);
        assert!(without.contains("4242,987654,1000"));
    }
}

/// Fake re-authentication tools for tests (shell scripts in a tempdir).
#[cfg(test)]
pub(crate) mod fakes {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fake `security` in `dir`: records its argv, its pid, its stdin and
    /// (Linux) its initial environment there, then prints `answer` (to
    /// stderr when `to_stderr`) and exits `code`, or sleeps `sleep` seconds
    /// when that is not 0. Each call writes a new script.
    pub(crate) fn security(
        dir: &Path,
        answer: &str,
        to_stderr: bool,
        code: i32,
        sleep: u32,
    ) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let script = dir.join(format!("security-{}", N.fetch_add(1, Ordering::SeqCst)));
        let out = dir.display();
        let answer_file = PathBuf::from(format!("{}.answer", script.display()));
        fs::write(&answer_file, answer).unwrap();
        let redirect = if to_stderr { " >&2" } else { "" };
        // `exec` so the timeout kill reaches the sleeper itself.
        let tail = if sleep > 0 {
            format!("exec sleep {sleep}")
        } else {
            format!("cat '{}'{redirect}\nexit {code}", answer_file.display())
        };
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$@\" > '{out}/argv'\n\
                 echo $$ > '{out}/pid'\n\
                 if [ -r /proc/$$/environ ]; then tr '\\000' '\\n' < /proc/$$/environ > '{out}/env'; fi\n\
                 cat > '{out}/stdin'\n\
                 {tail}\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }
}
