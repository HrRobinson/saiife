//! Approval requests (spec §6.10.1, §8.10): one `<id>.json` per request,
//! 0600 in `<state>/approvals/` (0700, checked like the vault dir), with
//! the id counter in `next_id` (fsynced) and a result in `<id>.result`.
//! The exact request to send (`request_sealed`) and the result are sealed
//! with the vault key ([`crate::vault::Shared::seal`]), bound to the id by
//! [`aad`] / [`result_aad`]; the display copy is masked by the caller.
//! Every change happens under one mutex and re-reads the file, so two
//! deciders never both win. The calls do blocking disk IO: call them off
//! the runtime thread.
//!
//! Ids never repeat: a new id is above both `next_id` and every request
//! file, and an unreadable `next_id` is an error, not a restart. They can
//! repeat only if `next_id` is deleted by the daemon user (or root) after
//! the requests it counted have been swept.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::vault::{check_dir, open_regular, VaultError};

/// The AAD prefix of a sealed request.
pub const AAD_PREFIX: &[u8; 9] = b"SAIIFEAP1";
/// The AAD prefix of a sealed result (a result never opens as a request).
pub const RESULT_AAD_PREFIX: &[u8; 9] = b"SAIIFEAR1";
/// How long a result is kept.
pub const RESULT_KEEP: Duration = Duration::from_secs(24 * 3600);
/// How long a decided request is kept after it expires.
pub const REQUEST_KEEP: Duration = Duration::from_secs(7 * 24 * 3600);
/// How often the daemon sweeps (and once at start).
pub const SWEEP_EVERY: Duration = Duration::from_secs(30);
/// The longest note, in bytes.
pub const NOTE_MAX: usize = 1024;
/// A request or result file larger than this is not read.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const NEXT_ID: &str = "next_id";

/// `SAIIFEAP1 || id (u64 BE)`: the AAD of request `id`'s sealed request.
pub fn aad(id: u64) -> Vec<u8> {
    bound(AAD_PREFIX, id)
}

/// `SAIIFEAR1 || id (u64 BE)`: the AAD of request `id`'s sealed result.
pub fn result_aad(id: u64) -> Vec<u8> {
    bound(RESULT_AAD_PREFIX, id)
}

fn bound(prefix: &[u8; 9], id: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(17);
    a.extend_from_slice(prefix);
    a.extend_from_slice(&id.to_be_bytes());
    a
}

/// The store below the daemon's state dir.
pub fn dir_in(state_dir: &Path) -> PathBuf {
    state_dir.join("approvals")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalType {
    Connector,
    Command,
    /// A `tools/call` of an MCP gateway server (plan 17, spec §8.10):
    /// `service` is `mcp:<server>`, `operation` the tool, `body_display`
    /// the masked arguments.
    Mcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Approved,
    Rejected,
    Expired,
    Sent,
    SendFailed,
}

/// The only moves [`Store::transition`] makes.
fn allowed(from: State, to: State) -> bool {
    matches!(
        (from, to),
        (
            State::Pending,
            State::Approved | State::Rejected | State::Expired
        ) | (State::Approved, State::Sent | State::SendFailed)
    )
}

/// The `result_ref` of a request whose result could not be kept.
pub const RESULT_UNAVAILABLE: &str = "unavailable";

/// One request file (§8.10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub created: String,
    pub expires: String,
    pub uid: u32,
    pub user: String,
    pub session: Option<String>,
    pub agent: String,
    pub project: String,
    #[serde(rename = "type")]
    pub kind: ApprovalType,
    pub service: Option<String>,
    pub operation: Option<String>,
    pub capability: Option<String>,
    /// Masked, for display.
    pub params: BTreeMap<String, String>,
    /// The masked command (command requests).
    pub input: Option<String>,
    pub grant_key: Option<String>,
    /// The project a command grant covers (its canonical root), shown to
    /// approvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The `[guard] ask` rule (`pack/rule_id`) that denied a command
    /// request's command: what notifications and the polkit prompt name,
    /// never the command itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_rule: Option<String>,
    /// What will be sent, for the approver (connector requests): the
    /// masked body cut at 4 KiB, the SHA-256 of the exact body bytes, the
    /// amount and the masked agent headers.
    #[serde(default)]
    pub body_display: Option<String>,
    #[serde(default)]
    pub body_sha256: Option<String>,
    /// The masked body was over 1 MiB and `body_display` is cut: approving
    /// needs `ack_truncated`.
    #[serde(default)]
    pub body_truncated: bool,
    #[serde(default)]
    pub amount: Option<Amount>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// The environment a connector request was asked under (its
    /// snapshot's), shown to approvers; absent for the base config, a
    /// command request, or a request stored before environments existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// The connector request was asked under the base config (no
    /// environment), as recorded at the ask: shown as `env base`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub env_base: bool,
    /// Masking changed nothing the approver is shown of this request (its
    /// operation, params, headers, body and project): the display is the
    /// request itself. Only such requests are ever deduped (decision 8).
    /// Absent (false) in a request stored before it existed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub display_faithful: bool,
    /// Base64 of the sealed exact request.
    pub request_sealed: Option<String>,
    pub state: State,
    pub decided_by: Option<u32>,
    pub note: Option<String>,
    pub result_ref: Option<String>,
}

/// What the caller supplies for a new request; the store adds the id,
/// times, sealed request and state.
#[derive(Debug, Clone, PartialEq)]
pub struct NewRequest {
    pub uid: u32,
    pub user: String,
    pub session: Option<String>,
    pub agent: String,
    pub project: String,
    pub kind: ApprovalType,
    pub service: Option<String>,
    pub operation: Option<String>,
    pub capability: Option<String>,
    /// The display copy: only a [`saiife_broker::mask::Masker`] (or
    /// `Default`, empty) makes one, so raw parameters cannot be stored.
    pub params: saiife_broker::mask::Masked<BTreeMap<String, String>>,
    pub input: Option<String>,
    pub grant_key: Option<String>,
    /// [`Request::scope`].
    pub scope: Option<String>,
    /// [`Request::ask_rule`].
    pub ask_rule: Option<String>,
    /// The send's display fields ([`Request::body_display`] ...); empty
    /// (`Default`) for a command request.
    pub send: SendDisplay,
}

/// The amount of an operation that moves money.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amount {
    pub minor: u64,
    pub currency: String,
}

/// [`Store::create_capped`]: the requester has too many pending requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingFull;

impl std::fmt::Display for PendingFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("too many pending approval requests for this uid")
    }
}

impl std::error::Error for PendingFull {}

/// What a connector request will send, as the approver sees it (masked).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SendDisplay {
    pub body_display: Option<String>,
    pub body_sha256: Option<String>,
    pub body_truncated: bool,
    pub amount: Option<Amount>,
    pub headers: Vec<(String, String)>,
    /// [`Request::env`].
    pub env: Option<String>,
    /// [`Request::env_base`].
    pub env_base: bool,
    /// [`Request::display_faithful`]: set by the caller only when every
    /// masked display field equals its raw value.
    pub faithful: bool,
}

/// Which requests [`Store::list`] returns: `None`/empty means any.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub uid: Option<u32>,
    pub states: Vec<State>,
}

#[derive(Debug)]
pub enum StoreError {
    /// No such request.
    Unknown,
    /// The request is in `state`, not one of those asked for, or the move
    /// is not an allowed edge. `newly_expired` is the request when this
    /// call found it past `expires` and expired it: the caller records it.
    WrongState {
        state: State,
        newly_expired: Option<Box<Request>>,
    },
    /// The note is longer than [`NOTE_MAX`] or holds a control or format
    /// character.
    BadNote(&'static str),
    Io(io::Error),
}

impl StoreError {
    /// The state of a `WrongState`.
    pub fn wrong_state(&self) -> Option<State> {
        match self {
            StoreError::WrongState { state, .. } => Some(*state),
            _ => None,
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Unknown => f.write_str("no such approval request"),
            StoreError::WrongState { state, .. } => {
                write!(f, "the request is {}", state_name(*state))
            }
            StoreError::BadNote(why) => f.write_str(why),
            StoreError::Io(e) => write!(f, "the approval store: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// The snake_case name of a state, as in the file.
pub fn state_name(s: State) -> &'static str {
    match s {
        State::Pending => "pending",
        State::Approved => "approved",
        State::Rejected => "rejected",
        State::Expired => "expired",
        State::Sent => "sent",
        State::SendFailed => "send_failed",
    }
}

/// Unicode format (Cf) characters, and the line and paragraph separators:
/// invisible or reordering text that could disguise a note.
fn is_format(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

/// Refuse a note over [`NOTE_MAX`] bytes or with a control or format
/// character.
pub fn check_note(note: &str) -> Result<(), StoreError> {
    if note.len() > NOTE_MAX {
        return Err(StoreError::BadNote("the note is longer than 1 KiB"));
    }
    if note.chars().any(|c| c.is_control() || is_format(c)) {
        return Err(StoreError::BadNote(
            "the note holds a control or format character",
        ));
    }
    Ok(())
}

/// UTC in the record format, `YYYY-MM-DDTHH:MM:SS.mmmZ`. Fixed width, so
/// two of these compare as strings in time order.
pub fn ts(t: SystemTime) -> String {
    const F: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    time::OffsetDateTime::from_unix_timestamp_nanos(d.as_nanos() as i128)
        .ok()
        .and_then(|o| o.format(F).ok())
        .unwrap_or_else(|| "0000-00-00T00:00:00.000Z".into())
}

/// The masked one-line summary of a request for its records:
/// `service operation`, or the masked command.
pub fn summary(r: &Request) -> String {
    match r.kind {
        // `mcp:<name> <tool>` for an MCP request.
        ApprovalType::Connector | ApprovalType::Mcp => format!(
            "{} {}",
            r.service.as_deref().unwrap_or(""),
            r.operation.as_deref().unwrap_or("")
        )
        .trim()
        .to_string(),
        ApprovalType::Command => r.input.clone().unwrap_or_default(),
    }
}

/// What may leave the host about `r` (a notification): the service and
/// operation of a connector request, and its environment when it has one; for a command only
/// `command request (<pack>/<rule_id>)`, never the command text.
pub fn offhost_summary(r: &Request) -> String {
    match r.kind {
        ApprovalType::Connector | ApprovalType::Mcp => match &r.env {
            Some(e) => format!("{} (env {e})", summary(r)),
            None if r.env_base => format!("{} (env base)", summary(r)),
            None => summary(r),
        },
        ApprovalType::Command => format!(
            "command request ({})",
            r.ask_rule.as_deref().unwrap_or("unknown rule")
        ),
    }
}

/// The polkit `--detail request` of a decision on `r`:
/// `#<id> <service> <operation>` or `#<id> <pack>/<rule_id>`.
pub fn reauth_detail(r: &Request) -> String {
    let what = match r.kind {
        ApprovalType::Connector | ApprovalType::Mcp => summary(r),
        ApprovalType::Command => r.ask_rule.clone().unwrap_or_else(|| "command".into()),
    };
    format!("#{} {what}", r.id)
}

/// Fill an `approval` record for `r`: `base` is the daemon's record of
/// kind `approval` with the masked [`summary`] as input; this adds the
/// requester (`uid`, `user`, agent, project, session), `action`, `id`,
/// `approval`, and `by_uid`/`note` when decided.
pub fn record_for(
    mut base: saiife_audit::Record,
    r: &Request,
    action: &str,
) -> saiife_audit::Record {
    use saiife_audit::DecisionKind;
    base.kind = Some("approval".into());
    base.uid = Some(r.uid);
    base.user = Some(r.user.clone());
    base.agent = r.agent.clone();
    base.project = r.project.clone();
    base.session = r.session.clone();
    base.decision = match action {
        "expired" => DecisionKind::Expired,
        "approved" => DecisionKind::Approved,
        "rejected" | "refused" => DecisionKind::Rejected,
        "created" => DecisionKind::Ask,
        _ => base.decision,
    };
    base.extra.insert("action".into(), action.into());
    base.extra.insert("id".into(), r.id.into());
    base.extra.insert("approval".into(), r.id.into());
    let kind = match r.kind {
        ApprovalType::Connector => "connector",
        ApprovalType::Command => "command",
        ApprovalType::Mcp => "mcp",
    };
    base.extra.insert("type".into(), kind.into());
    if let Some(s) = &r.service {
        base.extra.insert("service".into(), s.clone().into());
    }
    if let Some(o) = &r.operation {
        base.extra.insert("operation".into(), o.clone().into());
    }
    if let Some(b) = r.decided_by {
        base.extra.insert("by_uid".into(), b.into());
    }
    if let Some(n) = &r.note {
        base.extra.insert("note".into(), n.clone().into());
    }
    base
}

/// Whether pending request `r` is the one `new` would create (decision 8):
/// a command by its `grant_key`; a connector or MCP request by everything
/// its approver is shown (service, operation, capability, params, body
/// display and SHA-256, amount, headers, environment, project and
/// session), and only when both displays are faithful (masking changed
/// none of them): two equal displays are then two equal requests. A
/// display that masking changed may hide a difference (two different
/// vault values both shown as `[MASKED]`), so such a request is never
/// deduped.
fn same_request(r: &Request, new: &NewRequest) -> bool {
    if r.kind != new.kind || r.uid != new.uid {
        return false;
    }
    match new.kind {
        ApprovalType::Command => new.grant_key.is_some() && r.grant_key == new.grant_key,
        ApprovalType::Connector | ApprovalType::Mcp => {
            r.display_faithful
                && new.send.faithful
                && r.service == new.service
                && r.operation == new.operation
                && r.capability == new.capability
                && &r.params == new.params.get()
                && r.body_display == new.send.body_display
                && r.body_sha256 == new.send.body_sha256
                && r.body_truncated == new.send.body_truncated
                && r.amount == new.send.amount
                && r.headers == new.send.headers
                && r.env == new.send.env
                && r.env_base == new.send.env_base
                && r.project == new.project
                && r.session == new.session
        }
    }
}

/// The magic of a result file: `SAIIFER2 || stored (24-byte timestamp) ||
/// sealed bytes`, raw (no base64).
const RESULT_MAGIC: &[u8; 8] = b"SAIIFER2";
/// The width of [`ts`].
const TS_LEN: usize = 24;

struct ResultFile {
    stored: String,
    sealed: Vec<u8>,
}

/// Where an atomic write failed: before the rename the old file is
/// intact; after it the new file is in place but the dir fsync failed.
enum WriteErr {
    Before(io::Error),
    After(io::Error),
}

impl WriteErr {
    fn into_io(self) -> io::Error {
        match self {
            WriteErr::Before(e) | WriteErr::After(e) => e,
        }
    }
}

type DirSync = Box<dyn Fn(&Path) -> io::Result<()> + Send + Sync>;

pub struct Store {
    dir: PathBuf,
    /// Held by every change, across its disk IO.
    lock: Mutex<()>,
    /// The fsync of the dir after a rename (a seam for tests).
    dir_sync: DirSync,
    /// Files the sweep warned about, so it warns once per start.
    warned: Mutex<HashSet<String>>,
    /// The largest sealed result kept, in bytes (smaller in tests).
    result_cap: usize,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("dir", &self.dir).finish()
    }
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// `<id>.<ext>` -> the id, for canonical names only (`1.json`, never
/// `01.json` or `0.json`).
fn id_of(name: &str, ext: &str) -> Option<u64> {
    let stem = name.strip_suffix(ext)?.strip_suffix('.')?;
    if stem.is_empty() || stem.starts_with('0') || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    stem.parse().ok()
}

fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    let f = open_regular(path)?;
    let mut buf = Vec::new();
    f.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(buf)
}

fn real_dir_sync(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

impl Store {
    /// Open (and create) the store dir: a real dir owned by the euid, 0700.
    /// Temp files a crash left behind are removed.
    pub fn open(dir: &Path) -> io::Result<Store> {
        check_dir(dir, true)?;
        for e in std::fs::read_dir(dir)?.flatten() {
            let n = e.file_name();
            let n = n.to_string_lossy();
            if n.starts_with('.') && n.ends_with(".tmp") {
                let _ = std::fs::remove_file(e.path());
            }
        }
        Ok(Store {
            dir: dir.to_path_buf(),
            lock: Mutex::new(()),
            dir_sync: Box::new(real_dir_sync),
            warned: Mutex::new(HashSet::new()),
            result_cap: MAX_FILE_BYTES as usize - RESULT_MAGIC.len() - TS_LEN,
        })
    }

    /// This store with a smaller result cap (a seam for tests).
    pub fn with_result_cap(mut self, cap: usize) -> Store {
        self.result_cap = cap.min(self.result_cap);
        self
    }

    /// The largest sealed result [`Store::put_result`] keeps, in bytes.
    pub fn result_cap(&self) -> usize {
        self.result_cap
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn json_path(&self, id: u64) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn result_path(&self, id: u64) -> PathBuf {
        self.dir.join(format!("{id}.result"))
    }

    /// Temp file (0600, no symlink), fsync, rename, fsync the dir.
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), WriteErr> {
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let _ = std::fs::remove_file(&tmp);
        let staged = (|| {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, self.dir.join(name))
        })();
        if let Err(e) = staged {
            let _ = std::fs::remove_file(&tmp);
            return Err(WriteErr::Before(e));
        }
        (self.dir_sync)(&self.dir).map_err(WriteErr::After)
    }

    fn write_request(&self, r: &Request) -> Result<(), WriteErr> {
        let bytes = serde_json::to_vec(r).map_err(|e| WriteErr::Before(io::Error::other(e)))?;
        self.write_atomic(&format!("{}.json", r.id), &bytes)
    }

    /// Write a changed request; a failed dir fsync after the rename counts
    /// as committed (the file is in place), with one stderr line.
    fn commit_request(&self, r: &Request) -> io::Result<()> {
        match self.write_request(r) {
            Ok(()) => Ok(()),
            Err(WriteErr::After(e)) => {
                eprintln!(
                    "saiife: warning: approval #{} written but the directory sync failed: {e}",
                    r.id
                );
                Ok(())
            }
            Err(WriteErr::Before(e)) => Err(e),
        }
    }

    /// The file of request `id`, or `NotFound`; a file whose id differs
    /// from its name is `InvalidData`.
    fn read(&self, id: u64) -> io::Result<Request> {
        let bytes = read_capped(&self.json_path(id))?;
        let r: Request = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if r.id != id {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "id mismatch"));
        }
        Ok(r)
    }

    fn ids(&self, ext: &str) -> Vec<u64> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut ids: Vec<u64> = rd
            .flatten()
            .filter_map(|e| id_of(&e.file_name().to_string_lossy(), ext))
            .collect();
        ids.sort_unstable();
        ids
    }

    /// The next id: `next_id`, and never at or below a request on disk. A
    /// missing counter starts after the highest file (or at 1); an
    /// unreadable one is an error (ids must never repeat).
    fn next_id(&self) -> io::Result<u64> {
        let after_files = self.ids("json").last().map_or(1, |m| m + 1);
        match read_capped(&self.dir.join(NEXT_ID)) {
            Ok(b) => {
                let n: u64 = std::str::from_utf8(&b)
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .filter(|n| *n >= 1)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "next_id is unreadable")
                    })?;
                Ok(n.max(after_files))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(after_files),
            Err(e) => Err(e),
        }
    }

    /// Store a new pending request. `seal` gets the new id and returns the
    /// sealed exact request (bound to that id with [`aad`]), or `None` for
    /// a command request; a seal failure stores nothing and uses no id.
    /// The counter is fsynced before the request file is written; any
    /// failure writing the request removes `<id>.json` again, so an error
    /// never leaves a pending request behind that could be approved.
    pub fn create(
        &self,
        req: NewRequest,
        seal: impl FnOnce(u64) -> Result<Option<Vec<u8>>, VaultError>,
        ttl: Duration,
        now: SystemTime,
    ) -> io::Result<Request> {
        self.create_capped(req, seal, ttl, now, None)
    }

    /// [`Store::create`], refused with a [`PendingFull`] error when the
    /// requester already has `max_pending` pending requests (counted under
    /// the store's lock, so concurrent creates cannot pass the cap).
    pub fn create_capped(
        &self,
        req: NewRequest,
        seal: impl FnOnce(u64) -> Result<Option<Vec<u8>>, VaultError>,
        ttl: Duration,
        now: SystemTime,
        max_pending: Option<usize>,
    ) -> io::Result<Request> {
        // Commands only, as before decision 8: a store-level create of a
        // connector request always makes a new one.
        let dedupe = req.kind == ApprovalType::Command;
        self.create_in(req, seal, ttl, now, max_pending, dedupe)
            .map(|(r, _)| r)
    }

    /// [`Store::create_capped`], except that a request identical to one of
    /// the requester's pending (unexpired) requests gives that request back
    /// (`false`: nothing was created), under the store's lock, before the
    /// cap is counted. Identical is [`same_request`]: for a command its
    /// `grant_key`; for a connector or MCP request what the approver is
    /// shown of it (plan 17 decision 8), so an agent retrying a call that
    /// waits gets the same id each time.
    pub fn create_dedup(
        &self,
        req: NewRequest,
        seal: impl FnOnce(u64) -> Result<Option<Vec<u8>>, VaultError>,
        ttl: Duration,
        now: SystemTime,
        max_pending: Option<usize>,
    ) -> io::Result<(Request, bool)> {
        self.create_in(req, seal, ttl, now, max_pending, true)
    }

    fn create_in(
        &self,
        req: NewRequest,
        seal: impl FnOnce(u64) -> Result<Option<Vec<u8>>, VaultError>,
        ttl: Duration,
        now: SystemTime,
        max_pending: Option<usize>,
        dedupe: bool,
    ) -> io::Result<(Request, bool)> {
        let _g = self.guard();
        if dedupe {
            let now_s = ts(now);
            let same = self
                .list(Filter {
                    uid: Some(req.uid),
                    states: vec![State::Pending],
                })
                .into_iter()
                .find(|r| r.expires > now_s && same_request(r, &req));
            if let Some(r) = same {
                return Ok((r, false));
            }
        }
        if let Some(max) = max_pending {
            let now_s = ts(now);
            let pending = self
                .list(Filter {
                    uid: Some(req.uid),
                    states: vec![State::Pending],
                })
                .iter()
                .filter(|r| r.expires > now_s)
                .count();
            if pending >= max {
                return Err(io::Error::other(PendingFull));
            }
        }
        let id = self.next_id()?;
        let sealed = seal(id).map_err(io::Error::other)?;
        let next = id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("approval ids exhausted"))?;
        self.write_atomic(NEXT_ID, format!("{next}\n").as_bytes())
            .map_err(WriteErr::into_io)?;
        let r = Request {
            id,
            created: ts(now),
            expires: ts(now + ttl),
            uid: req.uid,
            user: req.user,
            session: req.session,
            agent: req.agent,
            project: req.project,
            kind: req.kind,
            service: req.service,
            operation: req.operation,
            capability: req.capability,
            params: req.params.into_inner(),
            input: req.input,
            grant_key: req.grant_key,
            scope: req.scope,
            ask_rule: req.ask_rule,
            body_display: req.send.body_display,
            body_sha256: req.send.body_sha256,
            body_truncated: req.send.body_truncated,
            amount: req.send.amount,
            headers: req.send.headers,
            env: req.send.env,
            env_base: req.send.env_base,
            display_faithful: req.send.faithful,
            request_sealed: sealed.map(|s| b64().encode(s)),
            state: State::Pending,
            decided_by: None,
            note: None,
            result_ref: None,
        };
        if let Err(e) = self.write_request(&r) {
            let _ = std::fs::remove_file(self.json_path(id));
            return Err(e.into_io());
        }
        Ok((r, true))
    }

    /// Request `id`, or `None` when there is none or it cannot be read.
    pub fn get(&self, id: u64) -> Option<Request> {
        self.read(id).ok()
    }

    /// The sealed exact request of `id`, decoded.
    pub fn sealed_request(&self, id: u64) -> Option<Vec<u8>> {
        let r = self.get(id)?;
        b64().decode(r.request_sealed?).ok()
    }

    /// The requests that match, by id. Unreadable files are skipped.
    pub fn list(&self, filter: Filter) -> Vec<Request> {
        self.ids("json")
            .into_iter()
            .filter_map(|id| self.get(id))
            .filter(|r| filter.uid.is_none_or(|u| r.uid == u))
            .filter(|r| filter.states.is_empty() || filter.states.contains(&r.state))
            .collect()
    }

    /// Move `id` from one of `from` to `to`, re-read from disk under the
    /// store's lock: of two racing deciders exactly one wins. Only the
    /// edges Pending -> Approved | Rejected | Expired and Approved -> Sent
    /// | SendFailed are made. A pending request past `expires` at `now` is
    /// expired here instead (`WrongState(Expired)` with `newly_expired`).
    /// `by` and `note` are set when given and kept otherwise.
    pub fn transition(
        &self,
        id: u64,
        from: &[State],
        to: State,
        by: Option<u32>,
        note: Option<String>,
        now: SystemTime,
    ) -> Result<Request, StoreError> {
        if let Some(n) = &note {
            check_note(n)?;
        }
        let _g = self.guard();
        let mut r = match self.read(id) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StoreError::Unknown),
            Err(e) => return Err(StoreError::Io(e)),
        };
        if r.state == State::Pending && to != State::Expired && r.expires <= ts(now) {
            r.state = State::Expired;
            self.commit_request(&r).map_err(StoreError::Io)?;
            return Err(StoreError::WrongState {
                state: State::Expired,
                newly_expired: Some(Box::new(r)),
            });
        }
        if !from.contains(&r.state) || !allowed(r.state, to) {
            return Err(StoreError::WrongState {
                state: r.state,
                newly_expired: None,
            });
        }
        r.state = to;
        if by.is_some() {
            r.decided_by = by;
        }
        if note.is_some() {
            r.note = note;
        }
        self.commit_request(&r).map_err(StoreError::Io)?;
        Ok(r)
    }

    /// Keep the sealed (masked) result of `id` as `<id>.result` and point
    /// the request's `result_ref` at it.
    /// A result over [`Store::result_cap`] is refused (`InvalidInput`):
    /// the caller stores a small one instead.
    pub fn put_result(&self, id: u64, sealed: Vec<u8>, now: SystemTime) -> io::Result<()> {
        if sealed.len() > self.result_cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the result ({} bytes) is over the cap of {} bytes",
                    sealed.len(),
                    self.result_cap
                ),
            ));
        }
        let _g = self.guard();
        let mut r = self.read(id)?;
        let name = format!("{id}.result");
        let stored = ts(now);
        let mut bytes = Vec::with_capacity(RESULT_MAGIC.len() + TS_LEN + sealed.len());
        bytes.extend_from_slice(RESULT_MAGIC);
        bytes.extend_from_slice(stored.as_bytes());
        bytes.extend_from_slice(&sealed);
        self.write_atomic(&name, &bytes)
            .map_err(WriteErr::into_io)?;
        r.result_ref = Some(name);
        self.commit_request(&r)
    }

    /// Note that the result of `id` could not be kept (it could not be
    /// sealed or written): its `result_ref` becomes
    /// [`RESULT_UNAVAILABLE`], so the requester is told `result_unavailable`
    /// rather than that it was kept and is gone.
    pub fn mark_result_unavailable(&self, id: u64) -> io::Result<()> {
        let _g = self.guard();
        let mut r = self.read(id)?;
        r.result_ref = Some(RESULT_UNAVAILABLE.to_string());
        self.commit_request(&r)
    }

    fn read_result(&self, id: u64) -> io::Result<ResultFile> {
        let bytes = read_capped(&self.result_path(id))?;
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "not a result file");
        let rest = bytes
            .strip_prefix(RESULT_MAGIC.as_slice())
            .ok_or_else(bad)?;
        if rest.len() < TS_LEN {
            return Err(bad());
        }
        let (stored, sealed) = rest.split_at(TS_LEN);
        Ok(ResultFile {
            stored: std::str::from_utf8(stored).map_err(|_| bad())?.to_string(),
            sealed: sealed.to_vec(),
        })
    }

    /// The sealed result of `id`, while it is kept.
    pub fn get_result(&self, id: u64) -> Option<Vec<u8>> {
        Some(self.read_result(id).ok()?.sealed)
    }

    /// One stderr line per file per start.
    fn warn_once(&self, name: String, e: &io::Error) {
        let mut w = self.warned.lock().unwrap_or_else(|p| p.into_inner());
        if w.insert(name.clone()) {
            eprintln!("saiife: warning: approval file {name} cannot be read: {e}");
        }
    }

    /// Expire pending requests past `expires` (returned, for their records),
    /// drop results kept longer than [`RESULT_KEEP`] (and results without a
    /// request), and delete decided requests [`REQUEST_KEEP`] after they
    /// expired. Corrupt or oversize request files are left in place and
    /// warned about once.
    pub fn sweep(&self, now: SystemTime) -> Vec<Request> {
        let _g = self.guard();
        let now_s = ts(now);
        let old_req = ts(now.checked_sub(REQUEST_KEEP).unwrap_or(UNIX_EPOCH));
        let old_res = ts(now.checked_sub(RESULT_KEEP).unwrap_or(UNIX_EPOCH));
        let mut expired = Vec::new();
        for id in self.ids("json") {
            let mut r = match self.read(id) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => {
                    self.warn_once(format!("{id}.json"), &e);
                    continue;
                }
            };
            if r.state == State::Pending {
                if r.expires <= now_s {
                    r.state = State::Expired;
                    match self.commit_request(&r) {
                        Ok(()) => expired.push(r),
                        Err(e) => {
                            eprintln!("saiife: warning: cannot expire approval #{id}: {e}")
                        }
                    }
                }
            } else if r.expires < old_req {
                let _ = std::fs::remove_file(self.result_path(id));
                let _ = std::fs::remove_file(self.json_path(id));
            }
        }
        for id in self.ids("result") {
            let keep = self.json_path(id).exists()
                && self.read_result(id).is_ok_and(|f| f.stored >= old_res);
            if !keep {
                let _ = std::fs::remove_file(self.result_path(id));
            }
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{Shared, VaultState};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const MIN: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_secs(3600);
    const DAY: Duration = Duration::from_secs(24 * 3600);

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn new_req(uid: u32) -> NewRequest {
        let mut params = BTreeMap::new();
        params.insert("id".into(), "42".into());
        NewRequest {
            uid,
            user: "agent-shop".into(),
            session: Some("s1".into()),
            agent: "claude".into(),
            project: "/p".into(),
            kind: ApprovalType::Connector,
            service: Some("shopify".into()),
            operation: Some("products.update".into()),
            capability: Some("products:write".into()),
            params: saiife_broker::mask::Masker::new(&[]).mask_params(&params),
            input: None,
            grant_key: None,
            scope: None,
            ask_rule: None,
            send: SendDisplay::default(),
        }
    }

    fn no_seal(_: u64) -> Result<Option<Vec<u8>>, VaultError> {
        Ok(None)
    }

    struct Env {
        t: tempfile::TempDir,
        store: Store,
    }

    fn env() -> Env {
        let t = tempfile::tempdir().unwrap();
        let store = Store::open(&dir_in(t.path())).unwrap();
        Env { t, store }
    }

    fn vault(t: &tempfile::TempDir) -> Shared {
        let key = t.path().join("vault-key");
        std::fs::write(&key, [7u8; 32]).unwrap();
        // The key is the daemon's own and private (macOS checks it).
        std::fs::set_permissions(
            &key,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
        let s = crate::vault::open(&key, &t.path().join("vault").join("vault.bin"));
        assert!(matches!(s, VaultState::Ready(_)));
        Shared::new(s)
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    /// Decide `id` at `t0()`.
    fn decide(s: &Store, id: u64, from: State, to: State) -> Result<Request, StoreError> {
        s.transition(id, &[from], to, Some(2), None, t0())
    }

    #[test]
    fn ids_monotonic_across_reopen() {
        let e = env();
        let a = e.store.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        let b = e.store.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        assert_eq!((a.id, b.id), (1, 2));
        drop(e.store);
        let dir = dir_in(e.t.path());
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.create(new_req(1), no_seal, HOUR, t0()).unwrap().id, 3);
        // Swept away, the ids still do not come back.
        for id in [1, 2, 3] {
            decide(&s, id, State::Pending, State::Rejected).unwrap();
        }
        s.sweep(t0() + 8 * DAY);
        assert!(s.list(Filter::default()).is_empty());
        let s = Store::open(&dir).unwrap();
        assert_eq!(s.create(new_req(1), no_seal, HOUR, t0()).unwrap().id, 4);
        // A counter behind the files never reuses an id.
        std::fs::write(dir.join(NEXT_ID), "2\n").unwrap();
        assert_eq!(s.create(new_req(1), no_seal, HOUR, t0()).unwrap().id, 5);
        // An unreadable counter is an error, not a restart at 1.
        std::fs::write(dir.join(NEXT_ID), "x").unwrap();
        assert!(s.create(new_req(1), no_seal, HOUR, t0()).is_err());
    }

    /// Decision 8: an identical pending connector (or mcp) request gives
    /// its id back from `create_dedup`; anything the approver would see
    /// differently makes a new one. A plain `create` never dedupes them.
    #[test]
    fn identical_pending_connector_request_is_deduped() {
        let e = env();
        let s = &e.store;
        let d = |mut r: NewRequest| {
            r.send.faithful = true;
            s.create_dedup(r, no_seal, HOUR, t0(), Some(20)).unwrap()
        };
        let (a, made) = d(new_req(1));
        assert!(made);
        let (b, made) = d(new_req(1));
        assert!(!made);
        assert_eq!(a.id, b.id);
        // Another uid, other params, another body hash, another type.
        assert_ne!(d(new_req(2)).0.id, a.id);
        let mut other = new_req(1);
        other.params = saiife_broker::mask::Masker::new(&[])
            .mask_params(&[("id".to_string(), "43".to_string())].into());
        assert_ne!(d(other).0.id, a.id);
        let mut hashed = new_req(1);
        hashed.send.body_sha256 = Some("ab".repeat(32));
        assert_ne!(d(hashed).0.id, a.id);
        let mut mcp = new_req(1);
        mcp.kind = ApprovalType::Mcp;
        assert_ne!(d(mcp).0.id, a.id);
        // A display masking changed is never deduped, either way round.
        let unfaithful = |r: NewRequest| s.create_dedup(r, no_seal, HOUR, t0(), Some(20)).unwrap();
        let (u, made) = unfaithful(new_req(1));
        assert!(made);
        assert_ne!(u.id, a.id);
        let (v, made) = unfaithful(new_req(1));
        assert!(made);
        assert_ne!(v.id, u.id);
        // Decided: no longer pending, so a new request.
        decide(s, a.id, State::Pending, State::Rejected).unwrap();
        assert_ne!(d(new_req(1)).0.id, a.id);
        // Expired but not swept: a new one too.
        let faithful = |mut r: NewRequest| {
            r.send.faithful = true;
            r
        };
        let (x, _) = s
            .create_dedup(faithful(new_req(9)), no_seal, MIN, t0(), None)
            .unwrap();
        let (y, made) = s
            .create_dedup(faithful(new_req(9)), no_seal, MIN, t0() + HOUR, None)
            .unwrap();
        assert!(made);
        assert_ne!(x.id, y.id);
        // The store-level create keeps making new ones.
        let p = s.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        let q = s.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        assert_ne!(p.id, q.id);
    }

    #[test]
    fn files_0600_dir_0700() {
        let t = tempfile::tempdir().unwrap();
        let dir = dir_in(t.path());
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = Store::open(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        let r = s.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        s.put_result(r.id, vec![1, 2, 3], t0()).unwrap();
        for f in ["1.json", "1.result", NEXT_ID] {
            assert_eq!(mode(&dir.join(f)), 0o600, "{f}");
        }
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
        // The file is §8.10: `type`, snake_case states.
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("1.json")).unwrap()).unwrap();
        assert_eq!(v["type"], "connector");
        assert_eq!(v["state"], "pending");
        assert_eq!(v["result_ref"], "1.result");
        assert_eq!(v["created"], "2027-01-15T08:00:00.000Z");
        assert_eq!(v["expires"], "2027-01-15T09:00:00.000Z");
        // A symlinked dir is refused.
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(Store::open(&link).is_err());
    }

    #[test]
    fn transition_rejects_wrong_state() {
        let e = env();
        let r = e.store.create(new_req(1), no_seal, MIN, t0()).unwrap();
        assert_eq!(e.store.sweep(t0() + 2 * MIN).len(), 1);
        match decide(&e.store, r.id, State::Pending, State::Approved) {
            Err(StoreError::WrongState {
                state: State::Expired,
                newly_expired: None,
            }) => {}
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            decide(&e.store, 99, State::Pending, State::Approved),
            Err(StoreError::Unknown)
        ));
        assert_eq!(e.store.get(r.id).unwrap().state, State::Expired);
        assert_eq!(e.store.get(r.id).unwrap().decided_by, None);
    }

    #[test]
    fn approving_past_expiry_unswept_expires_it() {
        let e = env();
        let r = e.store.create(new_req(1), no_seal, MIN, t0()).unwrap();
        let err = e
            .store
            .transition(
                r.id,
                &[State::Pending],
                State::Approved,
                Some(2),
                None,
                t0() + 2 * MIN,
            )
            .unwrap_err();
        let StoreError::WrongState {
            state: State::Expired,
            newly_expired: Some(gone),
        } = err
        else {
            panic!("{err:?}")
        };
        assert_eq!(
            (gone.id, gone.state, gone.decided_by),
            (r.id, State::Expired, None)
        );
        assert_eq!(e.store.get(r.id).unwrap().state, State::Expired);
        // Already expired: the sweep does not report it again.
        assert!(e.store.sweep(t0() + 3 * MIN).is_empty());
        // Before expiry the same call wins.
        let r2 = e.store.create(new_req(1), no_seal, MIN, t0()).unwrap();
        assert!(decide(&e.store, r2.id, State::Pending, State::Approved).is_ok());
    }

    #[test]
    fn only_allowed_edges() {
        let e = env();
        let s = &e.store;
        let id = s.create(new_req(1), no_seal, HOUR, t0()).unwrap().id;
        let all = [
            State::Pending,
            State::Approved,
            State::Rejected,
            State::Expired,
            State::Sent,
            State::SendFailed,
        ];
        // Pending -> Sent / Pending -> Pending are refused even if asked for.
        for to in [State::Sent, State::SendFailed, State::Pending] {
            let err = s.transition(id, &all, to, None, None, t0()).unwrap_err();
            assert_eq!(err.wrong_state(), Some(State::Pending), "{to:?}");
        }
        decide(s, id, State::Pending, State::Approved).unwrap();
        for to in [
            State::Pending,
            State::Rejected,
            State::Expired,
            State::Approved,
        ] {
            let err = s.transition(id, &all, to, None, None, t0()).unwrap_err();
            assert_eq!(err.wrong_state(), Some(State::Approved), "{to:?}");
        }
        s.transition(id, &all, State::Sent, None, None, t0())
            .unwrap();
        for to in all {
            let err = s.transition(id, &all, to, None, None, t0()).unwrap_err();
            assert_eq!(err.wrong_state(), Some(State::Sent), "{to:?}");
        }
    }

    #[test]
    fn concurrent_transitions_one_wins() {
        for _ in 0..20 {
            let e = env();
            let store = Arc::new(e.store);
            let id = store.create(new_req(1), no_seal, HOUR, t0()).unwrap().id;
            let go = Arc::new(std::sync::Barrier::new(2));
            let hs: Vec<_> = [State::Approved, State::Rejected]
                .into_iter()
                .map(|to| {
                    let (s, go) = (Arc::clone(&store), Arc::clone(&go));
                    std::thread::spawn(move || {
                        go.wait();
                        decide(&s, id, State::Pending, to)
                    })
                })
                .collect();
            let rs: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
            let won: Vec<_> = rs.iter().filter_map(|r| r.as_ref().ok()).collect();
            assert_eq!(won.len(), 1, "{rs:?}");
            let lost = rs.iter().find_map(|r| r.as_ref().err()).unwrap();
            assert_eq!(lost.wrong_state(), Some(won[0].state), "{lost:?}");
            assert_eq!(store.get(id).unwrap().state, won[0].state);
            drop(e.t);
        }
    }

    #[test]
    fn sweep_expires_pending_only() {
        let e = env();
        let s = &e.store;
        let p = s.create(new_req(1), no_seal, MIN, t0()).unwrap();
        let a = s.create(new_req(1), no_seal, MIN, t0()).unwrap();
        let later = s.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        decide(s, a.id, State::Pending, State::Approved).unwrap();
        assert!(s.sweep(t0() + MIN / 2).is_empty());
        let gone = s.sweep(t0() + 2 * MIN);
        assert_eq!(gone.iter().map(|r| r.id).collect::<Vec<_>>(), vec![p.id]);
        assert_eq!(gone[0].state, State::Expired);
        assert_eq!(s.get(p.id).unwrap().state, State::Expired);
        assert_eq!(s.get(a.id).unwrap().state, State::Approved);
        assert_eq!(s.get(later.id).unwrap().state, State::Pending);
        // Newly expired only: a second sweep returns nothing more.
        assert!(s.sweep(t0() + 3 * MIN).is_empty());
        // Decided requests go 7 days after they expired; pending never.
        assert_eq!(s.sweep(t0() + 6 * DAY).len(), 1);
        assert_eq!(
            s.list(Filter {
                states: vec![State::Expired],
                ..Filter::default()
            })
            .len(),
            2
        );
        s.sweep(t0() + 8 * DAY);
        assert!(s.list(Filter::default()).is_empty());
    }

    #[test]
    fn sweep_leaves_corrupt_and_oversize_files() {
        let e = env();
        let dir = dir_in(e.t.path());
        std::fs::write(dir.join("5.json"), b"{not json").unwrap();
        let big = std::fs::File::create(dir.join("6.json")).unwrap();
        big.set_len(MAX_FILE_BYTES + 1).unwrap();
        assert!(e.store.sweep(t0()).is_empty());
        assert!(e.store.sweep(t0()).is_empty());
        let w = e.store.warned.lock().unwrap();
        assert_eq!(
            w.iter().cloned().collect::<std::collections::BTreeSet<_>>(),
            ["5.json".to_string(), "6.json".to_string()].into()
        );
        assert!(dir.join("5.json").exists() && dir.join("6.json").exists());
    }

    #[test]
    fn results_dropped_after_24h() {
        let e = env();
        let s = &e.store;
        let r = s.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        decide(s, r.id, State::Pending, State::Approved).unwrap();
        s.transition(r.id, &[State::Approved], State::Sent, None, None, t0())
            .unwrap();
        s.put_result(r.id, b"sealed".to_vec(), t0() + MIN).unwrap();
        assert_eq!(s.get(r.id).unwrap().decided_by, Some(2));
        s.sweep(t0() + 23 * HOUR);
        assert_eq!(s.get_result(r.id).as_deref(), Some(&b"sealed"[..]));
        s.sweep(t0() + 25 * HOUR);
        assert_eq!(s.get_result(r.id), None);
        assert!(!dir_in(e.t.path()).join("1.result").exists());
        // The request itself stays (7 days).
        assert_eq!(s.get(r.id).unwrap().state, State::Sent);
        assert!(s.put_result(77, vec![1], t0()).is_err());
    }

    #[test]
    fn sealed_request_is_what_is_sent() {
        let e = env();
        let v = vault(&e.t);
        let exact = br#"{"op":"products.update","body":"{\"price\":\"9.99\",\"token\":\"x\"}"}"#;
        let r = e
            .store
            .create(
                new_req(1),
                |id| v.seal(&aad(id), exact).map(Some),
                HOUR,
                t0(),
            )
            .unwrap();
        let sealed = e.store.sealed_request(r.id).unwrap();
        assert!(!sealed.windows(5).any(|w| w == b"price"));
        let opened = v.open_sealed(&aad(r.id), &sealed).unwrap();
        assert_eq!(&opened[..], &exact[..]);
        // A flipped byte anywhere fails.
        for i in [0, 23, 24, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert_eq!(
                v.open_sealed(&aad(r.id), &bad).unwrap_err(),
                VaultError::Crypto
            );
        }
        // The AAD binds the id, and a result never opens as a request.
        assert_eq!(
            v.open_sealed(&aad(2), &sealed).unwrap_err(),
            VaultError::Crypto
        );
        assert_eq!(
            v.open_sealed(&result_aad(r.id), &sealed).unwrap_err(),
            VaultError::Crypto
        );
        assert_eq!(
            v.open_sealed(&aad(1), &sealed[..30]).unwrap_err(),
            VaultError::Crypto
        );
        // A fresh nonce every seal.
        assert_ne!(
            v.seal(&aad(1), exact).unwrap(),
            v.seal(&aad(1), exact).unwrap()
        );
    }

    #[test]
    fn vault_unavailable_seal_fails_closed() {
        let e = env();
        let v = Shared::new(VaultState::Unavailable("no vault key".into()));
        assert_eq!(v.seal(&aad(1), b"x").unwrap_err(), VaultError::Unavailable);
        assert_eq!(
            v.open_sealed(&aad(1), &[0u8; 64]).unwrap_err(),
            VaultError::Unavailable
        );
        let err = e
            .store
            .create(
                new_req(1),
                |id| v.seal(&aad(id), b"x").map(Some),
                HOUR,
                t0(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("unavailable"), "{err}");
        // Nothing stored, no id used.
        assert!(e.store.list(Filter::default()).is_empty());
        assert_eq!(
            e.store.create(new_req(1), no_seal, HOUR, t0()).unwrap().id,
            1
        );
        // Sealed with a key that is gone: opening fails closed too.
        let good = vault(&e.t);
        let sealed = good.seal(&aad(1), b"x").unwrap();
        assert_eq!(
            v.open_sealed(&aad(1), &sealed).unwrap_err(),
            VaultError::Unavailable
        );
    }

    /// A dir fsync that fails on call number `n` (from 1), counting all.
    fn failing_sync(s: &mut Store, n: usize) -> Arc<AtomicUsize> {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        s.dir_sync = Box::new(move |_| {
            if c.fetch_add(1, Ordering::SeqCst) + 1 == n {
                Err(io::Error::other("injected dir sync failure"))
            } else {
                Ok(())
            }
        });
        calls
    }

    #[test]
    fn failed_create_leaves_no_pending_request() {
        let mut e = env();
        // Sync 1 is next_id, sync 2 the request file (after its rename).
        failing_sync(&mut e.store, 2);
        assert!(e.store.create(new_req(1), no_seal, HOUR, t0()).is_err());
        let dir = dir_in(e.t.path());
        assert!(!dir.join("1.json").exists());
        assert!(e.store.list(Filter::default()).is_empty());
        assert!(matches!(
            decide(&e.store, 1, State::Pending, State::Approved),
            Err(StoreError::Unknown)
        ));
        // The id is used up, not reused.
        assert_eq!(
            e.store.create(new_req(1), no_seal, HOUR, t0()).unwrap().id,
            2
        );
        // A failed counter sync fails the create too, with no request.
        failing_sync(&mut e.store, 1);
        assert!(e.store.create(new_req(1), no_seal, HOUR, t0()).is_err());
        assert!(!dir.join("3.json").exists());
    }

    #[test]
    fn transition_dir_sync_failure_counts_as_committed() {
        let mut e = env();
        let id = e.store.create(new_req(1), no_seal, HOUR, t0()).unwrap().id;
        let calls = failing_sync(&mut e.store, 1);
        let r = decide(&e.store, id, State::Pending, State::Approved).unwrap();
        assert_eq!(r.state, State::Approved);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(e.store.get(id).unwrap().state, State::Approved);
        // And it stays decided: a second decider loses.
        assert_eq!(
            decide(&e.store, id, State::Pending, State::Rejected)
                .unwrap_err()
                .wrong_state(),
            Some(State::Approved)
        );
    }

    #[test]
    fn note_capped_and_control_chars_refused() {
        let e = env();
        let s = &e.store;
        let id = s.create(new_req(1), no_seal, HOUR, t0()).unwrap().id;
        let bad = [
            "a".repeat(NOTE_MAX + 1),
            "line\nbreak".into(),
            "\u{1b}[31m".into(),
            "tab\t".into(),
            "\u{7f}".into(),
            "\u{85}".into(),
            "ok\u{202E}evil".into(),
            "\u{202A}".into(),
            "\u{2066}x\u{2069}".into(),
            "zero\u{200B}width".into(),
            "\u{FEFF}".into(),
            "\u{2028}".into(),
            "\u{2029}".into(),
            "\u{E0041}".into(),
        ];
        for b in bad {
            assert!(
                matches!(
                    s.transition(
                        id,
                        &[State::Pending],
                        State::Approved,
                        Some(2),
                        Some(b.clone()),
                        t0()
                    ),
                    Err(StoreError::BadNote(_))
                ),
                "{b:?}"
            );
        }
        assert_eq!(s.get(id).unwrap().state, State::Pending);
        let ok = "é".repeat(NOTE_MAX / 2);
        let r = s
            .transition(
                id,
                &[State::Pending],
                State::Approved,
                Some(2),
                Some(ok.clone()),
                t0(),
            )
            .unwrap();
        assert_eq!(r.note.as_deref(), Some(ok.as_str()));
        assert_eq!(s.get(id).unwrap().note, Some(ok));
    }

    #[test]
    fn list_filters_by_uid_and_state() {
        let e = env();
        let s = &e.store;
        s.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        s.create(new_req(2), no_seal, HOUR, t0()).unwrap();
        decide(s, 2, State::Pending, State::Rejected).unwrap();
        let ids = |f| s.list(f).iter().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(ids(Filter::default()), vec![1, 2]);
        assert_eq!(
            ids(Filter {
                uid: Some(2),
                states: vec![]
            }),
            vec![2]
        );
        assert_eq!(
            ids(Filter {
                uid: None,
                states: vec![State::Pending]
            }),
            vec![1]
        );
        // A file whose id differs from its name is not served.
        let dir = dir_in(e.t.path());
        std::fs::copy(dir.join("1.json"), dir.join("9.json")).unwrap();
        assert!(s.get(9).is_none());
    }

    #[test]
    fn only_canonical_names_are_ids() {
        assert_eq!(id_of("1.json", "json"), Some(1));
        assert_eq!(id_of("42.result", "result"), Some(42));
        for n in [
            "01.json",
            "0.json",
            "00.json",
            ".json",
            "1.json.tmp",
            "+1.json",
            "1x.json",
        ] {
            assert_eq!(id_of(n, "json"), None, "{n}");
        }
        // A non-canonical copy is not listed and does not move the counter.
        let e = env();
        let dir = dir_in(e.t.path());
        let r = e.store.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        std::fs::copy(dir.join("1.json"), dir.join("01.json")).unwrap();
        assert_eq!(e.store.list(Filter::default()).len(), 1);
        assert_eq!(
            e.store.create(new_req(1), no_seal, HOUR, t0()).unwrap().id,
            r.id + 1
        );
    }

    #[test]
    fn pending_cap_counts_only_live_pending_of_the_uid() {
        let e = env();
        let s = &e.store;
        let cap = |uid, at| s.create_capped(new_req(uid), no_seal, MIN, at, Some(2));
        cap(1, t0()).unwrap();
        cap(1, t0()).unwrap();
        let err = cap(1, t0()).unwrap_err();
        assert!(err
            .get_ref()
            .unwrap()
            .downcast_ref::<PendingFull>()
            .is_some());
        // Another uid has its own count.
        cap(2, t0()).unwrap();
        // Decided or expired ones do not count.
        decide(s, 1, State::Pending, State::Rejected).unwrap();
        cap(1, t0()).unwrap();
        assert!(cap(1, t0()).is_err());
        cap(1, t0() + 2 * MIN).unwrap();
    }

    #[test]
    fn results_are_raw_and_capped() {
        let e = env();
        let s = e.store.with_result_cap(100);
        let r = s.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        let err = s.put_result(r.id, vec![9; 101], t0()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(s.get_result(r.id), None);
        s.put_result(r.id, vec![9; 100], t0()).unwrap();
        assert_eq!(s.get_result(r.id), Some(vec![9; 100]));
        let raw = std::fs::read(dir_in(e.t.path()).join("1.result")).unwrap();
        assert_eq!(raw.len(), 8 + 24 + 100);
        assert!(raw.starts_with(RESULT_MAGIC));
    }

    #[test]
    fn expired_record_names_requester_and_id() {
        let e = env();
        let mut req = new_req(1001);
        let mut raw = req.params.get().clone();
        raw.insert(
            "token".into(),
            concat!("shp", "at_0123456789abcdef0123456789abcdef").into(),
        );
        // Not a vault value or a v1 pattern: left as is in the display copy,
        // and never in a record.
        req.params = saiife_broker::mask::Masker::new(&[]).mask_params(&raw);
        let r = e.store.create(req, no_seal, MIN, t0()).unwrap();
        let gone = e.store.sweep(t0() + 2 * MIN).pop().unwrap();
        let base = saiife_audit::Record::at(
            saiife_audit::NewRecord {
                agent: "",
                project: "",
                session: None,
                tool: "approval",
                input: &summary(&gone),
                decision: saiife_audit::DecisionKind::Allow,
                pack: None,
                rule: None,
                reason: None,
                mode: "locked",
                policy: None,
                permission_mode: None,
            },
            "test",
            time::OffsetDateTime::now_utc(),
        );
        let rec = record_for(base, &gone, "expired");
        let v = serde_json::to_value(&rec).unwrap();
        assert_eq!(v["kind"], "approval");
        assert_eq!(v["action"], "expired");
        assert_eq!(v["id"], r.id);
        assert_eq!(v["approval"], r.id);
        assert_eq!(v["uid"], 1001);
        assert_eq!(v["user"], "agent-shop");
        assert_eq!(v["agent"], "claude");
        assert_eq!(v["decision"], "expired");
        assert_eq!(v["input"], "shopify products.update");
        assert!(!v.to_string().contains("shpat_"), "{v}");
        assert!(v.get("by_uid").is_none());
    }
}
