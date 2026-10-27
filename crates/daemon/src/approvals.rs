//! Approval requests (spec §6.10.1, §8.10): one `<id>.json` per request,
//! 0600 in `<state>/approvals/` (0700, checked like the vault dir), with
//! the id counter in `next_id` (fsynced; ids never repeat) and a result in
//! `<id>.result`. The exact request to send (`request_sealed`) and the
//! result are sealed with the vault key ([`crate::vault::Shared::seal`]),
//! bound to the id by [`aad`] / [`result_aad`]; the display copy is masked
//! by the caller. Every change happens under one mutex and re-reads the
//! file, so two deciders never both win. The calls do blocking disk IO:
//! call them off the runtime thread.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    pub params: BTreeMap<String, String>,
    pub input: Option<String>,
    pub grant_key: Option<String>,
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
    /// The request is in this state, not one of those asked for.
    WrongState(State),
    /// The note is longer than [`NOTE_MAX`] or holds a control character.
    BadNote(&'static str),
    Io(io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Unknown => f.write_str("no such approval request"),
            StoreError::WrongState(s) => write!(f, "the request is {}", state_name(*s)),
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

/// Refuse a note over [`NOTE_MAX`] bytes or with a control character.
pub fn check_note(note: &str) -> Result<(), StoreError> {
    if note.len() > NOTE_MAX {
        return Err(StoreError::BadNote("the note is longer than 1 KiB"));
    }
    if note.chars().any(char::is_control) {
        return Err(StoreError::BadNote("the note holds a control character"));
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

#[derive(Serialize, Deserialize)]
struct ResultFile {
    stored: String,
    sealed: String,
}

pub struct Store {
    dir: PathBuf,
    /// Held by every change, across its disk IO.
    lock: Mutex<()>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("dir", &self.dir).finish()
    }
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// `<digits>.<ext>` -> the id.
fn id_of(name: &str, ext: &str) -> Option<u64> {
    let stem = name.strip_suffix(ext)?.strip_suffix('.')?;
    if stem.is_empty() || !stem.bytes().all(|b| b.is_ascii_digit()) {
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
        })
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
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
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
            return Err(e);
        }
        std::fs::File::open(&self.dir)?.sync_all()
    }

    fn write_request(&self, r: &Request) -> io::Result<()> {
        let bytes = serde_json::to_vec(r).map_err(io::Error::other)?;
        self.write_atomic(&format!("{}.json", r.id), &bytes)
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
    /// The counter is fsynced before the request file is written.
    pub fn create(
        &self,
        req: NewRequest,
        seal: impl FnOnce(u64) -> Result<Option<Vec<u8>>, VaultError>,
        ttl: Duration,
        now: SystemTime,
    ) -> io::Result<Request> {
        let _g = self.guard();
        let id = self.next_id()?;
        let sealed = seal(id).map_err(io::Error::other)?;
        let next = id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("approval ids exhausted"))?;
        self.write_atomic(NEXT_ID, format!("{next}\n").as_bytes())?;
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
            params: req.params,
            input: req.input,
            grant_key: req.grant_key,
            request_sealed: sealed.map(|s| b64().encode(s)),
            state: State::Pending,
            decided_by: None,
            note: None,
            result_ref: None,
        };
        self.write_request(&r)?;
        Ok(r)
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
    /// store's lock: of two racing deciders exactly one wins. `by` and
    /// `note` are set when given and kept otherwise.
    pub fn transition(
        &self,
        id: u64,
        from: &[State],
        to: State,
        by: Option<u32>,
        note: Option<String>,
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
        if !from.contains(&r.state) {
            return Err(StoreError::WrongState(r.state));
        }
        r.state = to;
        if by.is_some() {
            r.decided_by = by;
        }
        if note.is_some() {
            r.note = note;
        }
        self.write_request(&r).map_err(StoreError::Io)?;
        Ok(r)
    }

    /// Keep the sealed (masked) result of `id` as `<id>.result` and point
    /// the request's `result_ref` at it.
    pub fn put_result(&self, id: u64, sealed: Vec<u8>, now: SystemTime) -> io::Result<()> {
        let _g = self.guard();
        let mut r = self.read(id)?;
        let name = format!("{id}.result");
        let file = ResultFile {
            stored: ts(now),
            sealed: b64().encode(sealed),
        };
        let bytes = serde_json::to_vec(&file).map_err(io::Error::other)?;
        self.write_atomic(&name, &bytes)?;
        r.result_ref = Some(name);
        self.write_request(&r)
    }

    fn read_result(&self, id: u64) -> io::Result<ResultFile> {
        let bytes = read_capped(&self.result_path(id))?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// The sealed result of `id`, while it is kept.
    pub fn get_result(&self, id: u64) -> Option<Vec<u8>> {
        b64().decode(self.read_result(id).ok()?.sealed).ok()
    }

    /// Expire pending requests past `expires` (returned, for their records),
    /// drop results kept longer than [`RESULT_KEEP`] (and results without a
    /// request), and delete decided requests [`REQUEST_KEEP`] after they
    /// expired.
    pub fn sweep(&self, now: SystemTime) -> Vec<Request> {
        let _g = self.guard();
        let now_s = ts(now);
        let old_req = ts(now.checked_sub(REQUEST_KEEP).unwrap_or(UNIX_EPOCH));
        let old_res = ts(now.checked_sub(RESULT_KEEP).unwrap_or(UNIX_EPOCH));
        let mut expired = Vec::new();
        for id in self.ids("json") {
            let Ok(mut r) = self.read(id) else {
                continue;
            };
            if r.state == State::Pending {
                if r.expires <= now_s {
                    r.state = State::Expired;
                    match self.write_request(&r) {
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
            params,
            input: None,
            grant_key: None,
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
        let s = crate::vault::open(&key, &t.path().join("vault").join("vault.bin"));
        assert!(matches!(s, VaultState::Ready(_)));
        Shared::new(s)
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
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
        s.transition(3, &[State::Pending], State::Rejected, Some(2), None)
            .unwrap();
        for id in [1, 2] {
            s.transition(id, &[State::Pending], State::Rejected, Some(2), None)
                .unwrap();
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
        match e
            .store
            .transition(r.id, &[State::Pending], State::Approved, Some(2), None)
        {
            Err(StoreError::WrongState(State::Expired)) => {}
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            e.store
                .transition(99, &[State::Pending], State::Approved, Some(2), None),
            Err(StoreError::Unknown)
        ));
        assert_eq!(e.store.get(r.id).unwrap().state, State::Expired);
        assert_eq!(e.store.get(r.id).unwrap().decided_by, None);
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
                        s.transition(id, &[State::Pending], to, Some(2), None)
                    })
                })
                .collect();
            let rs: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
            let won: Vec<_> = rs.iter().filter_map(|r| r.as_ref().ok()).collect();
            assert_eq!(won.len(), 1, "{rs:?}");
            let lost = rs.iter().find_map(|r| r.as_ref().err()).unwrap();
            assert!(
                matches!(lost, StoreError::WrongState(s) if *s == won[0].state),
                "{lost:?}"
            );
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
        s.transition(a.id, &[State::Pending], State::Approved, Some(2), None)
            .unwrap();
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
    fn results_dropped_after_24h() {
        let e = env();
        let s = &e.store;
        let r = s.create(new_req(1), no_seal, HOUR, t0()).unwrap();
        s.transition(r.id, &[State::Pending], State::Approved, Some(2), None)
            .unwrap();
        s.transition(r.id, &[State::Approved], State::Sent, None, None)
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

    #[test]
    fn note_capped_and_control_chars_refused() {
        let e = env();
        let s = &e.store;
        let id = s.create(new_req(1), no_seal, HOUR, t0()).unwrap().id;
        for bad in [
            "a".repeat(NOTE_MAX + 1),
            "line\nbreak".into(),
            "\u{1b}[31m".into(),
            "tab\t".into(),
        ] {
            assert!(matches!(
                s.transition(id, &[State::Pending], State::Approved, Some(2), Some(bad)),
                Err(StoreError::BadNote(_))
            ),);
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
        s.transition(2, &[State::Pending], State::Rejected, Some(3), None)
            .unwrap();
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
}
