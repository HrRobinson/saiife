//! The land book (plan 39 Task 4, spec §7.5, §7.7, §8.2): reviews of a
//! box's diff, land requests bound to a `land` touch, their approval or
//! rejection, and the records of every land.
//!
//! - **Reviews.** [`Lands::refresh`] asks the guest for export `n` (one
//!   more than the highest `lands/<n>` and any export tried before, so
//!   numbers never repeat), validates it against the box's current base
//!   (ruling R-P3: the spawn manifest `base.json` plus every approved
//!   land's entries, in land order, rebuilt from `lands/<n>/` each time;
//!   nothing else stores it), renders it (`saiife_boxhost::review`, with
//!   plan 32's `diff_hits` as flags) and caches it per box. A refused
//!   export is one `diff_rejected` record and stores nothing.
//! - **Requests.** [`Lands::begin`] issues `IssueKey::Land(request_id)` in
//!   plan 26's touch state (class `land`; fields `repo`, `base_commit` (the
//!   snapshot commit, L5), `target_ref`, `diff_sha256`) and writes
//!   `lands/<n>/request.json`. A partial land (`only`) is checked with
//!   `review::check_subset` (R-T1d) and hashed over the subset alone.
//!   [`LandBook::pending`] issues at most [`PENDING_PER_OWNER`] of them per
//!   owner (L8), for the oldest `Done` boxes with a non-empty review.
//! - **Approval** ([`Lands::approve`], the CLI's `box.land` and the
//!   Workspace's `complete`): the request must still name the box's latest
//!   review; `approved.json` (0600, `O_EXCL`) is written, the manager moves
//!   the box to `Landed`, the guest advances its base (`Advance { n,
//!   paths }`) and a `land` record carries the touch. The commit is written
//!   later by the CLI (L4: `saiife box apply`), which reports it with
//!   [`Lands::applied`].
//! - **A failed advance.** When the guest does not take the advance after
//!   the state moved, the land keeps no `advanced.json`; the next
//!   [`Lands::refresh`] advances again before it exports. A guest that lies
//!   about its advance fails the base check of the next export anyway.
//!
//! Locking: the state mutex is never held across a guest request, a file
//! write or an audit write. One per-box mutex orders a box's exports,
//! approvals and advances. Every method blocks (guest, disk, the audit
//! writer through [`crate::writer::WriterHandle::append_blocking`]): call
//! them from `spawn_blocking`, never on a runtime worker.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use saiife_audit::Record;
use saiife_boxes::manager::Manager;
use saiife_boxes::source::LandBook;
use saiife_boxes::store::BoxRecord;
use saiife_boxes::{BoxError, BoxId, BoxState};
use saiife_boxhost::guest::VsockGuest;
use saiife_boxhost::layout::Layout;
use saiife_boxhost::paths::BoxPaths;
use saiife_boxhost::review::{self, Flag, Review};
use saiife_boxproto::delta::{apply_manifest, Valid};
use saiife_boxproto::manifest::{is_oid, BaseManifest};
use saiife_boxproto::msg::{Reply, Request};
use saiife_touch::{ActionRecord, TouchClass, TouchEvidence};
use saiife_wire::source::{Decision, DiffSummary, PendingAction};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ops::Ctx;
use crate::touch::IssueKey;

/// The touch summary is cut at this many chars.
pub const MAX_SUMMARY: usize = 512;
/// L8: land records the Workspace sees per owner at once.
pub const PENDING_PER_OWNER: usize = 4;
/// `request.json`, `approved.json`, `applied.json` are at most this big.
const RECORD_MAX: u64 = 64 << 10;
/// `review.json` (the unified text is at most 2 MiB; 20 000 entry heads).
const REVIEW_MAX: u64 = 64 << 20;
/// The guest's base advance (git plumbing over `/work`'s export).
const ADVANCE_TIMEOUT: Duration = Duration::from_secs(60);
/// Guest text kept in an error, in bytes.
const MAX_WHY: usize = 512;
/// receive's refusal when the box has no live guest channel.
const NOT_CONNECTED: &str = "the guest is not connected";

/// Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// One approved land, as the CLI applies it (always answered nested as
/// `{land: LandInfo}`, plan 34 R20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandInfo {
    pub id: BoxId,
    pub n: u32,
    pub target_ref: String,
    /// The snapshot commit the box started from (L5).
    pub base_commit: String,
    pub diff_sha256: String,
    pub task: String,
    pub repo_dir: Option<String>,
}

/// A land request: what `lands/<n>/request.json` holds and the touch
/// record is built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandRequest {
    pub request_id: u64,
    pub id: BoxId,
    /// The export the request lands.
    pub n: u32,
    /// The uid the touch was issued to.
    pub owner: u32,
    /// A partial land's paths; `None`: the whole export.
    pub only: Option<BTreeSet<String>>,
    /// What the touch binds: the hash of the rendering of what lands.
    pub diff_sha256: String,
    /// The hash of the whole review the request was made from: the request
    /// is current while the box's latest review has it.
    pub review_sha256: String,
    pub base_commit: String,
    pub target_ref: String,
    pub repo: String,
    pub summary: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// `lands/<n>/approved.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Approved {
    request_id: u64,
    id: BoxId,
    n: u32,
    only: Option<BTreeSet<String>>,
    diff_sha256: String,
    base_commit: String,
    /// `BaseManifest::sha256()` of the base the land was reviewed against
    /// (ruling R-P6).
    base_sha256: String,
    target_ref: String,
    via: String,
    approved_at: u64,
    task: String,
    repo_dir: Option<String>,
}

/// `lands/<n>/applied.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Applied {
    commit: String,
    applied_at: u64,
}

/// A box's latest review and the base it was made against.
struct Cached {
    review: Review,
    base: BaseManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decided {
    Approved,
    Rejected,
}

#[derive(Clone)]
struct Req {
    req: LandRequest,
    record: ActionRecord,
    /// The review of what lands (the subset's for a partial land).
    review: Review,
    decided: Option<Decided>,
}

struct State {
    next_rid: u64,
    reviews: BTreeMap<BoxId, Arc<Cached>>,
    requests: BTreeMap<u64, Req>,
    /// The whole-review hash the owner rejected: that review is not
    /// offered again (a new review is).
    rejected: BTreeMap<BoxId, String>,
    /// The last export number asked for, per box.
    last_export: BTreeMap<BoxId, u32>,
}

/// The box's current base (R-P3).
struct Current {
    base: BaseManifest,
    /// The highest `lands/<n>` (0: none).
    highest: u32,
    /// The last approved land, when the guest has not taken it.
    unadvanced: Option<(u32, Option<BTreeSet<String>>)>,
}

pub struct Lands {
    ctx: Weak<Ctx>,
    mgr: Arc<Manager>,
    guest: Arc<VsockGuest>,
    layout: Layout,
    clock: Clock,
    state: Mutex<State>,
    /// One lock per box: exports, approvals and advances of a box in turn.
    boxes: Mutex<BTreeMap<BoxId, Arc<Mutex<()>>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn unavailable(m: impl Into<String>) -> BoxError {
    BoxError::Unavailable(m.into())
}

/// `refresh`'s answer for a box whose VM is off and that has no review.
pub fn vm_off(id: &BoxId) -> String {
    format!(
        "the box's VM is off and it has no review; saiife box revise {} restarts it",
        id.as_str()
    )
}

/// `saiife/box-<id>`.
pub fn target_ref(id: &BoxId) -> String {
    format!("saiife/box-{}", id.as_str())
}

/// Guest text cut to [`MAX_WHY`] bytes and escaped.
fn guest_text(s: &str) -> String {
    let mut k = s.len().min(MAX_WHY);
    while !s.is_char_boundary(k) {
        k -= 1;
    }
    review::escape(&s[..k])
}

/// `land <id>: <k> files (+a −r)[; flagged: <path> (<why>), …]`, every
/// guest string escaped, cut at [`MAX_SUMMARY`] chars.
pub fn summary(id: &BoxId, r: &Review) -> String {
    let files = &r.summary.files;
    let added: u64 = files.iter().map(|f| u64::from(f.added)).sum();
    let removed: u64 = files.iter().map(|f| u64::from(f.removed)).sum();
    let mut s = format!(
        "land {}: {} files (+{added} \u{2212}{removed})",
        id.as_str(),
        files.len()
    );
    if !r.flags.is_empty() {
        let flagged: Vec<String> = r
            .flags
            .iter()
            .map(|f| format!("{} ({})", review::escape(&f.path), review::escape(&f.why)))
            .collect();
        s.push_str("; flagged: ");
        s.push_str(&flagged.join(", "));
    }
    if s.chars().count() > MAX_SUMMARY {
        s = s.chars().take(MAX_SUMMARY - 1).collect();
        s.push('\u{2026}');
    }
    s
}

/// The fields a `land` touch binds (plan 26's reserved names).
fn fields(id: &BoxId, base: &BaseManifest, r: &Review) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("repo".to_string(), base.repo.clone()),
        ("base_commit".to_string(), r.summary.base_commit.clone()),
        ("target_ref".to_string(), target_ref(id)),
        ("diff_sha256".to_string(), r.summary.diff_sha256.clone()),
    ])
}

fn nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits() as i32
}

/// A new file (0600, `O_EXCL|O_NOFOLLOW`) holding `body`, synced.
fn write_new(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nofollow())
        .open(path)?;
    let r = f.write_all(body).and_then(|()| f.sync_all());
    if r.is_err() {
        let _ = fs::remove_file(path);
    }
    r
}

/// `path` replaced by a new file holding `body` (a record file the daemon
/// rewrites; memory holds the truth while it runs).
fn write_over(path: &Path, body: &[u8]) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    write_new(path, body)
}

/// Whether `path` exists (not followed).
fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// A daemon-trusted JSON record, bounded; `None` when it is missing.
fn read_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    what: &str,
    max: u64,
) -> Result<Option<T>, String> {
    if !exists(path).map_err(|e| format!("the {what}: {e}"))? {
        return Ok(None);
    }
    let b = crate::box_repo::read_trusted(path, what, max)?;
    serde_json::from_slice(&b)
        .map(Some)
        .map_err(|e| format!("the {what}: {e}"))
}

/// The export numbers under `lands/`, ascending.
fn land_numbers(paths: &BoxPaths) -> Result<Vec<u32>, String> {
    let dir = paths.lands_dir();
    match fs::symlink_metadata(&dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err("the box's lands entry is not a directory".into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("the box's lands: {e}")),
    }
    let mut out = Vec::new();
    for e in fs::read_dir(&dir).map_err(|e| format!("the box's lands: {e}"))? {
        let e = e.map_err(|e| format!("the box's lands: {e}"))?;
        if let Some(n) = BoxPaths::land_number(&e.file_name()) {
            out.push(n);
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// The owner's home for plan 32's `$HOME` rules: root's is `/root`, any
/// other user's `/home/<name>` (the directory has no home lookup).
fn home_of(ctx: &Ctx, uid: u32) -> std::path::PathBuf {
    if uid == 0 {
        return "/root".into();
    }
    match ctx.directory.name_of(uid) {
        Some(n) => Path::new("/home").join(n),
        None => "/nonexistent".into(),
    }
}

/// Plan 32's `diff_hits` of the policy's user packs (`Profile::Box`) as
/// flags. Packs that do not load flag every path (a broken pack denies).
fn hits_for(ctx: &Ctx, rec: &BoxRecord) -> impl Fn(&[&str]) -> Vec<Flag> {
    use saiifeguard::userpack::{diff_hits, load_user_packs_cached, UserSrc};
    let files = ctx
        .policy()
        .system
        .map(|s| s.user_packs.clone())
        .unwrap_or_default();
    let srcs: Vec<UserSrc<'_>> = files
        .iter()
        .map(|u| UserSrc {
            source: &u.path,
            text: &u.text,
        })
        .collect();
    let loaded = if srcs.is_empty() {
        Ok(Vec::new())
    } else {
        load_user_packs_cached(
            &srcs,
            saiifeguard::canon::PathStyle::host(),
            saiifeguard::profile::Profile::Box,
        )
        .map_err(|e| e.to_string())
    };
    let root = std::path::PathBuf::from(rec.repo_dir.clone().unwrap_or_else(|| "/work".into()));
    let home = home_of(ctx, rec.owner_uid);
    move |paths: &[&str]| match &loaded {
        Ok(packs) if packs.is_empty() => Vec::new(),
        Ok(packs) => diff_hits(packs, &root, &home, paths)
            .into_iter()
            .map(|h| Flag {
                path: h.path,
                why: format!("rule {}: {}", h.pack, h.reason),
            })
            .collect(),
        Err(e) => paths
            .iter()
            .map(|p| Flag {
                path: (*p).to_string(),
                why: format!("rule packs could not be loaded: {e}"),
            })
            .collect(),
    }
}

impl Lands {
    /// The book over `mgr`'s boxes, reaching each box's guest through
    /// `guest` and its files through `layout` (whose `boxes` is the
    /// manager's root). The context is held weakly (it holds the book).
    pub fn new(
        ctx: Arc<Ctx>,
        mgr: Arc<Manager>,
        guest: Arc<VsockGuest>,
        layout: Layout,
    ) -> Arc<Lands> {
        Self::with_clock(ctx, mgr, guest, layout, Arc::new(crate::touch::unix_now))
    }

    /// [`Lands::new`] with its own clock (tests).
    pub fn with_clock(
        ctx: Arc<Ctx>,
        mgr: Arc<Manager>,
        guest: Arc<VsockGuest>,
        layout: Layout,
        clock: Clock,
    ) -> Arc<Lands> {
        // Request ids start at a random point past 2^32: a restart never
        // hands out an id an old record or a client still holds.
        let mut b = [0u8; 4];
        let seed = getrandom::fill(&mut b).map_or(0, |()| u32::from_le_bytes(b));
        Arc::new(Lands {
            ctx: Arc::downgrade(&ctx),
            mgr,
            guest,
            layout,
            clock,
            state: Mutex::new(State {
                next_rid: (1u64 << 32) + u64::from(seed),
                reviews: BTreeMap::new(),
                requests: BTreeMap::new(),
                rejected: BTreeMap::new(),
                last_export: BTreeMap::new(),
            }),
            boxes: Mutex::new(BTreeMap::new()),
        })
    }

    fn ctx(&self) -> Result<Arc<Ctx>, BoxError> {
        self.ctx
            .upgrade()
            .ok_or_else(|| unavailable("the daemon is stopping"))
    }

    fn paths(&self, id: &BoxId) -> BoxPaths {
        self.layout.box_paths(id)
    }

    fn box_lock(&self, id: &BoxId) -> Arc<Mutex<()>> {
        Arc::clone(lock(&self.boxes).entry(id.clone()).or_default())
    }

    fn cached(&self, id: &BoxId) -> Option<Arc<Cached>> {
        lock(&self.state).reviews.get(id).cloned()
    }

    fn state_of(&self, id: &BoxId) -> BoxState {
        self.mgr.get(id).map_or(BoxState::Discarded, |r| r.state)
    }

    /// The box's latest review, if one is cached.
    pub fn latest(&self, id: &BoxId) -> Option<Review> {
        self.cached(id).map(|c| c.review.clone())
    }

    /// Request `rid` and its touch record (the CLI path rebuilds the record
    /// it verifies from this, never from the client).
    pub fn request(&self, rid: u64) -> Option<(LandRequest, ActionRecord)> {
        lock(&self.state)
            .requests
            .get(&rid)
            .map(|q| (q.req.clone(), q.record.clone()))
    }

    /// Whether request `rid` still names its box's latest review.
    pub fn is_current(&self, rid: u64) -> bool {
        let st = lock(&self.state);
        let Some(q) = st.requests.get(&rid) else {
            return false;
        };
        st.reviews
            .get(&q.req.id)
            .is_some_and(|c| c.review.summary.diff_sha256 == q.req.review_sha256)
    }

    /// One `box` record of `action` about box `id`.
    fn record(&self, ctx: &Ctx, action: &str, id: &BoxId, owner: Option<u32>) -> Record {
        let mut r = ctx.record("box", &format!("{action} {}", id.as_str()));
        r.session = Some(format!("box-{}", id.as_str()));
        if let Some(u) = owner {
            r.uid = Some(u);
            r.user = ctx.directory.name_of(u);
        }
        r.extra.insert("action".into(), action.into());
        r.extra.insert("box".into(), id.as_str().into());
        r
    }

    fn write(&self, ctx: &Ctx, rec: Record) {
        if let Err(e) = ctx.writer.append_blocking(rec) {
            eprintln!("saiifed: warning: cannot write a box land record: {e}");
        }
    }

    /// The box's current base (R-P3): `base.json`, then every approved
    /// land's entries in land order.
    fn current(&self, paths: &BoxPaths) -> Result<Current, String> {
        let mut base = crate::box_repo::read_base_manifest(paths)?;
        let ns = land_numbers(paths)?;
        let mut unadvanced = None;
        for &n in &ns {
            let Some(a) =
                read_json::<Approved>(&paths.land_approved(n), "approved land", RECORD_MAX)?
            else {
                continue;
            };
            let r: Review = read_json(&paths.land_review(n), "land review", REVIEW_MAX)?
                .ok_or_else(|| format!("approved land {n} has no review"))?;
            if r.n != n || a.n != n {
                return Err(format!("the records of land {n} name another export"));
            }
            let v = Valid {
                n,
                entries: r.entries,
            };
            base = apply_manifest(&base, &v, a.only.as_ref());
            let advanced = exists(&paths.land_advanced(n)).map_err(|e| e.to_string())?;
            unadvanced = (!advanced).then_some((n, a.only));
        }
        Ok(Current {
            base,
            highest: ns.last().copied().unwrap_or(0),
            unadvanced,
        })
    }

    /// The guest takes land `n` (`only`'s paths of it) into its base; on
    /// success `advanced.json` says so.
    fn advance(
        &self,
        id: &BoxId,
        paths: &BoxPaths,
        n: u32,
        only: Option<&BTreeSet<String>>,
    ) -> Result<(), String> {
        let req = Request::Advance {
            n,
            paths: only.map(|o| o.iter().cloned().collect()),
        };
        match self.guest.request(id, &req, ADVANCE_TIMEOUT) {
            Ok(Reply::Ok) => {}
            Ok(Reply::Err { why }) => {
                return Err(format!("the guest refused: {}", guest_text(&why)))
            }
            Err(e) => return Err(guest_text(&BoxError::from(e).to_string())),
        }
        let body = serde_json::json!({"advanced_at": (self.clock)()}).to_string();
        match write_new(&paths.land_advanced(n), body.as_bytes()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(format!("cannot record the advance: {e}")),
        }
    }

    /// Export, validate, render and cache the box's diff against its
    /// current base. A box whose VM is off answers its cached review, or
    /// `Unavailable` ([`vm_off`]). A refused export is one `diff_rejected`
    /// record (a guest that is not connected is none), drops the cached
    /// review and stores nothing. A land the guest has not taken yet is
    /// advanced first.
    pub fn refresh(&self, id: &BoxId) -> Result<Review, BoxError> {
        let rec = self.mgr.get(id)?;
        if !rec.vm_on {
            return self.latest(id).ok_or_else(|| unavailable(vm_off(id)));
        }
        let ctx = self.ctx()?;
        let bl = self.box_lock(id);
        let _held = lock(&bl);
        let paths = self.paths(id);
        let cur = self
            .current(&paths)
            .map_err(|e| unavailable(format!("box {} has no reviewable base: {e}", id.as_str())))?;
        if let Some((n, only)) = &cur.unadvanced {
            self.advance(id, &paths, *n, only.as_ref())
                .map_err(|e| unavailable(format!("the box's base did not take land {n}: {e}")))?;
        }
        let n = {
            let mut st = lock(&self.state);
            let last = st.last_export.get(id).copied().unwrap_or(0);
            let n = cur
                .highest
                .max(last)
                .checked_add(1)
                .ok_or_else(|| unavailable("the box has no export numbers left"))?;
            st.last_export.insert(id.clone(), n);
            n
        };
        let v = match review::receive(&self.guest, id, &paths, &cur.base, n) {
            Ok(v) => v,
            Err(e) => {
                lock(&self.state).reviews.remove(id);
                let reason = e.to_string();
                if !(e.path.is_none() && e.reason == NOT_CONNECTED) {
                    let mut r = self.record(&ctx, "diff_rejected", id, None);
                    r.reason = Some(reason.clone());
                    r.extra.insert("reason".into(), reason.clone().into());
                    self.write(&ctx, r);
                }
                return Err(unavailable(reason));
            }
        };
        let hits = hits_for(&ctx, &rec);
        let rev = review::review(id, &cur.base, &v, &paths.land_blobs(n), None, &hits);
        review::write_land_files(&paths, &cur.base, &rev, None).map_err(unavailable)?;
        let mut st = lock(&self.state);
        if st
            .rejected
            .get(id)
            .is_some_and(|s| *s != rev.summary.diff_sha256)
        {
            st.rejected.remove(id);
        }
        st.reviews.insert(
            id.clone(),
            Arc::new(Cached {
                review: rev.clone(),
                base: cur.base,
            }),
        );
        Ok(rev)
    }

    /// A land request for box `id` (Done or Landed) by `owner`, over its
    /// latest review (refreshed when there is none), or the `only` paths of
    /// it (R-T1d: they must leave a valid tree). Issues
    /// `IssueKey::Land(request_id)` and writes `lands/<n>/request.json`.
    pub fn begin(
        &self,
        id: &BoxId,
        owner: u32,
        only: Option<BTreeSet<String>>,
        now: u64,
    ) -> Result<(u64, ActionRecord, Review), BoxError> {
        let ctx = self.ctx()?;
        let rec = self.mgr.get(id)?;
        if !matches!(rec.state, BoxState::Done | BoxState::Landed) {
            return Err(BoxError::WrongState { state: rec.state });
        }
        let cached = match self.cached(id) {
            Some(c) => c,
            None => {
                self.refresh(id)?;
                self.cached(id)
                    .ok_or_else(|| unavailable("the box's review is gone"))?
            }
        };
        let full = &cached.review;
        if full.summary.files.is_empty() {
            return Err(BoxError::Invalid(format!(
                "box {} has no changes to land",
                id.as_str()
            )));
        }
        let land = match &only {
            None => full.clone(),
            Some(o) => {
                let v = Valid {
                    n: full.n,
                    entries: full.entries.clone(),
                };
                review::check_subset(&cached.base, &v, Some(o))
                    .map_err(|e| BoxError::Invalid(review::escape(&e)))?;
                let hits = hits_for(&ctx, &rec);
                let blobs = self.paths(id).land_blobs(full.n);
                review::review(id, &cached.base, &v, &blobs, Some(o), &hits)
            }
        };
        let summary = summary(id, &land);
        let fields = fields(id, &cached.base, &land);
        let rid = {
            let mut st = lock(&self.state);
            let r = st.next_rid;
            st.next_rid = r.wrapping_add(1).max(1);
            r
        };
        let issued = ctx
            .touch
            .issue(
                IssueKey::Land(rid),
                owner,
                TouchClass::Land,
                summary.clone(),
                fields.clone(),
                now,
            )
            .map_err(unavailable)?;
        let record = ActionRecord {
            instance_id: ctx.touch.instance_id(),
            request_id: rid,
            class: TouchClass::Land,
            summary: summary.clone(),
            fields,
            nonce: issued.nonce,
            expires_at: issued.expires_at,
        };
        let req = LandRequest {
            request_id: rid,
            id: id.clone(),
            n: full.n,
            owner,
            only,
            diff_sha256: land.summary.diff_sha256.clone(),
            review_sha256: full.summary.diff_sha256.clone(),
            base_commit: land.summary.base_commit.clone(),
            target_ref: target_ref(id),
            repo: cached.base.repo.clone(),
            summary,
            created_at: now,
            expires_at: issued.expires_at,
        };
        let body = serde_json::to_vec_pretty(&req).map_err(|e| unavailable(e.to_string()))?;
        if let Err(e) = write_over(&self.paths(id).land_request(full.n), &body) {
            let _ = ctx.touch.take(&IssueKey::Land(rid), owner);
            return Err(unavailable(format!("cannot write the land request: {e}")));
        }
        lock(&self.state).requests.insert(
            rid,
            Req {
                req,
                record: record.clone(),
                review: land.clone(),
                decided: None,
            },
        );
        Ok((rid, record, land))
    }

    /// Approve request `rid` with the verified touch `ev` (`via`: "cli" or
    /// "web"): `approved.json`, the box to `Landed`, the guest's base
    /// advanced, a `land` record with the touch. One approval per request;
    /// a request that no longer names the box's latest review is
    /// `WrongState`.
    pub fn approve(
        &self,
        rid: u64,
        ev: &TouchEvidence,
        via: &'static str,
    ) -> Result<LandInfo, BoxError> {
        let ctx = self.ctx()?;
        let q = {
            let mut st = lock(&self.state);
            let q = st.requests.get_mut(&rid).ok_or(BoxError::NotFound)?;
            if q.decided.is_some() {
                let id = q.req.id.clone();
                drop(st);
                return Err(BoxError::WrongState {
                    state: self.state_of(&id),
                });
            }
            q.decided = Some(Decided::Approved);
            q.clone()
        };
        let id = q.req.id.clone();
        let bl = self.box_lock(&id);
        let _held = lock(&bl);
        let rec = self.mgr.get(&id)?;
        let wrong = || BoxError::WrongState { state: rec.state };
        if !self.is_current(rid) || !matches!(rec.state, BoxState::Done | BoxState::Landed) {
            return Err(wrong());
        }
        let cached = self.cached(&id).ok_or_else(wrong)?;
        let paths = self.paths(&id);
        let n = q.req.n;
        if let Some(o) = &q.req.only {
            review::write_land_files(&paths, &cached.base, &q.review, Some(o))
                .map_err(unavailable)?;
        }
        let approved = Approved {
            request_id: rid,
            id: id.clone(),
            n,
            only: q.req.only.clone(),
            diff_sha256: q.req.diff_sha256.clone(),
            base_commit: q.req.base_commit.clone(),
            base_sha256: cached.base.sha256(),
            target_ref: q.req.target_ref.clone(),
            via: via.into(),
            approved_at: (self.clock)(),
            task: rec.task.clone(),
            repo_dir: rec.repo_dir.clone(),
        };
        let body = serde_json::to_vec_pretty(&approved).map_err(|e| unavailable(e.to_string()))?;
        match write_new(&paths.land_approved(n), &body) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(wrong()),
            Err(e) => return Err(unavailable(format!("cannot record the approval: {e}"))),
        }
        if let Err(e) = self.mgr.land(&id) {
            // A failed save still moved the record in memory: keep the
            // approval then, as the manager does.
            let moved = self
                .mgr
                .get(&id)
                .is_ok_and(|r| r.lands == rec.lands.saturating_add(1));
            if !moved {
                let _ = fs::remove_file(paths.land_approved(n));
                return Err(e);
            }
        }
        {
            let mut st = lock(&self.state);
            st.reviews.remove(&id);
            st.rejected.remove(&id);
        }
        if let Err(e) = self.advance(&id, &paths, n, q.req.only.as_ref()) {
            eprintln!(
                "saiifed: boxes: box {} did not take land {n} into its base (retried before its next export): {e}",
                id.as_str()
            );
        }
        let mut r = self.record(&ctx, "land", &id, Some(q.req.owner));
        let x = &mut r.extra;
        x.insert("land".into(), n.into());
        x.insert("request".into(), rid.to_string().into());
        x.insert("diff_sha256".into(), q.req.diff_sha256.clone().into());
        x.insert("files".into(), q.review.summary.files.len().into());
        x.insert("via".into(), via.into());
        x.insert("target_ref".into(), q.req.target_ref.clone().into());
        self.write(&ctx, crate::approvals::record_with_touch(r, ev));
        Ok(LandInfo {
            id: id.clone(),
            n,
            target_ref: q.req.target_ref,
            base_commit: q.req.base_commit,
            diff_sha256: q.req.diff_sha256,
            task: rec.task,
            repo_dir: rec.repo_dir,
        })
    }

    /// Reject request `rid` (`via`: "cli" or "web"): a `land_rejected`
    /// record; the box keeps its state and that review is not offered again.
    pub fn reject(&self, rid: u64, via: &'static str) -> Result<(), BoxError> {
        let ctx = self.ctx()?;
        let q = {
            let mut st = lock(&self.state);
            let q = st.requests.get_mut(&rid).ok_or(BoxError::NotFound)?;
            if q.decided.is_some() {
                let id = q.req.id.clone();
                drop(st);
                return Err(BoxError::WrongState {
                    state: self.state_of(&id),
                });
            }
            q.decided = Some(Decided::Rejected);
            let q = q.clone();
            st.rejected
                .insert(q.req.id.clone(), q.req.review_sha256.clone());
            q
        };
        let mut r = self.record(&ctx, "land_rejected", &q.req.id, Some(q.req.owner));
        r.extra.insert("land".into(), q.req.n.into());
        r.extra.insert("request".into(), rid.to_string().into());
        r.extra.insert("via".into(), via.into());
        self.write(&ctx, r);
        Ok(())
    }

    /// The CLI wrote land `n`'s commit: `applied.json` and a
    /// `land_applied` record, once.
    pub fn applied(&self, id: &BoxId, n: u32, commit: &str) -> Result<(), BoxError> {
        let ctx = self.ctx()?;
        let rec = self.mgr.get(id)?;
        if !is_oid(commit) {
            return Err(BoxError::Invalid("commit must be a git commit id".into()));
        }
        let paths = self.paths(id);
        let bl = self.box_lock(id);
        let _held = lock(&bl);
        let approved: Option<Approved> =
            read_json(&paths.land_approved(n), "approved land", RECORD_MAX).map_err(unavailable)?;
        if approved.is_none() {
            return Err(BoxError::Invalid(format!(
                "land {n} of box {} is not approved",
                id.as_str()
            )));
        }
        let body = serde_json::to_vec_pretty(&Applied {
            commit: commit.into(),
            applied_at: (self.clock)(),
        })
        .map_err(|e| unavailable(e.to_string()))?;
        match write_new(&paths.land_applied(n), &body) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(BoxError::Invalid(format!(
                    "land {n} of box {} is already applied",
                    id.as_str()
                )))
            }
            Err(e) => return Err(unavailable(format!("cannot record the apply: {e}"))),
        }
        let mut r = self.record(&ctx, "land_applied", id, Some(rec.owner_uid));
        r.extra.insert("land".into(), n.into());
        r.extra.insert("commit".into(), commit.into());
        self.write(&ctx, r);
        Ok(())
    }

    /// The box's approved lands without `applied.json`, in land order.
    pub fn approved_unapplied(&self, id: &BoxId) -> Vec<LandInfo> {
        let paths = self.paths(id);
        let Ok(ns) = land_numbers(&paths) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for n in ns {
            let Ok(Some(a)) =
                read_json::<Approved>(&paths.land_approved(n), "approved land", RECORD_MAX)
            else {
                continue;
            };
            if exists(&paths.land_applied(n)).unwrap_or(true) || a.n != n {
                continue;
            }
            out.push(LandInfo {
                id: id.clone(),
                n,
                target_ref: a.target_ref,
                base_commit: a.base_commit,
                diff_sha256: a.diff_sha256,
                task: a.task,
                repo_dir: a.repo_dir,
            });
        }
        out
    }

    /// The pending action of a live request.
    fn action(q: &Req) -> PendingAction {
        PendingAction {
            request_id: q.req.request_id,
            class: TouchClass::Land,
            box_id: Some(q.req.id.clone()),
            summary: q.record.summary.clone(),
            record: q.record.clone(),
            created_at: q.req.created_at,
            expires_at: q.record.expires_at,
        }
    }
}

impl LandBook for Lands {
    /// The cached review, else a fresh one.
    fn diff(&self, id: &BoxId) -> Result<DiffSummary, BoxError> {
        self.mgr.get(id)?;
        match self.latest(id) {
            Some(r) => Ok(r.summary),
            None => self.refresh(id).map(|r| r.summary),
        }
    }

    /// Per owner, the [`PENDING_PER_OWNER`] oldest `Done` boxes whose
    /// cached review has changes and was not rejected: each one's live
    /// whole-review request, or a new one (a request past its expiry is
    /// issued again under a new id).
    fn pending(&self) -> Vec<PendingAction> {
        let now = (self.clock)();
        let mut done: Vec<BoxRecord> = self
            .mgr
            .list()
            .into_iter()
            .filter(|r| r.state == BoxState::Done)
            .collect();
        done.sort_by(|a, b| {
            (a.owner_uid, a.updated_at, &a.id).cmp(&(b.owner_uid, b.updated_at, &b.id))
        });
        let mut want: Vec<(BoxRecord, Option<PendingAction>)> = Vec::new();
        {
            let mut st = lock(&self.state);
            let live: BTreeSet<BoxId> = self.mgr.list().into_iter().map(|r| r.id).collect();
            st.reviews.retain(|k, _| live.contains(k));
            st.rejected.retain(|k, _| live.contains(k));
            st.requests.retain(|_, q| live.contains(&q.req.id));
            let mut per: BTreeMap<u32, usize> = BTreeMap::new();
            for r in done {
                let Some(c) = st.reviews.get(&r.id) else {
                    continue;
                };
                let sha = c.review.summary.diff_sha256.clone();
                if c.review.summary.files.is_empty() || st.rejected.get(&r.id) == Some(&sha) {
                    continue;
                }
                let k = per.entry(r.owner_uid).or_default();
                if *k >= PENDING_PER_OWNER {
                    continue;
                }
                *k += 1;
                // Undecided whole requests of this box past their expiry
                // are gone with their touch entry.
                st.requests.retain(|_, q| {
                    !(q.req.id == r.id && q.decided.is_none() && q.record.expires_at < now)
                });
                let have = st
                    .requests
                    .values()
                    .filter(|q| {
                        q.req.id == r.id
                            && q.decided.is_none()
                            && q.req.only.is_none()
                            && q.req.owner == r.owner_uid
                            && q.req.review_sha256 == sha
                    })
                    .max_by_key(|q| q.req.request_id)
                    .map(Self::action);
                want.push((r, have));
            }
        }
        let mut out = Vec::new();
        for (r, have) in want {
            match have {
                Some(p) => out.push(p),
                None => {
                    if let Ok((rid, _, _)) = self.begin(&r.id, r.owner_uid, None, now) {
                        if let Some(q) = lock(&self.state).requests.get(&rid) {
                            out.push(Self::action(q));
                        }
                    }
                }
            }
        }
        out
    }

    /// Approve (with the touch plan 31 verified) or reject request
    /// `request_id`; either burns the CLI's challenge for it.
    fn complete(
        &self,
        request_id: u64,
        d: Decision,
        ev: Option<TouchEvidence>,
    ) -> Result<(), BoxError> {
        let (id, owner, decided) = {
            let st = lock(&self.state);
            let q = st.requests.get(&request_id).ok_or(BoxError::NotFound)?;
            (q.req.id.clone(), q.req.owner, q.decided)
        };
        let ctx = self.ctx()?;
        match (d, ev) {
            (Decision::Approve, None) => Err(BoxError::Invalid(
                "an approval needs the touch evidence".into(),
            )),
            (Decision::Reject, Some(_)) => Err(BoxError::Invalid(
                "a rejection takes no touch evidence".into(),
            )),
            (Decision::Approve, Some(ev)) => {
                if decided.is_some() || !self.is_current(request_id) {
                    return Err(BoxError::WrongState {
                        state: self.state_of(&id),
                    });
                }
                let _ = ctx.touch.take(&IssueKey::Land(request_id), owner);
                self.approve(request_id, &ev, "web").map(|_| ())
            }
            (Decision::Reject, None) => {
                self.reject(request_id, "web")?;
                let _ = ctx.touch.take(&IssueKey::Land(request_id), owner);
                Ok(())
            }
        }
    }

    fn unapplied(&self, id: &BoxId) -> u32 {
        u32::try_from(self.approved_unapplied(id).len()).unwrap_or(u32::MAX)
    }

    fn box_of(&self, request_id: u64) -> Option<BoxId> {
        lock(&self.state)
            .requests
            .get(&request_id)
            .map(|q| q.req.id.clone())
    }
}

/// The `{land: LandInfo}` answer (R20).
pub fn land_answer(l: &LandInfo) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert(
        "land".into(),
        serde_json::to_value(l).unwrap_or(Value::Null),
    );
    m
}
