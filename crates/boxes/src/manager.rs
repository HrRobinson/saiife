//! The box manager (spec §7.6, §7.7): the queue, admission, the lifecycle,
//! guest events, the periodic tick, recovery after a daemon restart and gc.
//!
//! One `Mutex` guards every record and every `Store` call (the store is
//! single-writer by contract). It is held across VMM calls, which the trait
//! contract bounds to about a second, but never across a guest call: a
//! prompt's timing is the guest's, so it is taken out under the lock, sent
//! with the lock released and its outcome recorded under the lock again
//! (only while the box's send is still the one in flight). Time comes from
//! the injected [`Clock`]; the manager never reads the system clock.
//!
//! Each state change is saved before the method returns. Two saves come
//! before any VMM work and are strict: spawn's first save (on failure the
//! claimed dir is removed, nothing stays in memory and the error is
//! returned) and admission's save of the Starting record (on failure the box
//! stays Queued, no VM is created and the pass stops). Every later save
//! follows a VMM call that already happened, so the in-memory record keeps
//! following the VMM even when the save fails: the caller-facing methods
//! return that error as `Unavailable`, while the tick and the admission pass
//! (which return only changes) are best effort and retry on the next save.
//!
//! A Discarded record whose `vm` is still `Some` means the VMM resource may
//! still exist (its destroy failed, for instance a VMM still stopping: a
//! driver's destroy is bounded and does not wait out its stop ladder, R41).
//! The tick retries the destroy and clears `vm` once it succeeds; gc also
//! retries it before removing the record. Each tick retry that fails backs
//! that record off (R44): the next try waits [`DESTROY_RETRY_FIRST_SECS`],
//! doubling to at most [`DESTROY_RETRY_MAX_SECS`], so a VMM that never
//! confirms its exit does not cost every tick a second of the lock. The
//! backoff is in memory only and never treats the VM as gone.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use saiife_wire::source::{
    check_text, BoxError, BoxId, BoxState, Start, MAX_STEER_BYTES, MAX_TASK_BYTES,
};
pub use saiife_wire::source::{HELD_PROMPT_SENT_FIRST, MAX_REVISED_PROMPT_BYTES};

use crate::capacity::{self, Committed, HostFacts};
use crate::error::BoxesError;
use crate::guest::{GuestError, GuestEvent, GuestLink};
use crate::state::{holds_capacity, transition, Event};
use crate::store::{BoxRecord, Store};
use crate::template::{
    BoxTemplate, ImageRef, Login, SUBSCRIPTION_GATED, SUBSCRIPTION_LOGIN_CLEARED,
};
use crate::vmm::{VmSpec, VmStatus, Vmm, VmmError};

/// No `Ready` this long after admission → the boot failed.
pub const BOOT_TIMEOUT_SECS: u64 = 90;
/// The `why` (and error) of a box the boot timeout ended.
pub const WHY_BOOT_TIMED_OUT: &str = "boot timed out";
/// A finished turn with no activity for this long → `Done`.
pub const DONE_IDLE_SECS: u64 = 30;
/// R44: the tick's first wait before retrying a destroy that failed
/// again (one daemon tick); it doubles after each failure.
pub const DESTROY_RETRY_FIRST_SECS: u64 = 5;
/// R44: the cap on that wait.
pub const DESTROY_RETRY_MAX_SECS: u64 = 300;
/// Idle stop for a box whose template was deleted.
pub const DEFAULT_IDLE_STOP_MINS: u32 = 120;
/// Longest repo name accepted at spawn.
pub const MAX_REPO_BYTES: usize = 256;
const PAIR: &str = "a repo disk and its base manifest come together, or neither";
const NOT_INCOMING: &str =
    "the repo disk and its base manifest must be in one dir of the box store's .incoming";
const CREDENTIAL_IN_BOX: &str =
    "credential_in_box is not supported: the real credential never enters the box";
const NO_PLACER: &str = "this box manager takes no repo disk";
const NOT_IN_BOX: &str = "the repo disk's place is not in the box dir";

const RECORD_VERSION: u32 = 1;
const LOST: &str = "the VM was gone after a daemon restart";
/// The `why` of a restart's changes (R29).
pub const WHY_LOST: &str = "vm lost after restart";
pub const WHY_RECONCILED: &str = "reconciled";
const REORDER: &str = "reorder must list every queued box once";
const PROMPT_NOT_DELIVERED: &str = "the box's prompt is not delivered yet; steer again once it is";
/// A paused box sends its held prompt only once it runs again.
const PROMPT_HELD_PAUSED: &str =
    "the box's prompt is not delivered yet; resume the box first, then steer again";

/// Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;
/// A live sample of the host.
pub type HostProbe = Arc<dyn Fn() -> HostFacts + Send + Sync>;

/// Where spawn moves a box's repo disk and its base manifest (plan 37).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskPlace {
    pub repo_image: PathBuf,
    pub base_manifest: PathBuf,
}

/// `(store root, box id)` to the [`DiskPlace`] of that box. The manager
/// never names these files itself: the daemon's placer comes from its
/// layout helpers (`saiife_boxhost::paths::BoxPaths`). Both places must be
/// in the box dir (`<root>/<id>`), where the move is directory-relative.
pub type DiskPlacer = Arc<dyn Fn(&Path, &BoxId) -> DiskPlace + Send + Sync>;

pub struct ManagerInit {
    pub store: Store,
    pub vmm: Arc<dyn Vmm>,
    pub guest: Arc<dyn GuestLink>,
    pub templates: Vec<BoxTemplate>,
    pub host: HostProbe,
    pub clock: Clock,
    /// Where a spawn's repo disk goes; `None`: a spawn with one is
    /// `Unavailable`.
    pub disk_place: Option<DiskPlacer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnArgs {
    pub template: String,
    pub repo: String,
    pub repo_dir: Option<String>,
    pub task: String,
    pub start: Start,
    pub owner_uid: u32,
    /// A repo disk image (plan 37) in `<store root>/.incoming/<dir>/`;
    /// spawn moves it to its [`DiskPlace`] before admission.
    pub repo_image: Option<PathBuf>,
    /// The base manifest of that disk, in the same dir; it goes to its
    /// [`DiskPlace`] too. Both or neither.
    pub base_manifest: Option<PathBuf>,
}

/// One state change, for the audit log. `from == to` is a change too when the
/// VM turned off (idle stop of a done box) or a stop was idempotent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub id: BoxId,
    pub from: BoxState,
    pub to: BoxState,
    pub why: &'static str,
    /// The base image id (plan 36): the admission change of a box whose
    /// VM was created names it; every other change has `None`.
    pub image: Option<String>,
}

/// What gc did. It goes on past a box it cannot remove: `removed` is every
/// id it did remove, `error` the first failure (R31).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GcReport {
    pub removed: Vec<BoxId>,
    pub error: Option<String>,
}

/// What [`Manager::open`] made: the manager, the warnings (the store's plus
/// one per recovered box) and the recovery's state changes, for the audit
/// log (R29).
pub struct Opened {
    pub manager: Manager,
    pub warnings: Vec<String>,
    pub changes: Vec<Change>,
}

struct Inner {
    store: Store,
    records: BTreeMap<BoxId, BoxRecord>,
    next_seq: u64,
    /// Ids claimed by a spawn that is moving its repo disk in, outside the
    /// lock: their dirs have no record yet, and gc must not take them for
    /// orphans.
    placing: BTreeSet<BoxId>,
    /// Boxes with a prompt out to the guest (sent with the lock released),
    /// each with its send's token. One at a time per box; a requeue or a
    /// discard drops the entry, so a late outcome changes nothing.
    prompting: BTreeMap<BoxId, u64>,
    next_token: u64,
    /// R44: the tick's destroy backoff of each Discarded record that still
    /// holds a VM and whose retry failed. In memory only: after a restart
    /// the first tick retries at once.
    retries: BTreeMap<BoxId, Backoff>,
}

/// A destroy the tick retried and that failed again (R44).
struct Backoff {
    /// Tick retries that failed in a row.
    fails: u32,
    /// The tick skips the record before this.
    next_at: u64,
}

impl Backoff {
    /// Whether the tick retries now. A clock set back past the longest
    /// wait counts as due, so it never stretches a wait.
    fn due(&self, now: u64) -> bool {
        now >= self.next_at || self.next_at - now > DESTROY_RETRY_MAX_SECS
    }

    /// One more failure at `now`: the wait is `DESTROY_RETRY_FIRST_SECS`
    /// doubled for each earlier failure, at most `DESTROY_RETRY_MAX_SECS`.
    fn failed(prev: Option<&Backoff>, now: u64) -> Backoff {
        let fails = prev.map_or(0, |b| b.fails).saturating_add(1);
        let wait = DESTROY_RETRY_FIRST_SECS
            .saturating_mul(1 << (fails - 1).min(32))
            .min(DESTROY_RETRY_MAX_SECS);
        Backoff {
            fails,
            next_at: now.saturating_add(wait),
        }
    }
}

/// A prompt taken out under the lock, to send once it is released.
struct Outgoing {
    id: BoxId,
    text: String,
    token: u64,
}

impl Inner {
    fn get(&self, id: &BoxId) -> Result<&BoxRecord, BoxError> {
        self.records.get(id).ok_or(BoxError::NotFound)
    }

    /// Keep `r` in memory and save it.
    fn put(&mut self, r: BoxRecord) -> Result<(), BoxError> {
        let saved = self.store.save(&r);
        self.records.insert(r.id.clone(), r);
        saved.map_err(BoxError::from)
    }

    /// Save `r`, and keep it in memory only when the save worked.
    fn save_new(&mut self, r: BoxRecord) -> Result<(), BoxError> {
        self.store.save(&r)?;
        self.records.insert(r.id.clone(), r);
        Ok(())
    }

    fn committed(&self) -> Committed {
        let mut c = Committed::default();
        for r in self.records.values() {
            if holds_capacity(r.state, r.vm_on) {
                c.mem_mib = c.mem_mib.saturating_add(capacity::charge_mib(&r.size));
                c.vcpus = c.vcpus.saturating_add(r.size.vcpus);
            }
        }
        c
    }

    /// Queued ids, head first.
    fn queue(&self) -> Vec<BoxId> {
        let mut q: Vec<&BoxRecord> = self
            .records
            .values()
            .filter(|r| r.state == BoxState::Queued)
            .collect();
        q.sort_by(|a, b| (a.queue_seq, &a.id).cmp(&(b.queue_seq, &b.id)));
        q.into_iter().map(|r| r.id.clone()).collect()
    }

    fn take_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        s
    }

    /// Marks a send to `id` in flight; `None` while one already is.
    fn claim_send(&mut self, id: &BoxId) -> Option<u64> {
        if self.prompting.contains_key(id) {
            return None;
        }
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        self.prompting.insert(id.clone(), token);
        Some(token)
    }

    /// Ends the send `token` to `id`: `true` when it was still the box's
    /// send in flight (nothing requeued or discarded the box meanwhile).
    fn end_send(&mut self, id: &BoxId, token: u64) -> bool {
        if self.prompting.get(id) == Some(&token) {
            self.prompting.remove(id);
            true
        } else {
            false
        }
    }

    /// `r`'s pending prompt, to send with the lock released. It stays in
    /// the record (and on disk) until the send's outcome is recorded.
    fn claim_pending(&mut self, r: &BoxRecord) -> Option<Outgoing> {
        let text = r.pending_prompt.clone()?;
        let token = self.claim_send(&r.id)?;
        Some(Outgoing {
            id: r.id.clone(),
            text,
            token,
        })
    }
}

pub struct Manager {
    inner: Mutex<Inner>,
    /// The store root, for the work done outside the lock.
    root: PathBuf,
    vmm: Arc<dyn Vmm>,
    guest: Arc<dyn GuestLink>,
    templates: Vec<BoxTemplate>,
    host: HostProbe,
    clock: Clock,
    disk_place: Option<DiskPlacer>,
}

fn change(r: &BoxRecord, from: BoxState, why: &'static str) -> Change {
    Change {
        id: r.id.clone(),
        from,
        to: r.state,
        why,
        image: None,
    }
}

fn vmm_msg(e: VmmError) -> String {
    match e {
        VmmError::Unavailable(m) | VmmError::Failed(m) => m,
    }
}

fn guest_msg(e: GuestError) -> String {
    match BoxError::from(e) {
        BoxError::Unavailable(m) => m,
        other => other.to_string(),
    }
}

/// Plan 28's overview order: running, paused, done, queued, starting, the rest.
fn rank(s: BoxState) -> u8 {
    match s {
        BoxState::Running => 0,
        BoxState::Paused => 1,
        BoxState::Done => 2,
        BoxState::Queued => 3,
        BoxState::Starting => 4,
        _ => 5,
    }
}

impl Manager {
    /// Load the store and recover: every record whose VM was on, and every
    /// Starting record with a VM handle, is checked against the VMM.
    pub fn open(init: ManagerInit) -> Result<Opened, BoxesError> {
        let (loaded, mut warns) = init.store.list()?;
        let now = (init.clock)();
        let root = init.store.root().to_path_buf();
        let mut inner = Inner {
            store: init.store,
            records: BTreeMap::new(),
            next_seq: 1,
            placing: BTreeSet::new(),
            prompting: BTreeMap::new(),
            next_token: 0,
            retries: BTreeMap::new(),
        };
        let mut max_seq = 0;
        let mut changes = Vec::new();
        for mut r in loaded {
            if let Some(s) = r.queue_seq {
                max_seq = max_seq.max(s);
            }
            let from = r.state;
            if let Some((note, why)) = recover(init.vmm.as_ref(), &mut r) {
                r.updated_at = now;
                if let Err(e) = inner.store.save(&r) {
                    warns.push(format!("{}: {e}", r.id.as_str()));
                }
                warns.push(format!("{}: {note}", r.id.as_str()));
                changes.push(change(&r, from, why));
            }
            inner.records.insert(r.id.clone(), r);
        }
        inner.next_seq = max_seq.saturating_add(1);
        // A queued record without a position joins the tail.
        let unplaced: Vec<BoxId> = inner
            .records
            .values()
            .filter(|r| r.state == BoxState::Queued && r.queue_seq.is_none())
            .map(|r| r.id.clone())
            .collect();
        for id in unplaced {
            let mut r = inner.records[&id].clone();
            r.queue_seq = Some(inner.take_seq());
            r.updated_at = now;
            if let Err(e) = inner.put(r) {
                warns.push(format!("{}: {e}", id.as_str()));
            }
        }
        let mgr = Manager {
            inner: Mutex::new(inner),
            root,
            vmm: init.vmm,
            guest: init.guest,
            templates: init.templates,
            host: init.host,
            clock: init.clock,
            disk_place: init.disk_place,
        };
        Ok(Opened {
            manager: mgr,
            warnings: warns,
            changes,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Remove the dir of `id`, claimed by a spawn that failed before its
    /// record was saved. The dir may hold a repo disk of many GiB, so the
    /// removal runs outside the lock: `id` is kept in `placing` meanwhile
    /// (gc leaves it alone; the id counter never hands it out again), and
    /// cleared once the lock is taken back.
    fn release(&self, mut g: MutexGuard<'_, Inner>, id: &BoxId) {
        g.placing.insert(id.clone());
        let store = g.store.clone();
        drop(g);
        let _ = store.remove(id);
        self.lock().placing.remove(id);
    }

    /// The box store's root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `(dir, image name, manifest name)` of a repo disk spawn takes: both
    /// files in one dir right under `<root>/.incoming`.
    fn incoming<'a>(
        &self,
        image: &'a Path,
        manifest: &'a Path,
    ) -> Result<(&'a OsStr, &'a OsStr, &'a OsStr), BoxError> {
        let bad = || BoxError::Invalid(NOT_INCOMING.into());
        let inc = self.root.join(crate::place::INCOMING);
        let split = |p: &'a Path| -> Option<(&'a OsStr, &'a OsStr)> {
            let name = p.file_name()?;
            let dir = p.parent()?;
            (dir.parent()? == inc).then_some((dir.file_name()?, name))
        };
        let (d1, image) = split(image).ok_or_else(bad)?;
        let (d2, manifest) = split(manifest).ok_or_else(bad)?;
        if d1 != d2 || image == manifest {
            return Err(bad());
        }
        Ok((d1, image, manifest))
    }

    /// The names of `to` in the box dir `dir`: both right in it, and two.
    fn names_in<'a>(dir: &Path, to: &'a DiskPlace) -> Option<(&'a OsStr, &'a OsStr)> {
        let name = |p: &'a Path| {
            if p.parent()? == dir {
                p.file_name()
            } else {
                None
            }
        };
        let (i, m) = (name(&to.repo_image)?, name(&to.base_manifest)?);
        (i != m).then_some((i, m))
    }

    /// Whether a `Start::Now` spawn must be refused.
    fn now_busy(g: &Inner, host: &HostFacts, size: &crate::template::Size) -> bool {
        !g.queue().is_empty() || capacity::admit(host, &g.committed(), size).is_err()
    }

    fn template(&self, name: &str) -> Option<&BoxTemplate> {
        self.templates.iter().find(|t| t.name == name)
    }

    fn idle_stop_secs(&self, template: &str) -> u64 {
        let mins = self
            .template(template)
            .map_or(DEFAULT_IDLE_STOP_MINS, |t| t.idle_stop_mins);
        u64::from(mins) * 60
    }

    /// The guest channel, for the box source's terminal and diff reads. The
    /// call is made outside the manager's lock.
    pub fn guest(&self) -> Arc<dyn GuestLink> {
        self.guest.clone()
    }

    pub fn templates(&self) -> Vec<BoxTemplate> {
        self.templates.clone()
    }

    pub fn get(&self, id: &BoxId) -> Result<BoxRecord, BoxError> {
        self.lock().get(id).cloned()
    }

    /// Plan 28's overview order; queued boxes by queue position; ties by id.
    pub fn list(&self) -> Vec<BoxRecord> {
        let g = self.lock();
        let pos: BTreeMap<BoxId, usize> = g
            .queue()
            .into_iter()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect();
        let mut out: Vec<BoxRecord> = g.records.values().cloned().collect();
        out.sort_by_key(|r| (rank(r.state), pos.get(&r.id).copied(), r.id.clone()));
        out
    }

    pub fn queue(&self) -> Vec<BoxId> {
        self.lock().queue()
    }

    /// 1-based position in the queue.
    pub fn queue_pos(&self, id: &BoxId) -> Option<u32> {
        let q = self.lock().queue();
        let i = q.iter().position(|q| q == id)?;
        u32::try_from(i + 1).ok()
    }

    pub fn capacity(&self) -> (HostFacts, Committed) {
        let host = (self.host)();
        (host, self.lock().committed())
    }

    pub fn spawn(&self, a: &SpawnArgs) -> Result<BoxRecord, BoxError> {
        self.spawn_changes(a).map(|(r, _)| r)
    }

    /// `spawn`, plus every change the admission pass made: the new box's own
    /// admission and any earlier queue heads it admitted (or discarded on a
    /// boot failure), which may belong to other owners. The audit log needs
    /// those, since the tick never sees them.
    ///
    /// With a repo disk the id is claimed under the lock, the lock let go
    /// while the disk and manifest are renamed into the box dir (gc leaves
    /// that id alone meanwhile), and taken again to save the record and
    /// admit. A rename error releases the id's dir and is `Unavailable`.
    pub fn spawn_changes(&self, a: &SpawnArgs) -> Result<(BoxRecord, Vec<Change>), BoxError> {
        let disk = match (&a.repo_image, &a.base_manifest) {
            (None, None) => None,
            (Some(i), Some(m)) => Some(self.incoming(i, m)?),
            _ => return Err(BoxError::Invalid(PAIR.into())),
        };
        if disk.is_some() && self.disk_place.is_none() {
            return Err(BoxError::Unavailable(NO_PLACER.into()));
        }
        if !a.task.is_empty() {
            check_text(&a.task, MAX_TASK_BYTES)?;
        }
        check_text(&a.repo, MAX_REPO_BYTES)?;
        let t = self
            .template(&a.template)
            .ok_or_else(|| BoxError::Invalid(format!("unknown template {}", a.template)))?;
        // Before any id is claimed (plan 40 C4, ruling R3).
        if t.login == Login::Subscription && !SUBSCRIPTION_LOGIN_CLEARED {
            return Err(BoxError::Invalid(SUBSCRIPTION_GATED.into()));
        }
        if t.credential_in_box {
            return Err(BoxError::Invalid(CREDENTIAL_IN_BOX.into()));
        }
        let size = t.size;
        let host = (self.host)();
        capacity::fits_ever(&host, &size).map_err(|r| BoxError::Invalid(r.message()))?;
        let now = self.now();
        let mut g = self.lock();
        if a.start == Start::Now && Self::now_busy(&g, &host, &size) {
            return Err(BoxError::Busy);
        }
        let id = g.store.claim_id()?;
        if let (Some((sub, image, manifest)), Some(placer)) = (disk, &self.disk_place) {
            g.placing.insert(id.clone());
            let dir = g.store.box_dir(&id);
            drop(g);
            let to = placer(&self.root, &id);
            let moved = match Self::names_in(&dir, &to) {
                Some((ti, tm)) => crate::place::place(
                    &self.root,
                    id.as_str(),
                    sub,
                    &[(image, ti), (manifest, tm)],
                ),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    NOT_IN_BOX,
                )),
            };
            g = self.lock();
            let refused = match moved {
                Err(e) => Some(BoxError::Unavailable(format!(
                    "cannot move the repo disk into the box: {e}"
                ))),
                // Another spawn may have taken the room meanwhile.
                Ok(()) if a.start == Start::Now && Self::now_busy(&g, &host, &size) => {
                    Some(BoxError::Busy)
                }
                Ok(()) => None,
            };
            if let Some(e) = refused {
                // Still in `placing`: the dir (and the disk moved into it)
                // goes outside the lock.
                self.release(g, &id);
                return Err(e);
            }
            g.placing.remove(&id);
        }
        let seq = g.take_seq();
        let r = BoxRecord {
            version: RECORD_VERSION,
            session: format!("box-{}", id.as_str()),
            id: id.clone(),
            state: BoxState::Queued,
            owner_uid: a.owner_uid,
            template: t.name.clone(),
            size,
            repo: a.repo.clone(),
            repo_dir: a.repo_dir.clone(),
            task: a.task.clone(),
            created_at: now,
            started_at: None,
            updated_at: now,
            queue_seq: Some(seq),
            vm: None,
            vm_on: false,
            keep: false,
            lands: 0,
            last_activity: now,
            turn_finished_at: None,
            pending_prompt: (!a.task.is_empty()).then(|| a.task.clone()),
            error: None,
            image: None,
        };
        if let Err(e) = g.save_new(r) {
            self.release(g, &id);
            return Err(e);
        }
        let changes = self.admission(&mut g, &host, now);
        Ok((g.get(&id)?.clone(), changes))
    }

    /// Admit queue heads while they fit (strict FIFO: a head that does not
    /// fit blocks the rest). A VMM error discards the box and goes on.
    fn admission(&self, g: &mut Inner, host: &HostFacts, now: u64) -> Vec<Change> {
        let mut out = Vec::new();
        while let Some(head) = g.queue().into_iter().next() {
            let mut r = g.records[&head].clone();
            if capacity::admit(host, &g.committed(), &r.size).is_err() {
                break;
            }
            let from = r.state;
            let Ok(to) = transition(from, Event::Admit) else {
                break;
            };
            r.state = to;
            r.queue_seq = None;
            r.started_at = Some(now);
            r.last_activity = now;
            r.turn_finished_at = None;
            r.error = None;
            r.updated_at = now;
            // Saved before the VM exists: a failed save leaves the box
            // Queued and stops the pass. The handle is saved right after
            // `create` and before `boot`, so a crash after `create` leaves a
            // Starting record that names its VM, and the boot timeout stops
            // and destroys it (recovery marks it on when the VMM says it
            // runs). A crash inside `create` itself can still leave a VMM
            // resource no record names.
            if g.save_new(r.clone()).is_err() {
                break;
            }
            let admitted = out.len();
            out.push(change(&r, from, "admitted"));
            let spec = VmSpec {
                id: r.id.clone(),
                size: r.size,
                image: self
                    .template(&r.template)
                    .map_or(ImageRef::Default, |t| t.image.clone()),
                dir: g.store.box_dir(&r.id),
            };
            let booted = self.vmm.create(&spec).and_then(|h| {
                r.vm = Some(h.clone());
                // The driver names the base image; the handle's data stays
                // opaque here (plan 36).
                r.image = self.vmm.image_id(&h);
                out[admitted].image = r.image.clone();
                // Best effort, like every save after a VMM call.
                let _ = g.put(r.clone());
                self.vmm.boot(&h)
            });
            match booted {
                Ok(()) => r.vm_on = true,
                Err(e) => {
                    let from = r.state;
                    let msg = format!("boot failed: {}", vmm_msg(e));
                    self.boot_failed(&mut r, msg, false);
                    out.push(change(&r, from, "boot failed"));
                }
            }
            r.updated_at = now;
            let _ = g.put(r);
        }
        out
    }

    /// Starting → Discarded with `error = why`: the VM is (stopped and)
    /// destroyed; a failed teardown is appended to the error and keeps `vm`
    /// set for gc to retry.
    fn boot_failed(&self, r: &mut BoxRecord, why: String, stop_first: bool) {
        let mut why = why;
        if let Some(h) = r.vm.clone() {
            if stop_first {
                if let Err(e) = self.vmm.stop(&h) {
                    why.push_str(&format!("; stop failed: {}", vmm_msg(e)));
                }
            }
            match self.vmm.destroy(&h) {
                Ok(()) => r.vm = None,
                Err(e) => why.push_str(&format!("; destroy failed: {}", vmm_msg(e))),
            }
        }
        r.state = transition(r.state, Event::BootFailed).unwrap_or(BoxState::Discarded);
        r.vm_on = false;
        r.error = Some(why);
    }

    /// Stop (when on) and destroy a box's VM; `vm` becomes `None` on success.
    fn teardown(&self, r: &mut BoxRecord) -> Result<(), String> {
        let Some(h) = r.vm.clone() else {
            return Ok(());
        };
        if r.vm_on {
            self.vmm.stop(&h).map_err(vmm_msg)?;
            r.vm_on = false;
        }
        self.vmm.destroy(&h).map_err(vmm_msg)?;
        r.vm = None;
        Ok(())
    }

    pub fn pause(&self, id: &BoxId) -> Result<Change, BoxError> {
        self.vm_step(id, Event::Pause, "pause", None, |v, h| v.pause(h))
    }

    /// `pause`, with the record's `error` set to `why` in the same save.
    pub fn pause_for(&self, id: &BoxId, why: &str) -> Result<Change, BoxError> {
        self.vm_step(id, Event::Pause, "pause", Some(why), |v, h| v.pause(h))
    }

    /// The host as probed now, without the manager lock.
    pub fn host_facts(&self) -> HostFacts {
        (self.host)()
    }

    pub fn resume(&self, id: &BoxId) -> Result<Change, BoxError> {
        self.vm_step(id, Event::Resume, "resume", None, |v, h| v.resume(h))
    }

    /// The transition first (so a wrong state costs no VMM call), then the
    /// VMM; a VMM error leaves the box unchanged.
    fn vm_step(
        &self,
        id: &BoxId,
        ev: Event,
        why: &'static str,
        error: Option<&str>,
        call: impl Fn(&dyn Vmm, &crate::vmm::VmHandle) -> Result<(), VmmError>,
    ) -> Result<Change, BoxError> {
        let now = self.now();
        let mut g = self.lock();
        let mut r = g.get(id)?.clone();
        let from = r.state;
        let to = transition(from, ev)?;
        let h =
            r.vm.clone()
                .filter(|_| r.vm_on)
                .ok_or_else(|| BoxError::Unavailable("the box has no VM".into()))?;
        call(self.vmm.as_ref(), &h).map_err(|e| BoxError::Unavailable(vmm_msg(e)))?;
        r.state = to;
        match ev {
            Event::Resume => {
                r.last_activity = now;
                r.error = None;
            }
            _ => {
                if let Some(e) = error {
                    r.error = Some(e.to_string());
                }
            }
        }
        r.updated_at = now;
        g.put(r.clone())?;
        Ok(change(&r, from, why))
    }

    /// Turn the VM off; Starting/Running/Paused become `Done`. With `keep`,
    /// a running VM is paused and snapshotted first (not while Starting).
    pub fn stop(&self, id: &BoxId, keep: bool) -> Result<Change, BoxError> {
        let now = self.now();
        let mut g = self.lock();
        let mut r = g.get(id)?.clone();
        let from = r.state;
        let to = transition(from, Event::Stop)?;
        let h = r.vm.clone().filter(|_| r.vm_on);
        let Some(h) = h else {
            if to != from || r.vm_on {
                r.state = to;
                r.vm_on = false;
                r.updated_at = now;
                g.put(r.clone())?;
            }
            return Ok(change(&r, from, "stop"));
        };
        // A snapshot taken while the task prompt is out to the guest (m3)
        // may or may not hold it: the guest can have typed it already or
        // not, and the prompt stays pending either way until its send
        // ends. A failed send keeps it (R25), so a box restored from this
        // snapshot can get the task twice (sent again at the next run) or,
        // when the send succeeded after the snapshot, not at all. Neither
        // is detectable from here; it is accepted, not handled.
        let snap = keep && from != BoxState::Starting;
        let paused_here = snap && from != BoxState::Paused;
        if paused_here {
            self.vmm
                .pause(&h)
                .map_err(|e| BoxError::Unavailable(format!("pause failed: {}", vmm_msg(e))))?;
        }
        if snap {
            let dest = g.store.box_dir(id).join("snapshot");
            if let Err(e) = self.vmm.snapshot(&h, &dest) {
                if paused_here {
                    let _ = self.vmm.resume(&h);
                }
                return Err(BoxError::Unavailable(format!(
                    "snapshot failed: {}",
                    vmm_msg(e)
                )));
            }
        }
        if let Err(e) = self.vmm.stop(&h) {
            if paused_here {
                let _ = self.vmm.resume(&h);
            }
            return Err(BoxError::Unavailable(format!(
                "stop failed: {}",
                vmm_msg(e)
            )));
        }
        r.vm_on = false;
        r.keep = snap;
        r.state = to;
        r.updated_at = now;
        g.put(r.clone())?;
        Ok(change(&r, from, "stop"))
    }

    /// Valid from Queued, Done, Landed and Discarded (R2). The VM is stopped
    /// and destroyed, the dir removed and the record dropped. When the VMM
    /// fails, the box is still Discarded (Ok) but the record and dir stay,
    /// with the error, for gc to retry the destroy.
    pub fn discard(&self, id: &BoxId) -> Result<Change, BoxError> {
        let now = self.now();
        let mut g = self.lock();
        let mut r = g.get(id)?.clone();
        let from = r.state;
        let to = transition(from, Event::Discard)?;
        let torn = self.teardown(&mut r);
        r.state = to;
        r.vm_on = false;
        r.queue_seq = None;
        r.updated_at = now;
        if let Err(msg) = torn {
            r.error = Some(format!("discard: the VM could not be destroyed: {msg}"));
            g.put(r.clone())?;
            return Ok(change(&r, from, "discard"));
        }
        // A prompt still out to the box records nothing when it ends.
        g.prompting.remove(id);
        if let Err(e) = g.store.remove(id) {
            // Keep it as a Discarded record so gc retries.
            let _ = g.put(r);
            return Err(e.into());
        }
        g.records.remove(id);
        Ok(change(&r, from, "discard"))
    }

    /// §7.7 `saiife box done`: Running → Done.
    pub fn done(&self, id: &BoxId) -> Result<Change, BoxError> {
        let now = self.now();
        let mut g = self.lock();
        let mut r = g.get(id)?.clone();
        let from = r.state;
        r.state = transition(from, Event::Finish)?;
        r.updated_at = now;
        g.put(r.clone())?;
        Ok(change(&r, from, "done"))
    }

    /// A land was approved (plan 39): Done or Landed → Landed and
    /// `lands += 1`, through `Event::Land`. The land book writes its
    /// records before and advances the guest after; the manager only keeps
    /// the count and the state.
    pub fn land(&self, id: &BoxId) -> Result<Change, BoxError> {
        let now = self.now();
        let mut g = self.lock();
        let mut r = g.get(id)?.clone();
        let from = r.state;
        r.state = transition(from, Event::Land)?;
        r.lands = r.lands.saturating_add(1);
        r.updated_at = now;
        g.put(r.clone())?;
        Ok(change(&r, from, "land"))
    }

    /// Steer a Running or Paused box (R3). The state is checked under the
    /// lock; the message is sent with it released.
    ///
    /// R26: a steer never overtakes the box's prompt. While a prompt is
    /// still to be delivered (held, or out to the guest) the steer is
    /// `Unavailable`, to retry once it is: the guest bounds a send to a
    /// few seconds, and a held prompt goes out at the next tick once the
    /// box runs. Nothing can start a prompt between this check and the
    /// steer's send: a prompt is only claimed at `Ready` (from Starting), by
    /// the tick (only a held one) or by a revise (from Done or Landed).
    pub fn say(&self, id: &BoxId, msg: &str) -> Result<(), BoxError> {
        check_text(msg, MAX_STEER_BYTES)?;
        {
            let g = self.lock();
            let r = g.get(id)?;
            if !matches!(r.state, BoxState::Running | BoxState::Paused) {
                return Err(BoxError::WrongState { state: r.state });
            }
            if r.pending_prompt.is_some() || g.prompting.contains_key(id) {
                // Paused, the held prompt waits for a resume: retrying alone
                // never helps.
                let why = if r.state == BoxState::Paused {
                    PROMPT_HELD_PAUSED
                } else {
                    PROMPT_NOT_DELIVERED
                };
                return Err(BoxError::Unavailable(why.into()));
            }
        }
        self.guest.prompt(id, msg).map_err(BoxError::from)
    }

    /// [`Manager::revise_noted`] without the note.
    pub fn revise(&self, id: &BoxId, comment: &str) -> Result<Change, BoxError> {
        self.revise_noted(id, comment).map(|(c, _)| c)
    }

    /// Done or Landed only. VM on: the comment is sent and the box runs
    /// again. VM off: the comment waits for `Ready` and the box rejoins the
    /// queue at the tail.
    ///
    /// A revise is a follow-up comment: a prompt the box still holds unsent
    /// (a stop or pause cut its send short, or lockdown held it; often the
    /// task itself) goes first, never dropped. VM on: the held prompt is
    /// sent, then the comment, under one send token. VM off: the next
    /// `Ready` sends `held + "\n\n" + comment`, refused (`Invalid`, nothing
    /// changed) when over [`MAX_REVISED_PROMPT_BYTES`]. The note is then
    /// [`HELD_PROMPT_SENT_FIRST`], for the caller's record (R25/N1).
    pub fn revise_noted(
        &self,
        id: &BoxId,
        comment: &str,
    ) -> Result<(Change, Option<&'static str>), BoxError> {
        check_text(comment, MAX_STEER_BYTES)?;
        let now = self.now();
        let mut g = self.lock();
        let mut r = g.get(id)?.clone();
        let from = r.state;
        if !matches!(from, BoxState::Done | BoxState::Landed) {
            return Err(BoxError::WrongState { state: from });
        }
        let held = r.pending_prompt.clone();
        let why = if r.vm_on {
            let to = transition(from, Event::Revise)?;
            let token = g.claim_send(id).ok_or_else(|| {
                BoxError::Unavailable("a prompt to the box is still being sent".into())
            })?;
            // Sent with the lock released, the held prompt first; the box is
            // re-read after.
            drop(g);
            let mut held_out = false;
            let mut sent = Ok(());
            if let Some(h) = held.as_deref() {
                sent = self.guest.prompt(id, h);
                held_out = sent.is_ok();
            }
            if sent.is_ok() {
                sent = self.guest.prompt(id, comment);
            }
            g = self.lock();
            let ours = g.end_send(id, token);
            if let Err(e) = sent {
                // The held prompt went out but the comment did not: it is
                // delivered, so the box (still as it was) no longer holds it.
                if let Some(mut cur) = g.records.get(id).cloned().filter(|c| {
                    held_out && ours && c.state == from && c.vm_on && c.pending_prompt == held
                }) {
                    cur.pending_prompt = None;
                    cur.updated_at = now;
                    let _ = g.put(cur);
                }
                return Err(BoxError::from(e));
            }
            r = g.get(id)?.clone();
            // The box moved on while the comment was out (stopped, requeued
            // or discarded): it is not revived.
            if !ours || r.state != from || !r.vm_on {
                return Err(BoxError::WrongState { state: r.state });
            }
            r.state = to;
            r.turn_finished_at = None;
            r.last_activity = now;
            r.pending_prompt = None;
            "revise"
        } else {
            let next = match &held {
                Some(h) => {
                    let joined = format!("{h}\n\n{comment}");
                    if joined.len() > MAX_REVISED_PROMPT_BYTES {
                        return Err(BoxError::Invalid(format!(
                            "the box still holds its unsent prompt ({} bytes), which goes \
                             ahead of the comment; together they are over \
                             {MAX_REVISED_PROMPT_BYTES} bytes: shorten the comment",
                            h.len()
                        )));
                    }
                    joined
                }
                None => comment.to_string(),
            };
            // A prompt still out from the box's earlier run records nothing.
            g.prompting.remove(id);
            r.state = transition(from, Event::Requeue)?;
            r.queue_seq = Some(g.take_seq());
            // The next `Ready` sends it.
            r.pending_prompt = Some(next);
            "requeue"
        };
        r.updated_at = now;
        g.put(r.clone())?;
        let note = held.is_some().then_some(HELD_PROMPT_SENT_FIRST);
        Ok((change(&r, from, why), note))
    }

    /// `ids` must be exactly the queued set; positions follow its order.
    pub fn reorder(&self, ids: &[BoxId]) -> Result<(), BoxError> {
        let now = self.now();
        let mut g = self.lock();
        let q = g.queue();
        let mut want = ids.to_vec();
        want.sort();
        want.dedup();
        let mut have = q.clone();
        have.sort();
        if want.len() != ids.len() || want != have {
            return Err(BoxError::Invalid(REORDER.into()));
        }
        let mut seqs: Vec<u64> = q
            .iter()
            .filter_map(|i| g.records.get(i).and_then(|r| r.queue_seq))
            .collect();
        seqs.sort_unstable();
        if seqs.len() != ids.len() {
            seqs = ids.iter().map(|_| g.take_seq()).collect();
        }
        let mut result = Ok(());
        for (id, seq) in ids.iter().zip(seqs) {
            let mut r = g.records[id].clone();
            if r.queue_seq == Some(seq) {
                continue;
            }
            r.queue_seq = Some(seq);
            r.updated_at = now;
            if let Err(e) = g.put(r) {
                result = Err(e);
            }
        }
        result
    }

    /// Ready and Exited are transitions (`Some(change)`); Activity and
    /// TurnFinished only update the idle clocks.
    pub fn guest_event(&self, id: &BoxId, ev: GuestEvent) -> Result<Option<Change>, BoxError> {
        self.guest_event_with(id, ev, true)
    }

    /// [`Manager::guest_event`]; with `prompt = false` (lockdown `all`, R30)
    /// a `Ready` keeps the box's pending prompt unsent. The next
    /// [`Manager::tick_with`] that may admit sends it, once the box runs.
    pub fn guest_event_with(
        &self,
        id: &BoxId,
        ev: GuestEvent,
        prompt: bool,
    ) -> Result<Option<Change>, BoxError> {
        let now = self.now();
        let mut g = self.lock();
        let mut r = g.get(id)?.clone();
        let from = r.state;
        let mut send = None;
        let out = match ev {
            GuestEvent::Ready => {
                r.state = transition(from, Event::Ready)?;
                // A kept snapshot is restored at most once (or not at all on
                // a cold boot): once the box runs, it is no longer kept.
                r.keep = false;
                r.last_activity = now;
                r.turn_finished_at = None;
                if prompt {
                    send = g.claim_pending(&r);
                }
                Some(change(&r, from, "ready"))
            }
            GuestEvent::Activity => {
                r.last_activity = now;
                r.turn_finished_at = None;
                None
            }
            GuestEvent::TurnFinished => {
                r.turn_finished_at = Some(now);
                None
            }
            GuestEvent::Exited => {
                r.state = transition(from, Event::Finish)?;
                Some(change(&r, from, "exited"))
            }
        };
        r.updated_at = now;
        let saved = g.put(r);
        drop(g);
        self.deliver(send);
        saved?;
        Ok(out)
    }

    /// Add `note` to the box's `error` (`"<error>; <note>"`, or `note` alone).
    /// The caller cleans and caps guest-derived text first.
    pub fn note_error(&self, id: &BoxId, note: &str) -> Result<(), BoxError> {
        let now = self.now();
        let mut g = self.lock();
        let mut r = g.get(id)?.clone();
        r.error = Some(match r.error.take().filter(|e| !e.is_empty()) {
            Some(e) => format!("{e}; {note}"),
            None => note.to_string(),
        });
        r.updated_at = now;
        g.put(r)
    }

    /// One step under the lock: a box that is still Starting is stopped
    /// (Done, its VM off and kept, no snapshot) with `note` added to its
    /// error; any other state is left alone (`None`). For a guest whose
    /// agent exited before it was ready.
    pub fn stop_if_starting(
        &self,
        id: &BoxId,
        note: &str,
        why: &'static str,
    ) -> Result<Option<Change>, BoxError> {
        let now = self.now();
        let mut g = self.lock();
        let mut r = g.get(id)?.clone();
        let from = r.state;
        if from != BoxState::Starting {
            return Ok(None);
        }
        let to = transition(from, Event::Stop)?;
        if let Some(h) = r.vm.clone().filter(|_| r.vm_on) {
            self.vmm
                .stop(&h)
                .map_err(|e| BoxError::Unavailable(format!("stop failed: {}", vmm_msg(e))))?;
        }
        r.state = to;
        r.vm_on = false;
        r.keep = false;
        r.error = Some(match r.error.take().filter(|e| !e.is_empty()) {
            Some(e) => format!("{e}; {note}"),
            None => note.to_string(),
        });
        r.updated_at = now;
        g.put(r.clone())?;
        Ok(Some(change(&r, from, why)))
    }

    /// Sends prompts taken out under the lock, with it released; then,
    /// under the lock again, clears each from its record (a failure goes to
    /// `error`) while the send is still the box's one in flight and the
    /// record still holds that prompt. A box that moved on meanwhile (a
    /// requeue gave it a newer prompt, or it was discarded) is left as is,
    /// and a failed send to a box no longer running with its VM on (a stop,
    /// pause or finish came in) keeps its prompt and records no error
    /// (R25): the tick sends it again once the box runs (after a resume, or
    /// a daemon restart), and a revise sends it ahead of its comment, with
    /// a note (N1).
    fn deliver(&self, out: impl IntoIterator<Item = Outgoing>) {
        for o in out {
            let sent = self.guest.prompt(&o.id, &o.text);
            let now = self.now();
            let mut g = self.lock();
            if !g.end_send(&o.id, o.token) {
                continue;
            }
            let Some(mut r) = g.records.get(&o.id).cloned() else {
                continue;
            };
            if r.pending_prompt.as_deref() != Some(o.text.as_str()) {
                continue;
            }
            // R25: a send that failed because the box moved on meanwhile
            // keeps its prompt (sent again once the box runs, or ahead of a
            // revise's comment), with no error.
            if sent.is_err() && !(r.state == BoxState::Running && r.vm_on) {
                continue;
            }
            r.pending_prompt = None;
            if let Err(e) = sent {
                r.error = Some(format!("prompt failed: {}", guest_msg(e)));
            }
            r.updated_at = now;
            // Best effort, like every save after a call that happened.
            let _ = g.put(r);
        }
    }

    /// When the tick next retries the destroy of `id`, a Discarded record
    /// whose VMM has not confirmed its exit (R44). `None`: no backoff (no
    /// retry failed yet, or the exit is confirmed); the next tick retries
    /// it if it still holds a VM.
    pub fn destroy_retry_at(&self, id: &BoxId) -> Option<u64> {
        self.lock().retries.get(id).map(|b| b.next_at)
    }

    /// `tick_with(true)`.
    pub fn tick(&self) -> Vec<Change> {
        self.tick_with(true)
    }

    /// Destroy retries for Discarded records that still hold a VM (R41;
    /// each record backed off after a failed retry, R44), boot timeouts,
    /// finished turns and idle stops, which only take power away; then, with `admit`, the prompts a `Ready` under lockdown held
    /// (for Running boxes) and the admission pass. The daemon passes
    /// `admit = false` under lockdown `all` (R30): the queue and held
    /// prompts wait until it lifts.
    pub fn tick_with(&self, admit: bool) -> Vec<Change> {
        let now = self.now();
        let host = (self.host)();
        let mut g = self.lock();
        let mut out = Vec::new();
        // Held prompts are sent after the pass, with the lock released.
        let mut sends = Vec::new();
        // R44: a backoff ends once its record no longer awaits a destroy
        // (confirmed elsewhere, by gc for instance, or removed).
        let Inner {
            records, retries, ..
        } = &mut *g;
        retries.retain(|id, _| {
            records
                .get(id)
                .is_some_and(|r| r.state == BoxState::Discarded && r.vm.is_some())
        });
        let ids: Vec<BoxId> = g.records.keys().cloned().collect();
        for id in ids {
            let mut r = g.records[&id].clone();
            if r.state == BoxState::Discarded {
                // R41: retry a destroy that failed (the VMM was still
                // stopping); R44: with a per-record backoff, since each try
                // can hold the lock about a second.
                if let Some(h) = r.vm.clone() {
                    if g.retries.get(&id).is_some_and(|b| !b.due(now)) {
                        continue;
                    }
                    if self.vmm.destroy(&h).is_ok() {
                        g.retries.remove(&id);
                        r.vm = None;
                        r.error = r.error.take().and_then(without_destroy_failure);
                        r.updated_at = now;
                        let _ = g.put(r);
                    } else {
                        let b = Backoff::failed(g.retries.get(&id), now);
                        g.retries.insert(id, b);
                    }
                }
                continue;
            }
            let mut changed = false;
            let started = r.started_at.unwrap_or(r.updated_at);
            if r.state == BoxState::Starting && now.saturating_sub(started) >= BOOT_TIMEOUT_SECS {
                let from = r.state;
                self.boot_failed(&mut r, WHY_BOOT_TIMED_OUT.into(), true);
                r.updated_at = now;
                out.push(change(&r, from, WHY_BOOT_TIMED_OUT));
                let _ = g.put(r);
                continue;
            }
            if r.state == BoxState::Running {
                if let Some(t) = r.turn_finished_at {
                    if now.saturating_sub(t.max(r.last_activity)) >= DONE_IDLE_SECS {
                        let from = r.state;
                        if let Ok(to) = transition(from, Event::Finish) {
                            r.state = to;
                            changed = true;
                            out.push(change(&r, from, "turn finished"));
                        }
                    }
                }
            }
            let idle = matches!(
                r.state,
                BoxState::Running | BoxState::Paused | BoxState::Done | BoxState::Landed
            );
            if r.vm_on
                && idle
                && now.saturating_sub(r.last_activity) >= self.idle_stop_secs(&r.template)
            {
                let stopped = r.vm.as_ref().is_none_or(|h| self.vmm.stop(h).is_ok());
                if stopped {
                    let from = r.state;
                    if let Ok(to) = transition(from, Event::Stop) {
                        r.state = to;
                    }
                    r.vm_on = false;
                    changed = true;
                    out.push(change(&r, from, "idle stop"));
                }
            }
            if admit && r.state == BoxState::Running && r.vm_on && r.pending_prompt.is_some() {
                // None while a send to the box is still out (it ends that).
                if let Some(o) = g.claim_pending(&r) {
                    sends.push(o);
                    r.last_activity = now;
                    r.turn_finished_at = None;
                    changed = true;
                }
            }
            if changed {
                r.updated_at = now;
                let _ = g.put(r);
            }
        }
        if admit {
            out.extend(self.admission(&mut g, &host, now));
        }
        drop(g);
        self.deliver(sends);
        out
    }

    /// Remove every Discarded record's dir and every orphan dir. A Discarded
    /// record that still holds a VM handle has its destroy retried first; if
    /// that fails again the record stays, with the error updated. A store
    /// error does not stop the pass: the report has every id removed and
    /// the first error.
    ///
    /// First, outside the lock, every `<root>/.incoming` entry older than
    /// [`crate::place::INCOMING_MAX_AGE_SECS`] goes: what a daemon that died
    /// mid-spawn left there.
    pub fn gc(&self) -> GcReport {
        let now = self.now();
        let mut rep = GcReport::default();
        let fail = |rep: &mut GcReport, e: String| {
            rep.error.get_or_insert(e);
        };
        for e in crate::place::sweep_incoming(&self.root, now, crate::place::INCOMING_MAX_AGE_SECS)
        {
            fail(&mut rep, e);
        }
        let mut g = self.lock();
        let gone: Vec<BoxId> = g
            .records
            .values()
            .filter(|r| r.state == BoxState::Discarded)
            .map(|r| r.id.clone())
            .collect();
        for id in gone {
            let mut r = g.records[&id].clone();
            if let Some(h) = r.vm.clone() {
                if let Err(e) = self.vmm.destroy(&h) {
                    r.error = Some(format!("gc: the VM could not be destroyed: {}", vmm_msg(e)));
                    r.updated_at = now;
                    if let Err(e) = g.store.save(&r) {
                        fail(&mut rep, e.to_string());
                    }
                    g.records.insert(id, r);
                    continue;
                }
                r.vm = None;
                g.records.insert(id.clone(), r);
            }
            g.retries.remove(&id);
            match g.store.remove(&id) {
                Ok(()) => {
                    g.records.remove(&id);
                    rep.removed.push(id);
                }
                Err(e) => fail(&mut rep, e.to_string()),
            }
        }
        match g.store.orphans() {
            Ok(orphans) => {
                for id in orphans {
                    if g.records.contains_key(&id) || g.placing.contains(&id) {
                        continue;
                    }
                    match g.store.remove(&id) {
                        Ok(()) => rep.removed.push(id),
                        Err(e) => fail(&mut rep, e.to_string()),
                    }
                }
            }
            Err(e) => fail(&mut rep, e.to_string()),
        }
        rep
    }
}

/// A record's error once its VM's destroy finally succeeded: the destroy
/// failure is dropped, whatever came before it is kept.
fn without_destroy_failure(e: String) -> Option<String> {
    if e.starts_with("discard: the VM could not be destroyed")
        || e.starts_with("gc: the VM could not be destroyed")
    {
        return None;
    }
    match e.find("; destroy failed:") {
        Some(i) => Some(e[..i].to_string()),
        None => Some(e),
    }
}

/// Reconcile one loaded record with the VMM's answer: a record whose VM
/// was on, or a Starting one that names a VM (a crash between `create` or
/// `boot` and the save that follows). Returns a note and the change's `why`
/// when the record changed.
fn recover(vmm: &dyn Vmm, r: &mut BoxRecord) -> Option<(String, &'static str)> {
    if !r.vm_on {
        if r.state != BoxState::Starting {
            return None;
        }
        // Booted, but the crash came before `vm_on` was saved: the box holds
        // capacity again. Otherwise the boot timeout stops and destroys it.
        let h = r.vm.as_ref()?;
        return match vmm.status(h) {
            VmStatus::Running | VmStatus::Paused => {
                r.vm_on = true;
                Some(("the VM was on; the box is starting".into(), WHY_RECONCILED))
            }
            _ => None,
        };
    }
    let status = r.vm.as_ref().map_or(VmStatus::Gone, |h| vmm.status(h));
    match status {
        VmStatus::Gone | VmStatus::Off => {
            if let Ok(to) = transition(r.state, Event::VmLost) {
                r.state = to;
            }
            r.vm_on = false;
            r.error = Some(LOST.into());
            Some((LOST.into(), WHY_LOST))
        }
        VmStatus::Paused if r.state == BoxState::Running => {
            r.state = BoxState::Paused;
            Some((
                "the VM was paused; the box is now paused".into(),
                WHY_RECONCILED,
            ))
        }
        VmStatus::Running if r.state == BoxState::Paused => {
            r.state = BoxState::Running;
            Some((
                "the VM was running; the box is now running".into(),
                WHY_RECONCILED,
            ))
        }
        _ => None,
    }
}
