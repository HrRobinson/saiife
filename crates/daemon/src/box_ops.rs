//! The `box.*` ops on the control socket (plan 34, Task 8) over the box
//! manager of `saiife-boxes`, and its 5 s tick.
//!
//! A release daemon has no boxes: [`build`] gives a manager only in a build
//! with the `fake-vmm` feature and `SAIIFE_BOX_FAKE_VMM=1` (a fake VM, for
//! tests). Without one every op answers `unavailable`.
//!
//! Each op checks its arguments (`BoxId::parse`, `check_text`) before the
//! manager is called, and every manager call runs in `spawn_blocking` (the
//! manager holds its lock across VMM and guest calls). A peer that is not the
//! box's owner, root or an `[admin] groups` member gets `not_found` for it,
//! the answer of a missing id (B8). Under lockdown `all`, the ops that give a
//! box power (spawn, resume, revise, steer) are refused with a deny record;
//! the ones that take it away stay allowed. Every change is a `box` record
//! with `extra = {action, box, template, from, to, via}` and `session =
//! "box-<id>"`.

use crate::ops::{Conn, Ctx, Mode};
use saiife_audit::{DecisionKind, Record};
use saiife_boxes::capacity::{self, HostFacts};
use saiife_boxes::manager::{Change, Manager, SpawnArgs, MAX_REPO_BYTES};
use saiife_boxes::source::{info, ManagerSource};
use saiife_boxes::store::BoxRecord;
use saiife_boxes::template::{TemplateWarning, Trust};
use saiife_boxes::{BoxError, BoxId, BoxState};
use saiife_broker::pipeline::LockScope;
use saiife_ipc::msg::{
    err, err_with, ok, ErrorCode, Request, OP_BOX_DIFF, OP_BOX_DISCARD, OP_BOX_DONE, OP_BOX_GC,
    OP_BOX_LIST, OP_BOX_PAUSE, OP_BOX_REORDER, OP_BOX_RESUME, OP_BOX_REVISE, OP_BOX_SPAWN,
    OP_BOX_STEER, OP_BOX_STOP, OP_BOX_TEMPLATES, OP_BOX_TERM_READ,
};
use saiife_ipc::peer::PeerCred;
use saiife_wire::source::{check_text, BoxSource, Start, MAX_STEER_BYTES, MAX_TASK_BYTES};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The daemon's tick of the box manager.
pub const TICK_SECS: u64 = 5;
/// The answer of every box op when there is no manager.
pub const UNAVAILABLE: &str = "boxes are not available in this version";
/// Set to `1` (in a `fake-vmm` build) to run boxes on the fake VM.
pub const FAKE_ENV: &str = "SAIIFE_BOX_FAKE_VMM";
/// With [`FAKE_ENV`] (a `fake-vmm` build only): `<n>` pins the host to
/// exactly `n` default boxes, so a test never depends on the machine's RAM.
pub const FAKE_SLOTS_ENV: &str = "SAIIFE_BOX_FAKE_SLOTS";
/// The stderr line of a daemon whose boxes run on the fake VM.
pub const FAKE_NOTICE: &str = "saiifed: boxes use a fake VM (test build)";
/// The longest template name and `repo_dir` taken.
const MAX_TEMPLATE_BYTES: usize = 64;
const MAX_REPO_DIR_BYTES: usize = 4096;

/// The ops [`handle`] serves.
pub const OPS: &[&str] = &[
    OP_BOX_SPAWN,
    OP_BOX_LIST,
    OP_BOX_TEMPLATES,
    OP_BOX_PAUSE,
    OP_BOX_STOP,
    OP_BOX_DISCARD,
    OP_BOX_DONE,
    OP_BOX_RESUME,
    OP_BOX_REVISE,
    OP_BOX_STEER,
    OP_BOX_REORDER,
    OP_BOX_GC,
    OP_BOX_DIFF,
    OP_BOX_TERM_READ,
];

/// `<state_dir>/boxes`.
pub fn dir_in(state_dir: &Path) -> PathBuf {
    state_dir.join("boxes")
}

/// Where box templates come from (B11). Locked: `<dir of config_path>/templates.d`,
/// root's files only. Personal: `$XDG_CONFIG_HOME/saiife/templates.d` (an absolute
/// `XDG_CONFIG_HOME`, else `$HOME/.config`), the user's own files only; with
/// neither, beside `config_path`. Never a project directory.
pub fn templates_dir(
    mode: &Mode,
    config_path: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> (PathBuf, Trust) {
    let beside_config = || {
        config_path
            .parent()
            .unwrap_or(Path::new("/"))
            .join("templates.d")
    };
    match mode {
        Mode::Locked => (beside_config(), Trust::RootOwned),
        Mode::Personal => {
            let abs = |k: &str| {
                env(k)
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
                    .filter(|p| p.is_absolute())
            };
            let dir = abs("XDG_CONFIG_HOME")
                .or_else(|| abs("HOME").map(|h| h.join(".config")))
                .map(|c| c.join("saiife").join("templates.d"))
                .unwrap_or_else(beside_config);
            (dir, Trust::OwnedBy(crate::fsx::process_uid()))
        }
    }
}

/// A live sample of the host for admission. Linux: `/proc/meminfo`
/// (`MemTotal`, `MemAvailable`), `available_parallelism`, `statvfs` of the
/// boxes dir (its nearest existing ancestor) and the CPU use since the last
/// sample (`/proc/stat`; `None` on the first). Anything unreadable is 0, so
/// nothing fits rather than too much. Elsewhere: nothing fits.
#[cfg(target_os = "linux")]
pub fn host_facts(boxes_dir: &Path, prev_cpu: &Mutex<Option<(u64, u64)>>) -> HostFacts {
    let mem = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mib = |name: &str| meminfo_kib(&mem, name).map_or(0, |k| k / 1024);
    let threads = std::thread::available_parallelism()
        .map_or(0, |n| u32::try_from(n.get()).unwrap_or(u32::MAX));
    let disk_free_mib = boxes_dir
        .ancestors()
        .find(|p| p.exists())
        .and_then(|p| rustix::fs::statvfs(p).ok())
        .map_or(0, |st| {
            st.f_bavail.saturating_mul(st.f_frsize) / (1024 * 1024)
        });
    let now = std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| cpu_times(&s));
    let cpu_pct = {
        let mut prev = prev_cpu.lock().unwrap_or_else(|p| p.into_inner());
        let pct = match (*prev, now) {
            (Some(a), Some(b)) => cpu_pct(a, b),
            _ => None,
        };
        if now.is_some() {
            *prev = now;
        }
        pct
    };
    HostFacts {
        mem_total_mib: mib("MemTotal"),
        mem_avail_mib: mib("MemAvailable"),
        threads,
        disk_free_mib,
        cpu_pct,
    }
}

/// Not Linux: no host facts, so nothing fits.
#[cfg(not(target_os = "linux"))]
pub fn host_facts(boxes_dir: &Path, prev_cpu: &Mutex<Option<(u64, u64)>>) -> HostFacts {
    let _ = (boxes_dir, prev_cpu);
    HostFacts::default()
}

/// `name:   123 kB` of `/proc/meminfo`, in KiB.
#[cfg(any(target_os = "linux", test))]
fn meminfo_kib(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let rest = l.strip_prefix(name)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

/// `(total, idle)` jiffies of the `cpu` line of `/proc/stat` (idle counts
/// iowait).
#[cfg(any(target_os = "linux", test))]
fn cpu_times(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|x| x.parse().ok())
        .collect::<Option<_>>()?;
    if v.len() < 4 {
        return None;
    }
    let idle = v[3].saturating_add(v.get(4).copied().unwrap_or(0));
    Some((v.iter().fold(0u64, |a, x| a.saturating_add(*x)), idle))
}

/// The busy share between two samples, 0..=100.
#[cfg(any(target_os = "linux", test))]
fn cpu_pct(a: (u64, u64), b: (u64, u64)) -> Option<u8> {
    let total = b.0.checked_sub(a.0)?;
    let idle = b.1.checked_sub(a.1)?;
    if total == 0 {
        return None;
    }
    let busy = total.saturating_sub(idle);
    u8::try_from(busy.saturating_mul(100) / total).ok()
}

/// What [`build`] made: the manager, the start warnings (store, recovery,
/// templates) for stderr, and the template warnings `box.templates` shows.
pub struct Built {
    pub manager: Arc<Manager>,
    pub warnings: Vec<String>,
    pub template_warnings: Vec<TemplateWarning>,
}

/// The box manager, or `None`: only a `fake-vmm` build with
/// `SAIIFE_BOX_FAKE_VMM=1` has one (a fake VM; no release build has boxes).
/// `Err` when the box state cannot be opened.
pub fn build(state_dir: &Path, mode: &Mode, config_path: &Path) -> Result<Option<Built>, String> {
    build_with(state_dir, mode, config_path, &|k| std::env::var_os(k))
}

/// [`build`] with the environment as a function (tests).
pub fn build_with(
    state_dir: &Path,
    mode: &Mode,
    config_path: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Option<Built>, String> {
    #[cfg(feature = "fake-vmm")]
    {
        if env(FAKE_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return Ok(None);
        }
        build_fake(state_dir, mode, config_path, env).map(Some)
    }
    #[cfg(not(feature = "fake-vmm"))]
    {
        let _ = (state_dir, mode, config_path, env);
        Ok(None)
    }
}

#[cfg(feature = "fake-vmm")]
fn build_fake(
    state_dir: &Path,
    mode: &Mode,
    config_path: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Built, String> {
    use saiife_boxes::guest::fake::FakeGuest;
    use saiife_boxes::manager::ManagerInit;
    use saiife_boxes::store::Store;
    use saiife_boxes::vmm::fake::FakeVmm;

    let root = dir_in(state_dir);
    let store = Store::open(root.clone()).map_err(|e| e.to_string())?;
    let (tdir, trust) = templates_dir(mode, config_path, env);
    let (templates, template_warnings) = saiife_boxes::template::load_dir(&tdir, trust);
    let prev = Mutex::new(None);
    let pinned = env(FAKE_SLOTS_ENV)
        .and_then(|v| v.to_str().and_then(|s| s.parse::<u64>().ok()))
        .map(fake_host);
    let (mgr, mut warnings) = Manager::open(ManagerInit {
        store,
        vmm: Arc::new(FakeVmm::new()),
        guest: Arc::new(FakeGuest::new()),
        templates,
        host: Arc::new(move || match &pinned {
            Some(h) => *h,
            None => host_facts(&root, &prev),
        }),
        clock: Arc::new(unix_now),
    })
    .map_err(|e| e.to_string())?;
    warnings.extend(
        template_warnings
            .iter()
            .map(|w| format!("template {}: {}", w.file.display(), w.reason)),
    );
    Ok(Built {
        manager: Arc::new(mgr),
        warnings,
        template_warnings,
    })
}

/// A host that holds exactly `n` default boxes (`SAIIFE_BOX_FAKE_SLOTS`).
#[cfg(feature = "fake-vmm")]
pub fn fake_host(n: u64) -> HostFacts {
    let mem = 8192
        + n.saturating_mul(capacity::charge_mib(
            &saiife_boxes::template::Size::default(),
        ));
    HostFacts {
        mem_total_mib: mem,
        mem_avail_mib: mem,
        threads: 12,
        disk_free_mib: 1024 * 1024,
        cpu_pct: None,
    }
}

#[cfg(feature = "fake-vmm")]
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Run the manager's tick every [`TICK_SECS`] and record its changes. The
/// task holds the context weakly and ends with it. No manager, no task.
pub fn start_tick(ctx: Arc<Ctx>) {
    if ctx.box_manager.is_none() {
        return;
    }
    let weak = Arc::downgrade(&ctx);
    drop(ctx);
    tokio::spawn(async move {
        let every = Duration::from_secs(TICK_SECS);
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(ctx) = weak.upgrade() else { break };
            tick_once(&ctx).await;
            #[cfg(feature = "fake-vmm")]
            fake_ready(&ctx).await;
        }
    });
}

/// The fake VM "boots" at once: its guest says `Ready` for every box that
/// is Starting, at the next tick (there is no guest process to say it). Test
/// builds only; the CLI tests need a Running box. Recorded like any tick
/// change.
#[cfg(feature = "fake-vmm")]
async fn fake_ready(ctx: &Ctx) {
    let Some(mgr) = ctx.box_manager.clone() else {
        return;
    };
    let done = tokio::task::spawn_blocking(move || {
        mgr.list()
            .into_iter()
            .filter(|r| r.state == BoxState::Starting)
            .filter_map(|r| {
                let c = mgr
                    .guest_event(&r.id, saiife_boxes::guest::GuestEvent::Ready)
                    .ok()
                    .flatten()?;
                Some((c, Some(r.template)))
            })
            .collect::<Vec<_>>()
    })
    .await;
    if let Ok(changes) = done {
        write_tick_records(ctx, changes).await;
    }
}

/// One tick: the manager's tick off the runtime thread, then one `box`
/// record (`via: "tick"`) per change. Returns the number of changes.
pub async fn tick_once(ctx: &Ctx) -> usize {
    let Some(mgr) = ctx.box_manager.clone() else {
        return 0;
    };
    let done = tokio::task::spawn_blocking(move || {
        let changes = mgr.tick();
        changes
            .into_iter()
            .map(|c| {
                let template = mgr.get(&c.id).ok().map(|r| r.template);
                (c, template)
            })
            .collect::<Vec<_>>()
    })
    .await;
    let changes = match done {
        Ok(c) => c,
        Err(e) => {
            eprintln!("saiifed: boxes: the tick did not finish: {e}");
            return 0;
        }
    };
    let n = changes.len();
    write_tick_records(ctx, changes).await;
    n
}

/// The daemon's own `box` records (`action`/`via` "tick", `reason` = why),
/// one per change, each with the box's template when it is still known.
async fn write_tick_records(ctx: &Ctx, changes: Vec<(Change, Option<String>)>) {
    for (c, template) in changes {
        let mut rec = box_rec(
            ctx,
            "tick",
            Some(&c.id),
            template.as_deref(),
            Some(c.from),
            Some(c.to),
            "tick",
        );
        rec.reason = Some(c.why.to_string());
        if let Err(e) = ctx.writer.append(rec).await {
            eprintln!("saiifed: warning: cannot write a box tick record: {e}");
        }
    }
}

fn state_value(s: BoxState) -> Value {
    serde_json::to_value(s).unwrap_or(Value::Null)
}

/// A `box` record of `action`. The caller sets the peer.
fn box_rec(
    ctx: &Ctx,
    action: &str,
    id: Option<&BoxId>,
    template: Option<&str>,
    from: Option<BoxState>,
    to: Option<BoxState>,
    via: &str,
) -> Record {
    let input = match id {
        Some(i) => format!("{action} {}", i.as_str()),
        None => action.to_string(),
    };
    let mut r = ctx.record("box", &input);
    r.session = id.map(|i| format!("box-{}", i.as_str()));
    let x = &mut r.extra;
    x.insert("action".into(), action.into());
    x.insert("box".into(), id.map_or(Value::Null, |i| i.as_str().into()));
    x.insert("template".into(), template.map_or(Value::Null, Value::from));
    x.insert("from".into(), from.map_or(Value::Null, state_value));
    x.insert("to".into(), to.map_or(Value::Null, state_value));
    x.insert("via".into(), via.into());
    r
}

/// The answer to a refused op: `bad_request` with `rule` for not found,
/// wrong state and invalid; `busy`; `unavailable`.
fn refusal(id: u64, e: &BoxError) -> Value {
    let code = match e {
        BoxError::NotFound | BoxError::WrongState { .. } | BoxError::Invalid(_) => {
            ErrorCode::BadRequest
        }
        BoxError::Busy => ErrorCode::Busy,
        BoxError::Unavailable(_) => ErrorCode::Unavailable,
    };
    let msg = match e {
        BoxError::Busy => "busy: no room for the box now, or boxes are waiting in the queue".into(),
        other => other.to_string(),
    };
    let mut m = Map::new();
    m.insert("rule".into(), e.rule().into());
    err_with(id, code, &msg, m)
}

fn invalid(why: &str) -> BoxError {
    BoxError::Invalid(why.into())
}

fn arg_id(args: &Map<String, Value>) -> Result<BoxId, BoxError> {
    match args.get("box") {
        Some(Value::String(s)) => BoxId::parse(s),
        _ => Err(invalid("box must be a box id")),
    }
}

/// A required text argument, checked with `check_text`.
fn arg_text(args: &Map<String, Value>, name: &str, max: usize) -> Result<String, BoxError> {
    match args.get(name) {
        Some(Value::String(s)) => {
            check_text(s, max)?;
            Ok(s.clone())
        }
        _ => Err(BoxError::Invalid(format!("{name} must be a string"))),
    }
}

fn arg_bool(args: &Map<String, Value>, name: &str) -> Result<bool, BoxError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(BoxError::Invalid(format!("{name} must be true or false"))),
    }
}

/// One op with its arguments checked.
enum Op {
    Spawn(SpawnArgs),
    List { all: bool },
    Templates,
    Pause(BoxId),
    Stop(BoxId, bool),
    Discard(BoxId),
    Done(BoxId),
    Resume(BoxId),
    Revise(BoxId, String),
    Steer(BoxId, String),
    Reorder(Vec<BoxId>),
    Gc,
    Diff(BoxId),
    TermRead(BoxId, Option<u64>),
}

impl Op {
    fn parse(op: &str, a: &Map<String, Value>, uid: u32) -> Result<Op, BoxError> {
        Ok(match op {
            OP_BOX_SPAWN => {
                let task = match a.get("task") {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) if s.is_empty() => String::new(),
                    Some(Value::String(s)) => {
                        check_text(s, MAX_TASK_BYTES)?;
                        s.clone()
                    }
                    Some(_) => return Err(invalid("task must be a string")),
                };
                let repo_dir = match a.get("repo_dir") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => {
                        check_text(s, MAX_REPO_DIR_BYTES)?;
                        Some(s.clone())
                    }
                    Some(_) => return Err(invalid("repo_dir must be a string")),
                };
                let start = match a.get("start") {
                    None | Some(Value::Null) => Start::Queue,
                    Some(Value::String(s)) if s == "queue" => Start::Queue,
                    Some(Value::String(s)) if s == "now" => Start::Now,
                    Some(_) => return Err(invalid("start is \"now\" or \"queue\"")),
                };
                Op::Spawn(SpawnArgs {
                    template: arg_text(a, "template", MAX_TEMPLATE_BYTES)?,
                    repo: arg_text(a, "repo", MAX_REPO_BYTES)?,
                    repo_dir,
                    task,
                    start,
                    owner_uid: uid,
                    repo_image: None,
                    base_manifest: None,
                })
            }
            OP_BOX_LIST => Op::List {
                all: arg_bool(a, "all")?,
            },
            OP_BOX_TEMPLATES => Op::Templates,
            OP_BOX_PAUSE => Op::Pause(arg_id(a)?),
            OP_BOX_STOP => Op::Stop(arg_id(a)?, arg_bool(a, "keep")?),
            OP_BOX_DISCARD => Op::Discard(arg_id(a)?),
            OP_BOX_DONE => Op::Done(arg_id(a)?),
            OP_BOX_RESUME => Op::Resume(arg_id(a)?),
            OP_BOX_REVISE => Op::Revise(arg_id(a)?, arg_text(a, "comment", MAX_STEER_BYTES)?),
            OP_BOX_STEER => Op::Steer(arg_id(a)?, arg_text(a, "msg", MAX_STEER_BYTES)?),
            OP_BOX_REORDER => {
                let Some(Value::Array(v)) = a.get("ids") else {
                    return Err(invalid("ids must be a list of box ids"));
                };
                let ids = v
                    .iter()
                    .map(|x| match x {
                        Value::String(s) => BoxId::parse(s),
                        _ => Err(invalid("ids must be a list of box ids")),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Op::Reorder(ids)
            }
            OP_BOX_GC => Op::Gc,
            OP_BOX_DIFF => Op::Diff(arg_id(a)?),
            OP_BOX_TERM_READ => {
                let after = match a.get("after") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(
                        v.as_u64()
                            .ok_or_else(|| invalid("after must be a number"))?,
                    ),
                };
                Op::TermRead(arg_id(a)?, after)
            }
            _ => return Err(invalid("not a box op")),
        })
    }

    /// The ops that give a box power, refused under lockdown `all`.
    fn grants_power(&self) -> bool {
        matches!(
            self,
            Op::Spawn(_) | Op::Resume(_) | Op::Revise(..) | Op::Steer(..)
        )
    }

    /// The box a per-box op is about.
    fn target(&self) -> Option<&BoxId> {
        match self {
            Op::Pause(i)
            | Op::Stop(i, _)
            | Op::Discard(i)
            | Op::Done(i)
            | Op::Resume(i)
            | Op::Revise(i, _)
            | Op::Steer(i, _)
            | Op::Diff(i)
            | Op::TermRead(i, _) => Some(i),
            _ => None,
        }
    }
}

/// A manager call off the runtime thread.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, BoxError> + Send + 'static,
) -> Result<T, BoxError> {
    tokio::task::spawn_blocking(f).await.unwrap_or_else(|e| {
        Err(BoxError::Unavailable(format!(
            "the box manager did not finish: {e}"
        )))
    })
}

/// `{name: t}`. Answers nest what carries an `id`: the answer's own `id`
/// is the request's.
fn under<T: Serialize>(name: &str, t: &T) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(name.into(), serde_json::to_value(t).unwrap_or(Value::Null));
    m
}

fn obj<T: Serialize>(t: &T) -> Map<String, Value> {
    match serde_json::to_value(t) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

/// `{box: BoxInfo}`: box `r` as `scope` sees it (queue positions among
/// that owner's boxes; `None`: the whole queue).
fn info_of(mgr: &Arc<Manager>, r: &BoxRecord, scope: Option<u32>) -> Map<String, Value> {
    let src = ManagerSource::new(Arc::clone(mgr), scope);
    let i = src
        .list()
        .into_iter()
        .find(|b| b.id == r.id)
        .unwrap_or_else(|| info(r, None));
    under("box", &i)
}

/// What the caller may see and do, once per op.
struct Caller {
    peer: PeerCred,
    /// Root or an `[admin] groups` member.
    privileged: bool,
}

impl Caller {
    fn may_see(&self, r: &BoxRecord) -> bool {
        self.privileged || r.owner_uid == self.peer.uid
    }

    /// Queue positions: among the caller's own boxes, or the whole queue for
    /// someone else's.
    fn scope_for(&self, r: &BoxRecord) -> Option<u32> {
        (r.owner_uid == self.peer.uid).then_some(self.peer.uid)
    }
}

/// Every op in [`OPS`].
pub async fn handle(ctx: &Arc<Ctx>, conn: &Conn, req: Request) -> Value {
    let id = req.id;
    let Some(mgr) = ctx.box_manager.clone() else {
        return err(id, ErrorCode::Unavailable, UNAVAILABLE);
    };
    let peer = conn.peer.clone();
    let action = req.op.strip_prefix("box.").unwrap_or(&req.op).to_string();
    let op = match Op::parse(&req.op, &req.args, peer.uid) {
        Ok(op) => op,
        Err(e) => return refusal(id, &e),
    };
    let user = ctx.peer_name(&peer).await;
    let with_peer = |mut r: Record| {
        r.uid = Some(peer.uid);
        r.sid = peer.sid.clone();
        r.user = user.clone();
        r
    };

    // Lockdown `all` refuses what gives a box power; the record says so.
    if op.grants_power() {
        if let Some(l) = ctx.lockdown.get().filter(|l| l.scope == LockScope::All) {
            let template = match &op {
                Op::Spawn(a) => Some(a.template.as_str()),
                _ => None,
            };
            let mut rec = with_peer(box_rec(
                ctx,
                &action,
                op.target(),
                template,
                None,
                None,
                "cli",
            ));
            let why = crate::lockdown::message(&l);
            rec.decision = DecisionKind::Deny;
            rec.rule = Some("lockdown".into());
            rec.reason = Some(why.clone());
            if let Err(e) = ctx.writer.append(rec).await {
                eprintln!("saiifed: warning: cannot write a box record: {e}");
            }
            let mut m = Map::new();
            m.insert("rule".into(), "lockdown".into());
            return err_with(id, ErrorCode::Lockdown, &why, m);
        }
    }

    let privileged = (peer.sid.is_none() && peer.uid == 0) || ctx.peer_is_admin(&peer).await;
    let caller = Arc::new(Caller {
        peer: peer.clone(),
        privileged,
    });

    // The owner check (B8): someone else's box is a missing one.
    let before = match op.target() {
        Some(target) => {
            let (m, t, c) = (Arc::clone(&mgr), target.clone(), Arc::clone(&caller));
            match blocking(move || {
                let r = m.get(&t)?;
                if c.may_see(&r) {
                    Ok(r)
                } else {
                    Err(BoxError::NotFound)
                }
            })
            .await
            {
                Ok(r) => Some(r),
                Err(e) => return refusal(id, &e),
            }
        }
        None => None,
    };

    let done = run(ctx, &mgr, &caller, op, before).await;
    let (answer, rec) = match done {
        Ok(x) => x,
        Err(e) => return refusal(id, &e),
    };
    if let Some(rec) = rec {
        if let Err(e) = ctx.writer.append(with_peer(rec)).await {
            return err(
                id,
                ErrorCode::Unrecorded,
                &format!("box.{action} is done, but its record could not be written: {e}"),
            );
        }
    }
    ok(id, answer)
}

/// The answer and the record (if the op writes one) of a checked op.
type Done = (Map<String, Value>, Option<Record>);

/// A manager call that changes one box.
type Step = Box<dyn FnOnce(&Manager) -> Result<Change, BoxError> + Send>;

/// One op, past its argument, lockdown and owner checks. `before` is the
/// target box as the owner check read it.
async fn run(
    ctx: &Ctx,
    mgr: &Arc<Manager>,
    caller: &Arc<Caller>,
    op: Op,
    before: Option<BoxRecord>,
) -> Result<Done, BoxError> {
    let m = Arc::clone(mgr);
    let c = Arc::clone(caller);
    let uid = caller.peer.uid;
    // A per-box change: the manager call, then the box as it is now.
    let change = |action: &'static str, f: Step| {
        let (m, c) = (Arc::clone(mgr), Arc::clone(caller));
        let before = before.clone();
        async move {
            let b = before.ok_or(BoxError::NotFound)?;
            let (ch, answer) = blocking(move || {
                let ch = f(&m)?;
                let answer = match m.get(&ch.id) {
                    Ok(r) => info_of(&m, &r, c.scope_for(&r)),
                    Err(_) => under("box", &json!({"id": ch.id.as_str()})),
                };
                Ok((ch, answer))
            })
            .await?;
            let rec = box_rec(
                ctx,
                action,
                Some(&ch.id),
                Some(&b.template),
                Some(ch.from),
                Some(ch.to),
                "cli",
            );
            Ok::<Done, BoxError>((answer, Some(rec)))
        }
    };
    match op {
        Op::Spawn(args) => {
            let (r, answer, others) = blocking(move || {
                let (r, changes) = m.spawn_changes(&args)?;
                let answer = info_of(&m, &r, Some(r.owner_uid));
                // Earlier queue heads this spawn's admission pass moved
                // (possibly other owners' boxes): the tick never sees them.
                // The new box's own admission is covered by the spawn
                // record's `to`.
                let others = changes
                    .into_iter()
                    .filter(|c| c.id != r.id)
                    .map(|c| {
                        let template = m.get(&c.id).ok().map(|b| b.template);
                        (c, template)
                    })
                    .collect::<Vec<_>>();
                Ok((r, answer, others))
            })
            .await?;
            write_tick_records(ctx, others).await;
            let mut rec = box_rec(
                ctx,
                "spawn",
                Some(&r.id),
                Some(&r.template),
                None,
                Some(r.state),
                "cli",
            );
            if r.state == BoxState::Discarded {
                rec.reason = r.error.clone();
            }
            Ok((answer, Some(rec)))
        }
        Op::List { all } => {
            let scope = (!(all && caller.privileged)).then_some(uid);
            blocking(move || {
                let boxes = ManagerSource::new(Arc::clone(&m), scope).list();
                let (host, committed) = m.capacity();
                let (total, free) = capacity::slots(&host, &committed);
                let mut a = Map::new();
                a.insert(
                    "boxes".into(),
                    serde_json::to_value(boxes).unwrap_or_default(),
                );
                a.insert("slots_total".into(), total.into());
                a.insert("slots_free".into(), free.into());
                Ok((a, None))
            })
            .await
        }
        Op::Templates => {
            let warnings: Vec<Value> = ctx
                .box_template_warnings
                .iter()
                .map(|w| json!({"file": w.file.display().to_string(), "reason": w.reason}))
                .collect();
            blocking(move || {
                let t: Vec<_> = m.templates().iter().map(|t| t.wire()).collect();
                let mut a = Map::new();
                a.insert(
                    "templates".into(),
                    serde_json::to_value(t).unwrap_or_default(),
                );
                a.insert("warnings".into(), Value::Array(warnings));
                Ok((a, None))
            })
            .await
        }
        Op::Pause(i) => change("pause", Box::new(move |m| m.pause(&i))).await,
        Op::Stop(i, keep) => change("stop", Box::new(move |m| m.stop(&i, keep))).await,
        Op::Done(i) => change("done", Box::new(move |m| m.done(&i))).await,
        Op::Resume(i) => change("resume", Box::new(move |m| m.resume(&i))).await,
        Op::Revise(i, text) => change("revise", Box::new(move |m| m.revise(&i, &text))).await,
        Op::Discard(i) => {
            let (_, rec) = change("discard", Box::new(move |m| m.discard(&i))).await?;
            let b = before.ok_or(BoxError::NotFound)?;
            Ok((under("box", &json!({"id": b.id.as_str()})), rec))
        }
        Op::Steer(i, msg) => {
            let b = before.ok_or(BoxError::NotFound)?;
            blocking(move || m.say(&i, &msg)).await?;
            let rec = box_rec(
                ctx,
                "steer",
                Some(&b.id),
                Some(&b.template),
                Some(b.state),
                Some(b.state),
                "cli",
            );
            Ok((Map::new(), Some(rec)))
        }
        Op::Reorder(ids) => {
            let ids2 = ids.clone();
            blocking(move || {
                // An admin listing the whole queue orders it; anyone else
                // (or an admin listing only their own) orders their own
                // boxes among the places they hold.
                let mut want = ids2.clone();
                want.sort();
                let mut all = m.queue();
                all.sort();
                if c.privileged && want == all {
                    m.reorder(&ids2)
                } else {
                    ManagerSource::new(Arc::clone(&m), Some(c.peer.uid)).reorder(&ids2)
                }
            })
            .await?;
            let mut rec = box_rec(ctx, "reorder", None, None, None, None, "cli");
            rec.extra.insert(
                "ids".into(),
                ids.iter().map(|i| i.as_str()).collect::<Vec<_>>().into(),
            );
            Ok((Map::new(), Some(rec)))
        }
        Op::Gc => {
            let removed = blocking(move || {
                if c.privileged {
                    return m.gc().map(|g| g.removed).map_err(BoxError::from);
                }
                // Only the caller's own discarded boxes; orphan dirs have no
                // owner, so they wait for an admin.
                let mine: Vec<BoxId> = m
                    .list()
                    .into_iter()
                    .filter(|r| r.state == BoxState::Discarded && r.owner_uid == c.peer.uid)
                    .map(|r| r.id)
                    .collect();
                let mut removed = Vec::new();
                for i in mine {
                    m.discard(&i)?;
                    if matches!(m.get(&i), Err(BoxError::NotFound)) {
                        removed.push(i);
                    }
                }
                Ok(removed)
            })
            .await?;
            let ids: Vec<&str> = removed.iter().map(|i| i.as_str()).collect();
            let mut rec = box_rec(ctx, "gc", None, None, None, None, "cli");
            rec.extra.insert("removed".into(), ids.clone().into());
            let mut a = Map::new();
            a.insert("removed".into(), ids.into());
            Ok((a, Some(rec)))
        }
        Op::Diff(i) => {
            blocking(move || {
                let d = ManagerSource::new(m, None).diff(&i)?;
                Ok((under("diff", &d), None))
            })
            .await
        }
        Op::TermRead(i, after) => {
            blocking(move || {
                let b = ManagerSource::new(m, None).terminal(&i, after)?;
                Ok((obj(&b), None))
            })
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_fields() {
        let t = "MemTotal:       32768000 kB\nMemFree:  1 kB\nMemAvailable:   16384000 kB\n";
        assert_eq!(meminfo_kib(t, "MemTotal"), Some(32_768_000));
        assert_eq!(meminfo_kib(t, "MemAvailable"), Some(16_384_000));
        assert_eq!(meminfo_kib(t, "Mem"), None);
        assert_eq!(meminfo_kib("", "MemTotal"), None);
    }

    #[test]
    fn cpu_delta() {
        let a = cpu_times("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\n").unwrap();
        assert_eq!(a, (1000, 800));
        let b = cpu_times("cpu  200 0 200 1300 300 0 0 0 0 0\n").unwrap();
        assert_eq!(cpu_pct(a, b), Some(20));
        assert_eq!(cpu_pct(a, a), None);
        assert_eq!(cpu_pct(b, a), None, "a counter that went back");
        assert_eq!(cpu_times("intr 1 2\n"), None);
    }

    #[test]
    fn personal_templates_dir_ignores_relative_xdg() {
        let env = |k: &str| -> Option<OsString> {
            match k {
                "XDG_CONFIG_HOME" => Some("rel/dir".into()),
                "HOME" => Some("/home/u".into()),
                _ => None,
            }
        };
        let (d, _) = templates_dir(&Mode::Personal, Path::new("/c/config.toml"), &env);
        assert_eq!(d, Path::new("/home/u/.config/saiife/templates.d"));
        let none = |_: &str| -> Option<OsString> { None };
        let (d, _) = templates_dir(&Mode::Personal, Path::new("/c/config.toml"), &none);
        assert_eq!(d, Path::new("/c/templates.d"));
    }
}
