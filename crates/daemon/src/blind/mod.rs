//! Data Shield in the daemon (plan 47): the `blind.*` ops, the datasets'
//! states, their sessions and the sealed key store, under `<state>/blind/`
//! (0700). The daemon owns every file and socket; `saiife-shield` does the
//! logic. Linux only: elsewhere `blind_stub.rs` answers every op with
//! [`UNAVAILABLE_OS`].

pub mod keys;
pub mod ops;

use saiife_ipc::msg::ErrorCode;
use saiife_shield::dataset::{DatasetDir, Manifest, Phase};
use saiife_shield::index::{AllowList, KnownIndex};
use saiife_shield::lexicon::Lexicon;
use saiife_shield::schema::DatasetName;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

/// Every `blind.*` op (the fixed-values table; plan 48's names included).
pub const OPS: &[&str] = saiife_ipc::msg::BLIND_OPS;

/// What every `blind.*` op answers outside Linux.
pub const UNAVAILABLE_OS: &str = "Data Shield runs on Linux in this release";

/// The datasets' directory under the blind root.
const DATASETS_DIR: &str = "datasets";

/// The Data Shield state the daemon shares (`Ctx::blind`).
pub struct Blind {
    /// `<state>/blind`.
    pub root: PathBuf,
    datasets: Mutex<BTreeMap<String, DatasetState>>,
    /// Live sessions, by (uid, dataset). Never logged: a `Turn` holds text.
    pub sessions: Mutex<saiife_shield::session::Sessions>,
    /// Held across a key store change (create, rotate, shred), so a check
    /// of `keys.sealed` still holds when it is written or removed.
    keys_lock: Mutex<()>,
}

/// Where a dataset is. A dataset not in the map is [`DatasetState::Absent`].
pub enum DatasetState {
    /// No live build known.
    Absent,
    /// A build is running (one at a time per dataset, ruling P47-5).
    Building {
        phase: Phase,
        done: u64,
        total: Option<u64>,
        started: Instant,
    },
    /// The live build, its files open.
    Live {
        manifest: Arc<Manifest>,
        open: Arc<LiveHandles>,
    },
    /// The live build cannot be used until the next refresh; why.
    NeedsRefresh(String),
}

impl DatasetState {
    fn snapshot(&self) -> DatasetState {
        match self {
            DatasetState::Absent => DatasetState::Absent,
            DatasetState::Building {
                phase,
                done,
                total,
                started,
            } => DatasetState::Building {
                phase: *phase,
                done: *done,
                total: *total,
                started: *started,
            },
            DatasetState::Live { manifest, open } => DatasetState::Live {
                manifest: Arc::clone(manifest),
                open: Arc::clone(open),
            },
            DatasetState::NeedsRefresh(why) => DatasetState::NeedsRefresh(why.clone()),
        }
    }
}

impl std::fmt::Debug for DatasetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatasetState::Absent => f.write_str("Absent"),
            DatasetState::Building {
                phase, done, total, ..
            } => f
                .debug_struct("Building")
                .field("phase", phase)
                .field("done", done)
                .field("total", total)
                .finish_non_exhaustive(),
            DatasetState::Live { manifest, .. } => f
                .debug_struct("Live")
                .field("built_at", &manifest.built_at)
                .finish_non_exhaustive(),
            DatasetState::NeedsRefresh(why) => f.debug_tuple("NeedsRefresh").field(why).finish(),
        }
    }
}

/// A live build's open files. The lexicon's SQLite connections are not
/// `Sync`, so it is behind a lock.
pub struct LiveHandles {
    pub lexicon: Mutex<Lexicon>,
    pub index: Option<KnownIndex>,
    pub allow: AllowList,
}

impl std::fmt::Debug for LiveHandles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveHandles")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// Why a `blind.*` op refused. `text` never holds a dataset value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// `BadRequest`, `Forbidden`, `Busy` or `Unavailable`.
    pub code: ErrorCode,
    pub text: String,
}

impl Refusal {
    pub fn new(code: ErrorCode, text: impl Into<String>) -> Refusal {
        Refusal {
            code,
            text: text.into(),
        }
    }

    /// The error answer of request `id`.
    pub fn to_value(&self, id: u64) -> Value {
        saiife_ipc::msg::err(id, self.code, &self.text)
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The fixed refreshing answer (en).
fn refreshing(name: &DatasetName, phase: Phase, done: u64, total: Option<u64>) -> String {
    let phase = match phase {
        Phase::Snapshot => "snapshot",
        Phase::Lexicon => "lexicon",
        Phase::Index => "index",
        Phase::Validate => "validate",
        Phase::Swap => "swap",
    };
    let total = total.map_or_else(|| "?".to_string(), |t| t.to_string());
    format!("{name} is refreshing ({phase}, {done} of {total}); try again in a moment")
}

impl Blind {
    /// The state under `root` (`<state>/blind`), made 0700 when missing.
    /// Every dataset starts [`DatasetState::Absent`]; a failure to make the
    /// dir is a warning, and each op that needs it fails then.
    pub fn open(root: &Path) -> Blind {
        if let Err(e) = private_dir(root) {
            eprintln!(
                "saiifed: warning: {}: {e}: Data Shield is unavailable",
                root.display()
            );
        }
        Blind {
            root: root.to_path_buf(),
            datasets: Mutex::new(BTreeMap::new()),
            sessions: Mutex::new(saiife_shield::session::Sessions::new()),
            keys_lock: Mutex::new(()),
        }
    }

    /// `<root>/datasets/<name>`.
    pub fn dataset_dir(&self, name: &DatasetName) -> DatasetDir {
        DatasetDir {
            root: self.root.join(DATASETS_DIR).join(name.as_str()),
        }
    }

    /// A copy of the dataset's state (the handles shared).
    pub fn state(&self, name: &DatasetName) -> DatasetState {
        lock(&self.datasets)
            .get(name.as_str())
            .map_or(DatasetState::Absent, DatasetState::snapshot)
    }

    /// Sets the dataset's state; `Absent` removes it from the map.
    pub fn set_state(&self, name: &DatasetName, s: DatasetState) {
        let mut m = lock(&self.datasets);
        match s {
            DatasetState::Absent => {
                m.remove(name.as_str());
            }
            s => {
                m.insert(name.as_str().to_string(), s);
            }
        }
    }

    /// The live build an ask runs on, or why there is none.
    pub fn live(&self, name: &DatasetName) -> Result<(Arc<Manifest>, Arc<LiveHandles>), Refusal> {
        match &self.state(name) {
            DatasetState::Live { manifest, open } => Ok((Arc::clone(manifest), Arc::clone(open))),
            DatasetState::Building {
                phase, done, total, ..
            } => Err(Refusal::new(
                ErrorCode::Busy,
                refreshing(name, *phase, *done, *total),
            )),
            DatasetState::NeedsRefresh(why) => {
                Err(Refusal::new(ErrorCode::Unavailable, why.clone()))
            }
            DatasetState::Absent => Err(Refusal::new(
                ErrorCode::Unavailable,
                format!("{name} has not been built: saiife blind data refresh --dataset {name}"),
            )),
        }
    }

    pub(crate) fn keys_lock(&self) -> MutexGuard<'_, ()> {
        lock(&self.keys_lock)
    }
}

/// `dir` and its missing parents at 0700, and `dir` itself set to 0700 if
/// it already was there (ruling P47-8). A symlink is refused.
pub(crate) fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    crate::fsx::create_private_dirs(dir)?;
    let md = std::fs::symlink_metadata(dir)?;
    if !md.is_dir() {
        return Err(io::Error::other("not a directory (links are not followed)"));
    }
    if md.permissions().mode() & 0o777 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes `bytes` to `path` so that a reader sees the old file or the new
/// one, never a part (ruling P47-8): the parent made 0700, a new 0600 temp
/// file beside it (never through a link), fsync, rename, fsync of the dir.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("no parent directory"))?;
    private_dir(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("no file name"))?;
    let mut part = name.to_os_string();
    part.push(".part");
    let part = dir.join(part);
    // A part left by a crash is ours; `create_new` never follows a link.
    match std::fs::remove_file(&part) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let done = (|| {
        let mut f = crate::fsx::new_private_file(&part)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&part, path)
    })();
    if done.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    done?;
    crate::fsx::sync_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_private_is_0600_in_0700_and_replaces() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a/b/f");
        write_private(&p, b"one").unwrap();
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(p.parent().unwrap()), 0o700);
        // A stale part and a loose dir are repaired.
        std::fs::set_permissions(p.parent().unwrap(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::write(p.with_file_name("f.part"), b"junk").unwrap();
        write_private(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(mode(p.parent().unwrap()), 0o700);
        assert!(!p.with_file_name("f.part").exists());
    }

    #[test]
    fn write_private_never_follows_a_part_link() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let d = t.path().join("d");
        std::fs::create_dir(&d).unwrap();
        std::os::unix::fs::symlink(&target, d.join("f.part")).unwrap();
        write_private(&d.join("f"), b"new").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert_eq!(std::fs::read(d.join("f")).unwrap(), b"new");
    }

    #[test]
    fn states_and_live_refusals() {
        let t = tempfile::tempdir().unwrap();
        let b = Blind::open(&t.path().join("blind"));
        assert_eq!(mode(&b.root), 0o700);
        let ds: DatasetName = "crm".parse().unwrap();
        assert_eq!(b.dataset_dir(&ds).root, t.path().join("blind/datasets/crm"));
        let r = b.live(&ds).unwrap_err();
        assert_eq!(r.code, ErrorCode::Unavailable);
        b.set_state(
            &ds,
            DatasetState::Building {
                phase: Phase::Index,
                done: 3,
                total: Some(9),
                started: Instant::now(),
            },
        );
        let r = b.live(&ds).unwrap_err();
        assert_eq!(r.code, ErrorCode::Busy);
        assert_eq!(
            r.text,
            "crm is refreshing (index, 3 of 9); try again in a moment"
        );
        let v = r.to_value(4);
        assert_eq!(v["error"], "busy");
        assert_eq!(v["id"], 4);
        b.set_state(&ds, DatasetState::NeedsRefresh("why".into()));
        assert_eq!(b.live(&ds).unwrap_err().text, "why");
        b.set_state(&ds, DatasetState::Absent);
        assert!(matches!(b.state(&ds), DatasetState::Absent));
    }
}
