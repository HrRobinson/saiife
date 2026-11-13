//! The box store (spec §7.3): one labelled directory per box under the state
//! root, `box.json` written atomically, ids from a persisted counter.
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::BoxesError;
use crate::template::Size;
use saiife_wire::source::{BoxId, BoxState};

const MARKER: &str = ".saiife-box";
const RECORD: &str = "box.json";
const COUNTER: &str = "next-id";
const VERSION: u32 = 1;

/// Opaque to the manager; only the VMM driver reads `data`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmHandle {
    pub id: BoxId,
    pub driver: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoxRecord {
    pub version: u32,
    pub id: BoxId,
    pub state: BoxState,
    pub owner_uid: u32,
    pub session: String,
    pub template: String,
    pub size: Size,
    pub repo: String,
    pub repo_dir: Option<String>,
    pub task: String,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub updated_at: u64,
    pub queue_seq: Option<u64>,
    pub vm: Option<VmHandle>,
    pub vm_on: bool,
    pub keep: bool,
    pub lands: u32,
    pub last_activity: u64,
    pub turn_finished_at: Option<u64>,
    pub pending_prompt: Option<String>,
    pub error: Option<String>,
    /// The base image id (plan 36), set at admission from the VMM
    /// (`Vmm::image_id`); `None` before, or when the driver cannot say.
    #[serde(default)]
    pub image: Option<String>,
}

/// Single-writer by contract: the Manager's one Mutex serialises every Store
/// call (spawn's `claim_id` plus first `save`, and gc, all run under it). A
/// spawn with a repo disk lets the lock go between the two, to move the disk
/// in; the manager marks that id as being placed and gc leaves it alone.
pub struct Store {
    root: PathBuf,
}

fn io_err(path: &Path, source: io::Error) -> BoxesError {
    BoxesError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn state_err(path: &Path, msg: impl Into<String>) -> BoxesError {
    BoxesError::State {
        path: path.to_path_buf(),
        msg: msg.into(),
    }
}

fn marker_text(id: &str) -> String {
    format!("saiife.managed box {id}\n")
}

static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Write `bytes` to `<final_path>.tmp.<pid>.<n>` (0600 on unix) then rename over `final_path`.
fn write_atomic(final_path: &Path, bytes: &[u8]) -> Result<(), BoxesError> {
    use std::io::Write;
    let mut name = final_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let tmp = final_path.with_file_name(name);
    let _ = fs::remove_file(&tmp);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|e| io_err(&tmp, e))?;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(io_err(&tmp, e));
    }
    drop(f);
    fs::rename(&tmp, final_path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_err(final_path, e)
    })
}

impl Store {
    pub fn open(root: PathBuf) -> Result<Store, BoxesError> {
        fs::create_dir_all(&root).map_err(|e| io_err(&root, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .map_err(|e| io_err(&root, e))?;
        }
        Ok(Store { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn box_dir(&self, id: &BoxId) -> PathBuf {
        self.root.join(id.as_str())
    }

    /// Next unused id from the persisted counter; never reuses a number.
    pub fn claim_id(&self) -> Result<BoxId, BoxesError> {
        let counter = self.root.join(COUNTER);
        let mut n: u64 = match fs::read_to_string(&counter) {
            Ok(t) => t
                .trim()
                .parse()
                .map_err(|_| state_err(&counter, "counter is not a number"))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => 1,
            Err(e) => return Err(io_err(&counter, e)),
        };
        n = n.max(1);
        loop {
            let id =
                BoxId::parse(&format!("b{n}")).map_err(|e| state_err(&counter, e.to_string()))?;
            let dir = self.box_dir(&id);
            #[cfg(unix)]
            let b = {
                use std::os::unix::fs::DirBuilderExt;
                let mut b = fs::DirBuilder::new();
                b.mode(0o700);
                b
            };
            #[cfg(not(unix))]
            let b = fs::DirBuilder::new();
            match b.create(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    n = n
                        .checked_add(1)
                        .ok_or_else(|| state_err(&counter, "counter overflow"))?;
                    continue;
                }
                Err(e) => return Err(io_err(&dir, e)),
            }
            let marker = dir.join(MARKER);
            if let Err(e) = write_atomic(&marker, marker_text(id.as_str()).as_bytes()) {
                let _ = fs::remove_dir_all(&dir);
                return Err(e);
            }
            let next = n
                .checked_add(1)
                .ok_or_else(|| state_err(&counter, "counter overflow"))?;
            write_atomic(&counter, next.to_string().as_bytes())?;
            return Ok(id);
        }
    }

    /// Ok when `dir` is a real directory (not a symlink) labelled for `id`.
    fn check_labelled(&self, id: &BoxId) -> Result<(), BoxesError> {
        let dir = self.box_dir(id);
        let md = fs::symlink_metadata(&dir).map_err(|e| io_err(&dir, e))?;
        if !md.file_type().is_dir() {
            return Err(state_err(&dir, "not a real directory"));
        }
        let marker = dir.join(MARKER);
        match fs::read_to_string(&marker) {
            Ok(t) if t == marker_text(id.as_str()) => Ok(()),
            Ok(_) => Err(state_err(&marker, "marker names another box")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(state_err(&marker, "marker missing"))
            }
            Err(e) => Err(io_err(&marker, e)),
        }
    }

    pub fn save(&self, r: &BoxRecord) -> Result<(), BoxesError> {
        self.check_labelled(&r.id)?;
        let file = self.box_dir(&r.id).join(RECORD);
        let text = serde_json::to_string_pretty(r).map_err(|e| state_err(&file, e.to_string()))?;
        write_atomic(&file, text.as_bytes())
    }

    pub fn load(&self, id: &BoxId) -> Result<Option<BoxRecord>, BoxesError> {
        let dir = self.box_dir(id);
        match fs::symlink_metadata(&dir) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(&dir, e)),
        }
        self.check_labelled(id)?;
        let file = dir.join(RECORD);
        let text = match fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(&file, e)),
        };
        let r: BoxRecord =
            serde_json::from_str(&text).map_err(|e| state_err(&file, e.to_string()))?;
        if r.version != VERSION {
            return Err(state_err(
                &file,
                format!("unsupported version {}", r.version),
            ));
        }
        if &r.id != id {
            return Err(state_err(&file, "id does not match its folder"));
        }
        Ok(Some(r))
    }

    /// Every directory entry that is a folder or symlink, with its name.
    fn entries(&self) -> Result<Vec<(String, bool)>, BoxesError> {
        let rd = match fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_err(&self.root, e)),
        };
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| io_err(&self.root, e))?;
            let ft = entry.file_type().map_err(|e| io_err(&entry.path(), e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // The daemon's staging of passed repo disks (plan 37), not a box.
            if name == crate::place::INCOMING {
                continue;
            }
            if ft.is_dir() || ft.is_symlink() {
                out.push((name, ft.is_symlink()));
            }
        }
        out.sort();
        Ok(out)
    }

    /// Records sorted by id; each skipped entry is named in the warnings.
    pub fn list(&self) -> Result<(Vec<BoxRecord>, Vec<String>), BoxesError> {
        let mut records = Vec::new();
        let mut warns = Vec::new();
        for (name, symlink) in self.entries()? {
            if symlink {
                warns.push(format!("{name}: symlink, skipped"));
                continue;
            }
            let id = match BoxId::parse(&name) {
                Ok(id) => id,
                Err(_) => {
                    warns.push(format!("{name}: not a box id, skipped"));
                    continue;
                }
            };
            match self.load(&id) {
                Ok(Some(r)) => records.push(r),
                Ok(None) => warns.push(format!("{name}: no box.json, skipped")),
                Err(e) => warns.push(format!("{name}: {e}")),
            }
        }
        records.sort_by(|a, b| a.id.cmp(&b.id));
        Ok((records, warns))
    }

    /// Delete a labelled box directory. Refuses symlinks and unlabelled dirs.
    pub fn remove(&self, id: &BoxId) -> Result<(), BoxesError> {
        let dir = self.box_dir(id);
        match fs::symlink_metadata(&dir) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io_err(&dir, e)),
        }
        self.check_labelled(id)?;
        fs::remove_dir_all(&dir).map_err(|e| io_err(&dir, e))
    }

    /// Labelled, non-symlink directories whose `box.json` is missing (leftovers
    /// of a crash). A present but unreadable or unparsable record is never an
    /// orphan: it stays a `list()` warning.
    pub fn orphans(&self) -> Result<Vec<BoxId>, BoxesError> {
        let mut out = Vec::new();
        for (name, symlink) in self.entries()? {
            if symlink {
                continue;
            }
            let Ok(id) = BoxId::parse(&name) else {
                continue;
            };
            if self.check_labelled(&id).is_err() {
                continue;
            }
            if matches!(self.load(&id), Ok(None)) {
                out.push(id);
            }
        }
        Ok(out)
    }
}
