//! The Data Shield drop-ins (plan 48 T5, R48-7): `policy.d/blind.toml`
//! (the `[blind]` globals) and `policy.d/blind-<dataset>.toml` (one
//! `[[blind.dataset]]`), in the config dir of the daemon the CLI talks to.
//!
//! Each file starts with [`MARKER`]. A file without it was written by hand
//! and is never overwritten. A write is a temp file and a rename; the file
//! is 0644 (root's) on a locked host and 0600 for the personal broker.
//! [`reload`] asks the daemon to load the policy; when that fails the
//! caller puts the previous file back ([`Previous::restore`]).

use super::imp::{call, s, Stop, READ_TIMEOUT};
use crate::broker::Target;
use saiife_policy::blind::{BlindCfg, BlindDataset};
use saiife_shield::schema::DatasetName;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The first line of every file `saiife blind` writes.
pub(crate) const MARKER: &str = "# written by saiife blind";

/// What a Data Shield drop-in holds: `[blind]` only.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DropIn {
    #[serde(default)]
    blind: BlindCfg,
}

/// `<config dir>/policy.d`.
pub(crate) fn dropin_dir(t: &Target) -> PathBuf {
    t.config()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("policy.d")
}

/// `policy.d/blind-<name>.toml`; `name` must be a dataset name (so it is
/// one plain file name).
pub(crate) fn dataset_path(t: &Target, name: &str) -> Result<PathBuf, String> {
    let n: DatasetName = name
        .parse()
        .map_err(|_| format!("{name:?} is not a dataset name"))?;
    Ok(dropin_dir(t).join(format!("blind-{n}.toml")))
}

/// `policy.d/blind.toml`.
pub(crate) fn globals_path(t: &Target) -> PathBuf {
    dropin_dir(t).join("blind.toml")
}

/// The refusal for a file without the marker.
pub(crate) fn not_ours(path: &Path) -> String {
    format!(
        "{} was not written by saiife blind (its first line is not \"{MARKER}\"), so it is left as it is: edit it by hand, then saiife policy reload",
        path.display()
    )
}

/// (file mode, dir mode): root's on a locked host, the user's own for the
/// personal broker.
fn modes(t: &Target) -> (u32, u32) {
    if t.is_locked() {
        (0o644, 0o755)
    } else {
        (0o600, 0o700)
    }
}

/// The drop-in dir of a locked host is root's.
pub(crate) fn may_write(t: &Target) -> Result<(), String> {
    if t.is_locked() && !rustix::process::geteuid().is_root() {
        return Err(format!(
            "{} is root's on a locked host: run this as root (sudo saiife blind …)",
            dropin_dir(t).display()
        ));
    }
    Ok(())
}

/// The bytes of `path` when `saiife blind` wrote it; `None` when there is
/// no such file. A file without the marker, or anything but a regular
/// file, is refused.
fn read_ours(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => {
            return Err(format!(
                "{} is not a regular file (symlinks are not followed)",
                path.display()
            ))
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    }
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let first = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    if first.strip_suffix(b"\r").unwrap_or(first) != MARKER.as_bytes() {
        return Err(not_ours(path));
    }
    Ok(Some(bytes))
}

/// The file's text: the marker, a note, then the TOML.
fn render(d: &DropIn) -> Result<String, String> {
    let body = toml::to_string(d).map_err(|e| format!("cannot write the policy as TOML: {e}"))?;
    Ok(format!(
        "{MARKER}\n# Data Shield policy (docs/data-shield.md). saiife blind rewrites this file;\n# remove the first line to keep it as you edit it.\n\n{body}"
    ))
}

/// Writes `text` to `path` (temp + rename), refusing a file it did not
/// write.
fn write(t: &Target, path: &Path, text: &str) -> Result<PathBuf, String> {
    may_write(t)?;
    read_ours(path)?;
    let (file_mode, dir_mode) = modes(t);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(dir_mode)
            .create(dir)
            .map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    }
    saiife_system::fsops::write_file_atomic(path, text.as_bytes(), file_mode)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path.to_path_buf())
}

/// `policy.d/blind-<name>.toml` holding `d` (its one `[[blind.dataset]]`).
pub(crate) fn write_dataset(t: &Target, d: &BlindDataset) -> Result<PathBuf, String> {
    let path = dataset_path(t, &d.name)?;
    let file = DropIn {
        blind: BlindCfg {
            dataset: vec![d.clone()],
            ..BlindCfg::default()
        },
    };
    write(t, &path, &render(&file)?)
}

/// `policy.d/blind.toml` holding the `[blind]` globals of `g` (its
/// datasets go in their own files).
pub(crate) fn write_globals(t: &Target, g: &BlindCfg) -> Result<PathBuf, String> {
    let path = globals_path(t);
    let file = DropIn {
        blind: BlindCfg {
            dataset: Vec::new(),
            ..g.clone()
        },
    };
    write(t, &path, &render(&file)?)
}

/// The dataset `name` as `policy.d/blind-<name>.toml` defines it; `None`
/// when there is no such file (the dataset is defined elsewhere, or not at
/// all). A file without the marker is refused.
pub(crate) fn read_dataset(t: &Target, name: &str) -> Result<Option<BlindDataset>, String> {
    let path = dataset_path(t, name)?;
    let Some(bytes) = read_ours(&path)? else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    let d: DropIn =
        toml::from_str(&text).map_err(|e| format!("{} does not parse: {e}", path.display()))?;
    d.blind
        .dataset
        .into_iter()
        .find(|x| x.name == name)
        .map(Some)
        .ok_or_else(|| format!("{} does not define the dataset {name}", path.display()))
}

/// The `[blind]` globals of `policy.d/blind.toml`; the default when there
/// is no such file. A file without the marker is refused.
pub(crate) fn read_globals(t: &Target) -> Result<BlindCfg, String> {
    let path = globals_path(t);
    let Some(bytes) = read_ours(&path)? else {
        return Ok(BlindCfg::default());
    };
    let text = String::from_utf8(bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    let d: DropIn =
        toml::from_str(&text).map_err(|e| format!("{} does not parse: {e}", path.display()))?;
    Ok(d.blind)
}

/// A file as it was before a write, to put back when the reload fails.
pub(crate) struct Previous {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
}

/// `path` as it is now (missing: `None`).
pub(crate) fn previous(path: &Path) -> Result<Previous, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    Ok(Previous {
        path: path.to_path_buf(),
        bytes,
    })
}

impl Previous {
    /// The file this is the previous state of.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The previous file back, or the new one removed.
    pub(crate) fn restore(self, t: &Target) -> Result<(), String> {
        match self.bytes {
            Some(b) => saiife_system::fsops::write_file_atomic(&self.path, &b, modes(t).0)
                .map_err(|e| format!("cannot put back {}: {e}", self.path.display())),
            None => match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("cannot remove {}: {e}", self.path.display())),
            },
        }
    }
}

/// `policy.reload` (OP_POLICY_RELOAD): `Err` with the loader's reason when
/// the daemon kept the old policy, or why it could not be asked.
pub(crate) fn reload(t: &Target) -> Result<(), String> {
    let a =
        call(t, "policy.reload", serde_json::Map::new(), READ_TIMEOUT).map_err(|e| match e {
            Stop::Refused(m) | Stop::Unavailable(m) => m,
        })?;
    let v = serde_json::Value::Object(a);
    match s(&v, "result") {
        "loaded" => Ok(()),
        other => {
            let why = s(&v, "reason");
            Err(if why.is_empty() {
                format!("the policy was not loaded ({other})")
            } else {
                why.to_string()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saiife_policy::blind::{BlindSource, ColumnCfg};

    fn personal(dir: &Path) -> Target {
        Target::Personal {
            config: dir.join("config.toml"),
            socket_dir: dir.join("sock"),
            owner_uid: rustix::process::getuid().as_raw(),
        }
    }

    fn crm() -> BlindDataset {
        let mut columns = std::collections::BTreeMap::new();
        columns.insert(
            "customers.city".to_string(),
            ColumnCfg {
                class: "quasi".into(),
                alias: None,
            },
        );
        BlindDataset {
            name: "crm".into(),
            source: BlindSource::Sqlite {
                file_name: "crm.sqlite".into(),
            },
            users: vec!["ann".into()],
            approvers: Vec::new(),
            mode: "exact".into(),
            k: None,
            preview_required: true,
            list_cap: None,
            tables: Default::default(),
            columns,
            entity: Vec::new(),
            joins: Vec::new(),
        }
    }

    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn dataset_round_trips_with_the_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let t = personal(tmp.path());
        assert_eq!(dropin_dir(&t), tmp.path().join("policy.d"));
        let p = write_dataset(&t, &crm()).unwrap();
        assert_eq!(p, tmp.path().join("policy.d/blind-crm.toml"));
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().next(), Some(MARKER));
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(&dropin_dir(&t)), 0o700);
        assert_eq!(read_dataset(&t, "crm").unwrap(), Some(crm()));
        // The policy loader reads it as a drop-in.
        std::fs::write(t.config(), "version = 2\n").unwrap();
        let l = saiife_policy::load_system(t.config()).unwrap();
        assert_eq!(l.config.blind.dataset, vec![crm()]);
        // Written again over its own file.
        let mut d = crm();
        d.preview_required = false;
        write_dataset(&t, &d).unwrap();
        assert_eq!(read_dataset(&t, "crm").unwrap(), Some(d));
        assert_eq!(read_dataset(&t, "other").unwrap(), None);
        assert!(dataset_path(&t, "../x").is_err());
    }

    #[test]
    fn a_hand_written_file_is_never_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let t = personal(tmp.path());
        let dir = dropin_dir(&t);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("blind-crm.toml");
        std::fs::write(&p, "# mine\n[[blind.dataset]]\n").unwrap();
        assert_eq!(write_dataset(&t, &crm()).unwrap_err(), not_ours(&p));
        assert_eq!(read_dataset(&t, "crm").unwrap_err(), not_ours(&p));
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "# mine\n[[blind.dataset]]\n"
        );
        std::fs::write(globals_path(&t), "[blind]\nk = 5\n").unwrap();
        assert_eq!(
            write_globals(&t, &BlindCfg::default()).unwrap_err(),
            not_ours(&globals_path(&t))
        );
    }

    #[test]
    fn globals_leave_datasets_out_and_restore_puts_back() {
        let tmp = tempfile::tempdir().unwrap();
        let t = personal(tmp.path());
        let g = BlindCfg {
            k: Some(12),
            dataset: vec![crm()],
            ..BlindCfg::default()
        };
        let before = previous(&globals_path(&t)).unwrap();
        assert_eq!(read_globals(&t).unwrap(), BlindCfg::default());
        let p = write_globals(&t, &g).unwrap();
        assert_eq!(read_globals(&t).unwrap().k, Some(12));
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with(&format!("{MARKER}\n")), "{text}");
        assert!(text.contains("k = 12"), "{text}");
        assert!(!text.contains("crm"), "{text}");
        // A new file is removed again.
        before.restore(&t).unwrap();
        assert!(!p.exists());
        // An old one comes back as it was.
        write_globals(&t, &g).unwrap();
        let kept = std::fs::read(&p).unwrap();
        let before = previous(&p).unwrap();
        write_globals(&t, &BlindCfg::default()).unwrap();
        before.restore(&t).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), kept);
    }
}
