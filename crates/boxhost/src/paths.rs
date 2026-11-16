//! The files in one box's runtime directory (`<layout.boxes>/<id>`, shared
//! with the VMM; R37). Only VMM-side files live here: the spec, sockets,
//! logs, disks and `snapshot/`. Daemon-trusted files (`base.json`,
//! `term.cast`, `lands/`: review and land state; plans 37-39)
//! belong in the box's record dir, which the box store owns.

use saiife_wire::source::BoxId;
use std::path::{Path, PathBuf};

/// VMM-shared runtime: the box's qcow2 root disk (overlay on the base).
pub const ROOT_DISK: &str = "root.qcow2";
/// VMM-shared runtime: the box's ext4 repo disk (plan 37), `/work` in the
/// guest. Spawn places it in the record dir; `ChVmm::create` moves it here
/// (`repo_handover`).
pub const REPO_DISK: &str = "repo.img";
/// Daemon-trusted state: the box's terminal recording (plan 38, R15), in
/// its record dir only (`layout::record_dir`).
pub const TERM_CAST: &str = "term.cast";
/// Daemon-trusted state: the box's model placeholder (plan 40, C1), one
/// line, 0600, in its record dir only (`placeholder::read_or_make_placeholder`).
pub const PLACEHOLDER: &str = "placeholder";
/// Daemon-trusted state: the base manifest of the repo disk (plan 37). It
/// lives in the box's record dir only (`layout::record_disk_place`), never
/// in a runtime dir, so [`BoxPaths`] has no helper for it.
pub const BASE_MANIFEST: &str = "base.json";

#[derive(Debug, Clone)]
pub struct BoxPaths {
    pub dir: PathBuf,
}

impl BoxPaths {
    pub fn new(dir: PathBuf) -> BoxPaths {
        BoxPaths { dir }
    }
    /// The box `id` of the store at `boxes_root`: `<boxes_root>/<id>`. The
    /// one place the per-box dir is made from a root and an id.
    pub fn of(boxes_root: &Path, id: &BoxId) -> BoxPaths {
        BoxPaths::new(boxes_root.join(id.as_str()))
    }
    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    pub fn vm_json(&self) -> PathBuf {
        self.file("vm.json")
    }
    pub fn api_sock(&self) -> PathBuf {
        self.file("api.sock")
    }
    pub fn vsock(&self) -> PathBuf {
        self.file("vsock.sock")
    }
    /// The Cloud Hypervisor multiplexer socket for a guest-initiated port.
    pub fn vsock_port(&self, port: u32) -> PathBuf {
        self.file(&format!("vsock.sock_{port}"))
    }
    pub fn serial(&self) -> PathBuf {
        self.file("serial.log")
    }
    pub fn ch_log(&self) -> PathBuf {
        self.file("ch.log")
    }
    /// VMM-shared runtime ([`ROOT_DISK`]).
    pub fn root_disk(&self) -> PathBuf {
        self.file(ROOT_DISK)
    }
    /// VMM-shared runtime ([`REPO_DISK`]): the VMM opens it read-write.
    pub fn repo_disk(&self) -> PathBuf {
        self.file(REPO_DISK)
    }
    pub fn snapshot_dir(&self) -> PathBuf {
        self.file("snapshot")
    }
    /// The longest socket path in the box dir (for sun_path length checks).
    pub fn longest_socket(&self) -> PathBuf {
        self.vsock_port(5003)
    }
}

/// The daemon-trusted files in one box's record dir
/// (`layout::record_dir`, `<records_root>/<id>`, R37): the land records of
/// plan 39 (`lands/<n>/`). The VMM never sees this dir; its runtime files
/// are [`BoxPaths`].
#[derive(Debug, Clone)]
pub struct RecordPaths {
    pub dir: PathBuf,
}

impl RecordPaths {
    pub fn new(dir: PathBuf) -> RecordPaths {
        RecordPaths { dir }
    }
    /// Box `id`'s record dir under the box store root `records_root`.
    pub fn of(records_root: &Path, id: &BoxId) -> RecordPaths {
        RecordPaths::new(crate::layout::record_dir(records_root, id))
    }
    /// `lands/`: the land records (plan 39), one dir per export.
    pub fn lands_dir(&self) -> PathBuf {
        self.dir.join("lands")
    }
    /// `lands/<n>/` (0700): one export's review and land records.
    pub fn land_dir(&self, n: u32) -> PathBuf {
        self.lands_dir().join(n.to_string())
    }
    /// `lands/<n>/blobs/`: content by SHA-256 (new content, and the old
    /// content of a modify the review renders as text).
    pub fn land_blobs(&self, n: u32) -> PathBuf {
        self.land_dir(n).join("blobs")
    }
    /// `lands/<n>/blobs/<sha256>`.
    pub fn land_blob(&self, n: u32, sha256: &str) -> PathBuf {
        self.land_blobs(n).join(sha256)
    }
    /// `lands/<n>/delta.bin`: the selected entries' new content, for the CLI.
    pub fn land_delta(&self, n: u32) -> PathBuf {
        self.land_dir(n).join("delta.bin")
    }
    /// `lands/<n>/review.json`.
    pub fn land_review(&self, n: u32) -> PathBuf {
        self.land_dir(n).join("review.json")
    }
    /// `lands/<n>/request.json`.
    pub fn land_request(&self, n: u32) -> PathBuf {
        self.land_dir(n).join("request.json")
    }
    /// `lands/<n>/approved.json`.
    pub fn land_approved(&self, n: u32) -> PathBuf {
        self.land_dir(n).join("approved.json")
    }
    /// `lands/<n>/applied.json`.
    pub fn land_applied(&self, n: u32) -> PathBuf {
        self.land_dir(n).join("applied.json")
    }
    /// `lands/<n>/advanced.json`: the guest's base took this land (an
    /// approved land without it is advanced again before the next export).
    pub fn land_advanced(&self, n: u32) -> PathBuf {
        self.land_dir(n).join("advanced.json")
    }
    /// The export number of a `lands/` entry name (`None`: not one).
    pub fn land_number(name: &std::ffi::OsStr) -> Option<u32> {
        let s = name.to_str()?;
        if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u32 = s.parse().ok()?;
        (n.to_string() == s).then_some(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsock_port_naming() {
        let p = BoxPaths::new(PathBuf::from("/b/x"));
        assert!(p.vsock_port(5000).ends_with("vsock.sock_5000"));
    }

    #[test]
    fn disk_names_are_the_helpers() {
        let id = saiife_wire::source::BoxId::parse("b3").unwrap();
        let p = BoxPaths::of(Path::new("/b"), &id);
        assert_eq!(p.dir, PathBuf::from("/b/b3"));
        assert_eq!(p.root_disk(), p.dir.join(ROOT_DISK));
        assert_eq!(p.repo_disk(), p.dir.join(REPO_DISK));
    }

    #[test]
    fn land_files_are_under_lands() {
        let id = saiife_wire::source::BoxId::parse("x").unwrap();
        let p = RecordPaths::of(Path::new("/b"), &id);
        assert_eq!(p.dir, crate::layout::record_dir(Path::new("/b"), &id));
        assert_eq!(p.land_dir(3), PathBuf::from("/b/x/lands/3"));
        assert_eq!(p.land_blob(3, "ab"), PathBuf::from("/b/x/lands/3/blobs/ab"));
        for f in [
            p.land_delta(3),
            p.land_review(3),
            p.land_request(3),
            p.land_approved(3),
            p.land_applied(3),
            p.land_advanced(3),
        ] {
            assert_eq!(f.parent(), Some(p.land_dir(3).as_path()));
        }
        let n = |s: &str| RecordPaths::land_number(std::ffi::OsStr::new(s));
        assert_eq!(n("3"), Some(3));
        assert_eq!(n("4294967295"), Some(u32::MAX));
        for bad in ["", "03", "-1", "1a", "4294967296", ".3"] {
            assert_eq!(n(bad), None, "{bad}");
        }
    }
}
