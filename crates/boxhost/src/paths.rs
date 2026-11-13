//! The files in one box directory.
//!
//! Every path of a box goes through [`BoxPaths`] (and the store-wide ones
//! through [`crate::layout`]); nothing else joins these names. Each disk
//! file is classed as VMM-shared runtime (the VMM opens or writes it, so
//! the daemon must never trust what it finds there) or daemon-trusted
//! state (the daemon reads it and acts on it: opened `O_NOFOLLOW`, fstat'd
//! for type, owner and size). Today both live in the box dir; plan 35's
//! locked layout may point the daemon-trusted helpers at a daemon-only
//! tree, which moves only these helpers.

use saiife_wire::source::BoxId;
use std::path::{Path, PathBuf};

/// VMM-shared runtime: the box's qcow2 root disk (overlay on the base).
pub const ROOT_DISK: &str = "root.qcow2";
/// VMM-shared runtime: the box's ext4 repo disk (plan 37), `/work` in the
/// guest.
pub const REPO_DISK: &str = "repo.img";
/// Daemon-trusted state: the base manifest of the repo disk (plan 37).
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
    /// Daemon-trusted state ([`BASE_MANIFEST`]): read only through
    /// `O_NOFOLLOW` with an owner check (the daemon's `box_repo`).
    pub fn base_manifest(&self) -> PathBuf {
        self.file(BASE_MANIFEST)
    }
    pub fn snapshot_dir(&self) -> PathBuf {
        self.file("snapshot")
    }
    pub fn term_cast(&self) -> PathBuf {
        self.file("term.cast")
    }
    /// Daemon-trusted state: the land records (plan 39), one dir per export.
    pub fn lands_dir(&self) -> PathBuf {
        self.file("lands")
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
    pub fn placeholder(&self) -> PathBuf {
        self.file("placeholder")
    }
    /// The longest socket path in the box dir (for sun_path length checks).
    pub fn longest_socket(&self) -> PathBuf {
        self.vsock_port(5003)
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
        assert_eq!(p.base_manifest(), p.dir.join(BASE_MANIFEST));
    }

    #[test]
    fn land_files_are_under_lands() {
        let p = BoxPaths::new(PathBuf::from("/b/x"));
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
        let n = |s: &str| BoxPaths::land_number(std::ffi::OsStr::new(s));
        assert_eq!(n("3"), Some(3));
        assert_eq!(n("4294967295"), Some(u32::MAX));
        for bad in ["", "03", "-1", "1a", "4294967296", ".3"] {
            assert_eq!(n(bad), None, "{bad}");
        }
    }
}
