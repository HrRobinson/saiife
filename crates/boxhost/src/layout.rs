//! Where boxes, images and the VMM live on disk (V5, V6).

use crate::paths::BoxPaths;
use saiife_wire::source::BoxId;
use std::path::{Path, PathBuf};

/// The box store under a state dir: `<state_dir>/boxes`. The personal
/// layout's boxes root and the daemon's box store root both come from it.
pub fn boxes_in(state_dir: &Path) -> PathBuf {
    state_dir.join("boxes")
}

/// Daemon-trusted state: where the daemon stages a repo disk and its base
/// manifest a CLI passed (plan 37), under the box store root. The daemon
/// reads the manifest there, so it is the daemon's own 0700 dir, opened
/// `O_NOFOLLOW` with an owner check; gc sweeps it.
pub fn incoming_in(boxes_root: &Path) -> PathBuf {
    boxes_root.join(saiife_boxes::place::INCOMING)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub boxes: PathBuf,
    pub images: PathBuf,
    pub vmm: PathBuf,
    /// Daemon-owned, never VMM-writable: snapshot markers, verified
    /// snapshot copies and pid records (S3).
    pub vault: PathBuf,
    pub locked: bool,
}

impl Layout {
    /// The locked (system-owned) layout.
    pub fn locked() -> Layout {
        Layout {
            boxes: PathBuf::from("/var/lib/saiife-box/boxes"),
            images: PathBuf::from("/var/lib/saiife-box/images"),
            vmm: PathBuf::from("/opt/saiife/vmm"),
            vault: PathBuf::from("/var/lib/saiife-box/vault"),
            locked: true,
        }
    }

    /// The personal layout under the user's state dir and XDG data home.
    pub fn personal(state_dir: &Path, data_home: &Path) -> Layout {
        Layout {
            boxes: boxes_in(state_dir),
            images: state_dir.join("images"),
            vmm: data_home.join("saiife").join("vmm"),
            vault: state_dir.join("box-vault"),
            locked: false,
        }
    }

    /// Daemon-trusted state: [`incoming_in`] of this layout's boxes root.
    pub fn incoming(&self) -> PathBuf {
        incoming_in(&self.boxes)
    }

    /// The files of box `id` ([`BoxPaths::of`] under this layout's root).
    pub fn box_paths(&self, id: &BoxId) -> BoxPaths {
        BoxPaths::of(&self.boxes, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_locked_paths() {
        let l = Layout::locked();
        assert_eq!(l.boxes, PathBuf::from("/var/lib/saiife-box/boxes"));
        assert_eq!(l.images, PathBuf::from("/var/lib/saiife-box/images"));
        assert_eq!(l.vmm, PathBuf::from("/opt/saiife/vmm"));
        assert_eq!(l.vault, PathBuf::from("/var/lib/saiife-box/vault"));
        assert!(l.locked);
    }

    #[test]
    fn layout_personal_paths() {
        let l = Layout::personal(Path::new("/s/state"), Path::new("/s/data"));
        assert_eq!(l.boxes, PathBuf::from("/s/state/boxes"));
        assert_eq!(l.images, PathBuf::from("/s/state/images"));
        assert_eq!(l.vmm, PathBuf::from("/s/data/saiife/vmm"));
        assert_eq!(l.vault, PathBuf::from("/s/state/box-vault"));
        assert!(!l.locked);
    }

    #[test]
    fn box_dirs_and_incoming_come_from_the_layout() {
        let id = saiife_wire::source::BoxId::parse("b7").unwrap();
        let l = Layout::personal(Path::new("/s/state"), Path::new("/s/data"));
        assert_eq!(boxes_in(Path::new("/s/state")), l.boxes);
        assert_eq!(l.incoming(), PathBuf::from("/s/state/boxes/.incoming"));
        assert_eq!(incoming_in(&l.boxes), l.incoming());
        assert_eq!(l.box_paths(&id).dir, PathBuf::from("/s/state/boxes/b7"));
        let l = Layout::locked();
        assert_eq!(
            l.incoming(),
            PathBuf::from("/var/lib/saiife-box/boxes/.incoming")
        );
        assert_eq!(
            l.box_paths(&id).dir,
            PathBuf::from("/var/lib/saiife-box/boxes/b7")
        );
    }
}
