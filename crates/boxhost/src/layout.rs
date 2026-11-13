//! Where boxes, images and the VMM live on disk (V5, V6).

use crate::paths::BoxPaths;
use saiife_wire::source::BoxId;
use std::path::{Path, PathBuf};

/// The box records under a state dir: `<state_dir>/boxes`, the daemon's
/// box store root (daemon-only, R37). Not a VMM runtime root: that is
/// [`Layout::boxes`].
pub fn boxes_in(state_dir: &Path) -> PathBuf {
    state_dir.join("boxes")
}

/// The personal image store under a state dir: `<state_dir>/images`, the
/// VMM-readable half of the image store (raw disks and kernels). The
/// daemon keeps the image manifests apart, in its own records dir.
pub fn images_in(state_dir: &Path) -> PathBuf {
    state_dir.join("images")
}

/// The daemon-only half of the image store (the manifests and `default`,
/// plan 36 R24) under a daemon state dir: personal `<state>/image-records`
/// (apart from the VMM-readable [`images_in`]), locked `<state>/images`
/// (`/var/lib/saiife/images`, apart from [`Layout::locked`]'s images).
pub fn image_records_in(state_dir: &Path, locked: bool) -> PathBuf {
    if locked {
        state_dir.join("images")
    } else {
        state_dir.join("image-records")
    }
}

/// Daemon-trusted state: where the daemon stages a repo disk and its base
/// manifest a CLI passed (plan 37), under the box store (record) root. The daemon
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

    /// [`Layout::locked`] with every path under `root` (tests: no test
    /// reads the host's install, M1).
    pub fn locked_under(root: &Path) -> Layout {
        let at = |p: PathBuf| root.join(p.strip_prefix("/").unwrap_or(&p));
        let l = Layout::locked();
        Layout {
            boxes: at(l.boxes),
            images: at(l.images),
            vmm: at(l.vmm),
            vault: at(l.vault),
            locked: true,
        }
    }

    /// The personal layout under the user's state dir and XDG data home.
    ///
    /// `boxes` is the VMM's runtime root, `<state>/box-run` (R37), apart from
    /// the daemon's record dirs (`<state>/boxes`, the box store's). The VMM
    /// runs as the user here, so its Landlock rules are the boundary: they
    /// cover only its runtime dir, the disks and (read-only) its vault copy,
    /// never the record dirs.
    pub fn personal(state_dir: &Path, data_home: &Path) -> Layout {
        Layout {
            boxes: state_dir.join("box-run"),
            images: images_in(state_dir),
            vmm: data_home.join("saiife").join("vmm"),
            vault: state_dir.join("box-vault"),
            locked: false,
        }
    }

    /// The VMM-side files of box `id` ([`BoxPaths::of`] under this layout's
    /// runtime root).
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
    fn layout_locked_under_a_root() {
        let l = Layout::locked_under(Path::new("/t/r"));
        assert_eq!(l.boxes, PathBuf::from("/t/r/var/lib/saiife-box/boxes"));
        assert_eq!(l.vmm, PathBuf::from("/t/r/opt/saiife/vmm"));
        assert_eq!(l.vault, PathBuf::from("/t/r/var/lib/saiife-box/vault"));
        assert!(l.locked);
    }

    #[test]
    fn layout_personal_paths() {
        let l = Layout::personal(Path::new("/s/state"), Path::new("/s/data"));
        assert_eq!(l.boxes, PathBuf::from("/s/state/box-run"));
        assert_eq!(l.images, PathBuf::from("/s/state/images"));
        assert_eq!(l.vmm, PathBuf::from("/s/data/saiife/vmm"));
        assert_eq!(l.vault, PathBuf::from("/s/state/box-vault"));
        assert!(!l.locked);
    }

    #[test]
    fn records_and_runtime_dirs_are_apart() {
        let id = saiife_wire::source::BoxId::parse("b7").unwrap();
        let state = Path::new("/s/state");
        let l = Layout::personal(state, Path::new("/s/data"));
        assert_eq!(boxes_in(state), PathBuf::from("/s/state/boxes"));
        assert_ne!(boxes_in(state), l.boxes);
        assert_eq!(images_in(state), l.images);
        assert_eq!(
            image_records_in(state, false),
            PathBuf::from("/s/state/image-records")
        );
        assert_eq!(
            image_records_in(Path::new("/var/lib/saiife"), true),
            PathBuf::from("/var/lib/saiife/images")
        );
        assert_ne!(
            image_records_in(Path::new("/var/lib/saiife"), true),
            Layout::locked().images
        );
        assert_eq!(
            incoming_in(&boxes_in(state)),
            PathBuf::from("/s/state/boxes/.incoming")
        );
        assert_eq!(l.box_paths(&id).dir, PathBuf::from("/s/state/box-run/b7"));
        let l = Layout::locked();
        assert_eq!(
            l.box_paths(&id).dir,
            PathBuf::from("/var/lib/saiife-box/boxes/b7")
        );
    }
}
