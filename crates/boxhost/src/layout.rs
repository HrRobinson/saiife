//! Where boxes, images and the VMM live on disk (V5, V6).

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub boxes: PathBuf,
    pub images: PathBuf,
    pub vmm: PathBuf,
    pub locked: bool,
}

impl Layout {
    /// The locked (system-owned) layout.
    pub fn locked() -> Layout {
        Layout {
            boxes: PathBuf::from("/var/lib/saiife-box/boxes"),
            images: PathBuf::from("/var/lib/saiife-box/images"),
            vmm: PathBuf::from("/opt/saiife/vmm"),
            locked: true,
        }
    }

    /// The personal layout under the user's state dir and XDG data home.
    pub fn personal(state_dir: &Path, data_home: &Path) -> Layout {
        Layout {
            boxes: state_dir.join("boxes"),
            images: state_dir.join("images"),
            vmm: data_home.join("saiife").join("vmm"),
            locked: false,
        }
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
        assert!(l.locked);
    }

    #[test]
    fn layout_personal_paths() {
        let l = Layout::personal(Path::new("/s/state"), Path::new("/s/data"));
        assert_eq!(l.boxes, PathBuf::from("/s/state/boxes"));
        assert_eq!(l.images, PathBuf::from("/s/state/images"));
        assert_eq!(l.vmm, PathBuf::from("/s/data/saiife/vmm"));
        assert!(!l.locked);
    }
}
