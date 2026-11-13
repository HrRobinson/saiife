//! Whether this host can run boxes (plan 35, Task 7): the pinned VMM and
//! firmware, `/dev/kvm` (personal mode), the disk tools, Landlock and a
//! default image. The daemon runs [`checks`] before it builds the real
//! driver and answers every box op with the first failure's detail
//! ([`ready`]); `saiife doctor` reports each check. Read-only: nothing is
//! created, fetched or started here.

use std::path::Path;

use crate::image::{Store, DEFAULT_IMAGE_HINT};
use crate::layout::Layout;
use crate::pins;
use crate::tools::{Tool, Tools};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// What a personal user runs to get the VMM.
pub const FETCH_HINT: &str = "run \"saiife box vmm fetch\"";
/// What a locked host runs to get everything boxes need.
pub const INSTALL_HINT: &str = "run \"sudo saiife system install --boxes\"";

fn pass(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok: true,
        detail: detail.into(),
    }
}

fn fail(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok: false,
        detail: detail.into(),
    }
}

fn hint(layout: &Layout) -> &'static str {
    if layout.locked {
        INSTALL_HINT
    } else {
        FETCH_HINT
    }
}

/// A pinned file of the VMM dir: present (not a symlink) and matching.
fn pinned(name: &'static str, what: &str, p: &Path, want: &str, hint: &str) -> Check {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_file() => match pins::verify(p, want) {
            Ok(()) => pass(name, format!("{what} matches the pin")),
            Err(e) => fail(
                name,
                format!("the {what} does not match the pin ({e}); {hint}"),
            ),
        },
        Ok(_) => fail(
            name,
            format!("{} is not a regular file; {hint}", p.display()),
        ),
        Err(_) => fail(
            name,
            format!(
                "boxes need the pinned {what} ({} is missing): {hint}",
                p.display()
            ),
        ),
    }
}

fn tool(name: &'static str, tools: &Tools, t: Tool, package: &str) -> Check {
    let p = tools.path(t);
    if p.is_file() {
        pass(name, p.display().to_string())
    } else {
        fail(
            name,
            format!("{} is missing: install {package}", p.display()),
        )
    }
}

/// Every check, in the order [`ready`] reports them. `kvm` is the device
/// to probe (`/dev/kvm`; tests pass a file), asked in personal mode only:
/// a locked VMM gets it from its unit. `landlock_abi` is the kernel's
/// Landlock ABI (`saiife_system::sandbox::landlock_abi`, which this crate
/// cannot depend on): the VMM always runs with `--landlock`.
/// `image_records` is the daemon-only half of the image store (the
/// manifests and `default`, plan 36 R24); its images are `layout.images`.
pub fn checks(
    layout: &Layout,
    image_records: &Path,
    tools: &Tools,
    kvm: &Path,
    landlock_abi: u32,
) -> Vec<Check> {
    let mut out = Vec::new();
    let hint = hint(layout);
    if layout.locked {
        let missing: Vec<String> = [&layout.boxes, &layout.images, &layout.vault, &layout.vmm]
            .iter()
            .filter(|d| !d.is_dir())
            .map(|d| d.display().to_string())
            .collect();
        out.push(if missing.is_empty() {
            pass("installed", "the box dirs are installed")
        } else {
            fail(
                "installed",
                format!(
                    "boxes are not installed ({} missing): {INSTALL_HINT}",
                    missing.join(", ")
                ),
            )
        });
    }
    out.push(pinned(
        "vmm",
        &format!("VMM (Cloud Hypervisor {})", pins::CH_VERSION),
        &layout.vmm.join("cloud-hypervisor"),
        pins::CH_SHA256,
        hint,
    ));
    out.push(pinned(
        "firmware",
        &format!("firmware ({})", pins::FW_VERSION),
        &layout.vmm.join("CLOUDHV.fd"),
        pins::FW_SHA256,
        hint,
    ));
    if !layout.locked {
        let rw = rustix::fs::Access::READ_OK | rustix::fs::Access::WRITE_OK;
        out.push(match rustix::fs::access(kvm, rw) {
            Ok(()) => pass("kvm", format!("{} is readable and writable", kvm.display())),
            Err(e) => fail(
                "kvm",
                format!(
                    "{} is not readable and writable by you ({e}): enable KVM and join the kvm group",
                    kvm.display()
                ),
            ),
        });
    }
    out.push(tool(
        "qemu-img",
        tools,
        Tool::QemuImg,
        "qemu-img (qemu-utils)",
    ));
    out.push(tool("mke2fs", tools, Tool::Mke2fs, "mke2fs (e2fsprogs)"));
    out.push(if landlock_abi >= 1 {
        pass("landlock", format!("Landlock ABI {landlock_abi}"))
    } else {
        fail(
            "landlock",
            "the kernel has no Landlock: boxes need Linux 5.13 or later with Landlock enabled",
        )
    });
    out.push(default_image(layout, image_records));
    out
}

/// The image store has a default image whose files are there. The store
/// is only read: a missing records or images dir is a failure, never
/// created here.
fn default_image(layout: &Layout, image_records: &Path) -> Check {
    for dir in [&layout.images, image_records] {
        if !dir.is_dir() {
            return fail(
                "image",
                format!(
                    "no box images yet ({} is missing): {DEFAULT_IMAGE_HINT}",
                    dir.display()
                ),
            );
        }
    }
    let store = match Store::open(image_records.to_path_buf(), layout.images.clone()) {
        Ok(s) => s,
        Err(e) => return fail("image", e),
    };
    match store.default_id() {
        None => fail(
            "image",
            format!("no default box image: {DEFAULT_IMAGE_HINT}"),
        ),
        Some(id) => match store.get(&id) {
            Ok(_) => pass("image", format!("default image {id}")),
            Err(e) => fail(
                "image",
                format!("the default image: {e}; {DEFAULT_IMAGE_HINT}"),
            ),
        },
    }
}

/// `Ok` when every check passed, else the first failure's detail.
pub fn ready(c: &[Check]) -> Result<(), String> {
    match c.iter().find(|c| !c.ok) {
        Some(f) => Err(f.detail.clone()),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct W {
        dir: tempfile::TempDir,
        layout: Layout,
        records: PathBuf,
        tools: Tools,
        kvm: PathBuf,
    }

    fn world(locked: bool) -> W {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        let layout = Layout {
            boxes: r.join("boxes"),
            images: r.join("images"),
            vmm: r.join("vmm"),
            vault: r.join("vault"),
            locked,
        };
        let records = r.join("image-records");
        for d in [
            &layout.boxes,
            &layout.images,
            &layout.vmm,
            &layout.vault,
            &records,
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        let qi = r.join("qemu-img");
        let mk = r.join("mke2fs");
        std::fs::write(&qi, "").unwrap();
        std::fs::write(&mk, "").unwrap();
        let env = move |k: &str| -> Option<OsString> {
            match k {
                "SAIIFE_TOOL_QEMU_IMG" => Some(qi.clone().into_os_string()),
                "SAIIFE_TOOL_MKE2FS" => Some(mk.clone().into_os_string()),
                _ => None,
            }
        };
        let tools = Tools::system(&layout.vmm).with_env(&env);
        let kvm = r.join("kvm");
        std::fs::write(&kvm, "").unwrap();
        std::fs::set_permissions(&kvm, std::fs::Permissions::from_mode(0o600)).unwrap();
        W {
            dir,
            layout,
            records,
            tools,
            kvm,
        }
    }

    fn by<'a>(c: &'a [Check], name: &str) -> &'a Check {
        c.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no {name} in {c:?}"))
    }

    #[test]
    fn missing_vmm_names_fetch() {
        let w = world(false);
        let c = checks(&w.layout, &w.records, &w.tools, &w.kvm, 3);
        let v = by(&c, "vmm");
        assert!(!v.ok, "{v:?}");
        assert!(v.detail.contains("saiife box vmm fetch"), "{v:?}");
        assert!(v.detail.contains("cloud-hypervisor"), "{v:?}");
        let e = ready(&c).unwrap_err();
        assert!(e.contains("saiife box vmm fetch"), "{e}");
        assert_eq!(c[0].name, "vmm", "the VMM is asked first: {c:?}");
    }

    #[test]
    fn locked_mode_names_the_install() {
        let w = world(true);
        let c = checks(
            &w.layout,
            &w.records,
            &w.tools,
            Path::new("/nonexistent-p35/kvm"),
            3,
        );
        assert!(c.iter().all(|c| c.name != "kvm"), "{c:?}");
        assert!(by(&c, "installed").ok);
        let v = by(&c, "vmm");
        assert!(
            v.detail.contains("sudo saiife system install --boxes"),
            "{v:?}"
        );
        std::fs::remove_dir(&w.layout.vault).unwrap();
        let c = checks(&w.layout, &w.records, &w.tools, &w.kvm, 3);
        let e = ready(&c).unwrap_err();
        assert!(e.contains("not installed"), "{e}");
        assert!(e.contains("sudo saiife system install --boxes"), "{e}");
    }

    #[test]
    fn wrong_digest_fails() {
        let w = world(false);
        std::fs::write(w.layout.vmm.join("cloud-hypervisor"), "not the vmm").unwrap();
        std::fs::write(w.layout.vmm.join("CLOUDHV.fd"), "not the firmware").unwrap();
        let c = checks(&w.layout, &w.records, &w.tools, &w.kvm, 3);
        for name in ["vmm", "firmware"] {
            let v = by(&c, name);
            assert!(!v.ok, "{v:?}");
            assert!(v.detail.contains("does not match the pin"), "{v:?}");
        }
        assert!(by(&c, "vmm").detail.contains(pins::CH_SHA256));
        assert!(by(&c, "firmware").detail.contains(pins::FW_SHA256));
    }

    #[test]
    fn a_symlinked_vmm_is_refused() {
        let w = world(false);
        let other = w.dir.path().join("elsewhere");
        std::fs::write(&other, "x").unwrap();
        std::os::unix::fs::symlink(&other, w.layout.vmm.join("cloud-hypervisor")).unwrap();
        let c = checks(&w.layout, &w.records, &w.tools, &w.kvm, 3);
        assert!(by(&c, "vmm").detail.contains("not a regular file"));
    }

    #[test]
    fn kvm_not_writable_fails() {
        let w = world(false);
        assert!(by(&checks(&w.layout, &w.records, &w.tools, &w.kvm, 3), "kvm").ok);
        std::fs::set_permissions(&w.kvm, std::fs::Permissions::from_mode(0o400)).unwrap();
        if rustix::process::geteuid().is_root() {
            return; // root writes anything
        }
        let c = checks(&w.layout, &w.records, &w.tools, &w.kvm, 3);
        let k = by(&c, "kvm");
        assert!(!k.ok, "{k:?}");
        assert!(k.detail.contains("kvm group"), "{k:?}");
    }

    #[test]
    fn tools_landlock_and_image() {
        let w = world(false);
        let c = checks(&w.layout, &w.records, &w.tools, &w.kvm, 1);
        assert!(by(&c, "qemu-img").ok && by(&c, "mke2fs").ok, "{c:?}");
        assert!(by(&c, "landlock").ok);
        let i = by(&c, "image");
        assert_eq!(
            i.detail,
            format!("no default box image: {}", crate::image::DEFAULT_IMAGE_HINT)
        );
        assert!(!i.ok, "{i:?}");
        std::fs::remove_file(w.tools.path(Tool::Mke2fs)).unwrap();
        let c = checks(&w.layout, &w.records, &w.tools, &w.kvm, 0);
        assert!(by(&c, "mke2fs").detail.contains("e2fsprogs"), "{c:?}");
        assert!(!by(&c, "landlock").ok);
        // nothing is created by the checks
        std::fs::remove_dir(&w.layout.images).unwrap();
        let c = checks(&w.layout, &w.records, &w.tools, &w.kvm, 1);
        assert!(!by(&c, "image").ok);
        assert!(!w.layout.images.exists());
        // nor the daemon-only records half of the store (plan 36 R24)
        std::fs::create_dir(&w.layout.images).unwrap();
        std::fs::remove_dir(&w.records).unwrap();
        let c = checks(&w.layout, &w.records, &w.tools, &w.kvm, 1);
        let i = by(&c, "image");
        assert!(!i.ok && i.detail.contains("image-records"), "{i:?}");
        assert!(!w.records.exists());
    }

    #[test]
    fn ready_reports_first_failure() {
        let c = vec![
            pass("vmm", "fine"),
            fail("kvm", "first"),
            fail("image", "second"),
        ];
        assert_eq!(ready(&c), Err("first".to_string()));
        assert_eq!(ready(&c[..1]), Ok(()));
        assert_eq!(ready(&[]), Ok(()));
    }
}
