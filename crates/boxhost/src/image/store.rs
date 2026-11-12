//! The base image store: `<dir>/base-<sha256>.raw` (0440), `.json`, an
//! optional `.vmlinuz`, and `<dir>/default` (one line: the id). The JSON
//! file is written last, so an entry without one is not in the store.
//! The store is also the Cloud Hypervisor driver's `ImageResolver`.

use super::{parse_image_id, Manifest, ManifestBoot};
use crate::launch::Boot;
use crate::vmm::{ImageResolver, ResolvedImage};
use saiife_boxes::template::ImageRef;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    /// The firmware a firmware-booting image boots with
    /// (`<vmm>/CLOUDHV.fd`); see `with_firmware`.
    fw: Option<PathBuf>,
}

/// Fails unless `p` is a regular file itself (not a symlink to one).
fn regular_file(p: &Path) -> Result<(), String> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_file() => Ok(()),
        Ok(_) => Err(format!("{} is not a regular file", p.display())),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_p: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// Removes the listed paths on drop unless disarmed.
struct Cleanup(Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = fs::remove_file(p);
        }
    }
}

/// Copies `src` into a new file at `dest` and returns the SHA-256 of what
/// was copied. A plain `std::io::copy`-style loop for now; plan 37's
/// `disk::copy_sparse` replaces it so holes stay holes.
fn copy_hashing(src: &mut File, dest: &Path) -> Result<String, String> {
    let e = |x: io::Error| format!("{}: {x}", dest.display());
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .map_err(e)?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(x) if x.kind() == io::ErrorKind::Interrupted => continue,
            Err(x) => return Err(format!("read the source image: {x}")),
        };
        ctx.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(e)?;
    }
    out.sync_all().map_err(e)?;
    let mut hex = String::with_capacity(64);
    for b in ctx.finish().as_ref() {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(hex)
}

/// Writes `text` to `<dir>/.<name>.tmp`, then renames it to `<dir>/<name>`.
fn write_atomic(dir: &Path, name: &str, text: &str, mode: u32) -> Result<(), String> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let dest = dir.join(name);
    let mut guard = Cleanup(vec![tmp.clone()]);
    let _ = fs::remove_file(&tmp);
    let e = |x: io::Error| format!("{}: {x}", dest.display());
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(e)?;
    f.write_all(text.as_bytes()).map_err(e)?;
    f.sync_all().map_err(e)?;
    set_mode(&tmp, mode).map_err(e)?;
    fs::rename(&tmp, &dest).map_err(e)?;
    guard.0.clear();
    Ok(())
}

impl Store {
    /// The store at `dir`, created 0700 when missing.
    pub fn open(dir: PathBuf) -> Result<Store, String> {
        if !dir.is_dir() {
            let mut b = fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b.create(&dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        Ok(Store { dir, fw: None })
    }

    /// The firmware firmware-booting images resolve to: the caller passes
    /// `<vmm>/CLOUDHV.fd`. Without it such an image does not resolve.
    pub fn with_firmware(self, fw: PathBuf) -> Store {
        Store {
            fw: Some(fw),
            ..self
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, id: &str, ext: &str) -> PathBuf {
        self.dir.join(format!("{id}.{ext}"))
    }

    /// Every `<id>.json` in the store, sorted by id, each with its
    /// warnings (file name not the manifest's id, `.raw` missing). The
    /// second list warns about manifests that cannot be read at all.
    pub fn list(&self) -> (Vec<(Manifest, Vec<String>)>, Vec<String>) {
        let mut entries = Vec::new();
        let mut bad = Vec::new();
        let rd = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) => return (entries, vec![format!("{}: {e}", self.dir.display())]),
        };
        let mut files: Vec<String> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
            .collect();
        files.sort();
        for name in files {
            let stem = &name[..name.len() - ".json".len()];
            let p = self.dir.join(&name);
            let m = fs::read_to_string(&p)
                .map_err(|e| e.to_string())
                .and_then(|t| Manifest::parse(&t));
            let m = match m {
                Ok(m) => m,
                Err(e) => {
                    bad.push(format!("{name}: {e}"));
                    continue;
                }
            };
            let mut warn = Vec::new();
            if stem != m.id {
                warn.push(format!("{name} holds the manifest of {}", m.id));
            }
            if !self.path(&m.id, "raw").is_file() {
                warn.push(format!("{}.raw is missing", m.id));
            }
            if matches!(m.boot, ManifestBoot::Kernel { .. })
                && !self.path(&m.id, "vmlinuz").is_file()
            {
                warn.push(format!("{}.vmlinuz is missing", m.id));
            }
            entries.push((m, warn));
        }
        entries.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        (entries, bad)
    }

    /// The manifest of an image that is in the store (its `.raw` present).
    pub fn get(&self, id: &str) -> Result<Manifest, String> {
        parse_image_id(id)?;
        let p = self.path(id, "json");
        let text = fs::read_to_string(&p).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => format!("no image {id} in the store"),
            _ => format!("{}: {e}", p.display()),
        })?;
        let m = Manifest::parse(&text)?;
        if m.id != id {
            return Err(format!("{id}.json holds the manifest of {}", m.id));
        }
        if !self.path(id, "raw").is_file() {
            return Err(format!("{id}.raw is missing from the store"));
        }
        Ok(m)
    }

    /// The id in `<dir>/default`, when it is a valid image id.
    pub fn default_id(&self) -> Option<String> {
        let text = fs::read_to_string(self.dir.join("default")).ok()?;
        let id = text.trim();
        parse_image_id(id).ok()?;
        Some(id.to_string())
    }

    /// Makes `id`, which must be in the store, the default.
    pub fn set_default(&self, id: &str) -> Result<(), String> {
        self.get(id)?;
        write_atomic(&self.dir, "default", &format!("{id}\n"), 0o600)
    }

    /// Copies an image into the store: the raw disk into `.<id>.raw.tmp`
    /// (hashed as it is copied and checked against `manifest.sha256`, then
    /// 0440 and renamed), the kernel when the manifest boots one (hashed
    /// the same way and checked against `boot.sha256`), and the manifest
    /// last. On failure nothing new is left in the store.
    pub fn insert(
        &self,
        raw_src: &mut File,
        manifest: &Manifest,
        kernel: Option<&mut File>,
    ) -> Result<(), String> {
        let m = Manifest::parse(&manifest.to_json())?;
        let id = m.id.as_str();
        let boots_kernel = matches!(m.boot, ManifestBoot::Kernel { .. });
        match (&kernel, boots_kernel) {
            (Some(_), false) => {
                return Err(format!("{id} boots from firmware but a kernel was given"))
            }
            (None, true) => return Err(format!("{id} boots a kernel but none was given")),
            _ => {}
        }
        let (raw, json, vmlinuz) = (
            self.path(id, "raw"),
            self.path(id, "json"),
            self.path(id, "vmlinuz"),
        );
        if raw.exists() || json.exists() || vmlinuz.exists() {
            return Err(format!("{id} is already in the store"));
        }
        let raw_tmp = self.dir.join(format!(".{id}.raw.tmp"));
        let k_tmp = self.dir.join(format!(".{id}.vmlinuz.tmp"));
        let _ = fs::remove_file(&raw_tmp);
        let _ = fs::remove_file(&k_tmp);
        let mut guard = Cleanup(vec![raw_tmp.clone(), k_tmp.clone()]);
        let got = copy_hashing(raw_src, &raw_tmp)?;
        if got != m.sha256 {
            return Err(format!(
                "the image's sha256 is {got}, the manifest says {}",
                m.sha256
            ));
        }
        let e = |p: &Path, x: io::Error| format!("{}: {x}", p.display());
        set_mode(&raw_tmp, 0o440).map_err(|x| e(&raw_tmp, x))?;
        if let (Some(k), ManifestBoot::Kernel { sha256: want, .. }) = (kernel, &m.boot) {
            let got = copy_hashing(k, &k_tmp)?;
            if got != *want {
                return Err(format!(
                    "the kernel's sha256 is {got}, the manifest says {want}"
                ));
            }
            set_mode(&k_tmp, 0o440).map_err(|x| e(&k_tmp, x))?;
        }
        guard.0.push(raw.clone());
        fs::rename(&raw_tmp, &raw).map_err(|x| e(&raw, x))?;
        if boots_kernel {
            guard.0.push(vmlinuz.clone());
            fs::rename(&k_tmp, &vmlinuz).map_err(|x| e(&vmlinuz, x))?;
        }
        write_atomic(&self.dir, &format!("{id}.json"), &m.to_json(), 0o440)?;
        guard.0.clear();
        Ok(())
    }

    /// Removes an image that is not the default.
    pub fn remove(&self, id: &str) -> Result<(), String> {
        parse_image_id(id)?;
        if self.default_id().as_deref() == Some(id) {
            return Err(format!(
                "{id} is the default image; make another image the default first"
            ));
        }
        let json = self.path(id, "json");
        if !json.exists() && !self.path(id, "raw").exists() {
            return Err(format!("no image {id} in the store"));
        }
        for ext in ["json", "raw", "vmlinuz"] {
            let p = self.path(id, ext);
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(x) if x.kind() == io::ErrorKind::NotFound => {}
                Err(x) => return Err(format!("{}: {x}", p.display())),
            }
        }
        Ok(())
    }
}

impl ImageResolver for Store {
    /// The default or a pinned image, as the driver boots it. The raw disk
    /// and the kernel must be regular files in the store (no symlinks); the
    /// kernel is re-hashed against the manifest, the raw disk is not (it
    /// was hashed on insert and is large).
    fn resolve(&self, r: &ImageRef) -> Result<ResolvedImage, String> {
        let id = match r {
            ImageRef::Default => self.default_id().ok_or_else(|| {
                "no default box image: saiife box image import --default <path>".to_string()
            })?,
            ImageRef::Pinned(id) => {
                parse_image_id(id)?;
                id.clone()
            }
        };
        let m = self.get(&id)?;
        let raw = self.path(&id, "raw");
        regular_file(&raw)?;
        let boot = match &m.boot {
            ManifestBoot::Firmware => Boot::Firmware {
                fw: self.fw.clone().ok_or_else(|| {
                    format!("{id} boots from firmware but no firmware path is set")
                })?,
            },
            ManifestBoot::Kernel {
                sha256: want,
                cmdline,
                ..
            } => {
                let kernel = self.path(&id, "vmlinuz");
                regular_file(&kernel)?;
                let got = crate::pins::sha256_file(&kernel)
                    .map_err(|e| format!("{}: {e}", kernel.display()))?;
                if got != *want {
                    return Err(format!(
                        "{id}: the kernel's sha256 is {got}, the manifest says {want}"
                    ));
                }
                Boot::Kernel {
                    kernel,
                    cmdline: cmdline.clone(),
                }
            }
        };
        Ok(ResolvedImage {
            id,
            raw,
            sha256: m.sha256,
            virtual_gib: m.virtual_gib,
            boot,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::image::tests::manifest_for;
    use crate::image::{image_id, ManifestBoot};
    use crate::launch::Boot;
    use crate::pins::sha256_file;
    use crate::vmm::{ImageResolver, ResolvedImage};
    use saiife_boxes::template::ImageRef;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    struct W {
        _d: tempfile::TempDir,
        root: PathBuf,
        store: Store,
    }

    fn world() -> W {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().to_path_buf();
        let store = Store::open(root.join("images")).unwrap();
        W { _d: d, root, store }
    }

    /// A source raw file with `content`, and a manifest for its digest.
    fn src(w: &W, name: &str, content: &str) -> (PathBuf, Manifest) {
        let p = w.root.join(name);
        fs::write(&p, content).unwrap();
        let sha = sha256_file(&p).unwrap();
        (p, manifest_for(&sha))
    }

    fn add(w: &W, name: &str, content: &str) -> Manifest {
        let (p, m) = src(w, name, content);
        w.store
            .insert(&mut File::open(&p).unwrap(), &m, None)
            .unwrap();
        m
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn open_creates_the_dir_0700() {
        let w = world();
        let m = fs::metadata(w.store.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o700);
        assert!(Store::open(w.store.dir().to_path_buf()).is_ok());
    }

    #[test]
    fn store_insert_checks_sha256() {
        let w = world();
        let (p, mut m) = src(&w, "a.raw", "image-a\n");
        let real = m.sha256.clone();
        m.sha256 = "0".repeat(64);
        m.id = image_id(&m.sha256);
        let e = w
            .store
            .insert(&mut File::open(&p).unwrap(), &m, None)
            .unwrap_err();
        assert!(e.contains("sha256") && e.contains(&real), "{e}");
        assert!(
            names(w.store.dir()).is_empty(),
            "{:?}",
            names(w.store.dir())
        );

        let m = add(&w, "b.raw", "image-b\n");
        let raw = w.store.dir().join(format!("{}.raw", m.id));
        assert_eq!(fs::read_to_string(&raw).unwrap(), "image-b\n");
        let mode = fs::metadata(&raw).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o440);
        assert_eq!(w.store.get(&m.id).unwrap(), m);
        assert_eq!(
            names(w.store.dir()),
            vec![format!("{}.json", m.id), format!("{}.raw", m.id)]
        );
        // The same id again is refused.
        let p = w.root.join("b.raw");
        let e = w
            .store
            .insert(&mut File::open(&p).unwrap(), &m, None)
            .unwrap_err();
        assert!(e.contains("already"), "{e}");
    }

    #[test]
    fn insert_with_kernel() {
        let w = world();
        let (p, mut m) = src(&w, "k.raw", "image-k\n");
        let k = w.root.join("vmlinuz");
        fs::write(&k, "kernel").unwrap();
        // Firmware boot with a kernel file, and kernel boot without one, are refused.
        let e = w
            .store
            .insert(
                &mut File::open(&p).unwrap(),
                &m,
                Some(&mut File::open(&k).unwrap()),
            )
            .unwrap_err();
        assert!(e.contains("kernel"), "{e}");
        m.boot = ManifestBoot::Kernel {
            kernel: format!("{}.vmlinuz", m.id),
            sha256: sha256_file(&k).unwrap(),
            cmdline: "console=ttyS0".into(),
        };
        let e = w
            .store
            .insert(&mut File::open(&p).unwrap(), &m, None)
            .unwrap_err();
        assert!(e.contains("kernel"), "{e}");
        assert!(names(w.store.dir()).is_empty());
        // A kernel whose hash is not the manifest's is refused, and nothing is left.
        let other = w.root.join("vmlinuz-other");
        fs::write(&other, "another kernel").unwrap();
        let e = w
            .store
            .insert(
                &mut File::open(&p).unwrap(),
                &m,
                Some(&mut File::open(&other).unwrap()),
            )
            .unwrap_err();
        assert!(e.contains("kernel's sha256"), "{e}");
        assert!(
            names(w.store.dir()).is_empty(),
            "{:?}",
            names(w.store.dir())
        );
        w.store
            .insert(
                &mut File::open(&p).unwrap(),
                &m,
                Some(&mut File::open(&k).unwrap()),
            )
            .unwrap();
        let kp = w.store.dir().join(format!("{}.vmlinuz", m.id));
        assert_eq!(fs::read_to_string(kp).unwrap(), "kernel");
    }

    #[test]
    fn store_resolves_default_and_pinned() {
        let w = world();
        assert_eq!(w.store.default_id(), None);
        let a = add(&w, "a.raw", "image-a\n");
        let b = add(&w, "b.raw", "image-b\n");
        let missing = image_id(&"9".repeat(64));
        assert!(w.store.set_default(&missing).is_err());
        assert!(w.store.set_default("base-nope").is_err());
        w.store.set_default(&a.id).unwrap();
        assert_eq!(w.store.default_id().as_deref(), Some(a.id.as_str()));
        assert_eq!(
            fs::read_to_string(w.store.dir().join("default")).unwrap(),
            format!("{}\n", a.id)
        );
        assert_eq!(w.store.get(&b.id).unwrap(), b);
        assert!(w.store.get(&missing).is_err());
        // The default cannot be removed; another image can.
        assert!(w.store.remove(&a.id).unwrap_err().contains("default"));
        w.store.remove(&b.id).unwrap();
        assert!(w.store.get(&b.id).is_err());
        assert!(w.store.remove(&b.id).is_err());
        w.store.set_default(&a.id).unwrap();
        assert_eq!(names(w.store.dir()).len(), 3);
        // The resolver takes the same default and the same pinned ids.
        let store = w.store.clone().with_firmware(w.root.join("vmm/CLOUDHV.fd"));
        let got = store.resolve(&ImageRef::Default).unwrap();
        assert_eq!(
            got,
            ResolvedImage {
                id: a.id.clone(),
                raw: w.store.dir().join(format!("{}.raw", a.id)),
                sha256: a.sha256.clone(),
                virtual_gib: a.virtual_gib,
                boot: Boot::Firmware {
                    fw: w.root.join("vmm/CLOUDHV.fd"),
                },
            }
        );
        assert_eq!(store.resolve(&ImageRef::Pinned(a.id.clone())).unwrap(), got);
        let e = store.resolve(&ImageRef::Pinned(b.id.clone())).unwrap_err();
        assert!(e.contains("no image"), "{e}");
        let e = store
            .resolve(&ImageRef::Pinned("base-nope".into()))
            .unwrap_err();
        assert!(e.contains("bad image id"), "{e}");
        // A garbage default file reads as no default.
        fs::write(w.store.dir().join("default"), "../etc\n").unwrap();
        assert_eq!(w.store.default_id(), None);
        let e = store.resolve(&ImageRef::Default).unwrap_err();
        assert_eq!(
            e,
            "no default box image: saiife box image import --default <path>"
        );
    }

    #[test]
    fn resolver_without_default_is_a_clear_error() {
        let w = world();
        add(&w, "a.raw", "image-a\n");
        let store = w.store.clone().with_firmware(w.root.join("fw"));
        let e = store.resolve(&ImageRef::Default).unwrap_err();
        assert_eq!(
            e,
            "no default box image: saiife box image import --default <path>"
        );
    }

    #[test]
    fn resolver_firmware_needs_with_firmware() {
        let w = world();
        let a = add(&w, "a.raw", "image-a\n");
        let e = w
            .store
            .resolve(&ImageRef::Pinned(a.id.clone()))
            .unwrap_err();
        assert!(e.contains("firmware"), "{e}");
    }

    #[test]
    fn resolver_refuses_a_symlinked_raw() {
        let w = world();
        let a = add(&w, "a.raw", "image-a\n");
        let store = w.store.clone().with_firmware(w.root.join("fw"));
        let raw = w.store.dir().join(format!("{}.raw", a.id));
        let real = w.root.join("elsewhere.raw");
        fs::rename(&raw, &real).unwrap();
        std::os::unix::fs::symlink(&real, &raw).unwrap();
        // Store::get follows the link; the resolver does not.
        assert!(w.store.get(&a.id).is_ok());
        let e = store.resolve(&ImageRef::Pinned(a.id.clone())).unwrap_err();
        assert!(e.contains("regular file"), "{e}");
    }

    /// Inserts a kernel-booting image and returns its manifest.
    fn add_kernel(w: &W, kernel: &str) -> Manifest {
        let (p, mut m) = src(w, "k.raw", "image-k\n");
        let k = w.root.join("vmlinuz");
        fs::write(&k, kernel).unwrap();
        m.boot = ManifestBoot::Kernel {
            kernel: format!("{}.vmlinuz", m.id),
            sha256: sha256_file(&k).unwrap(),
            cmdline: "console=ttyS0 root=/dev/vda1".into(),
        };
        w.store
            .insert(
                &mut File::open(&p).unwrap(),
                &m,
                Some(&mut File::open(&k).unwrap()),
            )
            .unwrap();
        m
    }

    #[test]
    fn resolver_kernel_boot() {
        let w = world();
        let m = add_kernel(&w, "kernel");
        // No firmware is needed for a direct kernel boot.
        let got = w.store.resolve(&ImageRef::Pinned(m.id.clone())).unwrap();
        assert_eq!(
            got,
            ResolvedImage {
                id: m.id.clone(),
                raw: w.store.dir().join(format!("{}.raw", m.id)),
                sha256: m.sha256.clone(),
                virtual_gib: m.virtual_gib,
                boot: Boot::Kernel {
                    kernel: w.store.dir().join(format!("{}.vmlinuz", m.id)),
                    cmdline: "console=ttyS0 root=/dev/vda1".into(),
                },
            }
        );
    }

    #[test]
    fn resolver_refuses_a_changed_or_symlinked_kernel() {
        let w = world();
        let m = add_kernel(&w, "kernel");
        let kp = w.store.dir().join(format!("{}.vmlinuz", m.id));
        // A kernel whose content no longer matches the manifest.
        set_mode(&kp, 0o640).unwrap();
        fs::write(&kp, "tampered").unwrap();
        let e = w
            .store
            .resolve(&ImageRef::Pinned(m.id.clone()))
            .unwrap_err();
        assert!(e.contains("kernel's sha256"), "{e}");
        // The right content behind a symlink is refused too.
        let real = w.root.join("real-vmlinuz");
        fs::write(&real, "kernel").unwrap();
        fs::remove_file(&kp).unwrap();
        std::os::unix::fs::symlink(&real, &kp).unwrap();
        let e = w
            .store
            .resolve(&ImageRef::Pinned(m.id.clone()))
            .unwrap_err();
        assert!(e.contains("regular file"), "{e}");
        // A missing kernel is an error.
        fs::remove_file(&kp).unwrap();
        assert!(w.store.resolve(&ImageRef::Pinned(m.id.clone())).is_err());
    }

    #[test]
    fn store_lists_and_warns() {
        let w = world();
        let a = add(&w, "a.raw", "image-a\n");
        let b = add(&w, "b.raw", "image-b\n");
        let c = add(&w, "c.raw", "image-c\n");
        let dir = w.store.dir();
        // b loses its raw file; c's json is filed under another id.
        fs::remove_file(dir.join(format!("{}.raw", b.id))).unwrap();
        let other = image_id(&"e".repeat(64));
        fs::rename(
            dir.join(format!("{}.json", c.id)),
            dir.join(format!("{other}.json")),
        )
        .unwrap();
        fs::write(dir.join(format!("{}.json", image_id(&"f".repeat(64)))), "{").unwrap();
        fs::write(dir.join(".tmp.json"), "{").unwrap();
        let (entries, warnings) = w.store.list();
        let mut want = vec![a.id.clone(), b.id.clone(), c.id.clone()];
        want.sort();
        let ids: Vec<&str> = entries.iter().map(|(m, _)| m.id.as_str()).collect();
        assert_eq!(ids, want);
        for (m, warn) in &entries {
            if m.id == a.id {
                assert!(warn.is_empty(), "{warn:?}");
            } else if m.id == b.id {
                assert!(warn.iter().any(|x| x.contains(".raw")), "{warn:?}");
            } else {
                assert!(warn.iter().any(|x| x.contains(&other)), "{warn:?}");
            }
        }
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(&"f".repeat(64)), "{warnings:?}");
    }
}
