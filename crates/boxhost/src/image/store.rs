//! The base image store, in two dirs (plan 35's final layout, R37):
//!
//! - the records dir, daemon-only (0700): the manifests `<id>.json` and
//!   `default` (one line: the id). The trusted manifest is only ever read
//!   from here.
//! - the images dir, readable by the VMM: `<id>.raw` (0440) and an optional
//!   `<id>.vmlinuz` (0440). Nothing is read back from it but the raw disk
//!   and the kernel themselves, for hashing.
//!
//! The manifest is written last, so an entry without one is not in the
//! store. The store is also the Cloud Hypervisor driver's `ImageResolver`.

use super::{parse_image_id, Manifest, ManifestBoot};
use crate::launch::Boot;
use crate::vmm::{ImageResolver, ResolvedImage};
use rustix::fs::{FileType, Mode, OFlags};
use saiife_boxes::template::ImageRef;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The largest manifest the store reads.
const MANIFEST_MAX_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone)]
pub struct Store {
    /// Daemon-only: `<id>.json` and `default`.
    records: PathBuf,
    /// VMM-readable: `<id>.raw` and `<id>.vmlinuz`.
    images: PathBuf,
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

fn set_mode(p: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
}

/// `p` opened read-only, never through a symlink and never blocking on a
/// FIFO; it must be a regular file.
fn open_plain(p: &Path) -> Result<File, String> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd =
        rustix::fs::open(p, flags, Mode::empty()).map_err(|e| format!("{}: {e}", p.display()))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| format!("{}: {e}", p.display()))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(format!("{} is not a regular file", p.display()));
    }
    Ok(File::from(fd))
}

/// The SHA-256 of what `f` holds, read from its start.
fn sha256_of(f: &File, what: &str) -> Result<String, String> {
    use std::os::unix::fs::FileExt;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    let mut at = 0u64;
    loop {
        let n = match f.read_at(&mut buf, at) {
            Ok(0) => break,
            Ok(n) => n,
            Err(x) if x.kind() == io::ErrorKind::Interrupted => continue,
            Err(x) => return Err(format!("cannot read {what}: {x}")),
        };
        ctx.update(&buf[..n]);
        at += n as u64;
    }
    let mut hex = String::with_capacity(64);
    for b in ctx.finish().as_ref() {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(hex)
}

/// A manifest file of the records dir: opened with [`open_plain`], at
/// most [`MANIFEST_MAX_BYTES`].
fn read_manifest_text(p: &Path) -> Result<String, io::Error> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let f = File::from(rustix::fs::open(p, flags, Mode::empty())?);
    if !f.metadata()?.file_type().is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut text = String::new();
    f.take(MANIFEST_MAX_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MANIFEST_MAX_BYTES {
        return Err(io::Error::other("the manifest is too large"));
    }
    Ok(text)
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
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&tmp)
        .map_err(e)?;
    f.write_all(text.as_bytes()).map_err(e)?;
    f.sync_all().map_err(e)?;
    set_mode(&tmp, mode).map_err(e)?;
    fs::rename(&tmp, &dest).map_err(e)?;
    guard.0.clear();
    Ok(())
}

/// `dir`, created 0700 when missing.
fn make_dir(dir: &Path) -> Result<(), String> {
    if !dir.is_dir() {
        let mut b = fs::DirBuilder::new();
        b.recursive(true);
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// The manifest, re-parsed (so every check of `Manifest::parse` holds),
/// and whether the kernel given matches what it boots.
fn checked(manifest: &Manifest, has_kernel: bool) -> Result<Manifest, String> {
    let m = Manifest::parse(&manifest.to_json())?;
    let boots_kernel = matches!(m.boot, ManifestBoot::Kernel { .. });
    match (has_kernel, boots_kernel) {
        (true, false) => Err(format!(
            "{} boots from firmware but a kernel was given",
            m.id
        )),
        (false, true) => Err(format!("{} boots a kernel but none was given", m.id)),
        _ => Ok(m),
    }
}

impl Store {
    /// The store with its manifests in `records` and its disks in
    /// `images`; each dir is created 0700 when missing.
    pub fn open(records: PathBuf, images: PathBuf) -> Result<Store, String> {
        make_dir(&records)?;
        make_dir(&images)?;
        Ok(Store {
            records,
            images,
            fw: None,
        })
    }

    /// The firmware firmware-booting images resolve to: the caller passes
    /// `<vmm>/CLOUDHV.fd`. Without it such an image does not resolve.
    pub fn with_firmware(self, fw: PathBuf) -> Store {
        Store {
            fw: Some(fw),
            ..self
        }
    }

    /// The daemon-only dir of the manifests and `default`.
    pub fn records_dir(&self) -> &Path {
        &self.records
    }

    /// The VMM-readable dir of the raw disks and kernels.
    pub fn images_dir(&self) -> &Path {
        &self.images
    }

    fn manifest_path(&self, id: &str) -> PathBuf {
        self.records.join(format!("{id}.json"))
    }

    fn path(&self, id: &str, ext: &str) -> PathBuf {
        self.images.join(format!("{id}.{ext}"))
    }

    /// Every `<id>.json` in the records dir, sorted by id, each with its
    /// warnings (file name not the manifest's id, `.raw` missing). The
    /// second list warns about manifests that cannot be read at all.
    pub fn list(&self) -> (Vec<(Manifest, Vec<String>)>, Vec<String>) {
        let mut entries = Vec::new();
        let mut bad = Vec::new();
        let rd = match fs::read_dir(&self.records) {
            Ok(rd) => rd,
            Err(e) => return (entries, vec![format!("{}: {e}", self.records.display())]),
        };
        let mut files: Vec<String> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
            .collect();
        files.sort();
        for name in files {
            let stem = &name[..name.len() - ".json".len()];
            let p = self.records.join(&name);
            let m = read_manifest_text(&p)
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
        let p = self.manifest_path(id);
        let text = read_manifest_text(&p).map_err(|e| match e.kind() {
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

    /// The id in `<records>/default`, when it is a valid image id.
    pub fn default_id(&self) -> Option<String> {
        let text = read_manifest_text(&self.records.join("default")).ok()?;
        let id = text.trim();
        parse_image_id(id).ok()?;
        Some(id.to_string())
    }

    /// Makes `id`, which must be in the store, the default.
    pub fn set_default(&self, id: &str) -> Result<(), String> {
        self.get(id)?;
        write_atomic(&self.records, "default", &format!("{id}\n"), 0o600)
    }

    /// Takes an image whose files are already in the images dir's
    /// filesystem (the daemon's own copies, e.g. in `<images>/.incoming/`)
    /// into the store: the manifest must parse and match the kernel given;
    /// each file is opened without following a link, must be a regular
    /// file, and is hashed against the manifest (`sha256`, and the kernel
    /// against `boot.sha256`); then made 0440 and renamed to `<id>.raw`
    /// and `<id>.vmlinuz`, and the manifest is written to the records dir
    /// last. On failure nothing new is in the store; the files given stay
    /// where they are for the caller to remove.
    pub fn adopt(
        &self,
        raw: &Path,
        kernel: Option<&Path>,
        manifest: &Manifest,
    ) -> Result<(), String> {
        let m = checked(manifest, kernel.is_some())?;
        let id = m.id.as_str();
        let (dest_raw, dest_k, json) = (
            self.path(id, "raw"),
            self.path(id, "vmlinuz"),
            self.manifest_path(id),
        );
        let there = |p: &Path| fs::symlink_metadata(p).is_ok();
        if there(&dest_raw) || there(&dest_k) || there(&json) {
            return Err(format!("{id} is already in the store"));
        }
        let ro = Mode::from_raw_mode(0o440);
        let f = open_plain(raw)?;
        let got = sha256_of(&f, "the image")?;
        if got != m.sha256 {
            return Err(format!(
                "the image's sha256 is {got}, the manifest says {}",
                m.sha256
            ));
        }
        rustix::fs::fchmod(&f, ro).map_err(|e| format!("{}: {e}", raw.display()))?;
        if let (Some(k), ManifestBoot::Kernel { sha256: want, .. }) = (kernel, &m.boot) {
            let f = open_plain(k)?;
            let got = sha256_of(&f, "the kernel")?;
            if got != *want {
                return Err(format!(
                    "the kernel's sha256 is {got}, the manifest says {want}"
                ));
            }
            rustix::fs::fchmod(&f, ro).map_err(|e| format!("{}: {e}", k.display()))?;
        }
        let e = |p: &Path, x: io::Error| format!("{}: {x}", p.display());
        let mut guard = Cleanup(Vec::new());
        fs::rename(raw, &dest_raw).map_err(|x| e(&dest_raw, x))?;
        guard.0.push(dest_raw.clone());
        if let Some(k) = kernel {
            fs::rename(k, &dest_k).map_err(|x| e(&dest_k, x))?;
            guard.0.push(dest_k.clone());
        }
        write_atomic(&self.records, &format!("{id}.json"), &m.to_json(), 0o440)?;
        guard.0.clear();
        Ok(())
    }

    /// For tests and the CLI-free path only: the daemon takes images in
    /// with [`Store::adopt`] of its own copies.
    ///
    /// Copies an image into the store: the raw disk (and the kernel when
    /// the manifest boots one) into randomly named temp files in the
    /// images dir (holes kept), then [`Store::adopt`]. On failure nothing
    /// new is left in the store.
    #[doc(hidden)]
    pub fn insert(
        &self,
        raw_src: &File,
        manifest: &Manifest,
        kernel: Option<&File>,
    ) -> Result<(), String> {
        let m = checked(manifest, kernel.is_some())?;
        let mut rnd = [0u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut rnd)
            .map_err(|_| "no randomness for a temp name".to_string())?;
        let tag: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let raw_tmp = self.images.join(format!(".insert-{tag}.raw.tmp"));
        let k_tmp = self.images.join(format!(".insert-{tag}.vmlinuz.tmp"));
        let _guard = Cleanup(vec![raw_tmp.clone(), k_tmp.clone()]);
        let copy = |src: &File, dest: &Path| -> Result<(), String> {
            let e = |x: io::Error| format!("{}: {x}", dest.display());
            let out = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(dest)
                .map_err(e)?;
            crate::disk::copy_sparse(src, &out).map_err(e)?;
            out.sync_all().map_err(e)
        };
        copy(raw_src, &raw_tmp)?;
        if let Some(k) = kernel {
            copy(k, &k_tmp)?;
        }
        self.adopt(&raw_tmp, kernel.map(|_| k_tmp.as_path()), &m)
    }

    /// Removes an image that is not the default: its manifest first (so
    /// the entry is gone at once), then its disk and kernel.
    pub fn remove(&self, id: &str) -> Result<(), String> {
        parse_image_id(id)?;
        if self.default_id().as_deref() == Some(id) {
            return Err(format!(
                "{id} is the default image; make another image the default first"
            ));
        }
        let json = self.manifest_path(id);
        if !json.exists() && !self.path(id, "raw").exists() {
            return Err(format!("no image {id} in the store"));
        }
        for p in [json, self.path(id, "raw"), self.path(id, "vmlinuz")] {
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
                let got = sha256_of(&open_plain(&kernel)?, "the kernel")?;
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
        let store = Store::open(root.join("records"), root.join("images")).unwrap();
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
        w.store.insert(&File::open(&p).unwrap(), &m, None).unwrap();
        m
    }

    /// Every name in both of the store's dirs, `r/` or `i/` before it.
    fn store_names(w: &W) -> Vec<String> {
        let mut v: Vec<String> = names(w.store.records_dir())
            .into_iter()
            .map(|n| format!("r/{n}"))
            .chain(
                names(w.store.images_dir())
                    .into_iter()
                    .map(|n| format!("i/{n}")),
            )
            .collect();
        v.sort();
        v
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
    fn open_creates_both_dirs_0700() {
        let w = world();
        for d in [w.store.records_dir(), w.store.images_dir()] {
            let m = fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o700, "{}", d.display());
        }
        assert_ne!(w.store.records_dir(), w.store.images_dir());
        assert!(Store::open(
            w.store.records_dir().to_path_buf(),
            w.store.images_dir().to_path_buf()
        )
        .is_ok());
    }

    /// The manifest and `default` are in the records dir only; the disk
    /// and the kernel in the images dir only.
    #[test]
    fn store_split_records_from_images() {
        let w = world();
        let m = add_kernel(&w, "kernel");
        w.store.set_default(&m.id).unwrap();
        assert_eq!(
            store_names(&w),
            vec![
                format!("i/{}.raw", m.id),
                format!("i/{}.vmlinuz", m.id),
                format!("r/{}.json", m.id),
                "r/default".to_string(),
            ]
        );
        let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(w.store.images_dir().join(format!("{}.vmlinuz", m.id))),
            0o440
        );
        assert_eq!(
            mode(w.store.records_dir().join(format!("{}.json", m.id))),
            0o440
        );
        // A manifest planted in the images dir is not read.
        let other = manifest_for(&"7".repeat(64));
        fs::write(
            w.store.images_dir().join(format!("{}.json", other.id)),
            other.to_json(),
        )
        .unwrap();
        let ids: Vec<String> = w.store.list().0.into_iter().map(|(m, _)| m.id).collect();
        assert_eq!(ids, vec![m.id.clone()]);
        assert!(w.store.get(&other.id).is_err());
        // A symlinked manifest in the records dir is not followed.
        let link = w.store.records_dir().join(format!("{}.json", other.id));
        std::os::unix::fs::symlink(
            w.store.images_dir().join(format!("{}.json", other.id)),
            &link,
        )
        .unwrap();
        assert!(w.store.get(&other.id).is_err());
    }

    /// `adopt` takes files already beside the store, hashes them, and
    /// renames them in; a symlink or a wrong hash leaves the store empty.
    #[test]
    fn adopt_checks_and_renames() {
        let w = world();
        let inc = w.store.images_dir().join(".incoming");
        fs::create_dir(&inc).unwrap();
        let raw = inc.join("base.raw");
        fs::write(&raw, "image-a\n").unwrap();
        let m = manifest_for(&sha256_file(&raw).unwrap());
        // A symlink to the right content is refused.
        let link = inc.join("link.raw");
        std::os::unix::fs::symlink(&raw, &link).unwrap();
        let e = w.store.adopt(&link, None, &m).unwrap_err();
        assert!(e.contains("link.raw"), "{e}");
        // A wrong digest is refused.
        let mut bad = manifest_for(&"0".repeat(64));
        bad.boot = ManifestBoot::Firmware;
        let e = w.store.adopt(&raw, None, &bad).unwrap_err();
        assert!(e.contains("sha256"), "{e}");
        assert_eq!(store_names(&w), vec!["i/.incoming".to_string()]);
        w.store.adopt(&raw, None, &m).unwrap();
        assert!(!raw.exists());
        assert_eq!(w.store.get(&m.id).unwrap(), m);
        let mode = fs::metadata(w.store.images_dir().join(format!("{}.raw", m.id)))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o440);
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
            .insert(&File::open(&p).unwrap(), &m, None)
            .unwrap_err();
        assert!(e.contains("sha256") && e.contains(&real), "{e}");
        assert!(store_names(&w).is_empty(), "{:?}", store_names(&w));

        let m = add(&w, "b.raw", "image-b\n");
        let raw = w.store.images_dir().join(format!("{}.raw", m.id));
        assert_eq!(fs::read_to_string(&raw).unwrap(), "image-b\n");
        let mode = fs::metadata(&raw).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o440);
        assert_eq!(w.store.get(&m.id).unwrap(), m);
        assert_eq!(
            store_names(&w),
            vec![format!("i/{}.raw", m.id), format!("r/{}.json", m.id)]
        );
        // The same id again is refused.
        let p = w.root.join("b.raw");
        let e = w
            .store
            .insert(&File::open(&p).unwrap(), &m, None)
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
            .insert(&File::open(&p).unwrap(), &m, Some(&File::open(&k).unwrap()))
            .unwrap_err();
        assert!(e.contains("kernel"), "{e}");
        m.boot = ManifestBoot::Kernel {
            kernel: format!("{}.vmlinuz", m.id),
            sha256: sha256_file(&k).unwrap(),
            cmdline: "console=ttyS0".into(),
        };
        let e = w
            .store
            .insert(&File::open(&p).unwrap(), &m, None)
            .unwrap_err();
        assert!(e.contains("kernel"), "{e}");
        assert!(store_names(&w).is_empty());
        // A kernel whose hash is not the manifest's is refused, and nothing is left.
        let other = w.root.join("vmlinuz-other");
        fs::write(&other, "another kernel").unwrap();
        let e = w
            .store
            .insert(
                &File::open(&p).unwrap(),
                &m,
                Some(&File::open(&other).unwrap()),
            )
            .unwrap_err();
        assert!(e.contains("kernel's sha256"), "{e}");
        assert!(store_names(&w).is_empty(), "{:?}", store_names(&w));
        w.store
            .insert(&File::open(&p).unwrap(), &m, Some(&File::open(&k).unwrap()))
            .unwrap();
        let kp = w.store.images_dir().join(format!("{}.vmlinuz", m.id));
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
            fs::read_to_string(w.store.records_dir().join("default")).unwrap(),
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
        assert_eq!(store_names(&w).len(), 3);
        // The resolver takes the same default and the same pinned ids.
        let store = w.store.clone().with_firmware(w.root.join("vmm/CLOUDHV.fd"));
        let got = store.resolve(&ImageRef::Default).unwrap();
        assert_eq!(
            got,
            ResolvedImage {
                id: a.id.clone(),
                raw: w.store.images_dir().join(format!("{}.raw", a.id)),
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
        fs::write(w.store.records_dir().join("default"), "../etc\n").unwrap();
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
        let raw = w.store.images_dir().join(format!("{}.raw", a.id));
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
            .insert(&File::open(&p).unwrap(), &m, Some(&File::open(&k).unwrap()))
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
                raw: w.store.images_dir().join(format!("{}.raw", m.id)),
                sha256: m.sha256.clone(),
                virtual_gib: m.virtual_gib,
                boot: Boot::Kernel {
                    kernel: w.store.images_dir().join(format!("{}.vmlinuz", m.id)),
                    cmdline: "console=ttyS0 root=/dev/vda1".into(),
                },
            }
        );
    }

    #[test]
    fn resolver_refuses_a_changed_or_symlinked_kernel() {
        let w = world();
        let m = add_kernel(&w, "kernel");
        let kp = w.store.images_dir().join(format!("{}.vmlinuz", m.id));
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
        let dir = w.store.records_dir();
        // b loses its raw file; c's json is filed under another id.
        fs::remove_file(w.store.images_dir().join(format!("{}.raw", b.id))).unwrap();
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
