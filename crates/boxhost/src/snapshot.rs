//! When a snapshot may be restored (S1, S3 / ruling R20). CH writes its
//! snapshot into `<box>/snapshot`, which the VMM can write. So right after
//! the daemon's own `vm.snapshot`, while the VM is paused, `seal` copies it
//! into the vault (`<vault>/<id>.snap`, which no VMM can write) through file
//! descriptors only (S4), read-only, and records the SHA-256 of every file
//! in `<vault>/<id>.marker`.
//! At boot `verify` re-hashes the vault copy, compares, and runs
//! `check_config` on the very bytes it hashed; the restore reads only that
//! copy. The box dir's `snapshot/` is never a restore source; it is made
//! before the VMM starts (`launch::ensure_snapshot_dir`) and only emptied.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Mode, OFlags, CWD};

use saiife_wire::source::BoxId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::launch::{Boot, LaunchSpec};
use crate::paths::BoxPaths;
use crate::vault::{self, euid, marker_path, read_bounded, snap_dir};

/// `config.json` larger than this is refused (it is parsed in memory);
/// `state.json` is held to the same cap.
pub const MAX_CONFIG: u64 = 16 * 1024 * 1024;
/// A snapshot may hold the guest memory plus this much (I8): beyond it the
/// copy into the vault (on /var in locked mode) is refused, not made.
pub const SLACK_MIB: u64 = 64;
/// A snapshot with more entries than this is refused.
pub const MAX_FILES: usize = 64;
const MAX_MARKER: u64 = 64 * 1024;
/// The files a CH v54 snapshot holds; any other name is refused.
pub const NAMES: &[&str] = &["config.json", "memory-ranges", "state.json"];

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u32,
    /// File name -> lowercase hex SHA-256.
    files: BTreeMap<String, String>,
}

fn hex(d: ring::digest::Digest) -> String {
    d.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn open_ro(p: &Path) -> Result<std::fs::File, String> {
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(p)
        .map_err(|e| format!("{}: {e}", p.display()))
}

/// SHA-256 of an open file, streamed, at most `len` bytes (its fstat size).
fn hash_file(f: &mut std::fs::File, len: u64) -> Result<String, String> {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    let mut r = f.take(len);
    loop {
        let n = r.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(hex(ctx.finish()))
}

/// The entries of a vault copy (daemon-owned, path lookups are safe there):
/// at most 64, regular files with one link, names CH v54 writes only.
fn entries(dir: &Path) -> Result<Vec<String>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut names = Vec::new();
    for e in rd.take(MAX_FILES + 1) {
        let e = e.map_err(|e| e.to_string())?;
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| "a snapshot file name is not UTF-8".to_string())?;
        let m = std::fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
        if !m.file_type().is_file() || m.nlink() != 1 || m.uid() != euid() {
            return Err(format!(
                "snapshot entry {name}: not a plain file of the daemon's"
            ));
        }
        names.push(name);
    }
    if names.len() > MAX_FILES {
        return Err(format!("snapshot: more than {MAX_FILES} entries"));
    }
    if let Some(n) = names.iter().find(|n| !NAMES.contains(&n.as_str())) {
        return Err(format!("snapshot: unexpected file {n}"));
    }
    names.sort();
    Ok(names)
}

fn remove_tree(p: &Path) {
    // Inside the vault only. std's remove_dir_all does not follow symlinks.
    let _ = std::fs::remove_dir_all(p);
    let _ = std::fs::remove_file(p);
}

/// Remove the box's marker, then its vault copy.
pub fn discard(vault: &Path, id: &BoxId) -> Result<(), String> {
    match std::fs::remove_file(marker_path(vault, id)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("snapshot marker: {e}")),
    }
    remove_tree(&snap_dir(vault, id));
    Ok(())
}

pub fn remove_marker(vault: &Path, id: &BoxId) {
    let _ = std::fs::remove_file(marker_path(vault, id));
}

fn dir_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Open the directory `name` under `at` without following a symlink.
fn open_dir_at<Fd: AsFd>(at: Fd, name: &Path) -> std::io::Result<OwnedFd> {
    Ok(rustix::fs::openat(at, name, dir_flags(), Mode::empty())?)
}

/// The names in the VMM-written snapshot dir, read from its fd.
fn list_fd(dir: &OwnedFd) -> Result<Vec<String>, String> {
    let rd = rustix::fs::Dir::read_from(dir).map_err(|e| format!("snapshot: {e}"))?;
    let mut names = Vec::new();
    for e in rd {
        let e = e.map_err(|e| format!("snapshot: {e}"))?;
        let name = e
            .file_name()
            .to_str()
            .map_err(|_| "a snapshot file name is not UTF-8".to_string())?;
        if name == "." || name == ".." {
            continue;
        }
        if names.len() == MAX_FILES {
            return Err(format!("snapshot: more than {MAX_FILES} entries"));
        }
        names.push(name.to_string());
    }
    names.sort();
    Ok(names)
}

/// The most bytes a snapshot of a `mem_mib` MiB guest may hold in all.
pub fn max_total(mem_mib: u64) -> u64 {
    mem_mib.saturating_add(SLACK_MIB).saturating_mul(1 << 20)
}

/// Empty the box's `snapshot/` before a new `vm.snapshot`, by fd: the box
/// dir and `snapshot` are opened O_DIRECTORY|O_NOFOLLOW (a symlink is
/// refused, never followed) and each entry, at most `MAX_FILES`, is
/// unlinked (unlinkat removes a link, never its target). The dir itself
/// stays: the VMM's Landlock rule is bound to it (I4). A missing dir or a
/// subdirectory is refused.
pub fn clear_dir(paths: &BoxPaths) -> Result<(), String> {
    let boxfd = open_dir_at(CWD, &paths.dir).map_err(|e| format!("box dir: {e}"))?;
    let dir = open_dir_at(&boxfd, Path::new("snapshot")).map_err(|e| {
        format!("snapshot: not a directory ({e}); a symlink is refused, a missing one is made when the VMM starts")
    })?;
    for n in list_fd(&dir)? {
        let st = rustix::fs::statat(&dir, n.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("snapshot entry {n}: {e}"))?;
        if rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory {
            return Err(format!("snapshot entry {n}: a directory"));
        }
        rustix::fs::unlinkat(&dir, n.as_str(), AtFlags::empty())
            .map_err(|e| format!("snapshot entry {n}: {e}"))?;
    }
    Ok(())
}

/// Remove a box's runtime dir once its VMM is confirmed gone (R37): opened
/// O_DIRECTORY|O_NOFOLLOW, at most `MAX_FILES` entries, each unlinked by fd
/// (a link is removed, never followed); `snapshot/` is emptied by
/// [`clear_dir`] and removed; any other directory in it is refused and the
/// dir is kept. A missing dir is fine.
pub fn remove_runtime_dir(paths: &BoxPaths) -> Result<(), String> {
    let boxfd = match open_dir_at(CWD, &paths.dir) {
        Ok(fd) => fd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", paths.dir.display())),
    };
    let names = list_fd(&boxfd)?;
    let mut snapshot = false;
    for n in &names {
        let st = rustix::fs::statat(&boxfd, n.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("{n}: {e}"))?;
        if rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory {
            if n != "snapshot" {
                return Err(format!("an unexpected directory {n}"));
            }
            snapshot = true;
        }
    }
    if snapshot {
        clear_dir(paths)?;
    }
    for n in &names {
        let flags = if snapshot && n == "snapshot" {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        rustix::fs::unlinkat(&boxfd, n.as_str(), flags).map_err(|e| format!("{n}: {e}"))?;
    }
    drop(boxfd);
    std::fs::remove_dir(&paths.dir).map_err(|e| format!("{}: {e}", paths.dir.display()))
}

/// Copy one VMM-written file into the vault copy, hashing as it goes. The
/// source is opened relative to the snapshot dir's fd, never followed, never
/// blocking; it must be a regular file of the VMM user with one link, of at
/// most `cap` bytes (fstat, checked before a byte is copied) and within
/// what is left of `budget`; no more than that fstat size is ever read.
fn copy_entry(
    src: &OwnedFd,
    dst: &OwnedFd,
    name: &str,
    vmm_uid: u32,
    cap: u64,
    budget: &mut u64,
) -> Result<String, String> {
    let bad = |why: String| format!("snapshot entry {name}: {why}");
    let fd = rustix::fs::openat(
        src,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| bad(format!("{e} (a symlink?)")))?;
    let mut f = std::fs::File::from(fd);
    let m = f.metadata().map_err(|e| bad(e.to_string()))?;
    if !m.file_type().is_file() {
        return Err(bad("not a regular file".into()));
    }
    if m.uid() != vmm_uid {
        return Err(bad("its owner is not the VMM user".into()));
    }
    if m.nlink() != 1 {
        return Err(bad("hard-linked".into()));
    }
    let limit = cap.min(*budget);
    if m.len() > limit {
        return Err(bad(format!(
            "larger than {limit} bytes (the box's memory plus {SLACK_MIB} MiB in all)"
        )));
    }
    *budget -= m.len();
    let out = rustix::fs::openat(
        dst,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| bad(e.to_string()))?;
    let mut out = std::fs::File::from(out);
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    let mut r = (&mut f).take(m.len());
    loop {
        let n = r.read(&mut buf).map_err(|e| bad(e.to_string()))?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|e| bad(e.to_string()))?;
    }
    rustix::fs::fchmod(&out, Mode::from_raw_mode(0o640)).map_err(|e| bad(e.to_string()))?;
    out.sync_all().map_err(|e| bad(e.to_string()))?;
    Ok(hex(ctx.finish()))
}

/// After the daemon's own `vm.snapshot` into `<box>/snapshot`, with the VM
/// paused: copy it into the vault, every step relative to file descriptors
/// (S4). The box dir is opened O_DIRECTORY|O_NOFOLLOW (its parent, the
/// boxes dir, is the daemon's), `snapshot` under it the same way, so a
/// symlink anywhere the VMM controls is refused, never followed. Each entry
/// must be one of the names CH v54 writes, a regular file of `vmm_uid`
/// with one link. The copy goes into a fresh daemon-owned
/// `<vault>/<id>.snap` (mkdirat; files O_CREAT|O_EXCL, fchmod 0640, dir
/// 0750), hashed while copying; the marker is written last. Nothing is
/// renamed or chmodded by path, so this also works when the dir belongs to
/// the locked-mode VMM user. The source files are then removed (best
/// effort, by fd); the `snapshot` dir itself stays (its inode carries the
/// VMM's Landlock rule). The whole copy is capped at `max_total(mem_mib)`
/// bytes, `config.json` and `state.json` at `MAX_CONFIG` each, all checked
/// on the fstat size before copying.
pub fn seal(
    vault: &Path,
    id: &BoxId,
    paths: &BoxPaths,
    vmm_uid: u32,
    mem_mib: u64,
) -> Result<(), String> {
    vault::ensure(vault)?;
    discard(vault, id)?;
    let boxfd = open_dir_at(CWD, &paths.dir).map_err(|e| format!("box dir: {e}"))?;
    let src = open_dir_at(&boxfd, Path::new("snapshot"))
        .map_err(|e| format!("snapshot: not a directory ({e}); a symlink is refused"))?;
    let st = rustix::fs::fstat(&src).map_err(|e| format!("snapshot: {e}"))?;
    if st.st_uid != vmm_uid {
        return Err("snapshot: its owner is not the VMM user".into());
    }
    let names = list_fd(&src)?;
    if let Some(n) = names.iter().find(|n| !NAMES.contains(&n.as_str())) {
        return Err(format!("snapshot: unexpected file {n}"));
    }
    if !names.iter().any(|n| n == "config.json") {
        return Err("snapshot: no config.json".into());
    }
    let vfd = open_dir_at(CWD, vault).map_err(|e| format!("box vault: {e}"))?;
    let leaf = format!("{}.snap", id.as_str());
    rustix::fs::mkdirat(&vfd, leaf.as_str(), Mode::from_raw_mode(0o700))
        .map_err(|e| format!("vault copy: {e}"))?;
    let copied = (|| -> Result<BTreeMap<String, String>, String> {
        let dst = open_dir_at(&vfd, Path::new(&leaf)).map_err(|e| format!("vault copy: {e}"))?;
        let mut files = BTreeMap::new();
        let mut budget = max_total(mem_mib);
        for n in &names {
            let cap = if n == "memory-ranges" {
                u64::MAX
            } else {
                MAX_CONFIG
            };
            let h = copy_entry(&src, &dst, n, vmm_uid, cap, &mut budget)?;
            files.insert(n.clone(), h);
        }
        rustix::fs::fchmod(&dst, Mode::from_raw_mode(0o750))
            .map_err(|e| format!("vault copy: {e}"))?;
        rustix::fs::fsync(&dst).map_err(|e| format!("vault copy: {e}"))?;
        Ok(files)
    })();
    let files = match copied {
        Ok(f) => f,
        Err(e) => {
            remove_tree(&snap_dir(vault, id));
            return Err(e);
        }
    };
    for n in &names {
        let _ = rustix::fs::unlinkat(&src, n.as_str(), AtFlags::empty());
    }
    let body = serde_json::to_vec(&Marker { version: 2, files }).map_err(|e| e.to_string())?;
    vault::write_atomic(&marker_path(vault, id), &body)
}

/// The vault copy to restore from, when the marker matches every file in it
/// and its config names only this box's files and devices; Err says why
/// not. Called right before the start, with no VMM of this box running.
pub fn verify(
    vault: &Path,
    id: &BoxId,
    paths: &BoxPaths,
    spec: &LaunchSpec,
) -> Result<PathBuf, String> {
    let raw = read_bounded(&marker_path(vault, id), MAX_MARKER)
        .map_err(|_| "no marker: the snapshot was not taken by this daemon".to_string())?;
    let m: Marker = serde_json::from_slice(&raw).map_err(|e| format!("bad marker: {e}"))?;
    if m.version != 2 {
        return Err("bad marker version".into());
    }
    let dir = snap_dir(vault, id);
    let names = entries(&dir)?;
    if names.iter().collect::<Vec<_>>() != m.files.keys().collect::<Vec<_>>() {
        return Err("snapshot: the vault copy's files differ from the marker".into());
    }
    let mut config = None;
    for n in &names {
        let p = dir.join(n);
        let got = if n == "config.json" {
            let b = read_bounded(&p, MAX_CONFIG)?;
            let h = hex(ring::digest::digest(&ring::digest::SHA256, &b));
            config = Some(b);
            h
        } else {
            let mut f = open_ro(&p)?;
            let len = f.metadata().map_err(|e| e.to_string())?.len();
            hash_file(&mut f, len)?
        };
        if m.files.get(n) != Some(&got) {
            return Err(format!("{n} differs from the snapshot the daemon took"));
        }
    }
    let config = config.ok_or("snapshot: no config.json")?;
    let v: Value = serde_json::from_slice(&config).map_err(|e| format!("config.json: {e}"))?;
    check_config(&v, paths, spec)?;
    Ok(dir)
}

/// Absent, null, false, `[]` or `{}`.
fn nullish(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => true,
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Object(o)) => o.is_empty(),
        _ => false,
    }
}

fn is_path(v: Option<&Value>, want: &Path) -> bool {
    v.and_then(Value::as_str)
        .is_some_and(|s| Path::new(s) == want)
}

fn only_keys(section: &str, o: &Value, checked: &[&str]) -> Result<(), String> {
    if let Some(map) = o.as_object() {
        for (k, v) in map {
            if !checked.contains(&k.as_str()) && !nullish(Some(v)) {
                return Err(format!("{section}: unexpected {k}"));
            }
        }
    }
    Ok(())
}

/// Top-level sections without host paths: not inspected further.
const PLAIN: &[&str] = &[
    "cpus",
    "balloon",
    "pvpanic",
    "iommu",
    "watchdog",
    "numa",
    "platform",
    "rate_limit_groups",
    "pci_segments",
];

/// The snapshot's `VmConfig` (CH v54) names this box's files only, the
/// devices `launch::argv` sets, and the same Landlock policy. Any other
/// section with a value (net, fs, pmem, vfio devices, user devices, vdpa,
/// tpm, sgx, preserved fds, or anything unknown) is refused.
pub fn check_config(v: &Value, paths: &BoxPaths, spec: &LaunchSpec) -> Result<(), String> {
    let Some(top) = v.as_object() else {
        return Err("config.json: not an object".into());
    };
    for (k, val) in top {
        let handled = PLAIN.contains(&k.as_str())
            || matches!(
                k.as_str(),
                "memory"
                    | "payload"
                    | "disks"
                    | "rng"
                    | "serial"
                    | "console"
                    | "debug_console"
                    | "vsock"
                    | "landlock_enable"
                    | "landlock_rules"
            );
        if !handled && !nullish(Some(val)) {
            return Err(format!("{k}: a device or setting the box does not have"));
        }
    }
    // memory: no file-backed zones
    if let Some(zones) = v.pointer("/memory/zones").and_then(Value::as_array) {
        if zones.iter().any(|z| !nullish(z.get("file"))) {
            return Err("memory: a file-backed zone".into());
        }
    }
    check_sizes(v, spec)?;
    check_payload(v.get("payload"), spec)?;
    check_disks(v.get("disks"), paths, spec)?;
    if let Some(rng) = v.get("rng").filter(|r| !nullish(Some(r))) {
        if rng.get("src").and_then(Value::as_str) != Some("/dev/urandom") {
            return Err("rng: src is not /dev/urandom".into());
        }
    }
    let serial = v.get("serial").unwrap_or(&Value::Null);
    if !is_path(serial.get("file"), &paths.serial()) || !nullish(serial.get("socket")) {
        return Err("serial: not the box's serial.log".into());
    }
    for c in ["console", "debug_console"] {
        let s = v.get(c).unwrap_or(&Value::Null);
        if !nullish(s.get("file")) || !nullish(s.get("socket")) {
            return Err(format!("{c}: a host file or socket"));
        }
    }
    let vsock = v.get("vsock").unwrap_or(&Value::Null);
    if !is_path(vsock.get("socket"), &paths.vsock()) {
        return Err("vsock: socket is not the box's vsock.sock".into());
    }
    check_landlock(v, paths, spec)
}

/// On restore Cloud Hypervisor takes the vCPUs and memory from the
/// snapshot's config, which the VMM wrote, not from argv: they must be
/// what the box was admitted with (`spec`, the daemon's), with no hotplug
/// room, shared or hugepage memory and no NUMA or memory zones.
fn check_sizes(v: &Value, spec: &LaunchSpec) -> Result<(), String> {
    let n = |p: &str| v.pointer(p).and_then(Value::as_u64);
    let vcpus = u64::from(spec.vcpus);
    if n("/cpus/boot_vcpus") != Some(vcpus) || n("/cpus/max_vcpus") != Some(vcpus) {
        return Err(format!("cpus: not the box's {} vCPUs", spec.vcpus));
    }
    if n("/memory/size") != Some(spec.mem_mib << 20) {
        return Err(format!("memory: not the box's {} MiB", spec.mem_mib));
    }
    for k in ["hotplug_size", "hotplugged_size", "zones"] {
        if !nullish(v.pointer(&format!("/memory/{k}"))) {
            return Err(format!("memory: {k} is set"));
        }
    }
    for k in ["shared", "hugepages"] {
        if v.pointer(&format!("/memory/{k}")).and_then(Value::as_bool) == Some(true) {
            return Err(format!("memory: {k} is on"));
        }
    }
    if !nullish(v.get("numa")) {
        return Err("numa: set".into());
    }
    Ok(())
}

fn check_payload(p: Option<&Value>, spec: &LaunchSpec) -> Result<(), String> {
    let p = p.unwrap_or(&Value::Null);
    let ok = match &spec.boot {
        Boot::Firmware { fw } => {
            is_path(p.get("firmware"), fw) && nullish(p.get("kernel")) && nullish(p.get("cmdline"))
        }
        Boot::Kernel { kernel, cmdline } => {
            is_path(p.get("kernel"), kernel)
                && nullish(p.get("firmware"))
                && p.get("cmdline").and_then(Value::as_str) == Some(cmdline.as_str())
        }
    };
    if !ok {
        return Err("payload: firmware or kernel is not the box's".into());
    }
    only_keys("payload", p, &["firmware", "kernel", "cmdline"])
}

fn check_disks(d: Option<&Value>, paths: &BoxPaths, spec: &LaunchSpec) -> Result<(), String> {
    let Some(disks) = d.and_then(Value::as_array) else {
        return Err("disks: missing".into());
    };
    let (root, repo) = (paths.root_disk(), paths.repo_disk());
    let (mut seen_root, mut seen_repo) = (false, false);
    for disk in disks {
        if !nullish(disk.get("vhost_user")) || !nullish(disk.get("vhost_socket")) {
            return Err("disks: a vhost-user disk".into());
        }
        if is_path(disk.get("path"), &root) && !seen_root {
            seen_root = true;
        } else if spec.repo && is_path(disk.get("path"), &repo) && !seen_repo {
            seen_repo = true;
        } else {
            return Err("disks: a disk that is not the box's root.qcow2 or repo.img".into());
        }
    }
    if !seen_root {
        return Err("disks: no root.qcow2".into());
    }
    Ok(())
}

fn check_landlock(v: &Value, paths: &BoxPaths, spec: &LaunchSpec) -> Result<(), String> {
    let on = v.get("landlock_enable").and_then(Value::as_bool) == Some(true);
    if on != spec.landlock {
        return Err(format!(
            "landlock: {} in the snapshot, {} for the box",
            if on { "on" } else { "off" },
            if spec.landlock { "on" } else { "off" }
        ));
    }
    let snap = paths.snapshot_dir();
    let rules = v.get("landlock_rules");
    if nullish(rules) {
        return Ok(());
    }
    let Some(rules) = rules.and_then(Value::as_array) else {
        return Err("landlock: rules are not a list".into());
    };
    for r in rules {
        let access = r.get("access").and_then(Value::as_str);
        let ok = (is_path(r.get("path"), &spec.base) && access == Some("r"))
            || (is_path(r.get("path"), &snap) && access == Some("rw"));
        if !ok {
            return Err("landlock: a rule the launcher does not set".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (BoxPaths, LaunchSpec, Value) {
        let paths = BoxPaths::new(PathBuf::from("/b/b1"));
        let spec = LaunchSpec {
            version: 1,
            id: BoxId::parse("b1").unwrap(),
            vcpus: 2,
            mem_mib: 1024,
            base: PathBuf::from("/i/base"),
            repo: true,
            boot: Boot::Firmware {
                fw: PathBuf::from("/v/CLOUDHV.fd"),
            },
            landlock: true,
            restore: None,
        };
        let v = serde_json::json!({
            "cpus": {"boot_vcpus": 2, "max_vcpus": 2},
            "memory": {"size": 1u64 << 30, "zones": null},
            "payload": {"firmware": "/v/CLOUDHV.fd", "kernel": null, "cmdline": null, "initramfs": null},
            "disks": [{"path": "/b/b1/root.qcow2", "vhost_user": false}, {"path": "/b/b1/repo.img"}],
            "net": null, "fs": null, "pmem": null, "devices": null,
            "rng": {"src": "/dev/urandom"},
            "serial": {"file": "/b/b1/serial.log", "mode": "File", "socket": null},
            "console": {"file": null, "mode": "Off"},
            "vsock": {"cid": 3, "socket": "/b/b1/vsock.sock"},
            "landlock_enable": true,
            "landlock_rules": [{"path": "/i/base", "access": "r"}, {"path": "/b/b1/snapshot", "access": "rw"}]
        });
        (paths, spec, v)
    }

    #[test]
    fn a_launcher_shaped_config_passes() {
        let (p, s, v) = fixture();
        check_config(&v, &p, &s).unwrap();
    }

    #[test]
    fn anything_else_is_refused() {
        type Edit = fn(&mut Value);
        let cases: &[(&str, Edit)] = &[
            ("disks", |v| v["disks"][1]["path"] = "/etc/shadow".into()),
            ("disks", |v| {
                v["disks"][0]["vhost_socket"] = "/x.sock".into()
            }),
            ("disks", |v| {
                v["disks"] = serde_json::json!([{"path": "/b/b1/repo.img"}])
            }),
            ("net", |v| v["net"] = serde_json::json!([{"tap": "t"}])),
            ("fs", |v| v["fs"] = serde_json::json!([{"socket": "/x"}])),
            ("user_devices", |v| {
                v["user_devices"] = serde_json::json!([{"socket": "/x"}])
            }),
            ("future", |v| v["future"] = 1.into()),
            ("payload", |v| v["payload"]["initramfs"] = "/x".into()),
            ("payload", |v| v["payload"]["kernel"] = "/v/vmlinux".into()),
            ("memory", |v| {
                v["memory"]["zones"] = serde_json::json!([{"file": "/dev/shm/x"}])
            }),
            ("cpus", |v| v["cpus"]["boot_vcpus"] = 32.into()),
            ("cpus", |v| v["cpus"]["max_vcpus"] = 32.into()),
            ("memory", |v| v["memory"]["size"] = (4u64 << 30).into()),
            ("memory", |v| {
                v["memory"]["hotplug_size"] = (1u64 << 34).into()
            }),
            ("memory", |v| v["memory"]["shared"] = true.into()),
            ("memory", |v| v["memory"]["hugepages"] = true.into()),
            ("numa", |v| {
                v["numa"] = serde_json::json!([{"guest_numa_id": 0}])
            }),
            ("rng", |v| v["rng"]["src"] = "/etc/shadow".into()),
            ("serial", |v| v["serial"]["file"] = "/etc/x".into()),
            ("console", |v| v["console"]["file"] = "/etc/x".into()),
            ("vsock", |v| {
                v["vsock"]["socket"] = "/b/b2/vsock.sock".into()
            }),
            ("landlock", |v| v["landlock_enable"] = false.into()),
            ("landlock", |v| {
                v["landlock_rules"][0]["access"] = "rw".into()
            }),
        ];
        for (what, edit) in cases {
            let (p, s, mut v) = fixture();
            edit(&mut v);
            let e = check_config(&v, &p, &s).unwrap_err();
            assert!(e.contains(what), "{what}: {e}");
        }
        // without repo.img in the spec, a repo disk is foreign
        let (p, mut s, v) = fixture();
        s.repo = false;
        assert!(check_config(&v, &p, &s).unwrap_err().contains("disks"));
    }
}
