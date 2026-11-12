//! When a snapshot may be restored (S1, S3 / ruling R20). CH writes its
//! snapshot into `<box>/snapshot`, which the VMM can write. So right after
//! the daemon's own `vm.snapshot`, while the VM is paused, `seal` moves it
//! into the vault (`<vault>/<id>.snap`, which no VMM can write), makes it
//! read-only and records the SHA-256 of every file in `<vault>/<id>.marker`.
//! At boot `verify` re-hashes the vault copy, compares, and runs
//! `check_config` on the very bytes it hashed; the restore reads only that
//! copy. The box dir's `snapshot/` is never a restore source.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use saiife_wire::source::BoxId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::launch::{Boot, LaunchSpec};
use crate::paths::BoxPaths;
use crate::vault::{self, euid, marker_path, read_bounded, snap_dir};

/// `config.json` larger than this is refused (it is parsed in memory).
pub const MAX_CONFIG: u64 = 16 * 1024 * 1024;
/// A snapshot with more entries than this is refused.
pub const MAX_FILES: usize = 64;
const MAX_MARKER: u64 = 64 * 1024;
const EXDEV: i32 = 18;

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

/// The entries of a snapshot dir: at most 64, regular files only.
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
        if !m.file_type().is_file() {
            return Err(format!("snapshot entry {name}: not a regular file"));
        }
        names.push(name);
    }
    if names.len() > MAX_FILES {
        return Err(format!("snapshot: more than {MAX_FILES} entries"));
    }
    names.sort();
    Ok(names)
}

/// Every entry of `dir` and its own dir are ours, unlinked elsewhere.
fn all_ours(dir: &Path, names: &[String]) -> bool {
    let me = euid();
    let ok = |p: &Path, file: bool| {
        std::fs::symlink_metadata(p)
            .is_ok_and(|m| m.uid() == me && (!file || (m.file_type().is_file() && m.nlink() == 1)))
    };
    ok(dir, false) && names.iter().all(|n| ok(&dir.join(n), true))
}

/// A bounded copy of `src`'s regular files into a new `dst` (0750) the daemon
/// owns. Each file is read up to its size when opened.
fn copy_dir(src: &Path, dst: &Path, names: &[String]) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .mode(0o750)
        .create(dst)
        .map_err(|e| format!("{}: {e}", dst.display()))?;
    for n in names {
        let mut f = open_ro(&src.join(n))?;
        let m = f.metadata().map_err(|e| e.to_string())?;
        if !m.file_type().is_file() {
            return Err(format!("snapshot entry {n}: not a regular file"));
        }
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(dst.join(n))
            .map_err(|e| format!("{n}: {e}"))?;
        std::io::copy(&mut (&mut f).take(m.len()), &mut out).map_err(|e| format!("{n}: {e}"))?;
        out.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn remove_tree(p: &Path) {
    // std's remove_dir_all does not follow symlinks.
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

/// After the daemon's own `vm.snapshot` into `<box>/snapshot`, with the VM
/// paused: move it into the vault (rename; a bounded copy across
/// filesystems or when a file is not the daemon's own, e.g. written by the
/// locked-mode VMM user, or hard-linked), make it read-only (files 0640,
/// dir 0750) and write the marker last.
pub fn seal(vault: &Path, id: &BoxId, paths: &BoxPaths) -> Result<(), String> {
    vault::ensure(vault)?;
    discard(vault, id)?;
    let src = paths.snapshot_dir();
    let dst = snap_dir(vault, id);
    let incoming = vault.join(format!("{}.snap.in", id.as_str()));
    remove_tree(&incoming);
    let names = match std::fs::rename(&src, &incoming) {
        Ok(()) => {
            let names = entries(&incoming)?;
            if all_ours(&incoming, &names) {
                std::fs::rename(&incoming, &dst).map_err(|e| format!("snapshot: {e}"))?;
            } else {
                let r = copy_dir(&incoming, &dst, &names);
                remove_tree(&incoming);
                r?;
            }
            names
        }
        Err(e) if e.raw_os_error() == Some(EXDEV) => {
            let names = entries(&src)?;
            copy_dir(&src, &dst, &names)?;
            remove_tree(&src);
            names
        }
        Err(e) => return Err(format!("move the snapshot into the vault: {e}")),
    };
    let mut files = BTreeMap::new();
    for n in &names {
        let p = dst.join(n);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640))
            .map_err(|e| format!("{n}: {e}"))?;
        let mut f = open_ro(&p)?;
        let len = f.metadata().map_err(|e| e.to_string())?.len();
        files.insert(n.clone(), hash_file(&mut f, len)?);
    }
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o750))
        .map_err(|e| format!("snapshot dir: {e}"))?;
    if !files.contains_key("config.json") {
        let _ = discard(vault, id);
        return Err("snapshot: no config.json".into());
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
    if !all_ours(&dir, &names) {
        return Err("snapshot: a file in the vault copy is not the daemon's own".into());
    }
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
            "cpus": {"boot_vcpus": 2},
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
