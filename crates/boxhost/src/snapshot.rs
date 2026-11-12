//! When a snapshot may be restored (S1). The box dir, and the snapshot in
//! it, is writable by the VMM; a compromised VMM could plant or edit a
//! snapshot whose config points the next VMM at other files or turns
//! Landlock off. So a restore needs:
//! - a marker in the daemon-private `marks` dir, written right after the
//!   daemon's own `vm.snapshot`, holding the SHA-256 of `config.json` and
//!   `state.json` (`memory-ranges` is the guest's own memory, not hashed);
//! - both digests matching now;
//! - `config.json` naming only this box's files and devices (`check_config`).

use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use saiife_wire::source::BoxId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::launch::{Boot, LaunchSpec};
use crate::paths::BoxPaths;

/// `config.json` and `state.json` larger than this are refused.
pub const MAX_SNAPSHOT_JSON: u64 = 16 * 1024 * 1024;
const MAX_MARKER: u64 = 4096;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u32,
    config: String,
    state: String,
}

pub fn marker_path(marks: &Path, id: &BoxId) -> PathBuf {
    marks.join(format!("{}.snapshot", id.as_str()))
}

pub fn remove_marker(marks: &Path, id: &BoxId) -> Result<(), String> {
    match std::fs::remove_file(marker_path(marks, id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("snapshot marker: {e}")),
    }
}

/// A regular file (no symlink, no FIFO) of at most `cap` bytes.
fn read_bounded(p: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let name = p
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(p)
        .map_err(|e| format!("{name}: {e}"))?;
    let m = f.metadata().map_err(|e| format!("{name}: {e}"))?;
    if !m.file_type().is_file() {
        return Err(format!("{name}: not a regular file"));
    }
    if m.len() > cap {
        return Err(format!("{name}: larger than {cap} bytes"));
    }
    let mut buf = Vec::new();
    f.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{name}: {e}"))?;
    if buf.len() as u64 > cap {
        return Err(format!("{name}: larger than {cap} bytes"));
    }
    Ok(buf)
}

fn sha_hex(b: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, b);
    d.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn digests(paths: &BoxPaths) -> Result<(Vec<u8>, String, String), String> {
    let dir = paths.snapshot_dir();
    let config = read_bounded(&dir.join("config.json"), MAX_SNAPSHOT_JSON)?;
    let state = read_bounded(&dir.join("state.json"), MAX_SNAPSHOT_JSON)?;
    let (c, s) = (sha_hex(&config), sha_hex(&state));
    Ok((config, c, s))
}

/// After the daemon's own `vm.snapshot`: record the digests (tmp + rename,
/// 0600). The `marks` dir is created 0700 when missing.
pub fn write_marker(marks: &Path, id: &BoxId, paths: &BoxPaths) -> Result<(), String> {
    let (_, config, state) = digests(paths)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(marks)
        .map_err(|e| format!("marks dir {}: {e}", marks.display()))?;
    let m = std::fs::symlink_metadata(marks).map_err(|e| format!("marks dir: {e}"))?;
    if !m.file_type().is_dir() {
        return Err(format!("marks dir {} is not a directory", marks.display()));
    }
    let body = serde_json::to_vec(&Marker {
        version: 1,
        config,
        state,
    })
    .map_err(|e| e.to_string())?;
    let dest = marker_path(marks, id);
    let tmp = marks.join(format!("{}.snapshot.tmp", id.as_str()));
    let _ = std::fs::remove_file(&tmp);
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &dest)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("snapshot marker: {e}")
    })
}

/// Ok when the box's snapshot may be restored with `spec`; Err says why not.
pub fn check(marks: &Path, id: &BoxId, paths: &BoxPaths, spec: &LaunchSpec) -> Result<(), String> {
    let raw = read_bounded(&marker_path(marks, id), MAX_MARKER)
        .map_err(|_| "no marker: the snapshot was not taken by this daemon".to_string())?;
    let m: Marker = serde_json::from_slice(&raw).map_err(|e| format!("bad marker: {e}"))?;
    if m.version != 1 {
        return Err("bad marker version".into());
    }
    let (config, c, s) = digests(paths)?;
    if c != m.config {
        return Err("config.json differs from the snapshot the daemon took".into());
    }
    if s != m.state {
        return Err("state.json differs from the snapshot the daemon took".into());
    }
    let v: Value = serde_json::from_slice(&config).map_err(|e| format!("config.json: {e}"))?;
    check_config(&v, paths, spec)
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
            restore: true,
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
