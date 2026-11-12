//! The launch spec (`vm.json`), its argv for Cloud Hypervisor, and the checks
//! `saiife __box-vmm` makes before it execs (V7, V8, V9; Review Focus 1-2).
//! Ported from the spike's `ch_boot` and `ch_restore`.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use saiife_wire::source::BoxId;
use serde::{Deserialize, Serialize};

use crate::layout::Layout;
use crate::paths::BoxPaths;

/// V7: the longest socket path a spec may produce (sun_path is 108 bytes).
pub const MAX_SOCK_PATH: usize = 100;
/// A `vm.json` larger than this is refused.
pub const MAX_SPEC_BYTES: u64 = 16 * 1024;
/// Plan 34's bounds (`crates/boxes/src/template.rs`, size validation).
const VCPUS: std::ops::RangeInclusive<u32> = 1..=32;
const MEM_MIB: std::ops::RangeInclusive<u64> = 512..=262_144;
const CMDLINE_MAX: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Boot {
    Firmware { fw: PathBuf },
    Kernel { kernel: PathBuf, cmdline: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    pub version: u32,
    pub id: BoxId,
    pub vcpus: u32,
    pub mem_mib: u64,
    pub base: PathBuf,
    pub repo: bool,
    pub boot: Boot,
    pub landlock: bool,
    pub restore: bool,
}

/// The directories a spec's paths must lie in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    pub boxes: PathBuf,
    pub images: PathBuf,
    pub vmm: PathBuf,
}

impl Allowed {
    pub fn for_layout(l: &Layout) -> Allowed {
        Allowed {
            boxes: l.boxes.clone(),
            images: l.images.clone(),
            vmm: l.vmm.clone(),
        }
    }
}

/// V9: `SAIIFE_TEST_NO_PIN=1` skips the digest check, in debug builds only.
pub fn pin_check_skipped(env: &dyn Fn(&str) -> Option<OsString>) -> bool {
    cfg!(debug_assertions) && env("SAIIFE_TEST_NO_PIN").is_some_and(|v| v == "1")
}

/// V8: why `s` cannot go into a Cloud Hypervisor option value.
fn unsafe_path_reason(p: &Path) -> Option<&'static str> {
    let Some(s) = p.to_str() else {
        return Some("is not UTF-8");
    };
    if !p.is_absolute() {
        return Some("is not absolute");
    }
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Some("has a \"..\" component");
    }
    if s.chars().any(|c| c == ',' || c == '=') {
        return Some("contains \",\" or \"=\"");
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Some("contains whitespace or a control character");
    }
    None
}

fn check_path(field: &str, p: &Path) -> Result<(), String> {
    match unsafe_path_reason(p) {
        Some(why) => Err(format!("{field}: {why}")),
        None => Ok(()),
    }
}

/// Lexically directly under `parent`: absolute paths, no `..` (checked before).
fn directly_under(p: &Path, parent: &Path) -> bool {
    p.parent() == Some(parent) && p.file_name().is_some()
}

fn under(p: &Path, root: &Path) -> bool {
    p != root && p.starts_with(root)
}

fn is_plain_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file())
}

pub fn check_spec(spec: &LaunchSpec, paths: &BoxPaths, allowed: &Allowed) -> Result<(), String> {
    if spec.version != 1 {
        return Err(format!("version: {} is not 1", spec.version));
    }
    let dir = &paths.dir;
    check_path("dir", dir)?;
    check_path("allowed boxes dir", &allowed.boxes)?;
    if dir.file_name().and_then(OsStr::to_str) != Some(spec.id.as_str()) {
        return Err("id: differs from the box directory name".into());
    }
    if !directly_under(dir, &allowed.boxes) {
        return Err("dir: not directly under the boxes directory".into());
    }
    let mut walk = PathBuf::new();
    for c in dir.components() {
        walk.push(c);
        match std::fs::symlink_metadata(&walk) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!("dir: {} is a symlink", walk.display()))
            }
            Ok(_) => {}
            Err(e) => return Err(format!("dir: {}: {e}", walk.display())),
        }
    }
    check_path("base", &spec.base)?;
    if !directly_under(&spec.base, &allowed.images) {
        return Err("base: not directly under the images directory".into());
    }
    if !is_plain_file(&spec.base) {
        return Err("base: not a regular file".into());
    }
    match &spec.boot {
        Boot::Firmware { fw } => check_boot_file("fw", fw, allowed)?,
        Boot::Kernel { kernel, cmdline } => {
            check_boot_file("kernel", kernel, allowed)?;
            // The cmdline is one argv element, not an option list: `=` and
            // spaces are ordinary kernel parameters. Control characters and
            // an unbounded length are not.
            if cmdline.len() > CMDLINE_MAX || cmdline.chars().any(char::is_control) {
                return Err("cmdline: too long or contains a control character".into());
            }
        }
    }
    if !VCPUS.contains(&spec.vcpus) {
        return Err(format!("vcpus: {} is outside 1..=32", spec.vcpus));
    }
    if !MEM_MIB.contains(&spec.mem_mib) {
        return Err(format!("mem_mib: {} is outside 512..=262144", spec.mem_mib));
    }
    let n = paths.longest_socket().as_os_str().as_bytes().len();
    if n > MAX_SOCK_PATH {
        return Err(format!(
            "dir: socket path would be {n} bytes, over {MAX_SOCK_PATH}"
        ));
    }
    Ok(())
}

fn check_boot_file(field: &str, p: &Path, allowed: &Allowed) -> Result<(), String> {
    check_path(field, p)?;
    if under(p, &allowed.vmm) || under(p, &allowed.images) {
        Ok(())
    } else {
        Err(format!("{field}: not under the vmm or images directory"))
    }
}

fn arg(parts: &[&OsStr]) -> OsString {
    let mut o = OsString::new();
    for p in parts {
        o.push(p);
    }
    o
}

/// The Cloud Hypervisor argv (pure). Callers run `check_spec` first.
pub fn argv(spec: &LaunchSpec, paths: &BoxPaths) -> Vec<OsString> {
    let o = |s: &str| OsString::from(s);
    let api = arg(&[OsStr::new("path="), paths.api_sock().as_os_str()]);
    if spec.restore {
        return vec![
            o("--restore"),
            arg(&[
                OsStr::new("source_url=file://"),
                paths.snapshot_dir().as_os_str(),
            ]),
            o("--api-socket"),
            api,
        ];
    }
    let mut v = Vec::new();
    match &spec.boot {
        Boot::Firmware { fw } => {
            v.push(o("--firmware"));
            v.push(fw.clone().into_os_string());
        }
        Boot::Kernel { kernel, cmdline } => {
            v.push(o("--kernel"));
            v.push(kernel.clone().into_os_string());
            v.push(o("--cmdline"));
            v.push(o(cmdline));
        }
    }
    v.push(o("--disk"));
    v.push(arg(&[
        OsStr::new("path="),
        paths.root_disk().as_os_str(),
        OsStr::new(",image_type=qcow2,backing_files=on"),
    ]));
    if spec.repo {
        v.push(arg(&[
            OsStr::new("path="),
            paths.repo_disk().as_os_str(),
            OsStr::new(",image_type=raw"),
        ]));
    }
    v.push(o("--cpus"));
    v.push(o(&format!("boot={}", spec.vcpus)));
    v.push(o("--memory"));
    v.push(o(&format!("size={}M", spec.mem_mib)));
    v.push(o("--vsock"));
    v.push(arg(&[
        OsStr::new("cid=3,socket="),
        paths.vsock().as_os_str(),
    ]));
    v.push(o("--balloon"));
    v.push(o("size=0,free_page_reporting=on,deflate_on_oom=on"));
    if spec.landlock {
        v.push(o("--landlock"));
        v.push(o("--landlock-rules"));
        v.push(arg(&[
            OsStr::new("path="),
            spec.base.as_os_str(),
            OsStr::new(",access=r"),
        ]));
        v.push(arg(&[
            OsStr::new("path="),
            paths.snapshot_dir().as_os_str(),
            OsStr::new(",access=rw"),
        ]));
    }
    v.push(o("--serial"));
    v.push(arg(&[OsStr::new("file="), paths.serial().as_os_str()]));
    v.push(o("--console"));
    v.push(o("off"));
    v.push(o("--api-socket"));
    v.push(api);
    v
}

/// `vm.json.tmp` (0640) renamed over `vm.json`.
pub fn write_spec(spec: &LaunchSpec, paths: &BoxPaths) -> Result<(), String> {
    let body = serde_json::to_vec(spec).map_err(|e| e.to_string())?;
    let tmp = paths.dir.join("vm.json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        std::fs::rename(&tmp, paths.vm_json())
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("vm.json: {e}")
    })
}

/// Reads `vm.json`: a regular file (not a symlink, no FIFO), at most 16 KiB.
pub fn read_spec(paths: &BoxPaths) -> Result<LaunchSpec, String> {
    let p = paths.vm_json();
    let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(&p)
        .map_err(|e| format!("vm.json: {}: {e}", p.display()))?;
    let m = f.metadata().map_err(|e| format!("vm.json: {e}"))?;
    if !m.file_type().is_file() {
        return Err("vm.json: not a regular file".into());
    }
    if m.len() > MAX_SPEC_BYTES {
        return Err(format!("vm.json: larger than {MAX_SPEC_BYTES} bytes"));
    }
    let mut buf = Vec::new();
    f.take(MAX_SPEC_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("vm.json: {e}"))?;
    if buf.len() as u64 > MAX_SPEC_BYTES {
        return Err(format!("vm.json: larger than {MAX_SPEC_BYTES} bytes"));
    }
    serde_json::from_slice(&buf).map_err(|e| format!("vm.json: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Env {
        _t: tempfile::TempDir,
        root: PathBuf,
        allowed: Allowed,
    }

    fn env() -> Env {
        let t = tempfile::tempdir_in(
            std::env::var_os("SAIIFE_TEST_TMP")
                .unwrap_or_else(|| "/".into())
                .as_os_str(),
        );
        let t = t.unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        for d in ["boxes", "images", "vmm", "elsewhere"] {
            std::fs::create_dir(root.join(d)).unwrap();
        }
        std::fs::write(root.join("images/base.qcow2"), b"x").unwrap();
        std::fs::write(root.join("vmm/CLOUDHV.fd"), b"x").unwrap();
        let allowed = Allowed {
            boxes: root.join("boxes"),
            images: root.join("images"),
            vmm: root.join("vmm"),
        };
        Env {
            _t: t,
            root,
            allowed,
        }
    }

    fn spec(e: &Env, id: &str) -> LaunchSpec {
        LaunchSpec {
            version: 1,
            id: BoxId::parse(id).unwrap(),
            vcpus: 2,
            mem_mib: 4096,
            base: e.root.join("images/base.qcow2"),
            repo: true,
            boot: Boot::Firmware {
                fw: e.root.join("vmm/CLOUDHV.fd"),
            },
            landlock: true,
            restore: false,
        }
    }

    fn mkbox(e: &Env, id: &str) -> BoxPaths {
        let d = e.root.join("boxes").join(id);
        std::fs::create_dir(&d).unwrap();
        BoxPaths::new(d)
    }

    fn strs(v: Vec<OsString>) -> Vec<String> {
        v.into_iter().map(|s| s.into_string().unwrap()).collect()
    }

    fn fixed() -> (LaunchSpec, BoxPaths) {
        let s = LaunchSpec {
            version: 1,
            id: BoxId::parse("b1").unwrap(),
            vcpus: 2,
            mem_mib: 4096,
            base: PathBuf::from("/i/base.qcow2"),
            repo: true,
            boot: Boot::Firmware {
                fw: PathBuf::from("/v/CLOUDHV.fd"),
            },
            landlock: true,
            restore: false,
        };
        (s, BoxPaths::new(PathBuf::from("/b/b1")))
    }

    #[test]
    fn argv_is_pinned_firmware() {
        let (s, p) = fixed();
        assert_eq!(
            strs(argv(&s, &p)),
            [
                "--firmware",
                "/v/CLOUDHV.fd",
                "--disk",
                "path=/b/b1/root.qcow2,image_type=qcow2,backing_files=on",
                "path=/b/b1/repo.img,image_type=raw",
                "--cpus",
                "boot=2",
                "--memory",
                "size=4096M",
                "--vsock",
                "cid=3,socket=/b/b1/vsock.sock",
                "--balloon",
                "size=0,free_page_reporting=on,deflate_on_oom=on",
                "--landlock",
                "--landlock-rules",
                "path=/i/base.qcow2,access=r",
                "path=/b/b1/snapshot,access=rw",
                "--serial",
                "file=/b/b1/serial.log",
                "--console",
                "off",
                "--api-socket",
                "path=/b/b1/api.sock",
            ]
        );
    }

    #[test]
    fn argv_is_pinned_kernel_no_repo() {
        let (mut s, p) = fixed();
        s.repo = false;
        s.boot = Boot::Kernel {
            kernel: PathBuf::from("/v/vmlinux"),
            cmdline: "console=ttyS0 root=/dev/vda".into(),
        };
        let a = strs(argv(&s, &p));
        assert_eq!(
            a[..6],
            [
                "--kernel",
                "/v/vmlinux",
                "--cmdline",
                "console=ttyS0 root=/dev/vda",
                "--disk",
                "path=/b/b1/root.qcow2,image_type=qcow2,backing_files=on",
            ]
        );
        assert_eq!(a[6], "--cpus");
        assert!(!a.iter().any(|x| x.contains("repo.img")));
    }

    #[test]
    fn argv_restore_is_short() {
        let (mut s, p) = fixed();
        s.restore = true;
        assert_eq!(
            strs(argv(&s, &p)),
            [
                "--restore",
                "source_url=file:///b/b1/snapshot",
                "--api-socket",
                "path=/b/b1/api.sock"
            ]
        );
    }

    #[test]
    fn argv_without_landlock() {
        let (mut s, p) = fixed();
        s.landlock = false;
        let a = strs(argv(&s, &p));
        assert!(!a.iter().any(|x| x.starts_with("--landlock")));
        assert_eq!(
            a[a.len() - 4..],
            ["--console", "off", "--api-socket", "path=/b/b1/api.sock"]
        );
    }

    #[test]
    fn spec_roundtrip_and_unknown_field_refused() {
        let e = env();
        let p = mkbox(&e, "b1");
        let s = spec(&e, "b1");
        write_spec(&s, &p).unwrap();
        assert_eq!(read_spec(&p).unwrap(), s);
        assert!(!p.dir.join("vm.json.tmp").exists());
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(p.vm_json()).unwrap()).unwrap();
        v["extra"] = 1.into();
        std::fs::write(p.vm_json(), serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(read_spec(&p).unwrap_err().contains("extra"));
        std::fs::write(p.vm_json(), vec![b' '; 17 * 1024]).unwrap();
        assert!(read_spec(&p).unwrap_err().contains("larger"));
        std::fs::remove_file(p.vm_json()).unwrap();
        symlink(e.root.join("images/base.qcow2"), p.vm_json()).unwrap();
        assert!(read_spec(&p).is_err());
    }

    #[test]
    fn accepts_a_good_spec() {
        let e = env();
        let p = mkbox(&e, "b1");
        check_spec(&spec(&e, "b1"), &p, &e.allowed).unwrap();
    }

    #[test]
    fn helper_refuses_paths_outside() {
        let e = env();
        let p = mkbox(&e, "b1");
        std::fs::write(e.root.join("elsewhere/base.qcow2"), b"x").unwrap();
        let mut s = spec(&e, "b1");
        s.base = e.root.join("elsewhere/base.qcow2");
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("base:"));
        s.base = PathBuf::from("/etc/shadow");
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("base:"));
        s.base = e.root.join("images/../elsewhere/base.qcow2");
        assert!(check_spec(&s, &p, &e.allowed).unwrap_err().contains(".."));
        s.base = PathBuf::from("images/base.qcow2");
        assert!(check_spec(&s, &p, &e.allowed).is_err());
        let mut s = spec(&e, "b1");
        s.boot = Boot::Firmware {
            fw: e.root.join("elsewhere/fw"),
        };
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("fw:"));
        s.boot = Boot::Kernel {
            kernel: PathBuf::from("/boot/vmlinuz"),
            cmdline: "ro".into(),
        };
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("kernel:"));
        // a dir outside the boxes dir
        let out = BoxPaths::new(e.root.join("elsewhere"));
        let mut s = spec(&e, "elsewhere");
        s.id = BoxId::parse("elsewhere").unwrap();
        assert!(check_spec(&s, &out, &e.allowed)
            .unwrap_err()
            .starts_with("dir:"));
    }

    #[test]
    fn helper_refuses_option_smuggling() {
        let e = env();
        let p = mkbox(&e, "b1");
        let mut s = spec(&e, "b1");
        s.base = e.root.join("images/a,image_type=raw");
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("base:"));
        for bad in ["images/a b", "images/a\nb", "images/a=b"] {
            s.base = e.root.join(bad);
            assert!(
                check_spec(&s, &p, &e.allowed)
                    .unwrap_err()
                    .starts_with("base:"),
                "{bad}"
            );
        }
        let mut s = spec(&e, "b1");
        s.boot = Boot::Kernel {
            kernel: e.root.join("vmm/CLOUDHV.fd"),
            cmdline: "ro\n--disk path=/etc/shadow".into(),
        };
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("cmdline:"));
        // a smuggling dir name is a bad dir too
        let bad = BoxPaths::new(e.root.join("boxes/b1,x=y"));
        assert!(check_spec(&spec(&e, "b1"), &bad, &e.allowed).is_err());
    }

    #[test]
    fn helper_refuses_symlinked_dir() {
        let e = env();
        std::fs::create_dir(e.root.join("elsewhere/real")).unwrap();
        symlink(e.root.join("elsewhere/real"), e.root.join("boxes/b1")).unwrap();
        let p = BoxPaths::new(e.root.join("boxes/b1"));
        let err = check_spec(&spec(&e, "b1"), &p, &e.allowed).unwrap_err();
        assert!(err.starts_with("dir:") && err.contains("symlink"), "{err}");
    }

    #[test]
    fn helper_refuses_id_mismatch() {
        let e = env();
        let p = mkbox(&e, "b1");
        let err = check_spec(&spec(&e, "b2"), &p, &e.allowed).unwrap_err();
        assert!(err.starts_with("id:"), "{err}");
        let mut s = spec(&e, "b1");
        s.version = 2;
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("version:"));
        let mut s = spec(&e, "b1");
        s.vcpus = 0;
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("vcpus:"));
        let mut s = spec(&e, "b1");
        s.mem_mib = 100;
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("mem_mib:"));
    }

    #[test]
    fn socket_path_too_long_is_refused() {
        let e = env();
        // vsock.sock_5003 is 15 bytes after the dir and its slash
        let id = "x".repeat(40);
        let p = mkbox(&e, &id);
        let used = p.longest_socket().as_os_str().len();
        let s = spec(&e, &id);
        if used > MAX_SOCK_PATH {
            assert!(check_spec(&s, &p, &e.allowed)
                .unwrap_err()
                .contains("socket"));
        } else {
            // pad with a long boxes dir name until over the limit
            let pad = e
                .root
                .join("boxes")
                .join("p".repeat(MAX_SOCK_PATH - used + 1));
            std::fs::create_dir(&pad).unwrap();
            let allowed = Allowed {
                boxes: pad.clone(),
                ..e.allowed.clone()
            };
            let d = pad.join(&id);
            std::fs::create_dir(&d).unwrap();
            let p = BoxPaths::new(d);
            assert!(check_spec(&s, &p, &allowed).unwrap_err().contains("socket"));
        }
    }

    #[test]
    fn no_pin_env_is_debug_only() {
        let on = |k: &str| (k == "SAIIFE_TEST_NO_PIN").then(|| OsString::from("1"));
        assert_eq!(pin_check_skipped(&on), cfg!(debug_assertions));
        assert!(!pin_check_skipped(&|_| None));
    }
}
