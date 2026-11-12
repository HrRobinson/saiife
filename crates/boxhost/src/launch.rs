//! The launch spec (`vm.json`), its argv for Cloud Hypervisor, and the checks
//! `saiife __box-vmm` makes before it execs (V7, V8, V9; Review Focus 1-2).
//! Ported from the spike's `ch_boot` and `ch_restore`.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;

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

/// Starts and stops the VMM process of a box.
pub trait Launcher: Send + Sync {
    /// Returns once the process is started.
    fn start(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String>;
    /// `None`: not started by this launcher (e.g. after a daemon restart).
    fn exited(&self, id: &BoxId) -> Option<bool>;
    /// Ends the process; Ok when it already exited.
    fn force_stop(&self, id: &BoxId) -> Result<(), String>;
    /// "child" | "unit"
    fn kind(&self) -> &'static str;
}

/// Opens `ch.log` for the VMM's stdout and stderr. The box dir is VMM
/// writable, so the path may be anything: a symlink is refused (O_NOFOLLOW;
/// the target is never touched), a FIFO or other non-regular file never
/// blocks the open (O_NONBLOCK) and, like a file owned by someone else, is
/// unlinked and created afresh (O_EXCL). Used by `ChildLauncher` and by
/// `saiife __box-vmm`.
pub fn open_ch_log(p: &Path) -> Result<std::fs::File, String> {
    use rustix::fs::OFlags;
    use std::os::unix::fs::MetadataExt;
    let err = |e: std::io::Error| format!("ch.log: {}: {e}", p.display());
    let base = (OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC).bits() as i32;
    let open = |excl: bool| {
        let mut o = std::fs::OpenOptions::new();
        o.append(true).mode(0o640).custom_flags(base);
        if excl {
            o.create_new(true);
        } else {
            o.create(true);
        }
        o.open(p)
    };
    let euid = rustix::process::geteuid().as_raw();
    let ours = |f: &std::fs::File| {
        f.metadata()
            .is_ok_and(|m| m.file_type().is_file() && m.uid() == euid)
    };
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(format!("ch.log: {} is a symlink", p.display()))
        }
        Ok(m) if m.file_type().is_file() => {
            // A path swapped since (ELOOP for a symlink, ENXIO for a FIFO
            // without a reader) falls through to the replace path below.
            if let Ok(f) = open(false) {
                if ours(&f) {
                    return Ok(f);
                }
            }
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(err(e)),
    }
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(format!("ch.log: {} is a symlink", p.display()))
        }
        Ok(_) => std::fs::remove_file(p).map_err(err)?,
        Err(_) => {}
    }
    let f = open(true).map_err(err)?;
    if !ours(&f) {
        return Err(format!(
            "ch.log: {} is not a regular file of ours",
            p.display()
        ));
    }
    Ok(f)
}

enum Mode {
    /// `<saiife> __box-vmm <dir>`: the helper checks `vm.json`, then execs.
    Helper,
    /// `<program> <argv(read_spec)>` (tests).
    Direct,
}

enum Slot {
    Running(Child),
    /// `force_stop` has taken the child out to kill and reap it.
    Killing,
    /// Reaped; the `Child` is dropped, its status kept.
    Exited(ExitStatus),
}

/// Runs the VMM as a child process of the daemon, stdout and stderr in
/// `ch.log`. Children are reaped through `try_wait` in `exited`, and
/// `force_stop` is `Child::kill` plus `wait` of its own child only. The
/// map lock covers bookkeeping only: no file I/O, spawn or wait under it.
pub struct ChildLauncher {
    program: PathBuf,
    mode: Mode,
    env: Vec<(OsString, OsString)>,
    children: Mutex<BTreeMap<BoxId, Slot>>,
    #[cfg(test)]
    pre_spawn: Option<Box<dyn Fn() + Send + Sync>>,
}

impl ChildLauncher {
    pub fn helper(saiife_bin: PathBuf) -> ChildLauncher {
        ChildLauncher::with_mode(saiife_bin, Mode::Helper)
    }

    pub fn direct(program: PathBuf) -> ChildLauncher {
        ChildLauncher::with_mode(program, Mode::Direct)
    }

    fn with_mode(program: PathBuf, mode: Mode) -> ChildLauncher {
        ChildLauncher {
            program,
            mode,
            env: Vec::new(),
            children: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            pre_spawn: None,
        }
    }

    /// An extra environment variable for every child (tests' fake knobs).
    pub fn env(mut self, k: impl Into<OsString>, v: impl Into<OsString>) -> ChildLauncher {
        self.env.push((k.into(), v.into()));
        self
    }

    fn slots(&self) -> std::sync::MutexGuard<'_, BTreeMap<BoxId, Slot>> {
        self.children.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reap a running child without blocking (waitpid WNOHANG).
    fn poll(slot: &mut Slot) {
        if let Slot::Running(c) = slot {
            match c.try_wait() {
                Ok(Some(s)) => *slot = Slot::Exited(s),
                Ok(None) => {}
                // not waitable any more: reaped elsewhere
                Err(_) => *slot = Slot::Exited(ExitStatus::default()),
            }
        }
    }

    /// The exit status of the box's child once it has exited and been reaped.
    pub fn exit_status(&self, id: &BoxId) -> Option<ExitStatus> {
        let mut g = self.slots();
        let slot = g.get_mut(id)?;
        Self::poll(slot);
        match slot {
            Slot::Exited(s) => Some(*s),
            _ => None,
        }
    }

    fn command(&self, paths: &BoxPaths) -> Result<Command, String> {
        let mut c = Command::new(&self.program);
        match self.mode {
            Mode::Helper => {
                c.arg("__box-vmm").arg(&paths.dir);
            }
            Mode::Direct => {
                let spec = read_spec(paths)?;
                c.args(argv(&spec, paths));
            }
        }
        let log = open_ch_log(&paths.ch_log())?;
        let log2 = log.try_clone().map_err(|e| format!("ch.log: {e}"))?;
        c.envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log2);
        Ok(c)
    }

    fn busy(&self, id: &BoxId) -> bool {
        let mut g = self.slots();
        match g.get_mut(id) {
            Some(slot) => {
                Self::poll(slot);
                !matches!(slot, Slot::Exited(_))
            }
            None => false,
        }
    }
}

impl Launcher for ChildLauncher {
    fn start(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String> {
        const RUNNING: &str = "the VMM of this box is already running";
        if self.busy(id) {
            return Err(RUNNING.into());
        }
        // File I/O and the spawn happen outside the lock.
        let mut cmd = self.command(paths)?;
        #[cfg(test)]
        if let Some(f) = &self.pre_spawn {
            f();
        }
        if self.busy(id) {
            return Err(RUNNING.into());
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("cannot start {}: {e}", self.program.display()))?;
        self.slots().insert(id.clone(), Slot::Running(child));
        Ok(())
    }

    fn exited(&self, id: &BoxId) -> Option<bool> {
        let mut g = self.slots();
        let slot = g.get_mut(id)?;
        Self::poll(slot);
        Some(matches!(slot, Slot::Exited(_)))
    }

    fn force_stop(&self, id: &BoxId) -> Result<(), String> {
        let mut c = {
            let mut g = self.slots();
            let Some(slot) = g.get_mut(id) else {
                return Err("the VMM was not started by this daemon".into());
            };
            Self::poll(slot);
            match std::mem::replace(slot, Slot::Killing) {
                Slot::Running(c) => c,
                other => {
                    // Exited: nothing to do. Killing: another caller has it.
                    *slot = other;
                    return Ok(());
                }
            }
        };
        // Our own child: kill(2) on its pid, then reap it, outside the lock.
        let _ = c.kill();
        let r = c.wait();
        let status = r.as_ref().map_or(ExitStatus::default(), |s| *s);
        self.slots().insert(id.clone(), Slot::Exited(status));
        r.map(|_| ()).map_err(|e| format!("wait for the VMM: {e}"))
    }

    fn kind(&self) -> &'static str {
        "child"
    }
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
    fn start_does_its_io_outside_the_lock() {
        use std::sync::{mpsc, Arc};
        use std::time::{Duration, Instant};
        let e = env();
        let p1 = mkbox(&e, "b1");
        let _p2 = mkbox(&e, "b2");
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let go_rx = Mutex::new(go_rx);
        let mut l = ChildLauncher::helper(PathBuf::from("/usr/bin/true"));
        l.pre_spawn = Some(Box::new(move || {
            let _ = go_rx.lock().unwrap().recv_timeout(Duration::from_secs(5));
        }));
        let l = Arc::new(l);
        let id1 = BoxId::parse("b1").unwrap();
        let id2 = BoxId::parse("b2").unwrap();
        let (l2, i2) = (Arc::clone(&l), id1.clone());
        let t = std::thread::spawn(move || l2.start(&i2, &p1));
        std::thread::sleep(Duration::from_millis(100));
        let t0 = Instant::now();
        assert_eq!(l.exited(&id2), None);
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "exited waited on start"
        );
        go_tx.send(()).unwrap();
        t.join().unwrap().unwrap();
        let t0 = Instant::now();
        while l.exited(&id1) != Some(true) && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(l.exited(&id1), Some(true));
        assert!(l.exit_status(&id1).unwrap().success());
        l.force_stop(&id1).unwrap();
    }

    #[test]
    fn no_pin_env_is_debug_only() {
        let on = |k: &str| (k == "SAIIFE_TEST_NO_PIN").then(|| OsString::from("1"));
        assert_eq!(pin_check_skipped(&on), cfg!(debug_assertions));
        assert!(!pin_check_skipped(&|_| None));
    }
}
