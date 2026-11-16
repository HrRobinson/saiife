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
#[cfg(test)]
use crate::vault::parse_starttime;
use crate::vault::{self, PidRecord};

/// V7: the longest socket path a spec may produce (sun_path is 108 bytes).
pub const MAX_SOCK_PATH: usize = 100;
/// A `vm.json` larger than this is refused.
pub const MAX_SPEC_BYTES: u64 = 16 * 1024;
/// Plan 34's bounds (`crates/boxes/src/template.rs`, size validation).
const VCPUS: std::ops::RangeInclusive<u32> = 1..=saiife_boxes::template::MAX_VCPUS;
const MEM_MIB: std::ops::RangeInclusive<u64> =
    saiife_boxes::template::MIN_MEM_MIB..=saiife_boxes::template::MAX_MEM_MIB;
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
    /// The verified snapshot copy to restore from: `<vault>/<id>.snap`.
    pub restore: Option<PathBuf>,
}

/// The directories a spec's paths must lie in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    pub boxes: PathBuf,
    pub images: PathBuf,
    pub vmm: PathBuf,
    pub vault: PathBuf,
}

impl Allowed {
    pub fn for_layout(l: &Layout) -> Allowed {
        Allowed {
            boxes: l.boxes.clone(),
            images: l.images.clone(),
            vmm: l.vmm.clone(),
            vault: l.vault.clone(),
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

/// The helper's fail-closed limits on a spec it reads from the
/// VMM-writable runtime dir, whatever wrote it: a VMM always runs under
/// Landlock (R23; the driver never turns it off, in either mode), and no
/// VMM gets more vCPUs or memory than any template may ask for
/// (`saiife_boxes::template::MAX_VCPUS`, `MAX_MEM_MIB`). The daemon never
/// reads the spec back (it rebuilds it every boot); this is the second
/// line.
pub fn check_limits(spec: &LaunchSpec) -> Result<(), String> {
    use saiife_boxes::template::{MAX_MEM_MIB, MAX_VCPUS, MIN_MEM_MIB};
    if !spec.landlock {
        return Err("landlock: a box VMM always runs under Landlock".into());
    }
    if !(1..=MAX_VCPUS).contains(&spec.vcpus) {
        return Err(format!("vcpus: {} is not 1..={MAX_VCPUS}", spec.vcpus));
    }
    if !(MIN_MEM_MIB..=MAX_MEM_MIB).contains(&spec.mem_mib) {
        return Err(format!(
            "mem_mib: {} is not {MIN_MEM_MIB}..={MAX_MEM_MIB}",
            spec.mem_mib
        ));
    }
    Ok(())
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
    // CH opens these by path, following links: a VMM-planted symlink or hard
    // link would hand the next VMM another file (S4 sweep).
    let mut files = vec![
        (crate::paths::ROOT_DISK, paths.root_disk()),
        ("serial.log", paths.serial()),
    ];
    if spec.repo {
        files.push((crate::paths::REPO_DISK, paths.repo_disk()));
    }
    for (name, p) in files {
        check_plain(name, &p)?;
    }
    if let Some(src) = &spec.restore {
        // Only the verified copy in the vault, never the box's own
        // VMM-writable snapshot dir (S3).
        check_path("restore", src)?;
        check_path("allowed vault dir", &allowed.vault)?;
        if *src != allowed.vault.join(format!("{}.snap", spec.id.as_str())) {
            return Err("restore: not this box's snapshot in the vault".into());
        }
        match std::fs::symlink_metadata(src) {
            Ok(m) if m.file_type().is_dir() => {}
            _ => return Err("restore: the vault copy is not a directory".into()),
        }
    }
    let n = paths.longest_socket().as_os_str().as_bytes().len();
    if n > MAX_SOCK_PATH {
        return Err(format!(
            "dir: socket path would be {n} bytes, over {MAX_SOCK_PATH}"
        ));
    }
    Ok(())
}

/// Absent, or a regular file with one link (not a symlink, FIFO, device or
/// hard link).
pub fn check_plain(name: &str, p: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("{name}: {e}")),
        Ok(m) if m.file_type().is_file() && m.nlink() == 1 => Ok(()),
        Ok(_) => Err(format!(
            "{name}: not a plain file (a symlink, special file or hard link)"
        )),
    }
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
    if let Some(src) = &spec.restore {
        return vec![
            o("--restore"),
            arg(&[OsStr::new("source_url=file://"), src.as_os_str()]),
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

/// A fresh temporary file (0640, `O_EXCL`, random name: nothing in the
/// VMM-writable runtime dir can be planted at it) renamed over `vm.json`.
/// A `vm.json` that is not a regular file is removed first (a directory
/// would make the rename fail; unlink removes a link, not its target).
pub fn write_spec(spec: &LaunchSpec, paths: &BoxPaths) -> Result<(), String> {
    use ring::rand::SecureRandom;
    use std::io::Write;
    let body = serde_json::to_vec(spec).map_err(|e| e.to_string())?;
    let target = paths.vm_json();
    if let Ok(m) = std::fs::symlink_metadata(&target) {
        if m.is_dir() {
            std::fs::remove_dir(&target)
                .map_err(|e| format!("vm.json: a directory that cannot be removed: {e}"))?;
        } else if !m.file_type().is_file() {
            std::fs::remove_file(&target).map_err(|e| format!("vm.json: {e}"))?;
        }
    }
    let rng = ring::rand::SystemRandom::new();
    for _ in 0..8 {
        let mut b = [0u8; 8];
        rng.fill(&mut b)
            .map_err(|_| "vm.json: no randomness for a temporary name".to_string())?;
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let tmp = paths.dir.join(format!(".vm.json.{name}.tmp"));
        let mut f = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&tmp)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("vm.json: {e}")),
        };
        let r = f
            .write_all(&body)
            .and_then(|()| f.sync_all())
            .and_then(|()| std::fs::rename(&tmp, &target));
        return r.map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("vm.json: {e}")
        });
    }
    Err("vm.json: no free temporary name".into())
}

/// Reads `vm.json`: a regular file (not a symlink, no FIFO), at most 16 KiB.
pub fn read_spec(paths: &BoxPaths) -> Result<LaunchSpec, String> {
    read_spec_owned(paths, None)
}

/// [`read_spec`]; with `not_uid`, the open file must also have one link
/// and an owner other than `not_uid` (locked: the helper's own user, the
/// VMM user, never writes the spec; the daemon does), checked on the same
/// descriptor that is read, so a file swapped in is never read.
pub fn read_spec_owned(paths: &BoxPaths, not_uid: Option<u32>) -> Result<LaunchSpec, String> {
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
    if let Some(u) = not_uid {
        use std::os::unix::fs::MetadataExt;
        if m.uid() == u || m.nlink() != 1 {
            return Err(format!(
                "vm.json: owned by uid {} with {} links, not written by the daemon",
                m.uid(),
                m.nlink()
            ));
        }
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

/// What the VMM process of a box may use on the host, beyond the guest
/// RAM: Cloud Hypervisor's own heap, threads, queues and caches.
pub const VMM_OVERHEAD_MIB: u64 = 256;

/// The host's caps on a box's VMM process (locked: the unit's cgroup),
/// from the spec the daemon built: the guest RAM plus
/// [`VMM_OVERHEAD_MIB`], and one CPU per vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmmLimits {
    /// `MemoryMax=`, in bytes.
    pub memory_max: u64,
    /// `CPUQuota=` as systemd's `CPUQuotaPerSecUSec`: CPU time per second.
    pub cpu_usec_per_sec: u64,
}

impl VmmLimits {
    pub fn of(spec: &LaunchSpec) -> VmmLimits {
        VmmLimits {
            memory_max: spec.mem_mib.saturating_add(VMM_OVERHEAD_MIB) << 20,
            cpu_usec_per_sec: u64::from(spec.vcpus) * 1_000_000,
        }
    }
}

/// Starts and stops the VMM process of a box.
pub trait Launcher: Send + Sync {
    /// Caps what the next start of the box's VMM may use; called right
    /// before every `start`, which does not happen when it fails. Locked:
    /// the unit's `MemoryMax=` and `CPUQuota=`. Personal mode has no cap
    /// (the default): the VMM is a child of the daemon in the user's own
    /// session, and only the guest's size in the spec bounds it.
    fn limit(&self, _id: &BoxId, _limits: &VmmLimits) -> Result<(), String> {
        Ok(())
    }
    /// Returns once the process is started.
    fn start(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String>;
    /// The only liveness source (S3, ruling R19); never the VMM's API.
    /// `Some(false)`: alive, or cannot tell (fail closed). `Some(true)`:
    /// gone. `None`: no process of this box is known to any launcher (never
    /// started, or reaped by the launcher that started it).
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
/// unlinked and created afresh (O_EXCL); so is a hard-linked one, whose
/// other name is left alone. Used by `ChildLauncher` and by
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
            .is_ok_and(|m| m.file_type().is_file() && m.uid() == euid && m.nlink() == 1)
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

/// `<dir>/snapshot`, the path of the Landlock `rw` rule. Landlock binds a
/// rule to the inode when the VM is made, so the dir exists before the VMM
/// starts and is afterwards only emptied, never removed
/// (`snapshot::clear_dir`, `snapshot::seal`). Made 0770 by the process
/// that execs the VMM (the helper runs as the VMM user, so `seal`'s owner
/// check holds). A symlink or non-directory there is refused, never
/// followed; an existing dir must be ours. Every step is relative to the
/// box dir's fd.
pub fn ensure_snapshot_dir(paths: &BoxPaths) -> Result<(), String> {
    use rustix::fs::{Mode, OFlags, CWD};
    let bad = |e: String| format!("snapshot: {}: {e}", paths.snapshot_dir().display());
    let dir = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let boxfd = rustix::fs::openat(CWD, &paths.dir, dir, Mode::empty())
        .map_err(|e| format!("box dir: {}: {e}", paths.dir.display()))?;
    match rustix::fs::mkdirat(&boxfd, "snapshot", Mode::from_raw_mode(0o770)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(bad(e.to_string())),
    }
    let fd = rustix::fs::openat(&boxfd, "snapshot", dir, Mode::empty())
        .map_err(|e| bad(format!("not a directory ({e}); a symlink is refused")))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| bad(e.to_string()))?;
    if st.st_uid != rustix::process::geteuid().as_raw() {
        return Err(bad("not owned by the VMM user".into()));
    }
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o770)).map_err(|e| bad(e.to_string()))
}

enum Mode {
    /// `<saiife> __box-vmm <dir>`: the helper checks `vm.json`, then execs.
    Helper,
    /// `<program> <argv(read_spec)>` (tests).
    Direct,
}

enum Slot {
    /// `start` reserved the box and is spawning.
    Starting,
    Running(Child),
    /// `force_stop` has taken the child out to kill and reap it.
    Killing,
    /// Reaped; the `Child` is dropped, its status kept.
    Exited(ExitStatus),
}

/// Runs the VMM as a child process of the daemon, stdout and stderr in
/// `ch.log`. Children are reaped through `try_wait` in `exited`, and
/// `force_stop` is `Child::kill` plus `wait` of its own child only. The
/// map lock covers bookkeeping only: no blocking I/O, spawn or wait under it
/// (unlinking a pid record in the daemon-owned vault is the one file call).
/// Each child gets a `<vault>/<id>.pid` record so a restarted daemon can
/// tell whether it still runs.
///
/// No host cap (personal-mode gap): the child shares the daemon's cgroup,
/// so `Launcher::limit` is a no-op here; a compromised VMM can use more
/// memory and CPU than the box was admitted with, up to the user's own
/// limits. Locked mode caps the unit ([`UnitLauncher`]).
pub struct ChildLauncher {
    program: PathBuf,
    mode: Mode,
    vault: PathBuf,
    env: Vec<(OsString, OsString)>,
    children: Mutex<BTreeMap<BoxId, Slot>>,
    /// Serialises pid-record writes and removals (never the map lock).
    records: Mutex<()>,
    #[cfg(test)]
    pre_spawn: Option<Box<dyn Fn() + Send + Sync>>,
}

impl ChildLauncher {
    pub fn helper(saiife_bin: PathBuf, vault: PathBuf) -> ChildLauncher {
        ChildLauncher::with_mode(saiife_bin, Mode::Helper, vault)
    }

    pub fn direct(program: PathBuf, vault: PathBuf) -> ChildLauncher {
        ChildLauncher::with_mode(program, Mode::Direct, vault)
    }

    fn with_mode(program: PathBuf, mode: Mode, vault: PathBuf) -> ChildLauncher {
        ChildLauncher {
            program,
            mode,
            vault,
            env: Vec::new(),
            children: Mutex::new(BTreeMap::new()),
            records: Mutex::new(()),
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

    /// Reap a running child without blocking (waitpid WNOHANG). True when
    /// it was reaped now: the caller then calls `drop_record` after
    /// releasing the map lock.
    fn poll(slot: &mut Slot) -> bool {
        if let Slot::Running(c) = slot {
            let status = match c.try_wait() {
                Ok(Some(s)) => s,
                Ok(None) => return false,
                // not waitable any more: reaped elsewhere
                Err(_) => ExitStatus::default(),
            };
            *slot = Slot::Exited(status);
            return true;
        }
        false
    }

    /// Remove a reaped child's pid record, outside the map lock. A start
    /// that reserved the box since then keeps its own record.
    fn drop_record(&self, id: &BoxId) {
        let _r = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(self.slots().get(id), Some(Slot::Exited(_))) {
            vault::remove_pid(&self.vault, id);
        }
    }

    /// The exit status of the box's child once it has exited and been reaped.
    pub fn exit_status(&self, id: &BoxId) -> Option<ExitStatus> {
        let (reaped, st) = {
            let mut g = self.slots();
            let slot = g.get_mut(id)?;
            let reaped = Self::poll(slot);
            let st = match slot {
                Slot::Exited(s) => Some(*s),
                _ => None,
            };
            (reaped, st)
        };
        if reaped {
            self.drop_record(id);
        }
        st
    }

    fn command(&self, paths: &BoxPaths) -> Result<Command, String> {
        let mut c = Command::new(&self.program);
        match self.mode {
            Mode::Helper => {
                c.arg("__box-vmm").arg(&paths.dir);
            }
            Mode::Direct => {
                let spec = read_spec(paths)?;
                // the helper does this in Helper mode, as the VMM user
                ensure_snapshot_dir(paths)?;
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

    /// Reserve the box (`Starting`) unless a child of it is still around.
    fn reserve(&self, id: &BoxId) -> Result<(), String> {
        let mut g = self.slots();
        if let Some(slot) = g.get_mut(id) {
            Self::poll(slot);
            if !matches!(slot, Slot::Exited(_)) {
                return Err("the VMM of this box is already running".into());
            }
        }
        // (a record of a child reaped just now is replaced by `starting`)
        g.insert(id.clone(), Slot::Starting);
        Ok(())
    }

    fn spawn(&self, paths: &BoxPaths) -> Result<Child, String> {
        let mut cmd = self.command(paths)?;
        #[cfg(test)]
        if let Some(f) = &self.pre_spawn {
            f();
        }
        cmd.spawn()
            .map_err(|e| format!("cannot start {}: {e}", self.program.display()))
    }

    /// Record `{pid, starttime}`; without a record a restarted daemon could
    /// not tell the VMM runs, so a failure kills our own child.
    fn record(&self, id: &BoxId, child: &mut Child) -> Result<(), String> {
        let pid = child.id();
        let r = vault::proc_starttime(pid).and_then(|t| {
            let starttime = t.ok_or("the VMM's /proc entry is gone")?;
            let _r = self.records.lock().unwrap_or_else(|e| e.into_inner());
            vault::write_pid(&self.vault, id, PidRecord { pid, starttime })
        });
        if r.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        r.map_err(|e| format!("pid record: {e}"))
    }
}

impl Launcher for ChildLauncher {
    fn start(&self, id: &BoxId, paths: &BoxPaths) -> Result<(), String> {
        self.reserve(id)?;
        // File I/O and the spawn happen outside the map lock. A `starting`
        // record goes first, so a daemon that dies before the pid record
        // leaves a record that fails closed (L2).
        let starting = {
            let _r = self.records.lock().unwrap_or_else(|e| e.into_inner());
            vault::write_starting(&self.vault, id)
        };
        let r = starting
            .map_err(|e| format!("pid record: {e}"))
            .and_then(|()| self.spawn(paths))
            .and_then(|mut c| {
                self.record(id, &mut c)?;
                Ok(c)
            });
        match r {
            Ok(c) => {
                self.slots().insert(id.clone(), Slot::Running(c));
                Ok(())
            }
            Err(e) => {
                // nothing runs (spawn failed, or `record` killed and reaped it)
                {
                    let _r = self.records.lock().unwrap_or_else(|e| e.into_inner());
                    vault::remove_pid(&self.vault, id);
                }
                self.slots().remove(id);
                Err(e)
            }
        }
    }

    fn exited(&self, id: &BoxId) -> Option<bool> {
        let known = {
            let mut g = self.slots();
            g.get_mut(id).map(|slot| {
                let reaped = Self::poll(slot);
                (reaped, matches!(slot, Slot::Exited(_)))
            })
        };
        match known {
            Some((reaped, gone)) => {
                if reaped {
                    self.drop_record(id);
                }
                Some(gone)
            }
            // Not ours (a daemon restart): the pid record answers.
            None => vault::pid_exited(&self.vault, id),
        }
    }

    fn force_stop(&self, id: &BoxId) -> Result<(), String> {
        let (mut c, reaped) = {
            let mut g = self.slots();
            let Some(slot) = g.get_mut(id) else {
                return Err("the VMM was not started by this daemon".into());
            };
            let reaped = Self::poll(slot);
            match std::mem::replace(slot, Slot::Killing) {
                Slot::Running(c) => (c, reaped),
                Slot::Starting => {
                    *slot = Slot::Starting;
                    return Err("the VMM is being started".into());
                }
                other => {
                    // Exited: nothing to do. Killing: another caller has it.
                    *slot = other;
                    drop(g);
                    if reaped {
                        self.drop_record(id);
                    }
                    return Ok(());
                }
            }
        };
        debug_assert!(!reaped);
        // Our own child: kill(2) on its pid, then reap it, outside the lock.
        let _ = c.kill();
        let r = c.wait();
        let status = r.as_ref().map_or(ExitStatus::default(), |s| *s);
        self.slots().insert(id.clone(), Slot::Exited(status));
        self.drop_record(id);
        r.map(|_| ()).map_err(|e| format!("wait for the VMM: {e}"))
    }

    fn kind(&self) -> &'static str {
        "child"
    }
}

/// The systemd calls `UnitLauncher` needs (locked mode). Methods are sync;
/// the daemon's implementation runs each call on a short-lived thread.
pub trait UnitBus: Send + Sync {
    fn start(&self, unit: &str) -> Result<(), String>;
    /// Sets the unit's `MemoryMax=` and `CPUQuota=` for its next run
    /// (runtime properties, gone at reboot; set before every start).
    fn set_limits(&self, unit: &str, limits: &VmmLimits) -> Result<(), String>;
    fn stop(&self, unit: &str) -> Result<(), String>;
    /// `Ok(false)` only when the unit is known to have no process: `inactive`
    /// or `failed`, or not loaded at all (systemd drops inactive units).
    /// Every other state is `Ok(true)`, and anything that cannot be told (a
    /// bus error, an odd answer) is an `Err`: `UnitLauncher::exited` then
    /// says "cannot tell", and a boot is refused.
    fn active(&self, unit: &str) -> Result<bool, String>;
}

/// `saiife-box@<id>.service`; the id must be `b` and 1 to 9 digits (the
/// polkit rule allows exactly that shape, so nothing else is ever asked).
pub fn unit_name(id: &BoxId) -> Result<String, String> {
    let s = id.as_str();
    let b = s.as_bytes();
    let ok = (2..=10).contains(&b.len()) && b[0] == b'b' && b[1..].iter().all(u8::is_ascii_digit);
    if ok {
        Ok(format!("saiife-box@{s}.service"))
    } else {
        Err(format!("box id {s:?} cannot name a unit (b<digits>)"))
    }
}

/// Locked mode: the VMM runs as the systemd unit `saiife-box@<id>.service`
/// under the `saiife-box` user, started and stopped over the system bus.
pub struct UnitLauncher {
    bus: std::sync::Arc<dyn UnitBus>,
}

impl UnitLauncher {
    pub fn new(bus: std::sync::Arc<dyn UnitBus>) -> UnitLauncher {
        UnitLauncher { bus }
    }
}

impl Launcher for UnitLauncher {
    /// Fails closed: a unit whose caps could not be set is not started.
    fn limit(&self, id: &BoxId, limits: &VmmLimits) -> Result<(), String> {
        self.bus
            .set_limits(&unit_name(id)?, limits)
            .map_err(|e| format!("cannot cap the box's VMM unit: {e}"))
    }

    fn start(&self, id: &BoxId, _paths: &BoxPaths) -> Result<(), String> {
        self.bus.start(&unit_name(id)?)
    }

    /// Fails closed: a bus error is "cannot tell", never "gone".
    fn exited(&self, id: &BoxId) -> Option<bool> {
        let Ok(unit) = unit_name(id) else {
            return Some(false);
        };
        match self.bus.active(&unit) {
            Ok(true) | Err(_) => Some(false),
            Ok(false) => Some(true),
        }
    }

    fn force_stop(&self, id: &BoxId) -> Result<(), String> {
        self.bus.stop(&unit_name(id)?)
    }

    fn kind(&self) -> &'static str {
        "unit"
    }
}

/// A `UnitBus` that records its calls as `"start <unit>"` lines (tests).
#[cfg(any(test, feature = "fake"))]
pub struct FakeUnitBus {
    pub calls: Mutex<Vec<String>>,
    /// What `active` answers.
    pub active: Mutex<Result<bool, String>>,
    /// What `set_limits` answers.
    pub limits: Mutex<Result<(), String>>,
}

#[cfg(any(test, feature = "fake"))]
impl FakeUnitBus {
    pub fn new() -> FakeUnitBus {
        FakeUnitBus {
            calls: Mutex::new(Vec::new()),
            active: Mutex::new(Ok(false)),
            limits: Mutex::new(Ok(())),
        }
    }

    fn record(&self, verb: &str, unit: &str) {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{verb} {unit}"));
    }
}

#[cfg(any(test, feature = "fake"))]
impl Default for FakeUnitBus {
    fn default() -> Self {
        FakeUnitBus::new()
    }
}

#[cfg(any(test, feature = "fake"))]
impl UnitBus for FakeUnitBus {
    fn start(&self, unit: &str) -> Result<(), String> {
        self.record("start", unit);
        Ok(())
    }
    fn set_limits(&self, unit: &str, limits: &VmmLimits) -> Result<(), String> {
        let l = format!("{unit} {} {}", limits.memory_max, limits.cpu_usec_per_sec);
        self.record("limit", &l);
        self.limits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    fn stop(&self, unit: &str) -> Result<(), String> {
        self.record("stop", unit);
        Ok(())
    }
    fn active(&self, unit: &str) -> Result<bool, String> {
        self.record("active", unit);
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn unit_name_rules() {
        let id = |s: &str| BoxId::parse(s).unwrap();
        assert_eq!(
            unit_name(&id("b3")).unwrap(),
            "saiife-box@b3.service".to_string()
        );
        assert_eq!(
            unit_name(&id("b123456789")).unwrap(),
            "saiife-box@b123456789.service"
        );
        for bad in ["b", "x1", "b1234567890", "b1-2", "b1x", "1b"] {
            assert!(unit_name(&id(bad)).is_err(), "{bad}");
        }
        // Not even a box id: never reaches a unit name.
        assert!(BoxId::parse("b1/../x").is_err());
    }

    /// The runtime dir is VMM-writable: a directory, FIFO or symlink at
    /// `vm.json`, or a planted `vm.json.tmp`, never stops the daemon's
    /// write, and a link's target is never written.
    #[test]
    fn write_spec_replaces_whatever_the_vmm_left() {
        use std::os::unix::fs::FileTypeExt;
        let e = env();
        let s = spec(&e, "b1");
        let paths = BoxPaths::new(e.root.join("boxes/b1"));
        std::fs::create_dir_all(&paths.dir).unwrap();
        let victim = e.root.join("elsewhere/victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, paths.dir.join("vm.json.tmp")).unwrap();
        for plant in ["dir", "fifo", "link"] {
            let p = paths.vm_json();
            let _ = std::fs::remove_file(&p);
            match plant {
                "dir" => std::fs::create_dir(&p).unwrap(),
                "fifo" => rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &p,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap(),
                _ => std::os::unix::fs::symlink(&victim, &p).unwrap(),
            }
            write_spec(&s, &paths).unwrap();
            let m = std::fs::symlink_metadata(&p).unwrap();
            assert!(
                m.file_type().is_file() && !m.file_type().is_fifo(),
                "{plant}"
            );
            assert_eq!(read_spec(&paths).unwrap(), s, "{plant}");
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        // only vm.json and the planted link: no temporary file is left
        let mut names: Vec<String> = std::fs::read_dir(&paths.dir)
            .unwrap()
            .map(|d| d.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["vm.json", "vm.json.tmp"]);
    }

    /// Locked: the unit is capped at the spec's RAM plus the VMM's
    /// overhead and one CPU per vCPU; a bus error fails closed.
    #[test]
    fn unit_launcher_caps_the_unit_from_the_spec() {
        let e = env();
        let bus = std::sync::Arc::new(FakeUnitBus::new());
        let l = UnitLauncher::new(bus.clone());
        let id = BoxId::parse("b7").unwrap();
        let s = LaunchSpec {
            vcpus: 3,
            mem_mib: 2048,
            ..spec(&e, "b7")
        };
        let lim = VmmLimits::of(&s);
        assert_eq!(lim.memory_max, (2048 + VMM_OVERHEAD_MIB) << 20);
        assert_eq!(lim.cpu_usec_per_sec, 3_000_000);
        l.limit(&id, &lim).unwrap();
        assert_eq!(
            bus.calls.lock().unwrap().clone(),
            [format!(
                "limit saiife-box@b7.service {} 3000000",
                (2048 + VMM_OVERHEAD_MIB) << 20
            )]
        );
        *bus.limits.lock().unwrap() = Err("denied".into());
        let err = l.limit(&id, &lim).unwrap_err();
        assert!(err.contains("cap") && err.contains("denied"), "{err}");
        // a bad id never reaches the bus
        assert!(l.limit(&BoxId::parse("x1").unwrap(), &lim).is_err());
        assert_eq!(bus.calls.lock().unwrap().len(), 2);
        // personal: no cap, nothing refused
        let c = ChildLauncher::helper(PathBuf::from("/x"), e.root.join("vault"));
        assert_eq!(c.limit(&id, &lim), Ok(()));
    }

    #[test]
    fn unit_launcher_calls_the_bus() {
        let bus = std::sync::Arc::new(FakeUnitBus::new());
        let l = UnitLauncher::new(bus.clone());
        let id = BoxId::parse("b7").unwrap();
        let paths = BoxPaths::new(PathBuf::from("/x/boxes/b7"));
        assert_eq!(l.kind(), "unit");
        l.start(&id, &paths).unwrap();
        l.force_stop(&id).unwrap();
        // inactive: gone; active: alive; bus error: alive (fail closed)
        assert_eq!(l.exited(&id), Some(true));
        *bus.active.lock().unwrap() = Ok(true);
        assert_eq!(l.exited(&id), Some(false));
        *bus.active.lock().unwrap() = Err("no bus".into());
        assert_eq!(l.exited(&id), Some(false));
        assert_eq!(
            bus.calls.lock().unwrap().clone(),
            [
                "start saiife-box@b7.service",
                "stop saiife-box@b7.service",
                "active saiife-box@b7.service",
                "active saiife-box@b7.service",
                "active saiife-box@b7.service",
            ]
        );
        // A bad id never reaches the bus.
        let bad = BoxId::parse("x1").unwrap();
        assert!(l.start(&bad, &paths).is_err());
        assert!(l.force_stop(&bad).is_err());
        assert_eq!(l.exited(&bad), Some(false));
        assert_eq!(bus.calls.lock().unwrap().len(), 5);
    }

    struct Env {
        _t: tempfile::TempDir,
        root: PathBuf,
        allowed: Allowed,
    }

    fn env() -> Env {
        let base =
            std::env::var_os("SAIIFE_TEST_TMP").map_or_else(std::env::temp_dir, PathBuf::from);
        let t = tempfile::tempdir_in(base).unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        for d in ["boxes", "images", "vmm", "vault", "elsewhere"] {
            std::fs::create_dir(root.join(d)).unwrap();
        }
        std::fs::write(root.join("images/base.qcow2"), b"x").unwrap();
        std::fs::write(root.join("vmm/CLOUDHV.fd"), b"x").unwrap();
        let allowed = Allowed {
            boxes: root.join("boxes"),
            images: root.join("images"),
            vmm: root.join("vmm"),
            vault: root.join("vault"),
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
            restore: None,
        }
    }

    /// The helper's fail-closed limits (a tampered spec, even if the
    /// daemon's rebuild regressed): Landlock on when locked, sizes within
    /// the template ceilings.
    #[test]
    fn limits_refuse_landlock_off_and_oversize() {
        let e = env();
        let ok = spec(&e, "b1");
        assert_eq!(check_limits(&ok), Ok(()));
        let off = LaunchSpec {
            landlock: false,
            ..ok.clone()
        };
        // in both modes: the driver always runs the VMM under Landlock (R23)
        assert!(check_limits(&off).unwrap_err().contains("landlock"));
        for (vcpus, mem_mib) in [(33, 4096), (0, 4096), (2, 262_145), (2, 511)] {
            let big = LaunchSpec {
                vcpus,
                mem_mib,
                ..ok.clone()
            };
            assert!(check_limits(&big).is_err(), "{vcpus} {mem_mib}");
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
            restore: None,
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
        s.restore = Some(PathBuf::from("/vault/b1.snap"));
        assert_eq!(
            strs(argv(&s, &p)),
            [
                "--restore",
                "source_url=file:///vault/b1.snap",
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
    fn a_starting_record_comes_before_the_spawn() {
        use std::sync::Arc;
        let e = env();
        let p = mkbox(&e, "b1");
        let vault = e.root.join("vault");
        let seen = Arc::new(Mutex::new(String::new()));
        let mut l = ChildLauncher::helper(PathBuf::from("/usr/bin/true"), vault.clone());
        let (s2, rec) = (Arc::clone(&seen), vault.join("b1.pid"));
        l.pre_spawn = Some(Box::new(move || {
            *s2.lock().unwrap() = std::fs::read_to_string(&rec).unwrap_or_default();
        }));
        let id = BoxId::parse("b1").unwrap();
        l.start(&id, &p).unwrap();
        assert!(
            seen.lock().unwrap().contains("starting"),
            "{}",
            seen.lock().unwrap()
        );
        let after = std::fs::read_to_string(vault.join("b1.pid")).unwrap_or_default();
        assert!(after.is_empty() || after.contains("\"pid\""), "{after}");
        let _ = l.force_stop(&id);
    }

    #[test]
    fn disks_and_serial_must_be_plain_files() {
        let e = env();
        let p = mkbox(&e, "b1");
        let s = spec(&e, "b1");
        let outside = e.root.join("elsewhere/f");
        std::fs::write(&outside, b"x").unwrap();
        // missing files are CH's business; present ones must be plain
        check_spec(&s, &p, &e.allowed).unwrap();
        std::os::unix::fs::symlink(&outside, p.root_disk()).unwrap();
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .contains("root.qcow2"));
        std::fs::remove_file(p.root_disk()).unwrap();
        std::fs::write(p.root_disk(), b"q").unwrap();
        std::fs::hard_link(&outside, p.repo_disk()).unwrap();
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .contains("repo.img"));
        std::fs::remove_file(p.repo_disk()).unwrap();
        std::os::unix::fs::symlink(&outside, p.serial()).unwrap();
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .contains("serial.log"));
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
        let mut l = ChildLauncher::helper(PathBuf::from("/usr/bin/true"), e.root.join("vault"));
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
    fn restore_must_be_the_vault_copy() {
        let e = env();
        let p = mkbox(&e, "b1");
        let mut s = spec(&e, "b1");
        let snap = e.root.join("vault/b1.snap");
        std::fs::create_dir(&snap).unwrap();
        s.restore = Some(snap.clone());
        check_spec(&s, &p, &e.allowed).unwrap();
        for bad in [
            p.snapshot_dir(),
            e.root.join("vault/b2.snap"),
            e.root.join("vault/../vault/b1.snap"),
            e.root.join("vault/b1.snap,x=y"),
            PathBuf::from("vault/b1.snap"),
        ] {
            s.restore = Some(bad.clone());
            let err = check_spec(&s, &p, &e.allowed).unwrap_err();
            assert!(err.starts_with("restore:"), "{bad:?}: {err}");
        }
        // a symlink at the vault path is not the copy
        std::fs::remove_dir(&snap).unwrap();
        std::os::unix::fs::symlink(e.root.join("elsewhere"), &snap).unwrap();
        s.restore = Some(snap);
        assert!(check_spec(&s, &p, &e.allowed)
            .unwrap_err()
            .starts_with("restore:"));
    }

    #[test]
    fn proc_starttime_skips_the_comm_field() {
        let stat = "1234 (a) b) c (d) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20 21";
        assert_eq!(parse_starttime(stat), Some(987654));
        assert_eq!(parse_starttime("1234 (x"), None);
        assert_eq!(parse_starttime("1234 (x) S 1 2"), None);
    }

    #[test]
    fn no_pin_env_is_debug_only() {
        let on = |k: &str| (k == "SAIIFE_TEST_NO_PIN").then(|| OsString::from("1"));
        assert_eq!(pin_check_skipped(&on), cfg!(debug_assertions));
        assert!(!pin_check_skipped(&|_| None));
    }

    /// A ch.log hard-linked to a file elsewhere is replaced, never appended
    /// to: the other name keeps its bytes.
    #[test]
    fn hard_linked_ch_log_is_replaced() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        let e = env();
        let p = mkbox(&e, "b1");
        let other = e.root.join("elsewhere/kept");
        std::fs::write(&other, b"keep").unwrap();
        std::fs::hard_link(&other, p.ch_log()).unwrap();
        let mut f = open_ch_log(&p.ch_log()).unwrap();
        f.write_all(b"log").unwrap();
        assert_eq!(std::fs::read(&other).unwrap(), b"keep");
        assert_eq!(std::fs::metadata(&other).unwrap().nlink(), 1);
        assert_eq!(std::fs::read(p.ch_log()).unwrap(), b"log");
    }

    /// The snapshot dir the Landlock rule names is made before the VMM
    /// starts (0770, ours), kept when it is there, and refused when it is a
    /// symlink or not a directory.
    #[test]
    fn snapshot_dir_is_made_kept_or_refused() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let e = env();
        let p = mkbox(&e, "b1");
        let d = p.snapshot_dir();
        ensure_snapshot_dir(&p).unwrap();
        let m = std::fs::symlink_metadata(&d).unwrap();
        assert!(m.file_type().is_dir());
        assert_eq!(m.mode() & 0o7777, 0o770);
        assert_eq!(m.uid(), rustix::process::geteuid().as_raw());
        std::fs::write(d.join("x"), b"x").unwrap();
        ensure_snapshot_dir(&p).unwrap();
        assert_eq!(std::fs::symlink_metadata(&d).unwrap().ino(), m.ino());
        std::fs::remove_file(d.join("x")).unwrap();
        std::fs::remove_dir(&d).unwrap();
        let target = e.root.join("elsewhere");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, &d).unwrap();
        assert!(ensure_snapshot_dir(&p).unwrap_err().contains("snapshot"));
        // the target's mode is untouched (nothing is chmodded through a link)
        assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o7777, 0o700);
        std::fs::remove_file(&d).unwrap();
        std::fs::write(&d, b"x").unwrap();
        assert!(ensure_snapshot_dir(&p).unwrap_err().contains("snapshot"));
    }
}
