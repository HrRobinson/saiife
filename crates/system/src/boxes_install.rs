//! `saiife system install --boxes` (plan 35, Task 6): the `saiife-box` user
//! and group, the box state dirs, the pinned VMM, the `saiife-box@` template
//! unit and the narrow polkit rule that lets the daemon start and stop
//! exactly those units. Everything acts through [`Host`] on paths from the
//! [`Layout`], so tests run on a fake root; nothing here runs `systemctl`
//! except through [`Host::systemctl`].

use crate::fsops;
use crate::host::Host;
use crate::install::{refused, step, InstallError};
use crate::layout::{Layout, Platform, OPT_DIR};
use crate::polkit::POLKIT_RULES_DIRS;
use saiife_policy::installed::{FileKind, Installed};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const BOX_USER: &str = "saiife-box";
pub const BOX_GROUP: &str = "saiife-box";
pub const KVM_GROUP: &str = "kvm";

pub const BOX_STATE_DIR: &str = "/var/lib/saiife-box";
pub const BOXES_DIR: &str = "/var/lib/saiife-box/boxes";
pub const IMAGES_DIR: &str = "/var/lib/saiife-box/images";
pub const VAULT_DIR: &str = "/var/lib/saiife-box/vault";
pub const VMM_DIR: &str = "/opt/saiife/vmm";
pub const VMM_CH: &str = "/opt/saiife/vmm/cloud-hypervisor";
pub const VMM_FW: &str = "/opt/saiife/vmm/CLOUDHV.fd";
pub const BOX_UNIT_PATH: &str = "/etc/systemd/system/saiife-box@.service";
pub const POLKIT_RULE_NAME: &str = "49-saiife-box.rules";

/// `/var/lib/saiife-box`: root:saiife-box. The VMM user cannot rename
/// entries in it (R26).
pub const MODE_STATE: u32 = 0o750;
/// `boxes/`: saiife:saiife-box, sticky and setgid: the VMM user cannot
/// rename or unlink the daemon-owned box dirs (R26).
pub const MODE_BOXES: u32 = 0o3770;
/// `images/` and `vault/`: saiife:saiife-box; the VMM reads, never writes.
pub const MODE_RO: u32 = 0o2750;

/// The template unit (`/etc/systemd/system/saiife-box@.service`).
pub const BOX_UNIT: &str = "\
[Unit]
Description=saiife box %i (Cloud Hypervisor)
[Service]
Type=exec
User=saiife-box
Group=saiife-box
SupplementaryGroups=kvm
ExecStart=/opt/saiife/bin/saiife __box-vmm /var/lib/saiife-box/boxes/%i --locked
UMask=0007
NoNewPrivileges=yes
DevicePolicy=closed
DeviceAllow=/dev/kvm rw
PrivateNetwork=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/saiife-box/boxes/%i
ReadOnlyPaths=/var/lib/saiife-box/images /var/lib/saiife-box/vault /opt/saiife/vmm
TimeoutStopSec=30
KillMode=control-group
Restart=no
";

/// The polkit rule: the daemon user may start and stop `saiife-box@b<N>`
/// units, nothing else.
pub const POLKIT_RULE: &str = r#"polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.systemd1.manage-units" && subject.user == "saiife") {
    var unit = action.lookup("unit"), verb = action.lookup("verb");
    if (/^saiife-box@b[0-9]{1,9}\.service$/.test(unit) && (verb == "start" || verb == "stop")) {
      return polkit.Result.YES;
    }
  }
});
"#;

/// The pinned VMM files: where they come from and what they must hash to.
#[derive(Debug, Clone, Copy)]
pub struct VmmPins {
    pub ch_url: &'static str,
    pub ch_sha256: &'static str,
    pub fw_url: &'static str,
    pub fw_sha256: &'static str,
}

impl VmmPins {
    /// The spike's pins.
    pub fn pinned() -> VmmPins {
        use saiife_boxhost::pins;
        VmmPins {
            ch_url: pins::CH_URL,
            ch_sha256: pins::CH_SHA256,
            fw_url: pins::FW_URL,
            fw_sha256: pins::FW_SHA256,
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Test builds of this crate only: pins for fake VMM files.
    pub(crate) static TEST_PINS: std::cell::Cell<Option<VmmPins>> =
        const { std::cell::Cell::new(None) };
}

/// The pins `system install --boxes` checks the VMM against: always the
/// spike's, except in this crate's own tests.
pub(crate) fn vmm_pins() -> VmmPins {
    #[cfg(test)]
    if let Some(p) = TEST_PINS.with(|c| c.get()) {
        return p;
    }
    VmmPins::pinned()
}

/// A file `--boxes` wrote, for `installed.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoxFile {
    pub path: PathBuf,
    pub kind: FileKind,
    pub sha256: Option<String>,
    pub created: bool,
}

/// What `--boxes` created, filled as it goes so a failure part-way still
/// leaves an accurate list for uninstall.
#[derive(Debug, Default)]
pub(crate) struct Created {
    pub users: Vec<String>,
    pub groups: Vec<String>,
    /// (user, group), only those this run added.
    pub memberships: Vec<(String, String)>,
    pub files: Vec<BoxFile>,
    pub changed: Vec<String>,
}

/// True when `rec` says `--boxes` was installed.
pub(crate) fn recorded(rec: &Installed) -> bool {
    rec.files
        .iter()
        .any(|f| f.kind == FileKind::Unit && f.path == Path::new(BOX_UNIT_PATH))
}

/// The polkit rule's logical path (the first rules dir).
pub fn polkit_rule_path() -> String {
    format!("{}/{POLKIT_RULE_NAME}", POLKIT_RULES_DIRS[0])
}

const MAX_VMM_FILE: u64 = 256 * 1024 * 1024;

/// The `--boxes` part of a locked install, after the v2 steps. `vmm_dir`
/// holds `cloud-hypervisor` and `CLOUDHV.fd` to copy (verified against the
/// pins); without it they are downloaded.
pub fn install_boxes(
    layout: &Layout,
    host: &dyn Host,
    daemon_user: &str,
    vmm_dir: Option<&Path>,
) -> Result<(), InstallError> {
    install_boxes_with(
        layout,
        host,
        daemon_user,
        vmm_dir,
        &VmmPins::pinned(),
        &mut Created::default(),
    )
}

fn read_checked(dir: &Path, name: &str, want: &str) -> Result<Vec<u8>, InstallError> {
    let p = dir.join(name);
    let bad = |d: String| refused(&p, d);
    let f = std::fs::File::open(&p).map_err(|e| bad(e.to_string()))?;
    let m = f.metadata().map_err(|e| bad(e.to_string()))?;
    if !m.is_file() {
        return Err(bad("is not a regular file".into()));
    }
    let mut bytes = Vec::new();
    f.take(MAX_VMM_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| bad(e.to_string()))?;
    if bytes.len() as u64 > MAX_VMM_FILE {
        return Err(bad(format!("is larger than {MAX_VMM_FILE} bytes")));
    }
    let got = fsops::sha256_hex(&bytes);
    if got != want {
        return Err(bad(format!(
            "sha256 {got} is not the pinned {want}; the VMM is not installed"
        )));
    }
    Ok(bytes)
}

pub(crate) fn install_boxes_with(
    layout: &Layout,
    host: &dyn Host,
    daemon_user: &str,
    vmm_dir: Option<&Path>,
    pins: &VmmPins,
    created: &mut Created,
) -> Result<(), InstallError> {
    if layout.platform() != Platform::Linux {
        return Err(InstallError::Unsupported(
            "boxes (--boxes) are for Linux only".into(),
        ));
    }
    if layout.is_system() && host.euid() != 0 {
        return Err(InstallError::NotRoot);
    }
    // 1. Refusals before the first change: the VMM bytes checked are the
    // bytes copied; polkit and kvm must be there; the daemon user exists.
    let vmm_bytes = match vmm_dir {
        Some(d) => Some((
            read_checked(d, "cloud-hypervisor", pins.ch_sha256)?,
            read_checked(d, "CLOUDHV.fd", pins.fw_sha256)?,
        )),
        None => None,
    };
    let rules_dir = layout.at(POLKIT_RULES_DIRS[0]);
    match fsops::lstat(&rules_dir).map_err(|e| refused(&rules_dir, e.to_string()))? {
        Some(m) if m.is_dir() => {}
        _ => {
            return Err(refused(
                &rules_dir,
                "polkit is not installed (no rules.d); boxes need it to start and stop units",
            ))
        }
    }
    if host.group_id(KVM_GROUP).is_none() {
        return Err(refused(
            &layout.at("/dev"),
            "no group kvm: this host has no KVM access group for boxes",
        ));
    }
    let daemon_uid = host
        .user(daemon_user)
        .map(|u| u.uid)
        .ok_or_else(|| refused(&layout.at("/etc/passwd"), format!("no user {daemon_user}")))?;
    let root_uid = host
        .user("root")
        .map(|u| u.uid)
        .ok_or_else(|| refused(&layout.at("/etc/passwd"), "no user root"))?;
    let root_gid = host
        .group_id("root")
        .ok_or_else(|| refused(&layout.at("/etc/group"), "no group root"))?;

    // 2. The group, the user, the memberships.
    if host.group_id(BOX_GROUP).is_none() {
        host.create_system_group(BOX_GROUP).map_err(step("users"))?;
        created.groups.push(BOX_GROUP.into());
        created.changed.push(format!("group {BOX_GROUP}"));
    }
    let box_gid = host
        .group_id(BOX_GROUP)
        .ok_or_else(|| refused(&layout.at("/etc/group"), "group saiife-box did not appear"))?;
    match host.user(BOX_USER) {
        None => {
            host.create_system_user(BOX_USER, BOX_GROUP)
                .map_err(step("users"))?;
            created.users.push(BOX_USER.into());
            created.changed.push(format!("user {BOX_USER}"));
        }
        Some(u) if u.gid != box_gid => {
            return Err(refused(
                &layout.at("/etc/passwd"),
                format!(
                    "a user {BOX_USER} exists with another primary group; saiife does not adopt it"
                ),
            ))
        }
        Some(_) => {}
    }
    for (user, group) in [(BOX_USER, KVM_GROUP), (daemon_user, BOX_GROUP)] {
        let member = host
            .group_members(group)
            .is_some_and(|m| m.iter().any(|u| u == user));
        if !member {
            created.memberships.push((user.into(), group.into()));
            host.add_to_group(user, group).map_err(step("users"))?;
            created.changed.push(format!("{user} in group {group}"));
        }
    }

    // 3. The state dirs (R26 modes).
    ensure_dir(
        layout,
        host,
        BOX_STATE_DIR,
        MODE_STATE,
        (root_uid, box_gid),
        created,
    )?;
    for (abs, mode) in [
        (BOXES_DIR, MODE_BOXES),
        (IMAGES_DIR, MODE_RO),
        (VAULT_DIR, MODE_RO),
    ] {
        ensure_dir(layout, host, abs, mode, (daemon_uid, box_gid), created)?;
    }

    // 4. The VMM.
    ensure_dir(layout, host, OPT_DIR, 0o755, (root_uid, root_gid), created)?;
    ensure_dir(layout, host, VMM_DIR, 0o755, (root_uid, root_gid), created)?;
    let (ch, fw) = (layout.at(VMM_CH), layout.at(VMM_FW));
    match vmm_bytes {
        Some((chb, fwb)) => {
            put(host, &ch, &chb, 0o755, (root_uid, root_gid), "vmm", created)?;
            put(host, &fw, &fwb, 0o644, (root_uid, root_gid), "vmm", created)?;
        }
        None => {
            let tools = saiife_boxhost::tools::Tools::system(&layout.at(VMM_DIR));
            for (url, want, dest, mode) in [
                (pins.ch_url, pins.ch_sha256, &ch, 0o755),
                (pins.fw_url, pins.fw_sha256, &fw, 0o644),
            ] {
                saiife_boxhost::pins::fetch(&tools, url, want, dest, mode).map_err(|e| {
                    InstallError::Step {
                        step: "vmm".into(),
                        detail: e,
                    }
                })?;
                host.chown(dest, root_uid, root_gid).map_err(step("vmm"))?;
                created.changed.push(dest.display().to_string());
            }
        }
    }

    // 5. The unit and the polkit rule, recorded for uninstall.
    let unit_dir = Path::new(BOX_UNIT_PATH)
        .parent()
        .and_then(Path::to_str)
        .unwrap_or("/");
    ensure_dir(layout, host, unit_dir, 0o755, (root_uid, root_gid), created)?;
    let unit_path = layout.at(BOX_UNIT_PATH);
    let unit_new = fsops::lstat(&unit_path)
        .map_err(|e| refused(&unit_path, e.to_string()))?
        .is_none();
    let rule_logical = polkit_rule_path();
    let rule_path = layout.at(&rule_logical);
    let rule_new = fsops::lstat(&rule_path)
        .map_err(|e| refused(&rule_path, e.to_string()))?
        .is_none();
    for (logical, path, text, kind, is_new, name) in [
        (
            BOX_UNIT_PATH,
            &unit_path,
            BOX_UNIT,
            FileKind::Unit,
            unit_new,
            "unit",
        ),
        (
            rule_logical.as_str(),
            &rule_path,
            POLKIT_RULE,
            FileKind::Polkit,
            rule_new,
            "polkit",
        ),
    ] {
        // Listed before it is written, so a failure leaves it on the list.
        created.files.push(BoxFile {
            path: PathBuf::from(logical),
            kind,
            sha256: None,
            created: is_new,
        });
        put(
            host,
            path,
            text.as_bytes(),
            0o644,
            (root_uid, root_gid),
            name,
            created,
        )?;
        if let Some(f) = created.files.last_mut() {
            f.sha256 = Some(fsops::sha256_hex(text.as_bytes()));
        }
    }
    match host.systemctl(&["daemon-reload"]) {
        Ok(o) if o.status == 0 => {}
        Ok(o) => {
            return Err(InstallError::Step {
                step: "unit".into(),
                detail: format!(
                    "systemctl daemon-reload exited {}: {}",
                    o.status,
                    o.stderr.trim()
                ),
            })
        }
        Err(e) => return Err(step("unit")(e)),
    }
    Ok(())
}

/// Writes `bytes` to `path` unless it holds them, then mode and owner.
fn put(
    host: &dyn Host,
    path: &Path,
    bytes: &[u8],
    mode: u32,
    (uid, gid): (u32, u32),
    step_name: &str,
    created: &mut Created,
) -> Result<(), InstallError> {
    let want = fsops::sha256_hex(bytes);
    let current = fsops::sha256_file(path).map_err(|e| refused(path, e.to_string()))?;
    if current.as_deref() != Some(want.as_str()) {
        fsops::write_file_atomic(path, bytes, mode).map_err(step(step_name))?;
        created.changed.push(path.display().to_string());
    } else {
        fsops::set_file_mode(path, mode).map_err(step(step_name))?;
    }
    host.chown(path, uid, gid).map_err(step(step_name))
}

/// Ensures the directory `abs` (missing ancestors 0755 root:root) with
/// `mode` and owner `(uid, gid)`; an existing one gets the mode and owner
/// again. A symlink anywhere on the way is refused.
fn ensure_dir(
    layout: &Layout,
    host: &dyn Host,
    abs: &str,
    mode: u32,
    (uid, gid): (u32, u32),
    created: &mut Created,
) -> Result<(), InstallError> {
    let root = (
        host.user("root").map(|u| u.uid).unwrap_or(0),
        host.group_id("root").unwrap_or(0),
    );
    let mut logical = PathBuf::from("/");
    let target = Path::new(abs);
    for comp in target.components().skip(1) {
        logical.push(comp);
        let p = layout
            .try_at(&logical)
            .map_err(|e| refused(&logical, e.to_string()))?;
        let last = logical == target;
        let (m, owner) = if last {
            (mode, (uid, gid))
        } else {
            (0o755, root)
        };
        let made = fsops::create_dir_mode(&p, m).map_err(|e| refused(&p, e.to_string()))?;
        if made {
            host.chown(&p, owner.0, owner.1).map_err(step("dirs"))?;
            created.changed.push(logical.display().to_string());
        } else if last {
            let before = fsops::mode_of(&p).map_err(step("dirs"))?;
            fsops::set_dir_mode(&p, m).map_err(|e| refused(&p, e.to_string()))?;
            host.chown(&p, owner.0, owner.1).map_err(step("dirs"))?;
            if before != Some(m) {
                created
                    .changed
                    .push(format!("{} (mode {m:o})", logical.display()));
            }
        }
    }
    Ok(())
}

/// Stops the box units and removes the template unit, the polkit rule and
/// the VMM. The users, the group and the data dirs stay (`--purge`, see
/// [`PURGE_TREES`]).
pub fn uninstall_boxes(layout: &Layout, host: &dyn Host) -> Result<Vec<String>, InstallError> {
    let mut out = Vec::new();
    match host.systemctl(&["stop", "saiife-box@*.service"]) {
        Ok(o) if o.status == 0 => {}
        Ok(o) => out.push(format!(
            "warning: systemctl stop saiife-box@*.service exited {}: {}",
            o.status,
            o.stderr.trim()
        )),
        Err(e) => out.push(format!("warning: systemctl stop saiife-box@*.service: {e}")),
    }
    for logical in [
        BOX_UNIT_PATH.to_string(),
        polkit_rule_path(),
        VMM_CH.to_string(),
        VMM_FW.to_string(),
        format!("{VMM_CH}.part"),
        format!("{VMM_FW}.part"),
        VMM_DIR.to_string(),
    ] {
        let p = layout.at(&logical);
        if fsops::remove_if_listed(&p).map_err(step("files"))? {
            out.push(format!("removed {logical}"));
        }
    }
    let _ = host.systemctl(&["daemon-reload"]);
    Ok(out)
}

/// What `--purge` removes of the box state, innermost first; the images and
/// the boxes only behind `--purge`, like the daemon's state.
pub const PURGE_TREES: &[&str] = &[BOXES_DIR, IMAGES_DIR, VAULT_DIR, BOX_STATE_DIR];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::FakeHost;
    use crate::testing::fake_install;
    use std::os::unix::fs::PermissionsExt;

    struct World {
        _t: tempfile::TempDir,
        layout: Layout,
        host: FakeHost,
        src: PathBuf,
        pins: VmmPins,
    }

    fn sha(b: &[u8]) -> &'static str {
        Box::leak(fsops::sha256_hex(b).into_boxed_str())
    }

    fn world() -> World {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("r");
        std::fs::create_dir(&root).unwrap();
        fake_install(&root);
        let layout = Layout::under_for(&root, Platform::Linux);
        let host = FakeHost::open(&root).unwrap();
        std::fs::create_dir_all(layout.at(POLKIT_RULES_DIRS[0])).unwrap();
        let src = t.path().join("vmm");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("cloud-hypervisor"), b"fake ch").unwrap();
        std::fs::write(src.join("CLOUDHV.fd"), b"fake fw").unwrap();
        let pins = VmmPins {
            ch_url: "https://invalid.example/ch",
            ch_sha256: sha(b"fake ch"),
            fw_url: "https://invalid.example/fw",
            fw_sha256: sha(b"fake fw"),
        };
        World {
            _t: t,
            layout,
            host,
            src,
            pins,
        }
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn run(w: &World, c: &mut Created) -> Result<(), InstallError> {
        install_boxes_with(&w.layout, &w.host, "saiife", Some(&w.src), &w.pins, c)
    }

    fn chowns(w: &World, p: &Path) -> Vec<(u32, u32)> {
        w.host
            .state()
            .chowns
            .iter()
            .filter(|c| c.path == p)
            .map(|c| (c.uid, c.gid))
            .collect()
    }

    #[test]
    fn box_unit_text_is_pinned() {
        let want = "[Unit]\nDescription=saiife box %i (Cloud Hypervisor)\n[Service]\nType=exec\n\
User=saiife-box\nGroup=saiife-box\nSupplementaryGroups=kvm\n\
ExecStart=/opt/saiife/bin/saiife __box-vmm /var/lib/saiife-box/boxes/%i --locked\n\
UMask=0007\nNoNewPrivileges=yes\nDevicePolicy=closed\nDeviceAllow=/dev/kvm rw\n\
PrivateNetwork=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n\
ReadWritePaths=/var/lib/saiife-box/boxes/%i\n\
ReadOnlyPaths=/var/lib/saiife-box/images /var/lib/saiife-box/vault /opt/saiife/vmm\n\
TimeoutStopSec=30\nKillMode=control-group\nRestart=no\n";
        assert_eq!(BOX_UNIT, want);
    }

    #[test]
    fn polkit_rule_is_narrow() {
        assert!(POLKIT_RULE.contains(r"/^saiife-box@b[0-9]{1,9}\.service$/.test(unit)"));
        assert!(POLKIT_RULE.contains(r#"(verb == "start" || verb == "stop")"#));
        assert!(POLKIT_RULE.contains(r#"subject.user == "saiife""#));
        assert!(POLKIT_RULE.contains(r#"action.id == "org.freedesktop.systemd1.manage-units""#));
        assert_eq!(POLKIT_RULE.matches("return polkit.Result").count(), 1);
        assert!(POLKIT_RULE.contains("return polkit.Result.YES;"));
        assert!(!POLKIT_RULE.contains("Result.AUTH"));
        assert!(!POLKIT_RULE.contains("restart"));
    }

    #[test]
    fn paths_match_the_boxhost_layout() {
        let l = saiife_boxhost::layout::Layout::locked();
        assert_eq!(l.boxes, Path::new(BOXES_DIR));
        assert_eq!(l.images, Path::new(IMAGES_DIR));
        assert_eq!(l.vault, Path::new(VAULT_DIR));
        assert_eq!(l.vmm, Path::new(VMM_DIR));
        assert_eq!(Path::new(BOX_STATE_DIR), l.boxes.parent().unwrap());
    }

    #[test]
    fn install_boxes_on_fake_root() {
        let w = world();
        let mut c = Created::default();
        run(&w, &mut c).unwrap();
        let h = &w.host;
        // The group and user exist, saiife-box in kvm, saiife in saiife-box.
        let box_gid = h.group_id(BOX_GROUP).unwrap();
        assert_eq!(h.user(BOX_USER).unwrap().gid, box_gid);
        assert!(h
            .group_members(KVM_GROUP)
            .unwrap()
            .contains(&BOX_USER.to_string()));
        assert!(h
            .group_members(BOX_GROUP)
            .unwrap()
            .contains(&"saiife".to_string()));
        assert_eq!(c.groups, [BOX_GROUP]);
        assert_eq!(c.users, [BOX_USER]);
        assert_eq!(
            c.memberships,
            [
                (BOX_USER.to_string(), KVM_GROUP.to_string()),
                ("saiife".to_string(), BOX_GROUP.to_string())
            ]
        );
        // Dirs: modes (R26) and owner.
        let daemon_uid = h.user("saiife").unwrap().uid;
        let root_uid = h.user("root").unwrap().uid;
        let at = |p: &str| w.layout.at(p);
        for (p, m, owner) in [
            (BOX_STATE_DIR, 0o750, root_uid),
            (BOXES_DIR, 0o3770, daemon_uid),
            (IMAGES_DIR, 0o2750, daemon_uid),
            (VAULT_DIR, 0o2750, daemon_uid),
            (VMM_DIR, 0o755, root_uid),
        ] {
            assert_eq!(mode(&at(p)), m, "{p}");
            let want_gid = if p == VMM_DIR {
                h.group_id("root").unwrap()
            } else {
                box_gid
            };
            assert_eq!(
                chowns(&w, &at(p)).last().copied(),
                Some((owner, want_gid)),
                "{p}"
            );
        }
        // The VMM, the unit and the rule.
        assert_eq!(std::fs::read(at(VMM_CH)).unwrap(), b"fake ch");
        assert_eq!(mode(&at(VMM_CH)), 0o755);
        assert_eq!(mode(&at(VMM_FW)), 0o644);
        assert_eq!(
            std::fs::read_to_string(at(BOX_UNIT_PATH)).unwrap(),
            BOX_UNIT
        );
        assert_eq!(mode(&at(BOX_UNIT_PATH)), 0o644);
        let rule = at(&polkit_rule_path());
        assert!(rule.starts_with(w.layout.at("/etc/polkit-1/rules.d")));
        assert_eq!(std::fs::read_to_string(&rule).unwrap(), POLKIT_RULE);
        assert_eq!(
            chowns(&w, &rule).last().copied(),
            Some((root_uid, h.group_id("root").unwrap()))
        );
        assert!(h
            .state()
            .calls
            .iter()
            .any(|l| l == "systemctl daemon-reload"));
        let kinds: Vec<FileKind> = c.files.iter().map(|f| f.kind).collect();
        assert_eq!(kinds, [FileKind::Unit, FileKind::Polkit]);
        assert!(c.files.iter().all(|f| f.sha256.is_some() && f.created));
        // A second run changes nothing.
        let mut again = Created::default();
        run(&w, &mut again).unwrap();
        assert!(again.groups.is_empty() && again.users.is_empty());
        assert!(again.memberships.is_empty());
        assert!(again.changed.is_empty(), "{:?}", again.changed);
    }

    #[test]
    fn wrong_vmm_digest_changes_nothing() {
        let w = world();
        std::fs::write(w.src.join("cloud-hypervisor"), b"tampered").unwrap();
        let mut c = Created::default();
        let e = run(&w, &mut c).unwrap_err();
        assert!(e.to_string().contains("pinned"), "{e}");
        assert!(w.host.group_id(BOX_GROUP).is_none());
        assert!(!w.layout.at(BOX_STATE_DIR).exists());
        assert!(c.changed.is_empty());
    }

    #[test]
    fn refuses_without_polkit() {
        let w = world();
        std::fs::remove_dir(w.layout.at(POLKIT_RULES_DIRS[0])).unwrap();
        let e = run(&w, &mut Created::default()).unwrap_err();
        assert!(e.to_string().contains("polkit"), "{e}");
    }

    #[test]
    fn uninstall_boxes_removes_unit_and_rule() {
        let w = world();
        run(&w, &mut Created::default()).unwrap();
        let out = uninstall_boxes(&w.layout, &w.host).unwrap();
        for p in [BOX_UNIT_PATH, VMM_CH, VMM_FW, VMM_DIR] {
            assert!(!w.layout.at(p).exists(), "{p}");
        }
        assert!(!w.layout.at(&polkit_rule_path()).exists());
        assert!(
            out.iter().any(|l| l == &format!("removed {BOX_UNIT_PATH}")),
            "{out:?}"
        );
        // The data stays without --purge.
        assert!(w.layout.at(BOXES_DIR).is_dir());
        assert!(w
            .host
            .state()
            .calls
            .iter()
            .any(|l| l == "systemctl stop saiife-box@*.service"));
        // Idempotent.
        uninstall_boxes(&w.layout, &w.host).unwrap();
    }

    /// Through `system install` itself.
    #[cfg(target_os = "linux")]
    mod full {
        use super::*;
        use crate::install::tests::{all_agents, env, Env};
        use crate::install::InstallOptions;
        use crate::layout::{INSTALLED, UNIT};
        use crate::uninstall::{uninstall, UninstallOptions};
        use crate::unit::{unit_text, unit_text_for};

        fn with_boxes(e: &Env) -> (tempfile::TempDir, InstallOptions) {
            std::fs::create_dir_all(e.at(POLKIT_RULES_DIRS[0])).unwrap();
            let src = tempfile::tempdir().unwrap();
            std::fs::write(src.path().join("cloud-hypervisor"), b"fake ch").unwrap();
            std::fs::write(src.path().join("CLOUDHV.fd"), b"fake fw").unwrap();
            TEST_PINS.with(|c| {
                c.set(Some(VmmPins {
                    ch_url: "https://invalid.example/ch",
                    ch_sha256: sha(b"fake ch"),
                    fw_url: "https://invalid.example/fw",
                    fw_sha256: sha(b"fake fw"),
                }))
            });
            let opts = InstallOptions {
                boxes: true,
                vmm_dir: Some(src.path().to_path_buf()),
                ..all_agents()
            };
            (src, opts)
        }

        #[test]
        fn install_without_boxes_is_unchanged() {
            let e = env(255);
            e.install();
            assert_eq!(std::fs::read_to_string(e.at(UNIT)).unwrap(), unit_text(255));
            assert!(!e.at(BOX_STATE_DIR).exists());
            assert!(!e.at(BOX_UNIT_PATH).exists());
            assert!(e.host.user(BOX_USER).is_none());
            assert!(e.host.group_id(BOX_GROUP).is_none());
            let rec = e.installed();
            assert!(!recorded(&rec));
            assert!(!rec.users.iter().any(|u| u == BOX_USER));
        }

        #[test]
        fn boxes_refused_off_linux_layouts_changes_nothing() {
            let mut e = env(255);
            e.layout = Layout::under_for(e.layout.root(), Platform::Macos);
            let o = InstallOptions {
                boxes: true,
                ..all_agents()
            };
            assert!(matches!(e.run(&o), Err(InstallError::Unsupported(_))));
        }

        #[test]
        fn install_and_uninstall_boxes_through_system_install() {
            let e = env(255);
            let (_src, opts) = with_boxes(&e);
            e.run(&opts).unwrap();
            assert_eq!(
                std::fs::read_to_string(e.at(UNIT)).unwrap(),
                unit_text_for(255, true)
            );
            let rec = e.installed();
            assert!(recorded(&rec));
            assert!(rec.users.iter().any(|u| u == BOX_USER));
            assert!(rec.groups.iter().any(|g| g == BOX_GROUP));
            assert!(rec
                .files
                .iter()
                .any(|f| f.kind == FileKind::Polkit && f.path == Path::new(&polkit_rule_path())));
            // The fake gives every account its one gid; a real host does not.
            e.host.set(|s| {
                s.groups.insert(BOX_GROUP.into(), 4242);
                s.users.get_mut(BOX_USER).unwrap().gid = 4242;
            });
            // A reinstall without --boxes keeps the box lines.
            e.install();
            assert_eq!(
                std::fs::read_to_string(e.at(UNIT)).unwrap(),
                unit_text_for(255, true)
            );
            // A plain uninstall takes the unit, rule and VMM, keeps the data.
            let out = uninstall(&e.layout, &e.host, &UninstallOptions { purge: false }).unwrap();
            assert!(!e.at(BOX_UNIT_PATH).exists() && !e.at(&polkit_rule_path()).exists());
            assert!(!e.at(VMM_DIR).exists(), "{out:?}");
            assert!(e.at(BOXES_DIR).is_dir() && e.at(VAULT_DIR).is_dir());
            assert!(e.host.user(BOX_USER).is_some());
        }

        #[test]
        fn purge_takes_the_box_data_the_user_and_the_group() {
            let e = env(255);
            let (_src, opts) = with_boxes(&e);
            e.run(&opts).unwrap();
            assert!(e.at(IMAGES_DIR).is_dir());
            uninstall(&e.layout, &e.host, &UninstallOptions { purge: true }).unwrap();
            assert!(!e.at(BOX_STATE_DIR).exists());
            assert!(e.host.user(BOX_USER).is_none());
            assert!(e.host.group_id(BOX_GROUP).is_none());
            assert!(!e.at(INSTALLED).exists());
        }
    }
}
