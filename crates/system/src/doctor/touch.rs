//! The `touch-key` check of `saiife doctor` (plan 27, Task 4): is a FIDO
//! security key plugged in, and can this session use it? Linux only: a
//! hidraw node whose report descriptor starts with the FIDO usage page item
//! (`06 D0 F1`) is a FIDO key. This is an access test only: the node is never
//! opened. It is Info or Pass, and a Warn at worst: touch is optional until a
//! policy marks something.

use super::report::{Check, Status};
use super::Ctx;
use rustix::fs::{access, Access};
use std::fs;
use std::io::Read;

const HIDRAW: &str = "/sys/class/hidraw";
const DEV: &str = "/dev";
/// The usage page item (page 0xF1D0) every FIDO authenticator's descriptor opens with.
const FIDO_PAGE: [u8; 3] = [0x06, 0xD0, 0xF1];
const ID: &str = "touch-key";
const TITLE: &str = "touch key";

pub(super) fn checks(ctx: &Ctx) -> Vec<Check> {
    let mut nodes = fido_nodes(ctx);
    nodes.sort();
    if nodes.is_empty() {
        return vec![Check::new(
            ID,
            Status::Info,
            TITLE,
            "no FIDO key plugged in",
        )];
    }
    let dev = ctx.layout.at(DEV);
    if let Some(n) = nodes
        .iter()
        .find(|n| access(dev.join(n), Access::READ_OK | Access::WRITE_OK).is_ok())
    {
        return vec![Check::new(
            ID,
            Status::Pass,
            TITLE,
            format!("{n} is usable by you"),
        )];
    }
    vec![Check::new(
        ID,
        Status::Warn,
        TITLE,
        format!(
            "{} is plugged in but not usable by you: log in at the machine \
             (an SSH session gets no access), or see docs/touch.md for other distros",
            nodes[0]
        ),
    )]
}

/// The names (`hidraw3`) of the FIDO hidraw nodes.
fn fido_nodes(ctx: &Ctx) -> Vec<String> {
    let Ok(rd) = fs::read_dir(ctx.layout.at(HIDRAW)) else {
        return Vec::new();
    };
    rd.filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let mut head = [0u8; 3];
            fs::File::open(e.path().join("device/report_descriptor"))
                .ok()?
                .read_exact(&mut head)
                .ok()?;
            (head == FIDO_PAGE).then_some(name)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::DoctorOptions;
    use crate::host::FakeHost;
    use crate::layout::Layout;
    use saiife_policy::FixedDirectory;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn run(root: &std::path::Path) -> Check {
        let layout = Layout::under(root);
        let host = FakeHost::open(root).unwrap();
        let dir = FixedDirectory::from_text("", "");
        let opts = DoctorOptions::default();
        let ctx = Ctx {
            layout: &layout,
            host: &host,
            dir: &dir,
            installed: None,
            installed_error: None,
            config: Err("none".into()),
            as_root: false,
            opts: &opts,
        };
        let mut cs = checks(&ctx);
        assert_eq!(cs.len(), 1);
        cs.pop().unwrap()
    }

    fn node(root: &std::path::Path, n: &str, desc: &[u8], mode: u32) {
        let d = root.join("sys/class/hidraw").join(n).join("device");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("report_descriptor"), desc).unwrap();
        fs::create_dir_all(root.join("dev")).unwrap();
        let f = root.join("dev").join(n);
        fs::write(&f, b"").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn no_key_is_info() {
        let t = TempDir::new().unwrap();
        fs::create_dir_all(t.path().join("sys/class/hidraw")).unwrap();
        let c = run(t.path());
        assert_eq!(c.id, "touch-key");
        assert_eq!(c.status, Status::Info);
        assert_eq!(c.title, "touch key");
        assert_eq!(c.detail, "no FIDO key plugged in");
    }

    #[test]
    fn fido_node_usable() {
        let t = TempDir::new().unwrap();
        node(t.path(), "hidraw3", &[0x06, 0xD0, 0xF1, 0x09, 0x01], 0o600);
        let c = run(t.path());
        assert_eq!(c.status, Status::Pass);
        assert_eq!(c.detail, "hidraw3 is usable by you");
    }

    #[test]
    fn fido_node_not_usable() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let t = TempDir::new().unwrap();
        node(t.path(), "hidraw3", &[0x06, 0xD0, 0xF1, 0x09, 0x01], 0o000);
        let c = run(t.path());
        assert_eq!(c.status, Status::Warn);
        assert!(c
            .detail
            .starts_with("hidraw3 is plugged in but not usable by you"));
        assert!(c.detail.contains("log in at the machine"));
    }

    #[test]
    fn other_hid_devices_ignored() {
        let t = TempDir::new().unwrap();
        node(t.path(), "hidraw1", &[0x05, 0x01, 0x09, 0x06], 0o600);
        let c = run(t.path());
        assert_eq!(c.status, Status::Info);
        assert_eq!(c.detail, "no FIDO key plugged in");
    }
}
