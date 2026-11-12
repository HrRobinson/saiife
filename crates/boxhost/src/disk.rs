//! Per-box disks. The root disk is a qcow2 overlay on the read-only raw base
//! image (spec §7.3, the spike layout): the base is never written, each box
//! gets its own copy-on-write layer.

use crate::tools::{Tool, ToolError, Tools};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

const QEMU_IMG_TIMEOUT: Duration = Duration::from_secs(60);

fn unsafe_for_qemu(s: &str) -> bool {
    s.contains([',', ':']) || s.chars().any(char::is_whitespace)
}

fn checked<'a>(what: &str, p: &'a Path) -> Result<&'a str, String> {
    let s = p
        .to_str()
        .ok_or_else(|| format!("{what} path is not valid UTF-8"))?;
    if unsafe_for_qemu(s) {
        return Err(format!(
            "{what} path {s:?} contains ',', ':' or whitespace (qemu option syntax)"
        ));
    }
    Ok(s)
}

/// Create `out` as a `virtual_gib` GiB qcow2 overlay backed by the raw `base`.
/// Writes `<out>.tmp` and renames it, so `out` never exists half-made. On a
/// failure the tmp is removed and the tool's stderr is returned.
pub fn make_overlay(
    tools: &Tools,
    base: &Path,
    out: &Path,
    virtual_gib: u64,
) -> Result<(), String> {
    if !base.is_absolute() {
        return Err(format!("base {} is not an absolute path", base.display()));
    }
    checked("base", base)?;
    let out_s = checked("out", out)?;
    // symlink_metadata: a dangling or live symlink at `out` also counts.
    if std::fs::symlink_metadata(out).is_ok() {
        return Err(format!("{} already exists", out.display()));
    }
    let tmp = PathBuf::from(format!("{out_s}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let size = OsString::from(format!("{virtual_gib}G"));
    let args: [&std::ffi::OsStr; 10] = [
        "create".as_ref(),
        "-q".as_ref(),
        "-f".as_ref(),
        "qcow2".as_ref(),
        "-F".as_ref(),
        "raw".as_ref(),
        "-b".as_ref(),
        base.as_os_str(),
        tmp.as_os_str(),
        &size,
    ];
    let fail = |tmp: &Path, msg: String| {
        let _ = std::fs::remove_file(tmp);
        msg
    };
    match tools.run(Tool::QemuImg, &args[..], QEMU_IMG_TIMEOUT) {
        Ok(_) => {}
        Err(ToolError::Failed { stderr, .. }) => return Err(fail(&tmp, stderr)),
        Err(e) => return Err(fail(&tmp, format!("qemu-img: {e:?}"))),
    }
    std::fs::rename(&tmp, out).map_err(|e| fail(&tmp, format!("rename overlay: {e}")))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    fn world(body: &str) -> (tempfile::TempDir, Tools) {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("qemu-img.sh");
        let text = format!(
            "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\" >> '{d}/argv'; done\n{body}\n",
            d = dir.path().display()
        );
        std::fs::write(&fake, text).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let env = move |k: &str| -> Option<OsString> {
            (k == "SAIIFE_TOOL_QEMU_IMG").then(|| fake.clone().into_os_string())
        };
        let tools = Tools::system(dir.path()).with_env(&env);
        (dir, tools)
    }

    // Writes the last-but-one argument (the tmp path).
    const WRITE_TMP: &str = "for a in \"$@\"; do prev=$last; last=$a; done\necho qcow > \"$prev\"";

    #[test]
    fn overlay_argv_is_pinned() {
        let (d, tools) = world(WRITE_TMP);
        let out = d.path().join("root.qcow2");
        make_overlay(&tools, Path::new("/base/root.raw"), &out, 20).unwrap();
        let argv = std::fs::read_to_string(d.path().join("argv")).unwrap();
        let want = format!(
            "create\n-q\n-f\nqcow2\n-F\nraw\n-b\n/base/root.raw\n{}.tmp\n20G\n",
            out.display()
        );
        assert_eq!(argv, want);
        assert!(out.exists());
        assert!(!d.path().join("root.qcow2.tmp").exists());
    }

    #[test]
    fn overlay_refuses_unsafe_paths() {
        let (d, tools) = world(WRITE_TMP);
        let out = d.path().join("o.qcow2");
        for base in [
            "rel/base.raw",
            "/b,ase.raw",
            "/b:ase.raw",
            "/b ase.raw",
            "/b\tase",
        ] {
            assert!(
                make_overlay(&tools, Path::new(base), &out, 10).is_err(),
                "{base}"
            );
        }
        for bad in ["a,b", "a:b", "a b"] {
            let o = d.path().join(bad);
            assert!(
                make_overlay(&tools, Path::new("/base.raw"), &o, 10).is_err(),
                "{bad}"
            );
        }
        assert!(!d.path().join("argv").exists(), "tool must not have run");
    }

    #[test]
    fn overlay_refuses_existing_out() {
        let (d, tools) = world(WRITE_TMP);
        let out = d.path().join("o.qcow2");
        std::fs::write(&out, "mine").unwrap();
        assert!(make_overlay(&tools, Path::new("/base.raw"), &out, 10).is_err());
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "mine");
        let link = d.path().join("link.qcow2");
        std::os::unix::fs::symlink(d.path().join("nowhere"), &link).unwrap();
        assert!(make_overlay(&tools, Path::new("/base.raw"), &link, 10).is_err());
        assert!(!d.path().join("argv").exists());
    }

    #[test]
    fn overlay_failure_leaves_nothing() {
        let body = format!("{WRITE_TMP}\necho 'qemu-img: bad base' >&2\nexit 1");
        let (d, tools) = world(&body);
        let out = d.path().join("o.qcow2");
        let e = make_overlay(&tools, Path::new("/base.raw"), &out, 10).unwrap_err();
        assert!(e.contains("bad base"), "{e}");
        assert!(!out.exists());
        assert!(!d.path().join("o.qcow2.tmp").exists());
    }
}
