//! The pinned Cloud Hypervisor and firmware (copied from the spike's
//! `box-spike.sh`): URL, version and SHA-256, and the checked download.

use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::tools::{Tool, ToolError, Tools};

pub const CH_VERSION: &str = "v54.0";
pub const CH_URL: &str = "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static";
pub const CH_SHA256: &str = "4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b";
pub const FW_VERSION: &str = "ch-97eeb7b09";
pub const FW_URL: &str =
    "https://github.com/cloud-hypervisor/edk2/releases/download/ch-97eeb7b09/CLOUDHV.fd";
pub const FW_SHA256: &str = "dc2fc8f0e43b96712d9fccc52a3a590769606412b3e1bc911d217addd3bef624";

const FETCH_TIMEOUT: Duration = Duration::from_secs(600);

/// Lowercase hex SHA-256 of a file, read in 1 MiB pieces.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let mut hex = String::with_capacity(64);
    for b in ctx.finish().as_ref() {
        hex.push_str(&format!("{b:02x}"));
    }
    Ok(hex)
}

/// `Ok` when the file's digest is `want`.
pub fn verify(path: &Path, want: &str) -> Result<(), String> {
    let got = sha256_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if got == want {
        Ok(())
    } else {
        Err(format!("{}: sha256 {got}, pinned {want}", path.display()))
    }
}

fn describe(e: &ToolError) -> String {
    match e {
        ToolError::Missing { path, .. } => format!("{} is missing", path.display()),
        ToolError::Failed { status, stderr, .. } => match status {
            Some(c) => format!("curl exited {c}: {}", stderr.trim()),
            None => format!("curl was killed: {}", stderr.trim()),
        },
        ToolError::Timeout { secs, .. } => format!("curl timed out after {secs} s"),
        ToolError::Io(e) => format!("curl: {e}"),
    }
}

/// Run curl with the hardened flags (https only, TLS 1.2+, fail on HTTP
/// errors, two retries), writing `url` to `out`.
pub fn curl_to(tools: &Tools, url: &str, out: &Path) -> Result<(), String> {
    let args: [&OsStr; 10] = [
        "--proto".as_ref(),
        "=https".as_ref(),
        "--tlsv1.2".as_ref(),
        "-fsSL".as_ref(),
        "--retry".as_ref(),
        "2".as_ref(),
        "-o".as_ref(),
        out.as_os_str(),
        "--".as_ref(),
        url.as_ref(),
    ];
    tools
        .run(Tool::Curl, &args, FETCH_TIMEOUT)
        .map(|_| ())
        .map_err(|e| format!("download failed: {url}: {}", describe(&e)))
}

/// Download `url` to `dest` unless `dest` already has the digest `want`:
/// into `<dest>.part`, verified, chmod `mode`, then renamed. A wrong digest
/// removes the part file and fails.
pub fn fetch(tools: &Tools, url: &str, want: &str, dest: &Path, mode: u32) -> Result<(), String> {
    if dest.is_file() && verify(dest, want).is_ok() {
        set_mode(dest, mode)?;
        return Ok(());
    }
    let mut part: PathBuf = dest.as_os_str().to_owned().into();
    part.as_mut_os_string().push(".part");
    let _ = std::fs::remove_file(&part);
    if let Err(e) = curl_to(tools, url, &part) {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    if let Err(e) = verify(&part, want) {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    let done = set_mode(&part, mode).and_then(|()| {
        std::fs::rename(&part, dest).map_err(|e| format!("{}: {e}", dest.display()))
    });
    if done.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    done
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", p.display()))
}

#[cfg(not(unix))]
fn set_mode(_p: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    // sha256("hello\n")
    const HELLO: &str = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";

    struct World {
        dir: tempfile::TempDir,
        tools: Tools,
    }

    fn world() -> World {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::write(&src, "hello\n").unwrap();
        let curl = dir.path().join("curl.sh");
        let body = format!(
            "#!/bin/sh\ntouch '{d}/curl-ran'\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -o ]; then out=$2; fi\n  shift\ndone\ncp \"$FAKE_SRC\" \"$out\"\n",
            d = dir.path().display()
        );
        std::fs::write(&curl, body).unwrap();
        std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
        let src2 = src.clone();
        let c2 = curl.clone();
        let env = move |k: &str| -> Option<OsString> {
            (k == "SAIIFE_TOOL_CURL").then(|| c2.clone().into_os_string())
        };
        // The fake reads FAKE_SRC from the (cleared) environment: bake the
        // path into the script instead.
        let baked = std::fs::read_to_string(&curl)
            .unwrap()
            .replace("$FAKE_SRC", &src2.display().to_string());
        std::fs::write(&curl, baked).unwrap();
        let tools = Tools::system(dir.path()).with_env(&env);
        World { dir, tools }
    }

    #[test]
    fn verify_names_both_digests() {
        let w = world();
        let e = verify(&w.dir.path().join("src"), "00ff").unwrap_err();
        assert!(e.contains(&format!("sha256 {HELLO}")), "{e}");
        assert!(e.contains("pinned 00ff"), "{e}");
        assert!(verify(&w.dir.path().join("src"), HELLO).is_ok());
    }

    #[test]
    fn fetch_writes_and_verifies() {
        let w = world();
        let dest = w.dir.path().join("out");
        fetch(&w.tools, "https://x/y", HELLO, &dest, 0o755).unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "hello\n");
        let m = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o755);
        assert!(!w.dir.path().join("out.part").exists());
    }

    #[test]
    fn fetch_keeps_a_matching_file() {
        let w = world();
        let dest = w.dir.path().join("out");
        std::fs::write(&dest, "hello\n").unwrap();
        fetch(&w.tools, "https://x/y", HELLO, &dest, 0o644).unwrap();
        assert!(!w.dir.path().join("curl-ran").exists());
    }

    #[test]
    fn fetch_refuses_wrong_digest() {
        let w = world();
        let dest = w.dir.path().join("out");
        let e = fetch(&w.tools, "https://x/y", "00ff", &dest, 0o644).unwrap_err();
        assert!(e.contains(HELLO) && e.contains("00ff"), "{e}");
        assert!(!dest.exists());
        assert!(!w.dir.path().join("out.part").exists());
    }
}
