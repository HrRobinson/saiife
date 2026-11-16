//! The Ubuntu cloud image, verified through `SHA256SUMS.gpg` against a pinned
//! signing-key fingerprint (I1), then against the recipe's own pin.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::image::Recipe;
use crate::pins;
use crate::tools::{Tool, ToolError, Tools};

const GPGV_TIMEOUT: Duration = Duration::from_secs(60);

pub const UBUNTU_CLOUD_FPR: &str = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
pub const UBUNTU_IMAGE: &str = "ubuntu-24.04-server-cloudimg-amd64.img";

/// The release directory plus `file`.
pub fn release_url(release: &str, file: &str) -> String {
    format!("https://cloud-images.ubuntu.com/releases/noble/{release}/{file}")
}

fn valid_release(r: &str) -> bool {
    r.strip_prefix("release-")
        .is_some_and(|d| d.len() == 8 && d.bytes().all(|b| b.is_ascii_digit()))
}

pub(crate) fn is_fpr(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))
}

/// The primary-key fingerprint (last field) of the single `VALIDSIG` line.
/// No line, several lines, or a last field that is not 40 uppercase hex: `None`.
pub fn parse_validsig(status: &str) -> Option<String> {
    let mut found = None;
    for line in status.lines() {
        let mut f = line.split_whitespace();
        if f.next() == Some("[GNUPG:]") && f.next() == Some("VALIDSIG") {
            if found.is_some() {
                return None;
            }
            found = Some(f.next_back().filter(|l| is_fpr(l))?.to_string());
        }
    }
    found
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The digest of `file` from a `SHA256SUMS` text: exactly one line
/// `<64 lowercase hex> *<file>` or `<64 hex>  <file>`.
pub fn sum_for(sums_text: &str, file: &str) -> Result<String, String> {
    let mut hits = Vec::new();
    for line in sums_text.lines() {
        let Some((hash, rest)) = line.split_at_checked(64) else {
            continue;
        };
        let name = rest.strip_prefix(" *").or_else(|| rest.strip_prefix("  "));
        if is_hex64(hash) && name == Some(file) {
            hits.push(hash);
        }
    }
    match hits.as_slice() {
        [one] => Ok((*one).to_string()),
        [] => Err(format!("SHA256SUMS has no line for {file}")),
        _ => Err(format!("SHA256SUMS has more than one line for {file}")),
    }
}

const REFUSED: [&str; 6] = [
    "BADSIG",
    "ERRSIG",
    "EXPKEYSIG",
    "REVKEYSIG",
    "EXPSIG",
    "NO_PUBKEY",
];

/// Run `gpgv --status-fd 1 --keyring <keyring> <sig> <sums>` and require a
/// clean exit, no failure status line, and a `VALIDSIG` from the pinned key.
pub fn check_signature(
    tools: &Tools,
    keyring: &Path,
    sums: &Path,
    sig: &Path,
) -> Result<(), String> {
    let args: [&OsStr; 6] = [
        "--status-fd".as_ref(),
        "1".as_ref(),
        "--keyring".as_ref(),
        keyring.as_os_str(),
        sig.as_os_str(),
        sums.as_os_str(),
    ];
    let out = tools
        .run(Tool::Gpgv, &args, GPGV_TIMEOUT)
        .map_err(|e| match e {
            ToolError::Failed { status, stderr, .. } => format!(
                "gpgv refused the signature on {} (exit {}): {}",
                sums.display(),
                status.map_or("none".into(), |c| c.to_string()),
                stderr.trim()
            ),
            ToolError::Missing { path, .. } => format!("gpgv is missing: {}", path.display()),
            ToolError::Timeout { secs, .. } => format!("gpgv timed out after {secs} s"),
            ToolError::Io(e) => format!("gpgv: {e}"),
        })?;
    let status = String::from_utf8_lossy(&out.stdout);
    for line in status.lines() {
        let mut f = line.split_whitespace();
        if f.next() == Some("[GNUPG:]") {
            if let Some(t) = f.next().filter(|t| REFUSED.contains(t)) {
                return Err(format!("gpgv reported {t} for {}", sums.display()));
            }
        }
    }
    match parse_validsig(&status) {
        Some(fpr) if fpr == UBUNTU_CLOUD_FPR => Ok(()),
        Some(fpr) => Err(format!(
            "SHA256SUMS is signed by {fpr}, not the pinned Ubuntu key {UBUNTU_CLOUD_FPR}"
        )),
        None => Err("gpgv gave no single VALIDSIG line for SHA256SUMS".into()),
    }
}

/// Download the signed checksum list fresh, verify it, then fetch the image
/// into `cache` with the signed digest (reusing a cached copy that has it).
/// The recipe's pin must equal the signed digest before the image is fetched.
pub fn fetch_verified(
    tools: &Tools,
    cache: &Path,
    recipe: &Recipe,
    keyring: &Path,
) -> Result<PathBuf, String> {
    if !keyring.is_file() {
        return Err(format!(
            "assets/box/ubuntu-cloudimage-keyring.gpg is missing: the owner verifies UBUNTU_CLOUD_FPR and runs `gpg --export --export-options export-minimal {UBUNTU_CLOUD_FPR} > assets/box/ubuntu-cloudimage-keyring.gpg` ({})",
            keyring.display()
        ));
    }
    if !valid_release(&recipe.ubuntu_release) {
        return Err(format!(
            "ubuntu.release {:?} is not release-<8 digits>",
            recipe.ubuntu_release
        ));
    }
    std::fs::create_dir_all(cache).map_err(|e| format!("{}: {e}", cache.display()))?;
    let sums = cache.join("SHA256SUMS");
    let sig = cache.join("SHA256SUMS.gpg");
    for (name, dest) in [("SHA256SUMS", &sums), ("SHA256SUMS.gpg", &sig)] {
        let mut part: PathBuf = dest.as_os_str().to_owned().into();
        part.as_mut_os_string().push(".part");
        let _ = std::fs::remove_file(&part);
        let url = release_url(&recipe.ubuntu_release, name);
        let done = pins::curl_to(tools, &url, &part).and_then(|()| {
            std::fs::rename(&part, dest).map_err(|e| format!("{}: {e}", dest.display()))
        });
        if let Err(e) = done {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
    }
    check_signature(tools, keyring, &sums, &sig)?;
    let text = std::fs::read_to_string(&sums).map_err(|e| format!("{}: {e}", sums.display()))?;
    let signed = sum_for(&text, UBUNTU_IMAGE)?;
    if signed != recipe.ubuntu_sha256 {
        return Err(format!(
            "the signed digest for {UBUNTU_IMAGE} is {signed} but the recipe pin is {}; update the pin once the new release is reviewed",
            recipe.ubuntu_sha256
        ));
    }
    let dest = cache.join(UBUNTU_IMAGE);
    let url = release_url(&recipe.ubuntu_release, UBUNTU_IMAGE);
    pins::fetch(tools, &url, &signed, &dest, 0o644)?;
    Ok(dest)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::image::ClaudePin;
    use crate::pins::sha256_file;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gpgv");
    const OTHER: &str = "1111111111111111111111111111111111111111";

    fn exec(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    struct World {
        dir: tempfile::TempDir,
        tools: Tools,
        cache: PathBuf,
        keyring: PathBuf,
        recipe: Recipe,
    }

    impl World {
        fn serve(&self, name: &str, content: &str) {
            std::fs::write(self.dir.path().join("serve").join(name), content).unwrap();
        }
        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("curl.log")).unwrap_or_default()
        }
    }

    /// A fake gpgv printing `fixture` and exiting `code`, a fake curl
    /// serving files from `serve/` by the URL's last path segment. The
    /// image is "hello\n"; the signed list names it with the recipe's pin
    /// unless a test serves another list.
    fn world(fixture: &str, code: i32) -> World {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir(d.join("serve")).unwrap();
        let gpgv = d.join("gpgv.sh");
        exec(
            &gpgv,
            &format!("#!/bin/sh\ncat '{FIX}/{fixture}'\nexit {code}\n"),
        );
        let curl = d.join("curl.sh");
        exec(
            &curl,
            &format!(
                "#!/bin/sh\nfor a; do last=$a; done\necho \"$last\" >> '{d}/curl.log'\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = -o ]; then out=$2; fi\n  shift\ndone\ncp \"{d}/serve/${{last##*/}}\" \"$out\"\n",
                d = d.display()
            ),
        );
        let (g, c) = (gpgv.into_os_string(), curl.into_os_string());
        let env = move |k: &str| -> Option<OsString> {
            match k {
                "SAIIFE_TOOL_GPGV" => Some(g.clone()),
                "SAIIFE_TOOL_CURL" => Some(c.clone()),
                _ => None,
            }
        };
        let tools = Tools::system(d).with_env(&env);
        let keyring = d.join("keyring.gpg");
        std::fs::write(&keyring, "k").unwrap();
        let image = d.join("image-src");
        std::fs::write(&image, "hello\n").unwrap();
        let sha = sha256_file(&image).unwrap();
        let recipe = Recipe {
            ubuntu_release: "release-20261017".into(),
            ubuntu_sha256: sha.clone(),
            packages: vec![],
            images: vec![],
            claude: ClaudePin {
                version: "UNPINNED".into(),
                url: "UNPINNED".into(),
                sha256: "UNPINNED".into(),
            },
            direct_kernel: false,
            codex: None,
            gemini: None,
        };
        let w = World {
            cache: d.join("cache"),
            keyring,
            recipe,
            tools,
            dir,
        };
        std::fs::create_dir(&w.cache).unwrap();
        w.serve(UBUNTU_IMAGE, "hello\n");
        w.serve("SHA256SUMS", &format!("{sha} *{UBUNTU_IMAGE}\n"));
        w.serve("SHA256SUMS.gpg", "sig");
        w
    }

    fn check(w: &World) -> Result<(), String> {
        let p = w.dir.path();
        check_signature(&w.tools, &w.keyring, &p.join("sums"), &p.join("sig"))
    }

    #[test]
    fn parse_validsig_takes_primary_fpr() {
        let sub = "[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 2024-01-01 1704067200 0 4 0 1 10 00 D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81\n";
        assert_eq!(parse_validsig(sub).as_deref(), Some(UBUNTU_CLOUD_FPR));
        let good = std::fs::read_to_string(format!("{FIX}/good.status")).unwrap();
        assert_eq!(parse_validsig(&good).as_deref(), Some(UBUNTU_CLOUD_FPR));
        assert_eq!(parse_validsig("[GNUPG:] NEWSIG\n"), None);
        // Two VALIDSIG lines are ambiguous; a short or lowercase field is no fingerprint.
        assert_eq!(parse_validsig(&format!("{sub}{sub}")), None);
        assert_eq!(
            parse_validsig("[GNUPG:] VALIDSIG a b c d e f g h i abc\n"),
            None
        );
    }

    #[test]
    fn good_signature_passes() {
        let w = world("good.status", 0);
        check(&w).unwrap();
    }

    #[test]
    fn bad_signature_is_refused() {
        let w = world("bad.status", 1);
        assert!(check(&w).unwrap_err().contains("gpgv"));
        // Even with a zero exit, BADSIG alone refuses.
        let w = world("bad.status", 0);
        assert!(check(&w).unwrap_err().contains("BADSIG"));
    }

    #[test]
    fn other_signer_is_refused() {
        let w = world("other-key.status", 0);
        let e = check(&w).unwrap_err();
        assert!(e.contains(OTHER) && e.contains(UBUNTU_CLOUD_FPR), "{e}");
    }

    #[test]
    fn exit_zero_without_validsig_is_refused() {
        let w = world("no-sig.status", 0);
        assert!(check(&w).unwrap_err().contains("VALIDSIG"));
    }

    #[test]
    fn missing_line_is_refused() {
        let h = "a".repeat(64);
        let text = format!("{h} *other.img\n{h}  {UBUNTU_IMAGE}.txt\nx{UBUNTU_IMAGE}\n");
        let e = sum_for(&text, UBUNTU_IMAGE).unwrap_err();
        assert!(e.contains("no line for"), "{e}");
        let ok = format!("{h} *{UBUNTU_IMAGE}\n");
        assert_eq!(sum_for(&ok, UBUNTU_IMAGE).unwrap(), h);
        let ok2 = format!("{h}  {UBUNTU_IMAGE}\n");
        assert_eq!(sum_for(&ok2, UBUNTU_IMAGE).unwrap(), h);
        let upper = format!("{} *{UBUNTU_IMAGE}\n", "A".repeat(64));
        assert!(sum_for(&upper, UBUNTU_IMAGE).is_err());
    }

    #[test]
    fn duplicate_line_is_refused() {
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        let text = format!("{a} *{UBUNTU_IMAGE}\n{b}  {UBUNTU_IMAGE}\n");
        let e = sum_for(&text, UBUNTU_IMAGE).unwrap_err();
        assert!(e.contains("more than one line"), "{e}");
    }

    #[test]
    fn pin_mismatch_is_refused() {
        let mut w = world("good.status", 0);
        w.recipe.ubuntu_sha256 = "0".repeat(64);
        let e = fetch_verified(&w.tools, &w.cache, &w.recipe, &w.keyring).unwrap_err();
        assert!(e.contains("pin"), "{e}");
        assert!(!w.log().contains(UBUNTU_IMAGE), "image must not be fetched");
        assert!(!w.cache.join(UBUNTU_IMAGE).exists());
    }

    #[test]
    fn missing_keyring_names_the_owner_step() {
        let w = world("good.status", 0);
        let missing = w.dir.path().join("nope.gpg");
        let e = fetch_verified(&w.tools, &w.cache, &w.recipe, &missing).unwrap_err();
        assert!(
            e.contains("gpg --export") && e.contains(UBUNTU_CLOUD_FPR),
            "{e}"
        );
        assert_eq!(w.log(), "", "nothing is downloaded first");
        let e = fetch_verified(&w.tools, &w.cache, &w.recipe, w.dir.path()).unwrap_err();
        assert!(e.contains("gpg --export"), "{e}");
    }

    #[test]
    fn fetch_verified_uses_the_cache() {
        let w = world("good.status", 0);
        let p = fetch_verified(&w.tools, &w.cache, &w.recipe, &w.keyring).unwrap();
        assert_eq!(p, w.cache.join(UBUNTU_IMAGE));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "hello\n");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let url = release_url(&w.recipe.ubuntu_release, UBUNTU_IMAGE);
        assert_eq!(w.log().matches(&url).count(), 1, "{}", w.log());
        let p2 = fetch_verified(&w.tools, &w.cache, &w.recipe, &w.keyring).unwrap();
        assert_eq!(p, p2);
        let log = w.log();
        assert_eq!(log.matches(&url).count(), 1, "image fetched again: {log}");
        assert_eq!(log.matches("SHA256SUMS\n").count(), 2, "{log}");
        assert_eq!(log.matches("SHA256SUMS.gpg").count(), 2, "{log}");
    }

    #[test]
    fn bad_release_is_refused_before_any_url() {
        let mut w = world("good.status", 0);
        w.recipe.ubuntu_release = "../evil".into();
        let e = fetch_verified(&w.tools, &w.cache, &w.recipe, &w.keyring).unwrap_err();
        assert!(e.contains("release"), "{e}");
        assert_eq!(w.log(), "");
    }
}
