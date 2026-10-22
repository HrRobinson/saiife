//! Which systems locked mode supports (spec §0 decision 8): Ubuntu 22.04+,
//! Debian 12+, RHEL 9+ (and distributions `ID_LIKE` rhel, 9+), each with
//! systemd running. Alpine and containers get developer mode only.

use crate::host::{Host, CONTAINER_UNKNOWN};
use crate::layout::Layout;
use std::collections::BTreeMap;

/// The reason on anything but Linux (the 9a text).
pub const NOT_LINUX: &str = "locked mode needs Linux in this version (macOS: v2.1)";

/// The oldest systemd with `LoadCredential=`.
const MIN_SYSTEMD: u32 = 247;

const SUPPORTED_LIST: &str = "Ubuntu 22.04+, Debian 12+, RHEL 9+";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    Supported {
        distro: String,
        systemd: u32,
    },
    /// Why not, as one clause for [`refusal_line`].
    Refused(String),
}

/// Checks this machine (or the tree under `layout`'s root): the OS, a
/// container, systemd and its version, then the distribution from
/// `<root>/etc/os-release`.
pub fn check_supported(layout: &Layout, host: &dyn Host) -> Support {
    supported_on(cfg!(target_os = "linux"), layout, host)
}

pub(crate) fn supported_on(linux: bool, layout: &Layout, host: &dyn Host) -> Support {
    if !linux {
        return Support::Refused(NOT_LINUX.to_string());
    }
    let container = host.container().or_else(|| {
        if layout.root().join(".dockerenv").exists() {
            Some("docker".to_string())
        } else if layout.root().join("run/.containerenv").exists() {
            Some("podman".to_string())
        } else {
            None
        }
    });
    if container.as_deref() == Some(CONTAINER_UNKNOWN) {
        return Support::Refused(
            "container detection failed (systemd-detect-virt is missing or did not answer); \
             locked mode needs it to rule out a container"
                .into(),
        );
    }
    if let Some(c) = container {
        return Support::Refused(format!("inside a container ({c}): developer mode only"));
    }
    if !layout.root().join("run/systemd/system").is_dir() {
        return Support::Refused("systemd is not running; locked mode needs systemd".into());
    }
    let systemd = match host.systemd_version() {
        Ok(v) => v,
        Err(e) => return Support::Refused(format!("the systemd version could not be read: {e}")),
    };
    if systemd < MIN_SYSTEMD {
        return Support::Refused(format!(
            "systemd {systemd} is too old ({MIN_SYSTEMD} or later is needed for LoadCredential)"
        ));
    }
    let os = std::fs::read_to_string(layout.root().join("etc/os-release"))
        .map(|t| parse_os_release(&t))
        .unwrap_or_default();
    let get = |k: &str| os.get(k).map(String::as_str).unwrap_or("");
    let id = get("ID");
    if id == "alpine" {
        return Support::Refused("Alpine: developer mode only".into());
    }
    let version = get("VERSION_ID");
    let like_rhel = id == "rhel" || get("ID_LIKE").split_whitespace().any(|w| w == "rhel");
    let ok = match id {
        "ubuntu" => version_at_least(version, (22, 4)),
        "debian" => version_at_least(version, (12, 0)),
        _ if like_rhel => version_at_least(version, (9, 0)),
        _ => false,
    };
    let distro = ["PRETTY_NAME", "NAME", "ID"]
        .into_iter()
        .map(get)
        .find(|v| !v.is_empty())
        .unwrap_or("this system")
        .to_string();
    if ok {
        Support::Supported { distro, systemd }
    } else {
        Support::Refused(format!(
            "{distro} is not supported for locked mode ({SUPPORTED_LIST})"
        ))
    }
}

/// The one line `install` prints when it refuses.
pub fn refusal_line(why: &str) -> String {
    format!("saiife: locked mode is not supported here: {why}. Developer mode works as before.")
}

/// `VERSION_ID` as (major, minor) ≥ `min`. A missing or odd version is not.
fn version_at_least(version: &str, min: (u32, u32)) -> bool {
    let mut parts = version.split('.');
    let Some(Ok(major)) = parts.next().map(str::parse::<u32>) else {
        return false;
    };
    let minor = match parts.next() {
        None => 0,
        Some(m) => match m.parse::<u32>() {
            Ok(m) => m,
            Err(_) => return false,
        },
    };
    (major, minor) >= min
}

/// `KEY=value` lines of os-release(5); quotes and backslash escapes removed.
pub(crate) fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        out.insert(k.to_string(), unquote(v));
    }
    out
}

fn unquote(v: &str) -> String {
    let inner = match v.as_bytes() {
        [b'"', .., b'"'] | [b'\'', .., b'\''] if v.len() >= 2 => &v[1..v.len() - 1],
        _ => v,
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::FakeHost;
    use std::fs;

    /// A root with `etc/os-release` and `run/systemd/system`, and its host.
    fn root_with(os_release: &str) -> (tempfile::TempDir, Layout, FakeHost) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        fs::write(dir.path().join("etc/os-release"), os_release).unwrap();
        fs::create_dir_all(dir.path().join("run/systemd/system")).unwrap();
        let layout = Layout::under(dir.path());
        let host = FakeHost::open(dir.path()).unwrap();
        (dir, layout, host)
    }

    /// The check as it runs on Linux, so these tests also run on macOS.
    fn check_linux(l: &Layout, h: &FakeHost) -> Support {
        supported_on(true, l, h)
    }

    fn check(os_release: &str) -> Support {
        let (_d, l, h) = root_with(os_release);
        check_linux(&l, &h)
    }

    #[test]
    fn not_linux_refused_first() {
        let (_d, l, h) = root_with(UBUNTU_2404);
        h.set(|s| s.container = Some("docker".into()));
        assert_eq!(
            refused(supported_on(false, &l, &h)),
            "locked mode needs Linux in this version (macOS: v2.1)"
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(refused(check_supported(&l, &h)), NOT_LINUX);
    }

    fn refused(s: Support) -> String {
        match s {
            Support::Refused(why) => why,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    const UBUNTU_2204: &str = "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\nID_LIKE=debian\n";
    const UBUNTU_2404: &str = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n";
    const UBUNTU_2004: &str = "NAME=\"Ubuntu\"\nVERSION=\"20.04.6 LTS (Focal Fossa)\"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 20.04.6 LTS\"\nVERSION_ID=\"20.04\"\n";
    const DEBIAN_12: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n";
    const DEBIAN_11: &str = "PRETTY_NAME=\"Debian GNU/Linux 11 (bullseye)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"11\"\nID=debian\n";
    const RHEL_9: &str = "NAME=\"Red Hat Enterprise Linux\"\nVERSION=\"9.4 (Plow)\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 9.4 (Plow)\"\n";
    const ROCKY_9: &str = "NAME=\"Rocky Linux\"\nVERSION=\"9.3 (Blue Onyx)\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.3\"\nPRETTY_NAME=\"Rocky Linux 9.3 (Blue Onyx)\"\n";
    const RHEL_8: &str = "NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"8.9\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 8.9 (Ootpa)\"\n";
    const ALPINE: &str =
        "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n";

    #[test]
    fn ubuntu_2204_and_2404_supported() {
        assert_eq!(
            check(UBUNTU_2204),
            Support::Supported {
                distro: "Ubuntu 22.04.4 LTS".into(),
                systemd: 255
            }
        );
        assert!(matches!(check(UBUNTU_2404), Support::Supported { .. }));
    }

    #[test]
    fn ubuntu_2004_refused() {
        assert_eq!(
            refused(check(UBUNTU_2004)),
            "Ubuntu 20.04.6 LTS is not supported for locked mode (Ubuntu 22.04+, Debian 12+, RHEL 9+)"
        );
    }

    #[test]
    fn debian_12_supported() {
        assert!(matches!(check(DEBIAN_12), Support::Supported { .. }));
    }

    #[test]
    fn debian_11_refused() {
        assert!(refused(check(DEBIAN_11))
            .starts_with("Debian GNU/Linux 11 (bullseye) is not supported"));
    }

    #[test]
    fn rhel_9_and_rocky_9_supported() {
        assert!(matches!(check(RHEL_9), Support::Supported { .. }));
        assert_eq!(
            check(ROCKY_9),
            Support::Supported {
                distro: "Rocky Linux 9.3 (Blue Onyx)".into(),
                systemd: 255
            }
        );
    }

    #[test]
    fn rhel_8_refused() {
        assert!(refused(check(RHEL_8)).contains("is not supported for locked mode"));
    }

    #[test]
    fn alpine_refused_developer_mode_only() {
        assert!(refused(check(ALPINE)).contains("Alpine: developer mode only"));
    }

    #[test]
    fn unknown_or_missing_os_release_refused() {
        let why = refused(check("ID=arch\nPRETTY_NAME=\"Arch Linux\"\n"));
        assert!(why.starts_with("Arch Linux is not supported"), "{why}");
        let (d, l, h) = root_with(UBUNTU_2404);
        fs::remove_file(d.path().join("etc/os-release")).unwrap();
        assert!(refused(check_linux(&l, &h)).contains("is not supported for locked mode"));
    }

    #[test]
    fn container_refused() {
        let (_d, l, h) = root_with(UBUNTU_2404);
        h.set(|s| s.container = Some("docker".into()));
        assert_eq!(
            refused(check_linux(&l, &h)),
            "inside a container (docker): developer mode only"
        );

        let (d, l, h) = root_with(UBUNTU_2404);
        fs::write(d.path().join(".dockerenv"), "").unwrap();
        assert!(refused(check_linux(&l, &h)).starts_with("inside a container ("));

        let (d, l, h) = root_with(UBUNTU_2404);
        fs::write(d.path().join("run/.containerenv"), "").unwrap();
        assert!(refused(check_linux(&l, &h)).starts_with("inside a container ("));
    }

    #[test]
    fn unknown_container_refused() {
        let (_d, l, h) = root_with(UBUNTU_2404);
        h.set(|s| s.container = Some(crate::host::CONTAINER_UNKNOWN.into()));
        let why = refused(check_linux(&l, &h));
        assert!(why.contains("systemd-detect-virt"), "{why}");
        assert!(!why.starts_with("inside a container"), "{why}");
    }

    #[test]
    fn container_comes_before_systemd() {
        let (d, l, h) = root_with(ALPINE);
        fs::remove_dir(d.path().join("run/systemd/system")).unwrap();
        h.set(|s| s.container = Some("lxc".into()));
        assert!(refused(check_linux(&l, &h)).starts_with("inside a container (lxc)"));
    }

    #[test]
    fn no_systemd_refused() {
        let (d, l, h) = root_with(UBUNTU_2404);
        fs::remove_dir(d.path().join("run/systemd/system")).unwrap();
        assert_eq!(
            refused(check_linux(&l, &h)),
            "systemd is not running; locked mode needs systemd"
        );
    }

    #[test]
    fn systemd_246_refused() {
        let (_d, l, h) = root_with(UBUNTU_2404);
        h.set(|s| s.systemd = 246);
        assert_eq!(
            refused(check_linux(&l, &h)),
            "systemd 246 is too old (247 or later is needed for LoadCredential)"
        );
        h.set(|s| s.systemd = 247);
        assert_eq!(
            check_linux(&l, &h),
            Support::Supported {
                distro: "Ubuntu 24.04.1 LTS".into(),
                systemd: 247
            }
        );
    }

    #[test]
    fn os_release_parsing() {
        let m = parse_os_release("# c\nA=plain\nB=\"dq \\\"x\\\"\"\nC='sq'\n\nbad line\n");
        assert_eq!(m.get("A").map(String::as_str), Some("plain"));
        assert_eq!(m.get("B").map(String::as_str), Some("dq \"x\""));
        assert_eq!(m.get("C").map(String::as_str), Some("sq"));
        assert!(!m.contains_key("bad line"));
    }

    #[test]
    fn refusal_line_is_exact() {
        assert_eq!(
            refusal_line("Alpine: developer mode only"),
            "saiife: locked mode is not supported here: Alpine: developer mode only. Developer mode works as before."
        );
    }
}
